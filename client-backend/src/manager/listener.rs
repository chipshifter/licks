//! An mpsc channel that waits for incoming messages (that are
//! being listened to/sent by a [`super::net::connection::Connection`])
use std::{cmp::Reverse, collections::BinaryHeap, sync::Arc};

use anyhow::{anyhow, bail};
use tokio::{
    sync::{mpsc, Mutex},
    task::JoinHandle,
};

use lib::{
    api::{connection::ListenerId, group::DeliveryStamp},
    crypto::blinded_address::BlindedAddressPublic,
    identifiers::GroupIdentifier,
};

use crate::{
    manager::groups::ProcessedCommit,
    messages::Content,
    ui::{GroupUi, MessageUi},
};

use super::{
    groups::ProcessedMessage,
    notifications::{Notification, NotificationSender},
    ProfileManager, WEBSOCKET_MANAGER,
};

/// What is sent by the server when listening to a [`BlindedAddress`].
pub type ListenerMessage = (DeliveryStamp, Vec<u8>);

/// The key type for the [`ListenerManager`]. Each Listener is associated
/// to one group, per profile.
type ListenerKey = (Arc<ProfileManager>, GroupIdentifier);

/// Keeps track of mpsc receivers for groups that are currently being
/// listened to for a certain profile. One listener per profile, per group.
pub struct ListenerManager {
    pub listeners: scc::HashMap<ListenerKey, (Arc<Listener>, JoinHandle<()>)>,
}

impl Default for ListenerManager {
    fn default() -> Self {
        Self {
            listeners: scc::HashMap::new(),
        }
    }
}

impl ListenerManager {
    /// Begin listening to messages for a particular group.
    /// This function starts a new listener and removes the old one if there was
    /// already a listener
    pub async fn listen(
        &self,
        profile_manager: Arc<ProfileManager>,
        group_id: GroupIdentifier,
        notification_sender: Arc<NotificationSender>,
    ) -> Result<(), anyhow::Error> {
        let key: ListenerKey = (profile_manager, group_id);

        if let Some((_, listener)) = self.listeners.remove_async(&key).await {
            listener.1.abort();
            // Wait for task to finish aborting
            let _ = listener.1.await;

            Arc::into_inner(listener.0)
                .expect("We aborted Listener's task, so we should have the only Arc instance left")
                .stop()
                .await;
        }

        let (blinded_address_secret, epoch) = key
            .0
            .group_manager
            .get_blinded_address_and_epoch(&group_id)?;

        let listener = Listener::start(
            key.clone(),
            epoch,
            blinded_address_secret.to_public(),
            notification_sender,
        )
        .await
        .map_err(|()| anyhow!("Starting listener didn't work (request to listen failed)"))?;

        let _ = self.listeners.insert_async(key, listener).await;

        Ok(())
    }

    pub async fn listen_new_epoch(
        &self,
        profile_manager: Arc<ProfileManager>,
        group_id: GroupIdentifier,
        epoch: u64,
        blinded_address: BlindedAddressPublic,
    ) -> anyhow::Result<()> {
        let key = &(profile_manager.clone(), group_id);
        if let Some(listener) = self.listeners.get_async(key).await {
            let listener_id = listener
                .0
                .listen_new_epoch(epoch, blinded_address)
                .await
                .map_err(|()| anyhow!("idk"))?;

            let _ = listener
                .0
                .listener_ids
                .insert_async(epoch, listener_id)
                .await;

            Ok(())
        } else {
            // TODO: Call Self::listen in that scenario?
            bail!("Not listening to that group")
        }
    }

    /// Stops a listener for a group. Returns [`Ok`] if there was a listener to remove [`Err`] otherwise.
    pub async fn stop(
        &self,
        profile: Arc<ProfileManager>,
        group_id: GroupIdentifier,
    ) -> Result<(), ()> {
        if let Some((_, listener)) = self
            .listeners
            .remove_async(&(profile.clone(), group_id))
            .await
        {
            // We can't use [`tokio::task::AbortHandle`]--it cancels the task,
            // but we need to be absolutely sure that the task ends,
            // which is why we `await` on the task handle.
            listener.1.abort();
            let _ = listener.1.await;

            Arc::into_inner(listener.0)
                .expect(
                    "We aborted Listener's rx task, so this is the only instace left of this Arc",
                )
                .stop()
                .await;

            Ok(())
        } else {
            Err(())
        }
    }
}

/// This is a ring-buffer like structure that stores
/// the epochs of the last N messages.
///
/// Those epochs are the ones the Listener is listening to.
///
/// Any epoch older than the oldest epoch of those N messages
/// should then stop being listened to.
pub struct LastNEpochs<const N: usize> {
    // NOTE: This takes N*8 bytes in memory per group,
    // so for 50 messags we're looking at most ~400 bytes per group.
    buff: BinaryHeap<Reverse<u64>>,
}

impl<const N: usize> LastNEpochs<N> {
    pub fn new(first_epoch: u64) -> Self {
        let mut buff = BinaryHeap::with_capacity(1);
        buff.push(Reverse(first_epoch));

        Self { buff }
    }

    /// Returns the new oldest epoch. Returns None
    /// if the epoch was less than the current lowest
    pub fn push(&mut self, new_epoch: u64) -> Option<u64> {
        let new_epoch = Reverse(new_epoch);

        // If the epoch we're adding is older than the oldest epoch
        // then we return None
        //
        // NOTE: Since we're wrapped on Reverse<>, we have to compare with
        // greater-equal, not with less-than.
        if new_epoch.ge(self.buff.peek().expect("buffer is never empty")) {
            return None;
        }

        self.buff.push(new_epoch);

        let mut oldest_removed_epoch = None;
        while self.buff.len() > N {
            oldest_removed_epoch = self.buff.pop();
        }

        match oldest_removed_epoch {
            Some(epoch) => {
                // Return oldest epoch, but only if the top of the heap has
                // a different epoch (meaning oldest_removed_epoch has expired)
                //
                // NOTE: Since we're wrapped on Reverse<>, we have to compare with
                // greater-equal, not with less-than.
                if epoch.gt(self.buff.peek().expect("buffer is never empty")) {
                    Some(epoch.0)
                } else {
                    None
                }
            }
            None => None,
        }
    }
}

pub struct Listener {
    sender: mpsc::Sender<ListenerMessage>,
    last_n_epochs: Mutex<LastNEpochs<50>>,
    /// Keeps track of the [`RequestId`]s listening to
    /// a given epoch
    listener_ids: scc::HashMap<u64, ListenerId>,
    /// Contains the [`ProfileManager`] + [`GroupIdentifier`]
    /// the listener is dealing with. This is the same key
    /// used in the [`ListenerManager`] hash map.
    key: ListenerKey,
    notification_sender: Arc<NotificationSender>,
}

impl Listener {
    pub async fn start(
        key: ListenerKey,
        start_epoch: u64,
        blinded_address: BlindedAddressPublic,
        notification_sender: Arc<NotificationSender>,
    ) -> Result<(Arc<Self>, JoinHandle<()>), ()> {
        let (sender, mut rx) = mpsc::channel::<ListenerMessage>(16);

        let listener: Arc<Self> = Arc::new(Self {
            sender,
            last_n_epochs: Mutex::const_new(LastNEpochs::<50>::new(start_epoch)),
            listener_ids: scc::HashMap::default(),
            key,
            notification_sender,
        });

        let listener_clone = listener.clone();

        let handle = tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match listener_clone.on_message_receive(&msg).await {
                    Ok(Some((new_epoch, new_blinded_address))) => {
                        listener_clone
                            .listen_new_epoch(new_epoch, new_blinded_address)
                            .await
                            // If this crashes this is fine
                            .expect("We are already listening so connection must be open");
                    }
                    Ok(None) => {}
                    Err(err) => {
                        log::warn!("An error occured when trying to process message with stamp {:?}: {err}. Silently ignoring.", msg.0);
                    }
                }
            }
        });

        // And of course, start listener for current epoch
        let listener_id = listener
            .listen_new_epoch(start_epoch, blinded_address)
            .await?;

        let _ = listener
            .listener_ids
            .insert_async(start_epoch, listener_id)
            .await;

        Ok((listener, handle))
    }

    pub async fn stop(&mut self) {
        // Tell the server to stop listening to all our epochs... one by one
        // TODO: Maybe not necessary. Where will we call ::stop()? When the client
        // shuts down? In that case the whole connection will shut down too, although
        // the server doesn't know how to handle it yet lol
        for epoch in self.last_n_epochs.lock().await.buff.drain() {
            if let Some((_, listener_id)) = self.listener_ids.remove_async(&epoch.0).await {
                let _ = self.stop_listening(listener_id).await;
            }
        }
    }

    /// Returns the [`RequestId`] of the request that
    /// is listening
    async fn listen_new_epoch(
        &self,
        epoch: u64,
        blinded_address: BlindedAddressPublic,
    ) -> Result<ListenerId, ()> {
        let server = self.key.0.get_server();
        let request_id = WEBSOCKET_MANAGER
            .start_listen(server, blinded_address, self.sender.clone())
            .await
            .map_err(|_| ())?;

        if let Err((_, old)) = self.listener_ids.insert_async(epoch, request_id).await {
            self.stop_listening(old).await?;
        }

        if let Some(old_epoch_to_remove) = self.last_n_epochs.lock().await.push(epoch) {
            if let Some((_, old_request_id)) =
                self.listener_ids.remove_async(&old_epoch_to_remove).await
            {
                self.stop_listening(old_request_id).await?;
            }
        }

        Ok(request_id)
    }

    /// Returns Err if the connection failed, or if the epoch wasn't being listened to.
    async fn stop_listening(&self, _listener_id: ListenerId) -> Result<(), ()> {
        Err(())
    }

    /// 1) Handle message
    /// 2) If it's a commit, then we update our epoch counter and
    ///    listen to the new address
    /// 3) If our epoch counter tells us to remove old epochs, then
    ///    we also do that
    #[allow(clippy::unused_async)] // async is used in cfg(test)
    async fn on_message_receive(
        &self,
        new_message: &ListenerMessage,
    ) -> anyhow::Result<Option<(u64, BlindedAddressPublic)>> {
        let (delivery_stamp, message_bytes) = new_message;
        let group_id = self.key.1;
        let profile_manager = &self.key.0;

        self.notification_sender
            .send_notification(Notification::Empty);

        match profile_manager
            .group_manager
            .process_incoming_message(&group_id, message_bytes)
        {
            #[allow(unused_variables)]
            Ok(ProcessedMessage::ApplicationMessage(message)) => {
                #[cfg(test)]
                {
                    let mut message_log = profile_manager.message_log.lock().await;

                    message_log.push((group_id, message.clone()));
                }

                let Content::BasicText { body } = message.content.clone();
                // TODO: Have some kind of ContactManager in the future
                // Where we'll be able to retrieve the profile name from the given AccountId
                let message_ui = MessageUi::plain_text(
                    "Unknown Contact".to_string(),
                    message.sender_account_id,
                    body,
                );

                self.notification_sender
                    .send_notification(Notification::Message(
                        GroupUi {
                            group_identifier: group_id,
                            group_name: "idk".to_string().into(),
                            last_message: Some(message_ui.clone()),
                        },
                        message_ui,
                    ));

                profile_manager.sqlite_database.add_message(
                    message.content,
                    message.sender_account_id,
                    delivery_stamp,
                    &group_id,
                )?;
            }
            Ok(ProcessedMessage::Commit(new_epoch, new_blinded_address, commits)) => {
                log::debug!("New epoch. Got blinded address {new_blinded_address:?}");

                for commit in commits {
                    match commit {
                        ProcessedCommit::Unknown => todo!(),
                        ProcessedCommit::AddedMember(account_id) => {
                            // add this new contact to our db
                            profile_manager
                                .sqlite_database
                                .add_new_contact(account_id, None, None, None)?;
                        }
                    }
                }
                // New epoch/blinded address. Add new listener, get rid of old one if needed
                return Ok(Some((new_epoch, new_blinded_address)));
            }
            Ok(ProcessedMessage::Ignore) => {}
            Err(e) => {
                panic!("{e:?}");
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_last_n_epochs() {
        let mut last_n_epochs = LastNEpochs::<3>::new(1);
        assert_eq!(last_n_epochs.push(1), None);
        assert_eq!(last_n_epochs.push(1), None);
        // Even though the buffer got too big, the oldest epoch
        // (which is 1) is still in the buffer, so we still return
        // nothing
        assert_eq!(last_n_epochs.push(1), None);

        assert_eq!(last_n_epochs.push(2), None);
        assert_eq!(last_n_epochs.push(2), None);
        // The buffer now got filled with a new epoch, leaving epoch 1 behind,
        // so we return it
        assert_eq!(last_n_epochs.push(2), Some(1));

        assert_eq!(last_n_epochs.push(2), None);
        assert_eq!(last_n_epochs.push(3), None);
        assert_eq!(last_n_epochs.push(4), None);
        assert_eq!(last_n_epochs.push(5), Some(2));
        assert_eq!(last_n_epochs.push(6), Some(3));
        assert_eq!(last_n_epochs.push(7), Some(4));

        assert_eq!(last_n_epochs.push(2), None);
        assert_eq!(last_n_epochs.push(3), None);
        assert_eq!(last_n_epochs.push(4), None);
        assert_eq!(last_n_epochs.push(5), None);

        // At this point the buffer is [5, 6, 7]
        // We push 5, nothing happens because we end up with [5, 6, 7] again and 5 is still there.
        // We push 6, it becomes [6, 6, 7], so 5 gets out.
        assert_eq!(last_n_epochs.push(5), None);
        assert_eq!(last_n_epochs.push(6), Some(5));
        assert_eq!(last_n_epochs.push(7), None);
        assert_eq!(last_n_epochs.push(7), Some(6));
    }
}
