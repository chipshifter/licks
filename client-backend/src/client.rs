use std::{io::ErrorKind, ops::Deref, sync::Arc};

use futures_channel::mpsc::{UnboundedReceiver, UnboundedSender};

use crate::manager::{
    listener::ListenerManager,
    notifications::{Notification, NotificationSender},
    ProfileManager,
};

/// Highest level. Handles the different [`ProfileManager`]s a user may have at a time.
/// Client is meant to handle different profiles. UI frontend keeps track
/// of the [`ProfileManager`] it's on, but also at highest level should start Client.
pub struct Client {
    pub listener_manager: ListenerManager,

    // String is the profile name.
    pub profile_managers: scc::HashMap<String, Arc<ProfileManager>>,

    /// The notification manager allows `Client` to send notifications
    /// to the Tauri client frontend who will display them.
    pub notification_manager: Arc<NotificationSender>,
}

impl Client {
    pub fn new() -> (Self, UnboundedReceiver<Notification>) {
        let (tx, rx) = futures_channel::mpsc::unbounded();
        (Self::new_with_notif(tx), rx)
    }

    pub fn new_with_notif(tx: UnboundedSender<Notification>) -> Self {
        Self {
            listener_manager: ListenerManager::default(),
            profile_managers: scc::HashMap::new(),
            notification_manager: NotificationSender::new(tx).into(),
        }
    }

    /// Same as [`Client::get_profile`] except it load the profile in memory instead.
    /// This mostly exists for testing purposes as the profile data wont be saved on disk
    async fn load_in_memory_profile(
        &self,
        profile_name: &str,
    ) -> anyhow::Result<Arc<ProfileManager>> {
        if let Some(profile) = self.profile_managers.get(profile_name) {
            return Ok(profile.get().clone());
        }

        let profile_manager: Arc<ProfileManager> = ProfileManager::initialise_params(None).await?;

        let _ = self
            .profile_managers
            .insert(profile_name.to_owned(), profile_manager.clone());

        Ok(profile_manager)
    }

    /// Loads a new profile from disk if it hasn't been loaded already.
    /// This function will panic if a profile hasn't been loaded already
    /// and fails to load a new one from the disk
    async fn load_profile(&self, profile_name: &str) -> anyhow::Result<Arc<ProfileManager>> {
        if let Some(profile) = self.profile_managers.get(profile_name) {
            return Ok(profile.get().clone());
        }

        let mut licks_folder_path =
            dirs::data_local_dir().expect("Operating system returns data local folder");
        licks_folder_path.push("licks");
        // Push to profile name
        licks_folder_path.push(profile_name);

        // If folder doesn't exist at that path, create it.
        if let Err(e) = std::fs::create_dir_all(&licks_folder_path) {
            match e.kind() {
                ErrorKind::AlreadyExists => {}
                _ => todo!("Ignore the error if folder already exists"),
            }
        }

        let profile_manager: Arc<ProfileManager> =
            ProfileManager::initialise_params(Some(licks_folder_path)).await?;

        self.profile_managers
            .insert(profile_name.to_owned(), profile_manager.clone())
            .expect("adds to hashmap");

        Ok(profile_manager)
    }

    pub fn add_profile(&self, profile_name: String, profile_manager: Arc<ProfileManager>) {
        if let Err(e) = self.profile_managers.insert(profile_name, profile_manager) {
            log::debug!("Replacing pre-existing profile {}, {:?}", e.0, e.1);
        }
    }

    pub fn send_notification(&self, notification: Notification) {
        self.notification_manager.send_notification(notification);
    }

    pub async fn get_profile<'a>(
        &'a self,
        profile_name: &str,
    ) -> anyhow::Result<ClientProfile<'a>> {
        let profile_manager = self.load_profile(profile_name).await?;

        let client_profile = ClientProfile {
            client: self,
            profile_manager,
        };

        // TODO: Move this logic to front-end
        // Also make sure this doesn't run if the account is already registered
        // when launching app (this isn't the case for now, but....)
        //
        // Ignore errors if they already existed
        let _ = client_profile.create_self_group().await;

        Ok(client_profile)
    }

    pub async fn get_in_memory_profile<'a>(
        &'a self,
        profile_name: &str,
    ) -> anyhow::Result<ClientProfile<'a>> {
        let profile_manager = self.load_in_memory_profile(profile_name).await?;

        let client_profile = ClientProfile {
            client: self,
            profile_manager,
        };

        // TODO: Move this logic to front-end
        // Also make sure this doesn't run if the account is already registered
        // when launching app (this isn't the case for now, but....)
        client_profile.create_self_group().await?;

        Ok(client_profile)
    }
}

/// An instance of Client+ProfileManager which is what is ultimately used
/// by the clients to handle profiles.
/// This wraps Client API on top of Arc<ProfileManager>.
pub struct ClientProfile<'a> {
    pub client: &'a Client,
    pub profile_manager: Arc<ProfileManager>,
}

impl Deref for ClientProfile<'_> {
    type Target = Arc<ProfileManager>;

    fn deref(&self) -> &Self::Target {
        &self.profile_manager
    }
}
