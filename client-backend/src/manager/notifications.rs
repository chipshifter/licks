// Dioxus uses that, not tokio's ...
pub use futures_channel::mpsc::{channel, UnboundedReceiver, UnboundedSender};

use crate::ui::{GroupUi, MessageUi};

/// Basic notifications.
/// We use an mpsc channel to add new notifications.
/// In our case, tauri will read the receiver and act accordingly.

// TODO: Error handling for when channel closes, and potentially try to reopen it

#[derive(Debug, Clone)]
pub enum Notification {
    Empty,
    Message(GroupUi, MessageUi),
}

pub struct NotificationSender {
    tx: UnboundedSender<Notification>,
}

impl NotificationSender {
    // might have to change those function conditions but rn it's ok
    pub fn new(tx: UnboundedSender<Notification>) -> Self {
        Self { tx }
    }

    pub fn send_notification(&self, notification: Notification) {
        let _ = self.tx.unbounded_send(notification);
    }
}

#[cfg(test)]
mod tests {
    #[test]
    pub fn notification_sender_test() {
        todo!("Write test");
    }
}
