use core::fmt::Display;
use lib::identifiers::{AccountId, GroupIdentifier, LicksIdentifier};
use std::{hash::Hash, sync::Arc};

#[derive(Debug, Clone)]
pub struct MessageUi {
    profile_name: String,
    _device_id: AccountId,
    message: MessageInner,
}

#[derive(Debug, Clone)]
enum MessageInner {
    PlainText(Arc<String>),
}

impl MessageUi {
    // TODO: have an impl ProfileManager... where we pass self.username automatically
    pub fn plain_text(profile_name: String, device_id: AccountId, message: String) -> Self {
        let string = Arc::new(message);
        Self {
            profile_name,
            _device_id: device_id,
            message: MessageInner::PlainText(string),
        }
    }

    pub fn msg(&self) -> &str {
        let MessageInner::PlainText(ref string) = self.message;

        string
    }
}

impl Display for MessageUi {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.message {
            MessageInner::PlainText(string) => {
                write!(f, "{}: {}", self.profile_name, string)
            }
        }
    }
}

/// (WIP) A struct used for displaying group information
/// to the client interface.
#[derive(Debug, Clone)]
pub struct GroupUi {
    pub group_identifier: GroupIdentifier,
    pub group_name: Arc<String>,
    pub last_message: Option<MessageUi>,
}

impl Hash for GroupUi {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.group_identifier.hash(state);
    }
}

impl PartialEq for GroupUi {
    fn eq(&self, other: &Self) -> bool {
        // We don't check the other information, GroupIdentifier
        // is enough since it is assumed to be unique to each client's group.
        self.group_identifier == other.group_identifier
    }
}

impl Eq for GroupUi {}

impl GroupUi {
    pub fn formatted_id(&self) -> String {
        self.group_identifier.as_uuid().to_string()
    }

    pub fn name(&self) -> &str {
        &self.group_name
    }

    // RGB-encoded color value "#123abc"
    // generated using the GroupIdentifier
    pub fn color(&self) -> String {
        // This is cursed but I don't care
        let mut encoded_string = String::from("#");
        let mut color_string = self.group_identifier.as_uuid().to_string();
        let _ = &color_string.split_off(6);
        encoded_string.push_str(&color_string);

        encoded_string
    }
}
