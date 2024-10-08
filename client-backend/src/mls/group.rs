use lib::{
    identifiers::GroupIdentifier,
    mls::{
        framing::{self, welcome::Welcome},
        group::Group,
    },
};

use crate::messages::MlsApplicationMessage;
#[expect(dead_code)]

pub struct MlsGroup(Group);

impl MlsGroup {
    pub fn new_group(_group_id: GroupIdentifier) -> Self {
        let group = Group::default();

        Self(group)
    }

    pub fn create_welcome(&self) -> Welcome {
        todo!();
    }

    pub fn send_application_message(&self, message: MlsApplicationMessage) {
        self.send_to_group(framing::Content::Application(message.to_bytes().into()));
    }

    #[expect(unused_variables)]
    fn send_to_group(&self, content: framing::Content) {
        todo!();
    }
}
