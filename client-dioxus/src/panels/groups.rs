use std::collections::HashMap;

use client_backend::{
    manager::notifications::Notification,
    mls::welcome::base64_string_to_welcome,
    ui::{GroupUi, MessageUi},
};
use dioxus::prelude::*;
use dioxus_free_icons::{
    icons::fi_icons::{FiPlusSquare, FiUserPlus},
    Icon,
};
use dioxus_logger::tracing::{error, info};
use futures_util::stream::StreamExt;

use crate::{components::modal::Modal, get_default_profile, panels::chat::ChatPanel};

pub static MESSAGES: GlobalSignal<HashMap<GroupUi, Vec<MessageUi>>> =
    GlobalSignal::new(HashMap::default);
// TODO: Maybe replace this with MESSAGES.get(...).last()?
pub static LAST_MESSAGE: GlobalSignal<HashMap<GroupUi, Option<MessageUi>>> =
    GlobalSignal::new(HashMap::default);

pub async fn message_service(mut rx: UnboundedReceiver<Notification>) {
    while let Some(msg) = rx.next().await {
        match msg {
            Notification::Empty => {
                info!("Received Notification::Empty");
            }
            Notification::Message(group, message) => {
                let mut writer_lock = MESSAGES.write();
                if let Some(vec) = writer_lock.get_mut(&group) {
                    vec.push(message.clone());
                } else {
                    writer_lock.insert(group.clone(), vec![message.clone()]);
                }

                let mut last_msg_writer_lock = LAST_MESSAGE.write();
                let _ = last_msg_writer_lock.insert(group, Some(message));
            }
        }
    }
}

#[component]
pub fn GroupsPanel(selected_group: Signal<GroupUi>) -> Element {
    rsx! {
        ChatPanel { selected_group }
    }
}

#[component]
pub fn GroupsTab(
    mut group_list: Signal<Vec<GroupUi>>,
    mut selected_group: Signal<GroupUi>,
) -> Element {
    let group_list_lock = group_list.read();
    let groups_rendered = group_list_lock.iter().map(|group| {
        let is_selected_group: bool = selected_group.read().eq(group);

        let group = group.clone();
        let group_color = group.color();

        let last_message_lock = LAST_MESSAGE.read();
        let last_message = last_message_lock.get(&group).unwrap_or(&None);

        rsx! {
            div {
                padding: "8px",
                class: if is_selected_group {
                    "group-tab-button selected"
                } else {
                    "group-tab-button"
                },
                onclick: move |_| {
                    info!("Selecting group {group:?}");
                    *selected_group.write() = group.clone();
                },
                div {
                    min_width: "60px",
                    min_height: "60px",
                    border_radius: "8px",
                    margin_right: "6px",
                    background_color: "{group_color}"
                }
                div {
                    display: "flex",
                    flex_direction: "column",
                    gap: "12px",
                    max_width: "100%",
                    max_height: "100%",
                    width: "100%",
                    height: "100%",
                    overflow: "hidden",
                    h3 {
                        overflow: "hidden",
                        white_space: "nowrap",
                        text_overflow: "ellipsis",
                        "{group.group_name}"
                    }
                    if let Some(msg) = last_message {
                        p {
                            width: "100%",
                            height: "100%",
                            overflow: "hidden",
                            white_space: "nowrap",
                            text_overflow: "ellipsis",
                            "{msg}"
                        }
                    }
                }
            }
        }
    });

    let mut is_join_group_modal_open = use_signal(|| false);
    let mut is_create_group_modal_open = use_signal(|| false);

    rsx! {
        div {
            id: "group-tab",
            style: r"
                overflow-x: none;
                overflow-y: scroll;
            ",
            section {
                padding: "0.5rem",
                border_bottom: "2px solid var(--primary)",
                div {
                    style: r"
                        display: flex;
                        align-items: center;
                        padding: 8px;
                        gap: 8px;
                    ",
                    onclick: move |_| {
                        *is_join_group_modal_open.write() = true;
                    },
                    JoinGroupModal { selected_group, group_list, is_open: is_join_group_modal_open },
                    Icon {
                        width: 24,
                        height: 24,
                        fill: "black",
                        icon: FiUserPlus,
                    }
                    h3 {
                        "Join group"
                    }
                }
                div {
                    style: r"
                        display: flex;
                        align-items: center;
                        padding: 8px;
                        gap: 8px;
                    ",
                    onclick: move |_| {
                        *is_create_group_modal_open.write() = true;
                    },
                    CreateGroupModal { selected_group, group_list, is_open: is_create_group_modal_open },
                    Icon {
                        width: 24,
                        height: 24,
                        fill: "black",
                        icon: FiPlusSquare,
                    }
                    h3 {
                        "Create group"
                    }
                }
            }
            {groups_rendered}
        }
    }
}

#[component]
pub fn CreateGroupModal(
    selected_group: Signal<GroupUi>,
    mut group_list: Signal<Vec<GroupUi>>,
    mut is_open: Signal<bool>,
) -> Element {
    let create_group_submit = move |event: FormEvent| {
        spawn(async move {
            let values = event.values();

            // Group description is optional
            let description = values
                .get("group-description")
                .expect("Form always returns a group-description")
                .as_slice()
                .first()
                .cloned();

            let mut group_name: &str = values
                .get("group-name")
                .expect("Form always returns a group-name attribute")
                .first()
                .expect("group-name is not None");

            if group_name.is_empty() {
                group_name = "Cool group";
            }

            let group = get_default_profile()
                .create_new_group(group_name.to_owned(), description)
                .await
                .expect("group creates");
            group_list.push(group.clone());
            *selected_group.write() = group;
            *is_open.write() = false;
        });
    };

    let child_element = rsx! {
        div {
            style: r"
                width: 100%;
                height: 100%;
            ",
            h3 { "Create group"}
            p {
                "Choose a name and description for your group in the boxes below"
            }
            form {
                class: "create-group",
                onsubmit: create_group_submit,
                div {
                    label {
                        r#for: "group-name",
                        "Name"
                    },
                    input {
                        r#type: "text",
                        autofocus: true,
                        name: "group-name"
                    },
                },
                div {
                    label {
                        r#for: "group-name",
                        "Description"
                    },
                    input {
                        r#type: "text",
                        name: "group-description"
                    },
                },
                input {
                    r#type: "submit",
                    value: "Join!"
                }
            }
        }
    };

    rsx! {
        Modal {
            title: "Create a new group",
            child_element,
            is_open
        }
    }
}

#[component]
pub fn JoinGroupModal(
    selected_group: Signal<GroupUi>,
    mut group_list: Signal<Vec<GroupUi>>,
    mut is_open: Signal<bool>,
) -> Element {
    let join_group_submit = move |event: FormEvent| {
        spawn(async move {
            let group_res = async {
                type Error = ();
                let values = event.values();
                let welcome_string: &str = values
                    .get("welcome-key")
                    .expect("Form always returns a welcome-key attribute")
                    .first()
                    .ok_or_else(|| {
                        error!("Couldn't join group, the user did not input any invite code.");
                    })?;

                let welcome = base64_string_to_welcome(welcome_string).ok_or_else(|| {
                    error!("Couldn't deserialize welcome code. It was probably invalid.");
                })?;

                let new_group_id = get_default_profile()
                    .join_group_from_welcome_and_listen(&welcome)
                    .await
                    .map_err(|err| {
                        error!("Joining group failed: {err:?}");
                    })?;

                Ok::<GroupUi, Error>(GroupUi {
                    group_identifier: new_group_id,
                    group_name: "Joined group".to_string().into(),
                    last_message: None,
                })
            };

            if let Ok(group) = group_res.await {
                *selected_group.write() = group.clone();
                group_list.write().push(group);
            }

            // Close Modal after submitting
            *is_open.write() = false;
        });
    };

    let child_element = rsx! {
        div {
            style: r"
                width: 100%;
                height: 100%;
            ",
            h3 { "Invite code "}
            p {
                "Paste your invite in the text box below, then just press the Join button!"
            }
            form {
                class: "create-group",
                onsubmit: join_group_submit,
                input {
                    r#type: "text",
                    name: "welcome-key",
                    autofocus: true,
                }
                input {
                    r#type: "submit",
                    value: "Join!"
                }
            }
        }
    };

    rsx! {
        Modal {
            title: "Join a new group",
            child_element,
            is_open,
        }
    }
}
