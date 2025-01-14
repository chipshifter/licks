use client_backend::{
    manager::account::Username,
    messages::Content,
    mls::welcome::welcome_to_base64,
    ui::{GroupUi, MessageUi},
};
use dioxus::prelude::*;
use dioxus_logger::tracing::*;
use dioxus_sdk::clipboard::use_clipboard;

use crate::{
    components::{icon::ImageIcon, modal::Modal},
    get_default_profile,
    panels::groups::{LAST_MESSAGE, MESSAGES},
};

#[component]
pub fn ChatPanel(selected_group: Signal<GroupUi>) -> Element {
    let mut input_message = use_signal(String::new);

    let messages: Memo<Vec<Result<VNode, RenderError>>> = use_memo(move || {
        let messages_lock: Vec<MessageUi> = MESSAGES
            .read()
            .get(&selected_group.read())
            .cloned()
            .unwrap_or_default();

        messages_lock
            .iter()
            .map(|message_ui| {
                let author = &message_ui.profile_name;
                let message = message_ui.msg();
                rsx! {
                    // TODO: ARIA labels for accessibility
                    div {
                        class: "message",
                        padding: "0 0 1px 4px",
                        width: "inherit",
                        p { 
                            word_break: "break-all",
                            text_wrap: "stable",
                            b { 
                                id: "message-author",
                                "{author}" 
                            }
                            "{message}" 
                        }
                    }
                }
            })
            .collect()
    });

    let on_press_send = move || {
        spawn(async move {
            let group_lock = selected_group.read();
            let profile = get_default_profile();
            let message = input_message.read().clone();

            let account_id = profile.profile.get_account_id();
            // TODO: Load our actual profile name somewhere idk
            let message_ui =
                MessageUi::plain_text(profile.username.0 .0.clone(), account_id, message.clone());

            let content = Content::plain_text(message);

            // For now, we silently fail.
            // TODO: If this fails, let the UI know that the message
            // did not send (for whatever reason).
            let _ = profile
                .send_application_message(&group_lock.group_identifier, content)
                .await;

            let mut messages_writer_lock = MESSAGES.write();
            if let Some(msg_vec) = messages_writer_lock.get_mut(&group_lock) {
                msg_vec.push(message_ui.clone());
            } else {
                messages_writer_lock.insert(group_lock.clone(), vec![message_ui.clone()]);
            }

            LAST_MESSAGE
                .write()
                .insert(group_lock.clone(), Some(message_ui));

            input_message.write().clear();
        });
    };

    let group_lock = selected_group.read();
    let group_name = group_lock.group_name.clone();
    let group_color = group_lock.color();
    drop(group_lock);

    let mut is_invite_modal_open = use_signal(|| false);

    rsx! {
        div {
            class: "chat-panel",
            display: "flex",
            flex_direction: "column",
            justify_content: "end",
            align_items: "stretch",
            overflow: "hidden",
            width: "100%",
            height: "100%",
            max_width: "100%",
            div {
                display: "flex",
                align_items: "center",
                margin: "var(--padding-medium)",
                padding: "var(--padding-large)",
                height: "50px",
                overflow: "hidden",
                width: "100%",
                max_width: "100%",
                // TODO: When we add support for group images,
                // replace this div with an image (with color
                // as a fallback)
                div {
                    background_color: "{group_color}",
                    width: "34px",
                    height: "34px",
                    min_width: "34px",
                    min_height: "34px",
                    border_radius: "1px",
                }
                h3 {
                    flex_grow: "1",
                    overflow_x: "hidden",
                    text_wrap: "nowrap",
                    text_overflow: "ellipsis",
                    margin_left: "10px",
                    "{group_name}"
                }
                div {
                    onclick: move |_| {
                        *is_invite_modal_open.write() = true;
                    },
                    InviteUsernameToGroupModal { selected_group, is_open: is_invite_modal_open }
                    ImageIcon {
                        size: 30,
                        icon_name: "contact_plus.png",
                        button: true,
                    }
                }
            }
            div {
                flex_grow: "2",
                width: "100%",
                height: "100%",
                overflow_y: "scroll",
                overflow_x: "hidden",
                display: "flex",
                flex_direction: "column",
                for message in messages() {
                    {message}
                }
            }
            // Message composer input
            form {
                display: "flex",
                justify_content: "center",
                align_items: "center",
                max_width: "100%",
                padding: "var(--padding-medium)",
                onsubmit: move |_| on_press_send(),
                input {
                    type: "text",
                    flex_grow: "1",
                    placeholder: "Write a message",
                    value: "{input_message}",
                    oninput: move |event| input_message.set(event.value()),
                }
                input { r#type: "submit", display: "none" }
                // Send button
                div {
                    id: "chat-send-button",
                    display: "flex",
                    justify_content: "center",
                    align_items: "center",
                    height: "100%",
                    width: "auto",
                    onclick: move |_| on_press_send(),
                    ImageIcon { size: 30, icon_name: "send_arrow.png", button: true, background_color: Some("var(--primary)") }
                }

            }
        }
    }
}

#[component]
pub fn InviteUsernameToGroupModal(
    selected_group: Signal<GroupUi>,
    mut is_open: Signal<bool>,
) -> Element {
    let create_welcome = move |event: FormEvent| {
        spawn(async move {
            let values = event.values();

            let username_str: &str = values
                .get("username")
                .expect("Form always returns a username attribute")
                .first()
                .expect("username is not None");

            let welcome_string = async {
                let username = Username::new(username_str.to_string()).map_err(|err| {
                    error!("Username given was invalid: {err:?}");
                })?;

                let account_id = get_default_profile()
                    .find_account_id_by_username(username)
                    .await
                    .map_err(|err| {
                        error!("Could not find account: {err:?}");
                    })?
                    .ok_or_else(|| {
                        error!("Account with username \"{username_str}\" does not exist");
                    })?;

                let welcome = get_default_profile()
                    .create_new_welcome(selected_group.read().group_identifier, account_id)
                    .await
                    .map_err(|err| {
                        error!("Creating welome message failed. Account might not exist: {err:?}")
                    })?;

                Ok::<_, ()>(welcome_to_base64(&welcome).expect("this is a welcome message"))
            };

            if let Ok(welcome) = welcome_string.await {
                info!("{welcome}");

                let mut clipboard = use_clipboard();
                let _ = clipboard.set(welcome.to_string());
            }
        });
    };

    let child_element = rsx! {
        div { width: "100%", height: "100%",
            h3 { "Invite user to group" }
            form { class: "invite-input", onsubmit: create_welcome,
                div {
                    label { r#for: "username", "Username" }
                    input { r#type: "text", autofocus: true, name: "username" }
                }
                input {
                    r#type: "submit",
                    value: "Create and copy invite code to clipboard",
                }
            }
        }
    };

    rsx! {
        Modal { title: "Invite user to group", child_element, is_open }
    }
}
