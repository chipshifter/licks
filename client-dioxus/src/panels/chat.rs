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
    components::icon::ImageIcon, get_default_profile, panels::groups::{LAST_MESSAGE, MESSAGES}
};

#[component]
pub fn ChatPanel(selected_group: Signal<GroupUi>) -> Element {
    let mut input_message = use_signal(String::new);
    let mut invite_input = use_signal(String::new);

    let messages: Memo<Vec<Option<VNode>>> = use_memo(move || {
        let messages_lock: Vec<MessageUi> = MESSAGES
            .read()
            .get(&selected_group.read())
            .cloned()
            .unwrap_or_default();

        messages_lock
            .iter()
            .map(|message_ui| {
                rsx! {
                    div {
                        class: "message",
                        "{message_ui}"
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
            let message_ui = MessageUi::plain_text("You".to_string(), account_id, message.clone());

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

    let create_welcome = move |_| {
        spawn(async move {
            let welcome_string = async {
                let username_str = invite_input.read();
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

    let group_name = selected_group.read().group_name.clone();

    rsx! {
        div {
            class: "chat-panel",
            display: "flex",
            flex_direction: "column",
            width: "100%",
            height: "100%",
            overflow: "hidden",
            div {
                display: "flex",
                align_items: "center",
                height: "50px",
                h3 {
                    margin_left: "10px",
                    "{group_name}"
                }
            }
            div {
                flex_grow: "2",
                width: "100%",
                height: "100%",
                overflow_y: "scroll",
                overflow_x: "hidden",
                class: "messages",
                for message in messages() {
                    {message}
                }
            }
            form {
                class: "invite-input",
                onsubmit: create_welcome,
                input {
                    value: "{invite_input}",
                    oninput: move |event| invite_input.set(event.value()),
                }
                input {
                    r#type: "submit",
                    value: "Create invite"
                }
            }
            form {
                class: "chat-input",
                onsubmit: move |_| on_press_send(),
                input {
                    class: "composer",
                    value: "{input_message}",
                    oninput: move |event| input_message.set(event.value()),
                }
                input {
                    r#type: "submit",
                    display: "none"
                }
                div {
                    onclick: move |_| on_press_send(),
                    ImageIcon {
                        size: 30,
                        icon_name: "send_arrow.png"
                    }
                }

            }
        }
    }
}
