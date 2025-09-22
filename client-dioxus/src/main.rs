#![allow(non_snake_case)]

use std::sync::OnceLock;

use client_backend::{
    client::{Client, ClientProfile},
    ui::GroupUi,
};
use dioxus::{
    desktop::{tao::platform::macos::WindowBuilderExtMacOS, WindowBuilder},
    prelude::*,
};
use dioxus_logger::tracing::{error, info};
use panels::{
    chat::{ChatPanel, ChatPanelProps},
    groups::{message_service, GroupsTab, GroupsTabProps},
    settings::{SettingsPanel, SettingsTab},
};

#[expect(unused)]
use crate::components::tabs::Tabs;

pub mod components;
pub mod panels;

pub static LICKS_CLIENT: OnceLock<Client> = OnceLock::new();

static PROFILE: OnceLock<ClientProfile<'static>> = OnceLock::new();

pub fn get_default_profile() -> &'static ClientProfile<'static> {
    PROFILE
        .get()
        .expect("OnceCell is only accessed after being initialized")
}

fn main() {
    env_logger::init();
    dioxus_logger::initialize_default();

    info!("Starting Dioxus app");
    let window = WindowBuilder::new()
        .with_titlebar_transparent(true)
        .with_resizable(false)
        .with_title("Licks!")
        .with_always_on_top(false);

    let config = dioxus::desktop::Config::default().with_window(window);

    dioxus::LaunchBuilder::desktop()
        .with_cfg(config)
        .launch(LoadingScreen);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Tab {
    Groups,
    #[expect(unused)]
    Contacts,
    #[expect(unused)]
    Settings,
}

#[component]
fn LoadingScreen() -> Element {
    let stuff = use_coroutine(message_service);

    let licks_client = Client::new_with_notif(stuff.tx());

    let _ = LICKS_CLIENT.set(licks_client);

    let profile_loaded = use_resource(move || async move {
        match LICKS_CLIENT
            .get()
            .expect("We just initialized the OnceCell")
            .get_in_memory_profile("wawa")
            .await
        {
            Ok(client) => {
                let _ = PROFILE.set(client);

                get_default_profile()
                    .upload_new_key_packages(1)
                    .await
                    .map_err(|err| error!("Couldn't upload key package: {err:?}"))?;

                Ok(())
            }
            Err(err) => {
                error!("Couldn't load profile: {err:?}");

                Err(())
            }
        }
    });

    let rendered = match *profile_loaded.read_unchecked() {
        Some(Ok(())) => App(),
        Some(Err(())) => {
            rsx! {
                div { class: "loading",
                    h3 { "Woops! We couldn't create an account. Is the server on?" }
                }
            }
        }
        None => {
            rsx! {
                div { class: "loading",
                    h3 { "Setting up Licks!..." }
                }
            }
        }
    };

    rsx! {
        link { rel: "stylesheet", href: "/assets/main.css" }
        {rendered}
    }
}

#[component]
fn App() -> Element {
    let tab = use_signal(|| Tab::Groups);

    let group_list: Signal<Vec<GroupUi>> = use_signal(|| {
        let group_ids = get_default_profile().get_all_group_ids().unwrap();

        group_ids
            .into_iter()
            // TODO: Filter_map quietly removes errors.
            // If a group fails or is corrupted, we want to log it or tell the user
            .filter_map(|group_id| {
                get_default_profile()
                    .sqlite_database
                    .get_group_info(group_id)
                    .ok()
                    .map(|ok| (group_id, ok))
            })
            .map(|group_info| GroupUi {
                group_identifier: group_info.0,
                group_name: group_info.1 .0.into(),
                last_message: None,
            })
            .collect()
    });

    let selected_group: Signal<GroupUi> = use_signal(|| {
        group_list
            .read()
            .first()
            .cloned()
            .expect("Personal Notes group exists, so there is always at least one group")
    });

    // This lets us only read signal once and guarantees only one of the booleans is true
    let (tab_rsx, panel_rsx) = match *tab.read() {
        Tab::Groups => (
            GroupsTab(GroupsTabProps {
                group_list,
                selected_group,
            }),
            ChatPanel(ChatPanelProps { selected_group }),
        ),
        Tab::Contacts => (rsx!( "Contacts tab" ), rsx!( "Contacts panel" )),
        Tab::Settings => (SettingsTab(), SettingsPanel()),
    };

    rsx! {
        div {
            display: "flex",
            overflow: "hidden",
            width: "inherit",
            height: "inherit",
            max_height: "100%",
            div {
                display: "flex",
                flex_direction: "column",
                overflow: "hidden",
                width: "inherit",
                height: "inherit",
                max_width: "270px",
                background_color: "var(--white-2)",
                flex_grow: "1",
                overflow_y: "scroll",
                {tab_rsx}
            }
            div {
                background_color: "var(--white-1)",
                width: "inherit",
                height: "inherit",
                overflow: "hidden",
                {panel_rsx}
            }
        }
    }
}
