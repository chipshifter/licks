use dioxus::prelude::*;

use crate::components::icon::ImageIcon;
#[component]
pub fn SettingsTab() -> Element {
    rsx! {}
}

#[component]
pub fn SettingsPanel() -> Element {
    rsx! {
        div {
            display: "flex",
            flex_direction: "column",
            width: "100%",
            height: "100%",
            justify_content: "center",
            align_items: "center",
            gap: "10px",
            ImageIcon { size: 80, icon_name: "licker.png" }
            h3 { "Licks Top Secret Dev Version" }
        }
    }
}
