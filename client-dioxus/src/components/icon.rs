use dioxus::prelude::*;

#[component]
pub fn ImageIcon(icon_name: &'static str, size: i64) -> Element {
    rsx! {
        img {
            width: size,
            height: size,
            src: format!("assets/icons/{icon_name}")
        }
    }
}
