use dioxus::prelude::*;

#[derive(PartialEq, Props, Clone)]
pub struct ImageIconProps {
    icon_name: &'static str,
    size: i64,
    #[props(default = false)]
    button: bool,
    #[props(default = "")]
    background_color: Option<&'static str>,
}

#[component]
pub fn ImageIcon(props: ImageIconProps) -> Element {
    let class = if props.button { "icon-button" } else { "" };

    rsx! {
        img {
            width: props.size,
            height: props.size,
            class,
            background_color: if let Some(color) = props.background_color { color },
            src: format!("assets/icons/{}", props.icon_name),
        }
    }
}
