use dioxus::prelude::*;

#[derive(PartialEq, Props, Clone)]
pub struct ImageIconProps {
    icon_name: &'static str,
    size: i64,
    #[props(default = false)]
    button: bool,
}

#[component]
pub fn ImageIcon(props: ImageIconProps) -> Element {
    let class = if props.button {
        "icon-button"
    } else {
        ""
    };

    rsx! {
        img {
            width: props.size,
            height: props.size,
            class: class,
            src: format!("assets/icons/{}", props.icon_name)
        }
    }
}
