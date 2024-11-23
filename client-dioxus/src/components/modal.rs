use dioxus::prelude::*;
use dioxus_free_icons::{icons::fi_icons::FiX, Icon};

#[component]
pub fn Modal(title: &'static str, child_element: Option<VNode>, is_open: Signal<bool>) -> Element {
    if *is_open.read() {
        rsx! {
            div {
                id: "modal-bg",
                position: "absolute",
                top: "0",
                bottom: "0",
                left: "0",
                right: "0",
                height: "100%",
                width: "100%",
                z_index: "99",
                background: "#00000044",
                display: "flex",
                justify_content: "center",
                align_items: "center",
                onkeydown: move |e| {
                    if e.key() == Key::Escape {
                        e.stop_propagation();
                        *is_open.write() = false;
                    }
                },
                div {
                    id: "modal",
                    border_radius: "24px",
                    height: "70%",
                    width: "60%",
                    max_width: "600px",
                    max_height: "400px",
                    overflow_x: "hidden",
                    overflow_y: "scroll",
                    background_color: "var(--element-foreground)",
                    display: "flex",
                    flex_direction: "column",
                    align_items: "center",
                    justify_content: "space-between",
                    padding: "1rem",
                    div {
                        width: "100%",
                        div {
                            float: "right",
                            onclick: move |e| {
                                e.stop_propagation();
                                *is_open.write() = false;
                            },
                            Icon {
                                width: 40,
                                height: 40,
                                fill: "black",
                                icon: FiX,
                            }
                        }
                        h1 {
                            width: "100%",
                            text_align: "center",
                            font_weight: "black",
                            margin: "1rem",
                            margin_bottom: "2rem",
                            {title}
                        }
                    }
                    {child_element}
                }
            }
        }
    } else {
        None
    }
}
