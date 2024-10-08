use dioxus::prelude::*;
use dioxus_free_icons::{icons::fi_icons::FiX, Icon};

#[component]
pub fn Modal(title: &'static str, child_element: Option<VNode>, is_open: Signal<bool>) -> Element {
    if *is_open.read() {
        rsx! {
            div {
                id: "modal-bg",
                style: r"
                    position: absolute;
                    top: 0;
                    bottom: 0;
                    left: 0;
                    right: 0;

                    height: 100%;
                    width: 100%;

                    z-index: 99;

                    background: #00000044;

                    display: flex;
                    justify-content: center;
                    align-items: center; 
                ",
                onkeydown: move |e| {
                    if e.key() == Key::Escape {
                        e.stop_propagation();
                        *is_open.write() = false;
                    }
                },
                div {
                    id: "modal",
                    style: r"
                        border-radius: 24px;

                        height: 70%;
                        width: 60%;
                        max-width: 600px;
                        max-height: 400px;
                        overflow-x: hidden;
                        overflow-y: scroll;

                        background-color: var(--element-foreground);

                        display: flex;
                        flex-direction: column;
                        align-items: center;
                        justify-content: space-between;

                        padding: 1rem;
                    ",

                    div {
                        style: r"
                            width: 100%;
                        ",
                        div {
                            style: r"
                                float: right;
                            ",
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
                            style: r"
                                width: 100%;
                                text-align: center;
                                font-weight: black;
                                margin: 1rem;
                                margin-bottom: 2rem;
                            ",
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
