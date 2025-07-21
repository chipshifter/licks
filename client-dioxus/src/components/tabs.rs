use dioxus::prelude::*;
use dioxus_logger::tracing::info;

// (tab name, tab element)
pub type Tab = (String, Result<VNode, RenderError>);

#[component]
pub fn Tabs() -> Element {
    // todo: move as optional prop
    let mut tabs = use_signal(Vec::<Tab>::new);
    let mut selected_tab = use_signal(|| None);
    rsx! {
        div {
            id: "chat-tabs",
            overflow: "hidden",
            width: "100%",
            height: "fit-content",
            if tabs.read().is_empty() {
                div {
                    "There are no tabs here!"
                }
            } else {
                div {
                    display: "flex",
                    style: "scrollbar-width: none;",
                    gap: "8px",
                    padding: "4px",
                    text_overflow: "ellipsis",
                    overflow: "hidden",
                    overflow_x: "scroll",
                    width: "100%",
                    height: "48px",
                    for (idx, tab) in tabs.read().clone().into_iter().enumerate() {
                        div {
                            display: "flex",
                            flex_direction: "center",
                            padding: "4px",
                            id: "tab-{idx}",
                            overflow: "hidden",
                            min_width: "120px",
                            max_width: "200px",
                            border_radius: "8px",
                            height: "40px",
                            padding: "4px",
                            box_shadow: "1px 1px 2px black",
                            background_color: if selected_tab.read().eq(&tab.1.clone().ok()) { "var()" }else { "#{tab.0}"},
                            onclick: move |_| {
                                *selected_tab.write() = Some(tab.clone().1.unwrap());
                            },
                            span {
                                text_overflow: "ellipsis",
                                word_wrap: "nowrap",
                                overflow: "hidden",
                                "{tab.0}"
                            },
                            button {
                                onclick: move |_| {
                                    let _ = selected_tab.write().take();
                                    let _ = tabs.write().remove(idx);
                                },
                                "X"
                            }
                        }

                    }
                }
                div {
                    id: "selected-tab-content",
                    padding: "8px",
                    border: "3px black",
                    {selected_tab}
                }
            }
        }
        button {
            onclick: move |_| {
                info!("adding tab");
                let tabs_len = tabs.read().len();
                let tab = rsx!(div {" a tab numbered {tabs_len}" });
                tabs.write().push((format!("Tab {} abdefg", tabs_len), tab.clone()));
                let _ = selected_tab.write().insert(tab.expect("tab rsx renders correctly"));
            },
            "+"
        }
    }
}
