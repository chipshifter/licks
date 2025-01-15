mod tests {
    use std::time::Duration;

    use mls_rs::MlsMessage;

    use crate::{client::Client, manager::ProfileManager, messages::Content};

    #[tokio::test]
    pub async fn new_group_test() {
        let manager = ProfileManager::initialise()
            .await
            .expect("client manager should initialize");

        manager
            .create_group_without_listener(
                String::from("Bob's group"),
                String::from("The place where Bob's friends hang out and talk").into(),
            )
            .expect("group creation should have succeeded");
    }

    #[tokio::test]
    pub async fn two_person_conversation_test() {
        let (client, _rx) = Client::new();
        let alice_manager = client
            .get_in_memory_profile("alice")
            .await
            .expect("server is open and registration works");

        alice_manager
            .upload_new_key_packages(1)
            .await
            .expect("keypackage should have uploaded");

        let bob_manager = client
            .get_in_memory_profile("bob")
            .await
            .expect("server is open and registration works");

        let bobs_group_ui = bob_manager
            .create_new_group(
                String::from("Bob's group"),
                String::from("The place where Bob's friends hang out and talk").into(),
            )
            .await
            .expect("group creation should have succeeded");

        let bobs_group_id = bobs_group_ui.group_identifier;

        let alices_welcome = bob_manager
            .create_new_welcome(bobs_group_id, alice_manager.profile.get_account_id())
            .await
            .expect("welcome should have been created");

        assert_eq!(
            MlsMessage::from_bytes(&alices_welcome.to_bytes().expect("serialization works"))
                .expect("serialization works"),
            alices_welcome
        );

        // Alice receives the welcome message out of band
        let alices_group_id = alice_manager
            .join_group_from_welcome_and_listen(&alices_welcome)
            .await
            .expect("group should have been made from welcome");

        assert_eq!(bobs_group_id, alices_group_id);

        // Send a message to alice and wait for it to get to her
        {
            let bobs_first_message_content = Content::plain_text("hello, Alice".to_owned());

            bob_manager
                .send_application_message(&bobs_group_id, bobs_first_message_content.clone())
                .await
                .expect("application message should have been sent");
            tokio::time::sleep(Duration::from_millis(500)).await;

            let alice_message_log = alice_manager.message_log.lock().await;
            let alice_message = alice_message_log.last().map(|v| &v.1);

            let alice_message_content = alice_message.map(|mes| &mes.content);

            assert_eq!(alice_message_content, Some(&bobs_first_message_content));
        }

        // Send a message to bob and wait for them to receive it
        {
            let alices_first_message_content = Content::plain_text("Hello, bob".to_owned());

            alice_manager
                .send_application_message(&bobs_group_id, alices_first_message_content.clone())
                .await
                .expect("application message should have been sent");
            tokio::time::sleep(Duration::from_millis(500)).await;

            let mut bob_message_log = bob_manager.message_log.lock().await;
            let bob_message = bob_message_log.pop().map(|v| v.1);

            let bob_message_content = bob_message.map(|mes| mes.content);

            assert_eq!(bob_message_content, Some(alices_first_message_content));
        }

        // Bob stops listening, Alice sends message, Bob doesn't receive it
        {
            let alices_first_message_content = Content::plain_text("Hello, bob".to_owned());

            client
                .listener_manager
                .stop(bob_manager.profile_manager.clone(), bobs_group_id)
                .await
                .expect("it stops");

            alice_manager
                .send_application_message(&bobs_group_id, alices_first_message_content.clone())
                .await
                .expect("application message should have been sent");
            tokio::time::sleep(Duration::from_millis(500)).await;

            assert!(bob_manager.message_log.lock().await.is_empty());
        }
    }

    #[tokio::test]
    pub async fn three_person_conversation() {
        let (client, _rx) = Client::new();
        let alice_manager = client
            .get_in_memory_profile("alice")
            .await
            .expect("server is open and registration works");

        alice_manager
            .upload_new_key_packages(1)
            .await
            .expect("keypackage should have uploaded");

        let charlie_manager = client
            .get_in_memory_profile("charlie")
            .await
            .expect("server is open and registration works");

        charlie_manager
            .upload_new_key_packages(1)
            .await
            .expect("keypackage should have uploaded");

        let bob_manager = client
            .get_in_memory_profile("bob")
            .await
            .expect("server is open and registration works");

        let bobs_group_ui = bob_manager
            .create_new_group(
                String::from("Bob's group"),
                String::from("The place where Bob's friends hang out and talk").into(),
            )
            .await
            .expect("group creation should have succeeded");

        let bobs_group_id = bobs_group_ui.group_identifier;

        let alice_welcome = bob_manager
            .create_new_welcome(
                bobs_group_ui.group_identifier,
                alice_manager.profile.get_account_id(),
            )
            .await
            .expect("welcome should have been created");

        alice_manager
            .join_group_from_welcome_and_listen(&alice_welcome)
            .await
            .expect("group should have been made from welcome");

        // Send a message to alice and wait for it to get to her
        {
            let bobs_first_message_content = Content::plain_text("Hello Alice, I'm going to add Charlie to this group".to_owned());

            bob_manager
                .send_application_message(&bobs_group_id, bobs_first_message_content.clone())
                .await
                .expect("application message should have been sent");
            tokio::time::sleep(Duration::from_millis(500)).await;

            let alice_message_log = alice_manager.message_log.lock().await;
            let alice_message = alice_message_log.last().map(|v| &v.1);

            let alice_message_content = alice_message.map(|mes| &mes.content);

            assert_eq!(alice_message_content, Some(&bobs_first_message_content));
        }

        // Send a message to bob and wait for it get to him
        {
            let alices_first_message_content = Content::plain_text("Hello, Bob".to_owned());

            alice_manager
                .send_application_message(&bobs_group_id, alices_first_message_content.clone())
                .await
                .expect("application message should have been sent");
            tokio::time::sleep(Duration::from_millis(500)).await;

            let mut bob_message_log = bob_manager.message_log.lock().await;
            let bob_message = bob_message_log.pop().map(|v| v.1);

            let bob_message_content = bob_message.map(|mes| mes.content);

            assert_eq!(bob_message_content, Some(alices_first_message_content));
        }

        // Charlie gets affed to the group
        let charlie_welcome = bob_manager
            .create_new_welcome(
                bobs_group_ui.group_identifier,
                charlie_manager.profile.get_account_id(),
            )
            .await
            .expect("welcome should have been created");

        charlie_manager
            .join_group_from_welcome_and_listen(&charlie_welcome)
            .await
            .expect("group should have been made from welcome");
        
        // Send a message to bob and alice and wait for it get to them
        {
            let charlies_first_message_content = Content::plain_text("Hello, Alice and Bob".to_owned());

            charlie_manager
                .send_application_message(&bobs_group_id, charlies_first_message_content.clone())
                .await
                .expect("application message should have been sent");
            tokio::time::sleep(Duration::from_millis(500)).await;
            tokio::time::sleep(Duration::from_millis(500)).await;

            let mut bob_message_log = bob_manager.message_log.lock().await;
            let bob_message = bob_message_log.pop().map(|v| v.1);

            let bob_message_content = bob_message.map(|mes| mes.content);
            drop(bob_message_log);

            let mut alice_message_log = alice_manager.message_log.lock().await;
            let alice_message = alice_message_log.pop().map(|v| v.1);

            let alice_message_content = alice_message.map(|mes| mes.content);
            drop(alice_message_log);

            assert_eq!(bob_message_content, Some(charlies_first_message_content.clone()));
            assert_eq!(alice_message_content, Some(charlies_first_message_content));
            
        }
        
        
    }
}
