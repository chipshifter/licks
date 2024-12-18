pub mod account;
pub mod connections;
pub mod error;
pub mod groups;
pub mod key_package;
pub mod listener;
pub mod notifications;
pub mod servers;

use std::{
    path::PathBuf,
    sync::{Arc, LazyLock},
};

use crate::{
    database::Database, manager::servers::ServerParser, mls::credentials::LicksIdentityProvider,
    net::manager::WebsocketManager,
};

use self::{account::Profile, connections::ConnectionManager, groups::GroupManager};
use super::account::register::create_account;
use anyhow::Result;
use lib::{
    api::server::Server,
    constants::LOCALHOST_DOMAIN,
    crypto::{
        rng::random_bytes,
        usernames::{Username, UsernameHash},
    },
    util::base64::Base64String,
};
use mls_rs::{
    client_builder::{BaseSqlConfig, WithCryptoProvider, WithIdentityProvider},
    CipherSuite,
};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use mls_rs_provider_sqlite::SqLiteDataStorageEngine;
use std::fmt::Debug;

pub static CONNECTIONS_MANAGER: LazyLock<ConnectionManager> =
    LazyLock::new(ConnectionManager::default);

pub static NEW_CONNECTIONS_MANAGER: LazyLock<WebsocketManager> =
    LazyLock::new(WebsocketManager::default);

pub type MlsClientConfig = WithIdentityProvider<
    LicksIdentityProvider,
    WithCryptoProvider<RustCryptoProvider, BaseSqlConfig>,
>;
type MlsClient = mls_rs::Client<MlsClientConfig>;

pub struct ProfileManager {
    /// Our account state -- account and device signature key pairs.
    /// The `ClientManager` only deals with one account at a time.
    /// Support for multiple accounts needs to be done at a higher level
    /// (by managing multiple `ClientManager` instances)
    pub profile: Arc<Profile>,

    pub username: (Username, UsernameHash),

    pub mls_client: Arc<MlsClient>,

    /// Group manager for storing and loading MLS groups into the db
    pub group_manager: GroupManager,

    // NOTE This is a temporary measure exclusively for testing until
    // message storage and retreival is implemented
    #[cfg(test)]
    pub message_log: tokio::sync::Mutex<
        Vec<(
            lib::identifiers::GroupIdentifier,
            crate::messages::MlsApplicationMessage,
        )>,
    >,

    pub sqlite_database: Database,
}

impl std::hash::Hash for ProfileManager {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.profile.hash(state);
    }
}

impl std::cmp::PartialEq for ProfileManager {
    fn eq(&self, other: &Self) -> bool {
        self.profile == other.profile
    }
}
impl std::cmp::Eq for ProfileManager {}

impl Debug for ProfileManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClientManager").finish()
    }
}

impl ProfileManager {
    /// If `root_data_folder` is Some(path), then the profile manager
    /// will create the necessary folders and database files at that location.
    /// Otherwise it will create an in-memory version.
    pub async fn initialise_params(root_data_folder: Option<PathBuf>) -> Result<Arc<Self>> {
        log::info!("Initialising: Loading database...");

        let sqlite_database = Database::new(root_data_folder)?;

        let random_username = Username::new(
            Base64String::from_bytes(random_bytes::<6>())
                .inner_str()
                .to_string(),
        )
        .expect("Unpadded base64 always produces a valid username");
        let random_username_hash = random_username.hash();

        let profile = if let Ok(db_profile) = sqlite_database.get_profile() {
            db_profile
        } else {
            // We don't have a profile, so we automatically register one
            // (for now that is)

            // TODO: Move registration logic to front-end
            // TODO: Change that when we can finally start having custom server URLs
            let server_domain = LOCALHOST_DOMAIN.to_string();

            let our_server: Box<Server> = Server::parse(server_domain)?.into();

            let profile =
                create_account(&our_server, &CONNECTIONS_MANAGER, random_username_hash).await?;

            // save new profile to db
            sqlite_database.set_profile(&profile)?;
            sqlite_database.add_new_contact(profile.get_account_id(), None, None, None)?;

            profile
        };

        let mls_client = Arc::new(Self::build_mlsrs_client(sqlite_database.clone(), &profile)?);

        let group_manager = GroupManager::init(mls_client.clone())?;

        let client_manager = Arc::new(Self {
            profile: Arc::new(profile),
            username: (random_username, random_username_hash),
            mls_client,
            group_manager,
            #[cfg(test)]
            message_log: tokio::sync::Mutex::new(Vec::new()),
            sqlite_database,
        });

        Ok(client_manager)
    }

    // FIXME: Is there for test compability purposes. Remove or rename meeeee
    pub async fn initialise() -> Result<Arc<Self>> {
        Self::initialise_params(None).await
    }

    pub fn build_mlsrs_client(sqlite_database: Database, profile: &Profile) -> Result<MlsClient> {
        let (secret_key, signing_identity) = profile.to_mls_signer();
        let sqlite_engine = SqLiteDataStorageEngine::new(sqlite_database)?;
        Ok(mls_rs::Client::builder()
            .crypto_provider(RustCryptoProvider::default())
            .psk_store(sqlite_engine.pre_shared_key_storage()?)
            .key_package_repo(sqlite_engine.key_package_storage()?)
            .group_state_storage(
                sqlite_engine
                    .group_state_storage()?
                    .with_max_epoch_retention(50),
            )
            .signing_identity(
                signing_identity,
                secret_key.into(),
                CipherSuite::CURVE25519_AES128,
            )
            .identity_provider(LicksIdentityProvider)
            .build())
    }

    /// Clones and returns the manager's registered `Profile`.
    pub fn get_profile(&self) -> Arc<Profile> {
        self.profile.clone()
    }

    pub fn get_server(&self) -> &Server {
        self.profile.get_server()
    }

    pub fn get_username_string(&self) -> &Username {
        &self.username.0
    }
}
