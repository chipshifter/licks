use anyhow::Result;

use lib::api::messages::AuthRequest;
use mls_rs::mls_rs_codec::MlsEncode;

use super::{ProfileManager, WEBSOCKET_MANAGER};

impl ProfileManager {
    // TODO we'll want a better mechanism for adding keypackages than this
    pub async fn upload_new_key_packages(&self, quantity: usize) -> Result<()> {
        let mut key_packages = Vec::new();
        for _ in 0..quantity {
            let message = self.mls_client.generate_key_package_message()?;
            key_packages.push(message.mls_encode_to_vec()?);
        }
        WEBSOCKET_MANAGER
            .request_auth(
                self.get_profile(),
                AuthRequest::UploadKeyPackages(key_packages),
            )
            .await?;
        Ok(())
    }
}
