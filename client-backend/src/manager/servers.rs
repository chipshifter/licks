use lib::{api::server::Server, constants};

#[derive(thiserror::Error, Debug)]
pub enum ServerParserError {
    #[error("The given URL has no valid domain name")]
    NoDomain,
    #[error("The domain used is invalid and cannot be parsed into a valid Url")]
    InvalidDomain,
}

pub(crate) trait ServerParser {
    fn parse(domain: String) -> Result<Server, ServerParserError>;
}

impl ServerParser for Server {
    fn parse(domain: String) -> Result<Server, ServerParserError> {
        // validate url
        // give the url a fake base (the "https://" part), so that `url` stops complaining
        // and then just keep the host name and port.
        let url = url::Url::parse(format!("https://{domain}").as_str()).map_err(|e| {
            log::error!("Error parsing domain {domain:?} into Url type: {e:?}");

            ServerParserError::InvalidDomain
        })?;

        let host = url
            .host_str()
            .ok_or(ServerParserError::InvalidDomain)?
            .to_owned();

        // TODO: Allow custom ports
        Ok(Server {
            host,
            unauth_endpoint_port: constants::DEFAULT_PORT_UNAUTHENTICATED,
            auth_endpoint_port: constants::DEFAULT_PORT_AUTHENTICATED,
        })
    }
}
