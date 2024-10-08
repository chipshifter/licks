//! Useful traits and types for handling connections and the API

use crate::{
    error::Error,
    services::{
        chat::ChatService, key_packages::KeyPackageService, register::RegistrationService,
        usernames::UsernameService,
    },
};
use lib::{
    api::connection::{
        AuthRequest, ClientRequestId, Message, MessageWire, ServiceError as SocketError,
        ServiceMessage, ServiceResult, UnauthRequest,
    },
    crypto::certificates::SerializedChain,
    identifiers::AccountId,
};
use std::{future::Future, sync::Arc};
use tokio::sync::mpsc;
use tracing::{debug_span, instrument, Span};

/// Each socket waits for requests (in the form of `MessageWire`)
/// For each `MessageWire` received through the socket:
///  - Create a mpsc channel
///  - Start a thread sending (`mpsc::Sender`, `MessageWire`) into it
///    and the `mpsc::Receiver` waits for response
///  - Once that's done (either by receiving `Message::Ok` or a `SocketError`)
///    the receiver closes
#[derive(Debug, Clone)]
pub struct Request {
    pub sender: mpsc::UnboundedSender<MessageWire>,
    pub req_id: ClientRequestId,
    pub span: tracing::Span,
}

impl Request {
    pub fn make(
        sender: mpsc::UnboundedSender<MessageWire>,
        req_id: ClientRequestId,
        parent_span: &Span,
    ) -> Self {
        Self {
            sender,
            req_id,
            span: debug_span!(parent: parent_span, "Req", id = %req_id),
        }
    }

    #[instrument(skip_all)]
    pub fn handle(mut self, message: Message) {
        tokio::task::spawn(async move {
            // Since we don't have an handle for this function, we don't care about its return value.
            // Panicking is therefore completely fine here. The use of `expect` allows us to add more
            // context to the panic message (which is logged).
            // This task will panic is a user abruptly closes the connection before a request gets finished.
            match message {
                Message::Unauth(as_msg) => {
                    UnauthenticatedChannelService::handle_request(&mut self, as_msg)
                        .await
                        .expect("Couldn't handle unauthenticated channel service request");
                }
                Message::Ignore => {}
                Message::Ping(b) => self
                    .message(Message::Pong(b))
                    .await
                    .expect("Couldn't ping back user"),
                _ => self
                    .error(SocketError::InvalidOperation)
                    .await
                    .expect("User requested an invalid operation, but couldn't send error back"),
            }
        });
    }

    #[instrument(skip_all)]
    pub fn handle_authenticated(mut self, chain: Arc<SerializedChain>, message: Message) {
        tokio::task::spawn(async move {
            match message {
                Message::Auth(as_msg) => {
                    AuthenticatedService::handle_authenticated_request(
                        &mut self,
                        chain.account_id(),
                        as_msg,
                    )
                    .await
                    .expect("Couldn't handle authenticated channel");
                }
                Message::Ignore | Message::Bye => {}
                Message::Ping(b) => self
                    .message(Message::Pong(b))
                    .await
                    .expect("Tried sending ping back to client, but connection was closed"),
                _ => self
                    .error(SocketError::InvalidOperation)
                    .await
                    .expect("User requested an invalid operation, but couldn't send error back"),
            }
        });
    }
}

pub type RequestReceiver = mpsc::UnboundedReceiver<MessageWire>;

/// A trait to handle socket connections.
#[allow(async_fn_in_trait)]
pub trait RequestHandler: Clone + Send + 'static {
    /// Keep track of the tracing span to log things related to the request we're handling
    fn span(&self) -> &Span;

    /// Send back an error to the user.
    #[instrument(skip_all, parent = self.span())]
    #[inline]
    async fn error(&mut self, err: SocketError) -> Result<(), Error> {
        self.message(Message::Error(err)).await
    }

    /// Send a socket message to the user.
    fn message(&mut self, msg: Message) -> impl Future<Output = Result<(), Error>> + Send;

    /// Takes a function `f` returning a `ServiceResult` as the argument.
    /// Uses the connection to send the message back to the connection,
    /// depending on the `Result`, it will return a regular message or an error message.
    #[instrument(skip_all, name = "unauth_service", parent = self.span())]
    #[inline]
    async fn map_service_result<F, Req: Send>(
        &mut self,
        service: F,
        request: Req,
    ) -> Result<(), Error>
    where
        F: FnOnce(Req) -> ServiceResult + Send,
    {
        match service(request) {
            Ok(ok_msg) => self.message(ok_msg).await,
            Err(err_msg) => self.error(err_msg).await,
        }
    }

    #[instrument(skip_all, name = "auth_service", parent = self.span())]
    #[inline]
    async fn map_authenticated_service_result<F, Req: Send>(
        &mut self,
        service: F,
        request: Req,
        verified_account_id: &AccountId,
    ) -> Result<(), Error>
    where
        F: FnOnce(&AccountId, Req) -> ServiceResult + Send,
    {
        match service(verified_account_id, request) {
            Ok(ok_msg) => self.message(ok_msg).await,
            Err(err_msg) => self.error(err_msg).await,
        }
    }
}

impl RequestHandler for Request {
    fn span(&self) -> &Span {
        &self.span
    }

    #[inline]
    async fn message(&mut self, msg: Message) -> Result<(), Error> {
        self.sender
            .send(MessageWire(self.req_id, msg))
            .map_err(|_| Error::RequestError)
    }
}

/// A "service" for connections. It handles messages/requests from
/// a connection `conn`, and is expected to use that connection
/// to send back a response.
#[allow(async_fn_in_trait)]
pub trait ConnectionService<M: ServiceMessage> {
    async fn handle_request(request: &mut impl RequestHandler, msg: M) -> Result<(), Error>;
}

/// Handle messages on the authenticated connection. It passes by reference
/// the device certificate chain that the server validated.
#[allow(async_fn_in_trait)]
pub trait AuthenticatedConnectionService<M: ServiceMessage> {
    async fn handle_authenticated_request(
        request: &mut impl RequestHandler,
        verified_account_id: &AccountId,
        msg: M,
    ) -> Result<(), Error>;
}

#[derive(Default)]
pub struct UnauthenticatedChannelService;

impl ConnectionService<UnauthRequest> for UnauthenticatedChannelService {
    async fn handle_request(
        request: &mut impl RequestHandler,
        msg: UnauthRequest,
    ) -> Result<(), Error> {
        match msg {
            UnauthRequest::Registration(req) => {
                RegistrationService::handle_request(request, req).await
            }
            UnauthRequest::GetKeyPackage(account_id) => {
                request
                    .map_service_result(KeyPackageService::get_key_package, account_id)
                    .await
            }
            UnauthRequest::ChatService(req) => ChatService::handle_request(request, req).await,
            UnauthRequest::GetAccountFromUsername(username_hash) => {
                request
                    .map_service_result(UsernameService::find_account_id, username_hash)
                    .await
            }
            _ => request.error(SocketError::InvalidOperation).await,
        }
    }
}

#[derive(Default)]
pub struct AuthenticatedService;

impl AuthenticatedConnectionService<AuthRequest> for AuthenticatedService {
    #[instrument(skip_all)]
    async fn handle_authenticated_request(
        request: &mut impl RequestHandler,
        verified_account_id: &AccountId,
        msg: AuthRequest,
    ) -> Result<(), Error> {
        match msg {
            AuthRequest::SetUsername(username) => {
                request
                    .map_authenticated_service_result(
                        UsernameService::set_username,
                        username,
                        verified_account_id,
                    )
                    .await
            }
            AuthRequest::RemoveUsername(username) => {
                request
                    .map_authenticated_service_result(
                        UsernameService::remove_username,
                        username,
                        verified_account_id,
                    )
                    .await
            }
            AuthRequest::UploadKeyPackages(key_packages) => {
                request
                    .map_authenticated_service_result(
                        KeyPackageService::upload_key_package,
                        &key_packages,
                        verified_account_id,
                    )
                    .await
            }
            _ => request.error(SocketError::InvalidOperation).await,
        }
    }
}
