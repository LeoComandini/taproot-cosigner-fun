use rocket::http::{ContentType, Status};
use rocket::response::Responder;
use rocket::{Request, Response};
use serde_json::json;
use std::io::Cursor;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("not found")]
    NotFound,

    #[error("Invalid derivation path")]
    InvalidDerivationPath,

    #[error("Invalid pubkey")]
    InvalidPubkey,

    #[error("Invalid seckey")]
    InvalidSeckey,

    #[error(transparent)]
    Bip32Error(#[from] bitcoin::util::bip32::Error),

    #[error(transparent)]
    IoError(#[from] std::io::Error),

    #[error(transparent)]
    HexError(#[from] hex::FromHexError),
}

impl Error {
    fn get_http_status(&self) -> Status {
        match self {
            Error::NotFound => Status::NotFound,
            Error::InvalidDerivationPath => Status::BadRequest,
            Error::Bip32Error(_) => Status::BadRequest,
            Error::InvalidPubkey => Status::BadRequest,
            Error::InvalidSeckey => Status::BadRequest,
            Error::IoError(_) => Status::BadRequest,
            Error::HexError(_) => Status::BadRequest,
        }
    }
}

impl<'r, 'o: 'r> Responder<'r, 'o> for Error {
    fn respond_to(self, _: &'r Request<'_>) -> rocket::response::Result<'o> {
        let err_response = json!({"error": self.to_string()}).to_string();
        Response::build()
            .status(self.get_http_status())
            .header(ContentType::JSON)
            .sized_body(err_response.len(), Cursor::new(err_response))
            .ok()
    }
}
