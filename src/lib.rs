#[macro_use]
extern crate rocket;

mod error;
pub mod signer;
#[cfg(test)]
pub mod util;

use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::util::key::Secp256k1;
use bitcoin::util::taproot::TapTweakHash;
use error::Error;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rocket::serde::json::Json;
use rocket::serde::{Deserialize, Serialize};
use schnorr_fun::binonce::Nonce;
use schnorr_fun::fun::marker::{Public, Secret, Zero};
use schnorr_fun::fun::{KeyPair, Point, Scalar};
use schnorr_fun::{musig, Message};
use std::fs;
use std::str::FromStr;

#[launch]
pub fn rocket_launcher() -> _ {
    rocket::build().mount("/", routes![xpub, sign])
}

fn read_xprv() -> Result<ExtendedPrivKey, Error> {
    let filename = std::env::var("XPRV_FILENAME").unwrap_or("xprv.txt".to_string());
    let mut s = fs::read_to_string(&filename)?;
    if s.ends_with("\n") {
        s.pop();
        if s.ends_with("\r") {
            s.pop();
        }
    }
    Ok(ExtendedPrivKey::from_str(&s)?)
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct XpubResponse {
    pub xpub: ExtendedPubKey,
}

/// Get the server xpub
#[get("/xpub")]
pub fn xpub() -> Result<Json<XpubResponse>, Error> {
    let xprv = read_xprv()?;
    let secp = Secp256k1::new();
    let xpub = ExtendedPubKey::from_priv(&secp, &xprv);
    Ok(Json(XpubResponse { xpub }))
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct SignRequest {
    pub message: String,
    pub client_public_nonce: Nonce,
    pub client_pubkey: Point,
    pub server_derivation_path: Vec<ChildNumber>,
}

impl SignRequest {
    pub fn validate_path(&self) -> Result<(), Error> {
        match self.server_derivation_path.iter().all(|e| e.is_normal()) {
            true => Ok(()),
            false => Err(Error::InvalidDerivationPath),
        }
    }
}

#[derive(Deserialize, Serialize, Debug, PartialEq)]
pub struct SignResponse {
    pub server_public_nonce: Nonce,
    pub server_partial_signature: Scalar<Public, Zero>,
}

/// Obtain a partial signature to aggregate
#[post("/sign", format = "application/json", data = "<req>")]
pub fn sign(req: Json<SignRequest>) -> Result<Json<SignResponse>, Error> {
    let req = req.into_inner();
    let musig = musig::new_with_synthetic_nonces::<sha2::Sha256, rand::rngs::ThreadRng>();
    // derive keypair from server_derivation_path
    let master_xprv = read_xprv()?;
    req.validate_path()?;
    let secp = Secp256k1::new();
    let xprv = master_xprv.derive_priv(&secp, &req.server_derivation_path)?;
    let xpub = ExtendedPubKey::from_priv(&secp, &xprv);
    let server_pubkey =
        Point::from_slice(&xpub.to_pub().to_bytes()).ok_or_else(|| Error::InvalidPubkey)?;
    let server_seckey = Scalar::from_slice_mod_order(&xprv.to_priv().to_bytes())
        .ok_or_else(|| Error::InvalidSeckey)?
        .non_zero()
        .ok_or_else(|| Error::InvalidSeckey)?;
    let server_keypair = KeyPair::new(server_seckey.clone());
    // compute aggregated key
    let agg_key = musig
        .new_agg_key(vec![req.client_pubkey, server_pubkey])
        .into_xonly_key();

    // tweak key
    let mut eng = TapTweakHash::engine();
    eng.input(&agg_key.agg_public_key().to_bytes()[1..]);
    let hash = TapTweakHash::from_engine(eng).as_hash();
    let tweak = Scalar::<Secret, Zero>::from_slice_mod_order(hash.as_ref())
        .expect("fails with negligibile probability");
    let agg_key = agg_key
        .tweak(tweak)
        .expect("fails with negligibile probability");

    // generate nonce
    let session_id = rand::thread_rng().gen::<[u8; 32]>();
    let mut nonce_rng: ChaCha20Rng = musig.seed_nonce_rng(&agg_key, &server_seckey, &session_id);
    let server_nonce = musig.gen_nonce(&mut nonce_rng);
    let server_public_nonce = server_nonce.public();
    // start signing session
    let nonces = vec![req.client_public_nonce, server_public_nonce];
    let message_bytes = hex::decode(req.message)?;
    let message = Message::raw(&message_bytes);
    let session = musig.start_sign_session(&agg_key, nonces, message);
    // sign
    let index = 1;
    let server_sig = musig.sign(&agg_key, &session, index, &server_keypair, server_nonce);

    Ok(Json(SignResponse {
        server_public_nonce,
        server_partial_signature: server_sig,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_serde() {
        let req_json_str = r#"{"message":"deadbeef","client_public_nonce":"020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202","client_pubkey":"020202020202020202020202020202020202020202020202020202020202020202","server_derivation_path":[0]}"#;
        let req = SignRequest {
            message: "deadbeef".to_string(),
            client_public_nonce: Nonce::from_bytes([2u8; 66]).unwrap(),
            client_pubkey: Point::from_bytes([2u8; 33]).unwrap(),
            server_derivation_path: vec![ChildNumber::Normal { index: 0 }],
        };
        assert_eq!(serde_json::to_string(&req).unwrap(), req_json_str);
        let req_from_str: SignRequest = serde_json::from_str(&req_json_str).unwrap();
        assert_eq!(req_from_str, req);

        let resp_json_str = r#"{"server_public_nonce":"020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202","server_partial_signature":"0101010101010101010101010101010101010101010101010101010101010101"}"#;
        let resp = SignResponse {
            server_public_nonce: Nonce::from_bytes([2u8; 66]).unwrap(),
            server_partial_signature: Scalar::from_bytes([1u8; 32]).unwrap(),
        };
        assert_eq!(serde_json::to_string(&resp).unwrap(), resp_json_str);
        let resp_from_str: SignResponse = serde_json::from_str(&resp_json_str).unwrap();
        assert_eq!(resp_from_str, resp);
    }
}
