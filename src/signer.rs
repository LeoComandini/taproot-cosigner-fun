use super::{rocket_launcher, SignRequest, SignResponse, XpubResponse};
use bdk::signer::{InputSigner, SignOptions, SignerCommon, SignerError, SignerId};
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::secp256k1::{All, Secp256k1};
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey, ExtendedPubKey};
use bitcoin::util::psbt;
use bitcoin::util::schnorr::SchnorrSig;
use bitcoin::util::sighash::{Prevouts, SighashCache};
use bitcoin::util::taproot::TapTweakHash;
use bitcoin::{TxOut, XOnlyPublicKey};
use rand::rngs::ThreadRng;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rocket::http::{ContentType, Status};
use rocket::local::blocking::Client as ApiClient;
use schnorr_fun::fun::marker::{EvenY, Secret, Zero};
use schnorr_fun::fun::{KeyPair, Point, Scalar};
use schnorr_fun::musig::{AggKey, MuSig};
use schnorr_fun::nonce::{GlobalRng, Synthetic};
use schnorr_fun::{musig, Message};
use sha2::Sha256;

/// Signer that can produce signatures for an aggregated key between the client and the server
#[derive(Debug)]
pub struct Signer {
    client_xprv: ExtendedPrivKey,
    server_xpub: ExtendedPubKey,
    secp: Secp256k1<All>,
    cosigner_url: String,
}

impl Signer {
    /// Create a new signer using a extended private key and fetching the server xpub from the
    /// server.
    #[cfg(test)]
    pub fn new_test(client_xprv: ExtendedPrivKey, apiclient: &ApiClient) -> Self {
        let r = apiclient.get("/xpub").dispatch();
        let r: XpubResponse = r.into_json().unwrap();
        Self {
            client_xprv,
            server_xpub: r.xpub,
            secp: Secp256k1::new(),
            cosigner_url: "".to_string(),
        }
    }

    #[allow(unused)]
    pub fn new(client_xprv: ExtendedPrivKey, cosigner_url: &str) -> Self {
        let s = format!("{}/xpub", cosigner_url);
        let r: XpubResponse = ureq::get(&s).call().unwrap().into_json().unwrap();
        Self {
            client_xprv,
            server_xpub: r.xpub,
            secp: Secp256k1::new(),
            cosigner_url: cosigner_url.to_string(),
        }
    }

    fn derive_client_seckey(&self, path: &Vec<ChildNumber>) -> Scalar {
        let xprv = self.client_xprv.derive_priv(&self.secp, &path).unwrap();
        let seckey_bytes = xprv.to_priv().to_bytes();
        Scalar::from_slice_mod_order(&seckey_bytes)
            .unwrap()
            .non_zero()
            .unwrap()
    }

    fn derive_client_keypair(&self, path: &Vec<ChildNumber>) -> KeyPair {
        KeyPair::new(self.derive_client_seckey(path))
    }

    fn derive_client_pubkey(&self, path: &Vec<ChildNumber>) -> Point {
        self.derive_client_keypair(path).public_key()
    }

    fn derive_server_pubkey(&self, path: &Vec<ChildNumber>) -> Point {
        let xpub = self.server_xpub.derive_pub(&self.secp, path).unwrap();
        let pubkey_bytes = xpub.to_pub().to_bytes();
        Point::from_slice(&pubkey_bytes).unwrap()
    }

    fn musig(&self) -> MuSig<Sha256, Synthetic<Sha256, GlobalRng<ThreadRng>>> {
        musig::new_with_synthetic_nonces::<sha2::Sha256, rand::rngs::ThreadRng>()
    }

    fn derive_aggregated_key(
        &self,
        client_path: &Vec<ChildNumber>,
        server_path: &Vec<ChildNumber>,
    ) -> AggKey<EvenY> {
        let client_pubkey = self.derive_client_pubkey(client_path);
        let server_pubkey = self.derive_server_pubkey(server_path);
        let musig = self.musig();
        musig
            .new_agg_key(vec![client_pubkey, server_pubkey])
            .into_xonly_key()
    }

    /// Derive a taproot descriptor where the key spend path is the aggregated key between the
    /// client and the server.
    pub fn derive_descriptor(
        &self,
        client_path: &Vec<ChildNumber>,
        server_path: &Vec<ChildNumber>,
    ) -> String {
        let agg_key_bytes = self
            .derive_aggregated_key(client_path, server_path)
            .agg_public_key()
            .to_bytes();
        format!("tr({})", hex::encode(agg_key_bytes))
    }
}

impl SignerCommon for Signer {
    fn id(&self, _secp: &Secp256k1<All>) -> SignerId {
        SignerId::Dummy(0)
    }
}

impl InputSigner for Signer {
    fn sign_input(
        &self,
        psbt: &mut psbt::PartiallySignedTransaction,
        input_index: usize,
        _sign_options: &SignOptions,
        _secp: &Secp256k1<All>,
    ) -> Result<(), SignerError> {
        let prevouts: Vec<TxOut> = psbt
            .inputs
            .iter()
            .enumerate()
            .map(|(index, input)| {
                if let Some(wutxo) = &input.witness_utxo {
                    wutxo.clone()
                } else if let Some(tx) = &input.non_witness_utxo {
                    let prevout_index = psbt.unsigned_tx.input[index].previous_output.vout as usize;
                    tx.output[prevout_index].clone()
                } else {
                    panic!("Either witness_utxo or non_witness_utxo must be Some")
                }
            })
            .collect();

        let input = &mut psbt.inputs[input_index];
        let path = vec![];
        let agg_key = self.derive_aggregated_key(&path, &path);
        let internal_key =
            XOnlyPublicKey::from_slice(&agg_key.agg_public_key().to_bytes()[1..]).unwrap();

        // tweak key
        let mut eng = TapTweakHash::engine();
        eng.input(&agg_key.agg_public_key().to_bytes()[1..]);
        let hash = TapTweakHash::from_engine(eng).as_hash();
        let tweak = Scalar::<Secret, Zero>::from_slice_mod_order(hash.as_ref()).unwrap();
        let agg_key = agg_key.tweak(tweak).unwrap();

        if let Some((_, (_, p))) = input.tap_key_origins.get(&internal_key) {
            // TODO: handle non-empty paths
            assert_eq!(p.len(), 0);
            let client_keypair = self.derive_client_keypair(&path);
            let musig = self.musig();
            let session_id = rand::thread_rng().gen::<[u8; 32]>();

            let mut nonce_rng: ChaCha20Rng =
                musig.seed_nonce_rng(&agg_key, &client_keypair.secret_key(), &session_id);
            let client_nonce = musig.gen_nonce(&mut nonce_rng);
            let client_public_nonce = client_nonce.public();

            let mut cache = SighashCache::new(&psbt.unsigned_tx);
            let prevouts = Prevouts::All(&prevouts[..]);
            let sig_hash_type = input.schnorr_hash_ty().unwrap();
            let sig_hash = cache
                .taproot_key_spend_signature_hash(input_index, &prevouts, sig_hash_type)
                .unwrap();
            let sig_hash_bytes = sig_hash.into_inner();
            let message = Message::raw(&sig_hash_bytes[..]);
            let message_str = hex::encode(message.bytes.as_inner());
            let req = SignRequest {
                message: message_str.to_string(),
                client_public_nonce,
                client_pubkey: client_keypair.public_key(),
                server_derivation_path: path.clone(),
            };
            let r: SignResponse = if cfg!(test) {
                let req = serde_json::to_string(&req).unwrap();
                let apiclient = ApiClient::tracked(rocket_launcher()).unwrap();
                let response = apiclient
                    .post("/sign")
                    .body(&req)
                    .header(ContentType::JSON)
                    .dispatch();
                assert_eq!(response.status(), Status::Ok);
                assert_eq!(response.content_type(), Some(ContentType::JSON));
                response.into_json().unwrap()
            } else {
                let s = format!("{}/sign", self.cosigner_url);
                ureq::post(&s).send_json(&req).unwrap().into_json().unwrap()
            };

            let nonces = vec![client_public_nonce, r.server_public_nonce];
            let session = musig.start_sign_session(&agg_key, nonces, message);
            let index = 1;
            assert!(musig.verify_partial_signature(
                &agg_key,
                &session,
                index,
                r.server_partial_signature
            ));
            let index = 0;
            let client_partial_signature =
                musig.sign(&agg_key, &session, index, &client_keypair, client_nonce);
            assert!(musig.verify_partial_signature(
                &agg_key,
                &session,
                index,
                client_partial_signature
            ));
            let sig = musig.combine_partial_signatures(
                &agg_key,
                &session,
                [r.server_partial_signature, client_partial_signature],
            );
            assert!(musig
                .schnorr
                .verify(&agg_key.agg_public_key(), message, &sig));

            let sig = SchnorrSig::from_slice(&sig.to_bytes()).unwrap();
            input.tap_key_sig = Some(sig);
        }
        Ok(())
    }
}
