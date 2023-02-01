use super::{rocket_launcher, signer::Signer, util::*, SignRequest, SignResponse, XpubResponse};
use bdk::blockchain::ElectrumBlockchain;
use bdk::database::MemoryDatabase;
use bdk::electrum_client::Client as ElectrumClient;
use bdk::signer::{SignOptions, SignerOrdering};
use bdk::wallet::AddressIndex;
use bdk::{KeychainKind, SyncOptions, Wallet};
use bitcoin::hashes::{Hash, HashEngine};
use bitcoin::network::constants::Network;
use bitcoin::secp256k1::Secp256k1;
use bitcoin::util::bip32::{ChildNumber, ExtendedPrivKey};
use bitcoin::util::taproot::TapTweakHash;
use rand::Rng;
use rand_chacha::ChaCha20Rng;
use rocket::http::{ContentType, Status};
use rocket::local::blocking::Client as ApiClient;
use schnorr_fun::fun::marker::{Secret, Zero};
use schnorr_fun::fun::{KeyPair, Point, Scalar};
use schnorr_fun::{musig, Message};
use std::sync::Arc;

#[test]
fn test_message() {
    let client = ApiClient::tracked(rocket_launcher()).unwrap();

    // Client gets the server xpub
    let response = client.get("/xpub").dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::JSON));
    let r: XpubResponse = response.into_json().unwrap();
    assert_eq!(r.xpub.to_string(), "tpubD8ew5PYUhsq1xF9ysDA2fS2Ux66askpbns89XS3wuehFXpbZEVjtCHH1PUhj6KAfCs4iCx5wKgswv1n3we2ZHEs2sP5pw9PnLsCFwiVgdjw".to_string());
    let server_xpub = r.xpub;

    // Client generates xprv
    let seed = [0u8; 16];
    let network = Network::Testnet;
    let client_xprv = ExtendedPrivKey::new_master(network, &seed).unwrap();

    // Client derives client keypair
    let secp = Secp256k1::new();
    let client_derivation_path: Vec<ChildNumber> = vec![];
    let client_xprv = client_xprv
        .derive_priv(&secp, &client_derivation_path)
        .unwrap();
    let client_seckey = Scalar::from_slice_mod_order(&client_xprv.to_priv().to_bytes())
        .unwrap()
        .non_zero()
        .unwrap();
    let client_pubkey =
        Point::from_slice(&client_xprv.to_keypair(&secp).public_key().serialize()).unwrap();
    let client_keypair = KeyPair::new(client_seckey.clone());

    // Client decides the derivation path
    let server_derivation_path: Vec<ChildNumber> = vec![];

    // Client derives server pubkey
    let server_xpub = server_xpub
        .derive_pub(&secp, &server_derivation_path)
        .unwrap();
    let server_pubkey = Point::from_slice(&server_xpub.to_pub().to_bytes()).unwrap();

    // Client creates musig ctx
    let musig = musig::new_with_synthetic_nonces::<sha2::Sha256, rand::rngs::ThreadRng>();

    // Client aggregates keys
    let agg_key = musig
        .new_agg_key(vec![client_pubkey, server_pubkey])
        .into_xonly_key();

    // Client tweak key
    let mut eng = TapTweakHash::engine();
    eng.input(&agg_key.agg_public_key().to_bytes()[1..]);
    let hash = TapTweakHash::from_engine(eng).as_hash();
    let tweak = Scalar::<Secret, Zero>::from_slice_mod_order(hash.as_ref()).unwrap();
    let agg_key = agg_key.tweak(tweak).unwrap();

    // Client generates the session id
    let session_id = rand::thread_rng().gen::<[u8; 32]>();

    // Client generates the nonce
    let mut nonce_rng: ChaCha20Rng = musig.seed_nonce_rng(&agg_key, &client_seckey, &session_id);
    let client_nonce = musig.gen_nonce(&mut nonce_rng);
    let client_public_nonce = client_nonce.public();

    // Client choose message
    let message_str = "aabbccddeeff";
    let message_bytes = hex::decode(message_str.clone()).unwrap();

    // Client calls sign
    let req = SignRequest {
        message: message_str.to_string(),
        client_public_nonce,
        client_pubkey,
        server_derivation_path,
    };
    let req = serde_json::to_string(&req).unwrap();
    let response = client
        .post("/sign")
        .body(&req)
        .header(ContentType::JSON)
        .dispatch();
    assert_eq!(response.status(), Status::Ok);
    assert_eq!(response.content_type(), Some(ContentType::JSON));
    let r: SignResponse = response.into_json().unwrap();

    // Client starts the signing session
    let nonces = vec![client_public_nonce, r.server_public_nonce];
    let message = Message::raw(&message_bytes);
    let session = musig.start_sign_session(&agg_key, nonces, message);

    // Client verifies the server partial signature
    assert!(musig.verify_partial_signature(&agg_key, &session, 1, r.server_partial_signature));

    // Client signs
    let index = 0;
    let client_partial_signature =
        musig.sign(&agg_key, &session, index, &client_keypair, client_nonce);
    assert!(musig.verify_partial_signature(&agg_key, &session, 0, client_partial_signature));

    // Client combines the signature
    let sig = musig.combine_partial_signatures(
        &agg_key,
        &session,
        [r.server_partial_signature, client_partial_signature],
    );

    // Check it's a valid normal Schnorr signature
    assert!(musig
        .schnorr
        .verify(&agg_key.agg_public_key(), message, &sig));
}

#[test]
fn test_tx() {
    let apiclient = ApiClient::tracked(rocket_launcher()).unwrap();

    // Client generates xprv
    let seed = [0u8; 16];
    let network = Network::Testnet;
    let client_xprv = ExtendedPrivKey::new_master(network, &seed).unwrap();

    let signer = Signer::new(client_xprv, &apiclient);

    let client_path: Vec<ChildNumber> = vec![];
    let server_path: Vec<ChildNumber> = vec![];
    let desc_str = signer.derive_descriptor(&client_path, &server_path);

    let (bitcoind, electrs) = setup();
    let electrum_url = electrs.electrum_url.clone();

    let electrum_client = ElectrumClient::new(&electrum_url).unwrap();
    let blockchain = ElectrumBlockchain::from(electrum_client);
    let mut wallet = Wallet::new(
        &desc_str,
        None,
        bitcoin::Network::Regtest,
        MemoryDatabase::default(),
    )
    .unwrap();

    let address = wallet.get_address(AddressIndex::New).unwrap();

    wallet.sync(&blockchain, SyncOptions::default()).unwrap();
    assert_eq!(wallet.get_balance().unwrap().confirmed, 0);

    let sats = 10_000;
    let s = address.address.to_string();
    let txid = sendtoaddress(&bitcoind.client, sats, &s);

    generate(&bitcoind.client, 1);
    electrs.trigger().unwrap();
    wait_tx(&wallet, &blockchain, &txid);
    assert_eq!(wallet.get_balance().unwrap().confirmed, sats);

    let send_to = wallet.get_address(AddressIndex::New).unwrap();
    let (mut psbt, details) = {
        let mut builder = wallet.build_tx();
        builder.add_recipient(send_to.script_pubkey(), 1_000);
        builder.finish().unwrap()
    };

    wallet.add_signer(
        KeychainKind::External,
        SignerOrdering(100),
        Arc::new(signer),
    );

    let finalized = wallet.sign(&mut psbt, SignOptions::default()).unwrap();
    assert!(finalized);
    let tx = psbt.extract_tx();
    let txhex = hex::encode(bitcoin::consensus::encode::serialize(&tx));
    assert!(testmempoolaccept(&bitcoind.client, &txhex));
    let txid = broadcast(&bitcoind.client, &txhex);

    generate(&bitcoind.client, 1);
    electrs.trigger().unwrap();
    wait_tx(&wallet, &blockchain, &txid);
    let fee = details.fee.unwrap();
    assert_eq!(wallet.get_balance().unwrap().confirmed, sats - fee);
}
