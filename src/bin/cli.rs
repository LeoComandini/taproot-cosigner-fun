use bdk::blockchain::ElectrumBlockchain;
use bdk::database::MemoryDatabase;
use bdk::electrum_client::{Client as ElectrumClient, ElectrumApi};
use bdk::signer::{SignOptions, SignerOrdering};
use bdk::wallet::AddressIndex;
use bdk::{KeychainKind, SyncOptions, Wallet};
use bitcoin::consensus::encode::{deserialize, serialize};
use bitcoin::util::bip32::ExtendedPrivKey;
use bitcoin::Network;
use bitcoin::{psbt::PartiallySignedTransaction, Address};
use clap::{Parser, Subcommand};
use std::str::FromStr;
use std::sync::Arc;
use taproot_cosigner_fun::signer::Signer;

/// Simple wallet to create and use a wallet with a Taproot cosigner
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The user extended private key
    #[arg(short, long)]
    xprv: ExtendedPrivKey,

    /// The Electrum Server URL
    #[clap(short, long, default_value = "ssl://electrum.blockstream.info:60002")]
    electrum_url: String,

    /// The Cosigner Server URL
    #[arg(short, long, default_value = "http://127.0.0.1:8000")]
    cosigner_url: String,

    /// Network
    #[arg(short, long, value_enum, default_value = "testnet")]
    network: Network,

    #[clap(subcommand)]
    subcommand: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Get a new wallet address
    Address,

    /// Get the wallet unconfirmed balance
    PendingBalance,

    /// Get the wallet confirmed balance
    Balance,

    /// Get the wallet descriptor
    Descriptor,

    /// Create a simple transaction
    Create { address: String, satoshi: u64 },

    /// Sign a psbt
    Sign { psbt: String },

    /// Finalize and broadcast a transaction
    Send { psbt: String },
}

fn main() {
    let args = Args::parse();

    let client_path = vec![];
    let server_path = vec![];

    let signer = Signer::new(args.xprv.clone(), "http://127.0.0.1:8000");
    let descriptor = signer.derive_descriptor(&client_path, &server_path);

    let electrum_client = ElectrumClient::new(&args.electrum_url).unwrap();
    let blockchain = ElectrumBlockchain::from(electrum_client);
    let mut wallet =
        Wallet::new(&descriptor, None, args.network, MemoryDatabase::default()).unwrap();

    wallet.add_signer(
        KeychainKind::External,
        SignerOrdering(100),
        Arc::new(signer),
    );

    match args.subcommand {
        Command::Descriptor => println!("{}", descriptor),
        Command::Address => println!("{}", wallet.get_address(AddressIndex::New).unwrap().address),
        Command::PendingBalance => {
            wallet.sync(&blockchain, SyncOptions::default()).unwrap();
            let balance = wallet.get_balance().unwrap();
            println!("{}", balance.trusted_pending + balance.untrusted_pending);
        }
        Command::Balance => {
            wallet.sync(&blockchain, SyncOptions::default()).unwrap();
            println!("{}", wallet.get_balance().unwrap().confirmed);
        }
        Command::Create { address, satoshi } => {
            // FIXME: check network
            let script_pubkey = Address::from_str(&address).unwrap().script_pubkey();
            wallet.sync(&blockchain, SyncOptions::default()).unwrap();
            let (psbt, _details) = {
                let mut builder = wallet.build_tx();
                builder.add_recipient(script_pubkey, satoshi);
                builder.finish().unwrap()
            };
            println!("{}", base64::encode(&serialize(&psbt)));
        }
        Command::Sign { psbt } => {
            let psbt = base64::decode(&psbt).unwrap();
            let mut psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();
            assert!(wallet.sign(&mut psbt, SignOptions::default()).unwrap());
            println!("{}", base64::encode(&serialize(&psbt)));
        }
        Command::Send { psbt } => {
            let psbt = base64::decode(&psbt).unwrap();
            let psbt: PartiallySignedTransaction = deserialize(&psbt).unwrap();
            let tx = serialize(&psbt.extract_tx());
            let electrum_client = ElectrumClient::new(&args.electrum_url).unwrap();
            let txid = electrum_client.transaction_broadcast_raw(&tx).unwrap();
            println!("{}", txid);
        }
    }
}
