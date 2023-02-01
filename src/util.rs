use bdk::blockchain::ElectrumBlockchain;
use bdk::database::MemoryDatabase;
use bdk::{SyncOptions, Wallet};
use bitcoin::util::amount::Denomination;
use bitcoin::{Amount, Txid};
use electrsd::bitcoind::bitcoincore_rpc::{Client as RpcClient, RpcApi};
use electrsd::bitcoind::BitcoinD;
use electrsd::ElectrsD;
use std::str::FromStr;

pub fn setup() -> (BitcoinD, ElectrsD) {
    let args = vec![
        "-fallbackfee=0.0001",
        "-dustrelayfee=0.00000001",
        "-regtest",
    ];
    let network = "regtest";
    let mut conf = electrsd::bitcoind::Conf::default();
    conf.args = args;
    conf.p2p = electrsd::bitcoind::P2P::Yes;
    conf.network = network;

    let exe_b = std::env::var("BITCOIND_EXEC")
        .unwrap_or(electrsd::bitcoind::downloaded_exe_path().unwrap());
    let node = BitcoinD::with_conf(&exe_b, &conf).unwrap();

    generate(&node.client, 101);

    let args = vec!["-v"];
    let mut conf = electrsd::Conf::default();
    conf.args = args;
    conf.http_enabled = false;
    conf.network = network;

    let exe_e = std::env::var("ELECTRS_EXEC").unwrap_or(electrsd::downloaded_exe_path().unwrap());
    let electrs = ElectrsD::with_conf(&exe_e, &node, &conf).unwrap();
    (node, electrs)
}

pub fn generate(rpc: &RpcClient, n: u32) {
    let address: String = rpc
        .call("getnewaddress", &["".into(), "bech32m".into()])
        .unwrap();
    let _: Vec<String> = rpc
        .call("generatetoaddress", &[n.into(), address.into()])
        .unwrap();
}

pub fn sendtoaddress(rpc: &RpcClient, sats: u64, address: &str) -> String {
    let btc = Amount::from_sat(sats).to_string_in(Denomination::Bitcoin);
    let txid = rpc
        .call("sendtoaddress", &[address.into(), btc.into()])
        .unwrap();
    txid
}

pub fn testmempoolaccept(rpc: &RpcClient, txhex: &str) -> bool {
    #[derive(serde::Deserialize, Debug)]
    struct TestmempoolacceptResult {
        allowed: bool,
        #[allow(unused)]
        #[serde(rename = "reject-reason")]
        reject_reason: Option<String>,
    }
    let r: Vec<TestmempoolacceptResult> = rpc
        .call("testmempoolaccept", &[vec![txhex].into()])
        .unwrap();
    r.iter().all(|e| e.allowed)
}

pub fn broadcast(rpc: &RpcClient, txhex: &str) -> String {
    rpc.call("sendrawtransaction", &[txhex.into()]).unwrap()
}

fn has_tx(wallet: &Wallet<MemoryDatabase>, txid: &Txid) -> bool {
    match wallet.get_tx(&txid, false) {
        Ok(Some(_)) => true,
        _ => false,
    }
}

pub fn wait_tx(wallet: &Wallet<MemoryDatabase>, blockchain: &ElectrumBlockchain, txid: &str) {
    let txid = Txid::from_str(txid).unwrap();
    for _ in 0..30 {
        wallet.sync(blockchain, SyncOptions::default()).unwrap();
        if has_tx(wallet, &txid) {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    assert!(false, "Transaction not received");
}
