# Taproot Cosigner Fun

**Disclaimer**: this is for fun and for experimenting, **not for production use**.

A Cosigner Server that allows any client to create an aggregated key between the server and the client using [MuSig2](https://eprint.iacr.org/2020/1261), and later to create aggregated Schnorr signatures.

It can be used to create a Taproot output where the key spend path is an aggregated key between the server and the client, while the script path is arbitrarily chosen by the client.

Once such outputs have been created and funded,
the client can create PSBTs spending those.
Then the server will cooperate to create the aggregated signatures for them.

This project can be used to demo a Taproot key spend.

### Run the server

    export XPRV_FILENAME=server-xprv-filename
    cargo run

Once the server is running, for instance you can get its xpub

    curl http://127.0.0.1:8000/xpub | jq .xpub

### Run the tests

    cargo test

You can set the env variables `BITCOIND_EXEC` and `ELECTRS_EXEC` to use different binaries.

For a e2e example, see `test_tx`.

## Manual tests with a CLI wallet

The server is running and reachable at `COSIGNER_URL` (e.g. at http://127.0.0.1:8000).

The wallet CLI is available at:

    cargo run --bin cli -- -h

Generate the client extended private `XPRV` key and create the wallet

    cargo run --bin cli -- -x $XPRV descriptor

Get a wallet address

    cargo run --bin cli -- -x $XPRV address

Fund the wallet, e.g. here we use Bitcoin Core

    bitcoin-cli sendtoaddress 0.0001

Wait until the transaction has been received and the funds appear in the wallet

    cargo run --bin cli -- -x $XPRV pending-balance
    cargo run --bin cli -- -x $XPRV balance

Create the transaction

    PSBTC=$(cargo run --bin cli -- -x $XPRV create $ADDRESS $SATOSHI)

Sign the transaction

    PSBTS=$(cargo run --bin cli -- -x $XPRV sign $PSBTC)

Send the transaction

    TXID=$(cargo run --bin cli -- -x $XPRV send $PSBTS)

Check the transcation on the explorer

    curl https://fbbe.info/testnet/t/${TXID} | less

## TODOs

* [ ] Clean up the code
* [x] CLI to receive funds and spend them
* [ ] Support for non-empty bip32 paths
* [ ] Support for non-empty script paths in descriptor
* [ ] Support for aggregated xpub in descriptor
* [ ] Testnet example
* [ ] Mainnet example 

## Copyright

[MIT](LICENSE)

## Acknowledgement

This project uses extensively [secp256kfun](https://github.com/LLFourn/secp256kfun) by LLoyd Fournier.
`secp256kfun` is a great library for this kind of experimental projects, have a look at it!
