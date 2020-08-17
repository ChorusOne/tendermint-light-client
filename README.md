# Tendermint light client
Implementation of tendermint light client in rust compilable to wasm. The code is heavily inspired from [tendermint-rs](https://github.com/informalsystems/tendermint-rs).
It is optimized to run in a constrained environment of a smart contract. Refer [here](#how-it-works) to know how it works under the hood.

## Compilation

### Prerequisites
1. Rust 1.42.0 or higher
2. Two target need to be installed
    1. `wasm32-unknown-unknown` to compile it into wasm and integrate it with CosmWasm
    2. `x86_64-apple-darwin` to run tests

### Compile in wasm
Run `make wasm` in project directory. This will produce a file `/target/wasm32-unknown-unknown/release/tendermint_light_client.wasm`
To produce a size optimized build, you need to run `make wasm-optimized`.

### Testing
Run `cargo test`

### Note
This library uses a fork of [signatory](https://github.com/tendermint/signatory) at [here](https://github.com/ChorusOne/signatory). This was done to 
resolve version conflict of `ed25519-dalek` between `signatory` crate and `substrate` node.

## How it works?
Tendermint light client is implemented according to the specification found [here](https://docs.tendermint.com/master/spec/consensus/light-client/verification.html).
Since this light client runs in a constrained environment without access to I/O, the bisection part of the specification is not implemented, instead only `verifySingle` function that operates only on the local trusted state. 
