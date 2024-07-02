# SP1 Vector

## Overview

Implementation of [Vector X](https://github.com/succinctlabs/vectorx) in Rust for SP1.

- `/program`: The SP1 Vector program.
- `/primitives`: Libraries for types and helper functions used in the program.
- `/script`: Scripts for getting the contract's genesis parameters and deploying the operator to 
    update the light client.
- `/services`: RPC fetcher for the `script` + the justification indexer.
- `/contracts`: The contract's source code and deployment scripts. 
- `/query`: Contains the logic for querying data root proofs from the contracts. Automatically deploys to https://vectorx-query.succinct.xyz.

## [Query Data Root Proofs](./query/README.md)

## Demo Contract

An example contract using SP1 Vector can be found on Sepolia [here](https://sepolia.etherscan.io/address/0x04819f50EE813a8f6F6ba28288551c4339fDC881).

## Deploying SP1 Vector

### Components

An SP1 Vector implementation has a few key components:
- An `SP1Vector` contract. Contains the logic for verifying SP1 Vector proofs, storing the
latest data from the Avail chain, including the headers and data commitments. Matches the interface
of the existing [VectorX](https://github.com/succinctlabs/vectorx/blob/main/contracts/src/VectorX.sol) contract so it can be upgraded in-place.
- An `SP1Verifier` contract. Verifies arbitrary SP1 programs. Most chains will have canonical deployments
upon SP1's mainnet launch. Until then, users can deploy their own `SP1Verifier` contracts to verify
SP1 programs on their chain. The SP1 Vector implementation will use the `SP1Verifier` contract to verify
the proofs of the SP1 Vector programs.
- The SP1 Vector program. An SP1 program that verifies the transition between two Avail
headers and computes the data commitment of the intermediate blocks.
- The operator. A Rust script that fetches the latest data from a deployed `SP1Vector` contract and an Avail chain, determines the block to request, requests for/generates a proof, and relays the proof to
the `SP1Vector` contract.

### Deployment

1. To deploy an SP1 Vector contract for an Avail chain do the following.

    Get the genesis parameters for the `SP1Vector` contract.

    ```shell
    cd script

    # Example with Avail Turing Testnet.
    AVAIL_URL=wss://turing-rpc.avail.so/ws cargo run --bin genesis --release
    ```

2. Deploy the `SP1Vector` contract with genesis parameters: `GENESIS_HEIGHT`, `GENESIS_HEADER`, and `GENESIS_AUTHORITY_SET_ID`, `GENESIS_AUTHORITY_SET_HASH`, `SP1_VECTOR_PROGRAM_VKEY` and `HEADER_RANGE_COMMITMENT_TREE_SIZE`.

    Add the genesis parameters to `/contracts/.env` mirroring `contracts/.env.example`.

    ```shell
    # Initialization Parameters
    GENESIS_HEIGHT=
    GENESIS_HEADER=
    GENESIS_AUTHORITY_SET_ID=
    GENESIS_AUTHORITY_SET_HASH=
    SP1_VECTOR_PROGRAM_VKEY=
    HEADER_RANGE_COMMITMENT_TREE_SIZE=
    ```

    ```shell
    cd ../contracts

    forge install

    SP1_PROVER={mock, network} forge script script/Deploy.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --etherscan-api-key $ETHERSCAN_API_KEY --broadcast --verify
    ```

    If you see the following error, add `--legacy` to the command.
    ```shell
    Error: Failed to get EIP-1559 fees    
    ```
3. Your deployed contract address will be printed to the terminal.

    ```shell
    == Return ==
    0: address <SP1_VECTOR_ADDRESS>
    ```

    This will be used when you run the operator in step 5.

4. Export your SP1 Prover Network configuration

    ```shell
    # Export the PRIVATE_KEY you will use to relay proofs.
    export PRIVATE_KEY=<PRIVATE_KEY>

    # Optional
    # If you're using the Succinct network, set SP1_PROVER to "network". Otherwise, set it to "local" or "mock".
    export SP1_PROVER={network|local|mock}
    # Only required if SP1_PROVER is set "network".
    export SP1_PRIVATE_KEY=<SP1_PRIVATE_KEY>
    ```

5. Run the SP1 Vector operator to update the LC continuously.

```
cd ../script

AVAIL_URL=wss://turing-rpc.avail.so/ws AVAIL_CHAIN_ID=turing CHAIN_ID=11155111 RPC_URL=https://ethereum-sepolia.publicnode.com/ CONTRACT_ADDRESS=<SP1_VECTOR_ADDRESS> VECTORX_QUERY_URL=https://vectorx-query.succinct.xyz
 cargo run --bin operator --release
```
