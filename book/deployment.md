# Deployment

## Overview

Here's how to deploy an SP1 Vector contract for an Avail chain.

## Steps

1. To deploy an SP1 Vector contract for an Avail chain do the following.

    Get the genesis parameters for the `SP1Vector` contract.

    ```shell
    cd script

    # Example with Avail Turing Testnet.
    AVAIL_URL=wss://turing-rpc.avail.so/ws cargo run --bin genesis --release
    ```

2. Add the genesis parameters to `/contracts/.env` mirroring `contracts/.env.example`.

    | Parameter | Description |
    |-----------|-------------|
    | GENESIS_HEIGHT | The block height of the genesis block for the Avail chain |
    | GENESIS_HEADER | The header of the genesis block for the Avail chain |
    | GENESIS_AUTHORITY_SET_ID | The ID of the initial authority set for the Avail chain |
    | GENESIS_AUTHORITY_SET_HASH | The hash of the initial authority set for the Avail chain |
    | SP1_VECTOR_PROGRAM_VKEY | The verification key for the SP1 Vector program |
    | HEADER_RANGE_COMMITMENT_TREE_SIZE | The size of the Merkle tree used for header range commitments (Default 1024) |


3. Deploy the `SP1Vector` contract with genesis parameters.
    ```shell
    cd ../contracts

    forge install

    SP1_PROVER={mock, network} CHAINS=sepolia forge script script/Deploy.s.sol --private-key $PRIVATE_KEY --multi --broadcast --verify
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
    # If you're generating proofs on the Succinct Network, set NETWORK_PRIVATE_KEY to the private key of the account you want to use.
    export NETWORK_PRIVATE_KEY=<NETWORK_PRIVATE_KEY>
    # If you're using a custom endpoint, set NETWORK_RPC_URL to the URL of the endpoint you want to use.
    export NETWORK_RPC_URL=<NETWORK_RPC_URL>
    # If you're generating proofs in mock mode, set SP1_PROVER to "mock".
    export SP1_PROVER={mock}
    ```

5. Run the SP1 Vector operator to update the LC continuously.

    ```
    cd ../script

    AVAIL_URL=wss://turing-rpc.avail.so/ws AVAIL_CHAIN_ID=turing CHAIN_ID=11155111 RPC_URL=https://ethereum-sepolia.publicnode.com/ CONTRACT_ADDRESS=<SP1_VECTOR_ADDRESS> VECTORX_QUERY_URL=https://vectorx-query.succinct.xyz
    cargo run --bin operator --release
    ```

## Demo Contract

An example contract using SP1 Vector can be found on Sepolia [here](https://sepolia.etherscan.io/address/0x04819f50EE813a8f6F6ba28288551c4339fDC881).