# Query Service

Whenever a new data root commitment is stored on-chain, the merkle proofs need to be made available for end-users to prove the data root's of blocks within those data commitments. This service listens for data root commitment events on-chain and stores the merkle proofs for each data root in the range, which is then exposed via a separate endpoint.

The indexed contracts are configured in [deployments.json](./query/app/utils/deployments.json).

## RPC Queries

### Query for `dataRoot` Proof Data

Querying with a block number.

```
https://vectorx-query.succinct.xyz/api?chainName=hex&contractChainId=11155111&contractAddress=0xbc281367e1F2dB1c3e92255AA2F040B1c642ec75&blockNumber=247230
```

Example response:

```json
{
  "data": {
    "blockNumber": 247230,
    "rangeHash": "0xafad54e98bdaebacc1f220dd919dda48b84ed0689906c288a4d93dae1ae9d7c5",
    ...
  }
}
```

Querying with a block hash.

```
https://vectorx-query.succinct.xyz/api?chainName=hex&contractChainId=11155111&contractAddress=0xbc281367e1F2dB1c3e92255AA2F040B1c642ec75&blockHash=0xad664ed32323c70e9c19333f6d7d6f855719f439bc0cb4cd92d89138c252d560
```

Example response:

```json
{
  "data": {
    "rangeHash": "0xafad54e98bdaebacc1f220dd919dda48b84ed0689906c288a4d93dae1ae9d7c5",
    "dataCommitment": "0x7b0f5743191b390b3ba21cdda41b3940b37566a9f336b9e37cf0ad94c937242a",
    ...
  }
}
```

### Health of the `VectorX` contract

Querying for the health of the VectorX contract deployed on Sepolia (chain ID: 11155111) at address 0xbc281367e1F2dB1c3e92255AA2F040B1c642ec75.

```
https://vectorx-query.succinct.xyz/api/health?chainName=hex&contractChainId=11155111&contractAddress=0xbc281367e1F2dB1c3e92255AA2F040B1c642ec75
```

Example response:

```json
{"data":{"logEmitted":true,"ethBlocksSinceLastLog":35,"lastLogTimestamp":1717707768,"blocksBehindHead":50}}
```

Note: If `logEmitted` is false, the contract has not emitted a log in at least the last `ethBlocksSinceLastLog` blocks.

### Range of the `VectorX` contract

Querying for the range of the VectorX contract deployed on Sepolia (chain ID: 11155111) at address 0xbc281367e1F2dB1c3e92255AA2F040B1c642ec75.

```
https://vectorx-query.succinct.xyz/api/range?contractChainId=11155111&contractAddress=0xbc281367e1F2dB1c3e92255AA2F040B1c642ec75
```

Example response:

```json
{"data":{"start":63091,"end":304710}}
```

## Launch the Query Service

Update [query/.env](./query/.env) with the corresponding variables from [.env.example](./.env.example). Then launch the service with:

```
npm run dev
```
