# Components

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
