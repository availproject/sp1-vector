# SP1 Vector

Implementation of zero-knowledge proof circuits for [Vector](https://blog.availproject.org/data-attestation-bridge/), Avail's Data Attestation Bridge in SP1.

**[Docs](https://succinctlabs.github.io/sp1-vector)**

## Building the program ELF

The zkVM guest program lives in [`program/`](./program) and is compiled to a RISC-V ELF
that is committed at [`elf/vector-elf`](./elf/vector-elf) (it is embedded into the host binaries
via `include_bytes!` in [`script/src/lib.rs`](./script/src/lib.rs)). The ELF determines the
program verification key (vkey), so it must be rebuilt reproducibly whenever the program or the
SP1 version changes.

### Prerequisites

- The SP1 toolchain (`sp1up`): `curl -L https://sp1up.succinct.xyz | bash && sp1up`
- [Docker](https://docs.docker.com/get-docker/) installed and running (for reproducible builds)

### Reproducible build (recommended)

Reproducible builds run the compilation inside the pinned `ghcr.io/succinctlabs/sp1` Docker
image, so the resulting ELF — and therefore the vkey — is bit-for-bit reproducible across
machines. Run from the `program/` directory:

```bash
cd program
cargo prove build --docker --tag v6.3.0 --elf-name vector-elf --output-directory ../elf
```

This overwrites `elf/vector-elf`. The `--tag` must match the SP1 version pinned in
[`Cargo.toml`](./Cargo.toml) (`sp1-sdk` / `sp1-build` / `sp1-zkvm`).

> A plain `cargo prove build` (without `--docker`) also produces a working ELF, but it is **not**
> reproducible (toolchain/host differences change the bytes), so it must not be used for the
> committed ELF that backs the on-chain vkey.

### Regenerating the vkey and genesis parameters

After rebuilding the ELF, regenerate the verification key and genesis parameters from the repo root:

```bash
cargo run --bin vkey      # prints SP1_VECTOR_PROGRAM_VKEY
cargo run --bin genesis   # prints genesis parameters (height, header, authority set, vkey, ...)
```

The printed `SP1_VECTOR_PROGRAM_VKEY` must be set on the `SP1Vector` contract.
