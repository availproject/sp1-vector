// Length of an Avail validator (pubkey + weight).
pub const VALIDATOR_LENGTH: usize = PUBKEY_LENGTH + WEIGHT_LENGTH;

// Length of an Avail pubkey.
pub const PUBKEY_LENGTH: usize = 32;

// Length of the weight of an Avail validator.
pub const WEIGHT_LENGTH: usize = 8;

// Blake2b hash size.
pub const HASH_SIZE: usize = 32;

// ABI-encoded length of the header range outputs.
pub const HEADER_OUTPUTS_LENGTH: usize = 32 * 9;

// ABI-encoded length of the rotate outputs.
pub const ROTATE_OUTPUTS_LENGTH: usize = 32 * 3;

// ABI-encoded length of final proof output.
pub const PROOF_OUTPUT_LENGTH: usize = 544;
