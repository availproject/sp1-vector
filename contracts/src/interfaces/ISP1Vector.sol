// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface ISP1Vector {
    /// @notice Emits event with the inputs of a header range request.
    /// @param trustedBlock The block height of the trusted block.
    /// @param trustedHeader The header hash of the trusted block.
    /// @param authoritySetId The authority set id of trusted block + 1.
    /// @param authoritySetHash The authority set hash of trusted block + 1.
    /// @param targetBlock The block height of the target block.
    event HeaderRangeRequested(
        uint32 trustedBlock, bytes32 trustedHeader, uint64 authoritySetId, bytes32 authoritySetHash, uint32 targetBlock
    );

    /// @notice Emits event with the inputs of a rotate request.
    /// @param currentAuthoritySetId The authority set id of the current authority set.
    /// @param currentAuthoritySetHash The authority set hash of the current authority set.
    event RotateRequested(uint64 currentAuthoritySetId, bytes32 currentAuthoritySetHash);

    /// @notice Emitted when the light client's head is updated.
    event HeadUpdate(uint32 blockNumber, bytes32 headerHash);

    /// @notice Emitted when data + state commitment for range (startBlock, endBlock] are stored.
    /// @param headerRangeCommitmentTreeSize The commitment tree size for the header range.
    event HeaderRangeCommitmentStored(
        uint32 startBlock,
        uint32 endBlock,
        bytes32 dataCommitment,
        bytes32 stateCommitment,
        uint32 headerRangeCommitmentTreeSize
    );

    /// @notice Emitted when a new authority set is stored.
    event AuthoritySetStored(uint64 authoritySetId, bytes32 authoritySetHash);

    /// @notice If the next authority set already exists.
    error NextAuthoritySetExists();

    /// @notice Contract is frozen.
    error ContractFrozen();

    /// @notice Trusted header not found.
    error TrustedHeaderNotFound();

    /// @notice Stored trusted header does not match proof trusted header.
    error TrustedHeaderMismatch();

    /// @notice Authority set not found.
    error AuthoritySetNotFound();

    /// @notice Stored authority set does not match proof authority set.
    error AuthoritySetMismatch();

    /// @notice The authority set id is older than the authority set id of the latest commitHeaderRange.
    error OldAuthoritySetId();

    /// @notice The proof type is not HeaderRangeProof or RotateProof.
    error InvalidProofType();

    /// @notice The merkle tree size does not match the expected size.
    error InvalidMerkleTreeSize();

    /// @notice The trusted block inside the proof does not match the trusted block of the contract.
    error BlockHeightMismatch();

    /// @notice Target block is not greater than the latest block.
    error InvalidTargetBlock();
}
