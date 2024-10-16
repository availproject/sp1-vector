// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import {ISP1Vector} from "./interfaces/ISP1Vector.sol";
import {TimelockedUpgradeable} from "@succinctx/upgrades/TimelockedUpgradeable.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";

/// @notice SP1Vector is a light client for Avail's consensus.
/// @dev The light client tracks both the state of Avail's Grandpa consensus and Vector, Avail's
///     data commitment solution.
/// @dev Ensure that all new storage variables are placed after existing storage variables to avoid
/// storage corruption during upgrades.
contract SP1Vector is ISP1Vector, TimelockedUpgradeable {
    /// @notice Indicator of if the contract is frozen.
    bool public frozen;

    /// @notice The address of the gateway contract.
    /// @dev DEPRECATED: Do not use. Compatibility for upgrades from VectorX.
    address public gateway_deprecated;

    /// @notice The latest block that has been committed.
    uint32 public latestBlock;

    /// @notice The latest authority set id used in commitHeaderRange.
    uint64 public latestAuthoritySetId;

    /// @notice The function for requesting a header range.
    /// @dev DEPRECATED: Do not use. Compatibility for upgrades from VectorX.
    bytes32 public headerRangeFunctionId_deprecated;

    /// @notice The function for requesting a rotate.
    /// @dev DEPRECATED: Do not use. Compatibility for upgrades from VectorX.
    bytes32 public rotateFunctionId_deprecated;

    /// @notice Maps block height to the header hash of the block.
    mapping(uint32 => bytes32) public blockHeightToHeaderHash;

    /// @notice Maps authority set id to the authority set hash.
    mapping(uint64 => bytes32) public authoritySetIdToHash;

    /// @notice Maps block ranges to data commitments. Block ranges are stored as
    ///     keccak256(abi.encode(startBlock, endBlock)).
    mapping(bytes32 => bytes32) public dataRootCommitments;

    /// @notice Maps block ranges to state commitments. Block ranges are stored as
    ///     keccak256(abi.encode(startBlock, endBlock)).
    mapping(bytes32 => bytes32) public stateRootCommitments;

    /// @notice Maps range hashes to the start block of the range. This allows us
    ///     to know the block height of an attestation.
    mapping(bytes32 => uint32) public rangeStartBlocks;

    /// @notice The commitment tree size for the header range.
    uint32 public headerRangeCommitmentTreeSize;

    /// @notice The verification key for the SP1Vector program.
    bytes32 public vectorXProgramVkey;

    /// @notice The deployed SP1 verifier contract.
    ISP1Verifier public verifier;

    /// @notice Approved relayers for the contract.
    mapping(address => bool) public approvedRelayers;

    /// @notice Check the relayer is approved.
    bool public checkRelayer;

    /// @notice The type of proof that is being verified.
    enum ProofType {
        HeaderRangeProof,
        RotateProof
    }

    struct InitParameters {
        address guardian;
        uint32 height;
        bytes32 header;
        uint64 authoritySetId;
        bytes32 authoritySetHash;
        uint32 headerRangeCommitmentTreeSize;
        bytes32 vectorProgramVkey;
        address verifier;
    }

    struct HeaderRangeOutputs {
        uint32 trusted_block;
        bytes32 trusted_header_hash;
        uint64 authority_set_id;
        bytes32 authority_set_hash;
        uint32 target_block;
        bytes32 target_header_hash;
        bytes32 state_root_commitment;
        bytes32 data_root_commitment;
        uint32 merkle_tree_size;
    }

    struct RotateOutputs {
        uint64 current_authority_set_id;
        bytes32 current_authority_set_hash;
        bytes32 new_authority_set_hash;
    }

    struct ProofOutputs {
        ProofType proofType;
        bytes headerRangeOutputs;
        bytes rotateOutputs;
    }

    /// @notice If the relayer check is enabled, only approved relayers can call the function.
    modifier onlyApprovedRelayer() {
        if (checkRelayer && !approvedRelayers[msg.sender]) {
            revert RelayerNotApproved();
        }
        _;
    }

    function VERSION() external pure override returns (string memory) {
        return "2.0.0";
    }

    /// @dev Initializes the contract.
    /// @param _params The initialization parameters for the contract.
    function initialize(InitParameters calldata _params) external initializer {
        blockHeightToHeaderHash[_params.height] = _params.header;
        authoritySetIdToHash[_params.authoritySetId] = _params.authoritySetHash;
        latestAuthoritySetId = _params.authoritySetId;
        latestBlock = _params.height;
        vectorXProgramVkey = _params.vectorProgramVkey;
        verifier = ISP1Verifier(_params.verifier);
        headerRangeCommitmentTreeSize = _params.headerRangeCommitmentTreeSize;

        __TimelockedUpgradeable_init(_params.guardian, _params.guardian);
    }

    /// @notice Update the SP1 verifier.
    function updateVerifier(address _verifier) external onlyGuardian {
        verifier = ISP1Verifier(_verifier);
    }

    /// @notice Update the SP1Vector program verification key.
    function updateVectorXProgramVkey(bytes32 _vectorXProgramVkey) external onlyGuardian {
        vectorXProgramVkey = _vectorXProgramVkey;
    }

    /// @notice Update the freeze parameter.
    function updateFreeze(bool _freeze) external onlyGuardian {
        frozen = _freeze;
    }

    /// @notice Update the commitment tree size for the header range function.
    function updateCommitmentTreeSize(uint32 _headerRangeCommitmentTreeSize) external onlyGuardian {
        headerRangeCommitmentTreeSize = _headerRangeCommitmentTreeSize;
    }

    /// @notice Update the genesis state of the light client.
    function updateGenesisState(uint32 _height, bytes32 _header, uint64 _authoritySetId, bytes32 _authoritySetHash)
        external
        onlyGuardian
    {
        blockHeightToHeaderHash[_height] = _header;
        latestBlock = _height;

        authoritySetIdToHash[_authoritySetId] = _authoritySetHash;
        latestAuthoritySetId = _authoritySetId;
    }

    /// @notice Force update the data & state commitments for a range of blocks.
    function updateBlockRangeData(
        uint32[] calldata _startBlocks,
        uint32[] calldata _endBlocks,
        bytes32[] calldata _headerHashes,
        bytes32[] calldata _dataRootCommitments,
        bytes32[] calldata _stateRootCommitments,
        uint64 _endAuthoritySetId,
        bytes32 _endAuthoritySetHash
    ) external onlyGuardian {
        assert(
            _startBlocks.length > 0 && _startBlocks.length == _endBlocks.length
                && _endBlocks.length == _headerHashes.length && _headerHashes.length == _dataRootCommitments.length
                && _dataRootCommitments.length == _stateRootCommitments.length
        );
        require(_startBlocks[0] == latestBlock);
        for (uint256 i = 0; i < _startBlocks.length; i++) {
            if (i < _startBlocks.length - 1) {
                require(_endBlocks[i] == _startBlocks[i + 1]);
            }
            bytes32 key = keccak256(abi.encode(_startBlocks[i], _endBlocks[i]));
            dataRootCommitments[key] = _dataRootCommitments[i];
            stateRootCommitments[key] = _stateRootCommitments[i];
            rangeStartBlocks[key] = _startBlocks[i];

            blockHeightToHeaderHash[_endBlocks[i]] = _headerHashes[i];

            emit HeadUpdate(_endBlocks[i], _headerHashes[i]);

            emit HeaderRangeCommitmentStored(
                _startBlocks[i],
                _endBlocks[i],
                _dataRootCommitments[i],
                _stateRootCommitments[i],
                headerRangeCommitmentTreeSize
            );
        }
        latestBlock = _endBlocks[_endBlocks.length - 1];

        authoritySetIdToHash[_endAuthoritySetId] = _endAuthoritySetHash;
        latestAuthoritySetId = _endAuthoritySetId;
    }

    /// @notice Set a relayer's approval status.
    function setRelayerApproval(address _relayer, bool _approved) external onlyGuardian {
        approvedRelayers[_relayer] = _approved;
    }

    /// @notice Set a check relayer status.
    function setCheckRelayer(bool _checkRelayer) external onlyGuardian {
        checkRelayer = _checkRelayer;
    }

    /// @notice Add target header hash, and data + state commitments for (latestBlock, targetBlock].
    /// @param proof The proof bytes for the SP1 proof.
    /// @param publicValues The public commitments from the SP1 proof.
    /// @dev The trusted block and requested block must have the same authority set id. If the target
    /// block is greater than the max batch size of the circuit, the proof will fail to generate.
    function commitHeaderRange(bytes calldata proof, bytes calldata publicValues) external onlyApprovedRelayer {
        if (frozen) {
            revert ContractFrozen();
        }

        // Parse the outputs from the committed public values associated with the proof.
        ProofOutputs memory proofOutputs = abi.decode(publicValues, (ProofOutputs));

        // Assert this is a header range proof. Sanity check to prevent accidental submission of a
        // rotate proof.
        if (proofOutputs.proofType != ProofType.HeaderRangeProof) {
            revert InvalidProofType();
        }

        // Decode the header range outputs from the proof outputs.
        HeaderRangeOutputs memory hro = abi.decode(proofOutputs.headerRangeOutputs, (HeaderRangeOutputs));

        // Verify the merkle tree size in the proof matches the expected size.
        if (hro.merkle_tree_size != headerRangeCommitmentTreeSize) {
            revert InvalidMerkleTreeSize();
        }

        // Verify the trusted header matches the stored trusted header and latestBlock.
        bytes32 storedTrustedHeader = blockHeightToHeaderHash[latestBlock];
        if (storedTrustedHeader == bytes32(0)) {
            revert TrustedHeaderNotFound();
        }
        if (hro.trusted_header_hash != storedTrustedHeader && hro.trusted_block != latestBlock) {
            revert TrustedHeaderMismatch();
        }

        // Verify the authority set hash matches the stored authority set hash.
        bytes32 authoritySetHashStored = authoritySetIdToHash[hro.authority_set_id];
        if (authoritySetHashStored == bytes32(0)) {
            revert AuthoritySetNotFound();
        }
        if (hro.authority_set_hash != authoritySetHashStored) {
            revert AuthoritySetMismatch();
        }

        // Verify the target block is greater than the latest block.
        if (hro.target_block <= latestBlock) {
            revert InvalidTargetBlock();
        }

        // If the authority set id is less than the latest authority set id proven in the contract,
        // the proof is invalid.
        if (hro.authority_set_id < latestAuthoritySetId) {
            revert OldAuthoritySetId();
        }

        // Verify the proof with the associated public values. This will revert if proof invalid.
        verifier.verifyProof(vectorXProgramVkey, publicValues, proof);

        emit HeadUpdate(hro.target_block, hro.target_header_hash);
        emit HeaderRangeCommitmentStored(
            hro.trusted_block,
            hro.target_block,
            hro.data_root_commitment,
            hro.state_root_commitment,
            headerRangeCommitmentTreeSize
        );

        // Update the latest authority set id if the authority set id is greater than the latest
        // authority set id.
        if (hro.authority_set_id > latestAuthoritySetId) {
            latestAuthoritySetId = hro.authority_set_id;
        }

        // Store the data and state commitments for the range (latestBlock, targetBlock].
        bytes32 key = keccak256(abi.encode(latestBlock, hro.target_block));
        dataRootCommitments[key] = hro.data_root_commitment;
        stateRootCommitments[key] = hro.state_root_commitment;
        rangeStartBlocks[key] = latestBlock;

        // Add the target header hash to the contract.
        blockHeightToHeaderHash[hro.target_block] = hro.target_header_hash;

        // Update latest block.
        latestBlock = hro.target_block;
    }

    /// @notice Adds the authority set hash for the next authority set id.
    /// @param proof The proof bytes for the SP1 proof.
    /// @param publicValues The public commitments from the SP1 proof.
    function rotate(bytes calldata proof, bytes calldata publicValues) external onlyApprovedRelayer {
        if (frozen) {
            revert ContractFrozen();
        }

        // Parse the outputs from the committed public values associated with the proof.
        ProofOutputs memory proofOutputs = abi.decode(publicValues, (ProofOutputs));

        // Assert this is a rotate proof.
        if (proofOutputs.proofType != ProofType.RotateProof) {
            revert InvalidProofType();
        }

        // Decode the rotate outputs from the proof.
        RotateOutputs memory ro = abi.decode(proofOutputs.rotateOutputs, (RotateOutputs));

        // Verify the current authority set hash has already been proven in the contract.
        bytes32 currentAuthoritySetHashStored = authoritySetIdToHash[ro.current_authority_set_id];
        if (currentAuthoritySetHashStored == bytes32(0)) {
            revert AuthoritySetNotFound();
        }
        if (ro.current_authority_set_hash != currentAuthoritySetHashStored) {
            revert AuthoritySetMismatch();
        }

        // Verify the next authority set hash does not exist yet.
        bytes32 nextAuthoritySetHash = authoritySetIdToHash[ro.current_authority_set_id + 1];
        if (nextAuthoritySetHash != bytes32(0)) {
            revert NextAuthoritySetExists();
        }

        // Verify the proof with the associated public values.
        verifier.verifyProof(vectorXProgramVkey, publicValues, proof);

        emit AuthoritySetStored(ro.current_authority_set_id + 1, ro.new_authority_set_hash);

        // Store the authority set hash for the next authority set id.
        authoritySetIdToHash[ro.current_authority_set_id + 1] = ro.new_authority_set_hash;
    }
}
