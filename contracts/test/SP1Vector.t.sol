// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {SP1Vector} from "../src/SP1Vector.sol";
import {ISP1Vector} from "../src/interfaces/ISP1Vector.sol";
import {TimelockedUpgradeable} from "@succinctx/upgrades/TimelockedUpgradeable.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import "forge-std/console.sol";
import {Script} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract SP1VectorTest is Test {
    using stdJson for string;
    /// @notice The type of proof that is being verified.

    enum ProofType {
        HeaderRangeProof,
        RotateProof
    }

    SP1Vector public sp1Vector;

    function setUp() public {}

    function test_Deploy() public {
        // Read trusted initialization parameters from .env
        address guardian = msg.sender;
        uint32 height = uint32(vm.envUint("GENESIS_HEIGHT"));
        bytes32 header = bytes32(vm.envBytes32("GENESIS_HEADER"));
        uint64 authoritySetId = uint64(vm.envUint("GENESIS_AUTHORITY_SET_ID"));
        bytes32 authoritySetHash = bytes32(vm.envBytes32("GENESIS_AUTHORITY_SET_HASH"));
        uint32 headerRangeCommitmentTreeSize = uint32(vm.envUint("HEADER_RANGE_COMMITMENT_TREE_SIZE"));
        bytes32 vectorProgramVkey = bytes32(vm.envBytes32("SP1_VECTOR_PROGRAM_VKEY"));
        SP1MockVerifier verifier = new SP1MockVerifier();

        SP1Vector vectorImpl = new SP1Vector();
        sp1Vector = SP1Vector(address(new ERC1967Proxy(address(vectorImpl), "")));
        sp1Vector.initialize(
            SP1Vector.InitParameters({
                guardian: guardian,
                height: height,
                header: header,
                authoritySetId: authoritySetId,
                authoritySetHash: authoritySetHash,
                headerRangeCommitmentTreeSize: headerRangeCommitmentTreeSize,
                vectorProgramVkey: vectorProgramVkey,
                verifier: address(verifier)
            })
        );

        console.log("Deployed Address:", address(sp1Vector));
    }

    function test_Rotate() public {
        test_Deploy();

        bytes memory publicValues =
            hex"00000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000001800000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000006100ac0925b3544fd394483fe65261944a57198a269d8048a45102df1cd355bd0a6b3648f7bf29f5e6d8113ddec2e26bbf8705e7459bedb15e0619778312e9fd8b";
        bytes memory proof = "";
        sp1Vector.rotate(proof, publicValues);
    }

    function test_HeaderRange() public {
        test_Deploy();

        bytes memory publicValues =
            hex"0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000600000000000000000000000000000000000000000000000000000000000000180000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000427e34c8dd5e52e2d3a01f0228070d6c6ec557304c1a71b21a8de344ed5f9de8588790000000000000000000000000000000000000000000000000000000000000054ba873a3572cc2e019a5ec10182716aea73325906882194b9d3a19fc0408834e80000000000000000000000000000000000000000000000000000000000042896bc4b14a9759ff3ba227179419129f719ee9ed33894e6a1f1edc300954f63f48b7f48a4428b18e80a47eaf92880dd048a79bd1d4161a3a5b5edb67b97c525972a13ab31250cb9b3890c436541c1fa081622b5117fdca36fe88a8ae8bf6d852bb00000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";
        bytes memory proof = "";
        sp1Vector.commitHeaderRange(proof, publicValues);
    }

    uint32 constant TRUSTED_HEIGHT = 100;
    bytes32 constant TRUSTED_HEADER = keccak256("TRUSTED_HEADER_100");
    uint64 constant SET_ID = 10;
    bytes32 constant SET_HASH = keccak256("SET_10");
    uint32 constant TREE_SIZE = 512;

    /// Deploys without .env, so the trusted-header tests run on their own.
    function deployFixture() internal {
        SP1Vector vectorImpl = new SP1Vector();
        sp1Vector = SP1Vector(address(new ERC1967Proxy(address(vectorImpl), "")));
        sp1Vector.initialize(
            SP1Vector.InitParameters({
                guardian: address(this),
                height: TRUSTED_HEIGHT,
                header: TRUSTED_HEADER,
                authoritySetId: SET_ID,
                authoritySetHash: SET_HASH,
                headerRangeCommitmentTreeSize: TREE_SIZE,
                vectorProgramVkey: keccak256("VKEY"),
                verifier: address(new SP1MockVerifier())
            })
        );
    }

    function headerRangePublicValues(uint32 trustedBlock, bytes32 trustedHeader) internal pure returns (bytes memory) {
        SP1Vector.HeaderRangeOutputs memory hro = SP1Vector.HeaderRangeOutputs({
            trusted_block: trustedBlock,
            trusted_header_hash: trustedHeader,
            authority_set_id: SET_ID,
            authority_set_hash: SET_HASH,
            target_block: TRUSTED_HEIGHT + 10,
            target_header_hash: keccak256("TARGET_HEADER_110"),
            state_root_commitment: keccak256("STATE_ROOTS"),
            data_root_commitment: keccak256("DATA_ROOTS"),
            merkle_tree_size: TREE_SIZE
        });
        return abi.encode(
            SP1Vector.ProofOutputs({
                proofType: SP1Vector.ProofType.HeaderRangeProof, headerRangeOutputs: abi.encode(hro), rotateOutputs: ""
            })
        );
    }

    function test_HeaderRange_TrustedHeaderMatches() public {
        deployFixture();
        sp1Vector.commitHeaderRange("", headerRangePublicValues(TRUSTED_HEIGHT, TRUSTED_HEADER));
        assertEq(sp1Vector.latestBlock(), TRUSTED_HEIGHT + 10);
    }

    function test_RevertHeaderRange_WrongTrustedHeader() public {
        deployFixture();
        bytes memory publicValues = headerRangePublicValues(TRUSTED_HEIGHT, keccak256("OTHER_HEADER_100"));
        vm.expectRevert(ISP1Vector.TrustedHeaderMismatch.selector);
        sp1Vector.commitHeaderRange("", publicValues);
    }

    function test_RevertHeaderRange_WrongTrustedBlock() public {
        deployFixture();
        bytes memory publicValues = headerRangePublicValues(TRUSTED_HEIGHT - 1, TRUSTED_HEADER);
        vm.expectRevert(ISP1Vector.TrustedHeaderMismatch.selector);
        sp1Vector.commitHeaderRange("", publicValues);
    }
}
