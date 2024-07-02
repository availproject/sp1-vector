// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/console.sol";
import {Vm} from "forge-std/Vm.sol";
import {StdAssertions} from "forge-std/StdAssertions.sol";
import {Script} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {SP1Vector} from "../src/SP1Vector.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// Required environment variables:
// - SP1_PROVER
// - GENESIS_HEIGHT
// - GENESIS_HEADER
// - GENESIS_AUTHORITY_SET_ID
// - GENESIS_AUTHORITY_SET_HASH
// - HEADER_RANGE_COMMITMENT_TREE_SIZE
// - SP1_VECTOR_PROGRAM_VKEY
// - CREATE2_SALT
// - GUARDIAN_ADDRESS
// - SP1_VERIFIER_ADDRESS

contract DeployScript is Script {
    using stdJson for string;

    SP1Vector public sp1Vector;
    ISP1Verifier public verifier;

    function setUp() public {}

    function run() public returns (address) {
        vm.startBroadcast();

        // Read trusted initialization parameters from environment.
        address guardian;
        if (vm.envAddress("GUARDIAN_ADDRESS") == address(0)) {
            guardian = msg.sender;
        } else {
            guardian = vm.envAddress("GUARDIAN_ADDRESS");
        }
        uint32 height = uint32(vm.envUint("GENESIS_HEIGHT"));
        bytes32 header = bytes32(vm.envBytes32("GENESIS_HEADER"));
        uint64 authoritySetId = uint64(vm.envUint("GENESIS_AUTHORITY_SET_ID"));
        bytes32 authoritySetHash = bytes32(vm.envBytes32("GENESIS_AUTHORITY_SET_HASH"));
        uint32 headerRangeCommitmentTreeSize = uint32(vm.envUint("HEADER_RANGE_COMMITMENT_TREE_SIZE"));
        bytes32 vectorProgramVkey = bytes32(vm.envBytes32("SP1_VECTOR_PROGRAM_VKEY"));

        SP1Vector sp1VectorImpl = new SP1Vector();
        string memory mockStr = "mock";
        if (keccak256(abi.encodePacked(vm.envString("SP1_PROVER"))) == keccak256(abi.encodePacked(mockStr))) {
            verifier = ISP1Verifier(address(new SP1MockVerifier()));
        } else {
            verifier = ISP1Verifier(vm.envAddress("SP1_VERIFIER_ADDRESS"));
        }
        ERC1967Proxy proxy = new ERC1967Proxy{salt: vm.envBytes32("CREATE2_SALT")}(address(sp1VectorImpl), "");
        sp1Vector = SP1Vector(address(proxy));
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

        vm.stopBroadcast();

        return address(sp1Vector);
    }
}
