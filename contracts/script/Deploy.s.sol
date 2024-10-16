// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.26;

import "forge-std/console.sol";
import {Vm} from "forge-std/Vm.sol";
import {StdAssertions} from "forge-std/StdAssertions.sol";
import {Script} from "forge-std/Script.sol";
import {stdJson} from "forge-std/StdJson.sol";
import {SP1MockVerifier} from "@sp1-contracts/SP1MockVerifier.sol";
import {ISP1Verifier} from "@sp1-contracts/ISP1Verifier.sol";
import {SP1Vector} from "../src/SP1Vector.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

import {BaseScript} from "./Base.s.sol";

// Required environment variables:
// - GENESIS_HEIGHT
// - GENESIS_HEADER
// - GENESIS_AUTHORITY_SET_ID
// - GENESIS_AUTHORITY_SET_HASH
// - HEADER_RANGE_COMMITMENT_TREE_SIZE
// - SP1_VECTOR_PROGRAM_VKEY
// - CREATE2_SALT
// - GUARDIAN_ADDRESS
// - SP1_VERIFIER_ADDRESS

contract DeployScript is BaseScript {
    using stdJson for string;

    string internal constant KEY = "SP1_VECTOR";

    SP1Vector public sp1Vector;

    function setUp() public {}

    function run() external multichain(KEY) returns (address sp1VectorAddress) {
        vm.startBroadcast();

        uint32 genesisHeight = uint32(vm.envUint("GENESIS_HEIGHT"));
        bytes32 genesisHeader = vm.envBytes32("GENESIS_HEADER");
        uint64 genesisAuthoritySetId = uint64(vm.envUint("GENESIS_AUTHORITY_SET_ID"));
        bytes32 genesisAuthoritySetHash = vm.envBytes32("GENESIS_AUTHORITY_SET_HASH");
        uint32 headerRangeCommitmentTreeSize = uint32(vm.envUint("HEADER_RANGE_COMMITMENT_TREE_SIZE"));
        bytes32 vectorProgramVkey = vm.envBytes32("SP1_VECTOR_PROGRAM_VKEY");

        // Read trusted initialization parameters from environment.
        address guardian = vm.envOr("GUARDIAN_ADDRESS", msg.sender);

        ISP1Verifier verifier =
            ISP1Verifier(vm.envOr("SP1_VERIFIER_ADDRESS", 0x3B6041173B80E77f038f3F2C0f9744f04837185e));
        SP1Vector sp1VectorImpl = new SP1Vector();
        // ERC1967Proxy proxy = new ERC1967Proxy{salt: vm.envBytes32("CREATE2_SALT")}(address(sp1VectorImpl), "");
        ERC1967Proxy proxy = new ERC1967Proxy(address(sp1VectorImpl), "");
        sp1Vector = SP1Vector(address(proxy));
        sp1Vector.initialize(
            SP1Vector.InitParameters({
                guardian: guardian,
                height: genesisHeight,
                header: genesisHeader,
                authoritySetId: genesisAuthoritySetId,
                authoritySetHash: genesisAuthoritySetHash,
                headerRangeCommitmentTreeSize: headerRangeCommitmentTreeSize,
                vectorProgramVkey: vectorProgramVkey,
                verifier: address(verifier)
            })
        );

        vm.stopBroadcast();

        return address(sp1Vector);
    }
}
