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
import {TimelockedUpgradeable} from "@succinctx/upgrades/TimelockedUpgradeable.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";

// Required environment variables:
// - CONTRACT_ADDRESS
// - SP1_VECTOR_PROGRAM_VKEY
// - SP1_PROVER
// - SP1_VERIFIER_ADDRESS

contract UpgradeScript is Script {
    using stdJson for string;

    function setUp() public {}

    function run() public returns (address) {
        vm.startBroadcast();

        SP1Vector sp1VectorImpl = new SP1Vector();

        address existingProxyAddress = vm.envAddress("CONTRACT_ADDRESS");
        TimelockedUpgradeable proxy = TimelockedUpgradeable(existingProxyAddress);
        proxy.upgradeTo(address(sp1VectorImpl));

        SP1Vector sp1Vector = SP1Vector(address(existingProxyAddress));

        // Update the SP1 Verifier address and the program vkey.
        if (vm.envBool("MOCK")) {
            SP1MockVerifier mockVerifier = new SP1MockVerifier();
            sp1Vector.updateVerifier(address(mockVerifier));
        } else {
            sp1Vector.updateVerifier(vm.envAddress("SP1_VERIFIER_ADDRESS"));
        }
        sp1Vector.updateVectorXProgramVkey(vm.envBytes32("SP1_VECTOR_PROGRAM_VKEY"));

        return address(existingProxyAddress);
    }
}
