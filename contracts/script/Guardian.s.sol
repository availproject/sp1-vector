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
import {BaseScript} from "./Base.s.sol";

// Required environment variables:
// - CHAINS (comma separated list of chain names)
// - CONTRACT_ADDRESS_{CHAIN_ID}
// - GUARDIAN_ADDRESS

contract UpgradeScript is BaseScript {
    using stdJson for string;

    function setUp() public {}

    string internal constant KEY = "GuardianScript";

    /// Reads CONTRACT_ADDRESS_<CHAIN_ID> from the environment variables and updates the SP1 Verifier and program vkey.
    function run() external multichain(KEY) broadcaster {
        string memory contractAddressKey = string.concat("CONTRACT_ADDRESS_", vm.toString(block.chainid));
        address existingProxyAddress = vm.envAddress(contractAddressKey);

        // Grant roles to multi-sig.
        SP1Vector sp1Vector = SP1Vector(address(existingProxyAddress));
        address guardian = vm.envAddress("GUARDIAN_ADDRESS");
        sp1Vector.grantRole(sp1Vector.DEFAULT_ADMIN_ROLE(), guardian);
        sp1Vector.grantRole(sp1Vector.GUARDIAN_ROLE(), guardian);
        sp1Vector.grantRole(sp1Vector.TIMELOCK_ROLE(), guardian);

        // // Removes roles from 0xded.
        // sp1Vector.revokeRole(sp1Vector.DEFAULT_ADMIN_ROLE(), 0xDEd0000E32f8F40414d3ab3a830f735a3553E18e);
        sp1Vector.revokeRole(sp1Vector.GUARDIAN_ROLE(), 0xDEd0000E32f8F40414d3ab3a830f735a3553E18e);
        sp1Vector.revokeRole(sp1Vector.TIMELOCK_ROLE(), 0xDEd0000E32f8F40414d3ab3a830f735a3553E18e);
    }
}
