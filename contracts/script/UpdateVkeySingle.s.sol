// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import {stdJson} from "forge-std/StdJson.sol";
import {SP1Vector} from "../src/SP1Vector.sol";
import "forge-std/Script.sol";

// Required environment variables:
// - CONTRACT_ADDRESS_{CHAIN_ID}

contract UpdateVkeySingleScript is Script {
    using stdJson for string;

    function setUp() public {}

    /// Reads CONTRACT_ADDRESS_<CHAIN_ID> from the environment variables and updates the SP1 Verifier and program vkey.
    function run() external {
        vm.startBroadcast();

        string memory contractAddressKey = string.concat("CONTRACT_ADDRESS_", vm.toString(block.chainid));
        address existingProxyAddress = vm.envAddress(contractAddressKey);

        SP1Vector sp1Vector = SP1Vector(address(existingProxyAddress));

        // v4 program vkey
        sp1Vector.updateVectorXProgramVkey(0x00e9bba2a9360f570b9ba99e5186825ac723bedebd486b6a818870c44e3e4d4f);

        vm.stopBroadcast();
    }
}
