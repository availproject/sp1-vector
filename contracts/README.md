# SP1 Vector Contracts

## Deploy new contracts
To deploy new contracts, generate genesis parameters, then add the chains to the .env file:
```
CHAINS=sepolia,arbitrum_sepolia,...
```

Then run the deploy script:
```
forge script script/Deploy.s.sol --private-key $PRIVATE_KEY --verify --verifier etherscan --multi --broadcast
```

## Updating existing contracts
To update the existing contracts, set the contract addresses on the chains you want to update:
```
CHAINS=sepolia,arbitrum_sepolia,...

CONTRACT_ADDRESS_<CHAIN_ID>=<NEW_CONTRACT_ADDRESS>
```

Then run the upgrade script:
```
forge script script/Upgrade.s.sol --verify --verifier etherscan --private-key $PRIVATE_KEY --multi --broadcast
```