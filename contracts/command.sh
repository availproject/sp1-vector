forge verify-contract --verifier etherscan \
--etherscan-api-key I1P6P4XSQM85V9YINFKDAUJAUXNMCPDPTU \
--compiler-version 0.8.25 \
--chain-id 1 \
--evm-version cancun \
--optimizer-runs 200 \
--via-ir \
0x02993cdC11213985b9B13224f3aF289F03bf298d \
FlatERC1967 \
--constructor-args 0000000000000000000000002434564f3524b44258b11643729343ef57d6098900000000000000000000000000000000000000000000000000000000000000400000000000000000000000000000000000000000000000000000000000000000 --watch \
--show-standard-json-input

# Reproduced:
# https://etherscan.io/find-similar-contracts?a=0x02993cdC11213985b9B13224f3aF289F03bf298d&m=exact
