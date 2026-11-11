# vnu-chain/contracts

## Create object and publish package 
```bash
movement move create-object-and-publish-package --address-name vnu --named-addresses root_admin=tester --profile tester --included-artifacts none
```
## Upgrade
```bash
movement move upgrade-object-package --object-address 0x4a66666f975ad138237e4da6f0cab1060a43e1b15fc556630ed67d4d762c6207 --named-addresses vnu=0x4a66666f975ad138237e4da6f0cab1060a43e1b15fc556630ed67d4d762c6207, root_admin=tester --profile tester --included-artifacts none
```

## Address Contract
```bash
0x4a66666f975ad138237e4da6f0cab1060a43e1b15fc556630ed67d4d762c6207
```
## Faucet 
```bash
movement account fund-with-faucet --profile tester
```