# 0.34.17

`main` at 0.34.16 is the parent. This version does not change consensus, script, issuance, or MatMul acceptance. `automatic_spend_atoms` remains `"0"`.

A live SwapNet route is no longer replaced when a different peer replays a valid packet or advertisement. The first live next hop stays until it expires. `getswapwalletinfo` now requires the owner. It returns the node identity and foreign-chain accounts.

`lab.deployment_observe` no longer moves a rollout plan that is `PAUSED`. A snapshot import checks the model bytes named by each piece before the import is installed.

Claim and refund keys remain fields of the signed agreement, so they are still created before that signature. No trade-size minimum beyond a positive amount was added. The Windows foreign-vault file layout is unchanged.
