# 0.34.17

`main` at 0.34.16 is the parent. This version does not change consensus, script, issuance, or MatMul acceptance. `automatic_spend_atoms` remains `"0"`.

A live SwapNet route is no longer replaced when a different peer replays a valid packet or advertisement. The first live next hop stays until it expires. `getswapwalletinfo` now requires the owner. It returns the node identity and foreign-chain accounts.

`lab.deployment_observe` no longer moves a rollout plan that is `PAUSED`. A snapshot import checks the model bytes named by each piece before the import is installed.

Claim and refund keys remain fields of the signed agreement, so they are still created before that signature. No trade-size minimum beyond a positive amount was added. The Windows foreign-vault file layout is unchanged.

The Windows unit fixture no longer includes `<unistd.h>` or the Unix-socket feed case. The other bridge cases stay compiled. `doc/modelnet/recovery.md` now describes keeping an independent copy of a retained model export and restoring it with `importmodel`. That is not a rebuild of the catalog from cloud objects alone.

The SwapNetHTLC artifact in this tree is open. Its runtime keccak256, under solc 0.8.24 with the optimizer at 200 runs and no metadata hash, is `a06e30bad714ff02db5a2401a898bd7194d1c475b61bdab312ae194b1509e45d`. Deploying that creation code with CREATE2 through the permissionless proxy `0x4e59b44847b379578588920cA78FbF26c0B4956C` and salt keccak256(`BTX/SWAPNET/HTLC/1`) yields `0x944C528F2e206a93CEb32B4723cd25DAa8f303EF`. The proxy has no admin key. This release does not send the deployment. A node still pins that address and that runtime hash together: the hash identifies the code, and the address is where the funds sit.

The external-sign, bounty, and model-plane documents now say what this build returns. Reachability stays `UNKNOWN`. Availability from `getmodelavailability` stays `UNKNOWN` because that call passes no piece total. A search record may still name a publisher that did not sign it. A pending deposit that leaves the mempool still becomes `UNKNOWN` without a new event.
