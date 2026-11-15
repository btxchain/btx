# 0.34.17

`main` at 0.34.16 is the parent. This version does not change consensus, script, issuance, or MatMul acceptance. `automatic_spend_atoms` remains `"0"`.

A live SwapNet route is no longer replaced when a different peer replays a valid packet or advertisement. The first live next hop stays until it expires. `getswapwalletinfo` now requires the owner. It returns the node identity and foreign-chain accounts.

A maker checks proposal deadlines after it has read both chain clocks. The time captured when the proposal arrives is still what the quote is checked against. A remote endpoint no longer makes that deadline check fail with `STALE_CHAIN`.

`lab.deployment_observe` no longer moves a rollout plan that is `PAUSED`. A snapshot import checks the model bytes named by each piece before the import is installed.

Claim and refund keys remain fields of the signed agreement, so they are still created before that signature. No trade-size minimum beyond a positive amount was added. The Windows foreign-vault file layout is unchanged.

The Windows unit fixture no longer includes `<unistd.h>` or the Unix-socket feed case. The other bridge cases stay compiled. `doc/modelnet/recovery.md` now describes keeping an independent copy of a retained model export and restoring it with `importmodel`. That is not a rebuild of the catalog from cloud objects alone.

The SwapNetHTLC artifact in this tree is open. Under solc 0.8.24 with the optimizer at 200 runs and no metadata hash, its runtime keccak256 is `a06e30bad714ff02db5a2401a898bd7194d1c475b61bdab312ae194b1509e45d` and its creation-code keccak256 is `401e81e4ab795f39e48b76bda608771e10078e23cfc1d807983b05ee3da97cde`. A matching runtime hash is not enough. Different init code can write a lock into storage while the contract is being created and then return this runtime, so two nodes can pin the same address and the same runtime hash with nothing behind the lock. Deploying this creation code with CREATE2 through the permissionless proxy `0x4e59b44847b379578588920cA78FbF26c0B4956C` and salt keccak256(`BTX/SWAPNET/HTLC/1`) yields `0x944C528F2e206a93CEb32B4723cd25DAa8f303EF`. That address is a recommendation, not an appointed deployment. The proxy has no admin key, and this release does not send the transaction. The address is fixed by the proxy, the salt, and the creation code, so independent owners who pin it are on the same deployment. A node still requires its owner to set both the address and the runtime hash. An owner who pins a different address has to check that the creation input is this creation code.

An incomplete admitted catalog entry can be filled by ordinary `getmodel` from configured cloud storage. That path does not require `direct_seed`. It does not rebuild a catalog from bucket objects alone. `direct_seed` and `direct_seed_fetch` remain a separate fetch.

The Linux archives carry libevent, libsqlite3, libzmq, libgomp, and the libraries those need. A base image does not have to install them. libc and libstdc++ stay on the host. The NVIDIA driver library is not in the archive. Every bundled library is within GLIBC 2.38.

The external-sign, bounty, and model-plane documents now say what this build returns. Reachability stays `UNKNOWN`. Availability from `getmodelavailability` stays `UNKNOWN` because that call passes no piece total. A search record may still name a publisher that did not sign it. A pending deposit that leaves the mempool still becomes `UNKNOWN` without a new event.
