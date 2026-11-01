# Experimental Windows / POSIX ExactReplay verifier

This is a draft, opt-in `contrib` prototype for discussing an operator-owned
external GPU service. It is **not a qualified release**, a drop-in replacement
for an existing pool verifier, or a new node validation mode. No `btxd` consumer
of this protocol is added. Do not enable it on production nodes on the strength
of this draft.

Related topology / trust discussion: https://github.com/btxchain/btx/issues/361.
Related Windows compiler work: https://github.com/btxchain/btx/issues/356.

## Why btx-pool.com uses a remote prover

**btx-pool.com uses an operator-maintained remote-prover arrangement for
operational convenience.** Several Linux VPS nodes handle networking, chain
state and RPC, while operator-controlled Windows machines provide the NVIDIA
GPU execution. Protected SSH forwarding connects the two sides. Pool-share
verification and block verification are separate work paths; the deployed
setup has its own mux and GPU scheduling.

This placement lets the operator keep the GPUs on machines they already own,
avoids putting a GPU in every VPS, and makes it easier to manage the GPU
software separately from the Linux nodes. Native Windows workers also avoid
requiring WSL for GPU execution. The operator is responsible for the availability
of the shared GPU machines and their network connection. Several nodes sharing
one GPU service do not create several independent execution domains.

The deployed arrangement currently relies on **private node/prover extensions**.
It is not evidence that upstream `btxd` officially supports this topology. The
code in this PR is a deliberately smaller integration candidate, not a dump of
that installation. Its behavior must be reviewed and qualified against the
current branch independently. Results from the older deployed binaries do not
qualify this prototype or a future 0.35 release.

A remote machine's result is inside the operator's trust boundary. A socket
connection or a JSON `ok` field does not prove that this node independently
ExactReplayed a block. Maintainers need to decide how such a backend should be
represented, qualified and distinguished from locally executed validation and
from pinned-attestor `trusted` mode. This PR does not silently relabel remote
execution as independent local consensus validation.

## What this draft implements

* A mainnet Profile-1 verifier process using the existing in-tree
  `VerifyBoundedExactReplay`, backend resolver and production startup canary.
  Before qualification it explicitly selects `StrictDevice` and disables CPU
  confirmation, matching mainnet btxd defaults; no automatic CPU fallback is
  requested.
* An IPv4 loopback-only listener with a required token file (32..4096 bytes).
  The token must be protected by the operator's filesystem permissions / Windows
  ACL. Use a separate token for this service, not a wallet or RPC password.
* One JSON line and one reply per connection. Calls are serialized. The maximum
  request line is 64 KiB, and network reads and writes have absolute deadlines.
* Invalid JSON, missing authentication, unsupported operations and provider
  failures are errors. They do not become successful verdicts. The service
  opens no listener if initial GPU qualification/canary fails. A later local
  accelerator result disables readiness until restart only for typed
  `ExecutionFailure` or `ProviderUnavailable` failures. An
  `UnconfirmedDigestMismatch` alone does not disable a healthy service, nor does
  a cancellation. A replay result never restores readiness after a real fault.
* A caller may request a target stricter than the header's compact target,
  but cannot use this protocol to make it easier.

There is no inbound `put` operation or caller-populated digest cache, no external
fast-engine shortcut, no wallet loading, no P2P, no attestor selection, and no
changes to consensus arithmetic, fork choice or issuance. The production mux,
its policies and private operational files are not included.

### Protocol sketch (experimental, version 1)

Status:

```json
{"op":"status","token":"<operator-secret>"}
```

Verify:

```json
{"op":"verify","token":"<operator-secret>","id":1,"header":"<serialized-header-hex>","height":265000,"profile":1,"target":"<optional-64-hex-target>"}
```

A verification reply includes `id`, `ok`, `outcome`, `digest`, `backend`, `note`
and `verify_s`. `outcome` is `valid`, `invalid`, `accel_failure` or `cancelled`.
Only this execution's in-tree result supplies that verdict. The caller remains
responsible for header/height context, chain selection, full block/script
validation, and interpreting operational failure as unavailability rather than
a consensus verdict. Protocol errors may omit `id` and must not be accepted.

No network encryption is implemented here. The listener is hard-bound to
loopback; any remote access must use an independently protected operator-owned
transport such as SSH forwarding. Do not forward it as an unauthenticated public
service. A slow client can occupy the serial worker up to the read deadline;
concurrency and scheduling are intentionally left for review.

## Build and validation status

The prototype is disabled by default and adds no target to a normal build.
From a separately qualified BTX toolchain, opt in with:

```text
-DBTX_BUILD_RC_PROVER_PROTOTYPE=ON
```

Then build the `btx-rc-prover` target. Its GPU backend must already be available
and qualified. This flag does not install CUDA or turn a CPU-only VPS into a
qualified GPU node. Windows host compilation uses clang-cl for the tree's
`__int128` code; this does not claim the full tree builds with cl.exe (see #356).

```text
btx-rc-prover --serve=9555 --token-file=<protected-token-file>
```

The independent transport test can be built without BTX, CUDA, wallet libraries
or a running node:

```sh
cmake -S contrib/rc-prover -B build-rc-transport
cmake --build build-rc-transport --config Release
ctest --test-dir build-rc-transport -C Release --output-on-failure
```

The transport harness has seven cases in one CTest entry, using only ephemeral
loopback ports: exact JSON byte preservation of a uint64-sized value, fragmented
replies, CRLF, receive timeout, slow trickle, EOF, request-size refusal and blocked
writes. The byte check is framing coverage, not actual header-nonce parsing.
The three deadline cases currently also pass when the peer closes before the
overly generous elapsed-time bound; they do **not yet establish deadline
enforcement**. Strengthening those cases remains an open review item. These
checks do not contact mainnet.

Executed for this draft on 1 November 2026, based on
`btx-035/swarm` at `cbf65894e6d61084527cd93e913a00c6794418dd`:

* Windows x64, MSVC 19.50: independent transport configured, built and all seven
  cases passed through CTest.
* Linux / WSL Ubuntu 22.04, GCC 11.4, `-Wall -Wextra -Werror`: the same seven
  transport cases passed.
* Windows x64, clang-cl 22.1.8: root CMake configuration with this option on and
  CUDA off succeeded; the actual prover translation unit compiled against this
  branch. This is an object compilation check, **not a complete link**.

The Windows and Linux checks above were repeated after replacing the timeout
initialization with casts to each `timeval` member's declared type. This fixes
a narrowing error reported by [repch1c on macOS](https://github.com/btxchain/btx/pull/362#issuecomment-6556867035),
where `tv_usec` is an `int`. On the original commit with the same local fix,
repch1c reports three successful transport-test runs (all seven cases), prover
syntax compilation, and an oversize-check mutation caught by the tests. Those
are reviewer-reported macOS results; no macOS run was performed here. In a
[later review](https://github.com/btxchain/btx/pull/362#issuecomment-6557778906),
Jpp reports a complete macOS/Metal link, qualification and startup canary with
successful malformed-request checks on the pre-policy-fix version plus the
same timeout-initialization fix. Those runs do not qualify the new strict-policy
build; real-GPU checks must be repeated after the policy change.

### Replay-policy regression checks

The in-tree opt-in build also provides `btx-rc-replay-policy-test`. Build that
target and run it directly (or use the `btx_rc_replay_policy` CTest entry when
BTX test registration is enabled). Unlike the independent transport project,
it includes the current BTX headers and needs a compatible core C++ toolchain.

This CPU-only unit test uses the real ExactReplay result/enumeration types and
stub configuration setters. It checks strict-device/no-CPU-confirmation setup,
eight readiness classifications from both ready and unavailable states, and
mismatch/success/fault sequences. It does not start the service, call the real
replay implementation or qualify a GPU. The test and updated prover translation
unit compiled on Windows/clang-cl; the test also passed on Linux/GCC with
`-Wall -Wextra -Werror`. In isolated Linux mutation builds, the test fails if
we restore the old all-accelerator-outcomes readiness latch, select AutoFallback,
or enable CPU confirmation.

### Still required before this could be considered for integration

- Full Windows and Linux links on supported toolchains, then real CUDA
  self-qualification and startup canary on supported hardware. Repeat real-GPU
  replay tests with the strict-device policy and CPU confirmation disabled.
- Remaining review items: deadline-sensitive transport tests, startup
  qualification/workspace parity with btxd, and its dimension/null-seed/null-digest
  prechecks. These are not fixed by the two policy/readiness changes.
- Positive and negative canonical-header vectors against the in-tree oracle,
  wrong digest/nonce/target/profile cases, malformed JSON and authentication
  tests against the actual process, GPU loss and service recovery.
- Agreement on the node/backend trust boundary, qualification identity,
  version negotiation, limits and correlated-failure behavior.
- A separately reviewed node integration; this PR adds none.
- Full regression/release qualification. No production routing was changed
  to test this draft, and the current pool binaries were not replaced.
