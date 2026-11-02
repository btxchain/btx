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
  The loader checks the same opened file it reads: POSIX requires this user's
  regular file with no group/other permission bits (normally 0600/0400);
  Apple additionally requires no extended ACL entries, including inherited,
  owner-only and deny entries. The check uses the same opened fd; Darwin's
  absent-ACL ENOENT result is allowed, while real lookup/enumeration errors
  refuse startup. Use a plain private token file (clear unwanted Apple ACLs
  with `chmod -N` on that file). Windows rejects reparse points and requires
  an owner/DACL restricted to the current user, SYSTEM and local Administrators.
  It refuses unsupported ACL entries rather than guessing effective access.
  Use a separate token for this service, not a wallet or RPC password. Token
  comparison uses `TimingResistantEqual`.
* One JSON line and one reply per connection. Calls are serialized. The maximum
  request line is 64 KiB. A nonblocking framing loop permits at most 32 pending
  connections, each with a 2-second absolute framing budget after acceptance.
  At capacity the listener is not polled: new connections wait in the OS backlog
  until capacity is released. An admitted frame is never evicted to make room
  for another unauthenticated connection. Waiting peers do not each own the GPU
  worker. Time spent outside the framing loop on a serial
  dispatch is excluded from other peers' framing budgets. Replies have a
  separate 5-second write deadline. No per-connection threads are created.
* Invalid JSON, missing authentication, unsupported operations and provider
  failures are errors. They do not become successful verdicts. The service
  opens no listener if initial GPU qualification/canary fails. A later local
  accelerator result disables readiness until restart only for typed
  `ExecutionFailure` or `ProviderUnavailable` failures. An
  `UnconfirmedDigestMismatch` alone does not disable a healthy service, nor does
  a cancellation. A replay result never restores readiness after a real fault.
* Dimension, non-null seeds and non-null committed digest are checked before
  replay, matching btxd's cheap RC prechecks. Startup checks the same estimated
  workspace fit as btxd, using CUDA global memory or Metal recommended working
  set with a 25% reserve; unknown/insufficient capacity refuses startup.
* Startup admission uses `passed && activation_ready`, not the canary outcome
  label alone. `MissingGolden` may admit a self-qualified device. The backend is
  re-resolved after the canary and must be production-eligible, activation-ready
  and capability-registered before the listener opens.
* A caller may request a target stricter than the header's compact target,
  but cannot use this protocol to make it easier. Pool-share verification is
  outside this protocol: a target looser than nBits is always refused.

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

A replay reply includes `id`, `ok`, `outcome`, `failure_kind`, `height`, `profile`,
`target`, `digest`, `backend`, `note` and `verify_s`. `outcome` is `valid`, `invalid`,
`accel_failure` or `cancelled`; malformed/unauthenticated requests instead use
`protocol_error`. Cheap header rejection returns `invalid` before replay and may
omit replay-only fields. Protocol errors may omit `id` and must not be accepted.
The status reply's `ok:true` means that the status request was processed;
**`ready` is the health indicator**. Status reports the live execution-policy
and CPU-confirmation getters, plus workspace. `failure_kind` uses the library's
canonical hyphenated names (for example `provider-unavailable`); the independent
`error` field keeps identifiers such as `provider_unavailable` for compatibility.

Only this execution's in-tree result supplies a successful verdict. These are
unsigned replies, not trusted-mirror attestations. The caller remains
responsible for header/height context, chain selection, full block/script
validation, and interpreting operational failure as unavailability rather than
a consensus verdict. The binary retains the experimental `btx-rc-prover` name
but only verifies; it does not generate a succinct proof.

No network encryption is implemented here. The listener is hard-bound to
loopback; remote access must use an independently protected operator-owned
transport such as SSH forwarding. GPU work remains serial and can delay other
requests; admission backlog time is additional to the framing budget. Under
heavy overload a connection may wait or time out at the OS layer. Bounded
connection/memory limits and backpressure are not general denial-of-service
protection, but full pending slots no longer cause accept-then-reset behavior.
In [Jpp's macOS retest](https://github.com/btxchain/btx/pull/362#issuecomment-6573371622),
a local process cycling 64 or more connections saturated pending slots and the
backlog: 18 of 20 normal requests timed out with 10-30-second client timeouts.
In the separately instrumented run, failures occurred during connect. At
40-56 cycling connections, all 47 requests were answered. These are observations
from that local workload, not portable capacity guarantees. The listener
remains loopback-only; this overload limitation is not claimed to be solved.
Socket/bind/listen/fatal listener errors are reported with operation and OS
error code. Recoverable accept errors are logged and retried instead of terminating the
verifier; resource/network exhaustion backs off, while peer resets retry
without cumulative sleeps. Per-peer resets drop that
peer; on platforms with SO_NOSIGPIPE, writes suppress SIGPIPE as well.

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

The standalone suite has three CTest entries:

* `btx_rc_socket_transport`: seven framing cases, including uint64-sized JSON
  bytes, fragmented replies, CRLF, receive/slow-trickle timeouts, EOF, oversized
  input and blocked writes. Deadline cases hold the peer open until the C++
  client finishes and require 75 ms <= elapsed < 1 s for the requested 150 ms,
  with an independent 3-second process watchdog. The byte check is framing
  coverage, not header parsing.
* `btx_rc_request_listener`: starts a CPU-only listener probe with real sockets;
  tests a complete request behind four idle peers and full 32-slot backpressure.
  With all slots held by idle peers, the extra request must take at least
  1 second and less than 6 seconds: this detects both a removed pending limit
  and the former accept-then-reset behavior. It also covers
  16 concurrent requests during 32-peer reconnect churn (including full 64 KiB
  frames), an admitted partial frame challenged by 31 simultaneous refreshes
  and another connection, 40 resets, overlong input, incomplete-line expiry,
  and pending framing across a synthetic slow dispatch.
  It also checks classification of recoverable and fatal accept errors.
* `btx_rc_token_file`: tests synthetic private tokens, CRLF/length limits,
  directory/missing-file rejection and public-access rejection using real
  Windows ACLs or POSIX mode bits. POSIX also tests symlink rejection and a
  FIFO containing a valid-length token with its writer closed: removing S_ISREG
  must make that fixture fail, independently of token size or read errors.
  Apple fixtures additionally test explicit read grants, inherited read grants,
  deny-only ACLs, cleanup back to a valid plain token, and invalid-fd inspection
  failure. These use actual OS ACL APIs/commands, not mocked ACL contents.
  An optional POSIX owner fixture runs only with effective UID 0; it reads a
  synthetic 0600 token owned by numeric UID 1. No account is created. Without
  privileges this isolated owner case reports an explicit SKIP. In an isolated
  privileged Linux run, the baseline passes and removing the UID guard makes
  the foreign-owner fixture fail. Windows ownership is not isolated by this
  POSIX fixture.

Validation on 1-2 November 2026, based on `btx-035/swarm` at
`cbf65894e6d61084527cd93e913a00c6794418dd`:

* Windows x64, MSVC 19.50: standalone CMake build and all three CTest entries
  passed, including the seven framing cases.
* Linux / WSL Ubuntu 22.04, GCC 11.4: standalone CMake build with
  `-Wall -Wextra -Werror` and the same three CTest entries passed.
* Windows x64, clang-cl 22.1.8: root CMake configuration with the prototype on
  and CUDA off succeeded; the actual prover translation unit compiled. This is
  an object compilation check, **not a complete prover link**.
* macOS 26.6.2 arm64, Apple clang 21: [native fork CI](https://github.com/lucasan123/btx/actions/runs/41397117678)
  on code commit `d1664e6bc567c01a6e5bba7ec702582423b24121` passed all three
  standalone CTest entries three times, plus the CPU policy and actual-handler
  tests. Private no-ACL tokens pass; explicit/inherited/deny ACLs and an invalid
  ACL fd are rejected. The original 7740583 token loader and a mutation removing
  the new ACL guard both fail the extended-ACL regression as expected. Core CPU
  test compilation uses the project's `-Wno-unused-parameter` setting; the
  standalone suite keeps `-Wall -Wextra -Werror`. This is CPU/OS validation,
  not a full prover link, Metal replay or GPU qualification.
* Isolated Linux mutation builds with 100-second read/write deadlines fail
  the corresponding deadline cases; renewing the deadline after every received
  fragment fails the slow-trickle case. The peers no longer close early and
  mask broken deadlines.

The Windows and Linux checks above were repeated after replacing the timeout
initialization with casts to each `timeval` member's declared type. This fixes
a narrowing error reported by [repch1c on macOS](https://github.com/btxchain/btx/pull/362#issuecomment-6556867035),
where `tv_usec` is an `int`. On the original commit with the same local fix,
repch1c reports three successful transport-test runs (all seven cases), prover
syntax compilation, and an oversize-check mutation caught by the tests. Those
are reviewer-reported results from that earlier revision. In a
[later review](https://github.com/btxchain/btx/pull/362#issuecomment-6557778906),
Jpp reports a complete macOS/Metal link, qualification and startup canary with
successful malformed-request checks on the pre-policy-fix version plus the
same timeout-initialization fix. Those earlier runs do not qualify the
strict-policy build; the later strict-policy retest and its memory-reserve
limitation are recorded below.

[repch1c subsequently tested 542f4d5 on macOS](https://github.com/btxchain/btx/pull/362#issuecomment-6559145656):
all three standalone CTest entries passed, 100-second read/write deadline
mutations failed, and prover/policy/protocol translation units passed syntax
checks. This was not a full in-tree link or Metal qualification of that revision.
His observation that the empty FIFO/owner cases did not isolate their guards
led to the filled-FIFO and optional privileged owner fixtures above. Both guard
removals now fail in isolated Linux tests, as do mode-check and O_NOFOLLOW
removals. The isolated UID-ownership case remains a privileged Linux check; native Apple
ACL validation for the current code is recorded in the validation results.

The subsequent full-slot timing assertion passed three listener runs each on
Windows/MSVC and Linux/GCC. With only `can_accept` forced to true in isolated
probe builds, the old test still passed, while the new test failed at that
assertion three times on each platform. No runtime source changed in this
test/documentation follow-up.

### Independent reviewer retests on 2 November 2026

[repch1c retested d1664e6](https://github.com/btxchain/btx/pull/362#issuecomment-6572903232)
on local macOS 26.6.2 / Apple M4 / Apple clang 21. The three standalone entries
and both manually compiled CPU policy/handler tests passed three runs. ACL
checks also accepted plain 0400 files and files whose ACL entry had been
removed, while rejecting owner-only, group and deny entries. Removing the ACL
guard, treating every ACL lookup failure as absence, restoring hard-coded
policy fields or restoring the underscore failure-kind spelling made the
corresponding tests fail. Reverting the listener fix caused resets, but removing
the pending limit still passed the old test. His measured 1.92-1.95-second wait
with the limit, versus an immediate response without it, motivated the new
lower-bound assertion described above.

[Jpp retested a12ae6f](https://github.com/btxchain/btx/pull/362#issuecomment-6573371622)
(the same runtime code; README-only changes after d1664e6) on macOS arm64.
He reports all four fixes holding, rejection of both explicit/inherited ACL
cases, a normal request answered in 1.8 seconds behind 32 idle peers, and 5/5
requests answered within 2 seconds against the earlier reconnect workload.
The full in-tree prover linked on Metal; live status reported strict-device
and CPU confirmation off. A wrong digest returned accel_failure /
unconfirmed-digest-mismatch while readiness stayed true. Both in-tree tests
passed three runs.

**Qualification limit:** Jpp disabled the 25% workspace reserve locally to run
on his 8 GB Mac, as in his earlier experiment. This is reviewer-reported full
link and live Metal behavior under that local modification, not qualification
with the unchanged production memory gate. He did not run the live not-ready
path or the root-only owner fixture. The reserve in this PR remains unchanged;
full supported-hardware qualification is still required.

### Policy and actual request-handler regression checks

The in-tree opt-in build also provides `btx-rc-replay-policy-test` and
`btx-rc-request-protocol-test`. Build and run those targets directly (or use
`btx_rc_replay_policy` / `btx_rc_request_protocol` when BTX test registration is
enabled). They include the current BTX headers and need a compatible core C++
toolchain, unlike the independent standalone socket/permission suite.

The CPU-only policy test uses real result/enumeration types and stub setters.
It checks strict-device/no-CPU-confirmation setup, eight readiness
classifications from ready/unavailable states, mismatch/success/fault sequences,
dimension/null-seed/null-digest prechecks and canary admission including
MissingGolden. Isolated Linux mutation builds fail when restoring the old
readiness latch, AutoFallback, CPU confirmation on, omitting prechecks or using
the old canary outcome-label gate.

The protocol test exercises the **actual request parser and handler** with a
replay callback and episode-resolution/name helpers replaced by test doubles.
It covers malformed JSON, authentication/type/operation errors, short/trailing
header bytes, height/profile/id bounds, invalid nBits/target, all three cheap
header prechecks, and mismatch/success/execution-fault/unavailable sequences.
Rejected requests must not call replay or change readiness. It round-trips an
actual serialized header with nNonce64 = UINT64_MAX; this is separate from the
transport byte check. It also verifies that a status response may be processed
successfully while ready is false, canonical failure names, and live status
changes between auto-fallback, configured strict-device and CPU diagnostic
policies with different confirmation settings. Both test executables passed on
Windows/clang-cl, Linux/GCC (`-Wall -Wextra -Werror`) and native
Apple clang 21 with the core unused-parameter setting described above.

These tests do not run the actual production main/qualification path, perform
real GPU replay or establish consensus correctness. The listener probe is a
test process; protocol tests use an in-process handler and a synthetic backend.

### Still required before this could be considered for integration

- Full Windows and Linux links on supported toolchains, then real CUDA
  self-qualification and startup canary on supported hardware. Repeat real-GPU
  replay tests with the strict-device policy and CPU confirmation disabled.
- Positive and negative canonical-header vectors against the in-tree oracle,
  wrong digest/nonce/target/profile cases, malformed JSON and authentication
  tests against the actual process, GPU loss and service recovery.
- Agreement on the node/backend trust boundary, qualification identity,
  version negotiation, limits and correlated-failure behavior.
- A separately reviewed node integration; this PR adds none.
- Full regression/release qualification. No production routing was changed
  to test this draft, and the current pool binaries were not replaced.
