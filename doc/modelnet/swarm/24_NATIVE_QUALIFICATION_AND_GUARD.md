# Native checkpoint, tool, release, and guard implementation

This document describes the source paths added on top of PR 245. A successful
component test is scoped to the executable, input hashes, and observed host in
its result. It does not set `btx_deployment_qualified`, qualify another operating
system, prove distinct physical hosts, or authorize a payment.

## Runnable owner interface

CMake builds and installs `btx-native-qualify` with Modelnet:

```sh
btx-native-qualify sign-checkpoint /absolute/source-sign-request.json
btx-native-qualify load /absolute/load-request.json
btx-native-qualify tool /absolute/tool-request.json
btx-native-qualify release /absolute/release-request.json
```

The equivalent `--sign-checkpoint`, `--load`, `--tool`, and `--release` spellings
are accepted. Each command reads one regular JSON request of at most 1 MiB,
rejects duplicate keys, and emits a single JSON result. Exit 0 means that exact
operation succeeded; exit 2 reports a refusal/failure. CLI usage errors exit 1.
The executable does not start a server, read a wallet, or create spending
authority. `automatic_spend_atoms` remains `"0"`.

Results have schema `BTX/NativeQualificationResult/v1`, the request SHA-384,
start/finish timestamps, `success`, and an error code on failure. The request
file is **owner policy**: do not turn a received peer card into an executable
path, expected result, source trust pin, or release key without owner review.
The schema file `native-qualification-request.schema.json` documents all four
request shapes; run-time validation also enforces cryptography, file bounds,
path restrictions, expiry, and the exact six-gate set.

## Checkpoint source signing and real consumption

`Load01::LoadVerified` verifies an ML-DSA-44 source receipt against a separately
supplied expected public key and nonce. The receipt binds the artifact ID,
SHA-384 of the whole checkpoint, exact byte length, nonce, expiry, and source
key. Expiry must be in the future and no more than one hour away. Two sources
count only when distinct pinned public keys sign the same artifact and digest.
Two filenames, two ports, or a caller-supplied provider count do not count.
Distinct public keys alone do not prove distinct machines or operators.

The loaded file must be SafeTensors with a bounded JSON header, unique tensor
names, supported scalar widths, valid shapes, and exact contiguous data
extents. Holes, overlaps, trailing data, digest mismatches and malformed files
are rejected before replacing resident state. Failed replacement preserves the
previous verified checkpoint. Successful loading keeps owned bytes in memory;
`TensorBytes` and `LinearF32` consume those verified bytes without reopening the
source path. Changing the source file after loading does not change execution.

The local signer reads **actual checkpoint bytes** and uses a separately
provisioned source secret. A signing request has these fields:

```json
{
  "checkpoint_path": "/absolute/source/checkpoint.safetensors",
  "artifact_id": "<96 lowercase hex characters>",
  "request_nonce": "<64 lowercase hex characters>",
  "expires_at_ms": 1792678000000,
  "max_checkpoint_bytes": 1073741824,
  "source_public_key": "<2624 lowercase hex characters>",
  "source_secret_file": "/absolute/private/source-key.hex"
}
```

The timestamp shown is illustrative; construct a fresh timestamp for each
request. Signing secrets contain 5120 lowercase hex characters (2560 bytes),
with at most one final newline. POSIX files must belong to the effective user
and grant no group/other permissions. On Windows, the file owner must be the
current user and allowed ACL entries may grant access only to that user and
SYSTEM. Secrets are passed by private file, never a command-line argument or
inherited environment variable, and their owned buffers are cleared on exit.
The signer verifies its own output against the pinned public key, refusing a
mismatched secret. It returns `receipt` and `scope: SOURCE_ATTESTATION_ONLY`.
Signing does not parse or qualify model behavior.

Acquire each receipt from its intended source using separately established
source identities. Put the resulting receipt object into a load request:

```json
{
  "max_checkpoint_bytes": 1073741824,
  "sources": [
    {
      "path": "/absolute/source-a/checkpoint.safetensors",
      "expected_source_public_key": "<source A public key hex>",
      "expected_request_nonce": "<source A nonce hex>",
      "receipt": {
        "artifact_id": "<artifact SHA-384 identifier>",
        "checkpoint_sha384": "<actual checkpoint SHA-384>",
        "bytes": 123456,
        "request_nonce": "<source A nonce hex>",
        "expires_at_ms": 1792678000000,
        "source_public_key": "<source A public key hex>",
        "signature": "<4840 lowercase hex characters>"
      }
    },
    {
      "path": "/absolute/source-b/checkpoint.safetensors",
      "expected_source_public_key": "<source B public key hex>",
      "expected_request_nonce": "<source B nonce hex>",
      "receipt": "<the complete receipt OBJECT returned by source B>"
    }
  ],
  "linear": {
    "weights": "weight",
    "bias": "bias",
    "input": [1, 2, 3],
    "expected_output": [14.5, 31.5]
  }
}
```

Placeholders must be replaced with real values, and the second `receipt` must
be a JSON object matching the first receipt's shape. A complete executable
fixture is generated by the test runner below; its deterministic test identities
must never be installed as operational identities.

The native consumer currently evaluates a bounded F32 dense layer, with an
optional bias (use an empty bias name when absent). The matrix has shape
`[outputs, inputs]`; input and output values must be finite. The CLI requires
exact F32 output equality with the owner-provided vector. A successful `load`
requires real consumption after at least two verified source identities. It
reports actual outputs, tensor count, checkpoint hash and `physical_host_count:
1`. This demonstrates real native tensor consumption. It does not assert that
an arbitrary decoder architecture, tokenizer, quantization scheme, GPU kernel,
or the existing `generatemodel` runtime can consume that model.

The signing message is generated by `CheckpointSourceMessage`, not JSON text.
It consists of the domain `BTX/CheckpointSource/v1`, artifact ID, checkpoint
SHA-384, byte length, request nonce, expiry, and raw source public key. String
fields use an unsigned 64-bit little-endian byte length followed by UTF-8
bytes; integer fields use unsigned 64-bit little-endian encoding. The raw
public key also has an unsigned 64-bit byte-length prefix. Consult that
function before implementing another-language signer; it is the byte-level
contract.

Legacy FNV `Load()` remains integrity-only. It now accepts a second local
source path, but clears native qualification and never grants signed provenance
or release qualification.

## Native tool package qualification

A `tool` request has one `probe` object:

```json
{
  "probe": {
    "root": "/absolute/isolated/package",
    "executable": "probe",
    "files": [
      {"path": "probe", "sha384": "<96 hex>", "bytes": 123456},
      {"path": "input.bin", "sha384": "<96 hex>", "bytes": 4096}
    ],
    "output_relative_path": "result.json",
    "expected_output_sha384": "<96 hex>",
    "expected_output_bytes": 125,
    "max_package_bytes": 1073741824,
    "wall_seconds": 60
  }
}
```

The executable and every package file must appear in the pinned manifest;
unlisted files, reparse objects, excessive tree depth and extra output files
are refused. Paths must stay inside the
root, and symlinks/traversal are rejected. The expected output must not already
exist. Native qualification hashes the inputs, executes the actual helper
inside the platform sandbox, requires normal exit zero, verifies newly produced
exact result bytes, and rechecks the original inputs. Evidence records the
package/executable/output hashes, observed OS and CPU architecture, exit status
and elapsed time. A helper that exits nonzero, cannot be confined, produces
wrong bytes, modifies its pinned inputs, or reuses stale output cannot pass.

The helper and expected results are owner-reviewed test policy. This framework
cannot infer whether an arbitrary supplied test adequately evaluates privacy,
revocation, model quality, or adversarial behavior. Pin the actual intended
tests and their dependencies in the package, and independently review them.

### Native isolation backends

| Platform | Implemented enforcement | Native validation still required |
|---|---|---|
| Linux | User, mount and network namespaces; UID/GID mapping; `pivot_root` (no chroot fallback: if it fails, the helper does not run); `no_new_privs`; CPU/file-descriptor limits; scrubbed environment/descriptors; wall timeout and process-group cleanup | Namespace-enabled host, real outside-file and network escape probes, actual workloads |
| macOS | Parameterized default-deny Seatbelt profile loaded from the OS sandbox library; helper-only execution; root writes; system-library reads; network/IPC denial; CPU/address-space/descriptor/wall limits | Apple runtime/SDK combinations, native escape probes and actual workloads |
| Windows | Fresh AppContainer with zero capabilities; actual low-integrity token/SID/capability verification; protected private staged tree; explicit inherited NUL handles; one-process Job with CPU/memory/wall limits; output/input revalidation and cleanup | Native Windows build and escape tests; actual workload qualification |

The Linux filesystem jail now creates `CLONE_NEWNET`; the earlier code only
recorded the `network_denied` request. Setup/exec errors use a CLOEXEC handshake
so a helper's own exit 126 cannot masquerade as a setup failure or vice versa.
Timeouts terminate only processes owned by this invocation. Limits fail closed
if the kernel refuses them.

The macOS implementation uses `sandbox_init_with_parameters` from the system
library rather than removed named-profile SDK constants. Its explicit OS
exceptions permit read-only system frameworks/dylibs and minimal runtime
resources. These source paths have not been validated on macOS in the Linux
build environment.

Windows never grants AppContainer ACL rights to the owner's original package
or wallet directories. It copies bounded, non-reparse regular inputs into a
fresh profile, executes there, verifies unchanged inputs, and copies only fresh
regular outputs back without replacement. The sandbox permits its own temporary
profile and Windows' normal AppContainer system resources; it does not claim a
Unix chroot. Reparse objects are rejected, and cleanup deletes junctions without
following them. Network access is denied by zero capabilities. Only the two NUL
handles supplied for stdin/stdout/stderr are inherited. No shell, wallet handle,
or parent environment is inherited. The Job caps one process and kills it when
the owner handle closes. `max_nofile` is a POSIX descriptor quota; Windows bounds
inherited handles and process memory instead of claiming a nonexistent generic
per-process handle-count quota. Additional output bytes are capped at 64 MiB.
Windows source requires the Windows 10 SDK selected by this repository. The Windows code has
passed a MinGW GCC 13 cross-compiler check with warnings treated as errors;
this does not execute Windows or qualify its native behavior. The component
cross-build also linked five real Windows PE executables, including the native
qualifier, guard, guard tests, sandbox probe and private release-file tests.

## Defensive model release

Legacy `QualifyModified(..., true, true)` records a claim only. Legacy
`IssueRelease(..., true)` cannot issue a release. Native release requires six
actual tests: `external-controls`, `outcome`, `revocation`, `rollback`, `privacy`,
and `adversarial`. Missing, duplicate or unknown gates fail before any test runs.
Every gate's pinned package must include the exact changed model, external
controls, and runtime image bytes named by the policy. The modified model hash
must differ from its parent hash. A source revision and realm scope are explicit
owner policy fields; a caller label is not independently measured provenance.

A release request contains:

```json
{
  "policy": {
    "model_id": "<96 hex>",
    "model_path": "/absolute/changed-model.safetensors",
    "model_sha384": "<96 hex>",
    "model_bytes": 123456,
    "max_model_bytes": 1073741824,
    "parent_model_sha384": "<different 96 hex>",
    "controls_sha384": "<96 hex>",
    "source_revision": "<40 lowercase hex>",
    "runtime_image_sha384": "<96 hex>",
    "realm_id": "<96 hex>",
    "expires_at_ms": 1792678000000,
    "release_public_key": "<2624 lowercase hex>"
  },
  "gates": [
    {"gate_id": "external-controls", "probe": "<complete probe OBJECT>"},
    {"gate_id": "outcome", "probe": "<complete probe OBJECT>"},
    {"gate_id": "revocation", "probe": "<complete probe OBJECT>"},
    {"gate_id": "rollback", "probe": "<complete probe OBJECT>"},
    {"gate_id": "privacy", "probe": "<complete probe OBJECT>"},
    {"gate_id": "adversarial", "probe": "<complete probe OBJECT>"}
  ],
  "version": "research-v1",
  "output_path": "/absolute/releases/research-v1.json",
  "release_secret_file": "/absolute/private/release-key.hex"
}
```

Each `probe` placeholder must be replaced with the full object shown above.
Use separate per-gate roots/output names. The expiry must be current and no
more than 24 hours ahead. Before signing, all model, test-input and test-output
bytes are revalidated. The research signing key must match the pinned public
key. The signed document has schema `BTX/DefensiveLearningRelease/v1`, scope
`EXACT_MODEL_AND_LISTED_GATES`, exact evidence hashes and times, zero automatic
spend, and `btx_deployment_qualified: false`.

The signature binds the compact serialized `release` object with domain
`BTX/DefensiveLearningReleaseSignature/v1` and 64-bit little-endian length
prefixes. Consumers must retain the emitted serialization or implement its
canonical ordering. The envelope includes `signing_public_key` and `signature`;
the whole document SHA-384 is returned separately.

POSIX writes a private temporary file, flushes it, links it exclusively into
place and flushes the directory. Windows creates a private owner/SYSTEM-only
temporary file, flushes it and atomically renames without replacement. A
preexisting release or symlink is refused. No successful six-gate release is
claimed from a host where the native sandbox could not run.

## Owned guard process

`GuardSupervisor` is connected to the default swarm observer lifecycle. It
locates the packaged sibling `btx-guardd` instead of searching `PATH`, starts it
with `--stdio`, requires `PING` → `READY BTX_GUARD/1`, performs health checks,
reaps exited children and restarts with bounded exponential backoff. Status
reports `enabled`, `ready`, `pid`, `restart_count` and an error. The persisted
`guard-process.json` includes a timestamp, a six-second validity bound, a
heartbeat sequence and READY/RESTARTING/STOPPED state. Consumers must treat
expired observations as unavailable. Orderly shutdown writes STOPPED with
`enabled: false`, `ready: false` and `pid: -1` after reaping. A missing or
unhealthy helper is an observable degraded condition; the monetary daemon
continues independently. Stop closes the private request pipe, waits briefly
for EOF shutdown, then terminates/reaps only its owned child if needed.

On POSIX the child inherits only stdin/stdout pipes, stderr mapped to
`/dev/null`, and `LANG=C`/`PATH=/usr/bin:/bin`. All other descriptors close before
exec. On Linux parent-death handling supplements EOF. On Windows the child uses
an explicit three-handle inheritance list, a clean LANG/SystemRoot environment,
and a one-process kill-on-close Job. No wallet secret or parent environment is
supplied to either backend.

`btx-guardd` has no default TCP listener. Legacy diagnostic loopback mode requires
both `--port N` and `--allow-legacy-loopback`; it is not the observer transport.
The private protocol bounds each line to 4096 bytes and the permit table to 4096
entries. Secrets use the OS CSPRNG. Negative/overflowed generations, extra
fields, timestamp overflow, clock rollback, replay and expiry fail closed.
Pause revokes outstanding permits; resume never revives them. A restart loses
all existing bearer permits.

A successful `CONSUME` (and the compatibility spelling `EXECUTE`) returns:

```text
RECEIPT <receipt-id> PERMIT_CONSUMED NOT_DISPATCHED
```

It consumes a one-use gate capability. It does not claim physical model work or
payment execution. The lab client and `lab.action_execute` report the same
honest distinction instead of returning `EXECUTED/STOPPED_QUIESCENT` for an
operation that never dispatched work.

## Reproducible verification

On Linux or macOS:

```sh
python3 test/util/native_qualification/run_tests.py \
  --build-dir /absolute/native-component-build \
  --report /absolute/native-component-results.json
```

This component runner compiles the actual repository ML-DSA implementation and
native sources, signs and verifies two checkpoint sources, executes a dense
layer, exercises tamper/path/expiry/nonfinite failures, runs signer-to-loader
CLI integration, and tests an actual owned guard process. The guard tests
include native child-side verification of the exact environment and inherited
descriptor boundary, CSPRNG permits, replay/pause behavior, restart/backoff,
clock rollback, line bounds and EOF shutdown. The runner attempts a real
filesystem/network probe. A kernel that refuses namespaces yields
`BLOCKED_OS_SANDBOX_UNAVAILABLE`; it cannot produce a native platform pass.

The Linux run in this work completed 42 component assertions and 27 real guard
process assertions, plus CLI tests. Native Linux sandbox execution remained
blocked by the execution host's namespace policy. macOS and Windows native
qualification remain unrun. A full daemon build is separate from this targeted
runner and must be recorded separately.

On Windows, build `btx-native-qualify` using the normal project Windows 10 SDK
configuration, then run in a Visual Studio Developer PowerShell:

```powershell
./test/util/native_qualification/run_windows_tests.ps1 `
  -QualifierPath C:\btx\bin\btx-native-qualify.exe `
  -ReportPath C:\btx-tests\native-windows-results.json
```

The Windows components can also be cross-compiled with an existing MinGW
compiler without executing them:

```sh
python3 test/util/native_qualification/cross_compile_windows.py \
  --compiler /absolute/x86_64-w64-mingw32-g++-posix \
  --build-dir /absolute/windows-components \
  --report /absolute/windows-cross-compile-results.json
```

The report explicitly records `native_windows_execution: NOT_RUN`. After
copying those test binaries to Windows, the additional native checks are:

```powershell
.\guard-supervisor-tests.exe C:\btx\bin\btx-guardd.exe
.\windows-release-file-tests.exe C:\btx-tests\empty-private-directory
```

The second command checks private owner-only ACLs, exclusive creation and
non-replacement using the real Windows release-file primitive. It does not
issue or qualify a model release. The directory must exist and be empty.

The script compiles `windows_sandbox_probe.cpp` (or accepts `-ProbePath`), starts
an owned loopback listener, supplies an outside private witness, and requires
actual Windows `ERROR_ACCESS_DENIED` for the file and `WSAEACCES` for the network
connection. A missing file, connection refusal or timeout cannot pass these
checks. It also checks environment scrubbing, process-creation refusal and stale
output rejection. The result remains local component evidence with deployment
qualification false. Native release-signing, meaningful model gates, GPU work,
multiple physical hosts and cross-platform workloads require their own real
execution evidence.

### Platform API references

Implementation uses the official Windows AppContainer model and process-start
attributes described by Microsoft:

- <https://learn.microsoft.com/en-us/windows/win32/secauthz/implementing-an-appcontainer>
- <https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation>
- <https://github.com/microsoft/SandboxSecurityTools/blob/main/LaunchAppContainer/LaunchAppContainer/LaunchAppContainer.cpp>

The macOS API loading approach is consistent with the system-library wrapper
used in Chromium's Seatbelt implementation:

- <https://chromium.googlesource.com/chromium/src/sandbox/+/refs/heads/main/mac/seatbelt.cc>
