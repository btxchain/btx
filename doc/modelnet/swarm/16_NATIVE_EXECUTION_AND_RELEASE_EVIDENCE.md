# Native participation, execution and release evidence

Candidate baseline: PR 245 at
`7f59e41f08e0394b13dd8e9f47015c0e7a3f8753`. This is a source implementation
and verification handoff for **0.35.0rc1**, not the shipping tag `v0.35.0`.
The last shipping tag recorded by this candidate is **v0.34.15**.
`CLIENT_VERSION_IS_RELEASE=true` describes the build version; it does not
mean that the native acceptance catalogue has passed.

## Default participation in this patch

The node continues to own startup. With Modelnet compiled, ordinary `btxd`
starts its managed helper and observer without an additional swarm daemon.
The helper now owns actual native LAN discovery and PQ1 admission. The
process-local `FormationPlane` remains a bookkeeping component; its return
value is not used as proof that a socket was opened or a remote peer admitted.

Native LAN discovery uses a bounded IPv4 multicast hint on private interfaces
(`239.192.0.35`, UDP port `29448`, TTL 1). A hint is untrusted. A peer only
appears as authenticated after the existing strict PQ1 transport succeeds and
the chain-specific availability response validates. This changes the discovery
path without mixing model peers with monetary AddrMan/BanMan or changing
consensus. WAN bootstrap infrastructure is a separately deployed dependency;
this patch does not invent public seed operators.

A fresh headless `auto` store receives a bounded **1 GiB** initial payload
budget. An explicit zero, saved disabled state, or zero/malformed environment
override is preserved. Within that budget, verified FREE model acquisition can
proceed from admitted peers. An empty store without a usable peer or verified
eligible listing remains empty and reports the missing prerequisite. Acquisition
does not authorize model execution, training, a private prompt, or payment.

`getmodelnetworkinfo` and `getmodelpeers` expose `native_participation`:

| Field | Meaning |
|---|---|
| `schema` | `BTX/NativeParticipation/1`. |
| `network` | Network binding for the observed helper. |
| `lan_enabled`, `lan_error` | Whether local discovery started and its current error. |
| `hint_count` | Bounded untrusted hints observed locally. |
| `authenticated_peers` | Successful PQ1/availability observations still within their 90-second TTL. |
| `peer_observations` | Endpoint, transport pin, observation/expiry time, advertised model IDs and `compute_authorized: false`. |
| `shared_model_families` | Locally verified model IDs and remote availability-advertisement pins; role is `observer`. This does not attest remote model quality or runtime authority. |
| `acquired_models` | Verified acquisitions completed during this helper lifetime. |
| `automatic_spend_atoms` | The canonical string `"0"`. |
| `release_qualified` | Remains false in the runtime status; qualification comes from a separately evaluated acceptance package. |

The helper atomically publishes the same observation under
`modeldir/swarm/native-participation.json`. `peers_connected` is the number of
currently open sockets; it is not a persistent-membership counter. An empty
peer list is not a successful discovery experiment. Model availability and
physical hardware capacity are separate observations.

The node's observer supervises the real `btx-guardd` subprocess. Its separate
`modeldir/swarm/guard-process.json` has schema `BTX/GuardProcess/1` and fields
`enabled`, `ready`, `pid`, `restart_count`, `error`,
`transport: PRIVATE_INHERITED_STDIO`, `automatic_spend_atoms: "0"`, and
`execution_authorized: false`. The native driver checks that the PID is alive;
on Linux it also hashes `/proc/<pid>/exe` and verifies the parent is this
scenario's node. Guard protocol readiness does not grant model/tool execution.

## What has actually run locally

The screenshot statuses are retained as historical input. The inventory's
`current_status` and `current_evidence` fields distinguish this patch's measured
results from outstanding physical deployment and vendor integration work.

| Scope | Observed result | Limit |
|---|---|---|
| Fresh Linux node | The new native driver launched built `btxd`, observed the real default helper, strict PQ1 readiness, durable participation, zero spend, and an owned live guard with matching executable hash. | One host; loopback model bind. No model execution, physical LAN or release qualification. |
| Packaged Linux runtime | Collected 33 actual binary/library/license/report files (261,279,703 bytes), built and verified the archive, launched extracted `btxd` with its packaged libraries, and passed the fresh native helper/PQ1/owned-guard checks from that image. | One Linux host with networking available. No physically disconnected run, cross-platform image qualification or bootable OS image. |
| Native LAN and bootstrap loss | `feature_swarm_lan_discover.py` passed real discovery, distinct PQ1 pins, default 1 GiB/explicit-zero storage, first free acquisition, shared observer families, owned guards, and acquisition after the original publisher stopped. | Four native processes on one host. The two-physical-host profile remains unrun. |
| Native SHA-256 HTLC economics | `wallet_modelnet_funding.py` and `feature_swarm_funded_objective.py` passed real funding/claim/refund, exact destination/fee checks, claim reorg revocation/restoration, expiry, early-refund rejection, recovery-journal restart and confirmed owner refund. | Isolated one-host regtest. Revocable/routed payment modes and coordinated physical fault topology are not qualified. |
| Native checkpoint/tool/release modules | Real signed checkpoint bytes and confined probe execution have local native tests; their CLI binds source/model/runtime/control evidence. | CPU dense-layer consumption is not a complete native decoder, GPU trainer or advertised vendor stack. |
| Trained checkpoint to native consumer | `gpu_training.py --allow-cpu` passed four bounded training steps and exact full-state replay with two local Gloo ranks. Its actual 123,344-byte, 25-tensor SafeTensors export received two local fixture signatures through `btx-native-qualify sign-checkpoint`; `checkpoint_bridge.py` then passed native verification and exact 64-value dense-layer output from those same trained bytes. | `CPU_ONLY`, one physical host, locally generated deterministic test identities. This demonstrates distinct signing keys, not independent administrative sources, GPU execution, a full native decoder or vendor-engine integration. |
| Python regression suites | All 13 original `contrib/swarm/tests` tests, 70 native-acceptance regressions and eight native-payment regressions passed. The original suite used CPU-only PyTorch 2.10.0 and OpenSSL 3.5.8. | Process-local regression evidence; the original evolution pipeline remains a synthetic CPU experiment. No GPU or vendor-engine qualification follows. |

These scoped passes do not rewrite the sealed catalogue. The full test tree,
remaining profiles and advertised platforms still require their own measured
records from the exact integrated candidate and binaries.

## Requirement accounting

The supplied gap report names 21 open behavioral requirements and 189 rows
whose native deployment was not run. The complete transcription and base
source mappings are in
[`SCREENSHOT_REQUIREMENTS.json`](../../../contrib/swarm/native_acceptance/SCREENSHOT_REQUIREMENTS.json)
and its CSV companion. The report's other 163 earlier closures do not become
qualification of this candidate. The original sealed 573-row acceptance
catalogue is preserved; its IDs and bytes must be supplied by its owner.

| Open IDs | Source work and required execution |
|---|---|
| `NIF-QA-007`, `DT-REL-003`, `DT-REL-007` | Native default-on runner, immutable receipts, complete catalogue gate, deterministic runtime packaging; real native/platform/GPU/topology runs still required. |
| `ASR-ART-005`, `ASR-CAP-002` | Verified multisource runtime loading and real tool-environment execution must produce artifact/environment evidence; file presence alone cannot qualify them. |
| `ASR-PAY-004`, `P2P-SCN-M`, `DS-PAY-002`, `DS-PAY-003` | Native wallet/transaction execution and confirmed chain observations for each advertised mode, ownership, refund, fee, expiry, stale-state and watchtower path. A prepared plan or submitted txid is insufficient. |
| `ASR-ACC-001`, `P2P-SCN-D`, `DS-OPS-006` | Independently enrolled participants/organizations; public-family membership and local validation must be observed on real machines. |
| `ASR-PUB-003`, `DS-DEL-003` | Current candidate/version, default storage/guard/LAN, RPC and complete helper-build contracts are aligned. Operator CLI waits now use native milliseconds; cloud HTTPS selection is explicit; profile overrides are sent/applied and reported. Historical release notes remain historical. |
| `DS-HIRE-003`, `DS-LEARN-001` | Outcome-qualified modified model and explicit release authority, with independent controls and holdout/benign-impact evidence. A caller Boolean cannot issue a release. |
| `DS-REC-006` | Ordered, measured partition/clock/response/liquidity fault and recovery phases across hosts. |
| `P2P-SCN-B`, `P2P-SCN-C`, `P2P-SCN-E` | Native LAN discovery and bootstrap-loss continuation passed with four local processes. Actual removal of internet access and independent physical LAN execution remain unrun. |
| `P2P-SCN-I` | Distinct GPUs performing one actual training task, with full-state checkpoint/replay and native engine integration. The provided NCCL workload does not by itself establish the BTX engine integration. |

There is no network-wide scheduler requirement. Local resource and authority
decisions remain local. The missing evidence is actual participation and
execution, not the existence of a global task assigner.

## Build and run the exact candidate

Use the platform build instructions in `doc/build-unix.md`, `doc/build-osx.md`
or `doc/build-windows-msvc.md` to obtain the toolchain and pinned dependencies.
Configure Modelnet and build every helper required by the advertised product:

```sh
cmake -S . -B build-native -DWITH_MODELNET=ON -DBUILD_GUI=OFF -DBUILD_TESTS=ON
cmake --build build-native --target btxd btx-cli btx-modeld btx-guardd btx-hcpd btx-native-qualify test_btx -j 4
```

Run the full `test_btx` target, the complete peerman suite, the affected
functional tests, and the full functional tree under its normal supported
configuration. In particular, reproduce the screenshot's
`feature_matmul_heard_serve.py` propagation failure with its activation flags
intact. Disabling matmul changes the test and cannot close that failure.
Build `btx-hcpd` before running `feature_modelnet_cr12_stage_chunk.py`; a
missing-binary skip is not a test success.

The native execution commands and exact trust model are in
[`contrib/swarm/native_acceptance/README.md`](../../../contrib/swarm/native_acceptance/README.md).
Generated plans pin the complete source tree, binaries, drivers and inputs.
The driver starts a fresh isolated regtest node without forcing Modelnet on or
substituting an absent helper. It checks real PQ1/native observations and stops
only the child daemon it launched. Its process fixtures never inherit public
release status.

An explicitly pinned `--model-run` request executes actual
`hostmodel`/`exportmodelpath`/`loadmodel`/`generatemodel`/`unloadmodel` with
byte checks and an independently approved output. The distributed GPU workload
exports its actual final trained weights; `checkpoint_bridge.py` feeds those
same signed bytes to native `Load01::LinearF32`. The WAN driver requires
owner-enrolled public IPs and PQ1 pins, pre-provisioned local identities, two
fresh remote observations per member and three physical-host enrollments.
The two-local-rank CPU training/export/native-dense path has executed as scoped
above. Separate complete-model, physical GPU and WAN inputs remain unrun.

`collect_runtime.py` inspects actual native dependencies, `offline_image.py`
creates a deterministic complete-file manifest/archive, and `offline_exec.py`
rehashes an installed image before selecting its packaged library path. That
source work does not supply a finished Windows/macOS/Ascend image or physically
disconnect a host. Complete native vendor inference/training adapters and the
combined partition/clock/provider/liquidity fault experiment remain explicit
implementation or deployment gaps; a generic bounded phase runner does not
silently count as those drivers.

The vendor provenance audit distinguishes a research citation from an adopted
build dependency. `docs/modelnet/BTX_0348_JIT_Capability_Development_Spec.md`
cites NIXL commit `d24959417cefb5ab5bfb8d132020da010a323684` and Mooncake commit
`ffe013517eaafa8f33e5e0ee034fd6b8f5561e92` in its source references [R06] and
[R07]. Those exact references are present in the specification; they are not
adopted, built or integrated engine pins. The repository does not identify a
DeepInfer upstream URL and revision to build. Selecting reviewed upstream
revisions, implementing the actual engine adapters and integrating them into
the native inference/training paths are source work still required. Obtaining
the corresponding hardware and running qualification come after that work.
This audit is of repository contents and does not assert remote revision
availability or compatibility.

## Qualification rules

All 32 named profiles must have current evidence. This includes native start,
whole-node airgap, useful CPU model, private-case revocation, economics,
failure/rollback, offline image, macOS, Windows, two-host LAN, three-host WAN,
the SM100/Ascend/DeepInfer profiles, exact multirank state, and `DT-Q01` through
`DT-Q18`. A profile name is not an engine implementation.

The independent gate requires the original catalogue hash and at least its
573 rows, independently reviewed plan digests for every row, all 32 profile
rules, finite evidence freshness, and enrolled physical-host/GPU identities.
Every accepted receipt binds the same candidate and fresh challenge, records
the actual command outputs, and satisfies the approved assertions. Changing
the source or a binary requires a new run. Missing evidence stays `NOT_RUN`,
failed execution stays `FAIL`, and missing hardware/toolchains stay explicitly
blocked; none is silently converted to `PASS`.

Receipt HMACs authenticate the recording authority. They are not consensus
signatures, PQ1 identities, or hardware-root attestation. The operator's
independent physical inventory remains necessary. The archive verifier checks
bytes and metadata; native offline operation additionally needs actual
disconnected execution and a complete runtime dependency closure.

The release gate can produce `release_qualified: true` when all evidence
conditions are met. Ordinary runtime/status reports and process-local unit
records cannot produce that authority by setting a field. No publication,
release tag, spending mandate or vendor qualification is created by a source
patch or by passing the verification tools' own regression tests.
