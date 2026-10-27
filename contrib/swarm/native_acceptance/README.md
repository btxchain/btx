# Native candidate execution and evidence

This directory provides executable verification and packaging code for the
remaining PR 245 deployment gaps. It is separate from the process-local
`Pass()` record classes. A successful record-class call, a missing-helper
fallback, a declared `gates_passed` Boolean, and an exit code of zero do not
qualify a deployment.

## What is implemented

| File | Behavior |
|---|---|
| `evidence.py` | Runs bounded child processes without a shell; records source, executable, input and output hashes; probes native machine/GPU identities; authenticates receipts. |
| `runner.py` | Runs finite plans on local and authenticated SSH hosts; executes independent steps in parallel within ordered phases; always runs explicitly designated cleanup phases; applies observed-output assertions; gates the sealed catalogue. |
| `prepare_plan.py` | Generates start/platform/owner-authorized model/LAN/WAN plans from actual local files; combines separately enrolled machine plans into one parallel experiment. |
| `native_node.py` | Starts actual packaged `btxd` in a new private regtest datadir, waits for its real default helper and PQ1 participation, checks durable status and owned live guard, optionally publishes a pinned seed or waits for acquisition, and stops only its own daemon. |
| `native_model.py` | Exercises actual host/export/load/generate/unload RPCs, checks exact materialized model bytes, optional CUDA residency, expected decoder/backend/device and independently approved output. |
| `wan_peers.py` | Stages owner-enrolled TLS identities and public-IP certificate pins in a fresh private node, then verifies fresh same-chain observations for the exact enrolled remote peers. |
| `gpu_training.py` | Performs real CUDA/NCCL decoder training across ranks, identifies every GPU, checks gradient-synchronized parameters, and verifies exact replay of model/optimizer/RNG/sampler state. Explicit CPU/Gloo mode is labelled `CPU_ONLY`. |
| `checkpoint_bridge.py` | Exports the actual trained in-memory weights to SafeTensors and drives `btx-native-qualify load` against two independently signed/pinned sources, checking the same trained bytes and an exact native dense-layer output. |
| `collect_runtime.py` / `offline_exec.py` | Inspect actual native dependency graphs and construct locks; verify installed image contents before launching with the packaged library search path. |
| `offline_image.py` | Builds byte-reproducible offline archives from pinned local binaries/dependencies; rejects missing helpers, links, traversal, duplicates, noncanonical metadata, oversize archives and digest mismatches. |
| `SCREENSHOT_REQUIREMENTS.json` / `.csv` | Enumerate all 21 open behavioral items and 189 in-process-only rows, their base source mappings, all 32 profiles, and the external evidence gaps. |

The screenshots report 373 total requirements, 210 never exercised natively,
163 earlier closures that are not qualification of this candidate, and a sealed
573-row acceptance catalogue. The screenshots do not reveal the 163 prior IDs
or the sealed catalogue's row IDs. This package does not invent them. Bring the
authoritative private catalogue to the gate unchanged.

## Prepare and execute a real fresh-node run

Build all five binaries (`btxd`, `btx-cli`, `btx-modeld`, `btx-guardd`, and
`btx-hcpd`) from the integrated candidate. Put plans, keys, logs, checkpoints,
and receipts **outside** the source checkout. Source hashes include uncommitted
and untracked nonignored files; changing the candidate invalidates older
receipts. For cross-platform work use identical checkout bytes, including
consistent line endings.

```sh
python3 contrib/swarm/native_acceptance/runner.py init-key /tmp/btx-native-receipt.key
python3 contrib/swarm/native_acceptance/prepare_plan.py local \
  --root /absolute/path/to/btx \
  --bin-dir /absolute/path/to/btx/build/bin \
  --work-dir /tmp/btx-native-fresh-245 \
  --profile fresh-native-start \
  --out /tmp/btx-native-fresh-plan.json
python3 contrib/swarm/native_acceptance/runner.py run \
  --plan /tmp/btx-native-fresh-plan.json \
  --key-file /tmp/btx-native-receipt.key \
  --out /tmp/btx-native-fresh-receipt.json
```

The work directory must not already exist. A rerun uses a new directory. The
runner uses the node's private RPC cookie. Passwords are not put on command
lines or in receipts. `native_node.py` does not pass `-modelnet=1`, an absent
helper, `-modelstorage=0`, or matmul-off flags. A failure to start the real
helper fails the run. Platform plans require the actual native OS, so a Linux
process cannot qualify `macos-portable` or `windows-portable`.

These starter plans verify their stated assertions only. They are not complete
coverage of `NIF-QA-007`; the independently approved catalogue policy must map
every detailed row to the stronger experiment it requires.

## Run two independent LAN hosts

Generate a `lan-two-physical-hosts` member plan on each machine. On a publisher,
add `--seed-file /absolute/path/to/known-model.gguf`. On a receiver that must
demonstrate the first-model path, add `--require-acquisition`. The model's local
digest is pinned before execution. No model is invented or downloaded by this
plan generator.

Transfer those plans to the coordinator. Its `host-config.json` is a mapping
from names to transport configuration, with the same `root` and
`machine_id_sha256` already recorded by each member. For POSIX SSH hosts,
include `transport: "ssh"`, `target`, an absolute `known_hosts` path,
`known_hosts_sha256`, and optionally a numeric `port` and Python executable.
Enroll the SSH host key independently. The runner enforces strict host checking
and never enables `StrictHostKeyChecking=no`. A local coordinator host can use
`transport: "local"`.

```sh
python3 contrib/swarm/native_acceptance/prepare_plan.py merge \
  --member node-a=/tmp/node-a-plan.json \
  --member node-b=/tmp/node-b-plan.json \
  --host-config /tmp/host-config.json \
  --out /tmp/two-host-plan.json
python3 contrib/swarm/native_acceptance/runner.py run \
  --plan /tmp/two-host-plan.json \
  --key-file /tmp/btx-native-receipt.key \
  --out /tmp/two-host-receipt.json
```

Both native daemons start concurrently. Neither driver supplies peer addresses
or calls `addnode`/`addmodelnode`. It requires distinct PQ1-admitted transport
pins in `native_participation.peer_observations` and a second successful
observation. An empty peer list fails. `peers_connected` is an instantaneous
socket count and is not used as proof of persistent membership.

Machine IDs are observed OS/firmware identifiers, not hardware-root
attestation. The gate separately requires the operator's independently enrolled
mapping of machine IDs to physical machines and GPU UUIDs. Two processes, two
containers with cloned IDs, or two labels do not establish two physical hosts.
The transport authenticates the enrolled machine; it does not make its
administrator adversarially trustworthy.

Removal of internet access, cross-organization validation, and coordinated
faults require their actual topology/control drivers. Extend
an immutable finite plan with the measured before/fault/after/recovery phases
and pinned drivers. Do not rename a LAN plan to WAN. A failed external TCP
probe by itself does not establish that all internet routes were removed.

## Run three independently enrolled WAN hosts

`wan-three-native-peers` now has a real native-node driver. Each host needs an
owner-provisioned `BTX-WAN-ENROLLMENT/1` file. It names `network: "regtest"`,
two or more peers with canonical numeric globally routable `endpoint` values
and independent 96-hex-character `transport_pin` values, and a `local` object
with `model_port`, `certificate` and `private_key`. Each local TLS entry has an
absolute `path` and SHA-256. Private key files must be owner-only. Use actual
independently provisioned ML-DSA TLS identities; never use fixture keys.

The driver copies that local identity into only its fresh private datadir and
preinstalls the enrolled peer pins before its first connection. It never
creates a public DNS service or disables pin checking. The model listen port
must already be routed to that owner-approved host. Only the model listener
is exposed; monetary P2P remains disabled in this isolated regtest scenario.

```sh
python3 contrib/swarm/native_acceptance/prepare_plan.py local \
  --root /absolute/path/to/btx --bin-dir /absolute/path/to/build/bin \
  --work-dir /tmp/btx-wan-node-a --profile wan-three-native-peers \
  --wan-enrollment /private/node-a-enrollment.json \
  --wan-enrollment-sha256 INDEPENDENTLY_APPROVED_ENROLLMENT_SHA256 \
  --seed-file /absolute/path/to/known-model.gguf --out /tmp/wan-node-a-plan.json
```

Create the other two member plans without `--seed-file`; they automatically
require a verified free acquisition. Merge all three with the same coordinator
workflow as LAN. Each run requires two fresh matching PQ1 identity observations
in the same chain namespace. The merger and release gate refuse fewer than
three independently enrolled physical hosts. No WAN profile was executed in
the implementation environment.

## Execute an explicitly authorized native model

Supply `--model-run /private/model-run.json --model-run-sha256 DIGEST` to
`native_node.py`, or use those arguments with the `local-cpu-useful-model`
plan profile. The manifest has schema `BTX-NATIVE-MODEL-RUN/1`, an absolute
`model_root`, and exact `files` entries containing `path`, `sha256`, and
`bytes`. The full tree must match that inventory; extra files and links fail.

The `adapter` object names `kind: "python"` or `"executable"`, absolute
`path`, and `sha256`. A Python adapter also names an independently pinned
`python: {"path": ..., "sha256": ...}` interpreter; the driver creates an
owned executable wrapper with that exact interpreter. For SafeTensors, the
existing `contrib/modelnet/generate_local.py` uses local Transformers files
with `trust_remote_code:false`. Its optional dependencies must already exist
in the pinned offline runtime. Python exec adapters currently require POSIX.

The `generate` object supplies `prompt`, `max_new_tokens`,
`expected_architecture`, `expected_backend`, `expected_device` (`cpu`/`cuda`),
and `expected_text_sha256` from a separately approved deterministic result.
For the existing Transformers adapter use backend `transformers` and the
actual allowlisted architecture in the model's config. A CUDA-residency run
also supplies a pinned `cuda_loader` and `require_cuda_resident:true`.

The driver executes `hostmodel` with publication disabled, materializes and
rehashes the exported artifact, loads actual tensors, requests local generation,
checks the observed output/device/backend, and always unloads its owned runtime.
The CPU profile cannot accept a CUDA result; CUDA evidence cannot silently
accept CPU fallback. A model must fit the fresh node's default storage budget.
An external adapter that does not report its actual device needs instrumentation
before it can satisfy this contract. A tiny decoder smoke result is not evidence
of general model usefulness or of a full vendor inference stack.

## Execute the distributed GPU workload

Use the already-pinned PyTorch environment on **two actual GPU hosts** and one
visible GPU per rank. Start both commands concurrently, with the same nonce,
candidate, rendezvous endpoint, node count and step count. Example for each
host, substituting its node rank and authorized LAN rendezvous address:

```sh
torchrun --nnodes=2 --nproc_per_node=1 --node_rank=0 \
  --master_addr=ENROLLED_LAN_COORDINATOR --master_port=29645 \
  contrib/swarm/native_acceptance/gpu_training.py \
  --output-dir /tmp/btx-gpu-checkpoints \
  --nonce SHARED_64_CHARACTER_RANDOM_HEX \
  --steps 6
```

Pin the Python/torchrun executable, workload script, `btxmesh` source, model
configuration, and runtime environment in the execution plan. Rank zero on
each machine prints one aggregate JSON report. Assert at least two distinct
machine IDs and GPU UUIDs, changed parameter hashes, identical final parameter
hashes across ranks, and each rank's matching full-state/replayed-state digest.
Use the same `runner.py` phase for all hosts so rendezvous is genuinely
concurrent. CPU mode requires `--allow-cpu`; it cannot satisfy a GPU gate.

This is an actual decoder/autograd/collective/checkpoint workload using the
existing `btxmesh.runtime.Decoder`. Its report explicitly says
`native_btx_engine_integration: NOT_EXERCISED`. It establishes the tested
PyTorch backend's behavior; it does **not** prove that `btxd` scheduled those
ranks, that a DeepInfer adapter is linked, or that NIXL/Mooncake/RDMA transferred
bytes. Those claims require their own pinned native adapter experiment.

### Consume trained weights in native C++

After exact replay succeeds, each host's local rank zero writes
`native-export-rank-<rank>-<nonce>/trained.safetensors` and `export.json`.
The export uses actual final model weights, not a fabricated fixture. It includes
their SHA-256/SHA-384, a training-bound artifact digest, and an F32 dense-layer
witness whose accumulation matches native `Load01::LinearF32` exactly.

On each independently provisioned source, the owner can use
`btx-native-qualify sign-checkpoint owner-request.json`. The request names
`checkpoint_path`, `artifact_id`, the consumer's fresh 64-hex `request_nonce`,
`expires_at_ms` (at most one hour), `max_checkpoint_bytes`, pinned
`source_public_key`, and owner-only `source_secret_file`. The native tool hashes
the actual checkpoint, signs its canonical ML-DSA receipt, and verifies that
signature against the pinned public key. Keep secret files out of the package.

The consumer's independently pinned `BTX-CHECKPOINT-SOURCES/1` JSON has
`sources` entries with local acquired checkpoint `path`, signed `receipt_path`,
`receipt_sha256`, and `expected_source_public_key`. At least two distinct keys
are required. Each receipt must bind the exact exported checkpoint/artifact and
the consumer nonce. A source's own claimed key is not an independent pin.

```sh
python3 contrib/swarm/native_acceptance/checkpoint_bridge.py \
  --export /private/training/export.json --export-sha256 APPROVED_EXPORT_SHA256 \
  --sources /private/acquired-sources.json --sources-sha256 APPROVED_SOURCES_SHA256 \
  --native-bin /absolute/path/to/build/bin/btx-native-qualify \
  --native-bin-sha256 APPROVED_NATIVE_BINARY_SHA256 \
  --nonce FRESH_64_CHARACTER_RANDOM_HEX --work-dir /tmp/native-consumption-run
```

This performs native CPU consumption of the same signed trained bytes and checks
the measured digest/extent/source count and exact output. Its explicit scope is
`TRAINED_WEIGHTS_AND_CPU_DENSE_LAYER_ONLY`. It does not turn the reference
decoder into a complete native Transformer or link DeepInfer/vLLM/Ascend kernels.
Two signing keys alone do not prove two physical hosts.

## Build a pinned offline image

Collect a real native build and its observed dependency graph first:

```sh
python3 contrib/swarm/native_acceptance/collect_runtime.py \
  --source /absolute/path/to/btx --bin-dir /absolute/path/to/build/bin \
  --platform linux-x86_64 --evidence-dir /tmp/btx-runtime-dependencies \
  --out /tmp/linux-x86_64-runtime-lock.json
```

Collection uses `ldd` on the owner's trusted Linux build outputs, `otool` on
macOS, or `dumpbin` on Windows. It rejects unresolved dependencies and conflicting
SONAMEs, packages actual regular bytes instead of symlinks, and records the OS
baseline plus inspector/command hashes. `--runtime-dir` resolves explicitly
provided non-system runtime paths. `--asset archive-prefix=/absolute/directory`
includes complete materialized model/tokenizer/runtime/license trees. There are
no downloads. A Python venv should be built with copied executables and its
complete dependency tree before packaging; a wheel name is not an installed
runtime. Third-party redistribution licenses remain part of the supplied assets.

Alternatively create a `BTX-OFFLINE-LOCK/1` JSON lock with `platform`, `source_commit`,
`source_tree_sha256`, and `files`. Each file has an absolute local `source`, a
portable archive `path`, its SHA-256, and a Boolean `executable`. All five native
binaries must be under `bin/` (with `.exe` for Windows). List each packaged
runtime dependency in `dependency_closure`; include engine binaries, required
libraries, model/tokenizer files and licenses for the advertised workload.

```sh
python3 contrib/swarm/native_acceptance/offline_image.py build \
  --lock /tmp/linux-x86_64-runtime-lock.json \
  --out /tmp/btx-linux-x86_64-runtime.tar.gz
python3 contrib/swarm/native_acceptance/offline_image.py verify \
  --archive /tmp/btx-linux-x86_64-runtime.tar.gz \
  --sha256 INDEPENDENTLY_RECORDED_ARCHIVE_SHA256 \
  --extract /tmp/btx-verified-offline-runtime
```

Generate a separate lock/image for each advertised platform from its real
native build. The tool never manufactures binary pins and never downloads a
runtime. Archive hashes are deterministic across repeated builds with identical
inputs. Verification proves the enumerated bytes, not that the declared
dependency closure is complete. Inspect dynamic dependencies against the
declared OS ABI baseline, then run the extracted runtime on the corresponding
isolated native host with networking actually unavailable. Until that run exists,
the packaging receipt remains `native_qualification: NOT_RUN`.

Run a verified extracted image with its separately recorded manifest digest:

```sh
python3 contrib/swarm/native_acceptance/offline_exec.py \
  --root /tmp/btx-verified-offline-runtime \
  --manifest-sha256 INDEPENDENTLY_RECORDED_MANIFEST_SHA256 \
  --program btxd -- -regtest -datadir=/tmp/separate-offline-node
```

This rechecks the entire installed tree and sets its packaged library path.
It does not itself remove internet routes or create OS/network confinement.

The implementation was exercised with an actual Linux build: 33 runtime files
(261,279,703 bytes) were collected, archived, verified and extracted. The
extracted daemon reported its version through `offline_exec.py`, and the
extracted node/helper/guard passed `native_node.py --mode fresh` with the
packaged library directory. This is measured application-image startup on one
Linux host with networking available. Native Windows/macOS images and actual
disconnected operation remain unqualified. Re-run collection and execution
after integration; these measurements do not attest later source or binaries.

## Qualify against the sealed catalogue

An independent reviewer constructs a `BTX-NATIVE-GATE/1` policy containing:

- The exact candidate source identity and the sealed catalogue SHA-256/count.
- A `row_plans` mapping for **every** acceptance row to independently reviewed
  plan digests; at least the reported 573 rows must be present.
- All 32 profile rules, their approved plan digests, host/GPU minima, and a
  `machine_enrollment` map from machine identity hashes to independently known
  `physical_host_id` and `gpu_uuids`.
- A finite receipt-age limit, defaulting to 24 hours.

Pass the policy's canonical SHA-256 separately as `--policy-sha256`. The gate
refuses catalogue shrinkage, missing rows/profiles, unmatched candidates,
unapproved plans, tampered receipts, replayed challenges, unenrolled machines,
insufficient hardware, stale evidence and failed observed-output assertions.
Policies cannot lower the hard two-host LAN, three-host WAN, or two-GPU
multirank minima. A successful gate returns `release_qualified: true` only
after the required evidence is actually present. It does not issue a tag.

```sh
python3 contrib/swarm/native_acceptance/runner.py gate \
  --policy /tmp/native-gate-policy.json \
  --policy-sha256 INDEPENDENTLY_APPROVED_POLICY_DIGEST \
  --catalogue /absolute/path/to/original-sealed-catalogue.csv \
  --receipt /tmp/two-host-receipt.json \
  --receipt /tmp/another-profile-receipt.json \
  --key-file /tmp/btx-native-receipt.key \
  --out /tmp/native-gate-result.json
```

HMAC receipts protect the local recording authority and its authenticated SSH
observations. They are not consensus certificates or post-quantum identity
substitutes. A reviewer must inspect test semantics, especially transaction
ownership, real negative controls, outcome tests, fault recovery, confidentiality
and vendor-engine measurements. An assertion that trusts a test program's
`passed: true` field is not a sufficient acceptance design.

## Verification of these tools

```sh
python3 -m unittest discover -s contrib/swarm/native_acceptance/tests -v
python3 -m compileall -q contrib/swarm/native_acceptance
```

These tests exercise receipt integrity, stale/cross-candidate evidence,
one-machine/two-label rejection, source mutations, subprocess limits, plan
combination, deterministic image round trips and malicious archive rejection.
They use explicit fixtures and do not qualify any real node, GPU, OS image,
payment, WAN deployment or sealed acceptance row.

The optional Ascend probe uses the vendor's documented `npu-smi info -l` and
`npu-smi info -t board -i ID` commands. The gate requires independently enrolled
NPU serial hashes for the Ascend profile and does not count an NVIDIA GPU as an
Ascend board. A container that cannot expose a board serial cannot satisfy that
hardware identity gate. Vendor command reference:
[Ascend npu-smi help](https://www.hiascend.com/document/detail/zh/Atlas%20200I%20A2/250RC1/re/npu/npusmi_003.html).
