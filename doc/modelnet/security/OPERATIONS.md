# Operations and qualification

## First run

Ordinary `btxd` owns the security-enabled guard. A private security directory and
service state do not by themselves grant anything. With no owner-installed root
pins, valid policy and local configuration, privileged work is unavailable.
The monetary node continues if the guard is unavailable.

Enroll roots out of band. Generate separate research/worker/peer keys with
`btx-security keygen`; never reuse wallet keys. Prepare the root-pin document,
owner-signed policy, explicitly installed static test/worker packages, local
workspace handles, and per-session grants. Every example key in a test is
freshly generated and deleted; there are no shipped operational credentials.

`btx-security init` creates root pins only if absent. `install-policy` requires
pinned-root signatures, an increasing epoch and an existing owner signature
when updating. It does not implement a full expired-root recovery ceremony or
TUF-compatible root-key rotation. Back up roots under separate custody and
review a future recovery design rather than bypassing a failed epoch check.

The local configuration contains `schema`, `workspaces`, `packages`, and `host`,
with optional `identity`, `peer_identity`, `execution_policy`,
`evaluation_plans`, and `runtimes`. The exact schema and test fixtures are the
source of truth. `allow_evaluation` is owner consent, not an idle detector.
No engine is downloaded automatically.

Use the host-side `contrib/model-security/guard_client.py` only from an approved
agent harness outside the model sandbox. It pins the CLI binary, owner grant,
composition/runtime/tool/session context and four typed tools. Do not leave an
alternative raw-shell handler enabled and call the combined system protected.

## Incident handling

Pause through the local owner RPC. Publish a properly threshold-signed
revocation for the affected key, composition, capsule, challenge or evidence ID.
Preserve the metadata journal and actual reviewed evidence. Future effects and
output release recheck current authority; queued output is not an entitlement.
Canary/release state freezes or returns to a retained still-eligible predecessor.

A partition cannot deliver immediate global revocation. Short leases and finite
policy/evidence validity bound future authority. An already delivered plaintext
secret cannot be cryptographically recalled. The new service has no plaintext
credential-custody API to rotate provider secrets automatically.

## Test levels must not be conflated

1. Component crypto/policy/database tests include signed synthetic evidence.
2. Native kernel sandbox probes exercise actual file/network/process denial.
3. Actual modified guard/supervisor IPC tests exercise owned children and pipes.
4. Full `btxd` functional test is supplied, but was NOT_RUN for this package.
5. Physical independent hosts/PQ1, Windows/macOS, actual LLM/GPU runtimes, private
   data, distributed training, offline images and complete release catalogue
   remain separately required.

The packet interface, host labels and signed receipts do not prove machines are
physically distinct. Qualifying a public network requires operator-controlled
inventory, independently administered signing authorities, audit of test inputs,
protected holdouts and independent reproduction. Never count two keys, two
ports, two local processes or two local ranks as two physical operators.

Do not install real credentials in adversarial fixtures. Use decoy files and a
local instrumented destination with no uncontrolled outbound network. Acceptance
must measure denied effects, not matching a known trigger string.

## Outstanding integration work

Implement a full native protected LLM runtime; bind its immutable loaded model,
tokenizer/template/system prompt and tool schema to the broker context; force
all its external tools through the reference monitor; wire the current BTX
model-engine generation to staged activation and rollback. Map security
composition IDs to existing native verified artifacts and retrieval without
assuming a registry name is identity. Qualify actual native PQ1 multi-host
evidence flows. Integrate resource governors, private data policy, actual
training/evaluation engines, security UI and explicitly authorized settlement.

These are real remaining implementation tasks, not merely missing test runs.
`REQUIREMENTS.json` at the package root is the comprehensive delivery ledger.
