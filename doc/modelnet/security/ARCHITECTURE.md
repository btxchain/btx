# Security-v2 architecture and threat model

## Authority separation

`btxd` owns the ordinary ModelNet helper and guard lifecycle. The new library is
linked into the existing guard, not a new public daemon. The helper accepts only
bounded signed evidence at `/btx-model/2/security/evidence`, on an already strict
PQ1 session. Its authenticated transport pin must match an owner-enrolled peer.
The owner RPC is `modelsecurity`; it is deliberately **not** exposed on PQ1.

Wallet keys, transaction signing, consensus, issuance, proof of work, block
validity, and automatic spending are untouched. No model artifact, evaluation,
channel quorum or peer presence creates financial authority.

Trust roots are operator-selected out of band. Policy binds realm, epoch,
expiry, admitted keys/roles and trust-domain/host labels. A signed statement
proves which key signed exact bytes; it does not prove truth, independence,
physical host identity, model benevolence, or complete test adequacy.

## Actual execution boundaries

The implemented `linux-static-fd-v1` worker is a static ELF executable whose
exact hash is installed in local owner configuration. The parent copies the
verified executable into a sealed memfd. The child receives clean environment,
stdin/stdout/stderr only, CPU/address-space/file-descriptor/output/wall limits,
`no_new_privs`, parent-death handling and a syscall allowlist. File opens,
networking, process creation, ptrace, mounts and later executable acquisition
are denied. Only initial execution of the pinned descriptor is permitted.
This backend was exercised against real system calls in the test environment.

It is not a general Python, llama.cpp, vLLM, GPU or dynamically linked runtime.
Those require a separately implemented, pinned, audited native runtime profile.
Unsupported systems must refuse; they may not silently execute on the host.

The file broker performs exact approved read/hash/write-new effects using
resource descriptors and exclusive atomic file publication. Protected credential
paths, symlinks, traversal, hardlink aliases and unapproved paths are denied.
An explicitly approved source file can itself contain sensitive content;
permission is an owner decision, not a content classifier's claim.

## Capability enforcement

Permits bind owner grant, immutable composition, runtime, tool schema, session,
exact arguments, policy epoch, expiry and guard boot. Durable SQLite consumption
occurs before dispatch. Budget reservation is conservative. A crash after an
external effect but before a result can produce unknown completion: there is
no false exactly-once promise. Replay does not repeat the effect.

Authorization is rechecked before effect, during worker execution and before
result release. Pausing and restarting invalidate outstanding permits; signed
resume cannot resurrect them. Revocation is forward-looking: it cannot recall
plaintext already delivered or undo an external action already completed.

A host-side adapter routes four typed tools into this boundary. It does not
magically intercept independent shells or other tool handlers. The old BTX
`generatemodel` path is not yet forced through security-v2. This is exposed in
status as `legacy_generatemodel_mediated: false`.

## Research evidence and evolution

A composition hashes weights, tokenizer, configuration, chat template and any
adapters, plus runtime/sandbox/tool/system-prompt identities. Parent and
contributor references remain immutable. The importer only handles these as
untrusted data; it does not execute imported code.

Capsule admission requires six named gates, matching challenge, suite and
sample commitments, actual referenced signed execution receipts, and distinct
owner-enrolled evaluator domains/hosts. The author and declared contributor
trust domains are excluded. All retained negative results are considered, not
just the favorable report set selected by a publisher. A key quorum is not a
Sybil-proof population vote.

Native evaluation invokes a locally installed, hash-pinned static test runtime
on a verified resident snapshot plus private test input. It measures actual
exit/output and emits a signed receipt and report. The owner must review what
the test actually measures. The sample worker proves isolation controls, not
LLM honesty. Synthetic admission fixtures are explicitly labeled as such.

Follow mandates constrain allowed runtimes/tool schemas and maximum profile.
Updates stage only verified resident bytes and eligible evidence. Activation
requires distinct actual local canary receipts spanning the policy duration.
Negative findings, expired authority and revocations freeze or roll back to a
previous still-eligible local binding. The existing model engine is not yet
connected to that binding; a production native generation adapter is a remaining
implementation item, not a completed deployment.

## Persistence, privacy and limits

SQLite is private to the owner, uses defensive mode, parameterized statements,
WAL/FULL sync, transactionally consumed permits and monotonically versioned
policy. The journal stores hashes/metadata, never raw tool output or secrets.
Private output stays in bounded ephemeral memory and is checked again at take.
The current store is not an encrypted database and is not resistant to a
same-user/root attacker rolling back the complete OS/data store. HSM storage,
TPM monotonic counters and stronger service-account separation are not included.

Peer inventories export explicitly published evidence only. Model acquisition
or observer subscription is not authorization to compute, seed private data or
publish results. Root policy and owner grants cannot be received as authority
from a peer. Peer keys are separately configurable from evaluation keys.

No theorem, signature, clean benchmark or security capsule proves absence of an
unknown dormant backdoor. The enforceable promise is scoped containment where
the actual runtime and tool path pass through these boundaries.
