# BTX 0.34.8: Agent-readable .btx packages

## A complete model handoff, from an ordinary link to verified local possession

**Document ID:** BTX-AHP-001 · **Revision:** 1.0 · **Date:** 16 September 2026  
**Assignment:** execute after the current private 0.34.8 convergence round has stopped and handed off its evidence.  
**Status:** normative implementation specification; not a statement of shipped capability. Markdown is canonical. The Word and PDF are reading editions.

> A model publisher should be able to hand an agent one ordinary HTTPS `.btx` link. The agent can inspect the package, read its embedded `AGENTS.md`, establish the required tooling through independently trusted channels, acquire an exact model from BTX, and hand verified local files to an authorized local runtime. Neither a preinstalled BTX-specific bootstrapper nor a centralized model-hub account is a prerequisite for understanding the package.

## Reading map

Sections 1–5 establish product scope, compatibility, authority and wire format. Sections 6–13 specify documents, agent handoff, client installation, acquisition, runtime, economics and privacy. Sections 14–19 cover publishing, HTTP/OS behavior, APIs, reference testing and code integration. Sections 20–23 define parallel implementation, end-to-end journeys and release gates. The complete individual test catalogue is included as Appendix A and also as `tests/ACCEPTANCE_TESTS.md`; the execution ledger is `tests/acceptance-matrix.csv`.

The companion strategy paper is analysis, not implementation authority. In a conflict, this specification and its schemas govern the proposed profile; existing monetary rules and user authorization always remain outside package authority.

# 1. Product contract and boundaries

## 1.1 The one-link journey

A user gives an agent a URL such as `https://models.example/model_latest.btx`. The agent fetches the descriptor with its ordinary file/web tools, inspects the framing and JSON, reads the embedded agent guidance, and makes a local plan. If compatible BTX tools are already installed, it uses them. Otherwise it identifies an approved client distribution and obtains independently verified software within the user's installation policy. After package and model verification, it acquires a selected immutable variant and returns an absolute local path plus a receipt. A separately authorized action can start an existing local runtime.

The user should not need to know whether model bytes were originally published on Hugging Face, imported from a torrent, placed in R2, copied from a local disk or created through a BTX bounty. Those remain acquisition and provenance details. The package carries the model handoff; BTX supplies the identity and acquisition mechanisms already being implemented. [B03, B04]

## 1.2 What this round adds

Implement embedded `AGENTS.md` and human documentation, typed acquisition guidance, local compatibility profiles, software requirements, a secure client-install planning contract, a local runtime handoff contract, signed channel updates and human/agent interfaces. Extend the existing `.btx` implementation rather than creating a new downloader, torrent client, storage backend, watch system, wallet policy or discovery network.

This round does not add remote inference, an inference marketplace, arbitrary package scripts, automatic mining, a general package manager, a new coin, a consensus activation, or an implicit monetary mandate. A local runtime may be invoked by a user-controlled application; the model helper is not turned into an inference server.

## 1.3 No-account experience, correctly scoped

For a public artifact available through native BTX providers, the acceptance journey must succeed without a Hugging Face login/token, a BTX-funded wallet, or S3 credentials on the recipient. Native peer authentication may create a local model-service key; this is not a centralized account. Do not start full blockchain synchronization simply to inspect a descriptor or retrieve free public bytes. Chain-backed economics is a separate optional workflow. If the present helper cannot operate that way, record and fix the model-client packaging dependency before claiming the no-account journey.

Private or gated source access remains an external-source matter. Do not infer redistribution rights from the absence of a gate, or infer a redistribution prohibition solely from the existence of one. Apply the actual artifact license and authorized mirroring policy. This supplement must not implement credential bypass or invent a publicly retrievable model when the only source requires authorization. [R10, R11]

## 1.4 Capability, not marketing, is the release claim

A generated guide, valid JSON schema and green parser tests do not establish a working first-run installer or runtime. The release gate is a fresh-machine scenario: ordinary HTTPS fetch, inspection without BTX, separately trusted client installation, native acquisition, exact verification, local path export and an authorized local smoke test. Record each stage independently. Failures or unavailable environments remain explicit in the final handoff.

# 2. Baseline reconciliation before any edit

## 2.1 Evidence boundary

The public branch inspected for this supplement is `42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b`. Its `AGENTS.md` separates monetary and model processes, sets default automatic spend to zero and treats external model descriptions as untrusted. Its `btx-open` implementation is a URI inspection dispatcher, not an installer or runtime. [B01, B02]

The supplied 0.34.8 expanded package already specifies `BTXPKG1`, `BTX-PJSON1`, signed core fields, observations, variants and a separate `.btxbundle`. Its v1 JSON schema uses `additionalProperties: false` for the core and has no embedded-document or agent-handoff field. That means silently adding `AGENTS.md` fields to an unchanged v1 payload would break strict readers. This supplement therefore defines **Package Core v2**, inside the unchanged `BTXPKG1` outer frame. [B03]

Private code may now implement more than either baseline. Cursor must inspect the actual private tree after the current round ends. The local code audit, not the conversation's green checklists, decides which changes are new.

## 2.2 Inventory and sequencing

Record HEAD, branch, working-tree diff, untracked-file hashes, compiler/build configuration, version macros and previous acceptance ledgers. A HEAD hash alone is not an evidence identifier for a dirty tree. Produce a candidate fingerprint containing HEAD, a digest of the tracked diff, hashes of relevant untracked files, build configuration and tested binary hashes.

Find the actual package codec/schema, package RPC registration, thin descriptor writer, bundle reader, GUI opener, `btx-model` helper, model path export, channel/watches, client release verification and local policy stores. Map every proposed symbol in section 19 to its existing equivalent or an explicitly new module. Never edit production processes, wallet data, services or current in-use binaries. Do not commit, push, merge, tag, publish or change the release flag without separate instruction.

## 2.3 Compatibility decision record

Write `audit/agent-package-baseline.md` and `audit/agent-package-compatibility.md`. Preserve v1 read support and golden bytes. New writes use Core v2 only when agent-handoff features are requested. A plain legacy descriptor may still be written as v1. Old readers must reject unsupported Core v2 clearly, not ignore critical instructions and proceed. The creator can deliberately export a legacy acquisition-only descriptor as a new separately signed package; label omitted documents, runtime guidance and constraints. Never silently downgrade a package that the user supplied for execution planning.

If the private tree already allocated a different Core v2, stop format allocation, document the collision, and choose the next unused core version with operator approval. Do not emit two incompatible formats under the same version. Keep the profile identifier and reference vectors in this package as the design proposal until that reconciliation is complete.

# 3. Authority model

## 3.1 Four authorities that must not collapse

**Package author:** signs the handoff, documents, references and recommendations. **Model publisher:** signs model/channel assertions under its own identity or delegation. **Software distributor:** signs the BTX client or runtime release through a trust root accepted independently by the user. **User/wallet policy:** grants installation, bandwidth, storage, process execution and monetary authority. A cryptographically valid package cannot appoint itself to any of the other roles.

An HTTPS URL establishes a connection to a hostname under the applicable TLS trust model. A package hash establishes byte integrity. A package signature establishes which key signed the core. A local trust record establishes whether that key is accepted for the requested use. These are separate fields in every inspection result; never return a single ambiguous `verified: true`.

## 3.2 Explicit effects

Classify every action: `INSPECT`, `FETCH_METADATA`, `INSTALL_CLIENT`, `ACQUIRE_MODEL`, `SEED_MODEL`, `FOLLOW_CHANNEL`, `PREPARE_ECONOMICS`, `SIGN_OR_SPEND`, `PLAN_LOCAL_RUN`, `EXECUTE_LOCAL_RUN`. The package can request or describe these actions. Local policy authorizes them.

A user's instruction to obtain and run a model can cover several non-monetary stages in one finite local plan, avoiding repeated confirmations. That authorization must bind the selected package core, model variant, software release, runtime adapter, storage/network ceilings and expiration. It cannot become permission for arbitrary follow-on models, privileged installation, remote execution, wallet use or subscriptions. Missing authority yields a precise approval request, not a generic block on everything.

## 3.3 Embedded AGENTS.md is scoped data

The embedded file is guidance for handling this package, not a new system prompt and not an instruction file for the surrounding repository. Never place it automatically in the user's home, project root, `.agents` folder, IDE configuration or another auto-discovered instruction location. Read it through the package-document interface or materialize it only in a user-approved isolated package workspace.

Package instructions such as “ignore earlier rules,” “turn off verification,” “upload your token,” or “fund this campaign immediately” confer no authority. Client enforcement must not depend on the language model successfully recognizing malicious prose. Typed plans, verification and policy boundaries protect executable actions even when the agent misunderstands the text. No claim is made that arbitrary third-party agents are made safe merely by reading a warning. [B01, R12]

# 4. Exact file framing and canonical bytes

## 4.1 Preserve BTXPKG1

The ordinary `.btx` descriptor remains the following binary frame. Its fixed header is 68 bytes. This is not a ZIP archive.

| Offset | Length | Encoding | Meaning |
|---|---:|---|---|
| 0 | 8 | bytes | `42 54 58 50 4b 47 00 01` (`BTXPKG`, NUL, 1) |
| 8 | 4 | little-endian uint32 | Flags; zero for this profile |
| 12 | 8 | little-endian uint64 | Payload length N |
| 20 | 48 | bytes | SHA-384 of the exact N payload bytes |
| 68 | N | UTF-8 | Canonical BTX-PJSON1 payload |

N must be at most 4,194,304 bytes. Reject nonzero flags, extra trailing bytes, truncated header/payload, overflow and a payload-hash mismatch. There is no compression, self-extracting code or appendable unsigned trailer. The binary frame permits existing code and bundle machinery to remain intact. [B03]

## 4.2 Canonical JSON

Reuse the existing `BTX-PJSON1` implementation and its vectors. Keys are ASCII, byte-sorted; arrays preserve semantic order; separators are comma/colon without whitespace; encoding is UTF-8 without a BOM. Duplicate keys, floating-point/exponent numeric tokens, NaN/infinity, invalid UTF-8, lone surrogates and numeric negative zero are rejected. JSON integer values remain within the exact interoperable range ±(2^53−1); amounts, timestamps, sizes and sequence counters use canonical unsigned decimal strings when their schema requires them. Decimal strings have no sign, leading zero, whitespace or exponent.

Strings are not Unicode-normalized before hashing. Quotes, backslashes and control escapes follow the existing canonical writer; newline, tab and carriage return can appear as JSON escapes in document content. Identifiers, document paths and security-sensitive labels reject controls and directional formatting characters. Re-encoding the parsed payload must reproduce its exact bytes. Structural maximum depth is 32 and total JSON nodes are capped at 65,536 before expensive schema/signature work.

Do not silently substitute RFC 8785 JCS, ordinary pretty-printed JSON or a platform-specific serializer. A parser that accepts more JSON than the writer produces is not sufficient for signed canonical content.

## 4.3 Core v2 payload

The payload retains the top-level objects `core`, `observations` and `signatures`. Core v2 adds `documents` and `agent_handoff`, and uses `version: 2`. It retains `network`, `package_type`, `label`, `resources`, optional `variants`, `economy_refs`, `source_hints` and `critical_extensions`. The critical feature set must include `AGENT_HANDOFF_V1`. The schema is `schemas/BTXAgentPackage.schema.json`.

Package kinds remain `MODEL`, `COLLECTION`, `RELEASE`, `BOUNTY` and `VARIANT_INDEX`. A bounty with no model yet can contain zero model resources and a typed bounty economy reference. Do not create dummy model IDs to satisfy an obsolete minimum-count constraint. Network is explicit; test fixtures use REGTEST and must not be converted to MAINNET merely by changing the envelope label.

Unknown core fields are rejected in this profile. Extensions require a versioned namespace and explicit schema evolution. Unknown critical extensions fail closed for actions. Existing signed canonical BTX records are embedded or referenced as original bytes and digests through the current record mechanism; never parse and re-sign a lossy interpretation.

## 4.4 Package identity and signatures

For Core v2 define:

```text
C = BTX-PJSON1(core)
package_core_id = SHA384(
    UTF8("BTX/PackageCore/v2") || 0x00 || LE64(len(C)) || C
)
```

A `PACKAGE_CORE` signature uses the existing pure ML-DSA-44 application signing API over the 48-byte `package_core_id`, with the native empty FIPS context, not a wallet transaction sighash. Preserve the current identity derivation and validate declared signer ID against the full public key. ML-DSA-44 public-key and signature lengths are exactly 1,312 and 2,420 bytes; validate lengths before verification. Hex representations are lowercase and even length. [R15]

All documents, client requirements, runtime profiles, source hints and economy references in `core` are signed together. Any edit changes `package_core_id`. `observations` is outside that signature and remains separately attributable data. The whole-file SHA-384 detects framing corruption; it does not authenticate observations or turn an unsigned fixture into trusted content.

Readers support unsigned packages for local preview and test fixtures. Automatic installation or runtime planning requires a locally accepted package author or explicit one-time user acceptance of the exact core. A valid self-signature by a new unknown key does not mean “trusted publisher.”

# 5. Resource and variant semantics

## 5.1 Immutable references

A resource descriptor carries `kind`, exact 96-character lowercase digest, optional canonical URI, manifest commitment, size, format and display label. Use the existing `ResourceKind` encoder/decoder for `btx://`; do not invent `btx-model://` or place a wallet address where a resource belongs. If URI and digest both appear they must match exactly. Where model and artifact IDs differ, retain both meanings rather than treating them as interchangeable filenames.

A package author can reference a model without being its creator. Provenance, original publisher claims, packager identity and compatibility attestations are displayed independently. An imported Hugging Face repository or torrent does not acquire the importer's authorship simply because its bytes have been re-addressed. [B03]

## 5.2 Variant selection

Each variant has a unique local `variant_id`, one exact model resource, format, quantization when known, required companion resources and zero or more compatible local runtime profile IDs. Hardware requirements are predicates on local observations: architecture, operating system, runtime backend capability and memory ranges. They are not routing commands and are not sent to peers or a central selection service.

Use a deterministic selection order: explicit user choice; authorized local preference; supported format/runtime intersection; memory feasibility; user-selected trade-off; stable variant-ID tie-break. Do not hardcode CUDA first, or penalize CUDA solely because the strategy paper addresses non-NVIDIA participants. Every supported hardware family is eligible under the same predicates.

Memory estimates include runtime overhead and KV-cache assumptions where known. A weights-file size is not a proof that the complete run fits. Unknown estimates are reported as unknown, and an OOM-safe local test may be proposed. No compatible profile returns `NO_COMPATIBLE_VARIANT`; it does not authorize fetching arbitrary code, converting a model silently or launching a cloud endpoint.

## 5.3 Dependencies and completeness

Limit resources to 256, variants to 64, dependency depth to 8 and distinct dependency nodes to 256. Reject cycles, missing references and duplicate IDs with conflicting commitments. Resolve optional dependencies only when the selected local plan includes them. A tokenizer-only acquisition is `SELECTION_READY`, not `MODEL_READY`, unless the application explicitly requested only that asset. Existing canonical manifests decide byte completeness; handoff metadata cannot redefine mandatory model files.

Do not mark every file format described in the strategy paper as supported by current model admission. OpenVINO IR, a Cerebras checkpoint or a vendor-specific artifact needs its own existing or separately implemented qualified format path. Otherwise it can be described as an external compatibility claim but cannot be silently promoted to runnable BTX content.

# 6. Embedded documents: AGENTS.md, README.md and profiles

## 6.1 Storage without an unsafe archive

Core v2 stores documents as a bounded array of objects with `path`, `media_type`, `encoding`, `text`, `size_bytes` and `sha384`. This represents a small virtual directory. `text` is the actual UTF-8 document, not base64. Compute `size_bytes` and SHA-384 from its decoded UTF-8 bytes before canonical JSON escaping. Documents are ordered by ASCII path.

Every agent-handoff package contains `AGENTS.md` and `README.md`. Additional paths may be `runtime/<name>.md`, `acquisition/<name>.md`, `licenses/<name>.txt` or `notes/<name>.md`. Paths are portable ASCII, case-sensitive but also unique under ASCII case-folding; reject absolute paths, dot/dot-dot segments, empty segments, backslashes, colon, NUL, reserved device names and percent-encoded path tricks. The client never follows document symlinks because this format has none.

At most 32 documents; 64 KiB per document; 24 KiB maximum for AGENTS.md; 256 KiB aggregate document bytes. Target generated AGENTS.md below 8 KiB. The limits include translated documents. Oversize prose is an authoring error, not a reason to truncate signed text.

## 6.2 Generated instructions

The default writer generates the operational portions of AGENTS.md from the same typed `agent_handoff` structure used by the planner. Required headings are: Package purpose; Trust and scope; Model and variant; Client requirements; Acquisition; Verification and output; Local runtime handoff; Economics; Privacy; Failure handling. Include finite actions and concrete file/field references. Author notes are allowed after the generated section and remain advisory.

Changes to structured operational fields require regenerating the generated portion before signing. A linter detects contradictory resource IDs, `auto_pay`, remote inference endpoints, unverifiable installer commands, package-supplied trust roots, and instructions to alter agent policy. The linter is a guardrail, not proof that prose is harmless. The typed plan and local policy remain decisive.

The README describes the same model and choices for humans. The two documents must not silently disagree about whether the package is public, funded, a bounty, compatible or automatically executable. Monetary amounts in explanatory prose are examples or dated observations, never signing input.

## 6.3 Inspection without BTX

The agent does not need a dedicated bootstrapper to read this package. Any bounded file reader with SHA-384 and JSON can validate the 68-byte frame and inspect its payload. Provide an independent, standard-library Python inspector in this package and document the byte layout. It prints the document to stdout or a caller-selected safe file; it does not install software, make network calls, verify ML-DSA, execute content or write project instruction files.

A website may offer an optional readable view or adjacent `.btx.json`/AGENTS.md preview generated from the exact descriptor. Such a view is convenience only, clearly tied to a core ID and whole-file digest. A mismatch is an error; do not prefer whichever prose is easier to read. The actual downloaded descriptor and verified signatures control later actions.

## 6.4 Safe rendering and extraction

CLI output escapes terminal control sequences. GUI preview does not render active HTML, external images, scripts or link previews. Copyable Markdown stays inert. Optional extraction creates a new dedicated directory exclusively, uses no-follow/open-at-safe equivalents, rejects overwrite and validates every path again. Default inspection does not change the workspace. Never install model-package AGENTS.md as the coding agent's own project instructions.

# 7. Typed AgentHandoff v1

`core.agent_handoff` contains `version: 1`, `entry_document: "AGENTS.md"`, `client_requirements`, `acquisition`, `runtime_profiles` and optional `channel_ref`. It is a declarative contract, not a general workflow language. There are no arbitrary expressions, loops, shell commands, scripts, environment interpolation or dynamically downloaded tools.

`client_requirements` declares a distribution ID, optional minimum client version, required capabilities and documentation hints. Capabilities—not optimistic version comparisons—decide feature support. Include `BTXPKG_CORE_V2` and `AGENT_HANDOFF_V1`; capability names used for transport and storage must be mapped to the real private tree before serialization.

`acquisition` declares default variant or selection intent, acceptable retrieval modes, required ready state and a preference to offer seeding. The profile default is `FREE_ONLY`, `NATIVE_ONLY`, verified local output and no automatic seeding change. The package can recommend seeding, but the recipient's policy determines whether it happens. A paid release is inspected and may prepare a funding plan; it never silently changes free retrieval into a purchase.

`runtime_profiles` defines a bounded set of typed hints for locally installed or independently obtainable runtimes. At most 16 profiles. Parameters must be specific to a locally trusted adapter schema, and that schema must reject unknown or unsafe flags. A profile may describe `llama.cpp`, `ollama`, `vllm`, `mlx` or another independently installed adapter, but a label alone does not establish support.

`channel_ref` references a signed mutable channel statement; the statement is not self-trusted and cannot retroactively change this package's static model commitments. Section 10 specifies the update contract.

# 8. Client acquisition without a circular trust dependency

## 8.1 No mandatory bootstrap application

A capable agent can use ordinary tools to read the descriptor, then follow its declarative client requirements. Do not require an already installed `btx-bootstrap` command to discover those requirements. Existing BTX clients provide a polished fast path, but understanding the file is independent of them.

The package can identify an official distribution, mirror candidates, required capabilities and platform targets. It cannot give itself permission to execute an installer or make its own public key the accepted client-distribution root. A binary URL plus a hash carried only in the same untrusted descriptor is not independent authentication.

## 8.2 Software trust sources

Installation is allowed through an operating-system/package manager already trusted by the user, an organization-pinned release catalogue, or a separately configured BTX distribution trust root. Prefer signed update metadata with explicit release/version/target/digest/size and rollback/freeze controls. TUF supplies a useful role-separation precedent; do not claim BTX already implements it simply because this spec cites it. [R13, R14]

If a first-time machine lacks every such trust source, the agent must identify the missing trust decision. It may propose installing from an independently obtained official release channel; it cannot resolve the problem by trusting an `AGENTS.md` instruction that says “trust this key.” One explicit trust/installation approval can establish the root for later unattended use under policy.

## 8.3 InstallPlan

Bind a local InstallPlan to package core ID, user-selected distribution ID, actual release version, platform, verified artifact digest/size, independently trusted signer/metadata, target installation directory, maximum download bytes, permitted hosts, expiry and requested privileges. Default installation is per-user and non-privileged. Never stop or replace an existing production btxd service, alter a wallet, or switch a running process's binaries.

Install with a temporary directory, bounded download, verified digest/signature, safe archive traversal, executable allowlist and atomic promotion. Roll back only the new installation path after failure. A newer package cannot lower the local minimum accepted software release or replace a trust root. Reuse current release-verification tooling rather than maintaining a second crypto stack.

## 8.4 Model-only client profile

Distribution targets must include a model-acquisition profile containing the required helper, URI/package tools and supported native crypto dependencies without requiring a funded wallet or GPU mining. The profile need not contain a separate consensus client if an existing build can run safely in standalone model mode. Verify CPU-only, Linux x86-64 and macOS arm64 paths independently. Unknown platform produces a useful manual option, not a fabricated compatible binary.

# 9. Acquisition plan and ready contract

## 9.1 Plan before side effects

The client builds an `AcquisitionPlan` from verified package core, selected immutable variant/dependencies, local trust decisions, existing cache state, resource limits and user policy. It includes exact resource IDs, expected manifests, selected files, destination, retention/seed policy, maximum bytes, source classes, deadline and a plan digest. No plan may inherit authority from text. Plans are immutable after approval; a changed model, client, runtime or material budget produces a new plan. Compute each local plan ID as SHA384(UTF8("BTX/" + plan_type + "/v1") || 0x00 || LE64(length) || canonical_plan_body), where plan_type is AcquisitionPlan, InstallPlan or RuntimePlan, and the body omits plan_id and the later authorization_ref. An authorization is bound to the resulting immutable ID; removing it from the digest does not remove its required runtime validation. Receipt IDs use the analogous AcquisitionReceipt/v1 domain and omit only receipt_id.

Use the existing live transfer scheduler, storage/quota controls, native provider routing, source policies and torrent/HF bridges. Do not create another “package download” path that bypasses VerifiedManifest, transfer credits, SSRF checks, peer authentication, or file-hash verification.

## 9.2 Source independence

Known providers/directories in a descriptor are hints, not trackers that define truth. Try diverse hints and existing routing; a missing original URL does not change a model ID. Native BTX retrieval is the default. External HF/torrent/cloud access requires the configured local source policy and explicit external-origin consent where applicable. Never forward the recipient's HF token, S3 credentials, install token or wallet material from one authority to another.

A private credential reference may exist in local acquisition state; it never appears in the portable package. Existing direct-origin offers are fetched dynamically, short lived and untrusted until normal BTX byte checks pass. Direct-origin retrieval must not be labeled native PQ1 merely because an offer was delivered over PQ1.

## 9.3 Finite resource policy

Enforce available disk reserve, declared maximum download, memory, time and job concurrency before and throughout transfer. A 400-GiB model should not be selected just because an author recommends it. Finite budget reservations are shared with existing jobs; duplicate package requests coalesce where appropriate. Rarity and newcomer lanes cannot bypass hard ceilings. Cancellation releases unused local reservations but records external operations whose outcome is uncertain.

## 9.4 Job state machine

```text
INSPECTED -> TRUST_REQUIRED or PLANNED
PLANNED -> APPROVAL_REQUIRED or ACQUIRING
ACQUIRING -> VERIFYING -> MATERIALIZING -> MODEL_READY
ACQUIRING -> WAITING_FOR_SOURCE / PAUSED / CANCELLED / FAILED
MODEL_READY -> RUN_PLAN_READY -> [separate local authorization] RUNNING
```

Client installation is a separate job linked to this plan, not hidden as a download state. Release/bounty economics may produce `WAITING_FOR_PUBLIC_RELEASE`; that is not a failed ordinary free download and never authorizes a paid fallback. Metadata-only/subset packages return `SELECTION_READY` with an exact completeness description.

## 9.5 Materialization and receipt

A runtime usually needs original files, not the internal piece store. Use the existing `exportmodelpath` or equivalent to materialize safe relative files without copying when safe, and without handing an origin URL to the runtime as a hidden download fallback. Pin/lease active outputs so GC or a channel update cannot replace files during loading. Verify stale cache claims after unclean shutdown and validate existing files instead of trusting names.

Return `package_core_id`, selected variant, exact model/artifact IDs, manifest commitments, verified local file map, materialization lease, verification time/build evidence, source-class summary, client version and local policy outcome. Separate `package_signature_valid`, `package_author_trusted`, `model_bytes_verified`, `runtime_compatible` and `runtime_started`. Local paths and hardware details are local-only receipt data and excluded from public export.

# 10. Mutable URLs and signed channels

`model_latest.btx` is a convenient web location, not an immutable identity. On first accepted use, persist the exact package core, publisher trust basis, selected model and optional signed channel sequence. Later changes must be evaluated as updates, never substituted midway through a transfer.

Reuse an existing signed BTX channel format where one has equivalent bindings. Otherwise define `AgentPackageChannel/v1` over network, publisher identity, family/channel name, canonical unsigned-decimal sequence, issue/expiry times, package core ID and optional previous statement ID. Sign a distinct application-domain digest, not a package self-reference. The channel statement lives separately from the package core so it can commit to that core without a circular hash.

Reject lower accepted sequences and same-sequence/different-digest equivocation. Identity rotation needs a valid existing delegation/rotation path or explicit new trust. A channel expiry affects automated freshness, not the identity of an already pinned immutable model. Offline exact acquisition can remain allowed under local policy; fresh-channel guarantees cannot.

Support `PINNED`, `ASK_ON_UPDATE` and explicitly authorized `FOLLOW` policies. Production default is pinned after first acceptance. Following may auto-acquire permitted variants, but it does not auto-restart a runtime, replace files currently in use, add install permissions, or expand a wallet subscription. Keep the old materialization lease until the application switches deliberately. HTTP ETag is a cache optimization, never channel authority.

# 11. Local runtime handoff without an inference platform

## 11.1 Typed adapters

Runtime guidance describes how a verified local model can be used. The model helper does not accept a remote launch request, serve prompts or bill inference. A local CLI/agent integration may use a trusted adapter to generate a run plan; executing that plan belongs to the user's process manager or a narrowly scoped local launcher.

An adapter resolves a trusted local executable or independently approved installed distribution. Package fields cannot set executable paths, shell text, `LD_PRELOAD`, Python startup hooks, arbitrary `PYTHONPATH`, container privileges or remote endpoints. Parameters are a typed allowlist: for example context length, concurrency, device selection and memory fraction with adapter-defined ranges. Unknown parameter names are errors.

Example safe plan: local adapter `llama.cpp`, verified GGUF file handle/path, context=4096, selected local backend, interactive or loopback-only endpoint, sanitized environment. The agent may display an argv array for the user. It must not concatenate prose into a shell command.

## 11.2 Files and execution policy

Default plan mounts or references only selected verified model files and the application's explicitly selected workspace. No wallet, cloud/HF credentials, SSH directory or unrelated project files are passed to the runtime. Disable dynamic repository code by default, including `trust_remote_code` paths in frameworks that support them. Installation or conversion requiring extra code is a distinct approval, not a hidden parameter.

Prefer network-denied local execution where the environment can enforce it; otherwise return the actual isolation status and require the corresponding local policy. Do not call a process sandboxed merely because its URL is loopback. A native model checksum proves bytes, not the absence of harmful behavior or vulnerabilities in a loader. A loopback server remains a local-runtime choice and must not be exposed through the public BTX HTTP bridge.

## 11.3 Readiness levels

`MODEL_READY` proves acquisition/materialization, not useful inference. `RUN_PLAN_READY` proves the selected adapter can describe a local invocation. `RUNTIME_STARTED` means process launch succeeded. `SMOKE_TEST_PASSED` means a declared bounded local test actually completed under that runtime. Publish compatibility evidence only when executed, and keep it separate from original model authorship.

No compatible runtime or unsupported hardware yields an actionable result. Do not silently choose a remote API. Cerebras and other specialized platforms can provide their own local/site-controlled adapters and artifact profiles; no universal runtime compatibility is asserted by a package label.

# 12. Economics remains a separate authority

A `.btx` file may represent a public model, unreleased campaign, open bounty, awarded bounty or collection of these. Embed immutable typed references and original signed terms through the existing envelope mechanism. Cached funding/reward labels are observations carrying source/time/chain context; they are never a balance oracle.

Opening a release package must show “available for free,” “awaiting release,” “economic state unknown,” or the accurate current state after permitted refresh. A bounty without a submitted model opens as a bounty, not a download failure. The client can prepare unsigned finance actions using existing RPCs. Signing and broadcast require explicit wallet approval or the already implemented finite mandate. Do not introduce a package-specific auto-pay mechanism.

Package author, model publisher and payout identity may be different. Bind payout and terms from the canonical economy object, not an AGENTS.md address or a `donate` field. Reorg behavior and independent contributor refunds follow existing bounty/release code. A readable package may refresh metadata without opening the user's wallet.

# 13. Privacy and telemetry contract

## 13.1 Do not create a mandatory observation point

No global bootstrap API, hardware-registration endpoint, package analytics endpoint or central “resolve my model” service is mandatory. Hardware/variant selection runs locally. Public acquisition must not send a recipient wallet address, email, organization name, hardware fingerprint or persistent cross-publisher consumer identifier as part of package handoff.

Define local profiles: `NATIVE_ONLY`, `EXTERNAL_ALLOWED` and `OFFLINE`. A richer privacy control may additionally restrict public search and seeding, but this round does not invent a new anonymity network. Keep telemetry disabled unless deliberately enabled by the operator. Metrics needed to operate a node remain local and have bounded retention.

## 13.2 Residual visibility is explicit

The HTTPS descriptor host can observe the request. Native peers can observe the resource/ranges they serve and the service identity/transport information available to them. A queried directory sees its queries. A directly used cloud origin or torrent swarm sees its own traffic. An adversary running several services may correlate observations. No central account requirement does not imply anonymity or a guarantee that competitors learn nothing.

The architectural objective is to remove a compulsory ecosystem-wide observer, not to claim invisibility. Include a local `ExposurePlan` listing prospective descriptor host, native peers, discovery services, external source classes and public seeding. Do not include secret URLs in the public package or diagnostics. If `NATIVE_ONLY` is selected and native sources are unavailable, return `NATIVE_SOURCES_UNAVAILABLE`; never quietly contact Hugging Face.

## 13.3 Adoption evidence

Define telemetry-reduction measurements by packet capture in a controlled test, not by a “private” UI badge. A native-only fixture must show zero HF, cloud-direct, analytics and install-origin traffic after tooling is ready. A clean install may necessarily contact an independently trusted software distributor; disclose that separately. Local cache restart should need no network when the user has pinned all dependencies and offline policy is selected.

# 14. Publisher workflow and default generation

Extend the existing `hostmodel`, import result, package writer and GUI sharing surface. A creator selects an existing verified resource or variant index, supplies a label and optional runtime/compatibility claims, and requests an agent-ready export. The writer generates AGENTS.md/README.md from typed fields, validates every reference/document/bound, previews the exact core and signs through the model identity store after approval.

The default created file is small and can be hosted anywhere or attached to a repository. Do not upload it to a BTX-operated website automatically. Provide a publisher helper that writes the descriptor, a readable documentation preview, a whole-file SHA-384 sidecar and an optional static landing page; all generated views display the same core ID. No account, tracking pixel, remote font, third-party JavaScript or external preview request is added to the static page.

A publisher can continue using Hugging Face as an upstream publication site while distributing `.btx` descriptors from its own domain and independent mirrors. The optional six-hour cross-catalogue ingest system discussed earlier is outside this round. Package export consumes already imported resources and must not accidentally launch an unbounded crawler.

# 15. Packaging, extensions and HTTP behavior

Register OS associations only through the existing approved installer/wizard. Double-click performs bounded local inspection and preview; it does not automatically install BTX, mine, seed, spend or run a model. `btx-open` retains its safe URI behavior and gains an explicit file mode that rejects ambiguous mixed arguments. Do not change an existing string handler to execute a command line.

Use an application-specific proposed MIME type such as `application/vnd.btx.package` and clearly document registration status. Descriptor servers should send exact content length where possible, `nosniff`, attachment/inline disposition as appropriate, and sensible cache headers. Immutable filenames may be cached longer; `model_latest.btx` requires revalidation. Content-Type alone does not select a dangerous parser: sniff and validate the fixed magic, then fail for HTML/error pages disguised as packages.

The client fetcher imposes the 4-MiB payload limit plus frame overhead, redirect cap=3, HTTPS policy and host/IP restrictions. Cross-origin redirects discard authorization/cookies; DNS is validated again at connect to address rebinding. External URLs are never accepted from arbitrary Markdown as executable sources. Tests use local fixture servers under a separate explicit test policy.

`.btxbundle` stays a separate streaming archive format from current work. It can include a checked thin descriptor and canonical payload records. This round allows the descriptor's embedded documents but does not authorize executing bundle contents or replace the bundle codec with ZIP. Exporting only the thin descriptor never exports model bytes, private paths or runtime secrets.

# 16. Proposed RPC and CLI contract

Reconcile names with current private RPCs. Where a listed operation already exists, extend it compatibly or create a documented alias; do not create a second implementation. Every write uses caller-scoped idempotency and expected object/plan digest. Public HTTP/explorer remains read-only and cannot proxy installation, acquisition, runtime execution or wallet effects.

| Operation | Effect | Required behavior |
|---|---|---|
| `inspectbtxpackage` | Local read | Frame/schema/document facts; no implied signature trust or network |
| `verifybtxpackage` | Local read | Native signature checks and local trust result; separate fields |
| `getbtxpackagedocument` | Local read | Bounded document by exact core ID/path; inert output |
| `createbtxpackage` / `exportbtxpackage` | Local write; optional model signing | Generate typed documents and exact v2 core |
| `planbtxacquisition` | Local plan; declared optional metadata fetch | Bind variant, resource/dependencies, budgets, source policy and destination |
| `executebtxacquisition` | Local execution | Revalidate approved plan; call existing transfer path |
| `getbtxacquisition` / `cancelbtxacquisition` | Read / local write | Existing job identity, generation and reservation lifecycle |
| `planbtxclientinstall` | Local application plan only | Independently trusted release target, no helper-driven installer |
| `planbtxruntime` | Local application plan only | Typed trusted adapter plus verified local materialization lease |
| `getbtxpackagecapabilities` | Read | Core/profile versions and actually supported features |

Install/run planners may be local CLI library calls rather than remote RPC methods. Their names in the catalogue label the application contract; never expose an install/run primitive through modeld's public server merely for symmetry. Existing wallet RPCs remain the sole economic write boundary.

Human helper examples describe the intended UX, not already-existing commands:

```text
btx-model package inspect ./model_latest.btx --json
btx-model package document ./model_latest.btx AGENTS.md
btx-model package verify ./model_latest.btx --json
btx-model package plan ./model_latest.btx --policy ./local-policy.json
btx-model package acquire --plan PLAN_ID --approve APPROVAL_REF
btx-model package status JOB_ID --json
btx-model package runtime-plan JOB_ID --adapter llama.cpp
```

The agent with no BTX starts with generic inspection, not these commands. After approved installation it uses the final versioned CLI capability report to discover supported commands. A CLI example must be generated from the same RPC inventory used by tests; do not leave plausible but unregistered command names in AGENTS.md.

# 17. Error semantics and idempotency

Stable errors include `BAD_PACKAGE_MAGIC`, `PACKAGE_TOO_LARGE`, `NONCANONICAL_PAYLOAD`, `UNSUPPORTED_CORE_VERSION`, `UNSUPPORTED_CRITICAL_EXTENSION`, `DOCUMENT_HASH_MISMATCH`, `DOCUMENT_PATH_REJECTED`, `INVALID_PACKAGE_SIGNATURE`, `PACKAGE_AUTHOR_UNTRUSTED`, `CLIENT_TRUST_REQUIRED`, `CLIENT_TARGET_UNSUPPORTED`, `INSTALL_APPROVAL_REQUIRED`, `CHANNEL_ROLLBACK`, `CHANNEL_EQUIVOCATION`, `NO_COMPATIBLE_VARIANT`, `DEPENDENCY_CYCLE`, `ACQUISITION_APPROVAL_REQUIRED`, `NATIVE_SOURCES_UNAVAILABLE`, `WAITING_FOR_PUBLIC_RELEASE`, `MODEL_BYTES_UNVERIFIED`, `RUNTIME_ADAPTER_UNSUPPORTED`, `EXECUTION_APPROVAL_REQUIRED`, `BUDGET_EXCEEDED` and `HELPER_DOWN`.

Return a structured stage, retryability, safe diagnostic, exact affected ID and next permitted action. Never include a bearer URL, secret, full local key path or raw untrusted terminal data. Unknown status remains unknown. An RPC returning success for “prepared” cannot be presented as “downloaded” or “ran.”

Idempotency binds caller, core ID, selected variant, destination, effect and plan generation. Duplicate execute returns the same job. A different core under the same mutable URL is a new candidate, not a retry. On restart, reconcile durable jobs and reservations before signing or launching any further action. A shared download can serve several local consumers, while each runtime launch still has its own authorization and materialization lease.

# 18. Schema, fixtures and supplied reference implementation

The package provides a strict Core v2 schema and related plan schemas. Cross-field invariants—document digest/length, dependency cycles, trusted signer resolution, network binding and signature verification—remain executable semantic checks; JSON Schema alone cannot establish them.

The independent Python reference validates framing, canonical JSON, schema-compatible documents, core digest and selected structural invariants. It intentionally has no network, installer, wallet or runtime code. It does not verify ML-DSA and reports that fact. Unsigned REGTEST example descriptors are only fixtures; they are not real downloadable models. The negative vectors test parser behavior rather than supply malicious runnable content.

Native conformance must add real ML-DSA-44 vectors from the implementation and test with an independently selected verifier or library. Do not substitute Ed25519, fake signatures or mocked `verified=true`. Reference tests passing locally is evidence for the reference contract only; every native/E2E row starts NOT_RUN.

The supplied standard-library reference is intentionally limited to framing, canonicalization, document commitments and selected structural semantics. Full JSON Schema validation is performed separately by scripts/validate_package.py. Native URI decoding, ML-DSA verification, publisher delegation, adapter-specific parameter limits and every side-effecting operation require the implementation tests; reference output reports them unverified.

# 19. Code-level implementation map

The following are integration targets, not instructions to create duplicate modules. The private-tree reconciliation names the actual locations before edits.

| Area | Known or expected integration | Required change |
|---|---|---|
| URI/file dispatch | `src/btx-open.cpp`; current package opener | Preserve URI mode; add safe file preview and explicit capabilities |
| Package codec | Private `.btx` module and current canonical codec | Retain BTXPKG1/v1; Core v2 schema, domains, signed docs |
| Documents | New module only if absent, e.g. `package_documents.*` | Virtual paths, bounds, hashes, safe rendering and generation |
| Plans | Current package/import/acquisition planner | Typed AgentHandoff, variant DAG, policies and receipts |
| Client requirements | Local CLI/install integration | Independent release trust and user-only InstallPlan |
| Runtime handoff | Local CLI adapter layer | Plan only by default; isolated argv and local lease |
| Channel/watch | Existing channel/events/watch modules | Bind package core, rollback floor, update policy |
| Retrieval/export | Existing VerifiedManifest, TransferSession, exportmodelpath | No alternate unverified path; materialization lease |
| RPC | Current `src/rpc/modelnet.cpp` and helper dispatcher | Reuse methods/aliases; public allowlist excludes effects |
| Human UX | Current Qt model/package pages and first-run flow | Show documents, trust levels, variant, exposure and exact action |
| Docs/tests | Existing README/HUMANS/AGENTS and test registration | Real recipes, old/new format vectors, native and process tests |

Create no new monetary resource kind, opcode or wallet balance rule for a handoff document. Package relationships may reference existing kinds. Any unexpectedly necessary consensus edit is a stop-and-escalate finding, not an implementation convenience.

# 20. Multi-agent execution after the current round

Coordinator first collects the completed current-round report and actual tree fingerprint. Do not assume every operator-gated test was completed. Carry unresolved prerequisites into a dependency ledger without representing this supplement as having fixed them.

Run parallel lanes with disjoint ownership: A—codec/schema/backward compatibility; B—documents/generic inspector; C—acquisition plans/materialization; D—trusted client installation; E—runtime adapters; F—channels/economics/privacy; G—GUI/CLI/docs; H—tests and conformance. A separate reviewer lane owns adversarial review and must not author primary code. Coordinator controls shared RPC/schema registration and CMake aggregation.

Freeze the Core v2 schema, signature domain, document rules and plan authority before parallel implementation. Commit-sized changes are recommended, but actual commits require the operator's existing authorization. Each lane returns call paths, tests run, failed cases and unexecuted cases. After integration, fresh reviewers test cross-lane contradictions, especially package-author versus software-distributor trust and AGENTS.md versus action policy.

# 21. End-to-end acceptance journeys

**J01 — Truly cold agent.** On a clean user environment with standard HTTPS/file tools and no BTX-specific command, obtain a signed fixture from a controlled HTTPS publisher, inspect AGENTS.md, select an independently trusted client release and install it non-privileged under explicit finite approval. Acquire a small public model from native peers, export verified local files, then separately authorize a local runtime smoke test. No HF account, BTX-funded wallet or model-specific bootstrapper is used. Record packet capture, software trust evidence, model digests and process outcome.

**J02 — Existing client, no account.** Open a v2 model-family package on Linux and macOS fixtures; locally select compatible variants with the same algorithm. Acquire through native providers, with upstream HF disabled. No wallet unlock or chain synchronization is triggered. Unknown hardware produces a controlled choice/error, not a guessed compatible runtime.

**J03 — Corporate isolation.** An organization supplies its own approved client/runtime catalogue and internal BTX peers. Block external domains after descriptor receipt. Acquisition, local model handoff and offline restart work from permitted sources. Hardware information and model selection remain within the host/organization boundary shown in captured traffic.

**J04 — Hostile descriptor.** Embed conflicting AGENTS.md, a same-package fake client key, a poisoned executable URL, hostile environment advice and a substituted variant. Inspection remains safe; planning refuses unauthorized effects; no secrets or processes leave policy scope. A valid package signature does not override these checks.

**J05 — Mutable latest.** Accept channel sequence 8/package A, then observe 9/package B while A is running. B is a new planned acquisition, A's lease remains intact. Replay 8 and conflicting 9 records; detect rollback/equivocation. Offline pinned A remains exact while fresh-channel status is unavailable.

**J06 — Release and bounty handoffs.** Open public, awaiting-release, unknown-economics and bounty-only packages. Refresh signed terms and local chain observations only under policy. Show no-model-yet correctly. Prepare funding without spending; execute an approved existing finite mandate only in isolated regtest and prove duplicate/reorg behavior.

**J07 — Interoperability.** Current v1 packages remain readable byte-for-byte. Old readers reject v2 safely. Current bundle import accepts the v2 descriptor only after capability checks and preserves payload verification. Thin export carries no credentials, model payload or local receipt data.

**J08 — Offline and cancellation.** Interrupt install, download, materialization and run planning at distinct boundaries; restart without double jobs, orphan processes or invalid trusted state. Open a fully pinned package offline and return correct verified paths without any network call. Cancel a run without cancelling another consumer's shared download.

# 22. Evidence and release gate

Each test in Appendix A has a unique ID, setup, action, assertions and required evidence. The CSV is an execution ledger, not proof of completion. Distinguish static source checks, reference tests, native unit tests, real helper-process tests, actual fresh-machine installation, GUI runtime, real hardware runtime and live external-source tests. A mocked network does not prove WAN behavior; generated sample docs do not prove safe agent operation.

Do not repeat the prior package's missing acceptance-file defect: `START_HERE.md`, the coordinator prompt and every cross-reference must resolve to a present file. Validate all examples against schemas, all frame/hash vectors against the reference implementation, and all release claims against execution evidence. Retain failed outputs while fixes are made; final QA states the current result and scope.

Before release require: unchanged v1 vectors; deterministic Core v2; no critical unknown-field downgrade; no document-to-authority bypass; independently trusted client installation; native acquisition with no required account/wallet; local-only compatible runtime handoff; rollback-safe channel updates; public bridge read-only; real Linux and macOS acquisition proof or explicit platform exclusion; and no regression to current 0.34.8 tests. Keep `CLIENT_VERSION_IS_RELEASE=false` until the operator approves release readiness. No auto-push or production restart.

# 23. Final handoff to the operator

Return the exact tree/build/binary fingerprint; baseline disposition; changed files/symbols; all new/extended RPCs and CLI names; final wire/schema version and domains; native signature evidence; every supported platform/runtime and evidence tier; all acceptance counts; each FAIL/NOT_RUN/deferred item; migration behavior; privacy traffic captures; dependency trust decisions; production-touch status; and the next concrete operator action.

The final product demonstration is simple: one ordinary `.btx` URL is enough information for a capable authorized agent to obtain the correct tools, acquire the exact public model from independent sources and use a verified local copy. The implementation should make that path short without letting the package choose its own authority.

# Sources and design provenance

**B01.** btxchain/btx, `AGENTS.md`, public commit `42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b` (GitHub connector inspection).  
**B02.** btxchain/btx, `src/btx-open.cpp`, same commit (GitHub connector inspection).  
**B03.** Supplied *BTX 0.34.8 Expanded Implementation Spec*, section 16 and package schema.  
**B04.** User's private-development screenshots and requested `.btx`/AGENTS.md workflow.  
**R10–R14.** Official Hugging Face download/gating documentation, AGENTS.md convention and The Update Framework documentation. Full dated URLs and evidence notes: `research/SOURCE_REGISTER.md`.

Everything explicitly designated in this document as a new field, state, test or behavior is a proposed implementation contract, not a claim that an upstream standard or the public BTX branch already implements it.

# Full reference locations

**[R10] Hugging Face.** Download files from the Hub. accessed 2026-09-16.

https://huggingface.co/docs/huggingface_hub/guides/download

**[R11] Hugging Face.** Gated models. accessed 2026-09-16.

https://huggingface.co/docs/hub/models-gated

**[R12] AGENTS.md project.** AGENTS.md. accessed 2026-09-16.

https://agents.md/

**[R13] The Update Framework.** Roles and metadata. accessed 2026-09-16.

https://theupdateframework.io/docs/metadata/

**[R14] The Update Framework.** The Update Framework specification. accessed 2026-09-16.

https://theupdateframework.github.io/specification/latest/

**[B01] btxchain/btx.** AGENTS.md at audited public main. 42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b.

https://github.com/btxchain/btx/blob/42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b/AGENTS.md

**[B02] btxchain/btx.** src/btx-open.cpp at audited public main. 42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b.

https://github.com/btxchain/btx/blob/42a5c4ec0d4c70311f0bf9a8e7cf2a53c3bd153b/src/btx-open.cpp

**[B03] BTX implementation package supplied in this conversation.** BTX 0.34.8 Expanded Implementation Spec, section 16. supplied 2026-09-16.

BTX_0.34.8_Expanded_Implementation_Spec.md, section 16

**[B04] User-provided development screenshots and decisions.** Private 0.34.8 development status and requested agent handoff. 2026-09-16.

Conversation, 0.34.8 development screenshots and .btx / AGENTS.md discussion

**[R15] NIST.** FIPS 204: Module-Lattice-Based Digital Signature Standard. 2024-08-13.

https://csrc.nist.gov/pubs/fips/204/final

# Appendix A. Complete acceptance catalogue


Each case is a native/integration acceptance requirement. Initial status is **NOT_RUN**. The supplied Python reference tests cover only their explicitly stated local scope. An accepted case requires the candidate fingerprint, exact command, environment, exit status and evidence path.

## FRM — Framing and canonical byte language

**Fixture:** Use a valid unsigned Core-v2 REGTEST descriptor and a native reader instrumented for allocations and side effects.

**Required evidence:** Native parser log, rejection code, allocation ceiling and golden bytes.

### AHP-FRM-01 — Header golden

**Steps.** Encode a known payload; compare the first 68 bytes with the independent vector.

**Pass condition.** Magic, flags, little-endian length and SHA-384 match byte for byte; offset 68 is the first payload byte.

**Evidence:** frm/01; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-FRM-02 — Truncation and trailing bytes

**Steps.** Cut at every header boundary and representative payload offsets; append one byte.

**Pass condition.** Every incomplete or trailing representation is rejected before it can be treated as an actionable package.

**Evidence:** frm/02; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-FRM-03 — Length bomb

**Steps.** Set length to 2^64−1 and to 4 MiB plus one, with a tiny actual input.

**Pass condition.** Reject before payload allocation; no arithmetic wrap, unbounded read or fall-through.

**Evidence:** frm/03; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-FRM-04 — Digest corruption

**Steps.** Flip one payload byte without changing the frame digest.

**Pass condition.** Return integrity failure and do not present embedded guidance as authenticated.

**Evidence:** frm/04; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-FRM-05 — Canonical number language

**Steps.** Supply float, exponent, NaN, infinity, negative zero and values beyond exact JSON integer range.

**Pass condition.** Reject each prohibited numeric form; monetary strings are never coerced into floating-point values.

**Evidence:** frm/05; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-FRM-06 — Duplicate and unknown fields

**Steps.** Repeat a key in raw JSON and add an undeclared core field.

**Pass condition.** Duplicate detection happens before semantic use; strict Core-v2 schema rejects the new field.

**Evidence:** frm/06; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-FRM-07 — Unicode preservation

**Steps.** Encode composed and decomposed Unicode documents; test lone surrogates and malformed UTF-8.

**Pass condition.** Valid strings retain distinct byte identities; invalid strings are rejected, not normalized or replaced.

**Evidence:** frm/07; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-FRM-08 — Depth and node limits

**Steps.** Construct maximum accepted depth/node counts, then exceed each independently.

**Pass condition.** Bounded rejection without stack exhaustion, excessive allocations or partial publication.

**Evidence:** frm/08; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-FRM-09 — Canonical serializer parity

**Steps.** Serialize the same semantic object in native C++ and reference Python with reordered input maps and escaped text.

**Pass condition.** Canonical payload and core digest match exactly; pretty JSON is not accepted as canonical wire bytes.

**Evidence:** frm/09; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-FRM-10 — Core-v1 compatibility

**Steps.** Read the supplied legacy fixture and existing private-tree golden v1 fixtures.

**Pass condition.** Old bytes and identity domains remain intact; v1 does not gain implicit runtime authority.

**Evidence:** frm/10; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-FRM-11 — Core-v2 on legacy client

**Steps.** Give the new descriptor to a strict v1 client and to the updated client.

**Pass condition.** Legacy client explicitly reports unsupported core; updated client understands it; neither silently downgrades.

**Evidence:** frm/11; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-FRM-12 — Critical extension collision

**Steps.** Add an unknown critical feature and test a preexisting private Core-v2 allocation.

**Pass condition.** Actions fail closed for unknown features; coordinator detects version collision before creating incompatible writes.

**Evidence:** frm/12; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

## DOC — Embedded guidance and safe presentation

**Fixture:** Use native inspect/document interfaces, a clean workspace, and sentinels in parent/home AGENTS.md.

**Required evidence:** Document hashes, stdout/GUI captures, filesystem diff and sandbox event trace.

### AHP-DOC-01 — Required documents

**Steps.** Create a handoff without AGENTS.md, then without README.md.

**Pass condition.** Writer/validator rejects an incomplete agent-handoff profile; never invent missing signed content.

**Evidence:** doc/01; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-DOC-02 — Byte-level document hash

**Steps.** Change one document byte or claimed byte size while preserving other fields.

**Pass condition.** Reject the mismatched document; changing and correctly resigning it creates a new core ID.

**Evidence:** doc/02; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-DOC-03 — Document limits

**Steps.** Exercise 24-KiB AGENTS, 64-KiB document, 256-KiB aggregate and 32-document boundaries.

**Pass condition.** At-limit inputs accepted; over-limit rejected without truncating signed prose.

**Evidence:** doc/03; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-DOC-04 — Path safety

**Steps.** Use absolute, dot-dot, backslash, device, colon, NUL, percent-encoded and case-collision paths.

**Pass condition.** No path escapes or overwrites; invalid virtual paths rejected consistently on Linux and macOS.

**Evidence:** doc/04; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-DOC-05 — Generated guide consistency

**Steps.** Change a structured model ID, retrieval mode or runtime profile and regenerate the package.

**Pass condition.** Generated operational guide follows typed fields; contradictory author notes are flagged and never become planner authority.

**Evidence:** doc/05; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-DOC-06 — Prompt-injection instruction

**Steps.** Insert notes claiming to override system rules, reveal credentials, or authorize wallet signing.

**Pass condition.** Inspection stays inert; application policy denies extra effects; no parent instructions or wallet state change.

**Evidence:** doc/06; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-DOC-07 — No workspace instruction takeover

**Steps.** Open a package containing AGENTS.md from within a code project.

**Pass condition.** Default read creates no AGENTS.md on disk and does not overwrite project or home guidance.

**Evidence:** doc/07; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-DOC-08 — Safe terminal and GUI rendering

**Steps.** Include ANSI escapes, bidi formatting, active HTML and external images in prose.

**Pass condition.** Terminal controls are escaped; GUI issues no image/link-preview requests and executes no active content.

**Evidence:** doc/08; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-DOC-09 — Generic first read

**Steps.** In a clean environment without BTX, run the independent inspector on a fetched fixture.

**Pass condition.** Agent can read AGENTS.md and typed client requirements using ordinary tools; no mandatory BTX bootstrapper.

**Evidence:** doc/09; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-DOC-10 — Readable-sidecar mismatch

**Steps.** Serve a readable JSON or Markdown preview inconsistent with the downloaded descriptor.

**Pass condition.** Preview is labeled nonauthoritative; mismatch blocks using it to choose installation, models or economics.

**Evidence:** doc/10; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-DOC-11 — Explicit safe extraction

**Steps.** Ask for extraction into a fresh directory, then attempt overwrite and a symlinked target.

**Pass condition.** Exclusive no-follow extraction succeeds only in the safe destination; default preview remains extraction-free.

**Evidence:** doc/11; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-DOC-12 — Translated prose

**Steps.** Add multilingual notes and regenerate signatures while keeping typed identifiers stable.

**Pass condition.** UTF-8 limits and hashes apply to actual bytes; language does not bypass authority or path checks.

**Evidence:** doc/12; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

## AUTH — Signing, provenance and local trust

**Fixture:** Use real native ML-DSA-44 keys for package author, publisher, software distributor and attacker; preserve distinct key stores.

**Required evidence:** Native signature vectors, trust-decision log and zero-effect assertions.

### AHP-AUTH-01 — Real signature vector

**Steps.** Sign a known Core-v2 digest and verify it with native APIs and an independent compatible verifier.

**Pass condition.** Exact 48-byte message, pure ML-DSA mode/context and key/signature sizes match; framing-only tests are not substituted.

**Evidence:** auth/01; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-AUTH-02 — Signed document mutation

**Steps.** Mutate a runtime profile or document and update only the framing digest.

**Pass condition.** Signature verification fails even though frame integrity now passes.

**Evidence:** auth/02; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-AUTH-03 — Signer identity mismatch

**Steps.** Keep a valid signature but replace the declared signer ID.

**Pass condition.** Native public-key-to-identity derivation rejects the mismatch.

**Evidence:** auth/03; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-AUTH-04 — Unknown self-signed author

**Steps.** Open a structurally valid package signed by a new untrusted key.

**Pass condition.** Report valid signature separately from unknown trust; no installation/execution without explicit trust/acceptance.

**Evidence:** auth/04; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-AUTH-05 — Observations outside core

**Steps.** Change a cached funding or availability observation while retaining signed core.

**Pass condition.** Core identity remains unchanged; observation never becomes package-author-attested or wallet-authoritative.

**Evidence:** auth/05; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-AUTH-06 — Provenance not authorship

**Steps.** A mirror signs a package referencing an upstream lab model.

**Pass condition.** UI/API expose packager and publisher separately; no automatic attribution of model authorship to the mirror.

**Evidence:** auth/06; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-AUTH-07 — Root substitution

**Steps.** Supply a client binary and a matching attacker key in package notes.

**Pass condition.** No independent software trust is established; installer remains TRUST_REQUIRED.

**Evidence:** auth/07; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-AUTH-08 — Finite multi-stage authority

**Steps.** Authorize exact install/acquire/local-run plan once and then alter its selected resource or maximum bytes.

**Pass condition.** Original approved plan runs without redundant prompts; materially changed plan requires new authority.

**Evidence:** auth/08; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-AUTH-09 — Unsigned preview

**Steps.** Open an unsigned descriptor and request inspection, installation and funding in sequence.

**Pass condition.** Inspection allowed; later effects require their independent authorities; no blanket verified flag.

**Evidence:** auth/09; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-AUTH-10 — Key rotation boundaries

**Steps.** Rotate package/publisher keys using a valid scoped native delegation; also test unsigned rotation.

**Pass condition.** Valid delegation accepted only for its scope; unsigned key replacement does not change software-distribution trust.

**Evidence:** auth/10; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

## INS — Client acquisition and installation

**Fixture:** Use an isolated fresh home, test distribution metadata signed by an independently configured root, and local HTTP fixtures only.

**Required evidence:** Install plan digest, file hashes, metadata validation and process/filesystem audit.

### AHP-INS-01 — No existing BTX client

**Steps.** Read package with generic tools, resolve trusted test distribution, approve and install user-local client.

**Pass condition.** Complete client acquisition without preinstalled btx-bootstrap, funded wallet, GPU or production-service mutation.

**Evidence:** ins/01; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-INS-02 — Already installed compatible client

**Steps.** Provide a trusted compatible client with required capabilities.

**Pass condition.** Reuse it; no unnecessary download or installation occurs.

**Evidence:** ins/02; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-INS-03 — Version versus capability

**Steps.** Offer a high version missing AGENT_HANDOFF_V1 and a lower compatible version within allowed policy.

**Pass condition.** Planner uses actual capabilities and minimum version together, not version marketing alone.

**Evidence:** ins/03; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-INS-04 — Freeze and rollback

**Steps.** Replay expired release metadata and downgrade target below the accepted local floor.

**Pass condition.** Reject freeze/rollback unless an explicit independently authorized recovery policy permits it.

**Evidence:** ins/04; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-INS-05 — Binary mismatch

**Steps.** Serve bytes whose digest/size differs from trusted target metadata.

**Pass condition.** Reject before execution and remove only staged installation files.

**Evidence:** ins/05; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-INS-06 — Unsafe software archive

**Steps.** Provide traversal, symlink escape, duplicate executable and unexpected binary entries.

**Pass condition.** Safe extraction denies them; no write outside user-local staging or executable allowlist.

**Evidence:** ins/06; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-INS-07 — Atomic failure recovery

**Steps.** Interrupt download, verification and final promotion in separate runs.

**Pass condition.** Restart either resumes verified stages or removes incomplete staging; previously installed client remains usable.

**Evidence:** ins/07; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-INS-08 — Privilege escalation

**Steps.** Package requests system install, sudo or replacement of running btxd.

**Pass condition.** Default user-local plan refuses escalation and leaves production unchanged.

**Evidence:** ins/08; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-INS-09 — First-use missing trust

**Steps.** Remove every independently accepted software root/package manager mapping.

**Pass condition.** Return precise trust decision, not automatic approval of the package-supplied key.

**Evidence:** ins/09; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-INS-10 — Offline approved cache

**Steps.** With no internet, install an independently verified locally cached distribution.

**Pass condition.** No network required when trust metadata and exact software bytes are already valid locally.

**Evidence:** ins/10; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

## VAR — Variants and dependency planning

**Fixture:** Use a family with CPU, ROCm, CUDA and Metal profiles, required tokenizer/config, optional adapters and conflicting claims.

**Required evidence:** Deterministic selection outputs, capability inventory and DAG validation.

### AHP-VAR-01 — Explicit selection wins

**Steps.** Select a compatible named variant when another is recommended by the publisher.

**Pass condition.** Use the user choice, exact immutable resource and its actual dependencies.

**Evidence:** var/01; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-VAR-02 — No vendor preference

**Steps.** Feed equivalent backend capabilities and permute variant order.

**Pass condition.** Stable policy/tie-break decides; no hardcoded CUDA-first or anti-NVIDIA bias.

**Evidence:** var/02; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-VAR-03 — Memory feasibility

**Steps.** Choose a model near RAM capacity with declared runtime/KV overhead and an oversized competitor.

**Pass condition.** Account for the complete memory estimate; never treat weight-file size alone as guaranteed fit.

**Evidence:** var/03; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-VAR-04 — Unknown compatibility

**Steps.** Provide a runtime label with no installed/qualified adapter or unknown format admission.

**Pass condition.** Return unsupported/unknown compatibility, not executable support by label.

**Evidence:** var/04; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-VAR-05 — Dependency cycle and depth

**Steps.** Create cycles, missing nodes and chains beyond depth eight.

**Pass condition.** Bounded failure before transfer; no recursive fetch explosion.

**Evidence:** var/05; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-VAR-06 — Variant-resource mismatch

**Steps.** Reference an absent resource or an ARTIFACT where variant expects MODEL.

**Pass condition.** Reject inconsistent commitments without inventing an alias.

**Evidence:** var/06; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-VAR-07 — Partial selection

**Steps.** Acquire tokenizer/docs only, then add mandatory weights.

**Pass condition.** First receipt is SELECTION_READY; later full receipt only after canonical completeness checks.

**Evidence:** var/07; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-VAR-08 — Model-less bounty

**Steps.** Open a BOUNTY package with no winning model and a valid immutable bounty reference.

**Pass condition.** Preview works without dummy resource; no acquisition/runtime plan is falsely READY.

**Evidence:** var/08; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

## ACQ — Native acquisition and local output

**Fixture:** Use real isolated model helpers with safe test model fixtures, finite disk/network quotas and a recipient without HF or S3 credentials.

**Required evidence:** Helper/process logs, exact manifests/hashes, packet accounting and receipts.

### AHP-ACQ-01 — No-account native journey

**Steps.** Acquire a public model only from BTX peers on a recipient with no HF account/token or funded wallet.

**Pass condition.** Exact verified local files become ready; no upstream login, cloud credential or blockchain sync is required.

**Evidence:** acq/01; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ACQ-02 — Original source outage

**Steps.** Serve package locally; disable original HF/HTTPS origin and one bootstrap provider.

**Pass condition.** Remaining native providers satisfy exact model identity; failure of original hosting does not rewrite IDs.

**Evidence:** acq/02; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ACQ-03 — Hint substitution

**Steps.** A hinted provider serves a different manifest under a familiar name.

**Pass condition.** VerifiedManifest/identity checks reject substitution before catalog mutation.

**Evidence:** acq/03; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ACQ-04 — Native-only policy

**Steps.** Block native sources but leave a working external HF/torrent/cloud source.

**Pass condition.** Wait or fail with source reason; do not silently leak requests through external fallback.

**Evidence:** acq/04; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ACQ-05 — External opt-in

**Steps.** Authorize one explicit external-origin mode with its own bounded plan.

**Pass condition.** Receipt records actual external transport; no claim that those bytes travelled over native PQ1.

**Evidence:** acq/05; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ACQ-06 — Resource ceiling

**Steps.** Exhaust finite byte/disk/concurrency reservations through simultaneous acquisitions.

**Pass condition.** Global limits hold; package or rare-piece recommendation cannot bypass them.

**Evidence:** acq/06; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ACQ-07 — Restart and stale cache

**Steps.** Interrupt after some pieces; alter one cached file before restart.

**Pass condition.** Valid bytes reused; altered data reverified/retrieved; no readiness by filename alone.

**Evidence:** acq/07; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ACQ-08 — Safe materialization

**Steps.** Materialize a multi-file model, attempting malicious relative paths and output symlink swaps.

**Pass condition.** Only safe canonical files exported; no escape; complete file hashes verified.

**Evidence:** acq/08; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ACQ-09 — Active output lease

**Steps.** Start a runtime load while GC, eviction and channel-update jobs run.

**Pass condition.** Active local files are not deleted/replaced until lease release.

**Evidence:** acq/09; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ACQ-10 — Cancellation and idempotency

**Steps.** Cancel an acquisition and retry the same caller-scoped idempotency key; also reuse key with altered payload.

**Pass condition.** Unused reservations released; retry returns existing outcome; conflicting payload is rejected.

**Evidence:** acq/10; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

## RUN — Local runtime handoff

**Fixture:** Use an installed, pinned test adapter and isolated local model fixture; no public inference endpoint is configured.

**Required evidence:** Typed plan, process argv/environment, network trace, resource usage and receipt.

### AHP-RUN-01 — Plan is not execution

**Steps.** Request a runtime plan from a ready receipt without execution authorization.

**Pass condition.** Return inert typed plan; no process starts.

**Evidence:** run/01; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-RUN-02 — Authorized local smoke

**Steps.** Approve exact runtime plan with local model path and finite limits.

**Pass condition.** Known adapter starts, loads exact files and returns a local smoke result; no remote inference.

**Evidence:** run/02; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-RUN-03 — No arbitrary shell

**Steps.** Put shell metacharacters, executable names and unknown flags into package parameters.

**Pass condition.** Adapter schema rejects unknown commands/flags; spawning uses typed args without shell evaluation.

**Evidence:** run/03; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-RUN-04 — No model custom code

**Steps.** Offer a model that asks for remote code/plugins or trust_remote_code.

**Pass condition.** No automatic dynamic code loading; require separate independently trusted adapter/format work.

**Evidence:** run/04; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-RUN-05 — Network containment

**Steps.** Attempt outbound prompt delivery or a non-loopback service bind.

**Pass condition.** Default local-run profile blocks it; loopback-only is enforced for service profiles.

**Evidence:** run/05; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-RUN-06 — Credentials and inherited environment

**Steps.** Place wallet/cloud/install sentinels in parent environment before runtime launch.

**Pass condition.** Child receives a minimal approved environment, not unrelated secrets.

**Evidence:** run/06; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-RUN-07 — OOM and cancellation

**Steps.** Exceed the run memory limit and interrupt a running model load.

**Pass condition.** Bounded cleanup and lease release; no success receipt for failed execution.

**Evidence:** run/07; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-RUN-08 — Changed executable

**Steps.** Replace a local runtime binary after planning but before authorized execution.

**Pass condition.** Digest revalidation invalidates plan and prevents time-of-check/time-of-use substitution.

**Evidence:** run/08; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

## ECO — Economic objects remain separate

**Fixture:** Use release/bounty REGTEST fixtures with independent wallet and reorg-capable test chain; no mainnet secrets.

**Required evidence:** Exact terms, chain anchors, wallet authorization audit and balances.

### AHP-ECO-01 — Stale reward preview

**Steps.** Open a package whose cached funding state differs from local chain facts.

**Pass condition.** Label cached state stale; refreshed current state is separate; no copied percentage controls spending.

**Evidence:** eco/01; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ECO-02 — Free does not become paid

**Steps.** Make the referenced model await a paid public release during FREE_ONLY acquisition.

**Pass condition.** Return WAITING_FOR_PUBLIC_RELEASE or explicit funding option; spend remains zero.

**Evidence:** eco/02; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ECO-03 — Bounty inspection only

**Steps.** Inspect reward, terms, evaluator references and no winning model.

**Pass condition.** No model ID invented and no pledge/funding transaction created.

**Evidence:** eco/03; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ECO-04 — Separate approved funding

**Steps.** Prepare and approve an exact existing funding operation after refreshing terms.

**Pass condition.** Only existing wallet authority signs; package signature is not accepted as wallet approval.

**Evidence:** eco/04; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ECO-05 — Reorg knowledge distinction

**Steps.** Reorg a release claim after its secret was disclosed.

**Pass condition.** Settlement observations update; disclosed knowledge is not forgotten or treated as unreleased ciphertext automatically.

**Evidence:** eco/05; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-ECO-06 — Observation source spoof

**Steps.** Portable JSON claims source LOCAL_CHAIN and marks itself current.

**Pass condition.** Treat as sender observation until locally re-derived; no elevated authority from an enum string.

**Evidence:** eco/06; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

## PRIV — Telemetry and access boundaries

**Fixture:** Use endpoint/request logging under operator control and native-only versus external-source test plans.

**Required evidence:** Packet captures or equivalent counters, exported data scan and policy audit.

### AHP-PRIV-01 — No required analytics

**Steps.** Run inspect, install planning, variant selection and native acquisition with analytics endpoints blackholed.

**Pass condition.** No mandatory telemetry dependency; local selection still succeeds.

**Evidence:** priv/01; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-PRIV-02 — Hardware inventory stays local

**Steps.** Choose between hardware profiles while monitoring all outbound metadata.

**Pass condition.** No detailed hardware/user inventory leaves the machine absent explicit separate consent.

**Evidence:** priv/02; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-PRIV-03 — Credential sentinels

**Steps.** Set HF, S3, wallet and distribution sentinels; export package/receipts/diagnostics.

**Pass condition.** No secrets in portable files or public responses; private local references stay scoped.

**Evidence:** priv/03; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-PRIV-04 — Descriptor-host disclosure

**Steps.** Fetch an HTTPS descriptor, then acquire via peers.

**Pass condition.** Document host sees its own fetch, not falsely claimed invisible; unrelated origin receives no acquisition call.

**Evidence:** priv/04; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-PRIV-05 — No embedded presigned capabilities

**Steps.** Author a source hint or note containing credential-bearing URLs.

**Pass condition.** Writer lints/rejects operational secret fields; inspector never follows prose URLs; author notes remain untrusted.

**Evidence:** priv/05; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-PRIV-06 — Multiple directories

**Steps.** Disable one directory and use independent alternative signed providers.

**Pass condition.** Discovery does not require a canonical analytics/catalog endpoint.

**Evidence:** priv/06; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-PRIV-07 — Gated-source distinction

**Steps.** Try an inaccessible source without authorization and a separately available legitimately mirrored public resource.

**Pass condition.** No gate bypass; availability/rights/source policy evaluated separately rather than assuming gate equals license.

**Evidence:** priv/07; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-PRIV-08 — Public versus private state

**Steps.** Expose inspection over allowed public bridge and request local paths/trust keys/install plans.

**Pass condition.** Public view remains read-only/redacted; local-only operations and personal state are inaccessible.

**Evidence:** priv/08; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

## CHAN — Latest pointers and signed channels

**Fixture:** Use an exact package pin plus a signed publisher channel with persisted local sequence state.

**Required evidence:** Signed statements, channel state history and acquisition plan digests.

### AHP-CHAN-01 — Mutable web path

**Steps.** Replace bytes behind model_latest.btx with a new valid package.

**Pass condition.** Previously pinned package remains exact; new selection is a distinct observed update.

**Evidence:** chan/01; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-CHAN-02 — Rollback

**Steps.** After accepting sequence 10, present sequence 9 with a valid signature.

**Pass condition.** Reject rollback under normal policy; wall-clock freshness cannot override the sequence floor.

**Evidence:** chan/02; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-CHAN-03 — Equivocation

**Steps.** Provide two different targets with same publisher/channel/sequence and valid signatures.

**Pass condition.** Expose conflict; do not silently choose last-arriving target.

**Evidence:** chan/03; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-CHAN-04 — Untrusted channel key

**Steps.** Serve update signed by new unrelated key from the same hostname.

**Pass condition.** Hostname alone does not rotate publisher trust.

**Evidence:** chan/04; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-CHAN-05 — Follow is explicit

**Steps.** Open a package containing channel_ref without follow permission.

**Pass condition.** Show update opportunity; do not persist watch or replace model automatically.

**Evidence:** chan/05; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-CHAN-06 — Offline expiry

**Steps.** Open cached channel metadata after expiry with no network.

**Pass condition.** Exact already pinned model can remain usable under policy; no claim that expired latest state is current.

**Evidence:** chan/06; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-CHAN-07 — Restart high-water mark

**Steps.** Restart after accepting a channel update and replay older state.

**Pass condition.** Persisted rollback protection survives restart.

**Evidence:** chan/07; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-CHAN-08 — Dependency update materiality

**Steps.** Keep channel label but change tokenizer/model dependency in new package.

**Pass condition.** Create new core and plan; active runtime remains on leased prior files until explicit transition.

**Evidence:** chan/08; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

## API — Interfaces and documentation

**Fixture:** Run CLI/RPC/Qt wrappers against one canonical package/planner implementation.

**Required evidence:** API fixtures, user journey captures, catalog diff and effects audit.

### AHP-API-01 — RPC alias reuse

**Steps.** Compare proposed method catalog to private-tree methods and register aliases where needed.

**Pass condition.** One handler per operation; no duplicate planner or package codec.

**Evidence:** api/01; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-API-02 — Structured agent output

**Steps.** Execute inspect/plan/status/cancel in JSON mode and human CLI mode.

**Pass condition.** Stable fields/errors in JSON; no need to parse presentation prose.

**Evidence:** api/02; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-API-03 — Public bridge denylist

**Steps.** Attempt install/acquire/run/funding mutation through public HTTP routes.

**Pass condition.** No mutation proxy; only intended read-only preview allowed.

**Evidence:** api/03; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-API-04 — OS double-click

**Steps.** Open descriptor through Linux/macOS supported file association.

**Pass condition.** Preview first with correct package identity and actions; no automatic install, download or run.

**Evidence:** api/04; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-API-05 — Agent walkthrough

**Steps.** Run documented fresh-agent recipe using exact shipped tool names.

**Pass condition.** Every command exists or is clearly an adapter-side plan; no imaginary bootstrap dependency.

**Evidence:** api/05; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-API-06 — Guide drift check

**Steps.** Modify schema capabilities/runtime enum and regenerate docs.

**Pass condition.** CI flags or regenerates stale examples and AGENTS instructions before package signing.

**Evidence:** api/06; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-API-07 — Error specificity

**Steps.** Inject unsupported client, missing trust, missing providers, hash mismatch and no-compatible-model faults.

**Pass condition.** Distinct stable codes and actionable nonmisleading messages; no generic READY on error.

**Evidence:** api/07; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-API-08 — Concurrent parser load

**Steps.** Submit malformed and valid descriptors concurrently within caps.

**Pass condition.** Bounded CPU/memory and fair service; expensive signature verification is rate-limited after cheap checks.

**Evidence:** api/08; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

## COMP — Compatibility and isolation

**Fixture:** Use old .btx vectors, old 0.34.7 model peer, new helper, modelnet-off build and independent reference reader.

**Required evidence:** Build logs, interoperability traces and immutable vector diffs.

### AHP-COMP-01 — Old peer new package

**Steps.** Resolve a Core-v2 package and retrieve its underlying ordinary model from a 0.34.7 peer.

**Pass condition.** Package extension does not require changing canonical model bytes or legacy native transfer semantics.

**Evidence:** comp/01; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-COMP-02 — Legacy export deliberate

**Steps.** Request a legacy acquisition-only export from a new package.

**Pass condition.** Output is distinct and labeled loss of handoff/runtime semantics; no silent execution downgrade.

**Evidence:** comp/02; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-COMP-03 — Bundle compatibility

**Steps.** Place a new thin descriptor into the existing approved bundle framing.

**Pass condition.** Streaming reader validates descriptor and payload separately; no arbitrary ZIP extraction or identity rewrite.

**Evidence:** comp/03; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-COMP-04 — Helper down

**Steps.** Stop isolated helper while monetary node runs.

**Pass condition.** Money remains operational; package acquisition fails closed/retries without wallet mutation.

**Evidence:** comp/04; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-COMP-05 — Modelnet disabled build

**Steps.** Compile WITH_MODELNET=OFF and run unaffected money tests.

**Pass condition.** No new required package/runtime dependency in monetary consensus build.

**Evidence:** comp/05; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.

### AHP-COMP-06 — Reference versus native evidence

**Steps.** Compare reference output with native signature/install/WAN test inventory.

**Pass condition.** Report scope honestly; framing PASS never becomes proof of PQ, installation or live acquisition.

**Evidence:** comp/06; candidate/build/environment plus artifacts described above. **Initial status:** NOT_RUN.
