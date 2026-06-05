# BTX client source-based auto-update (0.31.0, FINAL element — integrate last)

> **⚠️ STATUS — THIS IS THE ORIGINAL DESIGN SPEC; THE IMPLEMENTATION SUPERSEDES IT IN TWO WAYS.**
> Read [`contrib/autoupdate/BOOTSTRAP.md`](../contrib/autoupdate/BOOTSTRAP.md) for the as-built
> behavior. The two divergences below exist *because BTX is a post-quantum chain* — a classical
> signature on the code-update channel would be the weakest link in the system:
> 1. **Default signature scheme is post-quantum ML-DSA-44, not secp256k1/ECDSA.** secp256k1 remains
>    selectable (`-autoupdatepubkeyalgo=secp256k1`) only as a transitional first hop; see BOOTSTRAP.md.
> 2. **The v0.31.0 PQ release pubkey IS compiled in.** `DEFAULT_AUTOUPDATE_RELEASE_PUBKEY` holds the
>    ML-DSA-44 release public key, so auto-update is **default-on (opt-out)** on mainnet and works out
>    of the box — there is no key/algo mismatch because the baked-in key matches the `ml-dsa-44` default.
>    Operators can override with `-autoupdatepubkey` (+ `-autoupdatepubkeyalgo`) or set it to `0`/empty
>    to opt out. The historical secp256k1 key `03478e9d…21420c` below is retained ONLY as a reference for
>    an optional classical first hop — it is NOT the baked-in key. The key currently compiled in is the
>    dev PLACEHOLDER (regenerate via air-gapped ceremony + re-bake before real mainnet). (Baked in by
>    PR #221, commit 0bbbe0d4; verified: `btxd -chain=main` starts clean and the update thread runs.)

Opt-out (configurable) polling of https://btx.dev/version.txt → source build via install.sh → graceful
switch preserving mining + shielded data. Based on the btx.dev server spec; HARDENED with mandatory
signature verification (the provided HTTPS+origin trust model is insufficient for an RCE-by-design channel).

## Server side (already live on btx.dev)
- https://btx.dev/version.txt — JSON: {version, repo_url, script_url, release_tag, git_ref, channel}
- https://btx.dev/install.sh — SOURCE updater (clone/fetch repo_url@release_tag||git_ref, CMake build, reuse
  installed tree, preserve running btxd runtime shape: datadir/conf/walletdir/blocksdir/chain/pid/-wallet,
  ensure retainshieldedcommitmentindex=1, verify new binaries BEFORE stopping old node, keep old node on build fail).

## Client side (this task)
1. **Polling:** every 30 min (configurable) fetch BTX_MANIFEST_URL (default https://btx.dev/version.txt). Backoff
   on failure (exponential, capped); cache last-seen manifest; don't re-prompt/re-act on the same version.
2. **Parse + compare:** parse the JSON; semver-compare remote.version vs local CLIENT_VERSION. Treat version.txt
   as authoritative even if release_tag hasn't propagated (install.sh falls back to git_ref).
3. **TRUST MODEL (hardened — REQUIRED):**
   - HTTPS only; script_url MUST be same-origin btx.dev (exact host allowlist) unless -autoupdatedevorigin set.
   - ★ **Signature verification:** version.txt MUST carry a detached signature (e.g. version.txt.sig or a `sig`
     field) over its canonical bytes, verified against an operator-configured RELEASE PUBKEY
     (`-autoupdatepubkey` + `-autoupdatepubkeyalgo`; default scheme ML-DSA-44, default key = the
     compiled-in v0.31.0 PQ release pubkey). REFUSE any manifest without a valid signature.
     (Implemented: the resolved git commit can also be verified via a signed
     `git_commit`/`git_commit_sig_url`.) If the pubkey is overridden to empty (`0`) → feature INERT
     (fail-safe opt-out). This makes a btx.dev compromise insufficient to push code.
4. **Update path:** if remote newer AND verified AND seamless-mode enabled: invoke install.sh NON-interactively
   in the background as the installer entrypoint (never build from repo_url directly; no binary download).
   install.sh builds+verifies, then (only on success) stops old node + starts new on the SAME datadir.
5. **Graceful switch / minimal downtime:** only switch if the new build verifies AND can take over the existing
   datadir (mining chainstate + shielded persisted index). Build happens with old node still running; downtime =
   stop→start + shielded re-init (kept low by retainshieldedcommitmentindex=1; u2's progress bar shows it). On
   ANY failure, leave the old node running (rollback).
6. **Gating / config:** `-autoupdate=0/1` (poll+notify), `-autoupdateseamless=0/1` (actually apply), channel
   filter, manifest URL, pubkey, dev-origin override, poll interval. **DEFAULT ON (OPT-OUT) — maintainer
   decision:** 0.31.0 is the hard-fork adoption window, so auto-update ships enabled to keep the fleet
   updatable going forward; the signature floor (below) is what makes default-on safe. Users can `-autoupdate=0`.

## SIGNING SCHEME (AS BUILT — see the status banner at top; supersedes the original ECDSA-only plan)
- **Default scheme: post-quantum ML-DSA-44** over SHA-256(exact version.txt bytes), detached
  **version.txt.sig** (sig_url field, default `<manifest>.sig`). `slh-dsa-128s` also supported.
  secp256k1 ECDSA/DER remains selectable via `-autoupdatepubkeyalgo=secp256k1` as a transitional
  first hop only. The installer verifies PQ signatures with `btx-util verifyupdatesig` and classical
  ones with openssl. (Rationale: the update channel can ship code fleet-wide, so on a PQ chain it
  must itself be quantum-safe.)
- **Compiled-in release pubkey (v0.31.0).** `DEFAULT_AUTOUPDATE_RELEASE_PUBKEY` holds the ML-DSA-44
  release pubkey → auto-update is default-on out of the box; override with `-autoupdatepubkey`
  (+ `-autoupdatepubkeyalgo`) or set it to `0`/empty to opt out. The baked-in key is currently the dev
  PLACEHOLDER (regenerate via air-gapped ceremony + re-bake before mainnet). The historical secp256k1
  key `03478e9d7f986823a1d77c4e2bb75f4600d3dccb5475371e45922ebfc39521420c` is a *reference* for an
  optional classical first hop, NOT the baked-in key.
- OFFLINE key + operator README + sign/verify helpers live OUTSIDE the repo at `../btx-release-key/` (to be
  secured/rotated properly later). README documents the version.txt JSON `sig_url` add + the install.sh verify step.
- ★ AS BUILT: default ON on mainnet with the compiled-in ML-DSA-44 release pubkey (default-on, opt-out);
  scheme defaults to ML-DSA-44. The bootstrap/first-hop plan lives in `contrib/autoupdate/BOOTSTRAP.md`.
7. **Logging:** clear reason on every skip (not newer / sig fail / origin fail / net fail / disabled).

## Tests (unit)
parse version.txt (valid/malformed); semver compare; same-origin script_url validation (accept btx.dev, reject
evil.com / http / look-alikes); newer-version detection; no-op when current; manifest unreachable/malformed
handling; ★ signature: accept valid, REJECT tampered manifest / bad sig / missing sig / wrong key.

## Docker integration test (MUST fully pass — all scenarios)
Simulated btx.dev (local TLS server serving version.txt + .sig + install.sh) + a running regtest btxd:
- happy path: newer signed version → poll → install.sh build → graceful switch → node back up on same datadir,
  mining resumes, shielded loads from index; MEASURE downtime.
- already current → no-op. unreachable manifest → backoff, node untouched. malformed manifest → skip+log.
- ★ TAMPERED manifest / BAD signature / wrong-origin script_url → REJECTED, no build, node untouched.
- build FAILURE → old node keeps running (rollback verified).
- opt-out disabled → never acts. seamless off → notify only.
- mining + shielded data continuity verified across the switch (no chain/shielded loss; minimal downtime).

## Status
Integrate LAST in 0.31.0 (after security/feature work). Ships DISABLED until a release signing pubkey is
configured. Maintainer decision pending: (a) release signing key for version.txt? (b) default opt-in vs opt-out.
