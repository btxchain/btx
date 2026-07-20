// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_PARAMS_H
#define BITCOIN_CONSENSUS_PARAMS_H

#include <consensus/amount.h>
#include <uint256.h>

#include <array>
#include <chrono>
#include <limits>
#include <map>
#include <optional>
#include <vector>

namespace Consensus {

// Budget: 1042 SMILE txns × (2×100 + 2×15) = 239,660 units.
// Set to 240,000 so block size (24MB) is the binding constraint, not verify budget.
// CPU verification: 1042 txns × 3.5ms = 3.6s (4% of 90s block time, single core).
static constexpr uint64_t DEFAULT_MAX_BLOCK_SHIELDED_VERIFY_COST{240'000};
static constexpr uint64_t DEFAULT_MAX_BLOCK_SHIELDED_SCAN_UNITS{24'576};
static constexpr uint64_t DEFAULT_MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS{24'576};
static constexpr uint64_t DEFAULT_MAX_BLOCK_SHIELDED_ACCOUNT_REGISTRY_APPENDS{4'096};
static constexpr uint64_t DEFAULT_MAX_SHIELDED_ACCOUNT_REGISTRY_ENTRIES{65'536};

/**
 * A buried deployment is one where the height of the activation has been hardcoded into
 * the client implementation long after the consensus change has activated. See BIP 90.
 */
enum BuriedDeployment : int16_t {
    // buried deployments get negative values to avoid overlap with DeploymentPos
    DEPLOYMENT_HEIGHTINCB = std::numeric_limits<int16_t>::min(),
    DEPLOYMENT_CLTV,
    DEPLOYMENT_DERSIG,
    DEPLOYMENT_CSV,
    DEPLOYMENT_SEGWIT,
};
constexpr bool ValidDeployment(BuriedDeployment dep) { return dep <= DEPLOYMENT_SEGWIT; }

enum DeploymentPos : uint16_t {
    DEPLOYMENT_TESTDUMMY,
    DEPLOYMENT_TAPROOT, // Deployment of Schnorr/Taproot (BIPs 340-342)
    // NOTE: Also add new deployments to VersionBitsDeploymentInfo in deploymentinfo.cpp
    MAX_VERSION_BITS_DEPLOYMENTS
};
constexpr bool ValidDeployment(DeploymentPos dep) { return dep < MAX_VERSION_BITS_DEPLOYMENTS; }

/**
 * Struct for each individual consensus rule change using BIP9.
 */
struct BIP9Deployment {
    /** Bit position to select the particular bit in nVersion. */
    int bit{28};
    /** Start MedianTime for version bits miner confirmation. Can be a date in the past */
    int64_t nStartTime{NEVER_ACTIVE};
    /** Timeout/expiry MedianTime for the deployment attempt. */
    int64_t nTimeout{NEVER_ACTIVE};
    /** If lock in occurs, delay activation until at least this block
     *  height.  Note that activation will only occur on a retarget
     *  boundary.
     */
    int min_activation_height{0};

    /** Constant for nTimeout very far in the future. */
    static constexpr int64_t NO_TIMEOUT = std::numeric_limits<int64_t>::max();

    /** Special value for nStartTime indicating that the deployment is always active.
     *  This is useful for testing, as it means tests don't need to deal with the activation
     *  process (which takes at least 3 BIP9 intervals). Only tests that specifically test the
     *  behaviour during activation cannot use this. */
    static constexpr int64_t ALWAYS_ACTIVE = -1;

    /** Special value for nStartTime indicating that the deployment is never active.
     *  This is useful for integrating the code changes for a new feature
     *  prior to deploying it on some or all networks. */
    static constexpr int64_t NEVER_ACTIVE = -2;
};

/**
 * MatMul v4 committed-operand ENCODING PROFILES — the L1 (versioned) layer of
 * the v4.2 profile architecture (doc/btx-matmul-v4.2-bmx4c-spec.md §7,
 * doc/btx-matmul-v4.2-longevity-threat-model.md §3.1). Exactly one profile is
 * live at any height; the profile decides how header seeds become exact
 * integer operands (mantissa alphabet, scale structure, U/V alphabet, XOF
 * sampling rule + domain tags, magnitude constants, golden vectors, limb-base
 * reference). It NEVER touches the L0 invariant core (SketchFreivalds verifier
 * and its O(n^2) cost, q = 2^61-1, R = 3, exact-integer commitment, digest
 * form H(sigma||C_hat), Fiat-Shamir rule, price-independence, the hardness
 * floor, C-1' "no rounding on the committed path"). A profile change is a
 * height-gated hard fork of parameters-and-vectors into the same machine.
 * Profile IDs are never reused or redefined once activated on any network.
 */
enum class MatMulEncodingProfile : uint8_t {
    //! v4/v4.1 (spec §A.2/App. C-13): balanced signed-INT8 operands and U/V in
    //! [-125, 125], no scale planes, base-2^7 limb combine.
    ENC_S8 = 1,
    //! v4.2 BMX4-C (doc/btx-matmul-v4.2-bmx4c-spec.md §1-§3): M11 mantissas
    //! {0,±1,±2,±3,±4,±6} × per-32-block power-of-two scale 2^e, e ∈ {0..3};
    //! scale-free M11 U/V; base-2^6 remainder-top limb combine.
    ENC_BMX4C = 2,
    //! RESERVED (v4.4 ENC-DR retirement). ENC-BMX4C-D was the staged v4.2-D
    //! deeper-commit profile (tile b = 2, m = 2048, ~32 MiB sketch carried as a
    //! SEGREGATED PRUNABLE PROOF via the getmatmulproof/matmulproof relay). It
    //! was never activated on any public network. v4.4 ENC-DR
    //! (doc/btx-matmul-v4.4-tension-resolution.md §4.4) deletes the entire
    //! segregated-proof subsystem and obsoletes D by construction: under
    //! digest-only carriage m is a storage-free knob, so a deeper commit is a
    //! parameter retarget, not a new carriage. The enum value stays RESERVED
    //! per the profile-ID hygiene rule above (activated on regtest CI); no
    //! activation path exists.
    ENC_BMX4CD = 3,
    //! v4.4-LT Rank-1 package (doc/btx-matmul-v4.4-lt-normative-spec.md):
    //! ENC-DR carriage + deep-m (b=2) + MatExpand operand derivation +
    //! consensus-bound Q* window. STAGED: nMatMulDRLTHeight defaults to
    //! INT32_MAX on every public network.
    ENC_BMX4C_LT = 4,
    //! Resident Curriculum (3-phase episode). STAGED: nMatMulRCHeight defaults
    //! to INT32_MAX on every public network (clean cutover later).
    ENC_RC = 5,
    //! FINAL-FORM Stage C coupled puzzle (matmul_v4_rc_coupled.*). STAGED:
    //! nMatMulRCCoupledHeight defaults to INT32_MAX on every public network.
    //! Regtest may set a finite height + fMatMulRCCoupledUseToyDims to exercise
    //! CheckMatMulProofOfWork_RCCoupled / SolveMatMulV4RCCoupled end-to-end.
    //! When live, GetMatMulEncodingProfile prefers ENC_RC_COUPLED over ENC_RC.
    ENC_RC_COUPLED = 6,
};

/**
 * MatMul v4.4 COMMITMENT SCHEME — how the committed object Chat is CARRIED
 * (doc/btx-matmul-v4.4-tension-resolution.md §4.5). Orthogonal to the operand
 * ENCODING profile above: the encoding decides how header seeds become exact
 * integer operands; the commitment scheme decides where (if anywhere) the
 * 8·m² serialized sketch travels.
 */
enum class MatMulCommitmentScheme : uint8_t {
    //! Legacy v4.0-v4.2 carriage: the full 8·m²-byte serialized sketch rides
    //! in the block body (matrix_c_data) and validators Freivalds-verify it.
    //! v4.4: regtest vector-replay / differential-testing ONLY
    //! (fMatMulV4FlatSketchReplay); never activatable on a public network.
    FLAT_SKETCH_INBLOCK = 1,
    //! v4.4 ENC-DR ("digest-only, re-derivable", tension-resolution §4.1):
    //! ZERO consensus proof bytes. The block body's matrix_c_data MUST be
    //! empty; the header's matmul_digest = H(sigma||Chat_true) is the entire
    //! commitment, and a validator deterministically RECOMPUTES Chat_true from
    //! the header (exact check, epsilon = 0 — the CONSENSUS definition), or,
    //! when untrusted sketch-cache bytes authenticating as
    //! H(sigma||bytes) == matmul_digest are available, runs the v4.3
    //! Freivalds verifier over them (epsilon <= 2^-180 — an accept-side
    //! optimization deciding the identical predicate).
    DIGEST_RECOMPUTE = 2,
};

// ENC-BMX4C profile constants (consensus-normative; pinned by
// doc/btx-matmul-v4.2-bmx4c-spec.md §2.4/§3/§8.1, from
// doc/btx-matmul-v4.2-consolidated-design.md §2/§5 — the same source the
// src/matmul BMX4 implementation pins from; keep in sync). These are
// compile-time PROFILE DEFINITIONS, not per-network tunables: changing any of
// them defines a different encoding profile (a new hard fork with regenerated
// golden vectors), so they are deliberately not Params fields.
static constexpr uint32_t BMX4C_MANTISSA_ALPHABET_SIZE{11}; //!< |M11| = |{0,±1,±2,±3,±4,±6}| (exact-integer E2M1 subset; ±5/±0.5/±1.5/−0 never occur)
static constexpr int32_t BMX4C_MANTISSA_MAX{6};             //!< max |mu| over M11
static constexpr uint32_t BMX4C_SCALE_BLOCK_LENGTH{32};     //!< OCP MX block length L along the contraction dimension
static constexpr uint32_t BMX4C_SCALE_EXPONENT_MAX{3};      //!< e ∈ {0..S}, S = 3 (E8M0 codes 127..130); scales are powers of two ONLY (L0 rule)
static constexpr int32_t BMX4C_OPERAND_MAG_MAX{48};         //!< E_max = 6·2^3; ≤ 127 ⇒ every INT8 part runs ONE s8 GEMM on pre-shifted operands
static constexpr int64_t BMX4C_BASE_PRODUCT_BOUND_PER_N{2304};  //!< |C_ij| ≤ 2304·n = n·E_max² (< 2^24 at n = 4096: zero-promotion t=24 eligibility by bound)
static constexpr int64_t BMX4C_PROJECTION_BOUND_PER_N{288};     //!< |P|,|Q| ≤ 288·n = n·6·E_max (scale-free M11 U/V; < 2^21 at n = 4096)
static constexpr uint32_t BMX4C_COMBINE_LIMBS{4};           //!< C-13' fold digits per P/Q entry (16 limb-pair GEMMs)
static constexpr int32_t BMX4C_COMBINE_LIMB_BASE{64};       //!< balanced base-2^6 digits in [-32, 31], remainder-top rule (top digit ∈ [-32, +32])
static constexpr int64_t BMX4C_COMBINE_INPUT_BOUND{(int64_t{1} << 23) - 1}; //!< CheckCombineLimbBound successor pins 288·n ≤ 2^23-1 (⇔ n ≤ 29,127); pure-balanced coverage would end at 8,255,455 (n ≤ 28,664)
static constexpr int64_t BMX4C_LIMB_PAIR_BOUND_PER_N{1024}; //!< per-entry limb-pair GEMM bound n·32² (2^22 at n = 4096, 2^23 at n = 8192)
//! The CALIBRATED PRODUCTION sketch rank m = n/b for the ENC-S8 / ENC-BMX4C
//! profiles (tile kTileB = 4 at the mainnet n = 4096). The 8 MiB sketch payload
//! (8·m² bytes) AND the O(n²) verify DoS budget are calibrated for exactly this
//! rank. Design §0.3 requires m to STAY FIXED and b to track n (b -> 8 if n ->
//! 8192), NOT for n to silently raise m: growing m is what defines the separate
//! ENC-BMX4C-D profile (2·m = 2048, 32 MiB). AssertBMX4CConstructionInvariants
//! pins this: any nMatMulV4Dimension AT OR ABOVE production scale
//! (kTileB·BMX4C_SKETCH_RANK_M) must reduce to exactly this rank, so a future
//! dimension retarget not matched by a lockstep compile-time kTileB change fails
//! LOUD at startup instead of silently committing a different object. Small test
//! dimensions (regtest) sit below production scale and are exempt.
static constexpr uint32_t BMX4C_SKETCH_RANK_M{1024};
//! ENC-DR-LT Phase-A deep-m sketch rank (b=2 at n=4096). Under ENC-DR the
//! sketch is not carried on the wire, so deepening m is storage-free.
static constexpr uint32_t BMX4C_LT_SKETCH_RANK_M{2048};
// C-1' accumulator-eligibility anchors (consensus-PROTECTING, not
// consensus-changing: consumed by backend qualification/self-tests, never by
// block validation — doc/btx-matmul-v4.2-bmx4c-spec.md §5).
static constexpr uint32_t BMX4C_NATIVE_PATH_PROVEN_T{24};   //!< proven exact FP-mantissa accumulator bits required for the native block-scaled FP4/MX path; t≈14 fails closed to the 1-GEMM INT8 fallback
static constexpr uint32_t BMX4C_FALLBACK_INT8_ACCUMULATOR_BITS{32}; //!< C-1 floor for the INT8 fallback path (true two's-complement int32)

//! DR-34 FAIL-CLOSED ACTIVATION GATE (v4.4 ENC-DR normative spec §5, DR-34).
//! A public network (main/testnet/signet — regtest exempt) MUST NOT configure a
//! LIVE (non-INT32_MAX) `nMatMulV4Height` until BOTH activation gates are
//! recorded as passed IN THIS RELEASE:
//!   (1) the §K.2b silicon no-inversion measurement (GO/NO-GO), and
//!   (2) hard-fork ratification via the L0 amendment process.
//! This flag is the code-enforced record of that: it defaults to FALSE, and
//! `AssertBMX4CConstructionInvariants` aborts node startup if any public network
//! is built with a live v4 height while it is false. It is the same fail-closed
//! MECHANISM as the retired `BTX_MATMUL_SEGREGATED_PROOF_RELAY_READY` flag,
//! retargeted to the correct object (measured no-inversion + ratification, not
//! relay readiness). Flip to true ONLY in the deliberate, reviewed source change
//! of the release that ships activation, AFTER gates (1)-(2) are recorded.
static constexpr bool BTX_MATMUL_NO_INVERSION_GATE_RATIFIED{false};

/**
 * Per-profile MatMul v4 shape + carriage (consensus-normative; design §4.1 and
 * v4.4 tension-resolution §4.5). The single profile selector
 * GetMatMulEncodingProfile(height) chooses WHICH operand encoding is live;
 * GetMatMulProfileParams(height) wraps it and attaches the per-profile SHAPE
 * (tile b, production sketch rank m) and the COMMITMENT SCHEME (how the sketch
 * is carried), so every rank/tile/carriage call site reads the profile instead
 * of a single global constant (design §4.2). The shape values are the
 * CALIBRATED PRODUCTION constants (m at the mainnet n), not values recomputed
 * from a runtime dimension.
 *
 * v4.4 ENC-DR retires the STORAGE fields (sketch_payload_bytes /
 * proof_segregated): the 8·m² sketch is NEITHER an in-block payload NOR a
 * segregated stored proof — only H(sigma||Chat) rides in the header. The 8·m²
 * quantity survives ONLY as the size bound of the optional, non-consensus
 * sketch cache (SketchCacheBytes()).
 */
struct MatMulProfileParams {
    MatMulEncodingProfile profile;    //!< operand encoding: ENC_S8 | ENC_BMX4C (ENC_BMX4CD retired/reserved)
    MatMulCommitmentScheme commitment; //!< DIGEST_RECOMPUTE (v4.4 ENC-DR) | FLAT_SKETCH_INBLOCK (regtest replay only)
    uint32_t tile_b;                  //!< sketch tile b = 4. Mirrors matmul::v4::kTileB.
    uint32_t sketch_rank_m;           //!< production rank m = n / tile_b = 1024
    //! The 8·m² serialized-sketch size. NOT a consensus payload size under
    //! ENC-DR — it bounds (a) the legacy regtest-replay in-block payload and
    //! (b) the best-effort sketch-cache transport's serve/accept size cap
    //! (anti-amplification), tension-resolution §4.3.
    uint64_t SketchCacheBytes() const
    {
        return uint64_t{8} * sketch_rank_m * sketch_rank_m;
    }
};

/**
 * Parameters that influence chain consensus.
 */
struct Params {
    uint256 hashGenesisBlock;
    int nSubsidyHalvingInterval;
    /**
     * Hashes of blocks that
     * - are known to be consensus valid, and
     * - buried in the chain, and
     * - fail if the default script verify flags are applied.
     */
    std::map<uint256, uint32_t> script_flag_exceptions;
    /** Block height and hash at which BIP34 becomes active */
    int BIP34Height;
    uint256 BIP34Hash;
    /** Block height at which BIP65 becomes active */
    int BIP65Height;
    /** Block height at which BIP66 becomes active */
    int BIP66Height;
    /** Block height at which CSV (BIP68, BIP112 and BIP113) becomes active */
    int CSVHeight;
    /** Block height at which Segwit (BIP141, BIP143 and BIP147) becomes active.
     * Note that segwit v0 script rules are enforced on all blocks except the
     * BIP 16 exception blocks. */
    int SegwitHeight;
    /** Don't warn about unknown BIP 9 activations below this height.
     * This prevents us from warning about the CSV and segwit activations. */
    int MinBIP9WarningHeight;
    /**
     * Minimum blocks including miner confirmation of the total of 2016 blocks in a retargeting period,
     * (nPowTargetTimespan / nPowTargetSpacing) which is also used for BIP9 deployments.
     * Examples: 1916 for 95%, 1512 for testchains.
     */
    uint32_t nRuleChangeActivationThreshold;
    uint32_t nMinerConfirmationWindow;
    BIP9Deployment vDeployments[MAX_VERSION_BITS_DEPLOYMENTS];
    /** Proof of work parameters */
    uint256 powLimit;
    bool fPowAllowMinDifficultyBlocks;
    /**
      * Enforce BIP94 timewarp attack mitigation. On testnet4 this also enforces
      * the block storm mitigation.
      */
    bool enforce_BIP94;
    bool fPowNoRetargeting;
    bool fKAWPOW{false};
    bool fSkipKAWPOWValidation{false};
    int nKAWPOWHeight{std::numeric_limits<int>::max()};
    bool fReducedDataLimits{false};
    bool fEnforceP2MROnlyOutputs{false};
    unsigned int nMaxOpReturnBytes{83};
    unsigned int nMaxTxoutScriptPubKeyBytes{34};

    // MatMul PoW parameters.
    bool fMatMulPOW{false};
    bool fSkipMatMulValidation{false};
    uint32_t nMatMulDimension{512};
    uint32_t nMatMulTranscriptBlockSize{16};
    uint32_t nMatMulNoiseRank{8};
    uint32_t nMatMulMinDimension{64};
    uint32_t nMatMulMaxDimension{2048};
    uint32_t nMatMulFieldModulus{0x7FFFFFFFU};
    uint32_t nMatMulValidationWindow{1000};
    uint32_t nMatMulMaxPendingVerifications{16};
    uint32_t nMatMulPeerVerifyBudgetPerMin{32};
    /** WP-10 / C2 residual: BOUNDED per-peer expensive-verify budget floor used
     *  DURING IBD only. Historically IBD escalated the per-peer budget to
     *  200000/min, which effectively removed per-peer throttling during
     *  catch-up (only the shared global cap deferred), so a single peer bore no
     *  individual accountability. This floor applies ONLY to POST-fast-phase IBD
     *  (EffectiveMatMulPeerVerifyBudgetPerMin): fast-phase bootstrap keeps the
     *  full 200000 because every header there is phase-2-relevant. Post-fast-phase,
     *  deep history is assumevalid-skipped (0 checks) and only the unburied
     *  near-tip window charges — bounded by the assumevalid age (~2 weeks ~= ~13k
     *  blocks at production spacing), a one-time catch-up burst. 65536 covers that
     *  burst with ~5x margin (honest catch-up is never per-peer-throttled) while
     *  giving a concrete per-peer ceiling — a ~3x tightening from the old
     *  unconditional 200000. Note the expensive O(W) recompute is bounded
     *  separately (shared global 4/min for v4 + concurrency slots), so this
     *  header-check floor is not the expensive-DoS bound; combined with the
     *  already-landed defer-not-disconnect policy, exceeding it paces the peer
     *  rather than churning the connection. */
    uint32_t nMatMulIbdPeerVerifyBudgetPerMin{65536};
    uint32_t nMatMulPhase2FailBanThreshold{1};
    bool fMatMulStrictPunishment{false};
    uint32_t nMatMulSnapshotInterval{10'000};
    // Audit dead-code deletion: nMatMulProofPruneDepth removed. It was a leftover
    // from the deleted segregated-proof store with no consensus/validation reader;
    // under v4.4 ENC-DR the block carries ZERO proof bytes, so there is nothing to
    // prune. The -regtestmatmulproofprunedepth arg registration survives in
    // chainparamsbase.cpp as a harmless (unread) no-op for arg compatibility.
    /** Minimum equivalent-time age (seconds) an ENC-DR block must be buried under
     *  the best header before its digest-recompute PoW verification may be
     *  assumevalid-SKIPPED rather than recomputed (v4.4 tension-resolution §3.1-vi;
     *  validation.cpp ContextualCheckBlock). This is the SOLE bound on deep-history
     *  recompute cost for a default node's IBD: below the assumevalid block the
     *  identical trust ConnectBlock extends to buried scriptSigs is extended to the
     *  buried Chat recompute. Defaults to the 2-week equivalent-time DoS guard;
     *  regtest can shrink it via -regtestmatmulproofassumevalidminage so a
     *  functional test can exercise the trust boundary without mining ~13 000
     *  blocks. The trust ALSO requires an assumed-valid ancestor carrying >=
     *  MinimumChainWork of AUTHENTICATED work, so shrinking this alone never
     *  weakens a real network. (Retargeted by v4.4 ENC-DR from the deleted
     *  segregated-proof fetch+verify trust — the predicate is byte-for-byte the
     *  same; only its consequence changed.) */
    uint32_t nMatMulProofAssumeValidMinAge{60u * 60u * 24u * 7u * 2u};
    /** Pre-hash epsilon bits: sigma must satisfy target << N before a nonce reaches
     *  the expensive MatMul path. This makes the sigma gate 2^N easier than the
     *  final digest target before 256-bit saturation, but the absolute pass rate
     *  still depends on the active nBits target. */
    uint32_t nMatMulPreHashEpsilonBits{10};
    /** Optional future pre-hash epsilon upgrade. At this height and above, the
     *  sigma gate uses nMatMulPreHashEpsilonBitsUpgrade instead of the base
     *  nMatMulPreHashEpsilonBits value. */
    int32_t nMatMulPreHashEpsilonBitsUpgradeHeight{std::numeric_limits<int32_t>::max()};
    uint32_t nMatMulPreHashEpsilonBitsUpgrade{10};
    /** Height at which MatMul matrix seeds become nonce/header-bound. Legacy
     *  blocks use H(prev || height || which), allowing A/B reuse across nonce
     *  attempts. At and above this height, seeds commit to nonce, time, merkle,
     *  nBits, dimension, and version so every attempted header has a distinct
     *  matrix instance. */
    int32_t nMatMulNonceSeedHeight{std::numeric_limits<int32_t>::max()};
    /** Height at which nonce/header-bound MatMul seeds additionally commit to
     *  the parent median-time-past. This V3 seed rule must only be activated
     *  above already-mined history. */
    int32_t nMatMulParentMtpSeedHeight{std::numeric_limits<int32_t>::max()};
    /** Maximum Phase 2 verifications per minute across ALL peers combined.
     *  With n=512 each costs ~5ms, so 512/min ≈ 2.56s CPU/min. */
    uint32_t nMatMulGlobalVerifyBudgetPerMin{512};

    // Freivalds' algorithm verification parameters.
    // Verifiers use O(n^2) probabilistic verification via Freivalds' algorithm
    // as a fast product check. Full transcript recomputation can still be
    // required by a later upgrade to bind matmul_digest to the claimed work.
    bool fMatMulFreivaldsEnabled{true};
    /** Number of Freivalds' rounds per verification. Each round has false-positive
     *  probability 1/(2^31-1). With k=2 rounds, error < 2^-62. */
    uint32_t nMatMulFreivaldsRounds{2};
    /** Require blocks to carry the product matrix C' in their payload.
     *  When true, miners must include C' in the block payload.
     *  matmul_digest remains transcript-bound unless a separate digest
     *  commitment upgrade explicitly says otherwise. */
    bool fMatMulRequireProductPayload{true};
    /** Height at which Freivalds-verified blocks must also pass full
     *  transcript recomputation to bind matmul_digest to the claimed work. */
    int32_t nMatMulFreivaldsBindingHeight{std::numeric_limits<int32_t>::max()};
    /** Height at which the product-committed digest replaces the transcript
     *  digest.  Below this height the legacy transcript check remains
     *  authoritative.  Requires fMatMulFreivaldsEnabled and a non-empty
     *  matrix_c_data payload. */
    int32_t nMatMulProductDigestHeight{std::numeric_limits<int32_t>::max()};

    // MatMul v4 PoW parameters (see doc/btx-matmul-v4-design-spec.md, sections
    // G/H/I). v4 is a height-gated hard fork: at heights < nMatMulV4Height the
    // v3 rules above apply unchanged; at and above nMatMulV4Height, v4 rules
    // apply exclusively (no dual-algorithm grace period, no v3 fallback).
    // DEFAULT = INT32_MAX = disabled. Networks that have not explicitly set
    // this stay on v3 forever.
    int32_t nMatMulV4Height{std::numeric_limits<int32_t>::max()};
    /** Required v4 matrix dimension n (matmul_dim at and above nMatMulV4Height).
     *  Spec §0.7 normative launch parameter: 4096 on production nets. */
    uint32_t nMatMulV4Dimension{4096};
    /** v4 accepted-dimension bounds (spec §G.2/§G.4-#2): a v4 header's
     *  matmul_dim must satisfy nMatMulV4MinDimension <= matmul_dim <=
     *  nMatMulV4MaxDimension (and <= 65535, the uint16 header field). These are
     *  the height-selected replacements for the v3 nMatMul{Min,Max}Dimension
     *  bounds (v3 max 2048 is below the v4 default 4096, so bounds must be
     *  height-gated). Enforced structurally in ContextualCheckBlockHeader for
     *  v4 blocks, ahead of the exact nMatMulV4Dimension equality check. */
    uint32_t nMatMulV4MinDimension{4096};
    uint32_t nMatMulV4MaxDimension{8192};
    /** v4 Freivalds' rounds R over the independent prime q = 2^61-1 (spec
     *  §0.7-(2)/(D.3)). Normative: R = 3 (error <= 2^-180 for the default
     *  sketch payload); R = 2 is reserved for regtest only. */
    uint32_t nMatMulV4FreivaldsRounds{3};
    /** v4 product-commit/sketch tile size b; sketch dimension m = n/b (spec
     *  §0.7/§E.1/§K.2a/§K.2b). Normative: b = 4 at n = 4096 (m = 1024, payload
     *  8 MiB) — revised 8 -> 4 by the v4.1 batched-sketch profile (PR #89
     *  wall-time fix) so the enforced per-nonce INT8 tensor volume
     *  (~1.5*n^3 MACs incl. the C-13 limb combine) dominates wall-time on
     *  datacenter parts. If n is retargeted to 8192, b MUST become 8 (m stays
     *  1024). Keep in sync with matmul_v4::kTileB. */
    uint32_t nMatMulV4TranscriptBlockSize{4};
    /** One-time ASERT target rescale applied at nMatMulV4Height, mechanically
     *  identical to nMatMulAsertRetune2*: next_target = parent_target * Num/Den,
     *  then ASERT re-anchors on that block. The v4 per-nonce work unit differs
     *  sharply from v3 (dense INT8 GEMM vs. the v3 pre-hash-gated transcript),
     *  so attempts/s drops by a large hardware-dependent factor at the fork;
     *  this ratio must be calibrated empirically pre-release per network
     *  (spec §I.4). Default 1/1 = "no rescale" (fresh chains that bootstrap
     *  nBits directly for the v4 work unit leave this at 1/1). */
    int64_t nMatMulV4AsertRescaleNum{1};
    int64_t nMatMulV4AsertRescaleDen{1};
    /** v4 DoS verify budgets (spec §I.5): the O(n^2) sketch-Freivalds verify is
     *  far cheaper than the v3 transcript recomputation, but each check still
     *  costs ~0.14-0.28 s CPU at n=4096, so it stays bounded per-peer and
     *  globally. These are the height-selected replacements for the v3
     *  nMatMul{Global,Peer}VerifyBudgetPerMin fields (same rate-limit mechanism;
     *  only the value changes at and above nMatMulV4Height, spec §G.3/§H.4). */
    // DoS-F2 re-price: conservative default sized for the O(n^3) ENC-DR recompute
    // (~seconds/check), not the O(n^2) Freivalds fast path — honest block rate is
    // << 1/min so this leaves ample headroom while bounding attacker-forced
    // recompute CPU. Networks that set concrete values (testnet) match this;
    // pending the release-blocking on-hardware bench that may raise it.
    uint32_t nMatMulV4GlobalVerifyBudgetPerMin{4};
    uint32_t nMatMulV4PeerVerifyBudgetPerMin{2};

    // MatMul v4.2 / ENC-BMX4C encoding-profile parameters (see
    // doc/btx-matmul-v4.2-bmx4c-spec.md §7-§8 and
    // doc/btx-matmul-v4.2-consolidated-design.md). ENC-BMX4C is a
    // height-gated HARD FORK of the committed-operand ENCODING ONLY (L1):
    // at heights in [nMatMulV4Height, nMatMulBMX4CHeight) the ENC_S8 profile
    // applies; at and above nMatMulBMX4CHeight the ENC_BMX4C profile applies
    // exclusively (exactly one profile live at any height — no dual-profile
    // window). The verifier (q = 2^61-1, R = 3, b = 4, sketch payload,
    // digest, Fiat-Shamir) is byte-for-byte UNCHANGED across profiles.
    // DEFAULT = INT32_MAX = disabled: v4.2 is STAGED, parameter-frozen, and
    // NOT the current activation candidate; networks that never set this
    // stay on ENC-S8 forever. When set, the height MUST be strictly greater
    // than nMatMulV4Height, above every already-mined height at release, and
    // never lowered. Activation gates: ACTIVATION.md Gate C (M-t24 proven
    // t = 24 measurement on ≥ 2 vendors' frontier parts, joint v4.1+v4.2
    // C-15 external review, G-1 trigger confirmed on shipped silicon,
    // supermajority signaling).
    int32_t nMatMulBMX4CHeight{std::numeric_limits<int32_t>::max()};
    /** One-time ASERT target rescale + re-anchor at nMatMulBMX4CHeight,
     *  mechanically identical to nMatMulV4AsertRescale*: next_target =
     *  parent_target * Num/Den, then ASERT re-anchors on that block. The
     *  ENC-BMX4C marginal unit differs from ENC-S8's (~28% less XOF work;
     *  per-class GEMM rates shift), so this ratio MUST be calibrated
     *  empirically from the measured marginal nonce/s on the path rational
     *  miners actually run (ACTIVATION Gate C, B2b analogue). Default 1/1 =
     *  "no rescale" (only valid where measurement shows equal work units or
     *  the network has no pre-fork history). */
    int64_t nMatMulBMX4CAsertRescaleNum{1};
    int64_t nMatMulBMX4CAsertRescaleDen{1};
    /** v4.4-LT Rank-1 activation height (MatExpand + deep-m + Q*). DEFAULT =
     *  INT32_MAX = disabled on every public network until GO/NO-GO gates pass
     *  (doc/btx-matmul-v4.4-lt-normative-spec.md). When live, MUST be >=
     *  nMatMulBMX4CHeight (LT supersedes ENC-BMX4C at/above this height). */
    int32_t nMatMulDRLTHeight{std::numeric_limits<int32_t>::max()};
    /** Consensus-bound MatExpand window size Q* ∈ {128,256,512}. */
    uint32_t nMatMulConsensusQStar{256};
    /** LT tile b (deep-m). Normative Phase A: 2 (m = n/2). */
    uint32_t nMatMulLTTranscriptBlockSize{2};
    /** One-time ASERT rescale at nMatMulDRLTHeight (calibrate from silicon). */
    int64_t nMatMulDRLTAsertRescaleNum{1};
    int64_t nMatMulDRLTAsertRescaleDen{1};
    /** Resident Curriculum (ENC_RC) activation height. DEFAULT = INT32_MAX =
     *  disabled on every public network until a deliberate clean cutover.
     *  When live, GetMatMulEncodingProfile prefers ENC_RC over DRLT/BMX4C. */
    int32_t nMatMulRCHeight{std::numeric_limits<int32_t>::max()};
    /** One-time ASERT rescale at nMatMulRCHeight (calibrate from silicon). */
    int64_t nMatMulRCAsertRescaleNum{1};
    int64_t nMatMulRCAsertRescaleDen{1};
    /** REGTEST ONLY — when true, CheckMatMulProofOfWork_RC / SolveMatMulV4 ENC_RC
     *  use MakeToyRCEpisodeParams() instead of DefaultConsensusRCEpisodeParams().
     *  Public nets MUST keep this false (AssertBMX4CConstructionInvariants).
     *  Consensus dims (n_ctx=786432) are not CI-runnable; toy dims enable unit
     *  tests while production verify always uses the full episode when this is
     *  false and nMatMulRCHeight is live. */
    bool fMatMulRCUseToyDims{false};
    /** Coupled puzzle (ENC_RC_COUPLED) activation height. DEFAULT = INT32_MAX —
     *  disabled on every public network. Regtest may set a finite height to
     *  exercise CheckMatMulProofOfWork_RCCoupled / SolveMatMulV4RCCoupled.
     *  When live, GetMatMulEncodingProfile prefers ENC_RC_COUPLED over ENC_RC. */
    int32_t nMatMulRCCoupledHeight{std::numeric_limits<int32_t>::max()};
    /** REGTEST ONLY — when true, coupled checker/miner use MakeToyRCCoupParams()
     *  instead of MakeMediumRCCoupParams(). Public nets MUST keep this false. */
    bool fMatMulRCCoupledUseToyDims{false};
    /** RC tip-verify concurrency (pending full-episode recomputes). Default 1 --
     *  a single ~53T-MAC consensus episode must never share the EncDr/v4/LT
     *  pending counter or allow 16-way parallel recomputes. Cap is expressed in
     *  RC work units (see MatMulRCWorkUnits). INERT while nMatMulRCHeight ==
     *  INT32_MAX. Never raise without soak evidence. */
    uint32_t nMatMulRCMaxPendingVerifications{1};
    /** RC DoS verify budgets (global / per-peer), in complete tip-verification
     *  jobs per minute when IsMatMulRCActive. Effective helpers convert these
     *  to RC work units (MAC-scaled). Defaults admit one honest RC recompute
     *  per minute. INERT while RC is INT32_MAX. */
    uint32_t nMatMulRCGlobalVerifyBudgetPerMin{1};
    uint32_t nMatMulRCPeerVerifyBudgetPerMin{1};

    // --- ENC_RC §R.7 scheduled scaling (PARKED: kRCGrowthScheduleEnabled=false; also inert while nMatMulRCHeight==INT32_MAX) ---
    // All knobs below are owner-set / monetary-adjacent placeholders. Do NOT treat as final.
    // RCScaleForHeight (separate change) reads these; zero-filled tables must be replaced via
    // FillDefaultRCGrowthTables before any network that might ever activate ENC_RC.
    /** Blocks per scale epoch. ~90d at 144 blk/day (90s spacing). PROVISIONAL. */
    int32_t nRCScaleEpochBlocks{12960};
    /** ~10yr of quarterly epochs. Table length is consensus-pinned. */
    static constexpr size_t kRCGrowthTableLen = 40;
    /** Per-epoch Q16 multipliers (1.0 = 65536). Decaying geometric; PROVISIONAL.
     *  Defaults filled by FillDefaultRCGrowthTables (zero = misconfigured / no growth). */
    std::array<int64_t, kRCGrowthTableLen> nRCGrowthResTableQ16{};
    std::array<int64_t, kRCGrowthTableLen> nRCGrowthCapTableQ16{};
    /** Absolute ceiling on resident KV dial W_res (4 GiB). PROVISIONAL. */
    int64_t nRCScaleHardCapResBytes{1LL << 32};
    /** Absolute ceiling on activation dial W_cap (16 GiB). PROVISIONAL. */
    int64_t nRCScaleHardCapCapBytes{1LL << 34};
    /** One-sided brake: pause growth if closing-epoch work fell > this % vs trailing max.
     *  Pause-only — never accelerates or shrinks. PROVISIONAL. */
    int32_t nRCBrakeDeltaPct{20};
    /** v4.4-LT Q* Phase B — SEAL-AS-PoW mode (doc/btx-matmul-v4.4-lt-normative-spec.md
     *  "Q* window", doc/btx-matmul-v4.4-lt-adversarial-analysis.md "Phase B").
     *  When true AND DRLT is live, the header's matmul_digest is no longer the
     *  per-nonce ENC-DR-LT digest but the WINDOW SEAL
     *    matmul_digest := SealWindowCommit(sigma_anchor, Merkle(slot digests), Q*)
     *  binding a full Q* window of sibling-nonce ENC-DR-LT digests into a single
     *  consensus-bound lottery object (fat-window PoW; adversarial LT-Q1/LT-Q2).
     *  DEFAULT = false and, independently, INERT on every public network because
     *  IsMatMulLTSealAsPoWActive requires IsDRLTActive, which is fail-closed while
     *  nMatMulDRLTHeight == INT32_MAX. Regtest enables this by default for
     *  functional coverage and permits an explicit Phase-A override.
     *  This is a MODE toggle of the already-height-gated LT profile, NOT a second
     *  activation height: it never widens the surface that is live on a public
     *  net (that stays gated by nMatMulDRLTHeight == INT32_MAX). */
    bool fMatMulLTSealAsPoW{false};
    /** LT tip-verify concurrency (pending EncDr / seal recomputes). Height-
     *  selected by EffectiveMatMulMaxPendingVerifications when IsDRLTActive.
     *  Default 2 — tighter than nMatMulMaxPendingVerifications because a Phase B
     *  seal recompute is ~Q* sibling EncDr digests. INERT while
     *  nMatMulDRLTHeight == INT32_MAX. Regtest may raise via params. */
    uint32_t nMatMulLTMaxPendingVerifications{2};
    /** LT DoS verify budgets (global / per-peer), in complete tip-verification
     *  jobs per minute, when IsDRLTActive. Effective helpers convert these to
     *  leaf work units (multiplying by Q*) while seal-as-PoW is live. Sized for
     *  tip-verify of fat EncDr-LT / seal-as-PoW recomputes (honest rate << 1/min).
     *  Defaults are conservative placeholders pending on-hardware soak; never
     *  raise a public DRLT height until calibrated. INERT while DRLT is
     *  INT32_MAX. Regtest defaults to UINT32_MAX (unthrottled). */
    uint32_t nMatMulLTGlobalVerifyBudgetPerMin{1};
    uint32_t nMatMulLTPeerVerifyBudgetPerMin{1};
    /** v4.4 ENC-DR regtest-only DIFFERENTIAL-TESTING switch: when true, v4
     *  heights keep the legacy FLAT_SKETCH_INBLOCK carriage (the full 8·m²
     *  sketch in matrix_c_data, Freivalds-verified in-block) instead of the
     *  ENC-DR DIGEST_RECOMPUTE carriage. Exists ONLY so golden-vector replay
     *  and differential tests can exercise the retired carriage against the
     *  recompute path (tension-resolution §5-2); NEVER settable on a public
     *  network (AssertBMX4CConstructionInvariants fails closed). */
    bool fMatMulV4FlatSketchReplay{false};
    /** MatMul v4 header-PoW throttle (audit F1/C1/C2, doc/btx-matmul-v4.2-header-pow-gate.md).
     *  At v4 heights the ONLY header-level PoW check is `matmul_digest <= target`,
     *  but `matmul_digest` is a self-declared header field, not a hash of the
     *  header -- so an attacker can forge headers claiming arbitrary work at zero
     *  cost (set digest = 0) and flood header sync (best-header poisoning / stall).
     *  The throttle requires H(GetHash() || spam_nonce) <= (block_target <<
     *  nMatMulHeaderPoWDiscountBits), where spam_nonce is a header field DECOUPLED
     *  from the matmul preimage (so an honest miner grinds it WITHOUT recomputing
     *  the expensive matmul).
     *
     *  BOUND TO nBits, NOT A FIXED COST (audit C2): the throttle target is the
     *  block's OWN difficulty target (from nBits) shifted EASIER by the discount,
     *  so the header hash-work an attacker must pay to forge a header is
     *  PROPORTIONAL to the chainwork that header claims (~ D / 2^discount hashes for
     *  claimed difficulty D) -- a fixed target would let an attacker pay one easy
     *  grind while claiming arbitrary ASERT-derived chainwork. smaller discount =
     *  stronger throttle; honest overhead stays negligible because SHA256d is vastly
     *  cheaper than a matmul eval.
     *
     *  NOT full authentication (audit C1, OPEN): a SHA-based header PoW cannot
     *  *authenticate* matmul-calibrated chainwork -- SHA is ~10^7x cheaper than a
     *  matmul eval, so an attacker can still out-hash the honest matmul rate in SHA.
     *  This is a rate-limiting THROTTLE, not a chainwork proof. Closing C1 requires
     *  a header-verifiable matmul-work proof bound to nBits, or a chain-selection
     *  redesign that does not credit matmul chainwork until the body is verified --
     *  an architectural change tracked in the header-pow-gate doc.
     *
     *  SINGLE ACTIVATION: rides the v4 fork (IsMatMulV4Active), no height of its own.
     *  UINT32_MAX = disabled sentinel (default). The bit-26 self-describing
     *  HeaderPoW wire (nNonce on wire / in GetHash) was WITHDRAWN — headers stay
     *  182 bytes. Enabling this discount on public nets is a hard NO-GO until a
     *  height-contextual wire design lands. */
    uint32_t nMatMulHeaderPoWDiscountBits{std::numeric_limits<uint32_t>::max()};
    /** C-1' accumulator-eligibility qualification threshold (consensus-
     *  PROTECTING, not consensus-changing): the minimum PROVEN exact
     *  FP-mantissa accumulator width t (in bits, 2^t exact-integer capacity)
     *  a backend must demonstrate via the §5.3 adversarial vectors before it
     *  may claim the native block-scaled FP4/MX path. Consumed by backend
     *  qualification/self-test harnesses only — block validation never reads
     *  it. A device that cannot prove t fails closed down the fallback
     *  ladder (FP8 fold → 1-GEMM INT8 → mantissa-plane → CPU), never off
     *  the network and never able to split the chain (the dispatcher
     *  re-verifies every device result). */
    uint32_t nMatMulBMX4CMinProvenAccumulatorBits{BMX4C_NATIVE_PATH_PROVEN_T};
    uint32_t nMaxReorgDepth{std::numeric_limits<uint32_t>::max()};
    int32_t nReorgProtectionStartHeight{std::numeric_limits<int32_t>::max()};

    // Monetary policy.
    CAmount nMaxMoney{21'000'000 * COIN};
    CAmount nInitialSubsidy{20 * COIN};
    /** Height-gated empty-block economics. At and above this height,
     * consecutive coinbase-only blocks claim a halved subsidy, up to the
     * configured maximum number of halvings. This is deterministic from
     * block/chain data and intentionally ignores mempool contents. */
    int32_t nEmptyBlockSubsidyPenaltyHeight{std::numeric_limits<int32_t>::max()};
    /** v0.32.10 explicit schedule height. At and above this height,
     * coinbase-only blocks are capped at base/2 after a non-empty block and
     * base/4 after another empty block. */
    int32_t nEmptyBlockSubsidyStrictPenaltyHeight{std::numeric_limits<int32_t>::max()};
    /** v0.32.11 forward-only rollback height. At and above this height,
     * coinbase-only blocks receive the normal subsidy again. */
    int32_t nEmptyBlockSubsidyPenaltyEndHeight{std::numeric_limits<int32_t>::max()};
    uint32_t nEmptyBlockSubsidyMaxHalvings{2};

    // Target spacing schedule.
    int64_t nPowTargetSpacingNormal{90};
    int64_t nPowTargetSpacingFastMs{250};
    uint32_t nFastMineDifficultyScale{1};
    int32_t nFastMineHeight{61'000};
    // LEGACY DGW height gates -- NOT used for MatMul mining. DGW was
    // deliberately replaced by ASERT for all MatMul difficulty adjustment.
    // These fields are retained only for KAWPOW-era compatibility and must
    // remain at max() for all MatMul networks. Do not re-enable DGW for
    // MatMul without explicit project approval.
    int32_t nDgwAsymmetricClampHeight{std::numeric_limits<int32_t>::max()};
    int32_t nDgwEasingBoostHeight{std::numeric_limits<int32_t>::max()};
    int32_t nDgwWindowAlignmentHeight{std::numeric_limits<int32_t>::max()};
    int32_t nDgwSlewGuardHeight{std::numeric_limits<int32_t>::max()};
    // Height at which ASERT activates for MatMul mining. This MUST equal
    // nFastMineHeight so that ASERT governs difficulty from the first
    // post-bootstrap block onward. Do not change without project approval.
    int32_t nMatMulAsertHeight{std::numeric_limits<int32_t>::max()};
    // ASERT half-life in seconds (consensus-critical when ASERT is active).
    int64_t nMatMulAsertHalfLife{14'400};
    // One-time ASERT activation bootstrap multiplier applied to parent target at
    // nMatMulAsertHeight. Values >1 ease difficulty immediately at activation.
    uint32_t nMatMulAsertBootstrapFactor{1};
    // Optional one-time ASERT retune height. At this height, target can be
    // hardened by nMatMulAsertRetuneHardeningFactor to quickly recenter
    // cadence after bootstrap/ops-era drift.
    int32_t nMatMulAsertRetuneHeight{std::numeric_limits<int32_t>::max()};
    // Retune hardening factor applied at nMatMulAsertRetuneHeight:
    // next_target = parent_target / factor (factor>=1).
    uint32_t nMatMulAsertRetuneHardeningFactor{1};
    // Optional one-time ASERT recenter retune. At this height the next target
    // is scaled by (num/den) from the parent target, then ASERT re-anchors on
    // that block to preserve the recentered baseline.
    int32_t nMatMulAsertRetune2Height{std::numeric_limits<int32_t>::max()};
    uint32_t nMatMulAsertRetune2TargetNum{1};
    uint32_t nMatMulAsertRetune2TargetDen{1};
    // Optional future ASERT half-life upgrade. At this height the target is
    // inherited from the parent unchanged, then ASERT re-anchors on that block
    // and uses nMatMulAsertHalfLifeUpgrade for subsequent retargeting.
    int32_t nMatMulAsertHalfLifeUpgradeHeight{std::numeric_limits<int32_t>::max()};
    int64_t nMatMulAsertHalfLifeUpgrade{14'400};
    // Optional MatMul timestamp hardening. At and above this height, blocks
    // may not be more than nMatMulMaxFutureMtpDrift seconds ahead of the
    // previous block's median-time-past. This bounds ASERT's response to a
    // single future-dated block without changing the ASERT formula itself.
    int32_t nMatMulMaxFutureMtpDriftHeight{std::numeric_limits<int32_t>::max()};
    int64_t nMatMulMaxFutureMtpDrift{3'600};
    // a5 fix: at/above this height the future-MTP-drift upper bound is reconciled with the
    // BIP94 timewarp lower bound -- the upper bound is never allowed below
    // (prev_block_time - MAX_TIMEWARP). Without this, at a drift-cap activation boundary an
    // unprotected predecessor's high timestamp can push the lower bound above the upper bound,
    // leaving NO legal timestamp and wedging the chain (liveness halt). The reconciliation only
    // ever RAISES the upper bound (a relaxation confined to otherwise-unmineable blocks), so it
    // is flag-day gated to keep upgraded/non-upgraded nodes in agreement until activation.
    int32_t nMatMulTimewarpReconcileHeight{std::numeric_limits<int32_t>::max()};
    // Block capacity.
    uint32_t nMaxBlockWeight{24'000'000};
    uint32_t nMaxBlockSerializedSize{24'000'000};
    uint32_t nMaxBlockSigOpsCost{480'000};
    uint32_t nDefaultBlockMaxWeight{24'000'000};
    uint32_t nDefaultMempoolMaxSizeMB{2048};

    // Shielded pool consensus limits.
    uint32_t nMaxShieldedTxSize{6'500'000};
    uint32_t nMaxShieldedRingSize{32};
    uint32_t nShieldedMerkleTreeDepth{32};
    int32_t nShieldedPoolActivationHeight{0};
    int32_t nShieldedTxBindingActivationHeight{std::numeric_limits<int32_t>::max()};
    int32_t nShieldedBridgeTagActivationHeight{std::numeric_limits<int32_t>::max()};
    int32_t nShieldedSmileRiceCodecDisableHeight{std::numeric_limits<int32_t>::max()};
    int32_t nShieldedMatRiCTDisableHeight{std::numeric_limits<int32_t>::max()};
    int32_t nShieldedSpendPathRecoveryActivationHeight{std::numeric_limits<int32_t>::max()};
    /** C-002 shielded proof + SLH-DSA/FIPS-205 activation height. Mainnet default
     *  remains 123,000; regtest may lower this to exercise boundary behavior
     *  without mining 123k blocks. Keep the default in sync with
     *  smile2::SmileCTProof::C002_ACTIVATION_HEIGHT, which low-level proof
     *  helpers use when consensus params are unavailable. */
    int32_t nShieldedC002ActivationHeight{123'000};
    int32_t nShieldedPQ128UpgradeHeight{std::numeric_limits<int32_t>::max()};
    int32_t nShieldedPoolCreditDisableHeight{std::numeric_limits<int32_t>::max()};
    int32_t nShieldedSunsetHeight{std::numeric_limits<int32_t>::max()};
    /** Disable proofless transparent-funded V2_SEND public-flow shielding. This is
     *  deliberately separate from the 125,000 shielded sunset so upgraded nodes can
     *  enforce the mempool/template hardening immediately from the 128,000 cleanup
     *  boundary without retroactively changing the 125,000..127,999 history. */
    int32_t nShieldedDirectSendPublicFlowDisableHeight{std::numeric_limits<int32_t>::max()};
    /** Post-sunset zero-output V2_SEND z->t exit activation. Disabled by default
     *  so the decode compatibility fix can ship before a later consensus
     *  activation height permits these transactions once the sunset rules are
     *  active. Pre-sunset V2_SEND unshields remain governed by the existing
     *  C-002 rules. */
    int32_t nShieldedV2SendZeroOutputExitActivationHeight{std::numeric_limits<int32_t>::max()};
    /** RECOVERY_EXIT activation (transparent-claim stranded-note recovery). DISABLED by default
     *  (int32 max) for regtest unless explicitly overridden. Production networks activate it at the
     *  125,000 sunset only after strict zero-output sunset gating, mempool commitment/nullifier
     *  reservation, and block-level atomic dual retirement are present. Must be >= nShieldedSunsetHeight
     *  when set.
     *  See doc/recovery_exit_125000_spec.md. */
    int32_t nShieldedRecoveryExitActivationHeight{std::numeric_limits<int32_t>::max()};
    /** RECOVERY_EXIT membership anchor: the consensus-PINNED shielded note-commitment tree root of the
     *  frozen 125,000 ceiling when known at release time. A recovery claim's Merkle witness must
     *  authenticate the spent commitment against this root, or against the immutable live tree root after
     *  the sunset zero-output rule has frozen the tree. Null therefore means "use the live frozen root"
     *  only once the sunset is active; before then it fails closed. Regtest may set it via override. */
    uint256 nShieldedRecoveryExitFrozenRoot{};
    uint32_t nShieldedSettlementAnchorMaturity{6};
    int32_t nMLDSADisableHeight{std::numeric_limits<int32_t>::max()};
    /** Maximum shielded verification cost units per block (consensus rule).
     *  SMILE v2: Each spend costs ~100 units; each output ~15 units.
     *  Budget: 1042 × 230 = 240,000. Size (24MB) is the binding constraint.
     *  CPU: 1042 × 3.5ms = 3.6s (4% of 90s block, single core). */
    uint64_t nMaxBlockShieldedVerifyCost{DEFAULT_MAX_BLOCK_SHIELDED_VERIFY_COST};
    /** Maximum wallet-facing shielded discovery units per block.
     *  Calibrated to allow one large batched egress while keeping scan pressure bounded. */
    uint64_t nMaxBlockShieldedScanUnits{DEFAULT_MAX_BLOCK_SHIELDED_SCAN_UNITS};
    /** Maximum shielded state-mutation units per block (nullifiers + commitments). */
    uint64_t nMaxBlockShieldedTreeUpdateUnits{DEFAULT_MAX_BLOCK_SHIELDED_TREE_UPDATE_UNITS};
    /** Maximum shielded account-registry appends per block after the MatRiCT disable fork. */
    uint64_t nMaxBlockShieldedAccountRegistryAppends{
        DEFAULT_MAX_BLOCK_SHIELDED_ACCOUNT_REGISTRY_APPENDS};
    /** Maximum total shielded account-registry entries after the MatRiCT disable fork. */
    uint64_t nMaxShieldedAccountRegistryEntries{
        DEFAULT_MAX_SHIELDED_ACCOUNT_REGISTRY_ENTRIES};

    /** Shielded-pool unshield (z->t egress) velocity cap. Defense-in-depth on top of the turnstile
     *  (net-supply firewall) and the C-002 value-conservation binding (per-tx soundness): bounds how
     *  fast value can leave the pool, so a stolen spend key or a future soundness regression becomes a
     *  slow, observable leak rather than an instant drain. Consensus rule: a block is invalid if the
     *  total net unshield value over the trailing window exceeds nShieldedUnshieldVelocityCapBps basis
     *  points of the shielded pool balance at the window start. Inert until the activation height
     *  (fast-follow after C-002); self-serve unshield does not exist before C-002 anyway. */
    int32_t nShieldedUnshieldVelocityActivationHeight{std::numeric_limits<int32_t>::max()};
    /** Trailing window length in blocks over which net unshield value is summed. */
    uint32_t nShieldedUnshieldVelocityWindowBlocks{960}; // ~1 day at 90s spacing
    /** Cap as basis points (1/10000) of the pool balance at window start. 5000 bps = 50% per ~1-day
     *  window: aligned to the 125,000 sunset (active from the first exit-only block) but loosened from
     *  the original 10% so a legitimate large legacy holder can fully exit in ~1 week rather than ~3+
     *  weeks, while still throttling any residual drain to half the pool per day. */
    uint32_t nShieldedUnshieldVelocityCapBps{5000};
    /** Height at which the unshield velocity cap stops applying. */
    int32_t nShieldedUnshieldVelocityEndHeight{std::numeric_limits<int32_t>::max()};
    /** Height at which the v0.32.11 velocity-cap floor starts applying. */
    int32_t nShieldedUnshieldVelocityMinCapHeight{std::numeric_limits<int32_t>::max()};
    /** Minimum egress capacity per trailing window after nShieldedUnshieldVelocityMinCapHeight. */
    CAmount nShieldedUnshieldVelocityMinCap{0};
    bool IsShieldedUnshieldVelocityCapActive(int32_t height) const
    {
        return nShieldedUnshieldVelocityActivationHeight != std::numeric_limits<int32_t>::max() &&
               height >= nShieldedUnshieldVelocityActivationHeight &&
               height < nShieldedUnshieldVelocityEndHeight;
    }
    CAmount ShieldedUnshieldVelocityMinCapForHeight(int32_t height) const
    {
        if (!IsShieldedUnshieldVelocityCapActive(height)) return 0;
        if (height < nShieldedUnshieldVelocityMinCapHeight) return 0;
        return nShieldedUnshieldVelocityMinCap;
    }

    int64_t nPowTargetSpacing;
    int64_t nPowTargetTimespan;
    std::chrono::seconds PowTargetSpacing() const
    {
        return std::chrono::seconds{nPowTargetSpacing};
    }
    int64_t DifficultyAdjustmentInterval() const { return nPowTargetTimespan / nPowTargetSpacing; }
    double GetTargetSpacing(int32_t height) const
    {
        if (height < nFastMineHeight) {
            return static_cast<double>(nPowTargetSpacingFastMs) / 1000.0;
        }
        return static_cast<double>(nPowTargetSpacingNormal);
    }
    bool IsMatMulFreivaldsBindingActive(int32_t height) const
    {
        return fMatMulFreivaldsEnabled &&
            height >= 0 &&
            nMatMulFreivaldsBindingHeight != std::numeric_limits<int32_t>::max() &&
            height >= nMatMulFreivaldsBindingHeight;
    }
    bool IsMatMulProductDigestActive(int32_t height) const
    {
        return fMatMulFreivaldsEnabled &&
            height >= 0 &&
            nMatMulProductDigestHeight != std::numeric_limits<int32_t>::max() &&
            height >= nMatMulProductDigestHeight;
    }
    bool IsMatMulProductPayloadRequired(int32_t height) const
    {
        return fMatMulFreivaldsEnabled &&
            (fMatMulRequireProductPayload || IsMatMulProductDigestActive(height));
    }
    /** True at and above the v4 height-gated hard fork. When true, v4 rules
     *  apply exclusively for PoW validation, difficulty work-unit accounting,
     *  and mining (see pow.cpp/validation.cpp v4 dispatch); the v3 fields
     *  above (nMatMulDimension, nMatMulNoiseRank, nMatMulFreivaldsRounds,
     *  the pre-hash epsilon gate, etc.) are retired/ignored for this height
     *  and only consulted for < nMatMulV4Height (spec §G.3). */
    bool IsMatMulV4Active(int32_t height) const
    {
        // Self-guard the disabled sentinel exactly as IsBMX4CActive/IsDRLTActive do:
        // without this, IsMatMulV4Active(INT32_MAX) returns true on a disabled network
        // (INT32_MAX >= INT32_MAX), so a sentinel/"unknown" height would be treated as
        // v4-active. Real block heights never approach INT32_MAX, so this is byte-
        // identical for every real height; it just moves the guard callers hand-write
        // (IsDisabledHeight / != INT32_MAX) into the predicate itself.
        return height >= 0 &&
               nMatMulV4Height != std::numeric_limits<int32_t>::max() &&
               height >= nMatMulV4Height;
    }
    /** True at and above the v4.2 ENC-BMX4C encoding-profile hard fork.
     *  Mirrors IsMatMulV4Active; additionally requires v4 to be active,
     *  since ENC-BMX4C is a profile of the v4 machine (it re-versions the
     *  operand encoding only; the v4 verifier/payload/digest machinery is
     *  unchanged, doc/btx-matmul-v4.2-bmx4c-spec.md §0.3/§7.3). When true,
     *  operand/projector derivation, domain tags, magnitude constants, limb
     *  reference, golden vectors, and the one-time ASERT rescale follow
     *  ENC-BMX4C exclusively. */
    bool IsBMX4CActive(int32_t height) const
    {
        return IsMatMulV4Active(height) &&
            nMatMulBMX4CHeight != std::numeric_limits<int32_t>::max() &&
            height >= nMatMulBMX4CHeight;
    }
    /** True at and above the v4.4-LT Rank-1 package height (MatExpand + deep-m
     *  + Q*). Requires BMX4C to already be active; LT supersedes ENC-BMX4C. */
    bool IsDRLTActive(int32_t height) const
    {
        return IsBMX4CActive(height) &&
            nMatMulDRLTHeight != std::numeric_limits<int32_t>::max() &&
            height >= nMatMulDRLTHeight;
    }
    /** True at and above the Resident Curriculum (ENC_RC) height. Requires the
     *  MatMul v4 PoW path (IsMatMulV4Active) so RC only runs inside the MatMul
     *  cascade. Self-guards the INT32_MAX disabled sentinel. Public nets keep
     *  nMatMulRCHeight = INT32_MAX until a deliberate clean cutover. */
    bool IsMatMulRCActive(int32_t height) const
    {
        return IsMatMulV4Active(height)
            && nMatMulRCHeight != std::numeric_limits<int32_t>::max()
            && height >= nMatMulRCHeight;
    }
    /** True at and above the coupled-puzzle (ENC_RC_COUPLED) height. Requires
     *  MatMul v4. Self-guards INT32_MAX. Public nets keep
     *  nMatMulRCCoupledHeight = INT32_MAX (AssertBMX4CConstructionInvariants).
     *  Regtest enables via an explicit finite height (optionally with
     *  fMatMulRCCoupledUseToyDims for CI-scale dims). */
    bool IsMatMulRCCoupledActive(int32_t height) const
    {
        return IsMatMulV4Active(height)
            && nMatMulRCCoupledHeight != std::numeric_limits<int32_t>::max()
            && height >= nMatMulRCCoupledHeight;
    }
    /** True iff the v4.4-LT Q* Phase B SEAL-AS-PoW mode governs this height: the
     *  LT profile is live AND the seal-as-PoW mode toggle is set. Fail-closed on
     *  every public network: IsDRLTActive is false while nMatMulDRLTHeight ==
     *  INT32_MAX, so seal mode can only ever engage on a network that has BOTH
     *  configured a live LT height (still blocked by the no-inversion +
     *  ratification gate in AssertBMX4CConstructionInvariants) AND flipped the
     *  mode toggle. When false the LT lottery object is the Phase A per-nonce
     *  ENC-DR-LT digest H(sigma||Chat); when true it is the window seal. */
    bool IsMatMulLTSealAsPoWActive(int32_t height) const
    {
        return IsDRLTActive(height) && fMatMulLTSealAsPoW;
    }
    /** Header-PoW throttle (audit F1/C1/C2) is enabled iff a discount is configured;
     *  it has NO separate activation height -- it rides the single v4 fork (see
     *  nMatMulHeaderPoWDiscountBits). Callers gate on IsMatMulV4Active(height) &&
     *  IsMatMulHeaderPoWEnabled(). Default disabled (discount == UINT32_MAX). */
    bool IsMatMulHeaderPoWEnabled() const
    {
        return nMatMulHeaderPoWDiscountBits != std::numeric_limits<uint32_t>::max();
    }
    /** AUDIT H2: the ONLY valid configured discount range is 0..255. UINT32_MAX
     *  is reserved EXCLUSIVELY for "disabled". Any value in [256, UINT32_MAX-1]
     *  is a configuration error: a discount >= 256 would drive the throttle
     *  target to powLimit regardless of nBits, recreating the fixed-cost C2 gate
     *  that the nBits binding was introduced to remove. Such values must be
     *  rejected at chain-parameter construction (fatal startup, see
     *  AssertBMX4CConstructionInvariants) rather than silently clamped, and are
     *  additionally fail-closed at runtime in CheckMatMulHeaderSpamGate. */
    static constexpr uint32_t MATMUL_HEADER_POW_MAX_DISCOUNT_BITS{255};
    bool IsMatMulHeaderPoWDiscountValid() const
    {
        return nMatMulHeaderPoWDiscountBits <= MATMUL_HEADER_POW_MAX_DISCOUNT_BITS ||
               nMatMulHeaderPoWDiscountBits == std::numeric_limits<uint32_t>::max();
    }
    /** The committed-operand encoding profile live at this height. Only
     *  meaningful at v4 heights (below nMatMulV4Height the v3 rules apply
     *  and no profile is defined; callers dispatch on IsMatMulV4Active
     *  first). This is the SINGLE profile selector: every profile-dependent
     *  call site (seed derivation, operand/projector expansion, payload
     *  magnitude bounds, limb-combine reference, golden-vector selection)
     *  takes its profile from here and performs no second height compare
     *  (spec §8.2). */
    MatMulEncodingProfile GetMatMulEncodingProfile(int32_t height) const
    {
        // ENC_RC_COUPLED takes precedence over ENC_RC (structural successor).
        // Public nets keep both heights at INT32_MAX.
        if (IsMatMulRCCoupledActive(height)) return MatMulEncodingProfile::ENC_RC_COUPLED;
        // ENC_RC takes precedence over DRLT/BMX4C when live.
        if (IsMatMulRCActive(height)) return MatMulEncodingProfile::ENC_RC;
        if (IsDRLTActive(height)) return MatMulEncodingProfile::ENC_BMX4C_LT;
        return IsBMX4CActive(height) ? MatMulEncodingProfile::ENC_BMX4C
                                     : MatMulEncodingProfile::ENC_S8;
    }
    /** The per-profile SHAPE + CARRIAGE (design §4.1; v4.4 tension-resolution
     *  §4.5) live at this height: wraps GetMatMulEncodingProfile and attaches
     *  the profile's tile b, production sketch rank m, and the commitment
     *  scheme. Every rank/tile/carriage call site (validator dispatch, miner
     *  payload handling, sketch-cache size caps, per-profile construction
     *  assert) reads the shape from HERE rather than from a single global
     *  constant (design §4.2). Under v4.4 ENC-DR the carriage at every v4
     *  height is DIGEST_RECOMPUTE (zero consensus proof bytes); the
     *  FLAT_SKETCH_INBLOCK carriage survives only behind the regtest-only
     *  fMatMulV4FlatSketchReplay differential-testing switch. */
    MatMulProfileParams GetMatMulProfileParams(int32_t height) const
    {
        if (IsMatMulRCCoupledActive(height)) {
            // ENC_RC_COUPLED is digest-only (DIGEST_RECOMPUTE). No Freivalds sketch.
            return MatMulProfileParams{
                MatMulEncodingProfile::ENC_RC_COUPLED,
                MatMulCommitmentScheme::DIGEST_RECOMPUTE,
                /*tile_b=*/nMatMulLTTranscriptBlockSize,
                /*sketch_rank_m=*/BMX4C_LT_SKETCH_RANK_M,
            };
        }
        if (IsMatMulRCActive(height)) {
            // ENC_RC is digest-only (DIGEST_RECOMPUTE). tile_b / sketch_rank_m
            // are placeholders reused from LT until RC-specific shape knobs land;
            // RC episodes do not carry a Freivalds sketch.
            return MatMulProfileParams{
                MatMulEncodingProfile::ENC_RC,
                MatMulCommitmentScheme::DIGEST_RECOMPUTE,
                /*tile_b=*/nMatMulLTTranscriptBlockSize,
                /*sketch_rank_m=*/BMX4C_LT_SKETCH_RANK_M,
            };
        }
        if (IsDRLTActive(height)) {
            return MatMulProfileParams{
                MatMulEncodingProfile::ENC_BMX4C_LT,
                fMatMulV4FlatSketchReplay ? MatMulCommitmentScheme::FLAT_SKETCH_INBLOCK
                                          : MatMulCommitmentScheme::DIGEST_RECOMPUTE,
                /*tile_b=*/nMatMulLTTranscriptBlockSize,
                /*sketch_rank_m=*/BMX4C_LT_SKETCH_RANK_M,
            };
        }
        return MatMulProfileParams{
            GetMatMulEncodingProfile(height),
            fMatMulV4FlatSketchReplay ? MatMulCommitmentScheme::FLAT_SKETCH_INBLOCK
                                      : MatMulCommitmentScheme::DIGEST_RECOMPUTE,
            /*tile_b=*/4,
            /*sketch_rank_m=*/BMX4C_SKETCH_RANK_M,
        };
    }
    /** True iff v4.4 ENC-DR digest-only carriage governs this height: v4 is
     *  active and the regtest replay switch has not re-selected the legacy
     *  in-block carriage. The consensus predicate at ENC-DR heights is a pure
     *  function of the header (tension-resolution §4.1). */
    bool IsMatMulEncDrActive(int32_t height) const
    {
        return IsMatMulV4Active(height) && !fMatMulV4FlatSketchReplay;
    }
    bool IsMatMulPreHashEpsilonBitsUpgradeActive(int32_t height) const
    {
        return height >= 0 &&
            nMatMulPreHashEpsilonBitsUpgradeHeight != std::numeric_limits<int32_t>::max() &&
            height >= nMatMulPreHashEpsilonBitsUpgradeHeight;
    }
    bool IsMatMulNonceSeedActive(int32_t height) const
    {
        return fMatMulPOW &&
            height >= 0 &&
            nMatMulNonceSeedHeight != std::numeric_limits<int32_t>::max() &&
            height >= nMatMulNonceSeedHeight;
    }
    bool IsMatMulParentMtpSeedActive(int32_t height) const
    {
        return fMatMulPOW &&
            height >= 0 &&
            nMatMulParentMtpSeedHeight != std::numeric_limits<int32_t>::max() &&
            height >= nMatMulParentMtpSeedHeight;
    }
    bool IsMatMulMaxFutureMtpDriftActive(int32_t height) const
    {
        return fMatMulPOW &&
            height >= 0 &&
            nMatMulMaxFutureMtpDriftHeight != std::numeric_limits<int32_t>::max() &&
            height >= nMatMulMaxFutureMtpDriftHeight &&
            nMatMulMaxFutureMtpDrift > 0;
    }
    // a5 fix: whether the timewarp/drift bound reconciliation is active at this height.
    bool IsMatMulTimewarpReconcileActive(int32_t height) const
    {
        return fMatMulPOW &&
            height >= 0 &&
            nMatMulTimewarpReconcileHeight != std::numeric_limits<int32_t>::max() &&
            height >= nMatMulTimewarpReconcileHeight;
    }
    std::optional<int64_t> MaxMatMulFutureBlockTime(int32_t height, int64_t prev_median_time_past) const
    {
        if (!IsMatMulMaxFutureMtpDriftActive(height)) return std::nullopt;
        return MatMulFutureBlockTimeLimit(prev_median_time_past);
    }
    std::optional<int64_t> MatMulFutureBlockTimeLimit(int64_t prev_median_time_past) const
    {
        if (!fMatMulPOW ||
            nMatMulMaxFutureMtpDriftHeight == std::numeric_limits<int32_t>::max() ||
            nMatMulMaxFutureMtpDrift <= 0) {
            return std::nullopt;
        }
        if (prev_median_time_past > std::numeric_limits<int64_t>::max() - nMatMulMaxFutureMtpDrift) {
            return std::numeric_limits<int64_t>::max();
        }
        return prev_median_time_past + nMatMulMaxFutureMtpDrift;
    }
    bool IsShieldedTxBindingActive(int32_t height) const
    {
        return height >= 0 &&
            nShieldedTxBindingActivationHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedTxBindingActivationHeight;
    }
    bool IsShieldedBridgeTagUpgradeActive(int32_t height) const
    {
        return height >= 0 &&
            nShieldedBridgeTagActivationHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedBridgeTagActivationHeight;
    }
    bool IsShieldedSmileRiceCodecDisabled(int32_t height) const
    {
        return height >= 0 &&
            nShieldedSmileRiceCodecDisableHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedSmileRiceCodecDisableHeight;
    }
    bool IsShieldedMatRiCTDisabled(int32_t height) const
    {
        return height >= 0 &&
            nShieldedMatRiCTDisableHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedMatRiCTDisableHeight;
    }
    bool IsShieldedSpendPathRecoveryActive(int32_t height) const
    {
        return height >= 0 &&
            nShieldedSpendPathRecoveryActivationHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedSpendPathRecoveryActivationHeight;
    }
    bool IsShieldedC002Active(int32_t height) const
    {
        return height >= 0 &&
            nShieldedC002ActivationHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedC002ActivationHeight;
    }
    bool IsShieldedPQ128UpgradeActive(int32_t height) const
    {
        return height >= 0 &&
            nShieldedPQ128UpgradeHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedPQ128UpgradeHeight;
    }
    bool IsShieldedPoolCreditDisabled(int32_t height) const
    {
        return height >= 0 &&
            nShieldedPoolCreditDisableHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedPoolCreditDisableHeight;
    }
    bool IsShieldedSunsetActive(int32_t height) const
    {
        return height >= 0 &&
            nShieldedSunsetHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedSunsetHeight;
    }
    bool IsShieldedDirectSendPublicFlowDisabled(int32_t height) const
    {
        return height >= 0 &&
            nShieldedDirectSendPublicFlowDisableHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedDirectSendPublicFlowDisableHeight;
    }
    bool IsShieldedV2SendZeroOutputExitActive(int32_t height) const
    {
        return height >= 0 &&
            nShieldedV2SendZeroOutputExitActivationHeight != std::numeric_limits<int32_t>::max() &&
            height >= nShieldedV2SendZeroOutputExitActivationHeight;
    }
    bool IsShieldedRecoveryExitActive(int32_t height) const
    {
        return height >= 0 &&
            nShieldedRecoveryExitActivationHeight != std::numeric_limits<int32_t>::max() &&
            nShieldedSunsetHeight != std::numeric_limits<int32_t>::max() &&
            nShieldedRecoveryExitActivationHeight >= nShieldedSunsetHeight &&
            height >= nShieldedRecoveryExitActivationHeight &&
            height >= nShieldedSunsetHeight;
    }
    uint32_t GetShieldedSettlementAnchorMaturityDepth(int32_t height) const
    {
        return IsShieldedMatRiCTDisabled(height) ? nShieldedSettlementAnchorMaturity : 0;
    }
    uint32_t GetMatMulPreHashEpsilonBitsForHeight(int32_t height) const
    {
        return IsMatMulPreHashEpsilonBitsUpgradeActive(height)
            ? nMatMulPreHashEpsilonBitsUpgrade
            : nMatMulPreHashEpsilonBits;
    }
    /** The best chain should have at least this much work */
    uint256 nMinimumChainWork;
    /** By default assume that the signatures in ancestors of this block are valid */
    uint256 defaultAssumeValid;

    /**
     * If true, witness commitments contain a payload equal to a Bitcoin Script solution
     * to the signet challenge. See BIP325.
     */
    bool signet_blocks{false};
    std::vector<uint8_t> signet_challenge;

    int DeploymentHeight(BuriedDeployment dep) const
    {
        switch (dep) {
        case DEPLOYMENT_HEIGHTINCB:
            return BIP34Height;
        case DEPLOYMENT_CLTV:
            return BIP65Height;
        case DEPLOYMENT_DERSIG:
            return BIP66Height;
        case DEPLOYMENT_CSV:
            return CSVHeight;
        case DEPLOYMENT_SEGWIT:
            return SegwitHeight;
        } // no default case, so the compiler can warn about missing cases
        return std::numeric_limits<int>::max();
    }
};

/**
 * Fill nRCGrowth{Res,Cap}TableQ16 with the PROVISIONAL decaying-geometric schedule
 * from doc §R.7: annual g_res starts ~1.40, g_cap ~1.25; every 12 epochs reduce
 * annual g by ~0.02 then recompute the quarterly Q16 multiplier
 * (Q16 = round(g_annual^(1/4) * 65536)). Band-0 values ≈71300 / ≈69300.
 *
 * Must be called from every CChainParams constructor so tables are never left
 * zero-filled. Inert while nMatMulRCHeight==INT32_MAX (public nets keep that).
 */
inline void FillDefaultRCGrowthTables(Params& p)
{
    // Precomputed Q16 quarterly factors — no runtime float in consensus paths.
    // bands: epochs [0,12), [12,24), [24,36), [36,40)
    static constexpr int64_t kResQ16[4] = {71287, 71031, 70773, 70511}; // ≈71300,...
    static constexpr int64_t kCapQ16[4] = {69296, 69017, 68735, 68449}; // ≈69300,...
    static_assert(Params::kRCGrowthTableLen == 40);
    for (size_t e = 0; e < Params::kRCGrowthTableLen; ++e) {
        const size_t band = (e / 12) < 3 ? (e / 12) : 3;
        p.nRCGrowthResTableQ16[e] = kResQ16[band];
        p.nRCGrowthCapTableQ16[e] = kCapQ16[band];
    }
}

} // namespace Consensus

#endif // BITCOIN_CONSENSUS_PARAMS_H
