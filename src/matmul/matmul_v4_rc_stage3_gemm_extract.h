// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BTX_MATMUL_MATMUL_V4_RC_STAGE3_GEMM_EXTRACT_H
#define BTX_MATMUL_MATMUL_V4_RC_STAGE3_GEMM_EXTRACT_H

#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>
#include <matmul/matmul_v4_rc_stage3_episode.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// ============================================================================
// Stage-3 canonical GEMM/Extract coverage and signed-accumulator relation.
//
// The production episode has billions of Extract tiles.  Listing one record
// per tile is neither succinct nor a useful completeness boundary.  This
// module instead derives a compact, immutable range partition from Λ(params):
// every GEMM layer owns one consecutive output-cell interval and one
// consecutive 32-output Extract-tile interval.  Exact validation rejects any
// omitted, duplicated, reordered, resized, or relabelled interval.
//
// Per-layer roots bind the operand, result, Extract, scale, proof and CTL
// objects that must discharge those intervals.  A non-null root is only a
// binding, not proof verification.  In particular, the manifest does not
// claim the recursive Extract root is valid.
//
// The executable signed-range AIR proves, for every committed GEMM output:
//
//     value = (-1)^sign * magnitude
//     0 <= magnitude <= k*48*48 + residual_bound
//
// with a canonical positive zero and 31-bit bit-decompositions of magnitude
// and max-magnitude-minus-magnitude.  The bound is the pinned RC operand range
// (|s8| <= 48), with +48 exactly for the fused DOWN residual.  Exact
// deterministic sharding covers the entire manifest output interval.  This
// closes the modular-embedding/range relation only after an outer CTL links
// the AIR value column to the pre-Extract accumulator commitment.  That CTL
// link and execution of the recursive Extract roots are explicit residuals;
// authority/readiness remain false.
// ============================================================================

namespace matmul::v4::rc {

inline constexpr uint32_t kRCStage3GemmExtractManifestMagic =
    0x334d4547U; // "GEM3"
// Version 3: layer bindings additionally carry the Poseidon VectorRootAlg
// authority roots (operand/gemm_y/extract_input/scale), with the SHA256d roots
// demoted to transport/audit (ProductionProgramConsensusPinV1 doctrine).
inline constexpr uint16_t kRCStage3GemmExtractManifestVersion = 3;
// Profile 2 has 8*(2+2*24)=400 layers.  The inherited v7 hard cap of 256 is
// insufficient for Stage-3 and must not truncate the canonical manifest.
inline constexpr uint32_t kRCStage3GemmExtractMaxLayers = 1024;
inline constexpr uint32_t kRCStage3SignedRangeBits = 31;
inline constexpr uint32_t kRCStage3SignedRangeMaxShardRows = 1U << 20;
inline constexpr uint32_t kRCStage3ScaleScheduleMaxShardTiles = 1U << 20;
inline constexpr uint32_t kRCStage3RangeCtlNamespace = 0x47454d4dU; // "GEMM"
inline constexpr uint32_t kRCStage3RangeCtlBusBase = 0x47000000U;

struct RCStage3GemmExtractLayerBindings {
    /** Public Λ-derived Extract PRF key. */
    uint256 extract_prf{};
    // Transport / external-SHA256d-audit vector commitments.  Following the
    // ProductionProgramConsensusPinV1 rule (the recursive alg-hash root is the
    // sole authority; the SHA256d root is transport/audit-only), these SHA256d
    // roots are NO LONGER the opening authority — they are audit-transport.  The
    // *_root_alg fields below carry the Poseidon VectorRootAlg authority the
    // commitment openings (relation_closure OpenRCStage3EndpointCommitment) pin
    // against, so the registry assembles C_ρ against the same root the opening
    // proves.  Version 3 serializes both.
    uint256 operand_a_root{};
    uint256 operand_b_root{};
    uint256 gemm_y_root{};
    uint256 extract_input_root{};
    uint256 extract_output_root{};
    uint256 gemm_proof_root{};
    uint256 extract_recursive_root{};
    uint256 scale_schedule_root{};
    uint256 ctl_terminal_root{};

    // Poseidon VectorRootAlg AUTHORITY vector commitments (RCStage3ComputeVectorRootAlg
    // over the operand/output/input/scale value columns).  Empty on legacy
    // (transport-only) bindings; when present they are the registered authority.
    uint256 operand_a_root_alg{};
    uint256 operand_b_root_alg{};
    uint256 gemm_y_root_alg{};
    uint256 extract_input_root_alg{};
    uint256 scale_schedule_root_alg{};

    bool operator==(const RCStage3GemmExtractLayerBindings&) const = default;
};

struct RCStage3GemmExtractLayerManifest {
    uint32_t ordinal{0};
    RCGkrLayerKind kind{RCGkrLayerKind::GemmPhase1QKt};
    uint32_t round{0};
    uint32_t layer{0};
    uint32_t m{0};
    uint32_t n{0};
    uint32_t k{0};
    RCGkrOperandRef a{};
    RCGkrOperandRef b{};
    uint32_t y_first_column{0};
    uint32_t y_chunks{0};
    uint32_t out_first_column{0};
    uint32_t out_chunks{0};
    int32_t residual_first_column{-1};
    uint64_t gemm_cell_begin{0};
    uint64_t gemm_cell_count{0};
    uint64_t extract_tile_begin{0};
    uint64_t extract_tile_count{0};
    uint64_t signed_max_abs{0};
    RCStage3GemmExtractLayerBindings bindings{};

};

struct RCStage3GemmExtractManifest {
    uint32_t magic{kRCStage3GemmExtractManifestMagic};
    uint16_t version{kRCStage3GemmExtractManifestVersion};
    uint256 statement_commitment{};
    RCEpisodeParams params{};
    uint64_t total_gemm_cells{0};
    uint64_t total_extract_tiles{0};
    std::vector<RCStage3GemmExtractLayerManifest> layers;

};

/** Construct the sole canonical coverage partition for params.  bindings must
 * have exactly Λ(params).layers.size() non-null entries. */
[[nodiscard]] std::optional<RCStage3GemmExtractManifest>
BuildRCStage3GemmExtractManifest(
    const RCEpisodeParams& params,
    const uint256& statement_commitment,
    const std::vector<RCStage3GemmExtractLayerBindings>& bindings,
    std::string* why = nullptr);

/** Recompute Λ(params) and every cumulative interval. */
[[nodiscard]] bool ValidateRCStage3GemmExtractManifest(
    const RCStage3GemmExtractManifest& manifest,
    std::string* why = nullptr);
/** Bind the manifest to the exact outer episode/composed statement. */
[[nodiscard]] bool ValidateRCStage3GemmExtractManifestBinding(
    const RCStage3SuccinctProof& statement,
    const RCStage3GemmExtractManifest& manifest,
    std::string* why = nullptr);
/** Bind every Extract PRF and residual flag to verifier-derived episode
 * provenance (RCGkrEpisodeLayerProvenance(header, params, round_roots)). */
[[nodiscard]] bool ValidateRCStage3GemmExtractLayerProvenance(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCGkrSampledLayerProv>& provenance,
    std::string* why = nullptr);

[[nodiscard]] bool SerializeRCStage3GemmExtractManifest(
    const RCStage3GemmExtractManifest& manifest,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);
[[nodiscard]] std::optional<RCStage3GemmExtractManifest>
DeserializeRCStage3GemmExtractManifest(
    const std::vector<unsigned char>& bytes,
    std::string* why = nullptr);
[[nodiscard]] uint256 ComputeRCStage3GemmExtractManifestCommitment(
    const RCStage3GemmExtractManifest& manifest);

// ---------------------------------------------------------------------------
// Exact scale-schedule provenance.
// ---------------------------------------------------------------------------

struct RCStage3ScaleScheduleShard {
    uint32_t layer_ordinal{0};
    uint32_t shard_index{0};
    uint32_t shard_count{0};
    uint64_t tile_begin{0};
    uint32_t tile_count{0};
    /** Commitment to every canonical scale code in this interval. */
    uint256 scale_commitment{};

    bool operator==(const RCStage3ScaleScheduleShard&) const = default;
};

/** Native honest builder for one public scale shard.  Verification of this
 * commitment is deterministic but linear in tile_count; the hash/SHA AIR must
 * recursively prove it before a sublinear authority can use the root. */
[[nodiscard]] std::optional<RCStage3ScaleScheduleShard>
BuildRCStage3ScaleScheduleShard(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    uint32_t shard_index,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3ScaleScheduleShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3ScaleScheduleShard& shard,
    std::string* why = nullptr);
[[nodiscard]] uint256 ComputeRCStage3ScaleScheduleLayerRoot(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<RCStage3ScaleScheduleShard>& shards,
    std::string* why = nullptr);
/** Exact all-layer closure.  If replay_public_scales is true, re-derive every
 * public SHA-PRF scale code; false validates only canonical partition/root
 * bindings and is not proof execution. */
[[nodiscard]] bool VerifyRCStage3ScaleScheduleClosure(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3ScaleScheduleShard>& shards,
    bool replay_public_scales,
    std::string* why = nullptr);

enum RCStage3SignedRangeColumn : uint32_t {
    kRCStage3RangeActive = 0,
    kRCStage3RangeRemaining,
    kRCStage3RangeValue,
    kRCStage3RangeSign,
    kRCStage3RangeZero,
    kRCStage3RangeMagnitudeInverse,
    kRCStage3RangeMagnitude,
    kRCStage3RangeMagnitudeBits,
    kRCStage3RangeDifferenceBits =
        kRCStage3RangeMagnitudeBits + kRCStage3SignedRangeBits,
    kRCStage3SignedRangeColumns =
        kRCStage3RangeDifferenceBits + kRCStage3SignedRangeBits,
};
static_assert(kRCStage3SignedRangeColumns == 69);

struct RCStage3SignedRangeColumnPin {
    uint32_t column{0};
    uint256 root{};

    bool operator==(const RCStage3SignedRangeColumnPin&) const = default;
};

struct RCStage3SignedRangePin {
    uint256 statement_commitment{};
    uint256 manifest_commitment{};
    uint32_t layer_ordinal{0};
    uint32_t shard_index{0};
    uint32_t shard_count{0};
    uint64_t cell_begin{0};
    uint32_t logical_rows{0};
    uint32_t n_rows{0};
    uint64_t max_abs{0};
    std::vector<RCStage3SignedRangeColumnPin> column_roots;

    bool operator==(const RCStage3SignedRangePin&) const = default;
};

/** Canonical pin for one deterministic signed-range shard.  Roots are left
 * empty so a prover can fill them after building the trace. */
[[nodiscard]] std::optional<RCStage3SignedRangePin>
MakeRCStage3SignedRangePin(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    uint32_t shard_index,
    std::string* why = nullptr);

[[nodiscard]] bool SerializeRCStage3SignedRangePin(
    const RCStage3SignedRangePin& pin,
    std::vector<unsigned char>& out,
    std::string* why = nullptr);
[[nodiscard]] uint256 ComputeRCStage3SignedRangePinCommitment(
    const RCStage3SignedRangePin& pin);
[[nodiscard]] uint256 ComputeRCStage3SignedRangeSeed(
    const RCStage3SignedRangePin& pin);

/** Construct the 69 committed columns. values.size() must equal
 * pin.logical_rows; padding is canonical positive zero. */
[[nodiscard]] bool BuildRCStage3SignedRangeColumns(
    const RCStage3SignedRangePin& pin,
    const std::vector<int64_t>& values,
    std::vector<std::vector<gkr_field::Fp3>>& columns,
    std::string* why = nullptr);

/**
 * Immutable signed-range kernel for a fully populated public pin.
 *
 * This is the relation-only form shared by episode and coupled manifests.
 * Callers remain responsible for deriving every pin field from their
 * registered schedule.  In particular this function does not accept a
 * witness-selected row interval or bound.
 */
[[nodiscard]] bool ResolveRCStage3SignedRangeKernelConstraintSystem(
    const RCStage3SignedRangePin& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

[[nodiscard]] bool ResolveRCStage3SignedRangeConstraintSystem(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);

/** Verify a proof-only range shard.  It does not use or accept a native GEMM
 * witness and it does not replay GEMM.  A consensus-facing caller must first
 * run ValidateRCStage3GemmExtractManifestBinding on the outer statement. */
[[nodiscard]] bool VerifyRCStage3SignedRangeShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

/**
 * Resolve the same signed-range relation on CTL's degree profile.
 *
 * The ordinary range AIR has degree two and therefore commits its trace
 * columns on an N-coefficient FRI domain.  The LogUp CTL AIR has degree four
 * and commits on next_pow2(3N-3).  Equal H-domain VALUE columns would
 * consequently have different Merkle roots.  This variant adds one redundant
 * square of the already-enforced ACTIVE boolean identity.  It changes no
 * accepted range witnesses, but raises the declared composed degree to four
 * so both AIR proofs commit the shared VALUE polynomial on the same domain.
 */
[[nodiscard]] bool ResolveRCStage3SignedRangeCtlAlignedConstraintSystem(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    air_quotient::AirConstraintSystem<gkr_field::Fp3>& out,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3SignedRangeCtlAlignedShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const air_quotient::AirQuotientProof<gkr_field::Fp3>& proof,
    std::string* why = nullptr);

// ---------------------------------------------------------------------------
// Canonical per-shard CTL binding: range value -> Extract input.
// ---------------------------------------------------------------------------

struct RCStage3SignedRangeCtlBinding {
    /** Root of the exact Extract-input shard to which range VALUE is linked. */
    uint256 extract_input_shard_root{};
    /** Proof-independent obligation tying the shard root/interval to the
     * layer-wide bindings.extract_input_root. */
    uint256 extract_input_opening_commitment{};
    RCStage3CtlChildPin range_child;
    RCStage3CtlChildPin extract_child;

    bool operator==(const RCStage3SignedRangeCtlBinding&) const = default;
};

[[nodiscard]] uint32_t RCStage3SignedRangeGlobalShardOrdinal(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin);
[[nodiscard]] RCStage3CtlSchedule BuildRCStage3SignedRangeCtlSchedule(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    bool producer);
[[nodiscard]] uint256 CommitRCStage3SignedRangeCtlScheduleDescriptor(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    bool producer);
[[nodiscard]] uint256 ComputeRCStage3ExtractInputShardObligation(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const uint256& extract_input_shard_root,
    const uint256& extract_input_opening_commitment);
[[nodiscard]] uint256 ComputeRCStage3SignedRangeCtlTraceCommitment(
    const RCStage3SignedRangePin& pin);
[[nodiscard]] uint256 ComputeRCStage3ExtractCtlTraceCommitment(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3SignedRangeCtlBinding& binding);
[[nodiscard]] RCStage3CtlManifest BuildRCStage3SignedRangeCtlManifest(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3SignedRangeCtlBinding& binding);
/** Validate exact schedule/count/trace-root/challenge/terminal composition.
 * This remains public-pin composition: recursive child AIR execution is a
 * separate obligation. */
[[nodiscard]] bool VerifyRCStage3SignedRangeCtlBinding(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3SignedRangeCtlBinding& binding,
    std::string* why = nullptr);

struct RCStage3SignedRangeCtlShard {
    RCStage3SignedRangePin pin;
    RCStage3SignedRangeCtlBinding binding;
};

[[nodiscard]] bool VerifyRCStage3SignedRangeCtlClosure(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3SignedRangeCtlShard>& shards,
    std::string* why = nullptr);
[[nodiscard]] uint256 ComputeRCStage3SignedRangeCtlLayerCommitment(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<RCStage3SignedRangeCtlShard>& shards,
    bool range_children,
    std::string* why = nullptr);

struct RCStage3SignedRangeShardProof {
    RCStage3SignedRangePin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> proof;
};

/**
 * Additive Split-RAP canary for one production EpisodeSignedRange shard.
 *
 * The legacy per-column proof above remains byte- and API-identical.  This
 * canary instead commits the one proof-input VALUE column as R0, the 68
 * derived range/decomposition columns as Rdep, and the quotient as Rq.  All
 * three groups are consumed by one
 * ordered MultiRow-V2 proximity proof.  Keeping VALUE as the sole base/input
 * group makes `value_export_root` an exact proof-authenticated export rather
 * than a sampled cross-opening or a descriptor-only binding.
 *
 * This is deliberately a shard-local migration seam.  Recursive consumption
 * and production authority remain false.
 */
struct RCStage3EpisodeSignedRangeSplitRapShardProof {
    uint16_t version{1};
    RCStage3SignedRangePin pin;
    uint256 value_export_root{};
    air_quotient::AirQuotientSplitRapRowsProof quotient;
};

/** Canonical R0 schedule: the sole proof-input VALUE column. */
[[nodiscard]] const std::vector<uint32_t>&
RCStage3EpisodeSignedRangeSplitRapBaseColumns();

/**
 * Algebraic single-column row root exported by the Split-RAP VALUE group.
 * `values` is the exact signed GEMM-Y shard in canonical row order; canonical
 * positive-zero padding is derived from `pin`.
 */
[[nodiscard]] uint256
ComputeRCStage3EpisodeSignedRangeSplitRapValueExportRoot(
    const RCStage3SignedRangePin& pin,
    const std::vector<int64_t>& values,
    std::string* why = nullptr);

/**
 * Honest prover for one already-rooted canonical EpisodeSignedRange pin.
 * The legacy roots are checked against the same witness before the additive
 * Split-RAP product is emitted; no legacy proof or codec is modified.
 */
[[nodiscard]] bool ProveRCStage3EpisodeSignedRangeSplitRapShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const std::vector<int64_t>& values,
    RCStage3EpisodeSignedRangeSplitRapShardProof& out,
    std::string* why = nullptr);

/**
 * Public verifier-owned relation reconstruction.  `expected_pin` and
 * `expected_value_export_root` come from the registered episode/GEMM product;
 * the proof cannot select its interval, bound, column partition, or export.
 */
[[nodiscard]] bool VerifyRCStage3EpisodeSignedRangeSplitRapShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& expected_pin,
    const uint256& expected_value_export_root,
    const RCStage3EpisodeSignedRangeSplitRapShardProof& proof,
    std::string* why = nullptr);

/**
 * Executed-CTL binding.  Unlike RCStage3SignedRangeCtlBinding's older
 * descriptor-only pins, these child trace commitments must be the actual
 * prechallenge-column commitment verified by RCStage3CtlAirProof.
 */
struct RCStage3SignedRangeExecutedCtlBinding {
    uint256 extract_input_shard_root{};
    uint256 extract_input_opening_commitment{};
    RCStage3CtlChildPin range_child;
    RCStage3CtlChildPin extract_child;
};

struct RCStage3SignedRangeExecutedCtlShardProof {
    RCStage3SignedRangePin pin;
    air_quotient::AirQuotientProof<gkr_field::Fp3> range_proof;
    RCStage3SignedRangeExecutedCtlBinding binding;
    RCStage3CtlAirProof range_ctl_proof;
    RCStage3CtlAirProof extract_ctl_proof;
};

/**
 * Ordered Merkle opening from one executed Extract-input VALUE commitment to
 * the layer-wide bindings.extract_input_root.
 *
 * Leaves bind the immutable statement/layer interval, the exact signed-range
 * shard interval and shard_root.  Padding leaves and every internal level use
 * separate domains.  The final root is wrapped with the layer identity and
 * exact shard count, so an opening cannot be moved between layers, reordered
 * or interpreted under a different tree shape.
 */
struct RCStage3ExtractInputShardOpening {
    uint32_t layer_ordinal{0};
    uint32_t shard_index{0};
    uint32_t shard_count{0};
    uint64_t cell_begin{0};
    uint32_t logical_rows{0};
    uint256 shard_root{};
    std::vector<uint256> authentication_path;

    bool operator==(const RCStage3ExtractInputShardOpening&) const = default;
};

/** Build the registered layer root from the exact ordered shard-root vector.
 * This hash construction is executable, but its SHA256d execution must still
 * be proved by the recursive hash child before succinct authority is ready. */
[[nodiscard]] uint256 ComputeRCStage3ExtractInputLayerRoot(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<uint256>& ordered_shard_roots,
    std::string* why = nullptr);
[[nodiscard]] std::optional<RCStage3ExtractInputShardOpening>
BuildRCStage3ExtractInputShardOpening(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<uint256>& ordered_shard_roots,
    uint32_t shard_index,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3ExtractInputShardOpening(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3ExtractInputShardOpening& opening,
    std::string* why = nullptr);
/** Exact one-layer closure.  Omission, duplication, reordering and root
 * substitution fail before any recursive authority can consume the bundle. */
[[nodiscard]] bool VerifyRCStage3ExtractInputLayerOpeningClosure(
    const RCStage3GemmExtractManifest& manifest,
    uint32_t layer_ordinal,
    const std::vector<RCStage3ExtractInputShardOpening>& openings,
    std::string* why = nullptr);
/** Commitment placed in RCStage3SignedRangeExecutedCtlBinding before the CTL
 * Fiat-Shamir seed is derived. */
[[nodiscard]] uint256 ComputeRCStage3ExtractInputShardOpeningCommitment(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangePin& pin,
    const RCStage3ExtractInputShardOpening& opening);

struct RCStage3SignedRangeExecutedCtlOpenedShardProof {
    RCStage3SignedRangeExecutedCtlShardProof relation;
    RCStage3ExtractInputShardOpening extract_input_opening;
};

/**
 * Execute the CTL-aligned signed-range proof and both LogUp child proofs.
 *
 * In addition to native proof verification, this requires the producer CTL
 * VALUE root to equal the signed-range AIR's kRCStage3RangeValue root and the
 * consumer CTL VALUE root to equal extract_input_shard_root.  Thus root
 * substitution, proof relabelling and detached CTL witnesses fail before
 * terminal composition.  The separate Extract opening proof named by
 * extract_input_opening_commitment and recursive consumption remain open.
 */
[[nodiscard]] bool VerifyRCStage3SignedRangeExecutedCtlShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangeExecutedCtlShardProof& shard,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3SignedRangeExecutedCtlClosure(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3SignedRangeExecutedCtlShardProof>& shards,
    std::string* why = nullptr);
/** Composite algebraic/cryptographic edge:
 *
 * signed-range VALUE == executed producer CTL VALUE
 *                    == executed Extract CTL VALUE
 *                    == authenticated layer Extract-input leaf.
 */
[[nodiscard]] bool VerifyRCStage3SignedRangeExecutedCtlOpenedShard(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3SignedRangeExecutedCtlOpenedShardProof& shard,
    std::string* why = nullptr);
[[nodiscard]] bool VerifyRCStage3SignedRangeExecutedCtlOpenedClosure(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3SignedRangeExecutedCtlOpenedShardProof>& shards,
    std::string* why = nullptr);

/** Exact all-layer/all-shard closure in canonical order.  This proves range
 * for every manifest pre-Extract accumulator cell. The paired CTL API below
 * binds its value roots to Extract-input obligations; authority still waits
 * for recursive execution of those CTL and opening children. */
[[nodiscard]] bool VerifyRCStage3SignedRangeClosure(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3SignedRangeShardProof>& shards,
    std::string* why = nullptr);
/** Execute both closures and require byte-identical canonical pins at every
 * layer/shard position. */
[[nodiscard]] bool VerifyRCStage3SignedRangeProofCtlClosure(
    const RCStage3GemmExtractManifest& manifest,
    const std::vector<RCStage3SignedRangeShardProof>& range_shards,
    const std::vector<RCStage3SignedRangeCtlShard>& ctl_shards,
    std::string* why = nullptr);

// ---------------------------------------------------------------------------
// Exact per-layer execution-obligation manifest.
// ---------------------------------------------------------------------------

struct RCStage3GemmExtractLayerObligation {
    uint32_t layer_ordinal{0};
    uint256 operand_a_root{};
    uint256 operand_b_root{};
    uint256 gemm_y_root{};
    uint256 extract_input_root{};
    uint256 extract_output_root{};
    uint256 operand_a_opening_commitment{};
    uint256 operand_b_opening_commitment{};
    uint256 gemm_y_opening_commitment{};
    uint256 sumcheck_commitment{};
    uint256 signed_range_closure_commitment{};
    uint256 extract_recursive_proof_commitment{};
    uint256 scale_schedule_proof_commitment{};
    uint256 range_ctl_child_commitment{};
    uint256 extract_ctl_child_commitment{};

    bool operator==(const RCStage3GemmExtractLayerObligation&) const = default;
};

struct RCStage3GemmExtractObligationManifest {
    uint256 statement_commitment{};
    uint256 manifest_commitment{};
    std::vector<RCStage3GemmExtractLayerObligation> layers;

    bool operator==(const RCStage3GemmExtractObligationManifest&) const =
        default;
};

/** Rejects every omitted/duplicated/reordered/substituted relation root. This
 * validates the exact obligations, not the proof engines behind the roots. */
[[nodiscard]] bool ValidateRCStage3GemmExtractObligationManifest(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3GemmExtractObligationManifest& obligations,
    std::string* why = nullptr);
[[nodiscard]] uint256 ComputeRCStage3GemmExtractObligationCommitment(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3GemmExtractObligationManifest& obligations);
[[nodiscard]] bool ValidateRCStage3GemmExtractObligationCtlBinding(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3GemmExtractObligationManifest& obligations,
    const std::vector<RCStage3SignedRangeCtlShard>& ctl_shards,
    std::string* why = nullptr);

inline constexpr bool kRCStage3GemmExtractManifestComplete = false;
// Narrow executable fact only: the CTL-aligned range verifier above checks
// actual AirQuotient proofs on both sides of the shared VALUE commitment.
inline constexpr bool
    kRCStage3SignedRangeExecutedCtlValueRootBindingExecutable = true;
inline constexpr bool
    kRCStage3ExtractInputShardToLayerOpeningExecutable = true;
inline constexpr bool
    kRCStage3EpisodeSignedRangeSplitRapCanaryExecutable = true;
inline constexpr bool kRCStage3GemmSignedRangeAuthorityReady = false;
inline constexpr bool kRCStage3ExtractAllTileAuthorityReady = false;

} // namespace matmul::v4::rc

#endif // BTX_MATMUL_MATMUL_V4_RC_STAGE3_GEMM_EXTRACT_H
