// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_narrow_recurse.h>

#include <matmul/matmul_v4_rc_air_recurse.h>
#include <matmul/matmul_v4_rc_fri.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>

#include <algorithm>
#include <cmath>
#include <limits>

namespace matmul::v4::rc::narrow_recurse {
namespace {

constexpr uint32_t PERM_COLUMNS = air_recurse::kPermCellsPerPerm;
constexpr uint32_t SBOXES = air_recurse::kPermSboxCells;
constexpr uint32_t HASH_RATE = 8;
constexpr uint32_t HASH_DIGEST = 4;

static_assert(PERM_COLUMNS == 130);
static_assert(SBOXES == 118);
static_assert(kNarrowLaneColumns == 192);

bool Fail(std::string* why, const std::string& message)
{
    if (why != nullptr) *why = message;
    return false;
}

bool CheckedAdd(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a > std::numeric_limits<uint64_t>::max() - b) return false;
    out = a + b;
    return true;
}

bool CheckedMul(uint64_t a, uint64_t b, uint64_t& out)
{
    if (a != 0 && b > std::numeric_limits<uint64_t>::max() / a) return false;
    out = a * b;
    return true;
}

uint32_t NextPow2Checked(uint64_t n)
{
    if (n <= 2) return 2;
    if (n > (uint64_t{1} << 31)) return 0;
    uint32_t x = 1;
    while (x < n) x <<= 1;
    return x;
}

uint32_t Log2Exact(uint32_t n)
{
    if (n == 0 || (n & (n - 1)) != 0) return 0;
    uint32_t out = 0;
    while (n > 1) {
        n >>= 1;
        ++out;
    }
    return out;
}

uint64_t CeilDiv(uint64_t n, uint64_t d)
{
    return n / d + (n % d != 0 ? 1 : 0);
}

uint32_t FamilyTemplates(VerifierFamily family,
                         PoseidonLaneStrategy strategy)
{
    // Counts are intentionally conservative template counts for the future
    // selector-gated AIR. Shared permutation identities are over-counted
    // between families so the next-level per-point streaming budget is not
    // understated.
    uint32_t extra = 0;
    if (strategy == PoseidonLaneStrategy::DecomposedX2X4) {
        extra = 2 * SBOXES;
    } else if (strategy == PoseidonLaneStrategy::DecomposedX2X4X6) {
        extra = 3 * SBOXES;
    }
    switch (family) {
    case VerifierFamily::RowMerkle: return 151 + extra; // perm + sponge/path wiring
    case VerifierFamily::Fold: return 140 + extra;      // perm/path + fold algebra
    case VerifierFamily::Deep: return 12;             // dual-OOD accumulators
    case VerifierFamily::PerPoint: return 12;          // C(y)=Q(y)Z_H(y) stream
    case VerifierFamily::FiatShamirReplay: return 151 + extra; // sponge + challenge pins
    case VerifierFamily::Count: break;
    }
    return 0;
}

uint64_t FoldRowsPerQuery(const NarrowChildShape& child)
{
    // At fold l, both even and odd openings require one leaf plus a path of
    // depth D-l. One extra row checks the algebraic fold.
    const uint64_t nf = child.n_folds;
    const uint64_t depth_sum =
        nf * child.merkle_depth - (nf * (nf - 1)) / 2;
    return 2 * (nf + depth_sum) + nf;
}

bool ValidateChildShape(const NarrowChildShape& child, std::string* why)
{
    if (child.child_w == 0 || child.child_n_rows < 2 ||
        child.child_n_coeffs < child.child_n_rows ||
        child.child_n_lde < child.child_n_coeffs || child.queries == 0 ||
        child.child_constraints == 0 || child.arity == 0 ||
        child.arity > kNarrowMaxArity) {
        return Fail(why, "narrow_vcs: invalid zero/range field");
    }
    if ((child.child_n_rows & (child.child_n_rows - 1)) != 0 ||
        (child.child_n_coeffs & (child.child_n_coeffs - 1)) != 0 ||
        (child.child_n_lde & (child.child_n_lde - 1)) != 0) {
        return Fail(why, "narrow_vcs: child domains must be powers of two");
    }
    if (child.child_n_lde != child.child_n_coeffs * uint64_t{kRCFriBlowup}) {
        return Fail(why, "narrow_vcs: child LDE/blowup mismatch");
    }
    if (child.merkle_depth != Log2Exact(child.child_n_lde) ||
        child.n_folds != Log2Exact(child.child_n_coeffs) ||
        child.merkle_depth < child.n_folds) {
        return Fail(why, "narrow_vcs: child depth/fold mismatch");
    }
    return true;
}

} // namespace

bool NarrowLaneLayout::IsCanonical(std::string* why) const
{
    const std::array<ColumnRegion, 11> regions{
        control, permutation, sbox_x2, sbox_x4, sbox_x6,
        running_digest, sibling_digest,
        ext_registers, preprocessed, scalar, reserved};
    uint32_t cursor = 0;
    for (const ColumnRegion& region : regions) {
        if (region.offset != cursor) {
            return Fail(why, "narrow_vcs: non-canonical/gapped lane region");
        }
        cursor = region.End();
    }
    const bool decomposed =
        poseidon_strategy != PoseidonLaneStrategy::DirectX7;
    const bool quadratic =
        poseidon_strategy == PoseidonLaneStrategy::DecomposedX2X4X6;
    if (control.count != 1 + 3 + kNarrowRowKindCount + kNarrowFamilyCount ||
        permutation.count != PERM_COLUMNS ||
        sbox_x2.count != (decomposed ? SBOXES : 0) ||
        sbox_x4.count != (decomposed ? SBOXES : 0) ||
        sbox_x6.count != (quadratic ? SBOXES : 0) ||
        running_digest.count != HASH_DIGEST ||
        sibling_digest.count != HASH_DIGEST || ext_registers.count != 16 ||
        preprocessed.count != 16 || scalar.count != 4 || reserved.count != 1 ||
        cursor != kNarrowLaneColumns +
                      (decomposed ? 2 * SBOXES : 0) +
                      (quadratic ? SBOXES : 0) ||
        width != cursor) {
        return Fail(why, "narrow_vcs: lane width/region contract mismatch");
    }
    return true;
}

NarrowLaneLayout CanonicalNarrowLaneLayout()
{
    return CanonicalNarrowLaneLayout(PoseidonLaneStrategy::DirectX7);
}

NarrowLaneLayout CanonicalNarrowLaneLayout(PoseidonLaneStrategy strategy)
{
    NarrowLaneLayout out;
    out.poseidon_strategy = strategy;
    uint32_t col = 0;
    auto alloc = [&col](uint32_t count) {
        const ColumnRegion region{col, count};
        col += count;
        return region;
    };
    out.control = alloc(1 + 3 + kNarrowRowKindCount + kNarrowFamilyCount);
    out.permutation = alloc(PERM_COLUMNS);
    const uint32_t aux =
        strategy != PoseidonLaneStrategy::DirectX7 ? SBOXES : 0;
    out.sbox_x2 = alloc(aux);
    out.sbox_x4 = alloc(aux);
    out.sbox_x6 = alloc(
        strategy == PoseidonLaneStrategy::DecomposedX2X4X6 ? SBOXES : 0);
    out.running_digest = alloc(HASH_DIGEST);
    out.sibling_digest = alloc(HASH_DIGEST);
    out.ext_registers = alloc(16);
    out.preprocessed = alloc(16);
    out.scalar = alloc(4);
    out.reserved = alloc(1);
    out.width = col;
    return out;
}

PoseidonConstraintProfile CanonicalPoseidonConstraintProfile(
    PoseidonLaneStrategy strategy)
{
    PoseidonConstraintProfile out;
    out.strategy = strategy;
    out.sboxes = SBOXES;
    out.selector_degree = 1;
    if (strategy == PoseidonLaneStrategy::DirectX7) {
        out.constraints = SBOXES;
        out.ungated_max_degree = 7;
        out.gated_max_degree = 8;
    } else if (strategy == PoseidonLaneStrategy::DecomposedX2X4) {
        out.auxiliary_columns = 2 * SBOXES;
        out.constraints = 3 * SBOXES;
        out.ungated_max_degree = 3;
        out.gated_max_degree = 4;
    } else {
        out.auxiliary_columns = 3 * SBOXES;
        out.constraints = 4 * SBOXES;
        out.ungated_max_degree = 2;
        out.gated_max_degree = 3;
    }
    return out;
}

NarrowChildShape ProductionEpisodeChildShape()
{
    NarrowChildShape out;
    out.child_w = 26;
    out.child_n_rows = 1u << 16;
    // Episode shard AIR has maximum algebraic degree 2 and quotient length
    // below N, so its FRI coefficient domain remains N.
    out.child_n_coeffs = 1u << 16;
    out.child_n_lde = out.child_n_coeffs * kRCFriBlowup;
    out.merkle_depth = 20;
    out.n_folds = 16;
    out.queries = kRCFriNumQueries;
    out.child_constraints = 13; // BuildEpisodeShardConstraints registry
    out.arity = 2;
    return out;
}

uint64_t RowLeafPermutationRows(uint32_t child_w)
{
    // SpongeHashFp absorbs 3 coordinates for each of W+1 Fp3 openings, then
    // the query index. Its 10* padding always adds at least one field word.
    const uint64_t stream_words = 3 * (uint64_t{child_w} + 1) + 1;
    return stream_words / HASH_RATE + 1;
}

uint64_t FiatShamirReplayRows(const NarrowChildShape& child)
{
    // Conservative transcript field-word schedule used by the original
    // fixed-point planner. The executable verifier audit in
    // stage3_verifier_air computes the actual SHA256d compression count and
    // fails scheduler_capacity_sufficient when this estimate is too small.
    // Do not treat this row count as an executable SHA transcript schedule.
    const uint64_t words =
        30 + 7 * uint64_t{child.n_folds} +
        7 * (uint64_t{child.child_w} + 1);
    return words / HASH_RATE + 1;
}

NarrowVcsPlan BuildNarrowVcsPlan(const NarrowChildShape& child,
                                 uint32_t represented_family_mask)
{
    NarrowVcsConfig config;
    config.represented_family_mask = represented_family_mask;
    return BuildNarrowVcsPlan(child, config);
}

NarrowVcsPlan BuildNarrowVcsPlan(const NarrowChildShape& child,
                                 const NarrowVcsConfig& config)
{
    NarrowVcsPlan out;
    out.child = child;
    out.config = config;
    out.lane = CanonicalNarrowLaneLayout(config.poseidon_strategy);
    out.represented_family_mask =
        config.represented_family_mask & kNarrowMandatoryFamilyMask;

    std::string shape_why;
    if (!out.lane.IsCanonical(&shape_why) ||
        !ValidateChildShape(child, &shape_why)) {
        out.note = shape_why;
        return out;
    }
    if ((config.represented_family_mask & ~kNarrowMandatoryFamilyMask) != 0) {
        out.note = "narrow_vcs: unknown verifier family bit";
        return out;
    }

    const uint64_t row_merkle =
        RowLeafPermutationRows(child.child_w) + child.merkle_depth;
    const uint64_t fold = FoldRowsPerQuery(child);
    // NOTE ON kNarrowStreamBatch.  These two row counts assume a chip that
    // retires kNarrowStreamBatch (8) accumulator terms per row.  The
    // executable non-hash chip in stage3_verifier_air is NOT that chip: its
    // DeepAccumulate row carries exactly one out = a*b + c identity and its
    // PerPointAccumulate row exactly one a = b*c identity
    // (BuildScalarConstraints).  Against that chip these schedules are short
    // by up to a factor of kNarrowStreamBatch, in the same way
    // FiatShamirReplayRows is short against the exact SHA256d schedule.  Do
    // not read either count as an executable per-term budget.
    const uint64_t deep = CeilDiv(uint64_t{child.child_w} + 1, kNarrowStreamBatch);
    const uint64_t per_point =
        CeilDiv(child.child_constraints, kNarrowStreamBatch) + 1;
    const uint64_t fs = FiatShamirReplayRows(child);
    const std::array<uint64_t, kNarrowFamilyCount> per_query{
        row_merkle, fold, deep, per_point, 0};
    const std::array<uint64_t, kNarrowFamilyCount> per_child{
        0, 0, 0, 0, fs};

    uint64_t rows_per_query = 2; // segment start/end rows
    uint64_t rows_per_child = 0;
    for (uint32_t i = 0; i < kNarrowFamilyCount; ++i) {
        const VerifierFamily family = static_cast<VerifierFamily>(i);
        FamilySchedule& schedule = out.families[i];
        schedule.family = family;
        schedule.represented =
            (out.represented_family_mask & FamilyBit(family)) != 0;
        if (!schedule.represented) continue;
        schedule.rows_per_query = per_query[i];
        schedule.rows_per_child = per_child[i];
        schedule.constraint_templates =
            FamilyTemplates(family, config.poseidon_strategy);
        if (!CheckedAdd(rows_per_query, schedule.rows_per_query,
                        rows_per_query) ||
            !CheckedAdd(rows_per_child, schedule.rows_per_child,
                        rows_per_child)) {
            out.note = "narrow_vcs: schedule row overflow";
            return out;
        }
        if (out.constraint_templates >
            std::numeric_limits<uint32_t>::max() -
                schedule.constraint_templates) {
            out.note = "narrow_vcs: constraint count overflow";
            return out;
        }
        out.constraint_templates += schedule.constraint_templates;
    }

    uint64_t query_rows = 0;
    uint64_t rows_for_one_child = 0;
    if (!CheckedMul(rows_per_query, child.queries, query_rows) ||
        !CheckedAdd(query_rows, rows_per_child, rows_for_one_child)) {
        out.note = "narrow_vcs: active row overflow";
        return out;
    }
    if (config.child_packing == ChildPacking::VerticalRows) {
        if (!CheckedMul(rows_for_one_child, child.arity, out.active_rows)) {
            out.note = "narrow_vcs: active row overflow";
            return out;
        }
    } else {
        out.active_rows = rows_for_one_child;
    }
    out.trace_rows = NextPow2Checked(out.active_rows);
    if (out.trace_rows == 0) {
        out.note = "narrow_vcs: trace row domain overflow";
        return out;
    }

    // Vertical mode uses the maximum single-chip width. Parallel mode is a
    // distinct fixed binary-chip layout: it duplicates the bounded lane and
    // trades a small constant width increase for half as many child rows.
    const uint64_t packed_lanes =
        config.child_packing == ChildPacking::ParallelLanes ? child.arity : 1;
    const uint64_t parent_width = packed_lanes * out.lane.width;
    if (parent_width > std::numeric_limits<uint32_t>::max()) {
        out.note = "narrow_vcs: parent width overflow";
        return out;
    }
    out.parent_width = static_cast<uint32_t>(parent_width);
    out.recursively_planned_width = out.parent_width;
    out.width_fixed_point =
        out.recursively_planned_width <= out.parent_width;
    out.all_mandatory_families =
        out.represented_family_mask == kNarrowMandatoryFamilyMask;

    out.max_algebraic_degree =
        CanonicalPoseidonConstraintProfile(config.poseidon_strategy)
            .gated_max_degree;
    const uint64_t quotient =
        uint64_t{out.max_algebraic_degree - 1} * (out.trace_rows - 1);
    if (quotient > std::numeric_limits<uint32_t>::max()) {
        out.note = "narrow_vcs: quotient length overflow";
        return out;
    }
    out.quotient_len = static_cast<uint32_t>(quotient);
    out.n_coeffs =
        NextPow2Checked(std::max<uint64_t>(out.trace_rows, out.quotient_len));
    if (out.n_coeffs == 0 ||
        uint64_t{out.n_coeffs} * kRCFriBlowup >
            std::numeric_limits<uint32_t>::max()) {
        out.note = "narrow_vcs: parent FRI domain overflow";
        return out;
    }
    out.n_lde = out.n_coeffs * kRCFriBlowup;
    out.backend_columns_supported =
        out.parent_width <= kRCFri3AlgBatchMaxColumns;
    out.backend_lde_supported =
        uint64_t{out.n_lde} <= (uint64_t{1} << kRCFriMaxLdeLog2);
    out.valid = true;
    out.note = "narrow_vcs: deterministic layout/count prototype only";
    return out;
}

NarrowChildShape NextRecursiveChildShape(const NarrowVcsPlan& plan)
{
    if (!plan.valid) return {};
    NarrowChildShape out;
    out.child_w = plan.parent_width;
    out.child_n_rows = plan.trace_rows;
    out.child_n_coeffs = plan.n_coeffs;
    out.child_n_lde = plan.n_lde;
    out.merkle_depth = Log2Exact(plan.n_lde);
    out.n_folds = Log2Exact(plan.n_coeffs);
    out.queries = plan.child.queries;
    out.child_constraints = plan.constraint_templates;
    out.arity = plan.child.arity;
    return out;
}

NarrowVcsReadiness AssessNarrowVcsReadiness(
    const NarrowVcsPlan& leaf_plan,
    const NarrowVcsCapabilities& capabilities)
{
    NarrowVcsReadiness out;
    std::string lane_why;
    out.layout_valid =
        leaf_plan.valid && leaf_plan.lane.IsCanonical(&lane_why);
    out.all_mandatory_families = leaf_plan.all_mandatory_families;
    out.width_fixed_point = leaf_plan.width_fixed_point;
    out.backend_shape_supported =
        leaf_plan.backend_columns_supported && leaf_plan.backend_lde_supported;

    NarrowVcsPlan level1;
    NarrowVcsPlan level2;
    if (leaf_plan.valid) {
        level1 = BuildNarrowVcsPlan(
            NextRecursiveChildShape(leaf_plan), leaf_plan.config);
        if (level1.valid) {
            level2 = BuildNarrowVcsPlan(
                NextRecursiveChildShape(level1), leaf_plan.config);
        }
    }
    out.trace_shape_fixed_point =
        level1.valid && level2.valid &&
        level2.trace_rows <= level1.trace_rows &&
        level2.parent_width <= level1.parent_width;
    out.backend_shape_supported =
        out.backend_shape_supported && level1.valid && level2.valid &&
        level1.backend_columns_supported && level1.backend_lde_supported &&
        level2.backend_columns_supported && level2.backend_lde_supported;

    out.implementation_complete =
        kNarrowVcsExecutable && capabilities.executable_air &&
        capabilities.honest_witness_builder &&
        capabilities.native_differential_tests &&
        capabilities.proof_independent_fs_replay;
    out.soundness_target_met =
        capabilities.composed_soundness_bits >= kNarrowTargetSoundnessBits;
    out.performance_target_met =
        capabilities.production_verify_millis != 0 &&
        capabilities.production_verify_millis <= kNarrowVerifierBudgetMillis;

    auto gap = [&out](bool ok, const char* message) {
        if (!ok) out.gaps.emplace_back(message);
    };
    gap(out.layout_valid, "canonical narrow lane/layout is invalid");
    gap(out.all_mandatory_families,
        "not every verifier family is represented");
    gap(out.width_fixed_point,
        "F_width(W*) <= W* does not close");
    gap(out.trace_shape_fixed_point,
        "recursive padded trace shape does not stabilize");
    gap(out.backend_shape_supported,
        "recursive width or LDE exceeds the current backend cap");
    gap(out.implementation_complete,
        "executable AIR/witness/differential/FS replay is incomplete");
    gap(out.soundness_target_met,
        "composed post-grinding soundness is below 100 bits");
    gap(out.performance_target_met,
        "production root verification has no <=900ms measurement");
    gap(capabilities.consensus_authority_enabled,
        "consensus authority remains disabled");

    out.production_ready =
        out.layout_valid && out.all_mandatory_families &&
        out.width_fixed_point && out.trace_shape_fixed_point &&
        out.backend_shape_supported && out.implementation_complete &&
        out.soundness_target_met && out.performance_target_met &&
        capabilities.consensus_authority_enabled &&
        kNarrowVcsProductionReady;
    return out;
}

NarrowSoundnessPlan AssessNarrowSoundness(
    SoundnessTopology topology,
    uint32_t queries,
    uint32_t role_roots,
    uint32_t additional_recursive_nodes,
    uint32_t additional_accumulation_steps,
    bool multi_role_public_pin_schema)
{
    NarrowSoundnessPlan out;
    out.topology = topology;
    out.queries = queries;
    out.role_roots = role_roots;
    out.additional_recursive_nodes = additional_recursive_nodes;
    out.additional_accumulation_steps = additional_accumulation_steps;
    out.multi_role_public_pin_schema = multi_role_public_pin_schema;
    if (queries == 0 || role_roots == 0) {
        out.note = "narrow_vcs:soundness:invalid_shape";
        return out;
    }

    out.raw_bits =
        static_cast<double>(queries) * std::log2(32.0 / 17.0) -
        static_cast<double>(kRCFriGrindingBits);
    const uint64_t exposed_roots =
        topology == SoundnessTopology::IndependentRoleRoots ? role_roots : 1;
    if (exposed_roots >
        std::numeric_limits<uint64_t>::max() -
            additional_recursive_nodes -
            additional_accumulation_steps) {
        out.note = "narrow_vcs:soundness:union_count_overflow";
        return out;
    }
    out.union_sites = exposed_roots + additional_recursive_nodes +
                      additional_accumulation_steps;
    out.union_loss_bits = std::log2(static_cast<double>(out.union_sites));
    out.composed_bits = out.raw_bits - out.union_loss_bits;
    out.topology_complete =
        topology == SoundnessTopology::IndependentRoleRoots ||
        multi_role_public_pin_schema;
    out.target_met =
        out.topology_complete &&
        out.composed_bits >= kNarrowTargetSoundnessBits;
    if (topology == SoundnessTopology::UnifiedMultiRoleRoot &&
        !multi_role_public_pin_schema) {
        out.note =
            "narrow_vcs:soundness:multi_role_public_pin_schema_missing";
    } else if (!out.target_met) {
        out.note = "narrow_vcs:soundness:target_not_met_after_union";
    } else {
        out.note = "narrow_vcs:soundness:parameter_target_met";
    }
    return out;
}

FriFormalMarginExperiment AssessFriFormalMarginExperiment(
    uint32_t fri_lanes,
    uint32_t queries_per_lane,
    uint32_t field_bits,
    uint32_t lde_log2,
    uint32_t grinding_bits,
    uint32_t global_site_log2)
{
    FriFormalMarginExperiment out;
    out.field_bits = field_bits;
    out.lde_log2 = lde_log2;
    out.grinding_bits = grinding_bits;
    out.global_site_log2 = global_site_log2;
    out.fri_lanes = fri_lanes;
    out.queries_per_lane = queries_per_lane;
    if (fri_lanes == 0 || queries_per_lane == 0 ||
        field_bits <= 2 * lde_log2) {
        out.note = "narrow_vcs:formal_margin:invalid_parameters";
        return out;
    }

    const double common_losses =
        static_cast<double>(grinding_bits) +
        static_cast<double>(global_site_log2);
    out.proximity_bits_after_losses =
        static_cast<double>(fri_lanes) *
            static_cast<double>(queries_per_lane) *
            std::log2(32.0 / 17.0) -
        common_losses;
    out.field_domain_bits_after_losses =
        static_cast<double>(fri_lanes) *
            static_cast<double>(field_bits - 2 * lde_log2) -
        common_losses;
    out.bottleneck_bits =
        std::min(out.proximity_bits_after_losses,
                 out.field_domain_bits_after_losses);
    out.parameter_target_met =
        out.bottleneck_bits >= kNarrowTargetSoundnessBits;
    out.formal_reduction_complete = false;
    out.authority_eligible = false;
    if (fri_lanes == 1 && out.field_domain_bits_after_losses <
                              kNarrowTargetSoundnessBits) {
        out.note =
            "narrow_vcs:formal_margin:single_fp3_lane_field_term_below_target";
    } else if (fri_lanes > 1 && out.parameter_target_met) {
        out.note =
            "narrow_vcs:formal_margin:dual_lane_candidate_needs_independence_"
            "and_bcs_reduction";
    } else {
        out.note =
            "narrow_vcs:formal_margin:parameter_screen_below_target";
    }
    return out;
}

FriBcsRepetitionAssessment AssessFriBcsRepetition(
    uint32_t fri_lanes,
    uint32_t queries_per_lane,
    uint32_t field_bits,
    uint32_t lde_log2,
    uint32_t rate_inverse_log2,
    uint32_t list_parameter_m,
    uint32_t adversary_query_log2,
    uint32_t global_site_log2,
    uint32_t random_oracle_output_bits,
    uint32_t batch_columns_upper_bound,
    FriBatchingChallengeMode batching_mode,
    uint32_t uniform_sampler_words_per_draw,
    uint32_t uniform_sampler_required_valid_words,
    uint32_t challenge_draws_per_lane_upper_bound)
{
    FriBcsRepetitionAssessment out;
    out.fri_lanes = fri_lanes;
    out.queries_per_lane = queries_per_lane;
    out.field_bits = field_bits;
    out.lde_log2 = lde_log2;
    out.rate_inverse_log2 = rate_inverse_log2;
    out.list_parameter_m = list_parameter_m;
    out.adversary_query_log2 = adversary_query_log2;
    out.global_site_log2 = global_site_log2;
    out.random_oracle_output_bits = random_oracle_output_bits;
    out.batch_columns_upper_bound = batch_columns_upper_bound;
    out.uniform_sampler_words_per_draw =
        uniform_sampler_words_per_draw;
    out.uniform_sampler_required_valid_words =
        uniform_sampler_required_valid_words;
    out.challenge_draws_per_lane_upper_bound =
        challenge_draws_per_lane_upper_bound;
    out.batching_mode = batching_mode;

    if (fri_lanes == 0 || queries_per_lane == 0 || field_bits == 0 ||
        lde_log2 == 0 || lde_log2 > 32 ||
        rate_inverse_log2 == 0 || rate_inverse_log2 > 63 ||
        list_parameter_m < 3 || random_oracle_output_bits == 0 ||
        batch_columns_upper_bound == 0 ||
        uniform_sampler_words_per_draw == 0 ||
        uniform_sampler_required_valid_words == 0 ||
        uniform_sampler_required_valid_words >
            uniform_sampler_words_per_draw ||
        challenge_draws_per_lane_upper_bound == 0 ||
        adversary_query_log2 >= random_oracle_output_bits) {
        out.note = "narrow_vcs:bcs_repetition:invalid_parameters";
        return out;
    }

    // Concrete theorem witnesses:
    // rho=2^-rate_inverse_log2, eta=1/32, delta=15/32.
    // They satisfy eta < sqrt(rho)/(2m) and
    // delta < 1-sqrt(rho)-eta for the canonical rho=1/16,m=3 shape.
    const double rho =
        std::ldexp(1.0, -static_cast<int>(rate_inverse_log2));
    constexpr double ETA = 1.0 / 32.0;
    constexpr double DELTA = 15.0 / 32.0;
    out.fri_rbr_parameter_domain_valid =
        ETA > 0.0 &&
        ETA < std::sqrt(rho) /
                  (2.0 * static_cast<double>(list_parameter_m)) &&
        DELTA > 0.0 &&
        DELTA < 1.0 - std::sqrt(rho) - ETA &&
        static_cast<double>(field_bits) >
            2.0 * static_cast<double>(lde_log2);
    if (!out.fri_rbr_parameter_domain_valid) {
        out.note = "narrow_vcs:bcs_repetition:rbr_parameter_domain";
        return out;
    }

    out.theorem_constant_loss_bits =
        7.0 * std::log2(static_cast<double>(list_parameter_m) + 0.5) -
        std::log2(3.0) +
        1.5 * static_cast<double>(rate_inverse_log2);
    if (batching_mode == FriBatchingChallengeMode::SinglePowerChallenge) {
        // ePrint 2023/1071, Lemma 5.10 gives the exact communication-saving
        // batching factor (t-1) for t>=2. At t=1 this is ordinary, unbatched
        // FRI and has no batching loss.
        out.batching_loss_bits =
            batch_columns_upper_bound >= 2
                ? std::log2(
                      static_cast<double>(
                          batch_columns_upper_bound - 1))
                : 0.0;
        out.published_batching_constant_exact = true;
    } else {
        out.batching_loss_bits = 0.0;
        out.published_batching_constant_exact = true;
    }

    out.field_rbr_bits =
        static_cast<double>(field_bits) -
        2.0 * static_cast<double>(lde_log2) -
        out.theorem_constant_loss_bits -
        out.batching_loss_bits;
    out.proximity_rbr_bits =
        static_cast<double>(queries_per_lane) *
        std::log2(32.0 / 17.0);
    out.lane_rbr_bits =
        std::min(out.field_rbr_bits, out.proximity_rbr_bits);

    out.lane_bcs_query_term_bits =
        out.lane_rbr_bits -
        static_cast<double>(adversary_query_log2);
    // -log2(3*(Q^2+1)/2^kappa), evaluated without constructing Q.
    out.lane_bcs_ro_collision_bits =
        static_cast<double>(random_oracle_output_bits) -
        std::log2(3.0) -
        2.0 * static_cast<double>(adversary_query_log2) -
        std::log2(
            1.0 +
            std::exp2(-2.0 *
                      static_cast<double>(adversary_query_log2)));

    // -log2(2^-a + 2^-b), stably evaluated.
    const double smaller =
        std::min(out.lane_bcs_query_term_bits,
                 out.lane_bcs_ro_collision_bits);
    const double larger =
        std::max(out.lane_bcs_query_term_bits,
                 out.lane_bcs_ro_collision_bits);
    out.lane_fs_soundness_bits =
        smaller - std::log2(1.0 + std::exp2(smaller - larger));

    // Definition-2 work metric: log2(Q/epsilon_rep(Q)). Lemma B.1
    // contributes epsilon_rep <= epsilon_fs^lanes, so log2 Q is added once.
    out.repeated_work_bits_before_sites =
        static_cast<double>(adversary_query_log2) +
        static_cast<double>(fri_lanes) *
            out.lane_fs_soundness_bits;
    out.global_work_bits =
        out.repeated_work_bits_before_sites -
        static_cast<double>(global_site_log2);
    if (std::isfinite(out.global_work_bits) &&
        out.global_work_bits > 0.0) {
        out.conservative_floor_bits =
            static_cast<uint32_t>(std::floor(out.global_work_bits));
    }

    // Definition 2 quantifies over every Q. For Q>=1,
    //   A+B <= 2 max(A,B),
    // where A=Q*epsilon_rbr and
    // B=3(Q^2+1)/2^kappa <= 6Q^2/2^kappa.
    // Repeating r times and unioning S sites gives conservative crossover
    // work screens. The global union saturates when the per-lane upper bound
    // reaches S^(-1/r), which is why the site loss is divided by r:
    //   RBR: lane_rbr_bits - 1 - log2(S)/r
    //   RO:  (kappa - log2(12) - log2(S)/r)/2.
    // The fixed-Q 107-bit screen can therefore pass while the all-Q screen
    // fails. This remains conditional on the open commitment/batching
    // reductions represented below.
    const double per_lane_site_loss =
        static_cast<double>(global_site_log2) /
        static_cast<double>(fri_lanes);
    out.all_query_rbr_branch_work_bits =
        out.lane_rbr_bits - 1.0 - per_lane_site_loss;
    out.all_query_ro_branch_work_bits =
        (static_cast<double>(random_oracle_output_bits) -
         std::log2(12.0) - per_lane_site_loss) /
        2.0;
    out.all_query_work_screen_bits =
        std::min(out.all_query_rbr_branch_work_bits,
                 out.all_query_ro_branch_work_bits);
    if (std::isfinite(out.all_query_work_screen_bits) &&
        out.all_query_work_screen_bits > 0.0) {
        out.all_query_conservative_floor_bits =
            static_cast<uint32_t>(
                std::floor(out.all_query_work_screen_bits));
    }

    // FromChallengeBytes3's legacy map reduces each 64-bit limb modulo the
    // Goldilocks prime p=2^64-2^32+1. For one limb the statistical distance
    // is below (2^64-p)/p; a union bound over three limbs is only about
    // 2^-30.4. Such a draw cannot support a 100-bit theorem.
    static_assert(
        gkr_field::kP ==
        std::numeric_limits<uint64_t>::max() -
            ((uint64_t{1} << 32) - 2));
    const long double two64 = std::ldexp(1.0L, 64);
    // Do not recover this gap by floating-point subtraction: on targets where
    // long double == double, p rounds to 2^64 and the subtraction becomes 0.
    constexpr uint64_t LIMB_GAP_U64 = (uint64_t{1} << 32) - 1;
    const long double limb_gap =
        static_cast<long double>(LIMB_GAP_U64);
    const long double field_modulus =
        two64 - static_cast<long double>(LIMB_GAP_U64);
    const long double legacy_bias_bound =
        std::min(1.0L, 3.0L * limb_gap / field_modulus);
    out.legacy_modulo_bias_bits =
        -static_cast<double>(std::log2(legacy_bias_bound));

    // The fixed-schedule sampler expands two lane-prefixed SHA256d blocks to
    // eight independent uint64 words and selects the first three words <p.
    // Conditioned on at least three successes, those coordinates are exactly
    // independent uniform Fp values. Exhaustion requires at least
    // words-required+1 invalid words (six of eight in the canonical shape).
    const long double limb_rejection = limb_gap / two64;
    out.uniform_limb_rejection_bits =
        -static_cast<double>(std::log2(limb_rejection));
    auto binomial = [](uint32_t n, uint32_t k) -> long double {
        if (k > n) return 0.0L;
        k = std::min(k, n - k);
        long double value = 1.0L;
        for (uint32_t i = 1; i <= k; ++i) {
            value *= static_cast<long double>(n - k + i);
            value /= static_cast<long double>(i);
        }
        return value;
    };
    const uint32_t first_failing_invalid_count =
        uniform_sampler_words_per_draw -
        uniform_sampler_required_valid_words + 1;
    long double sampler_exhaustion = 0.0L;
    for (uint32_t invalid = first_failing_invalid_count;
         invalid <= uniform_sampler_words_per_draw; ++invalid) {
        sampler_exhaustion +=
            binomial(uniform_sampler_words_per_draw, invalid) *
            std::pow(limb_rejection,
                     static_cast<long double>(invalid)) *
            std::pow(1.0L - limb_rejection,
                     static_cast<long double>(
                         uniform_sampler_words_per_draw - invalid));
    }
    out.uniform_sampler_exhaustion_bits_per_draw =
        -static_cast<double>(std::log2(sampler_exhaustion));
    out.uniform_sampler_global_completeness_bits =
        out.uniform_sampler_exhaustion_bits_per_draw -
        std::log2(static_cast<double>(fri_lanes)) -
        std::log2(
            static_cast<double>(challenge_draws_per_lane_upper_bound)) -
        static_cast<double>(global_site_log2);

    // For a 2^k query domain, reducing a uniform c0 in [0,p) modulo 2^k
    // is biased because p == 1 (mod 2^k) for k<=32. Its exact total
    // variation distance is (2^k-1)/(2^k*p). V4 must instead use low k bits
    // of a lane-prefixed RO block, after enforcing the power-of-two domain.
    const long double query_domain =
        std::ldexp(1.0L, static_cast<int>(lde_log2));
    const long double legacy_index_bias =
        (query_domain - 1.0L) / (query_domain * field_modulus);
    out.legacy_query_index_bias_bits =
        -static_cast<double>(std::log2(legacy_index_bias));

    out.bcs_bound_numerically_accounted = true;
    out.nirop_repetition_theorem_available = true;
    out.executable_dual_lane_shape_present =
        fri_lanes == kRCFri3AlgDualNumLanes &&
        queries_per_lane == kRCFri3AlgDualQueriesPerLane &&
        batching_mode ==
            FriBatchingChallengeMode::IndependentCoefficients;
    out.lane_statement_equality_enforced =
        out.executable_dual_lane_shape_present;
    out.accept_all_lanes_enforced =
        out.executable_dual_lane_shape_present;
    out.lane_domain_prefixes_present =
        out.executable_dual_lane_shape_present;

    // These are proof obligations, not caller-selected switches.
    // The numerical batching factor is exact in the cited theorem, but the
    // executable codec-to-protocol correspondence and actual column manifest
    // have not been proved.
    out.batching_protocol_instantiation_proven = false;
    out.batch_columns_manifest_derived = false;
    // The executable dual-Q128/V5 path uses one independent uniform draw per
    // batch column, two candidates for each of two OOD points, two DEEP
    // weights, and one draw per fold. Its maximal 2^24 LDE therefore has:
    //   batch_columns + OOD(2*2) + DEEP weights(2) + folds(20)
    // field draws per lane. This closes the local schedule accounting only;
    // it does not discharge the full-oracle/common-commitment reduction.
    constexpr uint32_t BLOWUP_LOG2 = 4;
    static_assert(kRCFriBlowup == (1U << BLOWUP_LOG2));
    if (out.executable_dual_lane_shape_present &&
        lde_log2 >= BLOWUP_LOG2) {
        out.manifest_challenge_draws_per_lane =
            batch_columns_upper_bound +
            2U * kRCFri3AlgDualOodCandidates + 2U +
            (lde_log2 - BLOWUP_LOG2);
    }
    out.uniform_field_challenge_sampling_present =
        out.executable_dual_lane_shape_present;
    out.uniform_sampler_draw_bound_manifest_derived =
        out.manifest_challenge_draws_per_lane > 0 &&
        challenge_draws_per_lane_upper_bound >=
            out.manifest_challenge_draws_per_lane;
    out.power_of_two_query_domain_enforced =
        out.executable_dual_lane_shape_present;
    out.uniform_query_index_sampling_present =
        out.executable_dual_lane_shape_present;
    out.fixed_schedule_uniform_ood_sampling_present =
        out.executable_dual_lane_shape_present;
    out.all_random_oracle_calls_lane_prefixed = false;
    out.common_commitment_binding_quantitatively_accounted = false;
    out.common_commitment_hybrid_reduction_complete = false;
    out.transcript_domains_proven_disjoint =
        kRCFri3AlgDualIndependenceReductionReady;
    out.adversary_query_bound_enforced = false;
    out.definition2_all_query_budgets_proven = false;
    out.global_site_bound_manifest_derived = false;
    out.formal_reduction_complete =
        out.fri_rbr_parameter_domain_valid &&
        out.published_batching_constant_exact &&
        out.batching_protocol_instantiation_proven &&
        out.batch_columns_manifest_derived &&
        out.bcs_bound_numerically_accounted &&
        out.nirop_repetition_theorem_available &&
        out.executable_dual_lane_shape_present &&
        out.lane_statement_equality_enforced &&
        out.accept_all_lanes_enforced &&
        out.lane_domain_prefixes_present &&
        out.all_random_oracle_calls_lane_prefixed &&
        out.common_commitment_binding_quantitatively_accounted &&
        out.common_commitment_hybrid_reduction_complete &&
        out.uniform_field_challenge_sampling_present &&
        out.uniform_sampler_draw_bound_manifest_derived &&
        out.power_of_two_query_domain_enforced &&
        out.uniform_query_index_sampling_present &&
        out.fixed_schedule_uniform_ood_sampling_present &&
        out.transcript_domains_proven_disjoint &&
        out.adversary_query_bound_enforced &&
        out.definition2_all_query_budgets_proven &&
        out.global_site_bound_manifest_derived &&
        kRCFri3AlgDualFormalSoundnessReady;
    out.parameter_target_met =
        out.conservative_floor_bits >= kNarrowTargetSoundnessBits;
    out.all_query_parameter_target_met =
        out.all_query_conservative_floor_bits >=
        kNarrowTargetSoundnessBits;
    out.certified_bits =
        out.formal_reduction_complete
            ? std::min(out.conservative_floor_bits,
                       out.all_query_conservative_floor_bits)
            : 0;
    out.authority_eligible =
        out.parameter_target_met &&
        out.all_query_parameter_target_met &&
        out.certified_bits >= kNarrowTargetSoundnessBits &&
        out.formal_reduction_complete;

    if (!out.parameter_target_met) {
        out.note = "narrow_vcs:bcs_repetition:work_bits_below_target";
    } else if (!out.batching_protocol_instantiation_proven ||
               !out.batch_columns_manifest_derived) {
        out.note =
            "narrow_vcs:bcs_repetition:batch_protocol_instantiation_open";
    } else if (!out.transcript_domains_proven_disjoint) {
        out.note =
            "narrow_vcs:bcs_repetition:transcript_disjointness_proof_open";
    } else {
        out.note =
            "narrow_vcs:bcs_repetition:global_reduction_incomplete";
    }
    return out;
}

FriDualQ128HybridBoundAssessment AssessFriDualQ128HybridBound(
    uint64_t global_site_count,
    FriDualCommitmentTopology topology)
{
    FriDualQ128HybridBoundAssessment out;
    out.topology = topology;
    out.global_site_count = global_site_count;
    if (global_site_count == 0 ||
        (topology != FriDualCommitmentTopology::SharedMaster &&
         topology != FriDualCommitmentTopology::FullyDuplicatedLanes &&
         topology != FriDualCommitmentTopology::TwoCommonRoots)) {
        out.note = "narrow_vcs:hybrid_bound:invalid_parameters";
        return out;
    }

    // Obtain the canonical Q128/V5 lane theorem terms before any site union,
    // then apply log2(the exact uint64 count), rather than rounding the
    // manifest up to a power of two.
    const FriBcsRepetitionAssessment fri =
        AssessFriBcsRepetition(
            2, 128, 192, 24, 4, 3, 40, 0, 256, 1U << 14,
            FriBatchingChallengeMode::IndependentCoefficients);
    if (!fri.fri_rbr_parameter_domain_valid ||
        !fri.bcs_bound_numerically_accounted ||
        !fri.executable_dual_lane_shape_present) {
        out.note = "narrow_vcs:hybrid_bound:q128_screen_unavailable";
        return out;
    }

    out.global_site_log2 =
        std::log2(static_cast<double>(global_site_count));
    constexpr double LANES = 2.0;
    const double per_lane_site_loss = out.global_site_log2 / LANES;
    const double exact_rbr_bits =
        fri.all_query_rbr_branch_work_bits - per_lane_site_loss;
    const double exact_ro_bits =
        fri.all_query_ro_branch_work_bits - per_lane_site_loss / 2.0;
    out.fri_all_query_bits = std::min(exact_rbr_bits, exact_ro_bits);

    out.binding_events_per_site =
        topology == FriDualCommitmentTopology::SharedMaster ? 1U : 2U;
    out.commitment_binding_bits =
        static_cast<double>(kRCFri3AlgDualAlgHashCollisionBits) -
        out.global_site_log2 -
        std::log2(static_cast<double>(out.binding_events_per_site));
    if (topology == FriDualCommitmentTopology::TwoCommonRoots) {
        // This is not used by composed_union_bits.  Domain tags alone do not
        // establish independence for two invocations of the same algebraic
        // sponge, so the deployable/conservative screen remains the union of
        // two 128-bit binding events above.
        out.independence_amplified_binding_bits =
            2.0 *
                static_cast<double>(
                    kRCFri3AlgDualAlgHashCollisionBits) -
            out.global_site_log2;
    }

    // Stable evaluation of -log2(2^-a + 2^-b).
    const double smaller =
        std::min(out.fri_all_query_bits, out.commitment_binding_bits);
    const double larger =
        std::max(out.fri_all_query_bits, out.commitment_binding_bits);
    out.composed_union_bits =
        smaller - std::log2(1.0 + std::exp2(smaller - larger));
    out.parameters_valid =
        std::isfinite(out.composed_union_bits) &&
        out.fri_all_query_bits > 0.0 &&
        out.commitment_binding_bits > 0.0;
    out.numerical_target_met =
        out.parameters_valid &&
        out.composed_union_bits >= kNarrowTargetSoundnessBits;

    // These are theorem/backend facts, not options supplied to this numeric
    // evaluator.  Keep every authority gate fail-closed.
    out.two_common_root_backend_executable = false;
    out.binding_independence_reduction_complete = false;
    out.exact_site_manifest_backend_enforced = false;
    out.commitment_hybrid_reduction_complete = false;
    out.formal_reduction_complete = false;
    out.authority_eligible = false;
    out.note =
        topology == FriDualCommitmentTopology::TwoCommonRoots
            ? "narrow_vcs:hybrid_bound:two_common_roots_independence_open"
            : out.numerical_target_met
            ? "narrow_vcs:hybrid_bound:numeric_target_met_reduction_open"
            : "narrow_vcs:hybrid_bound:numeric_target_missed";
    return out;
}

static_assert(!kNarrowVcsExecutable);
static_assert(!kNarrowVcsProductionReady);

} // namespace matmul::v4::rc::narrow_recurse
