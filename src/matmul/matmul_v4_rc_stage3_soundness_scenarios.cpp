// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>

#include <hash.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_stage3_coupled.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>
#include <matmul/matmul_v4_rc_stage3_unified_root.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstring>
#include <limits>
#include <set>
#include <utility>

namespace matmul::v4::rc::soundness_scenarios {
namespace {

constexpr double TARGET_BITS = 100.0;
constexpr uint32_t RATE_INVERSE_LOG2 = 4;
constexpr uint32_t LIST_PARAMETER_M = 3;

uint64_t CeilDiv(uint64_t value, uint64_t divisor)
{
    return value / divisor + (value % divisor != 0);
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

bool NextPow2(uint64_t value, uint64_t& out)
{
    if (value == 0) return false;
    out = 1;
    while (out < value) {
        if (out > (std::numeric_limits<uint64_t>::max() >> 1)) return false;
        out <<= 1;
    }
    return true;
}

uint32_t CeilLog2(uint64_t value)
{
    if (value <= 1) return 0;
    uint32_t out{0};
    --value;
    while (value != 0) {
        value >>= 1;
        ++out;
    }
    return out;
}

double Log2Add(double a, double b)
{
    const double larger = std::max(a, b);
    const double smaller = std::min(a, b);
    return larger + std::log2(1.0 + std::exp2(smaller - larger));
}

double Log2BcsError(double query_log2,
                    double rbr_bits,
                    uint32_t random_oracle_bits)
{
    // log2(Q*e_rbr).
    const double rbr_term = query_log2 - rbr_bits;
    // log2(3*(Q^2+1)/2^kappa), evaluated without constructing Q.
    const double ro_term =
        std::log2(3.0) - static_cast<double>(random_oracle_bits) +
        2.0 * query_log2 +
        std::log2(1.0 + std::exp2(-2.0 * query_log2));
    return Log2Add(rbr_term, ro_term);
}

double AllQueryCrossoverBits(double rbr_bits,
                             uint32_t lanes,
                             uint64_t sites,
                             uint32_t random_oracle_bits)
{
    const double log_sites = std::log2(static_cast<double>(sites));
    const auto log_union_error = [&](double query_log2) {
        return log_sites +
               static_cast<double>(lanes) *
                   Log2BcsError(
                       query_log2, rbr_bits, random_oracle_bits);
    };

    // For Q>=1, Q/min(1,S*e_bcs(Q)^r) decreases up to the unique
    // S*e_bcs(Q)^r=1 crossover and increases afterward.  Binary search in
    // log2(Q) avoids underflow and gives the continuous minimum.  If the
    // union bound is already >=1 at Q=1, the lower bound is zero.
    if (log_union_error(0.0) >= 0.0) return 0.0;
    double low{0.0};
    double high{static_cast<double>(random_oracle_bits)};
    while (log_union_error(high) < 0.0 &&
           high < 4.0 * static_cast<double>(random_oracle_bits)) {
        high *= 2.0;
    }
    for (unsigned i = 0; i < 160; ++i) {
        const double middle = (low + high) / 2.0;
        if (log_union_error(middle) < 0.0) {
            low = middle;
        } else {
            high = middle;
        }
    }
    return low;
}

bool AddSiteEntry(ProductionProofSiteManifest& manifest,
                  ProductionProofSiteKind kind,
                  RCStage3RelationRole role,
                  uint64_t logical_units,
                  uint64_t units_per_site)
{
    if (logical_units == 0 || units_per_site == 0) return false;
    const uint64_t sites = CeilDiv(logical_units, units_per_site);
    uint64_t total{0};
    if (sites == 0 ||
        !CheckedAdd(manifest.relation_leaf_sites, sites, total)) {
        return false;
    }
    manifest.relation_leaf_sites = total;
    manifest.entries.push_back(
        {kind, role, logical_units, units_per_site, sites});
    return true;
}

uint64_t RefCells(const RCGkrLayout& layout, const RCGkrOperandRef& ref)
{
    if (ref.n_chunks == 0 ||
        ref.first_column > layout.columns.size() ||
        ref.n_chunks > layout.columns.size() - ref.first_column) {
        return 0;
    }
    uint64_t out{0};
    for (uint32_t i = 0; i < ref.n_chunks; ++i) {
        uint64_t next{0};
        if (!CheckedAdd(
                out, layout.columns[ref.first_column + i].len, next)) {
            return 0;
        }
        out = next;
    }
    return out;
}

bool AddMul(uint64_t a, uint64_t b, uint64_t& accumulator)
{
    uint64_t product{0};
    uint64_t next{0};
    if (!CheckedMul(a, b, product) ||
        !CheckedAdd(accumulator, product, next)) {
        return false;
    }
    accumulator = next;
    return true;
}

bool ExpansionHashCompressionUpperBound(
    uint64_t rows,
    uint64_t cols,
    uint64_t repetitions,
    uint32_t max_rejection_blocks_per_32_outputs,
    uint64_t& accumulator)
{
    uint64_t cells{0};
    uint64_t mantissa_blocks{0};
    uint64_t scale_codes{0};
    uint64_t one_expansion{0};
    uint64_t all_expansions{0};
    if (rows == 0 || cols == 0 || repetitions == 0 ||
        cols % kRCMxBlockLen != 0 ||
        !CheckedMul(rows, cols, cells) ||
        !CheckedMul(
            CeilDiv(cells, kRCMxBlockLen),
            max_rejection_blocks_per_32_outputs,
            mantissa_blocks) ||
        !CheckedMul(rows, cols / kRCMxBlockLen, scale_codes)) {
        return false;
    }
    // ExpandScaleStream emits 128 two-bit scale codes per 32-byte SHA block.
    if (!CheckedAdd(
            mantissa_blocks, CeilDiv(scale_codes, 128),
            one_expansion) ||
        !CheckedMul(one_expansion, repetitions, all_expansions) ||
        !CheckedAdd(accumulator, all_expansions, accumulator)) {
        return false;
    }
    return true;
}

bool Sha256dCompressionCount(uint64_t message_bytes, uint64_t& out)
{
    // First SHA pass has the standard 0x80 byte and 8-byte bit length.  The
    // second pass always hashes the 32-byte first digest in one compression.
    uint64_t padded{0};
    if (!CheckedAdd(message_bytes, 9, padded)) return false;
    return CheckedAdd(CeilDiv(padded, 64), 1, out);
}

bool AddRecursiveAggregationSites(ProductionProofSiteManifest& manifest)
{
    const auto& order = RCStage3UnifiedRoleOrder();
    std::array<uint64_t, kRCStage3UnifiedRoleCount> leaves{};
    for (const auto& entry : manifest.entries) {
        const auto role = std::find(order.begin(), order.end(), entry.role);
        if (role == order.end()) return false;
        const size_t index =
            static_cast<size_t>(std::distance(order.begin(), role));
        uint64_t next{0};
        if (!CheckedAdd(leaves[index], entry.proof_sites, next)) return false;
        leaves[index] = next;
    }
    const uint64_t arity = manifest.policy.aggregation_arity;
    if (arity < 2) return false;
    uint64_t nodes{0};
    for (uint64_t width : leaves) {
        if (width == 0) return false;
        while (width > 1) {
            const uint64_t parents = CeilDiv(width, arity);
            if (!CheckedAdd(nodes, parents, nodes)) return false;
            width = parents;
        }
    }
    manifest.below_root_aggregation_sites = nodes;
    // The fourteen completed role roots are leaves of the already fixed
    // normalized binary-16 tree.  Its fifteen internal proof nodes are new
    // sites; the role-root proofs themselves were counted above.
    manifest.final_tree_aggregation_sites =
        kRCStage3UnifiedInternalNodeCount;
    uint64_t total{0};
    if (!CheckedAdd(manifest.relation_leaf_sites, nodes, total) ||
        !CheckedAdd(
            total, manifest.final_tree_aggregation_sites, total)) {
        return false;
    }
    manifest.total_proof_sites = total;
    return NextPow2(total, manifest.union_bound_cap);
}

bool EntryOrderAndCoverageAreExact(
    const std::vector<ProductionProofSiteEntry>& entries)
{
    if (entries.empty()) return false;
    uint8_t previous = 0;
    std::set<RCStage3RelationRole> roles;
    for (const auto& entry : entries) {
        const uint8_t kind = static_cast<uint8_t>(entry.kind);
        if (kind <= previous || entry.logical_units == 0 ||
            entry.units_per_site == 0 ||
            entry.proof_sites !=
                CeilDiv(entry.logical_units, entry.units_per_site)) {
            return false;
        }
        previous = kind;
        roles.insert(entry.role);
    }
    for (const auto role : RCStage3UnifiedRoleOrder()) {
        if (!roles.contains(role)) return false;
    }
    return roles.size() == kRCStage3UnifiedRoleCount;
}

} // namespace

ProductionSiteInventory AssessProductionSiteInventory()
{
    ProductionSiteInventory out;
    const RCEpisodeParams params = MakeDatacenterRCEpisodeParams();
    const RCGkrLayout layout = RCGkrTraceLayout(params);
    out.gemm_layers = layout.layers.size();

    for (const auto& layer : layout.layers) {
        if (layer.n == 0 ||
            layer.m > std::numeric_limits<uint64_t>::max() / layer.n) {
            return out;
        }
        const uint64_t cells =
            static_cast<uint64_t>(layer.m) * layer.n;
        if (cells > std::numeric_limits<uint64_t>::max() - out.gemm_cells ||
            cells % kRCMxBlockLen != 0) {
            return out;
        }
        out.gemm_cells += cells;
        const uint64_t tiles = cells / kRCMxBlockLen;
        if (tiles >
            std::numeric_limits<uint64_t>::max() - out.extract_tiles) {
            return out;
        }
        out.extract_tiles += tiles;
        out.signed_range_shards +=
            CeilDiv(cells, kRCStage3SignedRangeMaxShardRows);
        out.scale_schedule_shards +=
            CeilDiv(tiles, kRCStage3ScaleScheduleMaxShardTiles);
    }

    out.range_ctl_child_air_invocations = 2 * out.signed_range_shards;
    out.known_leaf_air_invocations =
        out.signed_range_shards + out.range_ctl_child_air_invocations;
    out.final_tree_sites = RCStage3UnifiedSoundnessSiteManifest().size();
    out.known_sites_including_final_tree =
        out.known_leaf_air_invocations + out.final_tree_sites;
    out.known_sites_log2_ceiling =
        CeilLog2(out.known_sites_including_final_tree);
    const auto root = CanonicalRCStage3UnifiedRootParameters();
    out.declared_candidate_site_budget =
        root.soundness_union_bound_instances;
    out.declared_candidate_site_log2 =
        CeilLog2(out.declared_candidate_site_budget);

    out.profile2_layout_exact =
        out.gemm_layers == 400 &&
        out.gemm_cells == 347'490'222'080ULL &&
        out.extract_tiles == 10'859'069'440ULL &&
        out.signed_range_shards == 331'400 &&
        out.scale_schedule_shards == 10'472;
    out.final_tree_manifest_exact =
        out.final_tree_sites == kRCStage3UnifiedSoundnessSiteCount;
    out.known_sites_fit_declared_budget =
        out.known_sites_including_final_tree <=
        out.declared_candidate_site_budget;

    // The current registry does not enumerate the all-tile Extract, SHA,
    // GEMM-opening and below-root recursive aggregation sites.  Zero means
    // unknown, never "there are no more sites".
    out.complete_global_site_upper_bound = 0;
    out.complete_global_upper_bound_manifest_derived = false;
    const ProductionProofSiteManifest conditional =
        BuildProductionProofSiteManifest(
            SelectedProductionProofSitePolicy());
    out.conditional_stage3_site_upper_bound =
        conditional.union_bound_cap;
    out.conditional_stage3_site_log2 =
        conditional.union_bound_log2;
    out.conditional_rejection_blocks_per_32_outputs =
        conditional.policy.max_rejection_blocks_per_32_outputs;
    out.conditional_stage3_upper_bound_manifest_derived =
        conditional.complete_global_upper_bound_manifest_derived;
    out.declared_budget_enforced_by_executable_backend = false;
    return out;
}

ProductionProofSitePolicy SelectedProductionProofSitePolicy()
{
    ProductionProofSitePolicy out =
        UnpackedProductionProofSitePolicy();
    // Four independent 152-column public-boundary machines occupy 608
    // columns, leaving 484 columns beneath the normalized 1,092-column cap.
    // This exact direct product has an Fp3 quotient prove/verify regression.
    out.hash_parallel_lanes =
        stage3_hash_air::kFixedProgramPackedLanes;
    // 2^18 is the selected V1 relation shard cap. Registered builders accept
    // it and it materially improves the exact global ledger over 2^16. The
    // scheduler pins it below; authority remains unavailable until the
    // production peak-memory preflight and recursive child consumption run.
    out.relation_rows_per_site =
        kSelectedProductionRelationRowsPerSiteV1;
    return out;
}

ProductionProofSitePolicy UnpackedProductionProofSitePolicy()
{
    ProductionProofSitePolicy out;
    // Four blocks expose 512 candidate nibbles for 32 outputs.  This is a
    // proposed fail-closed Stage-3 rule, not a property of today's unbounded
    // solver.  Arity four is the largest shape supported by the registered
    // recursive child carrier.
    out.max_rejection_blocks_per_32_outputs =
        kRCStage3V1MaxRejectionBlocksPer32;
    out.aggregation_arity = kRCStage3RecursiveMaxChildren;
    return out;
}

ProductionProofSiteManifest
BuildProductionProofSiteManifest(const ProductionProofSitePolicy& policy)
{
    ProductionProofSiteManifest out;
    out.policy = policy;
    if (policy.version != 1 ||
        policy.relation_rows_per_site == 0 ||
        policy.hash_program_rows_per_instance == 0 ||
        policy.max_air_trace_rows == 0 ||
        policy.hash_program_rows_per_instance >
            policy.max_air_trace_rows ||
        policy.max_air_trace_rows %
                policy.hash_program_rows_per_instance !=
            0 ||
        policy.hash_parallel_lanes == 0 ||
        policy.hash_parallel_lanes >
            stage3_hash_air::kFixedProgramMaxPackedLanes ||
        static_cast<uint32_t>(policy.hash_parallel_lanes) *
                stage3_hash_air::kFixedProgramBoundaryColumns >
            stage3_hash_air::kFixedProgramRecursiveWidthCap ||
        policy.aggregation_arity < 2 ||
        policy.aggregation_arity > 16) {
        return out;
    }

    // A zero cap exactly models the current computation's unbounded
    // rejection loops.  No finite proof-site upper bound follows.
    if (policy.max_rejection_blocks_per_32_outputs == 0) return out;
    // Do not multiply maximum trace height by the public four-lane packing
    // factor here.  No executable proof-owned construction composes those two
    // capacities.  The complete semantic product currently proves private
    // boundary cells in chunks of 32 for SHA and one for ChaCha; those are the
    // only sound units-per-site values for the production inventory.
    constexpr uint64_t sha_instances_per_site =
        kProductionPrivateShaSourcesPerProofSiteV1;
    constexpr uint64_t chacha_instances_per_site =
        kProductionPrivateChaChaSourcesPerProofSiteV1;

    const RCEpisodeParams episode = MakeDatacenterRCEpisodeParams();
    const RCGkrLayout layout = RCGkrTraceLayout(episode);
    if (layout.layers.empty()) return out;

    // Unique seed/XOF-generated operands.  Datacenter Q and X0 are fresh per
    // round; K/V and the FFN weight pair are episode-shared and can be proved
    // once then equality-wired to every consumer.  X0 has an independent XOF
    // stream per 32-row block, so charge each stream separately.
    uint64_t builder_hash_blocks{0};
    const bool shared = UseDatacenterSharedFfnWeights(episode);
    const uint64_t shared_repetitions = shared ? 1 : episode.rounds;
    const uint64_t weight_repetitions =
        shared ? 1 :
        static_cast<uint64_t>(episode.rounds) * episode.L_lyr;
    const uint64_t x0_streams =
        static_cast<uint64_t>(episode.rounds) *
        (UseDatacenterRowBlockX0(episode) ?
             episode.b_seq / kRCX0RowBlockRows :
             1);
    if (!ExpansionHashCompressionUpperBound(
            episode.n_q, episode.d_head, episode.rounds,
            policy.max_rejection_blocks_per_32_outputs,
            builder_hash_blocks) ||
        !ExpansionHashCompressionUpperBound(
            episode.n_ctx, episode.d_head, shared_repetitions,
            policy.max_rejection_blocks_per_32_outputs,
            builder_hash_blocks) ||
        !ExpansionHashCompressionUpperBound(
            episode.n_ctx, episode.d_head, shared_repetitions,
            policy.max_rejection_blocks_per_32_outputs,
            builder_hash_blocks) ||
        !ExpansionHashCompressionUpperBound(
            UseDatacenterRowBlockX0(episode) ?
                kRCX0RowBlockRows : episode.b_seq,
            episode.d_model, x0_streams,
            policy.max_rejection_blocks_per_32_outputs,
            builder_hash_blocks) ||
        !ExpansionHashCompressionUpperBound(
            episode.d_model, episode.d_ff, weight_repetitions,
            policy.max_rejection_blocks_per_32_outputs,
            builder_hash_blocks) ||
        !ExpansionHashCompressionUpperBound(
            episode.d_ff, episode.d_model, weight_repetitions,
            policy.max_rejection_blocks_per_32_outputs,
            builder_hash_blocks)) {
        return {};
    }
    // Tagged seed/key derivations are small next to the streams. Charge three
    // SHA compression rows each, a conservative maximum for every registered
    // tag+32/40-byte payload including padding.
    const uint64_t builder_seed_derivations =
        8 + 3 * static_cast<uint64_t>(episode.rounds) +
        x0_streams +
        2 * static_cast<uint64_t>(episode.rounds) * episode.L_lyr +
        2 * shared_repetitions +
        2 * weight_repetitions;
    uint64_t builder_seed_hash_blocks{0};
    if (!CheckedMul(
            builder_seed_derivations, 3, builder_seed_hash_blocks) ||
        !CheckedAdd(
            builder_hash_blocks, builder_seed_hash_blocks,
            builder_hash_blocks) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::EpisodeBuilderCounterXof,
            RCStage3RelationRole::EpisodeDeterministicBuilder,
            builder_hash_blocks, sha_instances_per_site)) {
        return {};
    }

    if (!AddSiteEntry(
            out, ProductionProofSiteKind::EpisodeGemmSumcheck,
            RCStage3RelationRole::EpisodeGemm,
            layout.layers.size(), 1)) {
        return {};
    }
    uint64_t opening_cells{0};
    for (const auto& layer : layout.layers) {
        const uint64_t a = RefCells(layout, layer.a);
        const uint64_t b = RefCells(layout, layer.b);
        uint64_t y{0};
        uint64_t next{0};
        if (a == 0 || b == 0 ||
            !CheckedMul(layer.m, layer.n, y) ||
            !CheckedAdd(opening_cells, a, next) ||
            !CheckedAdd(next, b, next) ||
            !CheckedAdd(next, y, opening_cells)) {
            return {};
        }
    }
    if (!AddSiteEntry(
            out, ProductionProofSiteKind::EpisodeGemmOpenings,
            RCStage3RelationRole::EpisodeGemm,
            opening_cells, policy.relation_rows_per_site)) {
        return {};
    }

    uint64_t signed_range_shards{0};
    uint64_t extract_core_shards{0};
    for (const auto& layer : layout.layers) {
        uint64_t cells{0};
        if (!CheckedMul(layer.m, layer.n, cells) ||
            !CheckedAdd(
                signed_range_shards,
                CeilDiv(cells, kRCStage3SignedRangeMaxShardRows),
                signed_range_shards) ||
            !CheckedAdd(
                extract_core_shards,
                CeilDiv(cells, policy.relation_rows_per_site),
                extract_core_shards)) {
            return {};
        }
    }
    if (!AddSiteEntry(
            out, ProductionProofSiteKind::EpisodeSignedRange,
            RCStage3RelationRole::EpisodeGemm,
            signed_range_shards, 1) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::EpisodeRangeExtractCtl,
            RCStage3RelationRole::EpisodeExtract,
            2 * signed_range_shards, 1) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::EpisodeExtractCore,
            RCStage3RelationRole::EpisodeExtract,
            extract_core_shards, 1)) {
        return {};
    }

    const uint64_t extract_tiles =
        layout.trace_cells / kRCMxBlockLen;
    if (layout.trace_cells % kRCMxBlockLen != 0 ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::EpisodeScaleSha,
            RCStage3RelationRole::EpisodeExtract,
            2 * extract_tiles, sha_instances_per_site)) {
        return {};
    }
    uint64_t extract_chacha_blocks{0};
    if (!CheckedMul(
            extract_tiles,
            policy.max_rejection_blocks_per_32_outputs,
            extract_chacha_blocks) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::EpisodeExtractChaCha,
            RCStage3RelationRole::EpisodeExtract,
            extract_chacha_blocks, chacha_instances_per_site)) {
        return {};
    }
    if (!AddSiteEntry(
            out, ProductionProofSiteKind::EpisodeWiring,
            RCStage3RelationRole::EpisodeWiring,
            layout.total_cells, policy.relation_rows_per_site)) {
        return {};
    }

    uint64_t tile_tree_compressions{0};
    uint64_t leaf_sha_compressions{0};
    uint64_t internal_sha_compressions{0};
    if (!Sha256dCompressionCount(
            static_cast<uint64_t>(episode.T_leaf) + 1,
            leaf_sha_compressions) ||
        !Sha256dCompressionCount(65, internal_sha_compressions)) {
        return {};
    }
    uint64_t round_stream_bytes{0};
    if (!AddMul(
            episode.n_q, episode.d_head, round_stream_bytes)) {
        return {};
    }
    uint64_t phase2_output_bytes{0};
    if (!CheckedMul(
            episode.b_seq, episode.d_model,
            phase2_output_bytes) ||
        !CheckedMul(
            phase2_output_bytes, episode.L_lyr,
            phase2_output_bytes) ||
        !CheckedAdd(
            round_stream_bytes, phase2_output_bytes,
            round_stream_bytes)) {
        return {};
    }
    for (uint32_t round = 0; round < episode.rounds; ++round) {
        const uint64_t bytes = round_stream_bytes;
        const uint64_t logical_leaves =
            std::max<uint64_t>(1, CeilDiv(bytes, episode.T_leaf));
        uint64_t padded_leaves{0};
        uint64_t leaf_work{0};
        uint64_t internal_work{0};
        if (!NextPow2(logical_leaves, padded_leaves) ||
            !CheckedMul(
                logical_leaves, leaf_sha_compressions, leaf_work) ||
            (padded_leaves != logical_leaves &&
             !CheckedAdd(
                 leaf_work, leaf_sha_compressions, leaf_work)) ||
            !CheckedMul(
                padded_leaves - 1,
                internal_sha_compressions, internal_work) ||
            !CheckedAdd(
                tile_tree_compressions, leaf_work,
                tile_tree_compressions) ||
            !CheckedAdd(
                tile_tree_compressions, internal_work,
                tile_tree_compressions)) {
            return {};
        }
    }
    uint64_t episode_digest_compressions{0};
    if (!Sha256dCompressionCount(
            (sizeof(kRCEpisodeTag) - 1) +
                static_cast<uint64_t>(episode.rounds) * 32,
            episode_digest_compressions) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::EpisodeTileTreeSha256d,
            RCStage3RelationRole::EpisodeTileTree,
            tile_tree_compressions, sha_instances_per_site) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::EpisodeDigestSha256d,
            RCStage3RelationRole::EpisodeDigest,
            episode_digest_compressions, sha_instances_per_site)) {
        return {};
    }

    const RCCoupParams coupled_params = MakeProductionV3RCCoupParams();
    const RCCoupOptions coupled_options = MakeV4RCCoupOptions();
    const RCStage3CoupledShape coupled =
        MakeRCStage3CoupledShape(coupled_params, coupled_options);
    const uint64_t state_bytes = coupled_params.StateBytes();
    uint64_t all_state_cells{0};
    uint64_t bank_cells{0};
    uint64_t scheduled_pages{0};
    uint64_t coupled_gemm_cells{0};
    if (!CheckedMul(coupled.barriers, state_bytes, all_state_cells) ||
        !CheckedMul(
            coupled.bank_pages, coupled.lobe_width, bank_cells) ||
        !CheckedMul(bank_cells, coupled.lobe_width, bank_cells) ||
        !CheckedMul(coupled.barriers, coupled.lobes, scheduled_pages) ||
        !CheckedMul(
            scheduled_pages, coupled.pages_per_barrier_lobe,
            scheduled_pages) ||
        !CheckedMul(
            scheduled_pages, coupled.rows_per_lobe,
            coupled_gemm_cells) ||
        !CheckedMul(
            coupled_gemm_cells, coupled.lobe_width,
            coupled_gemm_cells)) {
        return {};
    }
    const auto& coupled_tags =
        RCCoupDomainTagsForVersion(coupled.transcript_version);

    // The 96-GiB production V3 bank is itself a deterministic XOF relation,
    // followed by one streaming SHA256d commitment over all expanded bytes.
    // Both must be in the global union; counting only lookup/GEMM rows would
    // materially undercharge the proof inventory.
    uint64_t coupled_bank_xof_compressions{0};
    uint64_t coupled_bank_seed_compressions{0};
    uint64_t coupled_bank_commitment_compressions{0};
    if (!ExpansionHashCompressionUpperBound(
            coupled.lobe_width, coupled.lobe_width,
            coupled.bank_pages,
            policy.max_rejection_blocks_per_32_outputs,
            coupled_bank_xof_compressions) ||
        !CheckedMul(
            static_cast<uint64_t>(coupled.bank_pages) + 1,
            3, coupled_bank_seed_compressions) ||
        !CheckedAdd(
            coupled_bank_xof_compressions,
            coupled_bank_seed_compressions,
            coupled_bank_xof_compressions) ||
        !Sha256dCompressionCount(
            std::strlen(coupled_tags.bank) + bank_cells,
            coupled_bank_commitment_compressions) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledBankCounterXof,
            RCStage3RelationRole::CoupledBank,
            coupled_bank_xof_compressions, sha_instances_per_site) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledBankCommitmentSha256d,
            RCStage3RelationRole::CoupledBank,
            coupled_bank_commitment_compressions,
            sha_instances_per_site) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledBank,
            RCStage3RelationRole::CoupledBank,
            bank_cells, policy.relation_rows_per_site)) {
        return {};
    }

    uint64_t coupled_lobe_xof_compressions{0};
    uint64_t coupled_page_schedule_xof_compressions{0};
    if (!ExpansionHashCompressionUpperBound(
            coupled.rows_per_lobe, coupled.lobe_width, coupled.lobes,
            policy.max_rejection_blocks_per_32_outputs,
            coupled_lobe_xof_compressions) ||
        !CheckedAdd(
            coupled_lobe_xof_compressions,
            3 * static_cast<uint64_t>(coupled.lobes),
            coupled_lobe_xof_compressions) ||
        !CheckedAdd(
            CeilDiv(coupled.bank_pages - 1, 8), 3,
            coupled_page_schedule_xof_compressions) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledLobeInitCounterXof,
            RCStage3RelationRole::CoupledGemm,
            coupled_lobe_xof_compressions, sha_instances_per_site) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledPageScheduleXof,
            RCStage3RelationRole::CoupledGemm,
            coupled_page_schedule_xof_compressions,
            sha_instances_per_site) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledGemm,
            RCStage3RelationRole::CoupledGemm,
            coupled_gemm_cells, policy.relation_rows_per_site)) {
        return {};
    }

    uint64_t coupled_exchange_xof_compressions{0};
    uint64_t exchange_xor_blocks{0};
    uint64_t exchange_permutation_blocks{0};
    uint64_t exchange_rounds{0};
    if (!CheckedMul(
            coupled.barriers, coupled_options.exchange_rounds,
            exchange_rounds) ||
        !CheckedMul(
            CeilDiv(state_bytes, 4), exchange_rounds,
            exchange_xor_blocks) ||
        !CheckedMul(
            CeilDiv(state_bytes - 1, 8), exchange_rounds,
            exchange_permutation_blocks) ||
        !CheckedAdd(
            exchange_xor_blocks, exchange_permutation_blocks,
            coupled_exchange_xof_compressions) ||
        !CheckedAdd(
            coupled_exchange_xof_compressions, 3 * exchange_rounds,
            coupled_exchange_xof_compressions) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledExchange,
            RCStage3RelationRole::CoupledExchange,
            all_state_cells, policy.relation_rows_per_site) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledExchangeXof,
            RCStage3RelationRole::CoupledExchange,
            coupled_exchange_xof_compressions,
            sha_instances_per_site)) {
        return {};
    }

    uint32_t state_bits{0};
    for (uint64_t width = state_bytes; width > 1; width >>= 1) {
        ++state_bits;
    }
    uint64_t coupled_permutation_xof_compressions{0};
    if (!CheckedMul(
            coupled.barriers, CeilDiv(2 * state_bits, 8),
            coupled_permutation_xof_compressions) ||
        !CheckedAdd(
            coupled_permutation_xof_compressions,
            3 * static_cast<uint64_t>(coupled.barriers),
            coupled_permutation_xof_compressions) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledPermutation,
            RCStage3RelationRole::CoupledPermutation,
            all_state_cells, policy.relation_rows_per_site) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledPermutationXof,
            RCStage3RelationRole::CoupledPermutation,
            coupled_permutation_xof_compressions,
            sha_instances_per_site)) {
        return {};
    }

    const uint64_t coupled_mix_xof_compressions =
        4 * static_cast<uint64_t>(coupled.barriers);
    if (!AddSiteEntry(
            out, ProductionProofSiteKind::CoupledMix,
            RCStage3RelationRole::CoupledMix,
            all_state_cells, policy.relation_rows_per_site) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledMixXof,
            RCStage3RelationRole::CoupledMix,
            coupled_mix_xof_compressions, sha_instances_per_site) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledExtractCore,
            RCStage3RelationRole::CoupledExtract,
            all_state_cells, policy.relation_rows_per_site)) {
        return {};
    }
    const uint64_t coupled_extract_tiles =
        all_state_cells / kRCMxBlockLen;
    uint64_t coupled_chacha_blocks{0};
    uint64_t coupled_scale_compressions{0};
    if (all_state_cells % kRCMxBlockLen != 0 ||
        !CheckedMul(
            coupled_extract_tiles,
            policy.max_rejection_blocks_per_32_outputs,
            coupled_chacha_blocks) ||
        !CheckedMul(
            coupled_extract_tiles, 2, coupled_scale_compressions) ||
        !CheckedAdd(
            coupled_scale_compressions,
            6 * static_cast<uint64_t>(coupled.barriers),
            coupled_scale_compressions) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledExtractScaleSha,
            RCStage3RelationRole::CoupledExtract,
            coupled_scale_compressions, sha_instances_per_site) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledExtractChaCha,
            RCStage3RelationRole::CoupledExtract,
            coupled_chacha_blocks, chacha_instances_per_site)) {
        return {};
    }

    uint64_t barrier_compressions{0};
    uint64_t one_barrier_compressions{0};
    if (!Sha256dCompressionCount(
            std::strlen(coupled_tags.barrier) +
                sizeof(uint32_t) + state_bytes,
            one_barrier_compressions) ||
        !CheckedMul(
            coupled.barriers, one_barrier_compressions,
            barrier_compressions) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledBarrierSha256d,
            RCStage3RelationRole::CoupledBarrier,
            barrier_compressions, sha_instances_per_site)) {
        return {};
    }
    uint64_t coupled_digest_compressions{0};
    if (!Sha256dCompressionCount(
            std::strlen(coupled_tags.episode) + 32 +
                static_cast<uint64_t>(coupled.barriers) * 32,
            coupled_digest_compressions) ||
        !AddSiteEntry(
            out, ProductionProofSiteKind::CoupledDigestSha256d,
            RCStage3RelationRole::CoupledDigest,
            coupled_digest_compressions, sha_instances_per_site)) {
        return {};
    }

    if (!EntryOrderAndCoverageAreExact(out.entries) ||
        !AddRecursiveAggregationSites(out) ||
        !NextPow2(out.total_proof_sites, out.union_bound_cap)) {
        return {};
    }
    out.union_bound_log2 = CeilLog2(out.union_bound_cap);
    out.arithmetic_exact = true;
    out.all_registered_roles_covered = true;
    out.rejection_loops_bounded = true;
    out.executable_hash_parallel_packing =
        policy.hash_parallel_lanes == 1 ||
        (stage3_hash_air::kHashPackedBoundaryAirExecutable &&
         policy.hash_parallel_lanes ==
             stage3_hash_air::kFixedProgramPackedLanes);
    out.executable_private_hash_site_capacity =
        sha_instances_per_site ==
            kProductionPrivateShaSourcesPerProofSiteV1 &&
        chacha_instances_per_site ==
            kProductionPrivateChaChaSourcesPerProofSiteV1;
    out.backend_shape_supported =
        policy.aggregation_arity <= kRCStage3RecursiveMaxChildren &&
        policy.max_air_trace_rows <= (1U << 20) &&
        policy.hash_parallel_lanes <=
            stage3_hash_air::kFixedProgramMaxPackedLanes &&
        static_cast<uint32_t>(policy.hash_parallel_lanes) *
                stage3_hash_air::kFixedProgramBoundaryColumns <=
            stage3_hash_air::kFixedProgramRecursiveWidthCap &&
        out.executable_hash_parallel_packing &&
        out.executable_private_hash_site_capacity;
    // All rejection-producing proof/witness builders consume the same V1 cap:
    //  * stage3_hash_air::BuildCounterXofManifest (builder SHA XOF);
    //  * gkr_air::VerifyMxExpandColumn (operand expansion);
    //  * gkr_air::TraceTile/CheckTileConstraints (Extract ChaCha).
    // The normalized recursive scheduler still does not consume this global
    // manifest, so the aggregate backend gate remains fail-closed.
    out.executable_rejection_paths_enforce_policy =
        policy.max_rejection_blocks_per_32_outputs ==
        kRCStage3V1MaxRejectionBlocksPer32;
    out.recursive_scheduler_consumes_manifest = false;
    out.executable_backend_enforces_policy =
        out.executable_rejection_paths_enforce_policy &&
        out.executable_hash_parallel_packing &&
        out.recursive_scheduler_consumes_manifest;
    out.complete_global_upper_bound_manifest_derived =
        out.arithmetic_exact &&
        out.all_registered_roles_covered &&
        out.rejection_loops_bounded;
    out.commitment = CommitProductionProofSiteManifest(out);
    if (out.commitment.IsNull()) return {};
    return out;
}

uint256 CommitProductionProofSiteManifest(
    const ProductionProofSiteManifest& manifest)
{
    if (!manifest.arithmetic_exact ||
        !manifest.all_registered_roles_covered ||
        !manifest.rejection_loops_bounded ||
        manifest.entries.empty() ||
        manifest.total_proof_sites == 0 ||
        manifest.union_bound_cap < manifest.total_proof_sites) {
        return {};
    }
    HashWriter hash;
    hash << "BTX_RC_STAGE3_GLOBAL_PROOF_SITE_MANIFEST_V1";
    hash << manifest.policy.version;
    hash << manifest.policy.relation_rows_per_site;
    hash << manifest.policy.hash_program_rows_per_instance;
    hash << manifest.policy.max_air_trace_rows;
    hash << manifest.policy.max_rejection_blocks_per_32_outputs;
    hash << manifest.policy.hash_parallel_lanes;
    hash << manifest.policy.aggregation_arity;
    hash << static_cast<uint32_t>(manifest.entries.size());
    for (const auto& entry : manifest.entries) {
        hash << static_cast<uint8_t>(entry.kind);
        hash << static_cast<uint16_t>(entry.role);
        hash << entry.logical_units;
        hash << entry.units_per_site;
        hash << entry.proof_sites;
    }
    hash << manifest.relation_leaf_sites;
    hash << manifest.below_root_aggregation_sites;
    hash << manifest.final_tree_aggregation_sites;
    hash << manifest.total_proof_sites;
    hash << manifest.union_bound_cap;
    hash << manifest.union_bound_log2;
    return hash.GetHash();
}

bool ValidateProductionProofSiteManifest(
    const ProductionProofSiteManifest& manifest,
    std::string* why)
{
    const ProductionProofSiteManifest expected =
        BuildProductionProofSiteManifest(manifest.policy);
    if (expected.commitment.IsNull()) {
        if (why != nullptr) {
            *why = "stage3:site_manifest:policy_has_no_finite_cap";
        }
        return false;
    }
    if (manifest != expected ||
        manifest.commitment !=
            CommitProductionProofSiteManifest(manifest)) {
        if (why != nullptr) {
            *why = "stage3:site_manifest:noncanonical_or_substituted";
        }
        return false;
    }
    if (why != nullptr) {
        *why =
            "stage3:site_manifest:rejection_paths_bounded_"
            "recursive_consumption_pending";
    }
    return true;
}

std::vector<ProductionProofSiteScenario>
AssessProductionProofSiteScenarios()
{
    struct Candidate {
        const char* name;
        uint32_t relation_rows;
        uint32_t rejection_blocks;
        uint8_t hash_parallel_lanes;
        uint8_t arity;
    };
    constexpr std::array<Candidate, 8> CANDIDATES{{
        {"current_unbounded_binary", 1U << 16, 0, 1, 2},
        {"bounded4_binary_unpacked", 1U << 16, 4, 1, 2},
        {"bounded4_quaternary_unpacked", 1U << 16, 4, 1, 4},
        {"bounded4_quaternary_packed4_rows18", 1U << 18, 4, 4, 4},
        {"bounded4_quaternary_packed6_rows18", 1U << 18, 4, 6, 4},
        {"bounded4_quaternary_packed7_rows18", 1U << 18, 4, 7, 4},
        {"bounded8_quaternary_packed4_rows18", 1U << 18, 8, 4, 4},
        {"bounded4_arity16_packed4_rows18", 1U << 18, 4, 4, 16},
    }};
    std::vector<ProductionProofSiteScenario> out;
    out.reserve(CANDIDATES.size());
    const ProductionProofSitePolicy selected =
        SelectedProductionProofSitePolicy();
    for (const auto& candidate : CANDIDATES) {
        ProductionProofSitePolicy policy;
        policy.relation_rows_per_site =
            candidate.relation_rows;
        policy.max_rejection_blocks_per_32_outputs =
            candidate.rejection_blocks;
        policy.hash_parallel_lanes =
            candidate.hash_parallel_lanes;
        policy.aggregation_arity = candidate.arity;
        const ProductionProofSiteManifest manifest =
            BuildProductionProofSiteManifest(policy);
        ProductionProofSiteScenario scenario;
        scenario.name = candidate.name;
        scenario.policy = policy;
        scenario.total_proof_sites = manifest.total_proof_sites;
        scenario.union_bound_cap = manifest.union_bound_cap;
        scenario.union_bound_log2 = manifest.union_bound_log2;
        scenario.finite = !manifest.commitment.IsNull();
        scenario.recursive_arity_supported =
            candidate.arity <= kRCStage3RecursiveMaxChildren;
        scenario.selected = policy == selected;
        if (!scenario.finite) {
            scenario.note =
                "stage3:site_scenario:unbounded_rejection_no_finite_cap";
        } else if (!scenario.recursive_arity_supported) {
            scenario.note =
                "stage3:site_scenario:recursive_child_arity_unsupported";
        } else if (scenario.selected) {
            scenario.note =
                "stage3:site_scenario:selected_conditional_policy_"
                "backend_enforcement_pending";
        } else {
            scenario.note =
                "stage3:site_scenario:conditional_comparison_only";
        }
        out.push_back(std::move(scenario));
    }
    return out;
}

std::vector<SingleQ192PackingAssessment>
AssessSingleQ192PackingScenarios()
{
    constexpr std::array<uint8_t, 3> LANES{
        4, 6, 7};
    constexpr double ALG_HASH_BINDING_BITS =
        128.0;
    const double GOLDILOCKS_BITS =
        64.0 +
        std::log2(
            1.0 - std::ldexp(1.0, -32) +
            std::ldexp(1.0, -64));
    const double FIELD_BITS =
        3.0 * GOLDILOCKS_BITS;
    const double THEOREM_LOSS_BITS =
        7.0 * std::log2(3.5) -
        std::log2(3.0) + 6.0;
    // Independent batching has no (t-1) factor. The extra one bit is the
    // conservative A+B <= 2*max(A,B) charge for the BCS branch sum.
    const double CONSERVATIVE_SINGLE_FRI_BITS =
        FIELD_BITS - 2.0 * 24.0 -
        THEOREM_LOSS_BITS - 1.0;
    const auto compose = [](double a, double b) {
        const double smaller = std::min(a, b);
        const double larger = std::max(a, b);
        return smaller -
            std::log2(
                1.0 +
                std::exp2(smaller - larger));
    };

    std::vector<SingleQ192PackingAssessment> out;
    out.reserve(LANES.size());
    for (const uint8_t lanes : LANES) {
        ProductionProofSitePolicy policy =
            UnpackedProductionProofSitePolicy();
        policy.hash_parallel_lanes = lanes;
        const ProductionProofSiteManifest manifest =
            BuildProductionProofSiteManifest(policy);
        SingleQ192PackingAssessment item;
        item.hash_parallel_lanes = lanes;
        item.trace_width =
            static_cast<uint32_t>(lanes) *
            stage3_hash_air::
                kFixedProgramBoundaryColumns;
        item.trace_width_headroom =
            item.trace_width <=
                    stage3_hash_air::
                        kFixedProgramRecursiveWidthCap
                ? stage3_hash_air::
                      kFixedProgramRecursiveWidthCap -
                      item.trace_width
                : 0;
        item.global_sites =
            manifest.total_proof_sites;
        if (item.global_sites == 0) {
            item.note =
                "stage3:single_q192:invalid_site_manifest";
            out.push_back(std::move(item));
            continue;
        }
        item.global_site_log2 =
            std::log2(
                static_cast<double>(
                    item.global_sites));
        item.fri_bits =
            CONSERVATIVE_SINGLE_FRI_BITS -
            item.global_site_log2;
        item.per_site_binding_bits =
            ALG_HASH_BINDING_BITS -
            item.global_site_log2;
        item.per_site_composed_bits =
            compose(
                item.fri_bits,
                item.per_site_binding_bits);
        item.global_first_collision_binding_bits =
            ALG_HASH_BINDING_BITS;
        item.global_first_collision_composed_bits =
            compose(
                item.fri_bits,
                item.global_first_collision_binding_bits);
        item.width_and_trace_schedule_executable =
            lanes >= 2 &&
            lanes <=
                stage3_hash_air::
                    kFixedProgramMaxPackedLanes &&
            item.trace_width <=
                stage3_hash_air::
                    kFixedProgramRecursiveWidthCap;
        item.quotient_proof_wrapper_executable =
            lanes ==
                stage3_hash_air::
                    kFixedProgramPackedLanes &&
            stage3_hash_air::
                kHashPackedBoundaryAirExecutable;
        item.global_first_collision_reduction_complete =
            false;
        item.authority_eligible = false;
        item.note =
            item.global_first_collision_composed_bits >=
                    TARGET_BITS
                ? "stage3:single_q192:numeric_target_met_"
                  "only_under_open_global_collision_hybrid"
                : "stage3:single_q192:numeric_target_missed";
        out.push_back(std::move(item));
    }
    return out;
}

GlobalSoundnessV1Assessment
AssessGlobalSoundnessV1(
    uint32_t constraint_count_cap,
    uint32_t hash_collision_floor_bits,
    uint32_t hash_binding_events_per_site,
    GlobalSoundnessV1PowHashAccountingMode pow_hash_mode)
{
    GlobalSoundnessV1Assessment out;
    out.constraint_count_cap = constraint_count_cap;
    out.hash_collision_floor_bits =
        hash_collision_floor_bits;
    out.hash_binding_events_per_site =
        hash_binding_events_per_site;
    out.pow_hash_mode = pow_hash_mode;
    out.grinding_bits = kRCFriGrindingBits;
    out.trace_width_cap =
        CanonicalRCStage3UnifiedRootParameters()
            .max_recursive_air_columns;

    const ProductionProofSiteManifest manifest =
        BuildProductionProofSiteManifest(
            SelectedProductionProofSitePolicy());
    std::string manifest_why;
    out.canonical_site_manifest_derived =
        ValidateProductionProofSiteManifest(
            manifest, &manifest_why) &&
        manifest.complete_global_upper_bound_manifest_derived;
    if (out.canonical_site_manifest_derived) {
        out.global_sites = manifest.total_proof_sites;
        out.global_site_log2 =
            std::log2(
                static_cast<double>(
                    out.global_sites));
    }

    const bool mode_valid =
        pow_hash_mode ==
            GlobalSoundnessV1PowHashAccountingMode::
                TotalAdversaryWorkIncluded ||
        pow_hash_mode ==
            GlobalSoundnessV1PowHashAccountingMode::
                PerAttemptProbability;
    out.parameters_valid =
        out.canonical_site_manifest_derived &&
        constraint_count_cap != 0 &&
        hash_collision_floor_bits != 0 &&
        hash_binding_events_per_site != 0 &&
        mode_valid;
    if (!out.parameters_valid) {
        out.terms.push_back({
            GlobalSoundnessV1TermKind::
                GlobalAdditiveUnion,
            0.0,
            false,
            false,
            "invalid parameters or noncanonical production site manifest"});
        out.note =
            "stage3:global_soundness_v1:invalid_parameters";
        return out;
    }

    const double goldilocks_bits =
        64.0 +
        std::log2(
            1.0 - std::ldexp(1.0, -32) +
            std::ldexp(1.0, -64));
    const double field_bits =
        3.0 * goldilocks_bits;
    const double theorem_loss_bits =
        7.0 *
            std::log2(
                static_cast<double>(
                    LIST_PARAMETER_M) +
                0.5) -
        std::log2(3.0) +
        1.5 *
            static_cast<double>(
                RATE_INVERSE_LOG2);
    const double single_field_rbr_bits =
        field_bits -
        2.0 * 24.0 -
        theorem_loss_bits;
    out.coarse_q192_fri_bits =
        single_field_rbr_bits -
        1.0 -
        out.global_site_log2;

    const FriScenario exact_q192 =
        AssessFriScenario(
            "global_v1_exact_q192",
            1, 192, 3, 24,
            BatchChallengeShape::
                IndependentCoefficients,
            out.global_sites);
    const FriScenario dual_q136 =
        AssessFriScenario(
            "global_v1_dual_q136",
            2, 136, 3, 24,
            BatchChallengeShape::
                IndependentCoefficients,
            out.global_sites);
    if (!exact_q192.parameters_valid ||
        !dual_q136.parameters_valid) {
        out.parameters_valid = false;
        out.note =
            "stage3:global_soundness_v1:fri_screen_unavailable";
        return out;
    }
    out.exact_q192_fri_bits =
        exact_q192.all_query_work_bits;
    out.dual_q136_fri_bits =
        dual_q136.all_query_work_bits;

    // The algebraic ledger uses the same deliberately conservative
    // |Fp3|>2^189 floor as the unified-root ledger. Grinding is charged here
    // explicitly; the FRI values above are all-query work bounds and already
    // quantify over the adversary's total oracle work.
    constexpr double CONSERVATIVE_FP3_BITS =
        189.0;
    out.trace_batching_bits =
        CONSERVATIVE_FP3_BITS -
        out.global_site_log2 -
        static_cast<double>(
            out.grinding_bits) -
        std::log2(
            static_cast<double>(
                out.trace_width_cap) +
            2.0);
    out.constraint_batching_bits =
        CONSERVATIVE_FP3_BITS -
        out.global_site_log2 -
        static_cast<double>(
            out.grinding_bits) -
        std::log2(
            static_cast<double>(
                constraint_count_cap));
    out.hash_binding_bits =
        static_cast<double>(
            hash_collision_floor_bits) -
        out.global_site_log2 -
        std::log2(
            static_cast<double>(
                hash_binding_events_per_site));
    if (pow_hash_mode ==
        GlobalSoundnessV1PowHashAccountingMode::
            PerAttemptProbability) {
        out.hash_binding_bits -=
            static_cast<double>(
                out.grinding_bits);
    }

    const auto compose = [](std::initializer_list<double> bits) {
        double log_error =
            -std::numeric_limits<double>::infinity();
        for (const double exponent : bits) {
            if (!std::isfinite(exponent)) {
                return 0.0;
            }
            const double term = -exponent;
            if (!std::isfinite(log_error)) {
                log_error = term;
            } else {
                log_error =
                    Log2Add(log_error, term);
            }
        }
        return -log_error;
    };
    out.coarse_q192_known_terms_bits =
        compose({
            out.coarse_q192_fri_bits,
            out.trace_batching_bits,
            out.constraint_batching_bits,
            out.hash_binding_bits});
    out.exact_q192_known_terms_bits =
        compose({
            out.exact_q192_fri_bits,
            out.trace_batching_bits,
            out.constraint_batching_bits,
            out.hash_binding_bits});
    out.dual_q136_known_terms_bits =
        compose({
            out.dual_q136_fri_bits,
            out.trace_batching_bits,
            out.constraint_batching_bits,
            out.hash_binding_bits});

    // Executable facts. SplitRAP's current final backend is MultiRow-V2/Q192;
    // the additive Q136 backend exists but is not its final proof backend.
    out.multirow_v2_post_claim_batching_executable =
        kRCFri3AlgMultiRowBatchProofVersion == 2;
    out.split_rap_air_executable =
        kRCStage3EpisodeSignedRangeSplitRapCanaryExecutable;
    out.split_rap_uses_single_q192 =
        kRCFri3AlgNumQueries == 192;
    out.dual_q136_backend_executable =
        kRCFri3AlgDualQ136QueriesPerLane == 136 &&
        kRCFri3AlgDualQ136TotalQueries == 272;
    out.dual_q136_split_rap_integrated = false;

    // Global theorem gates remain fail closed. A count-only manifest does not
    // imply that the recursive verifier consumed every scheduled child.
    out.canonical_site_manifest_backend_enforced =
        manifest.executable_backend_enforces_policy;
    out.semantic_closure_complete = false;
    out.recursive_consumption_complete = false;
    out.ali_degree_manifest_complete = false;
    out.ctl_event_manifest_complete = false;
    out.fiat_shamir_query_manifest_complete = false;
    out.protocol_match_complete = false;
    out.hash_binding_reduction_complete = false;
    out.global_additive_union_complete = false;

    out.coarse_q192_numeric_target_met =
        out.coarse_q192_known_terms_bits >=
        out.target_bits;
    out.exact_q192_numeric_target_met =
        out.exact_q192_known_terms_bits >=
        out.target_bits;
    out.dual_q136_numeric_target_met =
        out.dual_q136_known_terms_bits >=
        out.target_bits;
    out.deterministic_prerequisites_complete =
        out.canonical_site_manifest_backend_enforced &&
        out.semantic_closure_complete &&
        out.recursive_consumption_complete;

    out.terms = {
        {GlobalSoundnessV1TermKind::SemanticClosure,
         0.0, false, false,
         "all 52 semantic endpoints must be equality constrained"},
        {GlobalSoundnessV1TermKind::RecursiveConsumption,
         0.0, false, false,
         "all 14 roles and every manifest site must consume a child proof"},
        {GlobalSoundnessV1TermKind::FriBcs,
         out.coarse_q192_fri_bits, true, false,
         "coarse Q192, exact-crossover Q192 and dual-Q136 are conditional "
         "comparison screens; protocol match remains open"},
        {GlobalSoundnessV1TermKind::TraceBatching,
         out.trace_batching_bits, true, false,
         "conservative Fp3 width-cap union with 40-bit grinding"},
        {GlobalSoundnessV1TermKind::ConstraintBatching,
         out.constraint_batching_bits, true, false,
         "caller-supplied per-site constraint cap is not manifest-derived"},
        {GlobalSoundnessV1TermKind::AliQuotientIdentity,
         0.0, false, false,
         "global degree/domain/query inventory absent"},
        {GlobalSoundnessV1TermKind::CtlLogUp,
         0.0, false, false,
         "global CTL bus/event manifest and recursive reduction absent"},
        {GlobalSoundnessV1TermKind::HashBinding,
         out.hash_binding_bits, true, false,
         "binding-event count is explicit; commitment hybrid/extractor open"},
        {GlobalSoundnessV1TermKind::FiatShamir,
         0.0, false, false,
         "whole-verifier query manifest and ROM/NIROP composition absent"},
        {GlobalSoundnessV1TermKind::GlobalAdditiveUnion,
         0.0, false, false,
         "known-term screens omit open ALI/CTL/FS and deterministic terms"},
    };

    out.theorem_complete =
        out.parameters_valid &&
        out.deterministic_prerequisites_complete &&
        out.ali_degree_manifest_complete &&
        out.ctl_event_manifest_complete &&
        out.fiat_shamir_query_manifest_complete &&
        out.protocol_match_complete &&
        out.hash_binding_reduction_complete &&
        out.global_additive_union_complete &&
        std::all_of(
            out.terms.begin(),
            out.terms.end(),
            [](const GlobalSoundnessV1Term& term) {
                return
                    term.quantitatively_accounted &&
                    term.reduction_complete;
            });
    out.certified_bits = 0;
    out.authority_eligible = false;
    out.note =
        out.dual_q136_numeric_target_met
            ? "stage3:global_soundness_v1:"
              "conditional_numeric_target_met_global_gates_open"
            : "stage3:global_soundness_v1:"
              "conditional_numeric_target_missed";
    return out;
}

RecursiveBackendComparisonV1
AssessRecursiveBackendComparisonV1()
{
    RecursiveBackendComparisonV1 out;
    const ProductionProofSiteManifest manifest =
        BuildProductionProofSiteManifest(
            SelectedProductionProofSitePolicy());
    if (!manifest.arithmetic_exact ||
        !manifest.complete_global_upper_bound_manifest_derived ||
        !ValidateProductionProofSiteManifest(
            manifest, nullptr)) {
        out.note =
            "stage3:recursive_backend_v1:"
            "noncanonical_global_manifest";
        return out;
    }
    out.current_global_sites =
        manifest.total_proof_sites;
    out.relation_local_instances = 326;
    if (out.current_global_sites >
        std::numeric_limits<uint64_t>::max() /
            out.relation_local_instances) {
        out.note =
            "stage3:recursive_backend_v1:"
            "site_product_overflow";
        return out;
    }
    out.product_topology_sites =
        out.current_global_sites *
        out.relation_local_instances;
    out.product_topology_log2 =
        std::log2(
            static_cast<double>(
                out.product_topology_sites));
    // Retained only as a rejected-architecture diagnostic. The exact site
    // manifest already counts heterogeneous leaf and parent invocations.
    // A root-pinned constant-width universal verifier does not instantiate
    // this monolithic width decomposition at every site.
    out.relation_local_nodes_in_current_manifest =
        false;
    out.product_topology_is_production_theorem =
        false;
    out.canonical_heterogeneous_topology_manifest_derived =
        true;
    out.width_planner_instances_are_site_multiplicity =
        false;
    out.product_topology_rejected = true;
    out.universal_program_selection_binding_defined =
        true;
    out.universal_program_selection_consumed_in_recursive_air =
        false;

    const auto append =
        [&](RecursiveBackendTacticV1 tactic,
            uint32_t lanes,
            uint32_t queries,
            uint32_t extension_degree,
            bool primitive,
            bool split_rap,
            bool duplicated,
            bool oracle_separation,
            bool recursive_air,
            bool formal,
            bool selected,
            const char* note) {
            RecursiveBackendScenarioV1 item;
            item.tactic = tactic;
            item.lanes = lanes;
            item.queries_per_lane = queries;
            item.extension_degree =
                extension_degree;
            const FriScenario per_proof =
                AssessFriScenario(
                    "recursive_backend_per_proof",
                    lanes, queries,
                    extension_degree, 24,
                    BatchChallengeShape::
                        IndependentCoefficients,
                    1);
            const FriScenario current_global =
                AssessFriScenario(
                    "recursive_backend_current_global",
                    lanes, queries,
                    extension_degree, 24,
                    BatchChallengeShape::
                        IndependentCoefficients,
                    out.current_global_sites);
            const FriScenario product =
                AssessFriScenario(
                    "recursive_backend_product",
                    lanes, queries,
                    extension_degree, 24,
                    BatchChallengeShape::
                        IndependentCoefficients,
                    out.product_topology_sites);
            if (per_proof.parameters_valid &&
                current_global.parameters_valid &&
                product.parameters_valid) {
                item.per_proof_fri_bits =
                    per_proof.all_query_work_bits;
                item.current_global_manifest_fri_bits =
                    current_global.all_query_work_bits;
                item.product_topology_fri_bits =
                    product.all_query_work_bits;
            }
            item.proof_primitive_executable = primitive;
            item.split_rap_integrated = split_rap;
            item.fully_duplicated_lane_commitments =
                duplicated;
            item.full_oracle_domain_separation_proven =
                oracle_separation;
            item.recursive_verifier_air_executable =
                recursive_air;
            item.formal_reduction_complete = formal;
            item.selected_executable_baseline =
                selected;
            item.note = note;
            out.scenarios.push_back(std::move(item));
        };

    append(
        RecursiveBackendTacticV1::
            ExecutableSingleFp3Q192,
        1, 192, 3,
        /*primitive=*/true,
        /*split_rap=*/true,
        /*duplicated=*/false,
        /*oracle_separation=*/true,
        /*recursive_air=*/false,
        /*formal=*/false,
        /*selected=*/true,
        "executable honest baseline; recursive verifier AIR and global "
        "topology theorem remain open");
    append(
        RecursiveBackendTacticV1::
            DuplicatedDomainSeparatedFp3Q136,
        2, 136, 3,
        /*primitive=*/true,
        /*split_rap=*/false,
        /*duplicated=*/true,
        /*oracle_separation=*/false,
        /*recursive_air=*/false,
        /*formal=*/false,
        /*selected=*/false,
        "two separately lane-prefixed Q136 commitments execute; "
        "SplitRAP adapter and NIROP independence reduction remain open");
    append(
        RecursiveBackendTacticV1::
            HypotheticalFp4Q192,
        1, 192, 4,
        /*primitive=*/false,
        /*split_rap=*/false,
        /*duplicated=*/false,
        /*oracle_separation=*/false,
        /*recursive_air=*/false,
        /*formal=*/false,
        /*selected=*/false,
        "Fp4 numerical screen only; field, PCS, codec and recursive chips "
        "are absent");

    out.at_least_one_proof_primitive_executable =
        std::any_of(
            out.scenarios.begin(), out.scenarios.end(),
            [](const auto& item) {
                return item.proof_primitive_executable;
            });
    out.at_least_one_split_rap_path_executable =
        std::any_of(
            out.scenarios.begin(), out.scenarios.end(),
            [](const auto& item) {
                return item.proof_primitive_executable &&
                    item.split_rap_integrated;
            });
    out.any_109_bit_formal_recursive_backend =
        std::any_of(
            out.scenarios.begin(), out.scenarios.end(),
            [](const auto& item) {
                return
                    item.per_proof_fri_bits >= 109.0 &&
                    item.recursive_verifier_air_executable &&
                    item.formal_reduction_complete;
            });
    out.certified_bits = 0;
    out.authority_eligible = false;
    out.note =
        "stage3:recursive_backend_v1:"
        "q192_selected_executable_baseline;"
        "no_formal_recursive_backend;"
        "canonical_heterogeneous_topology_exact;"
        "width_product_rejected;"
        "recursive_program_selection_open";
    return out;
}

// PR-89 corrected composition constants. The untaxed dual query cap follows
// the grounded shared-commitment analysis (~226 - 2q => 98/66/26 at q=64/80/100
// for the two-lane shared-master construction). The joint squeeze binds both
// lane query rounds additively; its pairing cost vs a naive per-lane draw is
// kJointSqueezePairingLoss bits. The enforced per-squeeze tax then contributes
// g bits net of that pairing loss at the deciding round.
namespace {
constexpr double kDualUntaxedQueryConst = 226.0;
constexpr double kJointSqueezePairingLoss = 10.0;
} // namespace

double Fri3AlgHonestDualFloorBits(uint32_t queries_per_lane,
                                  uint32_t per_squeeze_grind_g,
                                  uint32_t random_oracle_bits)
{
    // SHA256d emits random_oracle_bits; its collision (birthday) floor caps the
    // reported soundness regardless of how large the query PAIR term grows.
    const double hash_birthday_bits =
        static_cast<double>(random_oracle_bits) / 2.0;
    const double dual_query_pair_bits =
        kDualUntaxedQueryConst -
        2.0 * static_cast<double>(queries_per_lane) +
        (static_cast<double>(per_squeeze_grind_g) - kJointSqueezePairingLoss);
    return std::min(hash_birthday_bits, dual_query_pair_bits);
}

FriScenario AssessFriScenario(
    std::string name,
    uint32_t lanes,
    uint32_t queries_per_lane,
    uint32_t extension_degree,
    uint32_t lde_log2,
    BatchChallengeShape batching,
    uint64_t global_sites,
    uint32_t batch_columns_upper_bound,
    uint32_t random_oracle_bits,
    uint32_t fixed_query_log2,
    bool joint_query_squeeze,
    uint32_t per_squeeze_grind_g)
{
    FriScenario out;
    out.name = std::move(name);
    out.lanes = lanes;
    out.joint_query_squeeze = joint_query_squeeze;
    out.per_squeeze_grind_g = per_squeeze_grind_g;
    out.queries_per_lane = queries_per_lane;
    out.extension_degree = extension_degree;
    out.lde_log2 = lde_log2;
    out.batch_columns_upper_bound = batch_columns_upper_bound;
    out.batching = batching;
    out.global_sites = global_sites;
    out.random_oracle_bits = random_oracle_bits;
    out.fixed_query_log2 = fixed_query_log2;

    if (lanes == 0 || queries_per_lane == 0 ||
        extension_degree < 2 || lde_log2 == 0 || lde_log2 > 32 ||
        batch_columns_upper_bound == 0 || global_sites == 0 ||
        random_oracle_bits < 64 ||
        fixed_query_log2 >= random_oracle_bits) {
        out.note = "stage3:soundness_scenario:invalid_parameters";
        return out;
    }

    // p=2^64-2^32+1.  Writing log2(p) this way retains the small deficit
    // even on platforms where converting p directly to double rounds to 2^64.
    const double goldilocks_bits =
        64.0 + std::log2(
                   1.0 - std::ldexp(1.0, -32) +
                   std::ldexp(1.0, -64));
    out.field_cardinality_bits =
        static_cast<double>(extension_degree) * goldilocks_bits;
    out.theorem_constant_loss_bits =
        7.0 * std::log2(static_cast<double>(LIST_PARAMETER_M) + 0.5) -
        std::log2(3.0) +
        1.5 * static_cast<double>(RATE_INVERSE_LOG2);

    if (batching == BatchChallengeShape::SinglePower &&
        batch_columns_upper_bound > 1) {
        // ePrint 2023/1071, Lemma 5.10 states the explicit (t-1) factor.
        out.batching_loss_bits =
            std::log2(
                static_cast<double>(batch_columns_upper_bound - 1));
    }
    out.published_batching_factor_exact = true;
    out.field_rbr_bits =
        out.field_cardinality_bits -
        2.0 * static_cast<double>(lde_log2) -
        out.theorem_constant_loss_bits -
        out.batching_loss_bits;
    out.proximity_rbr_bits =
        static_cast<double>(queries_per_lane) *
        std::log2(32.0 / 17.0);
    out.lane_rbr_bits =
        std::min(out.field_rbr_bits, out.proximity_rbr_bits);
    if (!(out.lane_rbr_bits > 0.0) ||
        !std::isfinite(out.lane_rbr_bits)) {
        out.note = "stage3:soundness_scenario:invalid_rbr_margin";
        return out;
    }

    const double log_sites =
        std::log2(static_cast<double>(global_sites));
    const double fixed_log_error =
        log_sites +
        static_cast<double>(lanes) *
            Log2BcsError(
                static_cast<double>(fixed_query_log2),
                out.lane_rbr_bits,
                random_oracle_bits);
    out.fixed_query_work_bits =
        static_cast<double>(fixed_query_log2) -
        std::min(0.0, fixed_log_error);
    out.all_query_work_bits =
        AllQueryCrossoverBits(
            out.lane_rbr_bits,
            lanes,
            global_sites,
            random_oracle_bits);

    // PR-89 corrected floor. When the Pi_JQ joint query squeeze is engaged with
    // an enforced per-squeeze tax g>0, the reported soundness is the dual-lane
    // shared-commitment floor min(hash birthday, dual query PAIR) with the
    // taxed round's q shifted by g -- REPLACING the fictional flat -40 and the
    // per-lane Log2BcsError^lanes multiplication for the reported number.
    out.hash_birthday_bits =
        static_cast<double>(random_oracle_bits) / 2.0;
    if (joint_query_squeeze && per_squeeze_grind_g > 0 && lanes == 2) {
        out.dual_query_pair_bits =
            kDualUntaxedQueryConst -
            2.0 * static_cast<double>(queries_per_lane) +
            (static_cast<double>(per_squeeze_grind_g) -
             kJointSqueezePairingLoss);
        out.honest_floor_bits =
            std::min(out.hash_birthday_bits, out.dual_query_pair_bits);
        // The honest floor is the reported soundness for this screen.
        out.target_margin_bits = out.honest_floor_bits - TARGET_BITS;
        out.parameters_valid = true;
        out.numeric_target_met = out.honest_floor_bits >= TARGET_BITS;
    } else {
        out.dual_query_pair_bits = 0.0;
        out.honest_floor_bits = out.all_query_work_bits;
        out.target_margin_bits = out.all_query_work_bits - TARGET_BITS;
        out.parameters_valid = true;
        out.numeric_target_met = out.all_query_work_bits >= TARGET_BITS;
    }

    // Fp3 arithmetic exists, while Fp4 is only a numerical option.  None of
    // the scenarios has the complete protocol-match/global reduction needed
    // for a certificate.
    out.field_backend_present = extension_degree == 3;
    out.executable_recursive_shape_present = false;
    out.backend_matches_published_protocol = false;
    out.transcript_domains_proven_disjoint = lanes == 1;
    out.common_commitment_hybrid_complete = lanes == 1;
    out.global_site_upper_bound_manifest_derived = false;
    out.formal_reduction_complete = false;
    out.certified_bits = 0;
    out.authority_eligible = false;

    if (!out.numeric_target_met) {
        out.note =
            "stage3:soundness_scenario:all_q_numeric_target_missed";
    } else if (extension_degree == 4) {
        out.note =
            "stage3:soundness_scenario:fp4_backend_absent";
    } else if (lanes > 1) {
        out.note =
            "stage3:soundness_scenario:repetition_and_shared_commitment_"
            "reductions_open";
    } else {
        out.note =
            "stage3:soundness_scenario:backend_site_and_global_reduction_open";
    }
    return out;
}

ComposedThreatModelFloorV1 AssessComposedThreatModelFloorV1(
    uint32_t qstar,
    uint64_t global_sites)
{
    ComposedThreatModelFloorV1 out;
    out.qstar = qstar;
    out.stress_ceiling_q = kThreatModelStressCeilingQ;
    out.global_sites = global_sites;
    out.transport_dual_alpha_screen_bits =
        kComposedTransportDualAlphaScreenBits;

    // The three composed terms at the supplied q (= log2 hash-oracle budget).
    const double q = static_cast<double>(qstar);
    out.field_pair_bits = kComposedFieldPairConst - 2.0 * q;
    out.taxed_query_pair_bits = kComposedTaxedQueryPairConst - q;
    out.shared_collision_bits = kComposedSharedCollisionConst - 2.0 * q;

    // Per-site floor = the binding (minimum) term.
    out.per_site_composed_floor_bits = out.field_pair_bits;
    out.binding_term = ComposedFloorBindingTerm::FieldPair;
    if (out.taxed_query_pair_bits < out.per_site_composed_floor_bits) {
        out.per_site_composed_floor_bits = out.taxed_query_pair_bits;
        out.binding_term = ComposedFloorBindingTerm::TaxedQueryPair;
    }
    if (out.shared_collision_bits < out.per_site_composed_floor_bits) {
        out.per_site_composed_floor_bits = out.shared_collision_bits;
        out.binding_term = ComposedFloorBindingTerm::SharedCollision;
    }

    // Within-proof site union: error multiplied by the site count, i.e. the
    // composed exponent loses log2(sites) bits. The doc reports the whole-bit
    // charge round(log2(59.5B)) = 36 -> F_g(76) ~ 68.
    if (global_sites > 0) {
        out.site_union_charge_exact_bits =
            std::log2(static_cast<double>(global_sites));
        out.site_union_charge_bits =
            std::round(out.site_union_charge_exact_bits);
    }
    out.global_composed_floor_bits =
        out.per_site_composed_floor_bits - out.site_union_charge_bits;

    out.transport_screen_non_binding =
        out.transport_dual_alpha_screen_bits >=
        out.per_site_composed_floor_bits;
    out.per_site_meets_100 =
        out.per_site_composed_floor_bits >= 100.0;
    out.per_site_meets_64 =
        out.per_site_composed_floor_bits >= 64.0;
    out.global_meets_100 =
        out.global_composed_floor_bits >= 100.0;
    out.global_meets_64 =
        out.global_composed_floor_bits >= 64.0;
    out.parameters_valid =
        qstar > 0 &&
        std::isfinite(out.per_site_composed_floor_bits) &&
        out.per_site_composed_floor_bits > 0.0;

    // Explicit AUDIT-INPUT assumption ledger. Each line is recorded here; NONE
    // is flag-flipped by this computation. The floor is conditioned on all of
    // them jointly.
    out.assumptions = {
        {
            "M2:poseidon2_binding",
            ComposedFloorAssumptionStatus::AssumedAuditInput,
            true,
            "shared-collision exponent 256-2q assumes generic-birthday-optimal "
            "collision search against Poseidon2 (Goldilocks, t=12, R_F=8, "
            "R_P=22, x^7): a non-standard algebraic-hash binding assumption "
            "dimensioned for a 128-bit level; open external audit item.",
        },
        {
            "A2:lane_independence",
            ComposedFloorAssumptionStatus::ProvenAuditInput,
            true,
            "dual-lane field pair 308-2q rests on lane independence; PROVEN "
            "under ROM + Poseidon-binding (worker a1bcb59a). Proof itself is "
            "audit-input, not flag-flipped. Single-lane fallback m_f-q=76@78.",
        },
        {
            "field_bounds:m_f_154",
            ComposedFloorAssumptionStatus::ProvenAuditInput,
            true,
            "field-bounds lift m_f~154 (unique-decoding; per-round 151-168), "
            "PROVEN (worker a104985f); places the field pair at 156@q* safely "
            "non-binding above the shared-collision term.",
        },
        {
            "hash_model:split_256bit_digest",
            ComposedFloorAssumptionStatus::ProvenAuditInput,
            true,
            "hash-model split (#2 resolved+code): full 256-bit untruncated "
            "digest with the shared row tree opened by both lanes fixes the "
            "binding term at 256-2q; enforced g=40 tax + Pi_JQ set the "
            "128/96/56 query floor (#3 built).",
        },
    };

    out.note =
        "stage3:composed_threat_model_floor_v1:"
        "F(q*)=min(308-2q,288-q,256-2q);"
        "binding=shared_collision_256_minus_2q;"
        "per_site_104_at_qstar_76;"
        "global_site_union_charged;"
        "probability_at_budget_exponents_not_work_factors;"
        "conditioned_on_M2_A2_field_bounds_hash_model_audit_inputs";
    return out;
}

Fri3AlgBcsRbrLedgerV1 AssessFri3AlgBcsRbrLedgerV1()
{
    Fri3AlgBcsRbrLedgerV1 out;

    // --- Parameters read directly from the executable FRI construction. ---
    out.queries = kRCFri3AlgNumQueries;             // 192
    out.extension_degree = 3;                        // Fp3
    out.blowup = kRCFriBlowup;                        // 16 => rho = 1/16
    out.grinding_bits = kRCFriGrindingBits;           // 40
    out.lde_log2 = 24U;                               // 24 (|L| = 2^24)
    out.batch_columns_cap = kRCFri3AlgBatchMaxColumns; // 2^15

    // log2|Fp3| = 3*log2(p), p = 2^64 - 2^32 + 1. Retain the small deficit.
    const double goldilocks_bits =
        64.0 + std::log2(1.0 - std::ldexp(1.0, -32) + std::ldexp(1.0, -64));
    out.field_cardinality_bits =
        static_cast<double>(out.extension_degree) * goldilocks_bits; // ~191.9999
    out.rho_inverse_log2 =
        std::log2(static_cast<double>(out.blowup));                   // 4
    out.alpha_log2_ratio = std::log2(32.0 / 17.0);                    // ~0.9127

    // BKS2018/BCIKS2020/Haboeck2022 proximity-gap theorem constant loss, same
    // published constant used by AssessFriScenario. This is the ONE published
    // theorem constant the FIELD rounds rest on; disclosed as an assumption.
    out.proximity_gap_constant_loss_bits =
        7.0 * std::log2(static_cast<double>(LIST_PARAMETER_M) + 0.5) -
        std::log2(3.0) +
        1.5 * static_cast<double>(RATE_INVERSE_LOG2);                 // ~17.07

    // Audit-input PROVEN per-round field window (worker a104985f): every
    // single-lane FRI field round is 151-168 bits, representative m_f ~ 154.
    out.field_round_min_bits = 151.0;
    out.field_round_max_bits = 168.0;
    out.field_round_mf_bits = 154.0;

    // In the UNIQUE-DECODING regime (alpha = 17/32 < (1-rho)/2) the correlated-
    // agreement / proximity-gap per-round error scales with a SINGLE |L| (not
    // |L|^2): -log2(err) = |Fp3|_bits - |L| - round_constant. |Fp3| - |L| =
    // ~168 (the lightest fold/line rounds); charging the proximity-gap constant
    // on the batching round yields ~151 (the binding field round). This
    // reproduces the proven [151,168] window from construction parameters.
    const double L = static_cast<double>(out.lde_log2);              // 24
    const double base_field_bits = out.field_cardinality_bits - L;   // ~168

    const uint32_t fold_rounds =
        out.lde_log2 > static_cast<uint32_t>(out.rho_inverse_log2)
            ? out.lde_log2 - static_cast<uint32_t>(out.rho_inverse_log2)
            : 1U;                                                    // ~20 folds

    auto push_field_round =
        [&](Fri3AlgRbrRoundKind kind, uint32_t mult, double round_const,
            std::string detail) {
            Fri3AlgRbrRoundBoundV1 r;
            r.kind = kind;
            r.multiplicity = mult;
            r.round_constant_bits = round_const;
            r.per_round_bits = base_field_bits - round_const;
            r.field_round = true;
            // 0.5-bit rounding tolerance around the proven [151,168] window.
            r.in_proven_field_window =
                r.per_round_bits >= out.field_round_min_bits - 0.5 &&
                r.per_round_bits <= out.field_round_max_bits + 0.5;
            r.detail = std::move(detail);
            out.rounds.push_back(r);
        };

    // 1. Batching correlated agreement over W columns. Proximity gaps make the
    //    RLC error W-INDEPENDENT; the proximity-gap theorem constant is charged
    //    here, giving the binding field round ~151.
    push_field_round(
        Fri3AlgRbrRoundKind::BatchingCorrelatedAgreement, 1,
        out.proximity_gap_constant_loss_bits,
        "RLC over W<=2^15 columns; proximity-gap (W-independent) correlated "
        "agreement; charges the BCIKS/Haboeck theorem constant => binding "
        "field round ~151");
    // 2. Dual-OOD DEEP quotient at z1,z2: 2 out-of-domain evaluation points.
    push_field_round(
        Fri3AlgRbrRoundKind::DualOodDeep, 1, 1.0,
        "DEEP quotient soundness at the two OOD points z1,z2 (log2 2 = 1 bit "
        "for the point count) => ~167");
    // 3. DEEP-weight line correlated agreement batching the two quotients.
    push_field_round(
        Fri3AlgRbrRoundKind::DeepWeightLineCA, 1, 1.0,
        "line correlated agreement of the (w1,w2) DEEP-weight batch => ~167");
    // 4. Per-fold-round line correlated agreement (multiplicity = folds).
    push_field_round(
        Fri3AlgRbrRoundKind::FoldRoundLineCA, fold_rounds, 0.0,
        "v5 half-domain fold: line correlated agreement per fold round "
        "(unique decoding, negligible constant) => ~168");

    // 5. Query phase: the (17/32)^Q proximity floor AFTER the honest g=40
    //    unenforced-regrind deduction, taken verbatim from the construction.
    {
        Fri3AlgRbrRoundBoundV1 q;
        q.kind = Fri3AlgRbrRoundKind::QueryProximity;
        q.multiplicity = out.queries;
        q.round_constant_bits = 0.0;
        q.per_round_bits = static_cast<double>(Fri3AlgSoundnessBoundBits());
        q.field_round = false;
        q.in_proven_field_window = false;
        q.detail =
            "query proximity floor(Q*log2(32/17)) - g = 135 "
            "(== Fri3AlgSoundnessBoundBits())";
        out.rounds.push_back(q);
    }

    // --- Composition. ---
    out.min_field_round_bits = std::numeric_limits<double>::infinity();
    out.max_field_round_bits = 0.0;
    out.fri_rbr_round_count = 0;
    out.every_field_round_in_proven_window = true;
    for (const auto& r : out.rounds) {
        // BCS state restoration counts interactive ROUNDS: each field round
        // kind by its round multiplicity, the query phase as a single round
        // (its Q repetitions are query complexity, not extra rounds).
        out.fri_rbr_round_count += r.field_round ? r.multiplicity : 1U;
        if (r.field_round) {
            out.min_field_round_bits =
                std::min(out.min_field_round_bits, r.per_round_bits);
            out.max_field_round_bits =
                std::max(out.max_field_round_bits, r.per_round_bits);
            out.every_field_round_in_proven_window &= r.in_proven_field_window;
        }
    }

    // BCS state restoration (ePrint 2016/116 Lemma B.1; 2023/1071 Thm 4.2):
    // e_bcs(Q) <= Q*e_rbr + 3(Q^2+1)/2^kappa. The t*e_rbr union over the
    // rbr rounds is a log2(t) bit charge; the random-oracle term at kappa=256,
    // Q=192 is ~2^-239 (negligible). Field side after BCS = min_field - log2(t).
    const uint32_t kappa = 256;
    const double Qd = static_cast<double>(out.queries);
    out.bcs_state_restoration_charge_bits =
        std::log2(static_cast<double>(out.fri_rbr_round_count));
    out.bcs_random_oracle_term_bits =
        static_cast<double>(kappa) -
        (std::log2(3.0) + std::log2(Qd * Qd + 1.0));   // ~239 bits of margin
    out.min_field_round_after_bcs_bits =
        out.min_field_round_bits - out.bcs_state_restoration_charge_bits;

    // Headline binding numbers.
    out.query_proximity_floor_bits =
        static_cast<double>(Fri3AlgSoundnessBoundBits());              // 135
    out.hash_collision_floor_bits =
        static_cast<double>(kRCFri3AlgDualAlgHashCollisionBits);       // 128
    out.composed_single_lane_floor_bits =
        std::min(out.query_proximity_floor_bits, out.hash_collision_floor_bits);

    // --- Machine-checkable verdicts. ---
    out.parameters_match_construction =
        out.queries == 192U && out.extension_degree == 3U &&
        out.blowup == 16U && out.grinding_bits == 40U &&
        out.lde_log2 == 24U;
    out.query_proximity_matches_construction =
        out.query_proximity_floor_bits == 135.0;
    out.hash_collision_floor_matches_construction =
        out.hash_collision_floor_bits == 128.0;
    // Field rounds are non-binding iff the WORST field round, even after the
    // BCS state-restoration charge, stays above both headline floors.
    out.field_rounds_non_binding =
        out.min_field_round_after_bcs_bits >=
        std::max(out.query_proximity_floor_bits,
                 out.hash_collision_floor_bits);
    out.composition_reproduces_135_128 =
        out.query_proximity_matches_construction &&
        out.hash_collision_floor_matches_construction &&
        out.composed_single_lane_floor_bits == 128.0;
    out.bcs_reduction_numerically_instantiated =
        std::isfinite(out.bcs_state_restoration_charge_bits) &&
        out.bcs_state_restoration_charge_bits > 0.0 &&
        out.bcs_state_restoration_charge_bits < 8.0 &&
        out.bcs_random_oracle_term_bits > 200.0 &&
        out.min_field_round_after_bcs_bits >= out.hash_collision_floor_bits;

    out.rbr_reduction_machine_checked =
        out.parameters_match_construction &&
        out.every_field_round_in_proven_window &&
        out.field_rounds_non_binding &&
        out.query_proximity_matches_construction &&
        out.hash_collision_floor_matches_construction &&
        out.composition_reproduces_135_128 &&
        out.bcs_reduction_numerically_instantiated;

    // Disclosed audit-input assumptions (published theorems), NOT gaps.
    out.assumptions = {
        {
            "proximity_gap:BKS2018_BCIKS2020_Haboeck2022",
            ComposedFloorAssumptionStatus::ProvenAuditInput,
            true,
            "the per-round FIELD bounds (unique-decoding correlated-agreement "
            "/ proximity gap, single-|L| scale, window 151-168, m_f~154) rest "
            "on the published proximity-gap theorem constant (m+1/2)^7|L|^2/"
            "(3 rho^{3/2}|F|); PROVEN audit-input (worker a104985f). The "
            "constant is recomputed here from construction parameters; the "
            "theorem itself is external published input, not machine-proven "
            "in-tree.",
        },
        {
            "bcs_transform:BCS2016_Block2023",
            ComposedFloorAssumptionStatus::ProvenAuditInput,
            true,
            "the RBR->FS composition e_bcs(Q) <= Q*e_rbr + 3(Q^2+1)/2^kappa "
            "and the FS-security-of-FRI reduction (ePrint 2016/116 Lemma B.1; "
            "2023/1071 Thm 4.2, Lemma 5.10) are the published BCS/Block-2023 "
            "transform. The composition STRUCTURE is machine-encoded and "
            "checked here; the transform theorem is external audit-input.",
        },
        {
            "hash_model:poseidon2_capacity_128",
            ComposedFloorAssumptionStatus::AssumedAuditInput,
            true,
            "the 128-bit headline floor is the 4-lane Poseidon2-Goldilocks "
            "capacity-sponge collision resistance (kRCFri3AlgDualAlgHash"
            "CollisionBits): a non-standard algebraic-hash binding assumption, "
            "open external audit item.",
        },
    };

    out.note =
        out.rbr_reduction_machine_checked
            ? "stage3:fri3alg_bcs_rbr_ledger_v1:"
              "per_round_field_window_151_168_reproduced;"
              "batching_binding_field_round_~151;"
              "query_proximity_135;shared_collision_128;"
              "bcs_state_restoration_charged;composed_135_over_128;"
              "MACHINE_CHECKED_modulo_disclosed_proximity_gap_and_bcs_"
              "transform_audit_inputs"
            : "stage3:fri3alg_bcs_rbr_ledger_v1:machine_check_incomplete";
    return out;
}

std::vector<FriScenario> AssessCanonicalFriScenarios()
{
    const uint64_t sites =
        CanonicalRCStage3UnifiedRootParameters()
            .soundness_union_bound_instances;
    std::vector<FriScenario> out;
    out.reserve(10);
    out.push_back(AssessFriScenario(
        "single_fp3_q192_lde24_power", 1, 192, 3, 24,
        BatchChallengeShape::SinglePower, sites));
    out.push_back(AssessFriScenario(
        "single_fp3_q192_lde24_independent", 1, 192, 3, 24,
        BatchChallengeShape::IndependentCoefficients, sites));
    out.push_back(AssessFriScenario(
        "single_fp3_q192_lde23_independent", 1, 192, 3, 23,
        BatchChallengeShape::IndependentCoefficients, sites));
    out.push_back(AssessFriScenario(
        "dual_fp3_q96_lde24_power", 2, 96, 3, 24,
        BatchChallengeShape::SinglePower, sites));
    out.push_back(AssessFriScenario(
        "dual_fp3_q96_lde24_independent", 2, 96, 3, 24,
        BatchChallengeShape::IndependentCoefficients, sites));
    out.push_back(AssessFriScenario(
        "dual_fp3_q128_lde24_independent", 2, 128, 3, 24,
        BatchChallengeShape::IndependentCoefficients, sites));
    out.push_back(AssessFriScenario(
        "dual_fp3_q128_lde23_power", 2, 128, 3, 23,
        BatchChallengeShape::SinglePower, sites));
    out.push_back(AssessFriScenario(
        "dual_fp3_q136_lde24_independent", 2, 136, 3, 24,
        BatchChallengeShape::IndependentCoefficients, sites));
    out.push_back(AssessFriScenario(
        "dual_fp3_q148_lde24_independent", 2, 148, 3, 24,
        BatchChallengeShape::IndependentCoefficients, sites));
    out.push_back(AssessFriScenario(
        "single_fp4_q192_lde24_power", 1, 192, 4, 24,
        BatchChallengeShape::SinglePower, sites));
    return out;
}

} // namespace matmul::v4::rc::soundness_scenarios
