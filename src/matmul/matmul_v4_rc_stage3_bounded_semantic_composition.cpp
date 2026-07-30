// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_bounded_semantic_composition.h>

#include <matmul/matmul_v4_rc_stage3_bounded_semantic_binding.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>
#include <matmul/matmul_v4_rc_stage3_episode_round_roots.h>
#include <matmul/matmul_v4_rc_stage3_root_chain.h>

#include <algorithm>
#include <array>
#include <initializer_list>
#include <limits>
#include <set>
#include <utility>

namespace matmul::v4::rc {
namespace {

namespace aq = air_quotient;
namespace gf = gkr_field;
using E = RCStage3RelationEndpoint;
using gf::Fp3;

bool Fail(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:bounded_semantic_composition:" + detail;
    }
    return false;
}

uint32_t EndpointNumber(E endpoint)
{
    return static_cast<uint32_t>(endpoint);
}

uint32_t EdgeNumber(E producer, E consumer)
{
    return EndpointNumber(producer) * 64U + EndpointNumber(consumer);
}

class ExecutedSchedule
{
public:
    void Endpoint(E endpoint)
    {
        const uint32_t value = EndpointNumber(endpoint);
        if (value < m_endpoints.size()) m_endpoints[value] = true;
    }

    void Endpoints(std::initializer_list<E> endpoints)
    {
        for (const E endpoint : endpoints) Endpoint(endpoint);
    }

    void Edge(E producer, E consumer)
    {
        m_edges.insert(EdgeNumber(producer, consumer));
    }

    void Edges(E consumer, std::initializer_list<E> producers)
    {
        for (const E producer : producers) Edge(producer, consumer);
    }

    bool Complete(std::string* why) const
    {
        const auto graph = CurrentRCStage3ProvenanceGraphAudit();
        if (!graph.exact_52_order ||
            !graph.exact_public_roots_1_and_25 ||
            !graph.every_non_public_node_has_a_producer ||
            !graph.no_missing_out_of_range_self_or_duplicate_producer ||
            graph.nodes.size() !=
                kRCStage3RelationClosureEndpointCount) {
            return Fail(why, "registry_shape");
        }
        for (const auto& node : graph.nodes) {
            const uint32_t consumer = EndpointNumber(node.endpoint);
            if (consumer >= m_endpoints.size() ||
                !m_endpoints[consumer]) {
                return Fail(
                    why, "endpoint_not_executed_" +
                        std::to_string(consumer));
            }
            for (const auto& edge : node.producers) {
                if (!m_edges.contains(
                        EdgeNumber(edge.producer, node.endpoint))) {
                    return Fail(
                        why, "edge_obligation_not_covered_" +
                            std::to_string(
                                EndpointNumber(edge.producer)) +
                            "_" + std::to_string(consumer));
                }
            }
        }
        if (m_edges.size() != graph.edges ||
            graph.edges != 81U) {
            return Fail(why, "covered_edge_obligation_inventory");
        }
        return true;
    }

private:
    std::array<bool, kRCStage3RelationClosureEndpointCount + 1U>
        m_endpoints{};
    std::set<uint32_t> m_edges;
};

uint256 ValuesRoot(
    const std::vector<int64_t>& values,
    uint64_t begin,
    uint32_t logical_rows,
    uint32_t n_rows)
{
    if (logical_rows == 0 || logical_rows > n_rows ||
        begin > values.size() ||
        values.size() - begin < logical_rows) {
        return {};
    }
    std::vector<Fp3> column(n_rows, Fp3::Zero());
    for (uint32_t row = 0; row < logical_rows; ++row) {
        column[row] = Fp3::FromFp(
            gf::FromSigned(values[begin + row]));
    }
    return aq::AirCommittedValuesRoot<Fp3>(column, n_rows);
}

bool SameRangePinSchedule(
    const RCStage3SignedRangePin& actual,
    const RCStage3SignedRangePin& expected)
{
    return actual.statement_commitment ==
               expected.statement_commitment &&
           actual.manifest_commitment ==
               expected.manifest_commitment &&
           actual.layer_ordinal == expected.layer_ordinal &&
           actual.shard_index == expected.shard_index &&
           actual.shard_count == expected.shard_count &&
           actual.cell_begin == expected.cell_begin &&
           actual.logical_rows == expected.logical_rows &&
           actual.n_rows == expected.n_rows &&
           actual.max_abs == expected.max_abs &&
           actual.column_roots.size() ==
               kRCStage3SignedRangeColumns;
}

bool VerifyEpisodeTreeAndSeedJoins(
    const RCStage3BoundedEpisodeSemanticComposition& episode,
    std::string* why)
{
    if (!(episode.seed_chain.round_root_manifest ==
          episode.root_chain.manifest) ||
        episode.tile_stream.rounds.size() !=
            episode.round_root_producers.rounds.size()) {
        return Fail(why, "episode_round_root_manifest_join");
    }
    for (uint32_t round = 0;
         round < episode.tile_stream.rounds.size(); ++round) {
        const auto& stream_tree =
            episode.tile_stream.rounds[round].tree.tree_manifest;
        const auto& digest_tree =
            episode.round_root_producers.rounds[round].tree_manifest;
        if (!(stream_tree == digest_tree)) {
            return Fail(
                why, "episode_tile_tree_join_" +
                    std::to_string(round));
        }
    }
    return true;
}

bool VerifyCoupledBarrierJoins(
    const RCStage3BoundedCoupledSemanticComposition& coupled,
    std::string* why)
{
    const auto& extract_barriers =
        coupled.extract.output_to_barrier.barriers;
    if (extract_barriers.size() != coupled.root_chain.barriers.size()) {
        return Fail(why, "coupled_barrier_count_join");
    }
    for (uint32_t barrier = 0;
         barrier < extract_barriers.size(); ++barrier) {
        if (!(extract_barriers[barrier].manifest ==
              coupled.root_chain.barriers[barrier].manifest)) {
            return Fail(
                why, "coupled_barrier_manifest_join_" +
                    std::to_string(barrier));
        }
    }
    return true;
}

} // namespace

const char* RCStage3BoundedSemanticBuildFamilyName(
    RCStage3BoundedSemanticBuildFamily family)
{
    using F = RCStage3BoundedSemanticBuildFamily;
    switch (family) {
    case F::EpisodeHeaderTarget:
        return "episode_header_target";
    case F::EpisodeSeedChain:
        return "episode_seed_chain";
    case F::EpisodeOperandXof:
        return "episode_operand_xof";
    case F::EpisodeBuilderTrace:
        return "episode_builder_trace";
    case F::EpisodeGemm:
        return "episode_gemm";
    case F::EpisodeSignedRange:
        return "episode_signed_range";
    case F::EpisodeExtract:
        return "episode_extract";
    case F::EpisodeTileStream:
        return "episode_tile_stream";
    case F::EpisodeWiring:
        return "episode_wiring";
    case F::EpisodeRoundRoots:
        return "episode_round_roots";
    case F::EpisodeDigestRootChain:
        return "episode_digest_root_chain";
    case F::EpisodePow:
        return "episode_pow";
    case F::CoupledBank:
        return "coupled_bank";
    case F::CoupledInitialState:
        return "coupled_initial_state";
    case F::CoupledGemm:
        return "coupled_gemm";
    case F::CoupledSignedRange:
        return "coupled_signed_range";
    case F::CoupledExchangePermutation:
        return "coupled_exchange_permutation";
    case F::CoupledMix:
        return "coupled_mix";
    case F::CoupledExtract:
        return "coupled_extract";
    case F::CoupledBankRoot:
        return "coupled_bank_root";
    case F::CoupledRootChain:
        return "coupled_root_chain";
    case F::CrossProductJoins:
        return "cross_product_joins";
    case F::BoundedAggregateVerifier:
        return "bounded_aggregate_verifier";
    }
    return "unknown";
}

bool BuildRCStage3BoundedSemanticProverPlan(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCEpisodeParams& params,
    const RCStage3CoupledShape& shape,
    RCStage3BoundedSemanticBuildPlan& out,
    std::string* why)
{
    out = {};
    if (statement.statement != RCStage3StatementKind::Composed ||
        statement.public_inputs.header_commitment !=
            RCStage3HeaderCommitment(header) ||
        statement.public_inputs.sigma !=
            matmul::v4::DeriveSigma(header) ||
        statement.public_inputs.n_bits != header.nBits ||
        statement.public_inputs.final_digest !=
            header.matmul_digest ||
        !ValidateRCEpisodeParams(params)) {
        return Fail(why, "build_plan_public_context");
    }
    std::string composition_why;
    if (!VerifyRCStage3CompositionLink(
            statement, &composition_why)) {
        return Fail(
            why, "build_plan_outer_composition:" +
                     composition_why);
    }

    uint64_t layers64{0};
    const uint64_t per_round =
        uint64_t{2} + uint64_t{2} * params.L_lyr;
    if (per_round >
            std::numeric_limits<uint64_t>::max() /
                params.rounds) {
        return Fail(why, "build_plan_episode_layer_overflow");
    }
    layers64 = per_round * params.rounds;
    if (layers64 == 0 ||
        layers64 > std::numeric_limits<uint32_t>::max()) {
        return Fail(why, "build_plan_episode_layer_count");
    }

    // Build only a schedule manifest.  The placeholder roots never leave this
    // function and are not accepted as proofs or returned as relation claims.
    std::vector<RCStage3GemmExtractLayerBindings> bindings(
        static_cast<size_t>(layers64));
    const uint256 schedule_marker =
        statement.public_inputs.header_commitment;
    for (auto& binding : bindings) {
        binding.extract_prf = statement.public_inputs.sigma;
        binding.operand_a_root = schedule_marker;
        binding.operand_b_root = schedule_marker;
        binding.gemm_y_root = schedule_marker;
        binding.extract_input_root = schedule_marker;
        binding.extract_output_root = schedule_marker;
        binding.gemm_proof_root = schedule_marker;
        binding.extract_recursive_root = schedule_marker;
        binding.scale_schedule_root = schedule_marker;
        binding.ctl_terminal_root = schedule_marker;
    }
    const auto manifest = BuildRCStage3GemmExtractManifest(
        params, RCStage3EpisodeStatementCommitment(statement),
        bindings, why);
    if (!manifest.has_value()) {
        return Fail(why, "build_plan_episode_manifest");
    }
    out.episode_layers =
        static_cast<uint32_t>(manifest->layers.size());
    out.episode_gemm_tiles = manifest->total_extract_tiles;
    out.episode_extract_tiles = manifest->total_extract_tiles;
    uint64_t range_shards{0};
    for (const auto& layer : manifest->layers) {
        if (RCStage3EpisodeLayerIsStreamed(layer.kind)) {
            if (out.episode_stream_tiles >
                std::numeric_limits<uint64_t>::max() -
                    layer.extract_tile_count) {
                return Fail(
                    why, "build_plan_episode_stream_overflow");
            }
            out.episode_stream_tiles +=
                layer.extract_tile_count;
        }
        const uint64_t shards =
            (layer.gemm_cell_count +
             kRCStage3SignedRangeMaxShardRows - 1U) /
            kRCStage3SignedRangeMaxShardRows;
        if (range_shards >
            std::numeric_limits<uint32_t>::max() - shards) {
            return Fail(
                why, "build_plan_episode_range_overflow");
        }
        range_shards += shards;
    }
    out.episode_signed_range_shards =
        static_cast<uint32_t>(range_shards);
    const auto copy =
        BuildRCStage3EpisodeWiringCopySchedule(*manifest, why);
    if (!copy.has_value()) {
        return Fail(why, "build_plan_episode_copy_schedule");
    }
    out.episode_wiring_edges =
        copy->size() +
        BuildRCStage3EpisodeWiringTransposeSchedule(
            *manifest).size() +
        BuildRCStage3EpisodeWiringResidualSchedule(
            *manifest).size() +
        BuildRCStage3EpisodeWiringRoundOrderSchedule(
            *manifest).size();

    std::vector<RCStage3CoupledGemmScheduleEntry>
        coupled_gemm_schedule;
    uint256 coupled_gemm_schedule_commitment;
    if (!BuildRCStage3CoupledGemmSchedule(
            statement, shape, coupled_gemm_schedule,
            coupled_gemm_schedule_commitment, why)) {
        return Fail(why, "build_plan_coupled_gemm_schedule");
    }
    RCStage3CoupledSignedRangeManifest coupled_range;
    if (!BuildRCStage3CoupledSignedRangeManifest(
            statement, shape, coupled_range, why)) {
        return Fail(why, "build_plan_coupled_range_schedule");
    }
    const auto exchange =
        BuildRCStage3CoupledExchangeSchedule(shape, why);
    const auto permutation =
        BuildRCStage3CoupledPermutationSchedule(
            statement, shape, why);
    const auto extract =
        BuildRCStage3CoupledExtractSchedule(
            statement, shape, why);
    if (exchange.empty() || permutation.empty() ||
        extract.empty()) {
        return Fail(
            why, "build_plan_coupled_nonempty_schedule");
    }
    out.coupled_bank_pages = shape.bank_pages;
    out.coupled_initial_lobes = shape.lobes;
    out.coupled_gemms =
        static_cast<uint32_t>(coupled_gemm_schedule.size());
    out.coupled_signed_range_shards =
        coupled_range.shard_count;
    out.coupled_exchange_stages =
        static_cast<uint32_t>(exchange.size());
    out.coupled_permutation_stages =
        static_cast<uint32_t>(permutation.size());
    out.coupled_mix_barriers = shape.barriers;
    out.coupled_extract_tiles =
        static_cast<uint32_t>(extract.size());
    out.coupled_root_barriers = shape.barriers;

    using F = RCStage3BoundedSemanticBuildFamily;
    const auto add = [&](F family, bool available,
                         const char* blocker) {
        RCStage3BoundedSemanticBuildFamilyPlan entry;
        entry.family = family;
        entry.honest_product_orchestration_available =
            available;
        if (blocker != nullptr) entry.blocker = blocker;
        out.families.push_back(std::move(entry));
        if (!available) {
            out.missing_product_orchestrators.emplace_back(
                RCStage3BoundedSemanticBuildFamilyName(family));
        }
    };
    add(F::EpisodeHeaderTarget, true, nullptr);
    add(F::EpisodeSeedChain, true, nullptr);
    add(F::EpisodeOperandXof, true, nullptr);
    add(F::EpisodeBuilderTrace, true, nullptr);
    add(F::EpisodeGemm, true, nullptr);
    add(F::EpisodeSignedRange, true, nullptr);
    add(F::EpisodeExtract, true, nullptr);
    add(F::EpisodeTileStream, true, nullptr);
    add(F::EpisodeWiring, true, nullptr);
    add(F::EpisodeRoundRoots, true, nullptr);
    add(F::EpisodeDigestRootChain, true, nullptr);
    add(F::EpisodePow, true, nullptr);
    add(F::CoupledBank, true, nullptr);
    add(F::CoupledInitialState, true, nullptr);
    add(F::CoupledGemm, true, nullptr);
    add(F::CoupledSignedRange, true, nullptr);
    add(F::CoupledExchangePermutation, true, nullptr);
    add(F::CoupledMix, true, nullptr);
    add(F::CoupledExtract, true, nullptr);
    add(F::CoupledBankRoot, true, nullptr);
    add(F::CoupledRootChain, true, nullptr);
    add(F::CrossProductJoins, true, nullptr);
    add(F::BoundedAggregateVerifier, true, nullptr);

    out.positive_fixture_buildable =
        out.missing_product_orchestrators.empty();
    if (why != nullptr) {
        *why =
            "stage3:bounded_semantic_composition:build_plan_"
            "constructed;missing_product_orchestrators=";
        for (size_t i = 0;
             i < out.missing_product_orchestrators.size(); ++i) {
            if (i != 0) *why += ",";
            *why += out.missing_product_orchestrators[i];
        }
    }
    return true;
}

bool ProveRCStage3EpisodeSignedRangeGemmLink(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    std::vector<RCStage3SignedRangeShardProof>& out,
    std::string* why)
{
    out.clear();
    if (!ValidateRCStage3GemmExtractManifest(manifest, why) ||
        gemm.layers.size() != manifest.layers.size()) {
        return Fail(why, "episode_range_prove_parent");
    }
    uint64_t total_shards{0};
    for (const auto& layer : manifest.layers) {
        total_shards +=
            (layer.gemm_cell_count +
             kRCStage3SignedRangeMaxShardRows - 1U) /
            kRCStage3SignedRangeMaxShardRows;
    }
    if (total_shards > out.max_size()) {
        return Fail(why, "episode_range_prove_inventory");
    }
    out.reserve(static_cast<size_t>(total_shards));
    for (uint32_t layer = 0; layer < manifest.layers.size(); ++layer) {
        const auto& spec = manifest.layers[layer];
        const auto& product = gemm.layers[layer];
        if (product.layer_ordinal != layer ||
            product.gemm_y.size() != spec.gemm_cell_count) {
            out.clear();
            return Fail(why, "episode_range_prove_gemm_shape");
        }
        const uint32_t shard_count = static_cast<uint32_t>(
            (spec.gemm_cell_count +
             kRCStage3SignedRangeMaxShardRows - 1U) /
            kRCStage3SignedRangeMaxShardRows);
        for (uint32_t shard_index = 0;
             shard_index < shard_count; ++shard_index) {
            const auto maybe_pin = MakeRCStage3SignedRangePin(
                manifest, layer, shard_index, why);
            if (!maybe_pin.has_value()) {
                out.clear();
                return Fail(why, "episode_range_prove_pin");
            }
            RCStage3SignedRangeShardProof shard;
            shard.pin = *maybe_pin;
            const uint64_t begin =
                static_cast<uint64_t>(shard_index) *
                kRCStage3SignedRangeMaxShardRows;
            std::vector<int64_t> values(
                product.gemm_y.begin() + begin,
                product.gemm_y.begin() + begin +
                    shard.pin.logical_rows);
            std::vector<std::vector<Fp3>> columns;
            if (!BuildRCStage3SignedRangeColumns(
                    shard.pin, values, columns, why)) {
                out.clear();
                return Fail(why, "episode_range_prove_columns");
            }
            for (uint32_t column = 0; column < columns.size(); ++column) {
                shard.pin.column_roots[column].root =
                    aq::AirCommittedValuesRoot<Fp3>(
                        columns[column], shard.pin.n_rows);
            }
            aq::AirConstraintSystem<Fp3> cs;
            if (!ResolveRCStage3SignedRangeConstraintSystem(
                    manifest, shard.pin, cs, why)) {
                out.clear();
                return Fail(why, "episode_range_prove_cs");
            }
            auto proved = aq::AirQuotientProve<Fp3>(
                cs, columns, ComputeRCStage3SignedRangeSeed(shard.pin));
            if (!proved.ok || !proved.division_exact) {
                out.clear();
                return Fail(
                    why, proved.note.empty()
                        ? "episode_range_prove_quotient"
                        : proved.note);
            }
            shard.proof = std::move(proved.proof);
            out.push_back(std::move(shard));
        }
    }
    if (!VerifyRCStage3EpisodeSignedRangeGemmLink(
            manifest, gemm, out, why)) {
        out.clear();
        return Fail(why, "episode_range_prove_self_verify");
    }
    return true;
}

bool VerifyRCStage3EpisodeSignedRangeGemmLink(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const std::vector<RCStage3SignedRangeShardProof>& range,
    std::string* why)
{
    if (!VerifyRCStage3SignedRangeClosure(manifest, range, why)) {
        return Fail(why, "episode_range_proof");
    }
    return ValidateRCStage3EpisodeSignedRangeGemmValueEquality(
        manifest, gemm, range, why);
}

bool ValidateRCStage3EpisodeSignedRangeGemmValueEquality(
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const std::vector<RCStage3SignedRangeShardProof>& range,
    std::string* why)
{
    if (!ValidateRCStage3GemmExtractManifest(manifest, why) ||
        gemm.layers.size() != manifest.layers.size()) {
        return Fail(why, "episode_range_parent_or_shape");
    }
    uint64_t range_cursor = 0;
    for (uint32_t layer = 0; layer < manifest.layers.size(); ++layer) {
        const auto& spec = manifest.layers[layer];
        const auto& values = gemm.layers[layer].gemm_y;
        const uint32_t shard_count = static_cast<uint32_t>(
            (spec.gemm_cell_count +
             kRCStage3SignedRangeMaxShardRows - 1U) /
            kRCStage3SignedRangeMaxShardRows);
        if (gemm.layers[layer].layer_ordinal != layer ||
            values.size() != spec.gemm_cell_count ||
            range_cursor + shard_count > range.size()) {
            return Fail(why, "episode_range_gemm_inventory");
        }
        for (uint32_t shard = 0; shard < shard_count;
             ++shard, ++range_cursor) {
            const auto& pin = range[range_cursor].pin;
            const auto canonical = MakeRCStage3SignedRangePin(
                manifest, layer, shard, why);
            const uint64_t local_begin =
                static_cast<uint64_t>(shard) *
                kRCStage3SignedRangeMaxShardRows;
            if (!canonical.has_value() ||
                !SameRangePinSchedule(pin, *canonical)) {
                return Fail(
                    why, "episode_range_pin_schedule_" +
                        std::to_string(layer) + "_" +
                        std::to_string(shard));
            }
            const uint256 expected = ValuesRoot(
                values, local_begin, pin.logical_rows, pin.n_rows);
            if (pin.layer_ordinal != layer ||
                pin.shard_index != shard ||
                expected.IsNull() ||
                pin.column_roots.size() !=
                    kRCStage3SignedRangeColumns ||
                pin.column_roots[kRCStage3RangeValue].root !=
                    expected) {
                return Fail(
                    why, "episode_range_value_join_" +
                        std::to_string(layer) + "_" +
                        std::to_string(shard));
            }
        }
    }
    if (range_cursor != range.size()) {
        return Fail(why, "episode_range_trailing_shard");
    }
    return true;
}

bool ProveRCStage3CoupledSignedRangeGemmLink(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmProduct& gemm,
    RCStage3CoupledSignedRangeExecution& out,
    std::string* why)
{
    out = {};
    if (!BuildRCStage3CoupledSignedRangeManifest(
            statement, shape, out.manifest, why)) {
        return Fail(why, "coupled_range_prove_manifest");
    }
    std::vector<int64_t> values;
    if (out.manifest.total_output_cells > values.max_size()) {
        out = {};
        return Fail(why, "coupled_range_prove_inventory");
    }
    values.reserve(
        static_cast<size_t>(out.manifest.total_output_cells));
    for (const auto& instance : gemm.gemms) {
        if (instance.output_y.size() >
            values.max_size() - values.size()) {
            out = {};
            return Fail(why, "coupled_range_prove_size");
        }
        values.insert(
            values.end(), instance.output_y.begin(),
            instance.output_y.end());
    }
    if (values.size() != out.manifest.total_output_cells) {
        out = {};
        return Fail(why, "coupled_range_prove_gemm_shape");
    }
    out.shards.resize(out.manifest.shard_count);
    for (uint32_t shard_index = 0;
         shard_index < out.shards.size(); ++shard_index) {
        auto& shard = out.shards[shard_index];
        if (!MakeRCStage3CoupledSignedRangePin(
                out.manifest, shard_index, shard.pin, why)) {
            out = {};
            return Fail(why, "coupled_range_prove_pin");
        }
        const auto first =
            values.begin() + shard.pin.cell_begin;
        std::vector<int64_t> shard_values(
            first, first + shard.pin.logical_rows);
        std::vector<std::vector<Fp3>> columns;
        if (!BuildRCStage3SignedRangeColumns(
                shard.pin, shard_values, columns, why)) {
            out = {};
            return Fail(why, "coupled_range_prove_columns");
        }
        for (uint32_t column = 0; column < columns.size(); ++column) {
            shard.pin.column_roots[column].root =
                aq::AirCommittedValuesRoot<Fp3>(
                    columns[column], shard.pin.n_rows);
        }
        aq::AirConstraintSystem<Fp3> cs;
        if (!ResolveRCStage3SignedRangeKernelConstraintSystem(
                shard.pin, cs, why)) {
            out = {};
            return Fail(why, "coupled_range_prove_cs");
        }
        auto proved = aq::AirQuotientProve<Fp3>(
            cs, columns,
            ComputeRCStage3SignedRangeSeed(shard.pin));
        if (!proved.ok || !proved.division_exact) {
            out = {};
            return Fail(
                why, proved.note.empty()
                    ? "coupled_range_prove_quotient"
                    : proved.note);
        }
        shard.proof = std::move(proved.proof);
    }
    out.value_roots_commitment =
        CommitRCStage3CoupledSignedRangeValueRoots(
            out.manifest, out.shards);
    if (!VerifyRCStage3CoupledSignedRangeGemmLink(
            statement, shape, gemm, out, why)) {
        out = {};
        return Fail(why, "coupled_range_prove_self_verify");
    }
    return true;
}

bool VerifyRCStage3CoupledSignedRangeGemmLink(
    const RCStage3SuccinctProof& statement,
    const RCStage3CoupledShape& shape,
    const RCStage3CoupledGemmProduct& gemm,
    const RCStage3CoupledSignedRangeExecution& range,
    std::string* why)
{
    if (!VerifyRCStage3CoupledSignedRangeExecution(
            statement, shape, range, why)) {
        return Fail(why, "coupled_range_proof");
    }
    return ValidateRCStage3CoupledSignedRangeGemmValueEquality(
        gemm, range, why);
}

bool ValidateRCStage3CoupledSignedRangeGemmValueEquality(
    const RCStage3CoupledGemmProduct& gemm,
    const RCStage3CoupledSignedRangeExecution& range,
    std::string* why)
{
    if (range.manifest.commitment.IsNull() ||
        range.shards.size() != range.manifest.shard_count) {
        return Fail(why, "coupled_range_manifest_shape");
    }
    std::vector<int64_t> values;
    for (const auto& instance : gemm.gemms) {
        if (instance.output_y.size() >
            values.max_size() - values.size()) {
            return Fail(why, "coupled_range_size");
        }
        values.insert(
            values.end(), instance.output_y.begin(),
            instance.output_y.end());
    }
    if (values.size() != range.manifest.total_output_cells) {
        return Fail(why, "coupled_range_gemm_inventory");
    }
    for (uint32_t shard = 0; shard < range.shards.size(); ++shard) {
        const auto& pin = range.shards[shard].pin;
        RCStage3SignedRangePin canonical;
        if (!MakeRCStage3CoupledSignedRangePin(
                range.manifest, shard, canonical, why) ||
            !SameRangePinSchedule(pin, canonical)) {
            return Fail(
                why, "coupled_range_pin_schedule_" +
                    std::to_string(shard));
        }
        const uint256 expected = ValuesRoot(
            values, pin.cell_begin, pin.logical_rows, pin.n_rows);
        if (pin.shard_index != shard ||
            expected.IsNull() ||
            pin.column_roots.size() !=
                kRCStage3SignedRangeColumns ||
            pin.column_roots[kRCStage3RangeValue].root != expected) {
            return Fail(
                why, "coupled_range_value_join_" +
                    std::to_string(shard));
        }
    }
    return true;
}

bool VerifyRCStage3BoundedSemanticComposition(
    const RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCEpisodeParams& params,
    const RCStage3CoupledShape& shape,
    const RCStage3BoundedSemanticComposition& composition,
    std::string* why)
{
    if (statement.statement != RCStage3StatementKind::Composed ||
        statement.public_inputs.header_commitment !=
            RCStage3HeaderCommitment(header) ||
        statement.public_inputs.sigma !=
            matmul::v4::DeriveSigma(header) ||
        statement.public_inputs.n_bits != header.nBits ||
        statement.public_inputs.final_digest !=
            header.matmul_digest) {
        return Fail(why, "public_header_binding");
    }
    std::string composition_why;
    if (!VerifyRCStage3CompositionLink(
            statement, &composition_why)) {
        return Fail(
            why, "outer_composition_link:" + composition_why);
    }
    if (!VerifyRCStage3BoundedSemanticBinding(
            statement, composition, &composition_why)) {
        return Fail(
            why, "typed_sidecar_binding:" + composition_why);
    }

    ExecutedSchedule executed;
    const auto& episode = composition.episode;
    const auto& coupled = composition.coupled;
    const uint256 episode_statement =
        RCStage3EpisodeStatementCommitment(statement);

    if (!VerifyRCStage3EpisodeHeaderTargetProduct(
            statement, RCStage3HeaderCommitment(header), header.nBits,
            statement.public_inputs.target, episode.header_target, why)) {
        return Fail(why, "endpoint_25_header_target");
    }
    executed.Endpoint(E::EpisodeDigestHeaderTarget);

    if (!VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, episode.seed_chain, why)) {
        return Fail(why, "endpoints_1_2_seed_chain");
    }
    executed.Endpoints(
        {E::EpisodeBuilderParams, E::EpisodeBuilderSeedChain});
    executed.Edge(E::EpisodeBuilderParams, E::EpisodeBuilderSeedChain);

    if (!VerifyRCStage3EpisodeBuilderOperandXofProduct(
            statement, params, episode.seed_chain,
            episode.operand_xof, why)) {
        return Fail(why, "endpoint_3_operand_xof");
    }
    executed.Endpoint(E::EpisodeBuilderOperandXof);
    executed.Edges(
        E::EpisodeBuilderOperandXof,
        {E::EpisodeBuilderParams, E::EpisodeBuilderSeedChain});

    if (!VerifyRCStage3EpisodeBuilderTraceProduct(
            statement, params, episode.seed_chain.params_product,
            episode.seed_chain, episode.operand_xof,
            episode.builder_trace, why)) {
        return Fail(why, "endpoint_4_builder_trace");
    }
    executed.Endpoint(E::EpisodeBuilderTrace);
    executed.Edges(
        E::EpisodeBuilderTrace,
        {E::EpisodeBuilderParams, E::EpisodeBuilderSeedChain,
         E::EpisodeBuilderOperandXof});

    if (!VerifyRCStage3EpisodeGemmProduct(
            statement, episode.gemm_extract_manifest,
            episode.gemm, episode.extract, why)) {
        return Fail(why, "endpoints_5_8_gemm");
    }
    executed.Endpoints(
        {E::EpisodeGemmOperandA, E::EpisodeGemmOperandB,
         E::EpisodeGemmOutputY, E::EpisodeGemmSumcheck});
    executed.Edges(
        E::EpisodeGemmOutputY,
        {E::EpisodeGemmOperandA, E::EpisodeGemmOperandB});
    executed.Edges(
        E::EpisodeGemmSumcheck,
        {E::EpisodeGemmOperandA, E::EpisodeGemmOperandB,
         E::EpisodeGemmOutputY});

    if (!VerifyRCStage3EpisodeSignedRangeGemmLink(
            episode.gemm_extract_manifest, episode.gemm,
            episode.signed_range, why)) {
        return Fail(why, "endpoint_9_signed_range");
    }
    executed.Endpoint(E::EpisodeGemmSignedRange);
    executed.Edge(
        E::EpisodeGemmOutputY, E::EpisodeGemmSignedRange);

    if (!VerifyRCStage3EpisodeExtractDerivationLinks(
            header, statement, params, episode.seed_chain,
            episode.gemm_extract_manifest, episode.extract,
            episode.tile_stream, why)) {
        return Fail(why, "endpoints_10_14_extract");
    }
    if (!VerifyRCStage3ExtractStreamCtl(
            statement, episode.gemm_extract_manifest,
            episode.extract, episode.tile_stream,
            episode.extract_stream_ctl, why) ||
        !VerifyRCStage3EpisodeTileStreamLeafCtl(
            statement, episode.gemm_extract_manifest,
            episode.tile_stream,
            episode.tile_stream_leaf_ctl, why) ||
        !VerifyRCStage3TileTreeHashCtl(
            statement, episode.gemm_extract_manifest,
            episode.tile_stream,
            episode.tile_tree_hash_ctl, why)) {
        return Fail(why, "endpoints_14_22_exact_ctl_chain");
    }
    executed.Endpoints(
        {E::EpisodeExtractInput, E::EpisodeExtractSampler,
         E::EpisodeExtractChaCha, E::EpisodeExtractScale,
         E::EpisodeExtractOutput});
    executed.Edges(
        E::EpisodeExtractSampler,
        {E::EpisodeExtractInput, E::EpisodeExtractChaCha,
         E::EpisodeExtractScale});
    executed.Edge(
        E::EpisodeBuilderSeedChain, E::EpisodeExtractChaCha);
    executed.Edge(
        E::EpisodeExtractChaCha, E::EpisodeExtractScale);
    executed.Edges(
        E::EpisodeExtractOutput,
        {E::EpisodeExtractInput, E::EpisodeExtractSampler,
         E::EpisodeExtractChaCha, E::EpisodeExtractScale});

    if (!VerifyRCStage3BoundedEpisodeProducerLinks(
            statement, params, episode.builder_trace,
            episode.gemm_extract_manifest, episode.gemm,
            episode.extract, episode.wiring, why)) {
        return Fail(why, "endpoints_5_18_producer_links");
    }
    executed.Edge(
        E::EpisodeBuilderTrace, E::EpisodeGemmOperandA);
    executed.Edge(
        E::EpisodeBuilderTrace, E::EpisodeGemmOperandB);
    executed.Edge(
        E::EpisodeGemmOutputY, E::EpisodeExtractInput);
    executed.Endpoints(
        {E::EpisodeWiringCopy, E::EpisodeWiringTranspose,
         E::EpisodeWiringResidual, E::EpisodeWiringRoundOrder});
    executed.Edges(
        E::EpisodeWiringCopy,
        {E::EpisodeBuilderTrace, E::EpisodeGemmOutputY,
         E::EpisodeExtractOutput});
    executed.Edges(
        E::EpisodeWiringTranspose,
        {E::EpisodeBuilderTrace, E::EpisodeGemmOperandA,
         E::EpisodeGemmOperandB});
    executed.Edges(
        E::EpisodeWiringResidual,
        {E::EpisodeBuilderTrace, E::EpisodeGemmOutputY});
    executed.Edges(
        E::EpisodeWiringRoundOrder,
        {E::EpisodeBuilderTrace, E::EpisodeGemmOutputY,
         E::EpisodeExtractOutput});

    // Extract verification above executes the complete tile-stream child.
    executed.Endpoints(
        {E::EpisodeTileTreeStream, E::EpisodeTileTreeLeafHash,
         E::EpisodeTileTreeInternalHash, E::EpisodeTileTreeRoot});
    executed.Edge(
        E::EpisodeExtractOutput, E::EpisodeTileTreeStream);
    executed.Edge(
        E::EpisodeTileTreeStream, E::EpisodeTileTreeLeafHash);
    executed.Edge(
        E::EpisodeTileTreeLeafHash,
        E::EpisodeTileTreeInternalHash);
    executed.Edge(
        E::EpisodeTileTreeInternalHash, E::EpisodeTileTreeRoot);

    if (!VerifyRCStage3EpisodeDigestRootChainWithRoundRootProducers(
            statement, params.rounds, episode.root_chain,
            episode.round_root_producers, why) ||
        !VerifyEpisodeTreeAndSeedJoins(episode, why)) {
        return Fail(why, "endpoints_23_24_round_digest_chain");
    }
    executed.Endpoints(
        {E::EpisodeDigestRoundRoots, E::EpisodeDigestValue});
    executed.Edge(
        E::EpisodeTileTreeRoot, E::EpisodeDigestRoundRoots);
    executed.Edge(
        E::EpisodeDigestRoundRoots, E::EpisodeDigestValue);
    executed.Edge(
        E::EpisodeDigestRoundRoots, E::EpisodeBuilderSeedChain);

    if (!VerifyRCStage3EpisodePow(
            statement, episode.pow_pin, episode.pow_proof, why)) {
        return Fail(why, "endpoint_26_pow");
    }
    executed.Endpoint(E::EpisodeDigestPow);
    executed.Edges(
        E::EpisodeDigestPow,
        {E::EpisodeDigestValue, E::EpisodeDigestHeaderTarget});

    RCStage3CoupledChainProduct coupled_chain;
    if (!VerifyRCStage3CoupledChainProduct(
            statement, header, shape, coupled.bank, coupled.gemm,
            coupled.exchange_permutation, coupled.mix,
            coupled.extract, coupled_chain, why)) {
        return Fail(why, "endpoints_27_46_coupled_chain");
    }
    executed.Endpoints(
        {E::CoupledBankSeedXof, E::CoupledBankPages,
         E::CoupledGemmOperandA, E::CoupledGemmOperandB,
         E::CoupledGemmOutputY, E::CoupledExchangeInput,
         E::CoupledExchangeHashXof, E::CoupledExchangeOutput,
         E::CoupledPermutationInput, E::CoupledPermutationOutput,
         E::CoupledMixInput, E::CoupledMixArithmetic,
         E::CoupledMixOutput, E::CoupledExtractInput,
         E::CoupledExtractSampler, E::CoupledExtractChaCha,
         E::CoupledExtractScale, E::CoupledExtractOutput,
         E::CoupledBarrierInput, E::CoupledBarrierHash,
         E::CoupledBarrierOutput});
    executed.Edge(
        E::EpisodeDigestHeaderTarget, E::CoupledBankSeedXof);
    executed.Edge(E::CoupledBankSeedXof, E::CoupledBankPages);
    executed.Edge(E::CoupledBankPages, E::CoupledGemmOperandB);
    executed.Edge(E::CoupledExtractOutput, E::CoupledGemmOperandA);
    executed.Edges(
        E::CoupledGemmOutputY,
        {E::CoupledGemmOperandA, E::CoupledGemmOperandB});
    executed.Edges(
        E::CoupledExchangeInput,
        {E::CoupledGemmOutputY, E::CoupledMixOutput});
    executed.Edge(
        E::EpisodeDigestHeaderTarget, E::CoupledExchangeHashXof);
    executed.Edges(
        E::CoupledExchangeOutput,
        {E::CoupledExchangeInput, E::CoupledExchangeHashXof});
    executed.Edge(
        E::CoupledExchangeOutput, E::CoupledPermutationInput);
    executed.Edge(
        E::CoupledPermutationInput, E::CoupledPermutationOutput);
    executed.Edge(
        E::CoupledPermutationOutput, E::CoupledMixInput);
    executed.Edge(
        E::CoupledMixInput, E::CoupledMixArithmetic);
    executed.Edge(
        E::CoupledMixArithmetic, E::CoupledMixOutput);
    // The chain verifier enforces the shape-selected branch; the inactive
    // alternative has an empty, verifier-derived schedule.
    executed.Edges(
        E::CoupledExtractInput,
        {E::CoupledMixOutput, E::CoupledExchangeOutput});
    executed.Edges(
        E::CoupledExtractSampler,
        {E::CoupledExtractInput, E::CoupledExtractChaCha,
         E::CoupledExtractScale});
    executed.Edge(
        E::EpisodeDigestHeaderTarget, E::CoupledExtractChaCha);
    executed.Edge(
        E::EpisodeDigestHeaderTarget, E::CoupledExtractScale);
    executed.Edges(
        E::CoupledExtractOutput,
        {E::CoupledExtractInput, E::CoupledExtractSampler,
         E::CoupledExtractChaCha, E::CoupledExtractScale});
    executed.Edge(
        E::CoupledExtractOutput, E::CoupledBarrierInput);
    executed.Edge(
        E::CoupledBarrierInput, E::CoupledBarrierHash);
    executed.Edge(
        E::CoupledBarrierHash, E::CoupledBarrierOutput);

    uint256 initial_link;
    if (!VerifyRCStage3CoupledInitialStateGemmLink(
            statement, shape, coupled.initial_state,
            coupled.gemm, initial_link, why)) {
        return Fail(why, "endpoint_25_to_30_initial_state");
    }
    executed.Edge(
        E::EpisodeDigestHeaderTarget, E::CoupledGemmOperandA);

    if (!VerifyRCStage3CoupledSignedRangeGemmLink(
            statement, shape, coupled.gemm,
            coupled.signed_range, why)) {
        return Fail(why, "endpoint_33_signed_range");
    }
    executed.Endpoint(E::CoupledGemmSignedRange);
    executed.Edge(
        E::CoupledGemmOutputY, E::CoupledGemmSignedRange);

    if (!VerifyRCStage3CoupledRootChainWithBoundedBankProductProducer(
            statement, header, shape, coupled.bank,
            coupled.bank_root, coupled.root_chain, why) ||
        !VerifyCoupledBarrierJoins(coupled, why)) {
        return Fail(why, "endpoints_29_52_coupled_root_chain");
    }
    executed.Endpoints(
        {E::CoupledBankRoot, E::CoupledDigestBankAndBarriers,
         E::CoupledDigestHash, E::CoupledDigestValue});
    executed.Edge(E::CoupledBankPages, E::CoupledBankRoot);
    executed.Edges(
        E::CoupledDigestBankAndBarriers,
        {E::CoupledBankRoot, E::CoupledBarrierOutput});
    executed.Edge(
        E::CoupledDigestBankAndBarriers, E::CoupledDigestHash);
    executed.Edge(
        E::CoupledDigestHash, E::CoupledDigestValue);

    if (!executed.Complete(why)) return false;
    if (episode_statement.IsNull()) {
        return Fail(why, "null_episode_statement");
    }
    if (why != nullptr) {
        *why =
            "stage3:bounded_semantic_composition:"
            "52_bounded_endpoint_sidecars_executed;"
            "81_guarded_immediate_edge_obligations_covered;"
            "production_and_recursion_disabled";
    }
    return true;
}

bool FinalizeRCStage3BoundedSemanticComposition(
    RCStage3SuccinctProof& statement,
    const CBlockHeader& header,
    const RCEpisodeParams& params,
    const RCStage3CoupledShape& shape,
    const RCStage3BoundedSemanticComposition& composition,
    std::string* why)
{
    RCStage3SuccinctProof candidate = statement;
    std::string binding_why;
    if (!AttachRCStage3BoundedSemanticBinding(
            candidate, composition, &binding_why)) {
        return Fail(
            why, "finalize_binding:" + binding_why);
    }
    if (!VerifyRCStage3BoundedSemanticComposition(
            candidate, header, params, shape,
            composition, &binding_why)) {
        return Fail(
            why, "finalize_verify:" + binding_why);
    }
    statement = std::move(candidate);
    return true;
}

static_assert(kRCStage3BoundedSemanticCompositionExecutable);
static_assert(!kRCStage3BoundedSemanticCompositionProductionExecutable);
static_assert(!kRCStage3BoundedSemanticCompositionRecursivelyConsumed);
static_assert(!kRCStage3BoundedSemanticCompositionDurablySerialized);
static_assert(!kRCStage3BoundedSemanticCompositionAuthorityReady);

} // namespace matmul::v4::rc
