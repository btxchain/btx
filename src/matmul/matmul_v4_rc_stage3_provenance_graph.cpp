// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_provenance_graph.h>

#include <matmul/matmul_v4_rc_stage3_consensus.h>

#include <algorithm>
#include <initializer_list>

namespace matmul::v4::rc {
namespace {

using E = RCStage3RelationEndpoint;
namespace gf = gkr_field;

RCStage3ProvenanceEdge Edge(
    E producer,
    bool equality,
    bool bounded,
    bool production,
    const char* construction,
    const char* remaining)
{
    RCStage3ProvenanceEdge out;
    out.producer = producer;
    out.value_equality_executable = equality;
    out.bounded_composition_executable = bounded;
    out.production_composition_executable = production;
    out.normalized_recursive_executable = false;
    out.construction = construction;
    out.remaining = remaining;
    return out;
}

RCStage3ProvenanceEdge Bounded(E producer, const char* construction)
{
    return Edge(
        producer, true, true, false, construction,
        "production streaming and normalized recursive consumption remain");
}

RCStage3ProvenanceEdge Production(E producer, const char* construction)
{
    return Edge(
        producer, true, true, true, construction,
        "normalized recursive consumption remains");
}

RCStage3ProvenanceNode Node(
    E endpoint,
    std::initializer_list<RCStage3ProvenanceEdge> producers)
{
    RCStage3ProvenanceNode out;
    out.endpoint = endpoint;
    out.producers.assign(producers.begin(), producers.end());
    return out;
}

RCStage3ProvenanceNode Public(E endpoint)
{
    RCStage3ProvenanceNode out;
    out.endpoint = endpoint;
    out.public_root = true;
    return out;
}

std::vector<RCStage3ProvenanceNode> BuildNodes()
{
    return {
        Public(E::EpisodeBuilderParams),
        Node(E::EpisodeBuilderSeedChain, {
            Production(E::EpisodeBuilderParams,
                       "episode_builder_seed_chain_v1:params"),
            Production(E::EpisodeDigestRoundRoots,
                       "episode_builder_seed_chain_v1:round_roots")}),
        Node(E::EpisodeBuilderOperandXof, {
            Bounded(E::EpisodeBuilderParams,
                    "episode_builder_operand_xof_v1:params"),
            Bounded(E::EpisodeBuilderSeedChain,
                    "episode_builder_operand_xof_v1:seed")}),
        Node(E::EpisodeBuilderTrace, {
            Bounded(E::EpisodeBuilderParams,
                    "episode_builder_trace_v1:params"),
            Bounded(E::EpisodeBuilderSeedChain,
                    "episode_builder_trace_v1:seed"),
            Bounded(E::EpisodeBuilderOperandXof,
                    "episode_builder_trace_v1:operands")}),

        Node(E::EpisodeGemmOperandA, {
            Bounded(E::EpisodeBuilderTrace,
                    "episode_bounded_producer_links_v1:builder_to_A")}),
        Node(E::EpisodeGemmOperandB, {
            Bounded(E::EpisodeBuilderTrace,
                    "episode_bounded_producer_links_v1:builder_to_B")}),
        Node(E::EpisodeGemmOutputY, {
            Bounded(E::EpisodeGemmOperandA,
                    "episode_gemm_product_v1:A_to_Y"),
            Bounded(E::EpisodeGemmOperandB,
                    "episode_gemm_product_v1:B_to_Y")}),
        Node(E::EpisodeGemmSumcheck, {
            Bounded(E::EpisodeGemmOperandA,
                    "episode_gemm_product_v1:A_to_sumcheck"),
            Bounded(E::EpisodeGemmOperandB,
                    "episode_gemm_product_v1:B_to_sumcheck"),
            Bounded(E::EpisodeGemmOutputY,
                    "episode_gemm_product_v1:Y_to_sumcheck")}),
        Node(E::EpisodeGemmSignedRange, {
            Production(E::EpisodeGemmOutputY,
                       "signed_range_v1:Y_value_root")}),

        Node(E::EpisodeExtractInput, {
            Bounded(E::EpisodeGemmOutputY,
                    "episode_bounded_producer_links_v1:Y_to_extract_input")}),
        Node(E::EpisodeExtractSampler, {
            Bounded(E::EpisodeExtractInput,
                    "episode_extract_product_v1:input_to_sampler"),
            Bounded(E::EpisodeExtractChaCha,
                    "episode_extract_product_v1:chacha_to_sampler"),
            Bounded(E::EpisodeExtractScale,
                    "episode_extract_product_v1:scale_to_sampler")}),
        Node(E::EpisodeExtractChaCha, {
            Bounded(E::EpisodeBuilderSeedChain,
                    "episode_extract_derivation_links_v1:"
                    "seed_chain_to_extract_prf")}),
        Node(E::EpisodeExtractScale, {
            Bounded(E::EpisodeExtractChaCha,
                    "episode_extract_derivation_links_v1:"
                    "extract_prf_to_scale_sha")}),
        Node(E::EpisodeExtractOutput, {
            Bounded(E::EpisodeExtractInput,
                    "episode_extract_product_v1:input_to_output"),
            Bounded(E::EpisodeExtractSampler,
                    "episode_extract_product_v1:sampler_to_output"),
            Bounded(E::EpisodeExtractChaCha,
                    "episode_extract_product_v1:chacha_to_output"),
            Bounded(E::EpisodeExtractScale,
                    "episode_extract_product_v1:scale_to_output")}),

        Node(E::EpisodeWiringCopy, {
            Bounded(E::EpisodeBuilderTrace,
                    "episode_bounded_producer_links_v1:builder_copy"),
            Bounded(E::EpisodeGemmOutputY,
                    "episode_bounded_producer_links_v1:gemm_copy"),
            Bounded(E::EpisodeExtractOutput,
                    "episode_bounded_producer_links_v1:extract_copy")}),
        Node(E::EpisodeWiringTranspose, {
            Bounded(E::EpisodeBuilderTrace,
                    "episode_bounded_producer_links_v1:builder_transpose"),
            Bounded(E::EpisodeGemmOperandA,
                    "episode_bounded_producer_links_v1:A_transpose"),
            Bounded(E::EpisodeGemmOperandB,
                    "episode_bounded_producer_links_v1:B_transpose")}),
        Node(E::EpisodeWiringResidual, {
            Bounded(E::EpisodeBuilderTrace,
                    "episode_bounded_producer_links_v1:builder_residual"),
            Bounded(E::EpisodeGemmOutputY,
                    "episode_bounded_producer_links_v1:Y_residual")}),
        Node(E::EpisodeWiringRoundOrder, {
            Bounded(E::EpisodeBuilderTrace,
                    "episode_bounded_producer_links_v1:builder_round_order"),
            Bounded(E::EpisodeGemmOutputY,
                    "episode_bounded_producer_links_v1:gemm_round_order"),
            Bounded(E::EpisodeExtractOutput,
                    "episode_bounded_producer_links_v1:extract_round_order")}),

        Node(E::EpisodeTileTreeStream, {
            Production(E::EpisodeExtractOutput,
                       "extract_stream_ctl_v1:"
                       "sampler_out_to_stream_memory_dual_logup")}),
        Node(E::EpisodeTileTreeLeafHash, {
            Production(E::EpisodeTileTreeStream,
                       "episode_tile_stream_leaf_ctl_v1:"
                       "signed_byte_same_trace_dual_logup")}),
        Node(E::EpisodeTileTreeInternalHash, {
            Production(E::EpisodeTileTreeLeafHash,
                       "tile_tree_hash_ctl_v1:"
                       "sha_output_to_parent_preimage_dual_logup")}),
        Node(E::EpisodeTileTreeRoot, {
            Production(E::EpisodeTileTreeInternalHash,
                       "tile_tree_hash_ctl_v1:"
                       "sha_output_to_typed_root_byte_dual_logup")}),
        Node(E::EpisodeDigestRoundRoots, {
            Bounded(E::EpisodeTileTreeRoot,
                    "episode_tile_root_vector_ctl_v1:"
                    "typed_byte_same_trace_dual_logup")}),
        Node(E::EpisodeDigestValue, {
            Production(E::EpisodeDigestRoundRoots,
                       "episode_round_root_digest_ctl_v1:"
                       "same_trace_typed_preimage_bytes")}),
        Public(E::EpisodeDigestHeaderTarget),
        Node(E::EpisodeDigestPow, {
            Production(E::EpisodeDigestValue,
                       "episode_digest_pow_ctl_v1:digest_same_trace_dual_logup"),
            Production(E::EpisodeDigestHeaderTarget,
                       "episode_digest_pow_ctl_v1:target_same_trace_dual_logup")}),

        Node(E::CoupledBankSeedXof, {
            Bounded(E::EpisodeDigestHeaderTarget,
                    "coupled_bank_product_v1:public_header_sigma")}),
        Node(E::CoupledBankPages, {
            Bounded(E::CoupledBankSeedXof,
                    "coupled_bank_product_v1:xof_to_pages")}),
        Node(E::CoupledBankRoot, {
            Bounded(E::CoupledBankPages,
                    "coupled_bank_flat_source_link_v1")}),

        Node(E::CoupledGemmOperandA, {
            Bounded(E::EpisodeDigestHeaderTarget,
                    "coupled_initial_state_product_v1:lobe_expand_to_barrier0_A"),
            Bounded(E::CoupledExtractOutput,
                    "coupled_chain_product_v1:prior_extract_to_gemm_a")}),
        Node(E::CoupledGemmOperandB, {
            Bounded(E::CoupledBankPages,
                    "coupled_chain_product_v1:bank_pages_to_gemm_b")}),
        Node(E::CoupledGemmOutputY, {
            Bounded(E::CoupledGemmOperandA,
                    "coupled_gemm_product_v1:A_to_Y"),
            Bounded(E::CoupledGemmOperandB,
                    "coupled_gemm_product_v1:B_to_Y")}),
        Node(E::CoupledGemmSignedRange, {
            Production(E::CoupledGemmOutputY,
                       "coupled_signed_range_v1:Y_value_roots")}),

        Node(E::CoupledExchangeInput, {
            Bounded(E::CoupledGemmOutputY,
                    "coupled_chain_product_v1:gemm_y_to_exchange_input"),
            Bounded(E::CoupledMixOutput,
                    "coupled_chain_product_v1:mix_to_material_round0")}),
        Node(E::CoupledExchangeHashXof, {
            Bounded(E::EpisodeDigestHeaderTarget,
                    "coupled_exchange_product_v1:public_material_seed")}),
        Node(E::CoupledExchangeOutput, {
            Bounded(E::CoupledExchangeInput,
                    "coupled_exchange_product_v1:input_to_output"),
            Bounded(E::CoupledExchangeHashXof,
                    "coupled_exchange_product_v1:material_to_output")}),
        Node(E::CoupledPermutationInput, {
            Bounded(E::CoupledExchangeOutput,
                    "coupled_exchange_product_v1:exchange_to_permutation")}),
        Node(E::CoupledPermutationOutput, {
            Bounded(E::CoupledPermutationInput,
                    "coupled_exchange_product_v1:permutation")}),

        Node(E::CoupledMixInput, {
            Bounded(E::CoupledPermutationOutput,
                    "coupled_chain_product_v1:permutation_output_to_mix_input")}),
        Node(E::CoupledMixArithmetic, {
            Bounded(E::CoupledMixInput,
                    "coupled_mix_product_v1:input_to_arithmetic")}),
        Node(E::CoupledMixOutput, {
            Bounded(E::CoupledMixArithmetic,
                    "coupled_mix_product_v1:arithmetic_to_output")}),

        Node(E::CoupledExtractInput, {
            Bounded(E::CoupledMixOutput,
                    "coupled_chain_product_v1:zero_round_mix_to_extract"),
            Bounded(E::CoupledExchangeOutput,
                    "coupled_chain_product_v1:material_final_to_extract")}),
        Node(E::CoupledExtractSampler, {
            Bounded(E::CoupledExtractInput,
                    "coupled_extract_product_v1:input_to_sampler"),
            Bounded(E::CoupledExtractChaCha,
                    "coupled_extract_product_v1:chacha_to_sampler"),
            Bounded(E::CoupledExtractScale,
                    "coupled_extract_product_v1:scale_to_sampler")}),
        Node(E::CoupledExtractChaCha, {
            Bounded(E::EpisodeDigestHeaderTarget,
                    "coupled_extract_product_v1:public_chacha_seed")}),
        Node(E::CoupledExtractScale, {
            Bounded(E::EpisodeDigestHeaderTarget,
                    "coupled_extract_product_v1:public_scale")}),
        Node(E::CoupledExtractOutput, {
            Bounded(E::CoupledExtractInput,
                    "coupled_extract_product_v1:input_to_output"),
            Bounded(E::CoupledExtractSampler,
                    "coupled_extract_product_v1:sampler_to_output"),
            Bounded(E::CoupledExtractChaCha,
                    "coupled_extract_product_v1:chacha_to_output"),
            Bounded(E::CoupledExtractScale,
                    "coupled_extract_product_v1:scale_to_output")}),

        Node(E::CoupledBarrierInput, {
            Bounded(E::CoupledExtractOutput,
                    "extract_barrier_link_v1")}),
        Node(E::CoupledBarrierHash, {
            Production(E::CoupledBarrierInput,
                       "global_root_chain_v1:barrier_input_to_hash")}),
        Node(E::CoupledBarrierOutput, {
            Production(E::CoupledBarrierHash,
                       "global_root_chain_v1:barrier_hash_to_output")}),
        Node(E::CoupledDigestBankAndBarriers, {
            Production(E::CoupledBankRoot,
                       "root_chain_streaming_bank_producer_v1"),
            Production(E::CoupledBarrierOutput,
                       "global_root_chain_v1:barrier_outputs_to_digest")}),
        Node(E::CoupledDigestHash, {
            Production(E::CoupledDigestBankAndBarriers,
                       "global_root_chain_v1:digest_inputs_to_hash")}),
        Node(E::CoupledDigestValue, {
            Production(E::CoupledDigestHash,
                       "global_root_chain_v1:digest_hash_to_public")}),
    };
}

} // namespace

bool VerifyRCStage3BoundedEpisodeProducerLinks(
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderTraceProduct& builder_trace,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeGemmProduct& gemm,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeWiringProduct& wiring,
    std::string* why)
{
    const auto fail = [&](const char* detail) {
        if (why != nullptr) {
            *why =
                std::string{"stage3:episode_producer_links:"} +
                detail;
        }
        return false;
    };
    if (!VerifyRCStage3EpisodeBuilderTraceManifestBinding(
            statement, params, builder_trace, manifest, why)) {
        return fail("builder_manifest");
    }
    const uint256 statement_commitment =
        RCStage3EpisodeStatementCommitment(statement);
    const uint256 manifest_commitment =
        ComputeRCStage3GemmExtractManifestCommitment(manifest);
    if (statement_commitment.IsNull() ||
        manifest_commitment.IsNull() ||
        gemm.statement_commitment != statement_commitment ||
        gemm.manifest_commitment != manifest_commitment ||
        gemm.layers.size() != manifest.layers.size() ||
        extract.statement_commitment != statement_commitment ||
        extract.manifest_commitment != manifest_commitment ||
        extract.tiles.size() != manifest.total_extract_tiles ||
        gemm.collection_commitment.IsNull() ||
        extract.collection_commitment.IsNull()) {
        return fail("product_identity");
    }

    const auto to_field = [](const auto& values) {
        std::vector<gf::Fp3> out;
        out.reserve(values.size());
        for (const auto value : values) {
            out.push_back(gf::Fp3::FromFp(
                gf::FromSigned(static_cast<int64_t>(value))));
        }
        return out;
    };
    for (uint32_t ordinal = 0;
         ordinal < manifest.layers.size(); ++ordinal) {
        const auto& spec = manifest.layers[ordinal];
        const auto& layer = gemm.layers[ordinal];
        if (layer.layer_ordinal != ordinal ||
            layer.operand_a.size() !=
                static_cast<uint64_t>(spec.m) * spec.k ||
            layer.operand_b.size() !=
                static_cast<uint64_t>(spec.k) * spec.n ||
            layer.gemm_y.size() != spec.gemm_cell_count ||
            (spec.residual_first_column < 0
                 ? !layer.residual.empty()
                 : layer.residual.size() !=
                       spec.gemm_cell_count)) {
            return fail("gemm_shape");
        }
        const auto a_root =
            ComputeRCStage3EpisodeWiringVectorRootFromValues(
                statement_commitment, spec.a.first_column,
                spec.a.n_chunks, to_field(layer.operand_a), why);
        const auto b_root =
            ComputeRCStage3EpisodeWiringVectorRootFromValues(
                statement_commitment, spec.b.first_column,
                spec.b.n_chunks, to_field(layer.operand_b), why);
        const auto y_root =
            ComputeRCStage3EpisodeWiringVectorRootFromValues(
                statement_commitment, spec.y_first_column,
                spec.y_chunks, to_field(layer.gemm_y), why);
        if (!a_root.has_value() || !b_root.has_value() ||
            !y_root.has_value() ||
            *a_root != spec.bindings.operand_a_root ||
            *b_root != spec.bindings.operand_b_root ||
            *y_root != spec.bindings.gemm_y_root) {
            return fail("gemm_registered_root");
        }

        uint64_t input_index{0};
        for (uint64_t local = 0;
             local < spec.extract_tile_count; ++local) {
            const uint64_t global =
                spec.extract_tile_begin + local;
            if (global >= extract.tiles.size()) {
                return fail("extract_omission");
            }
            const auto& tile = extract.tiles[global];
            if (tile.global_tile != global ||
                tile.layer_ordinal != ordinal ||
                tile.layer_tile_index != local) {
                return fail("extract_order");
            }
            for (uint32_t lane = 0;
                 lane < kRCMxBlockLen; ++lane, ++input_index) {
                const int64_t residual =
                    layer.residual.empty()
                    ? 0 : layer.residual[input_index];
                if (tile.input[lane] !=
                    layer.gemm_y[input_index] + residual) {
                    return fail("gemm_to_extract_value");
                }
            }
        }
        if (input_index != spec.gemm_cell_count) {
            return fail("extract_count");
        }
    }

    if (!VerifyRCStage3EpisodeWiringCopyClosure(
            statement, manifest, gemm.wiring, why)) {
        return fail("copy_proof");
    }
    if (!ValidateRCStage3EpisodeWiringProductSchedule(
            statement, manifest, gemm, extract, wiring, why) ||
        !VerifyRCStage3EpisodeWiringLocalProduct(
            statement, manifest, gemm, extract, wiring, why)) {
        return fail("wiring_proof");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_producer_links:14_bounded_edges_ok";
    }
    return true;
}

bool VerifyRCStage3EpisodeExtractPrfDerivation(
    const CBlockHeader& header,
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3GemmExtractManifest& manifest,
    std::string* why)
{
    const auto fail = [&](const char* detail) {
        if (why != nullptr) {
            *why =
                std::string{"stage3:episode_extract_derivation:"} +
                detail;
        }
        return false;
    };
    if (statement.public_inputs.header_commitment !=
            RCStage3HeaderCommitment(header) ||
        statement.public_inputs.sigma !=
            matmul::v4::DeriveSigma(header)) {
        return fail("header");
    }
    if (!VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, seed_chain, why)) {
        return fail("seed_chain");
    }
    if (!ValidateRCStage3GemmExtractManifestBinding(
            statement, manifest, why)) {
        return fail("manifest");
    }
    const auto canonical = RCGkrEpisodeLayerProvenance(
        header, params,
        seed_chain.round_root_manifest.round_roots);
    if (canonical.size() != manifest.layers.size()) {
        return fail("layer_count");
    }
    for (uint32_t ordinal = 0;
         ordinal < canonical.size(); ++ordinal) {
        const auto& expected = canonical[ordinal];
        const auto& layer = manifest.layers[ordinal];
        if (layer.ordinal != ordinal ||
            layer.kind != expected.kind ||
            layer.round != expected.round ||
            layer.layer != expected.layer ||
            layer.m != expected.m ||
            layer.n != expected.n ||
            layer.k != expected.k ||
            layer.bindings.extract_prf !=
                expected.extract_prf) {
            return fail("layer_prf");
        }
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_extract_derivation:"
            "seed_to_prf_ok";
    }
    return true;
}

bool VerifyRCStage3EpisodeExtractDerivationLinks(
    const CBlockHeader& header,
    const RCStage3SuccinctProof& statement,
    const RCEpisodeParams& params,
    const RCStage3EpisodeBuilderSeedChainProduct& seed_chain,
    const RCStage3GemmExtractManifest& manifest,
    const RCStage3EpisodeExtractProduct& extract,
    const RCStage3EpisodeTileStreamProduct& tile_stream,
    std::string* why)
{
    const auto fail = [&](const char* detail) {
        if (why != nullptr) {
            *why =
                std::string{"stage3:episode_extract_derivation:"} +
                detail;
        }
        return false;
    };
    if (!VerifyRCStage3EpisodeExtractPrfDerivation(
            header, statement, params, seed_chain, manifest,
            why)) {
        return fail("prf");
    }
    if (!VerifyRCStage3EpisodeExtractProduct(
            statement, manifest, extract, tile_stream, why)) {
        return fail("extract_scale_proofs");
    }
    if (why != nullptr) {
        *why =
            "stage3:episode_extract_derivation:"
            "seed_to_prf_and_prf_to_scale_sha_ok";
    }
    return true;
}

RCStage3ProvenanceGraphAudit CurrentRCStage3ProvenanceGraphAudit()
{
    RCStage3ProvenanceGraphAudit out;
    out.nodes = BuildNodes();
    out.exact_52_order =
        out.nodes.size() == kRCStage3RelationClosureEndpointCount;
    out.exact_public_roots_1_and_25 = out.exact_52_order;
    out.every_non_public_node_has_a_producer = out.exact_52_order;
    out.no_missing_out_of_range_self_or_duplicate_producer =
        out.exact_52_order;
    out.capability_flags_fail_closed = out.exact_52_order;

    for (uint16_t i = 0; i < out.nodes.size(); ++i) {
        const auto& node = out.nodes[i];
        const uint16_t endpoint =
            static_cast<uint16_t>(node.endpoint);
        if (endpoint != i + 1U) out.exact_52_order = false;
        const bool expected_public =
            endpoint == 1U || endpoint == 25U;
        if (node.public_root != expected_public ||
            (node.public_root && !node.producers.empty())) {
            out.exact_public_roots_1_and_25 = false;
        }
        if (!node.public_root && node.producers.empty()) {
            out.every_non_public_node_has_a_producer = false;
        }
        std::vector<uint16_t> seen;
        for (const auto& edge : node.producers) {
            ++out.edges;
            const uint16_t producer =
                static_cast<uint16_t>(edge.producer);
            if (producer == 0U ||
                producer >
                    kRCStage3RelationClosureEndpointCount ||
                producer == endpoint ||
                std::find(
                    seen.begin(), seen.end(), producer) !=
                    seen.end()) {
                out.no_missing_out_of_range_self_or_duplicate_producer =
                    false;
            }
            seen.push_back(producer);
            out.value_equality_edges +=
                edge.value_equality_executable;
            out.bounded_composition_edges +=
                edge.bounded_composition_executable;
            out.production_composition_edges +=
                edge.production_composition_executable;
            out.normalized_recursive_edges +=
                edge.normalized_recursive_executable;
            if ((edge.bounded_composition_executable ||
                 edge.production_composition_executable ||
                 edge.normalized_recursive_executable) &&
                !edge.value_equality_executable) {
                out.capability_flags_fail_closed = false;
            }
            if (edge.production_composition_executable &&
                !edge.bounded_composition_executable) {
                out.capability_flags_fail_closed = false;
            }
            if (edge.normalized_recursive_executable &&
                !edge.production_composition_executable) {
                out.capability_flags_fail_closed = false;
            }
            if (edge.value_equality_executable &&
                edge.construction.empty()) {
                out.capability_flags_fail_closed = false;
            }
            if (!edge.value_equality_executable &&
                edge.remaining.empty()) {
                out.capability_flags_fail_closed = false;
            }
        }
    }
    return out;
}

} // namespace matmul::v4::rc
