// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_semantic_status.h>

#include <matmul/matmul_v4_rc_stage3_coupled_missing_relations.h>
#include <matmul/matmul_v4_rc_stage3_coupled_bank_stream.h>
#include <matmul/matmul_v4_rc_stage3_coupled_bank_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_exchange_permutation_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_extract_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_coupled_mix_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_builder_params.h>
#include <matmul/matmul_v4_rc_stage3_episode_builder_operand_xof.h>
#include <matmul/matmul_v4_rc_stage3_episode_builder_seed_chain.h>
#include <matmul/matmul_v4_rc_stage3_episode_builder_trace.h>
#include <matmul/matmul_v4_rc_stage3_episode_header_target.h>
#include <matmul/matmul_v4_rc_stage3_episode_extract_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_gemm_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_relation_product.h>
#include <matmul/matmul_v4_rc_stage3_episode_round_roots.h>
#include <matmul/matmul_v4_rc_stage3_episode_tile_stream.h>
#include <matmul/matmul_v4_rc_stage3_episode_wiring_product.h>
#include <matmul/matmul_v4_rc_stage3_extract_barrier_link.h>
#include <matmul/matmul_v4_rc_stage3_provenance_graph.h>
#include <matmul/matmul_v4_rc_stage3_root_chain.h>

#include <hash.h>

#include <algorithm>
#include <array>
#include <set>

namespace matmul::v4::rc {

namespace {

constexpr char SEMANTIC_CLOSURE_INVENTORY_DOMAIN_V1[] =
    "BTX_RC_STAGE3_SEMANTIC_CLOSURE_INVENTORY_V1";

bool FailInventory(std::string* why, const std::string& detail)
{
    if (why != nullptr) {
        *why = "stage3:semantic_closure_inventory:" + detail;
    }
    return false;
}

void HashEndpointStatus(
    HashWriter& hash,
    const RCStage3SemanticEndpointStatus& endpoint)
{
    hash << static_cast<uint16_t>(endpoint.endpoint);
    hash << static_cast<uint16_t>(endpoint.role);
    hash << endpoint.canonical_memory;
    hash << endpoint.local_relation_engine;
    hash << endpoint.exact_instance_aggregation;
    hash << endpoint.canonical_root_chain;
    hash << endpoint.local_relation_complete;
    hash << endpoint.producer_provenance_complete;
    hash << endpoint.semantic_complete;
    hash << endpoint.recursively_consumed;
    hash << endpoint.source;
    hash << endpoint.remaining;
}

} // namespace

RCStage3SemanticStatus CurrentRCStage3SemanticStatus(
    const RCStage3CoupledShape& shape,
    const gkr_field::Fp3& gamma,
    const gkr_field::Fp3& alpha,
    uint8_t extract_scale_e,
    bool production_mode)
{
    RCStage3SemanticStatus out;
    const auto episode = CurrentRCStage3EpisodeSemanticEndpointAudit();
    const auto coupled = CurrentRCStage3CoupledSemanticAudit(
        shape, gamma, alpha, extract_scale_e);
    out.endpoints.reserve(episode.size() + coupled.size());

    for (const auto& item : episode) {
        RCStage3SemanticEndpointStatus status;
        status.endpoint = item.endpoint;
        status.role = item.role;
        status.canonical_memory =
            item.canonical_schedule_executable &&
            item.proof_owned_memory_executable &&
            item.canonical_root_authenticated &&
            item.same_trace_export_constrained;
        status.local_relation_engine =
            item.local_semantic_air_available;
        // Exact flat memory sharding is only an authenticated value ledger.
        // Do not count it as computation-instance aggregation: that bit is
        // earned only when the endpoint's relation product proves every
        // scheduled instance and binds its terminal root.
        status.exact_instance_aggregation =
            item.semantic_relation_complete;
        status.canonical_root_chain =
            item.semantic_relation_complete;
        status.local_relation_complete =
            item.semantic_relation_complete;
        // The currently complete episode range and PoW relations consume
        // roots/public values whose episode-computation provenance is still
        // open. They are locally complete, not transitively closed.
        status.producer_provenance_complete = false;
        status.semantic_complete = false;
        status.recursively_consumed =
            item.recursively_consumed;
        status.source = item.source;
        status.remaining = item.remaining;
        out.endpoints.push_back(std::move(status));
    }
    for (const auto& item : coupled) {
        RCStage3SemanticEndpointStatus status;
        status.endpoint = item.endpoint;
        status.role = item.role;
        status.canonical_memory =
            item.proof_owned_memory_root;
        status.local_relation_engine =
            item.relation_air_cell ||
            item.hash_or_xof_child_executable;
        status.exact_instance_aggregation =
            item.complete_instance_aggregation;
        status.canonical_root_chain =
            item.canonical_root_chain_link;
        status.local_relation_complete =
            item.semantic_relation_complete;
        status.producer_provenance_complete = false;
        status.semantic_complete = false;
        status.recursively_consumed = false;
        status.source = item.construction;
        status.remaining = item.remaining;
        out.endpoints.push_back(std::move(status));
    }

    // Overlay only facts executed by the exact episode relation products.
    // In particular, a local kernel is not promoted unless the product audit
    // says that every verifier-scheduled instance and both root aliases close.
    for (const auto& product :
         CurrentRCStage3EpisodeRelationProductEndpointStatus()) {
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [&product](const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == product.endpoint;
            });
        if (found == out.endpoints.end()) continue;
        found->local_relation_engine |=
            product.relation_proof_executed;
        found->exact_instance_aggregation |=
            product.all_instances_closed;
        found->canonical_root_chain |=
            product.producer_root_authenticated;
        found->local_relation_complete |=
            product.immutable_full_schedule &&
            product.relation_proof_executed &&
            product.exact_memory_root_alias &&
            product.all_instances_closed;
        found->producer_provenance_complete |=
            product.producer_root_authenticated;
        found->recursively_consumed |=
            product.recursively_consumed;
        found->source += "; episode_relation_product_v1";
        found->remaining = product.residual;
    }

    // Endpoint 1 terminates at consensus-resolved public data rather than
    // another proof relation. Its exact nine-cell vector is verifier
    // regenerated and commitment-equal to the proof-owned VALUE column.
    const auto builder_params =
        CurrentRCStage3EpisodeBuilderParamsAudit();
    {
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [&builder_params](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == builder_params.endpoint;
            });
        if (found != out.endpoints.end()) {
            found->canonical_memory |=
                builder_params.proof_owned_value_column;
            found->local_relation_engine |=
                builder_params.exact_ordered_vector_root;
            found->exact_instance_aggregation |=
                builder_params.consensus_values_regenerated;
            found->canonical_root_chain |=
                builder_params.statement_bound;
            found->local_relation_complete |=
                builder_params.local_relation_complete;
            found->producer_provenance_complete |=
                builder_params.producer_provenance_complete;
            found->recursively_consumed |=
                builder_params.recursively_consumed;
            found->source +=
                "; episode_builder_params_product_v1";
            found->remaining = builder_params.remaining;
        }
    }

    const auto round_roots =
        CurrentRCStage3EpisodeRoundRootProducerAudit();
    {
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [&round_roots](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == round_roots.endpoint;
            });
        if (found != out.endpoints.end()) {
            found->local_relation_engine |=
                round_roots.all_tile_tree_hash_children_executed;
            found->exact_instance_aggregation |=
                round_roots.verifier_ordered_round_schedule &&
                round_roots.proof_owned_digest_vector_executed;
            found->canonical_root_chain |=
                round_roots.immediate_producer_link_executable &&
                round_roots.tile_root_to_digest_vector_equality;
            found->local_relation_complete |=
                round_roots.local_relation_complete;
            found->producer_provenance_complete |=
                round_roots.transitively_complete;
            found->recursively_consumed |=
                round_roots.recursively_consumed;
            found->source += "; episode_round_root_product_v1";
            found->remaining = round_roots.remaining;
        }
    }

    const auto seed_chain =
        CurrentRCStage3EpisodeBuilderSeedChainAudit(
            true,
            builder_params.semantic_complete,
            round_roots.transitively_complete);
    {
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [&seed_chain](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == seed_chain.endpoint;
            });
        if (found != out.endpoints.end()) {
            found->local_relation_engine |=
                seed_chain.exact_all_instance_sha_execution;
            found->exact_instance_aggregation |=
                seed_chain.verifier_ordered_schedule;
            found->canonical_root_chain |=
                seed_chain.final_seed_words_memory_link &&
                seed_chain.endpoint1_params_product_executed &&
                seed_chain.round_root_vector_executed;
            found->local_relation_complete |=
                seed_chain.local_relation_complete;
            found->producer_provenance_complete |=
                seed_chain.producer_provenance_complete;
            found->recursively_consumed |=
                seed_chain.recursively_consumed;
            found->source +=
                "; episode_builder_seed_chain_v1";
            found->remaining = seed_chain.remaining;
        }
    }

    const auto operand_xof =
        CurrentRCStage3EpisodeBuilderOperandXofAudit(
            builder_params.semantic_complete,
            seed_chain.semantic_complete);
    {
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [&operand_xof](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == operand_xof.endpoint;
            });
        if (found != out.endpoints.end()) {
            const bool local =
                operand_xof.local_relation_complete &&
                (!production_mode ||
                 operand_xof.production_streaming_manifest_complete);
            found->local_relation_engine |=
                operand_xof.seed_derivation_sha_executable &&
                operand_xof.all_counter_xof_children_executable;
            found->exact_instance_aggregation |=
                operand_xof.exact_unique_operand_schedule;
            found->canonical_root_chain |=
                operand_xof.output_memory_equality_executable;
            found->local_relation_complete |= local;
            found->producer_provenance_complete |=
                local &&
                operand_xof.producer_provenance_complete;
            found->recursively_consumed |=
                operand_xof.recursively_consumed;
            found->source +=
                "; episode_builder_operand_xof_v1";
            found->remaining = operand_xof.remaining;
        }
    }

    const auto builder_trace =
        CurrentRCStage3EpisodeBuilderTraceAudit(
            builder_params.semantic_complete,
            seed_chain.semantic_complete,
            operand_xof.semantic_complete);
    {
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [&builder_trace](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == builder_trace.endpoint;
            });
        if (found != out.endpoints.end()) {
            const bool local =
                builder_trace.bounded_local_relation_complete &&
                (!production_mode ||
                 builder_trace.production_streaming_complete);
            found->canonical_memory |=
                builder_trace.canonical_trace_root_memory_executable;
            found->local_relation_engine |=
                builder_trace.all_dequant_children_executable;
            found->exact_instance_aggregation |=
                builder_trace.verifier_derived_layout_schedule &&
                builder_trace.exact_endpoint_1_3_composition;
            found->canonical_root_chain |=
                builder_trace.every_generated_source_linked &&
                builder_trace.gemm_wiring_manifest_binding_executable;
            found->local_relation_complete |= local;
            found->producer_provenance_complete |=
                local &&
                builder_trace.producer_provenance_complete;
            found->recursively_consumed |=
                builder_trace.recursively_consumed;
            found->source +=
                "; episode_builder_trace_product_v1";
            found->remaining = builder_trace.remaining;
        }
    }

    const auto header_target =
        CurrentRCStage3EpisodeHeaderTargetAudit();
    {
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [&header_target](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == header_target.endpoint;
            });
        if (found != out.endpoints.end()) {
            found->canonical_memory |=
                header_target.exact_public_vector_proved;
            found->local_relation_engine |=
                header_target.compact_target_relation_executable;
            found->exact_instance_aggregation |=
                header_target.exact_public_vector_proved;
            found->canonical_root_chain |=
                header_target.consensus_public_inputs_required;
            found->local_relation_complete |=
                header_target.local_relation_complete;
            found->producer_provenance_complete |=
                header_target.producer_provenance_complete;
            found->recursively_consumed |=
                header_target.recursively_consumed;
            found->source +=
                "; episode_header_target_product_v1";
            found->remaining = header_target.remaining;
        }
    }

    const auto gemm_product =
        CurrentRCStage3EpisodeGemmProductAudit();
    for (uint16_t endpoint_id =
             static_cast<uint16_t>(
                 RCStage3RelationEndpoint::EpisodeGemmOperandA);
         endpoint_id <= static_cast<uint16_t>(
             RCStage3RelationEndpoint::EpisodeGemmSumcheck);
         ++endpoint_id) {
        const auto endpoint =
            static_cast<RCStage3RelationEndpoint>(endpoint_id);
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [endpoint](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == endpoint;
            });
        if (found == out.endpoints.end()) continue;
        // V1 proves every exact dot-product/opening/wiring instance, but its
        // vectors and per-output-tile proofs are flat. Production only earns
        // this bit after a normalized streaming parent replaces that bundle.
        const bool local =
            gemm_product.endpoints_5_through_8_locally_complete &&
            (!production_mode ||
             gemm_product.production_streaming_complete);
        found->local_relation_engine |=
            gemm_product.every_dot_product_air_executed &&
            gemm_product.complete_signed_arithmetic_identity;
        found->exact_instance_aggregation |=
            gemm_product.immutable_full_lambda_schedule &&
            gemm_product.all_operand_openings_bound;
        found->canonical_root_chain |=
            gemm_product.y_root_bound &&
            gemm_product.y_residual_to_extract_input_equality &&
            gemm_product.internal_extract_and_wiring_producers_linked;
        found->local_relation_complete |= local;
        found->producer_provenance_complete |=
            local &&
            gemm_product.external_builder_provenance_complete;
        found->recursively_consumed |=
            gemm_product.recursively_consumed;
        found->source += "; episode_gemm_product_v1";
        found->remaining = gemm_product.remaining;
    }

    const auto tile_stream =
        CurrentRCStage3EpisodeTileStreamAudit();
    for (uint16_t endpoint_id =
             static_cast<uint16_t>(
                 RCStage3RelationEndpoint::EpisodeTileTreeStream);
         endpoint_id <= static_cast<uint16_t>(
             RCStage3RelationEndpoint::EpisodeTileTreeRoot);
         ++endpoint_id) {
        const auto endpoint =
            static_cast<RCStage3RelationEndpoint>(endpoint_id);
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [endpoint](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == endpoint;
            });
        if (found == out.endpoints.end()) continue;
        found->local_relation_engine |=
            tile_stream.endpoints_19_through_22_locally_complete;
        found->exact_instance_aggregation |=
            tile_stream.verifier_derived_emission_schedule &&
            tile_stream.every_streamed_extract_shard_executed &&
            tile_stream.every_leaf_hash_executed &&
            tile_stream.every_internal_hash_executed;
        found->canonical_root_chain |=
            tile_stream.extract_out_to_stream_byte_equality &&
            tile_stream.proof_owned_stream_memory_executed &&
            tile_stream.canonical_round_root_derived;
        found->local_relation_complete |=
            tile_stream.endpoints_19_through_22_locally_complete;
        found->producer_provenance_complete |=
            tile_stream.transitively_complete;
        found->recursively_consumed |=
            tile_stream.recursively_consumed;
        found->source += "; episode_tile_stream_product_v1";
        found->remaining = tile_stream.remaining;
    }

    const auto extract_product =
        CurrentRCStage3EpisodeExtractProductAudit();
    for (uint16_t endpoint_id =
             static_cast<uint16_t>(
                 RCStage3RelationEndpoint::EpisodeExtractInput);
         endpoint_id <= static_cast<uint16_t>(
             RCStage3RelationEndpoint::EpisodeExtractOutput);
         ++endpoint_id) {
        const auto endpoint =
            static_cast<RCStage3RelationEndpoint>(endpoint_id);
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [endpoint](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == endpoint;
            });
        if (found == out.endpoints.end()) continue;
        // V1 owns an exact flat all-tile vector. Production needs the same
        // statement behind normalized recursive streaming before this audit
        // can count it there.
        const bool local =
            !production_mode &&
            extract_product.endpoints_10_through_14_locally_complete;
        found->local_relation_engine |=
            extract_product.input_opening_and_mix_air_executed ||
            extract_product.sampler_walk_executed ||
            extract_product.chacha_consumption_air_executed ||
            extract_product.scale_sha_air_executed;
        found->exact_instance_aggregation |=
            extract_product.exact_all_tile_schedule;
        found->canonical_root_chain |=
            extract_product.dequant_output_root_bound &&
            extract_product.endpoint19_equality_executed;
        found->local_relation_complete |= local;
        found->producer_provenance_complete |=
            local && extract_product.transitively_complete;
        found->recursively_consumed |=
            extract_product.recursively_consumed;
        found->source += "; episode_extract_product_v1";
        found->remaining = extract_product.remaining;
    }

    const auto wiring_product =
        CurrentRCStage3EpisodeWiringProductAudit();
    for (uint16_t endpoint_id =
             static_cast<uint16_t>(
                 RCStage3RelationEndpoint::EpisodeWiringTranspose);
         endpoint_id <= static_cast<uint16_t>(
             RCStage3RelationEndpoint::EpisodeWiringRoundOrder);
         ++endpoint_id) {
        const auto endpoint =
            static_cast<RCStage3RelationEndpoint>(endpoint_id);
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [endpoint](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == endpoint;
            });
        if (found == out.endpoints.end()) continue;
        const bool local =
            !production_mode &&
            wiring_product
                .endpoints_16_through_18_bounded_local_complete;
        found->local_relation_engine |=
            wiring_product.dual_transpose_permutation_executable ||
            wiring_product.residual_addition_executable ||
            wiring_product.every_producer_consumer_edge_executable;
        found->exact_instance_aggregation |=
            wiring_product.exact_lambda_transpose_schedule &&
            wiring_product.exact_residual_schedule &&
            wiring_product.exact_round_order_schedule;
        found->canonical_root_chain |=
            wiring_product.transpose_memory_aliases_executable &&
            wiring_product.residual_memory_aliases_executable &&
            wiring_product.round_order_memory_aliases_executable;
        found->local_relation_complete |= local;
        found->producer_provenance_complete |=
            local &&
            wiring_product.external_producer_provenance_complete;
        found->recursively_consumed |=
            wiring_product.recursively_consumed;
        found->source += "; episode_wiring_product_v1";
        found->remaining = wiring_product.remaining;
    }

    // Root-chain proofs make important local relations executable, but this
    // audit deliberately does not treat a link to another incomplete endpoint
    // as producer provenance. That prevents a terminal digest equality from
    // hiding an open tile-tree, Extract, or bank-page ancestor.
    for (const auto& root : CurrentRCStage3RootChainEndpointAudit()) {
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [&root](const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == root.endpoint;
            });
        if (found == out.endpoints.end()) continue;
        found->local_relation_engine |=
            root.proof_owned_vector_executable ||
            root.hash_provenance_executable;
        found->exact_instance_aggregation |=
            root.typed_manifest_executable &&
            (root.proof_owned_vector_executable ||
             root.hash_provenance_executable);
        found->canonical_root_chain |=
            root.downstream_equality_executable &&
            (root.outer_statement_equality_executable ||
             root.upstream_relation_equality_executable);
        found->local_relation_complete |=
            root.local_relation_complete;
        found->producer_provenance_complete |=
            root.producer_graph_complete;
        if (!root.remaining.empty()) {
            found->remaining = root.remaining;
        }
        found->source += "; global_root_chain_v1";
    }

    for (const auto& missing :
         CurrentRCStage3CoupledMissingEndpointAudit(shape)) {
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [&missing](const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == missing.endpoint;
            });
        if (found == out.endpoints.end()) continue;
        found->local_relation_engine |=
            missing.local_engine_executable;
        found->exact_instance_aggregation |=
            missing.exact_all_instance_proof_execution;
        found->canonical_root_chain |=
            missing.outer_statement_equality;
        found->local_relation_complete |=
            missing.local_relation_complete;
        found->producer_provenance_complete |=
            missing.producer_graph_complete;
        if (!missing.remaining.empty()) {
            found->remaining = missing.remaining;
        }
        found->source += "; coupled_missing_relations_v1";
    }

    const auto coupled_gemm =
        CurrentRCStage3CoupledGemmProductAudit();
    for (uint16_t endpoint_id =
             static_cast<uint16_t>(
                 RCStage3RelationEndpoint::CoupledGemmOperandA);
         endpoint_id <= static_cast<uint16_t>(
             RCStage3RelationEndpoint::CoupledGemmOutputY);
         ++endpoint_id) {
        const auto endpoint =
            static_cast<RCStage3RelationEndpoint>(endpoint_id);
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [endpoint](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == endpoint;
            });
        if (found == out.endpoints.end()) continue;
        const bool local =
            !production_mode &&
            coupled_gemm.endpoints_30_through_32_locally_complete;
        found->local_relation_engine |=
            coupled_gemm.every_dot_air_executed;
        found->exact_instance_aggregation |=
            coupled_gemm.immutable_shape_derived_schedule &&
            coupled_gemm.every_a_opening_bound &&
            coupled_gemm.every_b_opening_bound &&
            coupled_gemm.every_y_opening_bound;
        found->canonical_root_chain |= local;
        found->local_relation_complete |= local;
        found->producer_provenance_complete |=
            local &&
            coupled_gemm.bank_page_producer_provenance_complete &&
            coupled_gemm.prior_state_producer_provenance_complete;
        found->recursively_consumed |=
            coupled_gemm.recursively_consumed;
        found->source += "; coupled_gemm_product_v1";
        found->remaining = coupled_gemm.remaining;
    }

    const auto coupled_bank =
        CurrentRCStage3CoupledBankProductAudit();
    for (uint16_t endpoint_id =
             static_cast<uint16_t>(
                 RCStage3RelationEndpoint::CoupledBankSeedXof);
         endpoint_id <= static_cast<uint16_t>(
             RCStage3RelationEndpoint::CoupledBankPages);
         ++endpoint_id) {
        const auto endpoint =
            static_cast<RCStage3RelationEndpoint>(endpoint_id);
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [endpoint](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == endpoint;
            });
        if (found == out.endpoints.end()) continue;
        const bool local =
            !production_mode &&
            coupled_bank.endpoints_27_28_bounded_local_complete;
        found->canonical_memory |=
            coupled_bank.proof_owned_page_memory_root;
        found->local_relation_engine |=
            coupled_bank.bank_seed_sha_executed &&
            coupled_bank.page_seed_sha_executed &&
            coupled_bank.mantissa_and_scale_xof_executed &&
            coupled_bank.xof_to_page_dequant_equality_executed;
        found->exact_instance_aggregation |=
            coupled_bank.immutable_all_page_schedule;
        found->canonical_root_chain |=
            coupled_bank.endpoint29_source_root_equality_executable;
        found->local_relation_complete |= local;
        // The bounded flat proof is exact, but its proof children are not yet
        // recursively consumed by the normalized root.
        found->producer_provenance_complete |= false;
        found->recursively_consumed |=
            coupled_bank.recursively_consumed;
        found->source += "; coupled_bank_product_v1";
        found->remaining = coupled_bank.remaining;
    }

    const auto exchange_permutation =
        CurrentRCStage3CoupledExchangePermutationProductAudit();
    for (uint16_t endpoint_id =
             static_cast<uint16_t>(
                 RCStage3RelationEndpoint::CoupledExchangeInput);
         endpoint_id <= static_cast<uint16_t>(
             RCStage3RelationEndpoint::CoupledPermutationOutput);
         ++endpoint_id) {
        const auto endpoint =
            static_cast<RCStage3RelationEndpoint>(endpoint_id);
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [endpoint](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == endpoint;
            });
        if (found == out.endpoints.end()) continue;
        const bool local =
            !production_mode &&
            exchange_permutation
                .endpoints_34_through_38_bounded_local_complete;
        found->local_relation_engine |=
            exchange_permutation.fixed_segment_equality_executable ||
            exchange_permutation.material_seed_sha256d_executable ||
            exchange_permutation.material_sha_xof_executable ||
            exchange_permutation
                .permutation_indexed_product_executable;
        found->exact_instance_aggregation |=
            exchange_permutation.exact_exchange_schedule &&
            exchange_permutation.exact_public_permutation_schedule;
        found->canonical_root_chain |=
            exchange_permutation.proof_owned_endpoint_roots;
        found->local_relation_complete |= local;
        found->producer_provenance_complete |=
            local &&
            exchange_permutation
                .external_producer_provenance_complete;
        found->recursively_consumed |=
            exchange_permutation.recursively_consumed;
        found->source +=
            "; coupled_exchange_permutation_product_v1";
        found->remaining = exchange_permutation.remaining;
    }

    const auto coupled_mix =
        CurrentRCStage3CoupledMixProductAudit();
    for (uint16_t endpoint_id =
             static_cast<uint16_t>(
                 RCStage3RelationEndpoint::CoupledMixInput);
         endpoint_id <= static_cast<uint16_t>(
             RCStage3RelationEndpoint::CoupledMixOutput);
         ++endpoint_id) {
        const auto endpoint =
            static_cast<RCStage3RelationEndpoint>(endpoint_id);
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [endpoint](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == endpoint;
            });
        if (found == out.endpoints.end()) continue;
        const bool local =
            !production_mode &&
            coupled_mix
                .endpoints_39_40_41_bounded_local_complete;
        found->local_relation_engine |=
            coupled_mix.mix_seed_and_mask_sha_executed &&
            coupled_mix.complete_u64_limb_range_executed &&
            coupled_mix.all_sum_difference_arithmetic_executed;
        found->exact_instance_aggregation |=
            coupled_mix.immutable_full_butterfly_schedule &&
            coupled_mix.index_relabelling_bound;
        found->canonical_root_chain |=
            coupled_mix.stage_state_equality_executed;
        found->local_relation_complete |= local;
        found->producer_provenance_complete |=
            local &&
            coupled_mix.producer_provenance_complete;
        found->recursively_consumed |=
            coupled_mix.recursively_consumed;
        found->source += "; coupled_mix_product_v1";
        found->remaining = coupled_mix.remaining;
    }

    const auto coupled_extract =
        CurrentRCStage3CoupledExtractProductAudit();
    for (uint16_t endpoint_id =
             static_cast<uint16_t>(
                 RCStage3RelationEndpoint::CoupledExtractInput);
         endpoint_id <= static_cast<uint16_t>(
             RCStage3RelationEndpoint::CoupledExtractOutput);
         ++endpoint_id) {
        const auto endpoint =
            static_cast<RCStage3RelationEndpoint>(endpoint_id);
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [endpoint](
                const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint == endpoint;
            });
        if (found == out.endpoints.end()) continue;
        const bool local =
            !production_mode &&
            coupled_extract
                .endpoints_42_through_46_bounded_complete;
        found->local_relation_engine |=
            coupled_extract.int64_mix_binding_executable &&
            coupled_extract.sampler_walk_executable &&
            coupled_extract.chacha_consumption_executable &&
            coupled_extract.scale_sha_executable;
        found->exact_instance_aggregation |=
            coupled_extract.exact_all_tile_schedule;
        found->canonical_root_chain |=
            coupled_extract.output_memory_root_executable &&
            coupled_extract.endpoint47_equality_executable;
        found->local_relation_complete |= local;
        found->producer_provenance_complete |=
            local &&
            coupled_extract
                .upstream_producer_provenance_complete;
        found->recursively_consumed |=
            coupled_extract.recursively_consumed;
        found->source += "; coupled_extract_product_v1";
        found->remaining = coupled_extract.remaining;
    }

    // Endpoint 47 now executes the exact ordered equality product from every
    // CoupledExtractOutput shard into every barrier input byte. This closes
    // the immediate relation, but not the open provenance ancestors of
    // CoupledExtractOutput itself.
    const auto extract_barrier =
        CurrentRCStage3ExtractBarrierLinkAudit(shape);
    {
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [](const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint ==
                    RCStage3RelationEndpoint::CoupledBarrierInput;
            });
        if (found != out.endpoints.end()) {
            const bool local =
                extract_barrier.consensus_shape_resolved &&
                extract_barrier.exact_extract_order_enforced &&
                extract_barrier.exact_barrier_order_enforced &&
                extract_barrier.signed_byte_embedding_bound &&
                extract_barrier.all_instance_proof_product_executable;
            found->local_relation_engine |= local;
            found->exact_instance_aggregation |= local;
            found->canonical_root_chain |= local;
            found->local_relation_complete |= local;
            // Deliberately false until endpoint 46 is transitively complete.
            found->producer_provenance_complete |= false;
            found->source += "; extract_barrier_link_v1";
            found->remaining = extract_barrier.remaining;
        }
    }

    const auto bank_stream =
        CurrentRCStage3CoupledBankStreamAudit();
    {
        const auto found = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [](const RCStage3SemanticEndpointStatus& item) {
                return item.endpoint ==
                    RCStage3RelationEndpoint::CoupledBankRoot;
            });
        if (found != out.endpoints.end()) {
            const bool local =
                bank_stream.production_counts_manifest_derived &&
                bank_stream.source_chunk_openings_executable &&
                bank_stream.byte_to_sha_word_projection_executable &&
                bank_stream.fixed_program_leaf_proof_executable &&
                bank_stream.exact_chaining_aggregation_schedule_executable &&
                bank_stream.interval_relation_air_executable &&
                bank_stream.recursive_child_tree_verifier_executable &&
                bank_stream.second_pass_and_bank_root_executable &&
                bank_stream.recursive_interval_proof_executable;
            found->local_relation_engine |= local;
            found->exact_instance_aggregation |= local;
            found->canonical_root_chain |= local;
            found->local_relation_complete |= local;
            // The full child tree is executable but not a normalized succinct
            // fixed point, and its source root still lacks endpoint-28
            // producer equality.
            found->producer_provenance_complete |= false;
            found->source += "; coupled_bank_stream_recursive_v1";
            found->remaining = bank_stream.remaining;
        }
    }

    std::array<uint16_t, kRCStage3RelationClosureRoleCount> complete{};
    out.registered_endpoints =
        static_cast<uint16_t>(out.endpoints.size());
    for (auto& item : out.endpoints) {
        // This is the only definition used by the consolidated count.
        // Local relation execution without an authenticated producer is not
        // a semantically complete episode/coupled endpoint.
        item.semantic_complete =
            item.local_relation_complete &&
            item.producer_provenance_complete;
        out.canonical_memory_endpoints += item.canonical_memory;
        out.local_relation_engines += item.local_relation_engine;
        out.exact_instance_aggregations +=
            item.exact_instance_aggregation;
        out.canonical_root_chains += item.canonical_root_chain;
        out.local_relation_complete_endpoints +=
            item.local_relation_complete;
        out.producer_provenance_endpoints +=
            item.producer_provenance_complete;
        out.semantic_complete_endpoints += item.semantic_complete;
        out.recursively_consumed_endpoints +=
            item.recursively_consumed;
    }
    out.registry_exact =
        out.endpoints.size() ==
            kRCStage3RelationClosureEndpointCount;
    if (out.registry_exact) {
        for (uint16_t i = 0; i < out.endpoints.size(); ++i) {
            if (static_cast<uint16_t>(
                    out.endpoints[i].endpoint) != i + 1) {
                out.registry_exact = false;
                break;
            }
        }
    }

    const auto& role_order = RCStage3UnifiedRoleOrder();
    for (uint16_t role_index = 0;
         role_index < role_order.size(); ++role_index) {
        const auto role = role_order[role_index];
        const auto first = std::find_if(
            out.endpoints.begin(), out.endpoints.end(),
            [role](const RCStage3SemanticEndpointStatus& item) {
                return item.role == role;
            });
        const bool any =
            first != out.endpoints.end();
        const bool all = any && std::all_of(
            first, out.endpoints.end(),
            [role](const RCStage3SemanticEndpointStatus& item) {
                return item.role != role ||
                       (item.semantic_complete &&
                        item.recursively_consumed);
            });
        complete[role_index] = all;
        out.complete_roles += all;
    }
    return out;
}

uint256 ComputeRCStage3SemanticClosureInventoryCommitmentV1(
    const RCStage3SemanticClosureInventoryV1& inventory)
{
    HashWriter hash;
    hash << SEMANTIC_CLOSURE_INVENTORY_DOMAIN_V1;
    hash << inventory.version;
    hash << inventory.production_mode;
    hash << inventory.exact_registry;
    hash << inventory.registered_endpoints;
    hash << inventory.local_relation_complete_endpoints;
    hash << inventory.strict_transitive_complete_endpoints;
    hash << inventory.recursively_consumed_endpoints;
    hash << inventory.complete_roles;
    hash << inventory.registered_edges;
    hash << inventory.value_equality_edges;
    hash << inventory.bounded_composition_edges;
    hash << inventory.production_composition_edges;
    hash << inventory.normalized_row_tagged_equality_edges;
    hash << static_cast<uint32_t>(inventory.endpoints.size());
    for (const auto& endpoint : inventory.endpoints) {
        HashEndpointStatus(hash, endpoint);
    }
    hash << static_cast<uint32_t>(inventory.edges.size());
    for (const auto& edge : inventory.edges) {
        hash << static_cast<uint16_t>(edge.producer);
        hash << static_cast<uint16_t>(edge.producer_role);
        hash << static_cast<uint16_t>(edge.consumer);
        hash << static_cast<uint16_t>(edge.consumer_role);
        hash << edge.value_equality_executable;
        hash << edge.bounded_composition_executable;
        hash << edge.production_composition_executable;
        hash << edge.normalized_row_tagged_equality;
        hash << edge.producer_strictly_complete;
        hash << edge.consumer_local_relation_complete;
        hash << edge.blocker_mask;
        hash << edge.construction;
        hash << edge.remaining;
    }
    hash << inventory.authority_ready;
    return hash.GetHash();
}

RCStage3SemanticClosureInventoryV1
BuildRCStage3SemanticClosureInventoryV1(
    const RCStage3CoupledShape& shape,
    const gkr_field::Fp3& gamma,
    const gkr_field::Fp3& alpha,
    uint8_t extract_scale_e,
    bool production_mode)
{
    RCStage3SemanticClosureInventoryV1 out;
    out.production_mode = production_mode;

    const auto semantic = CurrentRCStage3SemanticStatus(
        shape, gamma, alpha, extract_scale_e, production_mode);
    const auto graph = CurrentRCStage3ProvenanceGraphAudit();
    out.exact_registry =
        semantic.registry_exact &&
        graph.exact_52_order &&
        graph.exact_public_roots_1_and_25 &&
        graph.every_non_public_node_has_a_producer &&
        graph.no_missing_out_of_range_self_or_duplicate_producer &&
        graph.nodes.size() == kRCStage3RelationClosureEndpointCount;
    out.registered_endpoints = semantic.registered_endpoints;
    out.local_relation_complete_endpoints =
        semantic.local_relation_complete_endpoints;
    out.strict_transitive_complete_endpoints =
        semantic.semantic_complete_endpoints;
    out.recursively_consumed_endpoints =
        semantic.recursively_consumed_endpoints;
    out.complete_roles = semantic.complete_roles;
    out.endpoints = semantic.endpoints;
    out.registered_edges = graph.edges;

    std::set<uint32_t> ordered_edges;
    out.edges.reserve(graph.edges);
    for (const auto& node : graph.nodes) {
        const uint16_t consumer_id =
            static_cast<uint16_t>(node.endpoint);
        if (consumer_id == 0 ||
            consumer_id > semantic.endpoints.size()) {
            out.exact_registry = false;
            continue;
        }
        const auto& consumer =
            semantic.endpoints[consumer_id - 1U];
        for (const auto& declared : node.producers) {
            const uint16_t producer_id =
                static_cast<uint16_t>(declared.producer);
            if (producer_id == 0 ||
                producer_id > semantic.endpoints.size()) {
                out.exact_registry = false;
                continue;
            }
            const auto& producer =
                semantic.endpoints[producer_id - 1U];
            const uint32_t edge_id =
                static_cast<uint32_t>(producer_id) * 64U +
                consumer_id;
            if (!ordered_edges.insert(edge_id).second) {
                out.exact_registry = false;
            }

            RCStage3SemanticClosureEdgeStatusV1 edge;
            edge.producer = declared.producer;
            edge.producer_role = producer.role;
            edge.consumer = node.endpoint;
            edge.consumer_role = consumer.role;
            edge.value_equality_executable =
                declared.value_equality_executable;
            edge.bounded_composition_executable =
                declared.bounded_composition_executable;
            edge.production_composition_executable =
                declared.production_composition_executable;
            edge.normalized_row_tagged_equality =
                declared.normalized_recursive_executable;
            edge.producer_strictly_complete =
                producer.semantic_complete;
            edge.consumer_local_relation_complete =
                consumer.local_relation_complete;
            edge.construction = declared.construction;
            edge.remaining = declared.remaining;
            if (!consumer.local_relation_complete) {
                edge.blocker_mask |=
                    kRCStage3SemanticClosureMissingLocalRelationV1;
            }
            if (!producer.semantic_complete) {
                edge.blocker_mask |=
                    kRCStage3SemanticClosureMissingProducerProvenanceV1;
            }
            if (!declared.production_composition_executable) {
                edge.blocker_mask |=
                    kRCStage3SemanticClosureMissingProductionEqualityV1;
            }
            if (!declared.normalized_recursive_executable) {
                edge.blocker_mask |=
                    kRCStage3SemanticClosureMissingNormalizedEqualityV1;
            }
            if (!consumer.recursively_consumed) {
                edge.blocker_mask |=
                    kRCStage3SemanticClosureMissingRecursiveConsumptionV1;
            }
            out.value_equality_edges +=
                edge.value_equality_executable;
            out.bounded_composition_edges +=
                edge.bounded_composition_executable;
            out.production_composition_edges +=
                edge.production_composition_executable;
            out.normalized_row_tagged_equality_edges +=
                edge.normalized_row_tagged_equality;
            out.edges.push_back(std::move(edge));
        }
    }
    if (out.edges.size() != graph.edges) {
        out.exact_registry = false;
    }
    out.authority_ready =
        out.exact_registry &&
        out.registered_endpoints ==
            kRCStage3RelationClosureEndpointCount &&
        out.strict_transitive_complete_endpoints ==
            kRCStage3RelationClosureEndpointCount &&
        out.recursively_consumed_endpoints ==
            kRCStage3RelationClosureEndpointCount &&
        out.complete_roles == kRCStage3RelationClosureRoleCount &&
        out.production_composition_edges == out.registered_edges &&
        out.normalized_row_tagged_equality_edges ==
            out.registered_edges;
    out.inventory_commitment =
        ComputeRCStage3SemanticClosureInventoryCommitmentV1(out);
    return out;
}

bool ValidateRCStage3SemanticClosureInventoryV1(
    const RCStage3SemanticClosureInventoryV1& inventory,
    const RCStage3CoupledShape& shape,
    const gkr_field::Fp3& gamma,
    const gkr_field::Fp3& alpha,
    uint8_t extract_scale_e,
    bool production_mode,
    std::string* why)
{
    if (inventory.version !=
            kRCStage3SemanticClosureInventoryVersionV1 ||
        inventory.production_mode != production_mode) {
        return FailInventory(why, "version_or_mode");
    }
    if (inventory.inventory_commitment.IsNull() ||
        inventory.inventory_commitment !=
            ComputeRCStage3SemanticClosureInventoryCommitmentV1(
                inventory)) {
        return FailInventory(why, "commitment");
    }
    const auto expected = BuildRCStage3SemanticClosureInventoryV1(
        shape, gamma, alpha, extract_scale_e, production_mode);
    if (!(inventory == expected)) {
        return FailInventory(
            why, "not_verifier_rebuilt_exact_inventory");
    }
    return true;
}

} // namespace matmul::v4::rc
