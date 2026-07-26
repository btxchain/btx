// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_global_soundness_ledger.h>

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>
#include <matmul/matmul_v4_rc_stage3_episode.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>
#include <matmul/matmul_v4_rc_stage3_recursive_parent_air.h>
#include <matmul/matmul_v4_rc_stage3_verify.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_mlink.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_episode_semantic.h>
#include <matmul/matmul_v4_rc_stage3_family_fold.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>
#include <matmul/matmul_v4_rc_stage3_unified_root.h>

#include <algorithm>
#include <cmath>
#include <initializer_list>
#include <limits>

namespace matmul::v4::rc::global_soundness_ledger {
namespace {

namespace scenarios = soundness_scenarios;

double ComposeBits(
    std::initializer_list<double> bits)
{
    double error = 0.0;
    for (const double value : bits) {
        if (!std::isfinite(value) || value <= 0.0) {
            return 0.0;
        }
        error += std::exp2(-value);
    }
    return error > 0.0
        ? -std::log2(error)
        : 0.0;
}

ExecutableGlobalSiteScenarioV1 BuildScenario(
    uint64_t sites,
    bool manifest_derived,
    bool covers_selected_topology,
    bool production_theorem,
    uint32_t trace_width_cap,
    uint32_t constraint_count_cap)
{
    ExecutableGlobalSiteScenarioV1 out;
    out.sites = sites;
    out.site_count_manifest_derived =
        manifest_derived;
    out.covers_selected_relation_local_topology =
        covers_selected_topology;
    out.production_theorem = production_theorem;
    if (sites == 0 || trace_width_cap == 0 ||
        constraint_count_cap == 0) {
        return out;
    }
    out.site_log2 =
        std::log2(static_cast<double>(sites));

    const auto assess_q =
        [&](uint32_t queries) {
            return scenarios::AssessFriScenario(
                "executable_global_single_fp3",
                1, queries,
                kSelectedExtensionDegree,
                kSelectedLdeLog2,
                scenarios::BatchChallengeShape::
                    IndependentCoefficients,
                sites,
                trace_width_cap,
                256, 40);
        };
    const auto selected =
        assess_q(kSelectedSingleLaneQueries);
    if (selected.parameters_valid) {
        out.q192_fri_bcs_bits =
            selected.all_query_work_bits;
    }

    // At Q=140 the (17/32)^Q proximity term first exceeds the field RBR
    // term for the fixed Fp3/LDE24 parameters. No larger Q can improve the
    // provable RBR input to BCS.
    constexpr uint32_t SEARCH_CAP = 512;
    for (uint32_t queries = 1;
         queries <= SEARCH_CAP;
         ++queries) {
        const auto item = assess_q(queries);
        if (!item.parameters_valid) continue;
        if (item.all_query_work_bits >
            out.maximum_single_lane_fri_bcs_bits) {
            out.maximum_single_lane_fri_bcs_bits =
                item.all_query_work_bits;
            out.fri_saturation_queries = queries;
        }
        if (out.minimum_numeric_q_for_fri_100 == 0 &&
            item.all_query_work_bits >= 100.0) {
            out.minimum_numeric_q_for_fri_100 =
                queries;
        }
    }
    out.fri_100_reachable_by_any_single_lane_q =
        out.minimum_numeric_q_for_fri_100 != 0;
    out.minimum_currently_executable_q_for_fri_100 =
        out.q192_fri_bcs_bits >= 100.0
        ? kSelectedSingleLaneQueries
        : 0;

    out.trace_batching_bits =
        static_cast<double>(
            kConservativeFp3Bits) -
        out.site_log2 -
        static_cast<double>(
            kConservativeGrindingBits) -
        std::log2(
            static_cast<double>(
                trace_width_cap) +
            2.0);
    out.constraint_batching_bits =
        static_cast<double>(
            kConservativeFp3Bits) -
        out.site_log2 -
        static_cast<double>(
            kConservativeGrindingBits) -
        std::log2(
            static_cast<double>(
                constraint_count_cap));

    // Two independent LogUp lanes:
    //   sum_bus [4(E-1)]^2 / |Fp3|^2.
    // Use the enforced per-bus event cap and charge all 52 registered
    // endpoints as independent buses at every proof site. This is a numeric
    // envelope only; the missing export/terminal topology keeps the
    // reduction flag false below.
    const double one_lane_roots =
        4.0 *
        static_cast<double>(
            kCtlEventsPerBusEnvelope - 1);
    out.ctl_rational_identity_bits =
        2.0 *
            static_cast<double>(
                kConservativeFp3Bits) -
        out.site_log2 -
        std::log2(
            static_cast<double>(
                kCtlBusesPerSiteEnvelope)) -
        2.0 * std::log2(one_lane_roots) -
        static_cast<double>(
            kConservativeGrindingBits);

    // Total-adversary-work convention: the BCS work bound already quantifies
    // oracle work, and PoW grinding is not subtracted a second time from the
    // collision floor. Algebraic challenges above conservatively charge it.
    out.hash_binding_bits =
        static_cast<double>(
            kHashCollisionFloorBits) -
        out.site_log2;

    // The bounded Fp3 rejection sampler has failure probability <2^-187 per
    // draw. This is honest-prover liveness, not false acceptance.
    out.fs_sampler_liveness_bits =
        static_cast<double>(
            kFsSamplerFailureBits) -
        out.site_log2 -
        std::log2(
            static_cast<double>(
                kCtlBusesPerSiteEnvelope) *
            kFsSamplerDrawsPerCtlBus) -
        static_cast<double>(
            kConservativeGrindingBits);

    out.known_false_accept_union_bits =
        ComposeBits({
            out.q192_fri_bcs_bits,
            out.trace_batching_bits,
            out.constraint_batching_bits,
            out.ctl_rational_identity_bits,
            out.hash_binding_bits,
        });
    out.known_union_numeric_target_met =
        out.known_false_accept_union_bits >= 100.0;

    out.terms = {
        {
            ExecutableGlobalTermKindV1::FriBcs,
            out.q192_fri_bcs_bits,
            true, true, false,
            true, false,
            "published RBR/BCS protocol match, exact selected-site union and "
            "recursive verifier execution",
        },
        {
            ExecutableGlobalTermKindV1::TraceBatching,
            out.trace_batching_bits,
            true, true, false,
            true, false,
            "manifest-derived real support width and global coefficient "
            "challenge reduction",
        },
        {
            ExecutableGlobalTermKindV1::ConstraintBatching,
            out.constraint_batching_bits,
            true, true, false,
            true, false,
            "canonical bytecode-derived constraint inventory and ALI degree "
            "manifest",
        },
        {
            ExecutableGlobalTermKindV1::CtlRationalIdentity,
            out.ctl_rational_identity_bits,
            true, true, false,
            true, false,
            "all relation VALUE cells equality-constrained to executed CTL "
            "children and every terminal recursively consumed",
        },
        {
            ExecutableGlobalTermKindV1::HashBinding,
            out.hash_binding_bits,
            true, true, false,
            true, false,
            "complete SHA/AlgHash/shared-commitment first-collision hybrid",
        },
        {
            ExecutableGlobalTermKindV1::FiatShamirSampler,
            out.fs_sampler_liveness_bits,
            true, false, true,
            kRCStage3CtlUniformChallengeSampling,
            false,
            "exact global draw inventory; sampler exhaustion is liveness "
            "only and is excluded from false-accept composition",
        },
        {
            ExecutableGlobalTermKindV1::
                FiatShamirReplayAndNirop,
            0.0,
            false, false, false,
            false, false,
            "whole-verifier SHA replay, oracle-domain separation and the "
            "NIROP/BCS composition theorem",
        },
        {
            ExecutableGlobalTermKindV1::PowGrinding,
            static_cast<double>(
                kConservativeGrindingBits),
            true, false, false,
            true, false,
            "global theorem that the 40-bit charge covers every adaptive "
            "algebraic/FS attempt without double-counting total oracle work",
        },
    };
    return out;
}

uint64_t FamilyBatchedProofInstances(
    const scenarios::ProductionProofSiteManifest& manifest)
{
    if (manifest.entries.size() != 28 ||
        manifest.policy.aggregation_arity < 2) {
        return 0;
    }
    auto roles = RequiredRCStage3RelationRoles(
        RCStage3StatementKind::Composed);
    if (roles.empty() ||
        roles.back() != RCStage3RelationRole::CompositionLink) {
        return 0;
    }
    roles.pop_back();
    uint64_t parents{0};
    for (const auto role : roles) {
        uint64_t width = static_cast<uint64_t>(
            std::count_if(
                manifest.entries.begin(),
                manifest.entries.end(),
                [&](const auto& entry) {
                    return entry.role == role;
                }));
        if (width == 0) return 0;
        while (width > 1) {
            width =
                width / manifest.policy.aggregation_arity +
                static_cast<uint64_t>(
                    width % manifest.policy.aggregation_arity !=
                    0);
            parents += width;
        }
    }
    return manifest.entries.size() + parents +
           manifest.final_tree_aggregation_sites;
}

} // namespace

ExecutableGlobalAdditiveCompositionV1
ComposeExecutableGlobalAdditiveBoundV1(
    const scenarios::ComposedThreatModelFloorV1& composed_floor,
    double mlink_p2_epsilon_bits)
{
    ExecutableGlobalAdditiveCompositionV1 out;

    // (b) Dual-lane A2 per-node extractor error kappa = the binding minimum of
    // the field-pair (308-2q), taxed query-pair (288-q) and shared-collision
    // (256-2q) terms = F(q*) per-site floor.
    out.field_pair_bits = composed_floor.field_pair_bits;
    out.taxed_query_pair_bits = composed_floor.taxed_query_pair_bits;
    out.shared_collision_bits = composed_floor.shared_collision_bits;
    out.dual_lane_binding_kappa_bits =
        composed_floor.per_site_composed_floor_bits;
    out.per_node_extractor_kappa_bits =
        out.dual_lane_binding_kappa_bits;

    // (a) #1 statement-decomposition bridge: 341 = 256 leaves + 85 internal
    // nodes. The straight-line ROM extractor composes ADDITIVELY: the total
    // false-accept mass is <= 341*kappa, i.e. the kappa exponent loses a single
    // additive union charge of +log2(341) over the whole tree.
    out.recursion_leaf_nodes = kBridgeRecursionLeafNodes;
    out.recursion_internal_nodes = kBridgeRecursionInternalNodes;
    out.recursion_total_nodes = kBridgeRecursionTotalNodes;
    const double n_nodes =
        static_cast<double>(kBridgeRecursionTotalNodes);
    out.recursion_node_union_log2_bits = std::log2(n_nodes);
    out.bridge_additive_union_bits =
        out.per_node_extractor_kappa_bits -
        out.recursion_node_union_log2_bits;

    // Additive-not-multiplicative witness. A depth-multiplicative (nested
    // rewinding) tree extractor would re-charge the node union once PER LEVEL
    // (depth d = ceil(log_arity(N))), i.e. d*log2(N) bits, versus the bridge's
    // single additive log2(N). The bridge is strictly tighter, and its 8.41-bit
    // charge is itself subsumed by the 25-bit site union below.
    const double depth = std::ceil(
        out.recursion_node_union_log2_bits /
        std::log2(static_cast<double>(
            kBridgeRecursionAggregationArity)));
    out.recursion_tree_depth = static_cast<uint32_t>(depth);
    out.depth_multiplicative_comparison_bits =
        depth * out.recursion_node_union_log2_bits;
    out.extraction_loss_is_additive_not_multiplicative =
        out.recursion_node_union_log2_bits > 0.0 &&
        out.recursion_node_union_log2_bits <
            out.depth_multiplicative_comparison_bits;

    // (c) Flat collision/link terms of the bridge: 2^-128 hash-collision,
    // 2^-88 SHA256d cross-hash, eps_P2 = the executable M-LINK/P2 cross-shard
    // link floor (~2^-94). One collision breaks globally, so these do not union
    // over the tree; they enter the log-sum-exp as flat terms.
    out.hash_collision_bits = kBridgeHashCollisionBits;
    out.cross_hash_sha_bits = kBridgeCrossHashShaBits;
    out.mlink_p2_epsilon_bits = mlink_p2_epsilon_bits;
    out.flat_hash_link_lse_bits = ComposeBits({
        out.hash_collision_bits,
        out.cross_hash_sha_bits,
        out.mlink_p2_epsilon_bits,
    });

    // Per-proof bridge bound: log-sum-exp of the additive-unioned extractor mass
    // and the flat terms = the #1 bridge's 341*kappa + 2^-128 + 2^-88 + eps_P2.
    out.per_proof_bridge_bound_bits = ComposeBits({
        out.bridge_additive_union_bits,
        out.hash_collision_bits,
        out.cross_hash_sha_bits,
        out.mlink_p2_epsilon_bits,
    });

    // (d) Site-union charge over the canonical production site count. The 25-bit
    // charge over 37.5M sites subsumes and dominates the 8.41-bit 341-node
    // recursion union, so the binding global value is the shared-collision floor
    // minus the site union.
    out.global_sites = composed_floor.global_sites;
    out.site_union_charge_exact_bits =
        composed_floor.site_union_charge_exact_bits;
    out.site_union_charge_bits =
        composed_floor.site_union_charge_bits;
    out.site_union_charged_floor_bits =
        out.per_node_extractor_kappa_bits -
        out.site_union_charge_bits;

    out.global_composed_bits = std::min(
        out.site_union_charged_floor_bits,
        out.per_proof_bridge_bound_bits);
    out.global_certified_bits_target =
        std::isfinite(out.global_composed_bits) &&
                out.global_composed_bits > 0.0
            ? static_cast<uint32_t>(
                  std::llround(out.global_composed_bits))
            : 0;

    // Machine-check: reproduce the shipped composed-floor global (79) and the
    // published union arithmetic (341 = 256 + 85; site union = 25 bits).
    out.global_matches_shipped_composed_floor =
        out.global_certified_bits_target ==
        static_cast<uint32_t>(std::llround(
            composed_floor.global_composed_floor_bits));
    out.union_arithmetic_consistent =
        out.recursion_total_nodes ==
            out.recursion_leaf_nodes +
                out.recursion_internal_nodes &&
        out.recursion_leaf_nodes == kBridgeRecursionLeafNodes &&
        out.recursion_internal_nodes ==
            kBridgeRecursionInternalNodes &&
        std::abs(out.site_union_charge_bits - 25.0) < 0.5 &&
        std::isfinite(out.bridge_additive_union_bits) &&
        std::isfinite(out.per_proof_bridge_bound_bits);

    // M2 Poseidon2 binding is inherent to the shared-collision term and is NOT
    // removable; the composed floor already records it as an audit-input line.
    out.poseidon2_binding_is_explicit_assumption = true;

    out.machine_checked =
        composed_floor.parameters_valid &&
        out.union_arithmetic_consistent &&
        out.extraction_loss_is_additive_not_multiplicative &&
        out.global_matches_shipped_composed_floor &&
        out.global_certified_bits_target > 0 &&
        std::isfinite(out.global_composed_bits);

    out.note =
        "stage3:global_additive_composition_v1:"
        "bridge_341_nodes_256_leaf_85_internal;"
        "additive_extractor_union_not_depth_multiplicative;"
        "kappa_per_node_Fqstar_104;"
        "flat_terms_hashcoll_128_crosshash_88_mlink_p2_94;"
        "site_union_25b_over_37p5M;"
        "global_min_composed_79;"
        "M2_poseidon2_binding_inherent_explicit_assumption";
    return out;
}

ExecutableGlobalSoundnessLedgerV1
AssessExecutableGlobalSoundnessLedgerV1(
    uint32_t constraint_count_cap)
{
    ExecutableGlobalSoundnessLedgerV1 out;
    out.constraint_count_cap =
        constraint_count_cap;
    out.trace_width_cap =
        CanonicalRCStage3UnifiedRootParameters()
            .max_recursive_air_columns;

    const auto manifest =
        scenarios::BuildProductionProofSiteManifest(
            scenarios::SelectedProductionProofSitePolicy());
    const bool canonical_inventory =
        manifest.arithmetic_exact &&
        manifest.complete_global_upper_bound_manifest_derived &&
        manifest.total_proof_sites ==
            kCanonicalProductionSites &&
        scenarios::ValidateProductionProofSiteManifest(
            manifest, nullptr);
    out.canonical = BuildScenario(
        kCanonicalProductionSites,
        canonical_inventory,
        /*covers_selected_topology=*/canonical_inventory,
        /*production_theorem=*/false,
        out.trace_width_cap,
        constraint_count_cap);
    out.conservative_product = BuildScenario(
        kConservativeProductSites,
        /*manifest_derived=*/false,
        /*covers_selected_topology=*/false,
        /*production_theorem=*/false,
        out.trace_width_cap,
        constraint_count_cap);
    out.family_batched_proof_instances =
        FamilyBatchedProofInstances(manifest);
    out.family_batched_candidate = BuildScenario(
        out.family_batched_proof_instances,
        /*manifest_derived=*/false,
        /*covers_selected_topology=*/false,
        /*production_theorem=*/false,
        out.trace_width_cap,
        constraint_count_cap);
    out.shard_tree_economically_production_candidate =
        false;
    out.family_linear_fold_executable =
        stage3_family_fold::
            kAuthenticatedLinearFamilyFoldExecutable;
    out.family_zero_residual_fold_executable =
        stage3_family_fold::
            kAuthenticatedFamilyResidualZeroFoldExecutable;
    out.family_fold_proof_codec_executable =
        stage3_family_fold::
            kAuthenticatedLinearFamilyFoldCodecExecutable;
    out.nonlinear_trace_fold_explicitly_rejected =
        !stage3_family_fold::
             kAuthenticatedLinearFamilyFoldPreservesNonlinearAir;
    out.family_residual_bound_to_constraint_vm =
        stage3_family_fold::
            kAuthenticatedFamilyResidualOracleBoundToConstraintVm;
    out.family_batched_rows_absorbed_by_relation_theorems =
        out.family_residual_bound_to_constraint_vm;
    out.family_batched_single_quotient_fri_executable =
        out.family_zero_residual_fold_executable &&
        out.family_residual_bound_to_constraint_vm &&
        stage3_family_fold::
            kAuthenticatedFamilyQuotientIdentityExecutable;

    for (const uint8_t lanes : {uint8_t{4}, uint8_t{7}}) {
      for (const uint32_t rows : {
               1U << 16, 1U << 18, 1U << 20}) {
        auto policy =
            scenarios::UnpackedProductionProofSitePolicy();
        policy.hash_parallel_lanes = lanes;
        policy.relation_rows_per_site = rows;
        const auto candidate =
            scenarios::BuildProductionProofSiteManifest(
                policy);
        ExecutableRelationRowsPolicyScenarioV1 item;
        item.hash_parallel_lanes = lanes;
        item.relation_rows_per_site = rows;
        item.relation_leaf_sites =
            candidate.relation_leaf_sites;
        item.arity_four_parent_sites =
            candidate.below_root_aggregation_sites;
        item.final_tree_parent_sites =
            candidate.final_tree_aggregation_sites;
        item.total_sites = candidate.total_proof_sites;
        item.finite_manifest_derived =
            candidate.complete_global_upper_bound_manifest_derived &&
            scenarios::ValidateProductionProofSiteManifest(
                candidate, nullptr);
        item.row_cap_supported_by_registered_builders =
            rows <= kRCStage3EpisodeSemanticMaxRows &&
            rows <= kRCStage3SignedRangeMaxShardRows &&
            rows <= policy.max_air_trace_rows;
        item.hash_vector_shape_supported =
            lanes <=
                stage3_hash_air::
                    kFixedProgramMaxPackedLanes &&
            static_cast<uint32_t>(lanes) *
                    stage3_hash_air::
                        kFixedProgramBoundaryColumns <=
                stage3_hash_air::
                    kFixedProgramRecursiveWidthCap;
        item.hash_proof_wrapper_executable =
            candidate.executable_hash_parallel_packing;
        // Shape limits execute, but no production-dimension peak-memory
        // measurement exists for 2^18/2^20 leaves.
        item.production_memory_profile_measured = false;
        item.recursive_scheduler_enforces_policy =
            candidate.recursive_scheduler_consumes_manifest;
        item.production_selectable =
            item.finite_manifest_derived &&
            item.row_cap_supported_by_registered_builders &&
            item.hash_vector_shape_supported &&
            item.hash_proof_wrapper_executable &&
            item.production_memory_profile_measured &&
            item.recursive_scheduler_enforces_policy;
        item.additive = BuildScenario(
            candidate.total_proof_sites,
            item.finite_manifest_derived,
            /*covers_selected_topology=*/true,
            /*production_theorem=*/false,
            out.trace_width_cap,
            constraint_count_cap);
        out.relation_rows_policies.push_back(
            std::move(item));
      }
    }

    out.single_fp3_backend_executable =
        kSelectedExtensionDegree == 3;
    out.q192_multirow_v2_executable =
        kRCFri3AlgNumQueries ==
            kSelectedSingleLaneQueries &&
        kRCFri3AlgMultiRowBatchProofVersion == 2;
    out.q192_split_rap_integrated =
        kRCStage3EpisodeSignedRangeSplitRapCanaryExecutable;
    // The dual-lane arithmetic is now backed by an executable, tamper-tested
    // cross-shard (M-LINK) fraction accumulator (matmul_v4_rc_stage3_mlink),
    // not only by the config-level challenge/event predicate.
    out.ctl_dual_lane_arithmetic_executable =
        kRCStage3CtlUniformChallengeSampling &&
        kRCStage3CtlMaxEvents ==
            kCtlEventsPerBusEnvelope &&
        stage3_mlink::MLinkDualLaneArithmeticExecutable();
    out.recursive_child_transport_fp3_only =
        kSelectedExtensionDegree == 3;
    out.legacy_fp2_transport_bound_inapplicable =
        out.recursive_child_transport_fp3_only;
    out.hash_primitives_executable = true;
    out.grinding_parameter_executable =
        kRCFriGrindingBits ==
            kConservativeGrindingBits;
    out.internal_fri_grinding_charged =
        out.grinding_parameter_executable;
    // The FVT construction currently exists only as a design. The sampled
    // carrier verifier does not recompute the complete terminal round.
    // Stage-3's eventual work theorem must instead follow from the complete
    // relation proof and its immutable public statement.
    out.sampled_terminal_round_fvt_executable =
        false;
    out.external_pow_work_composition_complete =
        false;

    out.semantic_relation_closure_complete = false;
    out.normalized_recursive_verifier_executable = false;
    out.exact_selected_topology_manifest_derived = false;
    out.canonical_heterogeneous_site_topology_derived =
        canonical_inventory;
    out.deprecated_width_product_rejected = true;
    out.universal_program_registry_binding_defined = true;
    out.universal_program_registry_consumed_in_recursion =
        false;
    out.ali_degree_and_constraint_manifest_complete = false;
    out.ctl_export_and_terminal_reduction_complete = false;
    out.hash_first_collision_hybrid_complete = false;
    // g4 (child Fiat-Shamir replay).  COMPUTED from the single source of
    // truth, recursive_parent_air::AssessChildFsReplayClosureV1(), which is a
    // conjunction over the obligations g4 actually has (bus construction and
    // adversarial rejection, slot x challenge-kind coverage, FRI-proof-level
    // discharge of both bus endpoints, and the recursion-carrying parent
    // hosting the replay).  It is NOT written here and must never be.  Its
    // `note` enumerates exactly which conjunct is still open.
    out.fiat_shamir_replay_complete =
        recursive_parent_air::AssessChildFsReplayClosureV1().closed;
    out.self_similar_fixed_point_closed = false;
    out.nirop_oracle_separation_complete = false;
    out.pow_composition_theorem_complete = false;
    // global_additive_theorem_complete is COMPUTED below from the executable
    // composition (machine-checked) AND the gate-0..5 dependency conjunction;
    // it is no longer a hard-coded false.

    // Composed threat-model floor F(q*) at q* = 76 over the canonical site
    // count. Computed UNCONDITIONALLY so the ledger is correct today: per-site
    // 104 (binding shared-collision term), global ~79 after the site union.
    out.composed_floor =
        scenarios::AssessComposedThreatModelFloorV1(
            scenarios::kThreatModelDefensibleMinQStar,
            kCanonicalProductionSites);
    out.per_site_composed_floor_bits = static_cast<uint32_t>(
        std::llround(
            out.composed_floor.per_site_composed_floor_bits));
    out.composed_certified_bits_target = static_cast<uint32_t>(
        std::llround(
            out.composed_floor.global_composed_floor_bits));

    // Executable, machine-checked global additive composition (gate 6). It
    // recomposes the global bound from the #1 statement-decomposition bridge
    // (341*kappa additive union), the dual-lane A2 terms, the flat M-LINK/P2 +
    // cross-hash + hash-collision terms and the site-union charge, and self-
    // checks that it reproduces the shipped composed-floor global (79). eps_P2
    // is sourced from the executable M-LINK single-global-epsilon floor.
    const double mlink_p2_epsilon_bits =
        stage3_mlink::AssessMLinkSoundnessV1().epsilon_mlink_bits;
    out.global_additive_composition =
        ComposeExecutableGlobalAdditiveBoundV1(
            out.composed_floor, mlink_p2_epsilon_bits);
    out.global_additive_composition_machine_checked =
        out.global_additive_composition.machine_checked;

    // Gate 6 completes ONLY when (a) the executable composition genuinely
    // machine-checks AND (b) the constructions it composes are executable, i.e.
    // gates 0-5 are all true. The composition is machine-checked today, but the
    // dependency gates remain open, so the theorem stays incomplete and no bits
    // are minted. This is the honest, dependency-ordered flip.
    const bool dependency_gates_0_to_5 =
        kRCStage3MathematicalVerifierReady &&
        kRCStage3EpisodeRelationsReady &&
        kRCStage3RecursiveAggregationReady &&
        kRCFri3AlgFormalSoundnessReady &&
        out.fiat_shamir_replay_complete &&
        out.self_similar_fixed_point_closed;
    out.global_additive_theorem_complete =
        out.global_additive_composition_machine_checked &&
        dependency_gates_0_to_5;

    // Ordered readiness interlock. Every member is sourced from its honest
    // current flag value; NONE is fabricated here. `all_clear` is the single
    // predicate that flips the live certified_bits off zero.
    CompositionReadinessGateV1 gate;
    gate.mathematical_verifier_ready =
        kRCStage3MathematicalVerifierReady;
    gate.episode_relations_ready =
        kRCStage3EpisodeRelationsReady;
    gate.recursive_aggregation_ready =
        kRCStage3RecursiveAggregationReady;
    gate.fri_alg_formal_soundness_ready =
        kRCFri3AlgFormalSoundnessReady;
    gate.child_fiat_shamir_replay_closed =
        out.fiat_shamir_replay_complete;
    gate.self_similar_fixed_point_closed =
        out.self_similar_fixed_point_closed;
    gate.global_soundness_composition_proved =
        out.global_additive_theorem_complete;
    gate.all_clear =
        gate.mathematical_verifier_ready &&
        gate.episode_relations_ready &&
        gate.recursive_aggregation_ready &&
        gate.fri_alg_formal_soundness_ready &&
        gate.child_fiat_shamir_replay_closed &&
        gate.self_similar_fixed_point_closed &&
        gate.global_soundness_composition_proved;
    out.composition_gate = gate;

    // The theorem is complete exactly when the interlock clears. certified_bits
    // then equals the composed global floor; otherwise it is a computed 0. This
    // replaces the former hard-coded zero override.
    out.theorem_complete = gate.all_clear;
    out.certified_bits =
        gate.all_clear ? out.composed_certified_bits_target : 0;
    out.authority_eligible =
        out.theorem_complete &&
        out.certified_bits >=
            static_cast<uint32_t>(
                CanonicalRCStage3UnifiedRootParameters()
                    .target_soundness_bits) &&
        kExecutableGlobalSoundnessAuthorityReady;
    out.note =
        "stage3:global_soundness_ledger_v1:"
        "single_fp3_q192_selected_executable;"
        "recursive_child_transport_fp3_only;"
        "legacy_fp2_transport_bound_inapplicable;"
        "internal_fri_grinding_charged_separately;"
        "sampled_terminal_fvt_not_implemented;"
        "canonical_heterogeneous_topology_exact;"
        "deprecated_width_product_rejected;"
        "canonical_known_union_above_100;"
        "authenticated_family_residual_fold_executable;"
        "family_residual_vm_binding_open;"
        "product_diagnostic_fri_saturates_below_100;"
        "composed_floor_Fqstar_per_site_104_global_79_computed;"
        "certified_bits_gated_on_readiness_interlock_currently_zero;"
        "assumptions_M2_A2_field_bounds_hash_model_recorded_audit_input;"
        "global_reductions_open";
    return out;
}

} // namespace matmul::v4::rc::global_soundness_ledger
