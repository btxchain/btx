// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_global_soundness_ledger.h>

#include <algorithm>
#include <cmath>

namespace ledger =
    matmul::v4::rc::global_soundness_ledger;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_global_soundness_ledger_tests)

BOOST_AUTO_TEST_CASE(
    executable_q192_ledger_is_additive_topology_aware_and_fail_closed)
{
    const auto audit =
        ledger::AssessExecutableGlobalSoundnessLedgerV1();
    BOOST_CHECK_EQUAL(audit.version, 1U);
    BOOST_CHECK_EQUAL(audit.selected_queries, 192U);
    BOOST_CHECK_EQUAL(audit.extension_degree, 3U);
    BOOST_CHECK_EQUAL(audit.lde_log2, 24U);
    BOOST_CHECK_EQUAL(audit.grinding_bits, 40U);
    BOOST_CHECK_EQUAL(audit.trace_width_cap, 16'384U);
    BOOST_CHECK_EQUAL(
        audit.constraint_count_cap, 16'384U);

    BOOST_CHECK(audit.single_fp3_backend_executable);
    BOOST_CHECK(audit.q192_multirow_v2_executable);
    BOOST_CHECK(audit.q192_split_rap_integrated);
    BOOST_CHECK(
        audit.ctl_dual_lane_arithmetic_executable);
    BOOST_CHECK(
        audit.recursive_child_transport_fp3_only);
    BOOST_CHECK(
        audit.legacy_fp2_transport_bound_inapplicable);
    BOOST_CHECK(audit.hash_primitives_executable);
    BOOST_CHECK(audit.grinding_parameter_executable);
    BOOST_CHECK(audit.internal_fri_grinding_charged);
    BOOST_CHECK(
        !audit.sampled_terminal_round_fvt_executable);
    BOOST_CHECK(
        !audit.external_pow_work_composition_complete);

    const auto& canonical = audit.canonical;
    BOOST_CHECK_EQUAL(
        canonical.sites, 37'488'397ULL);
    BOOST_CHECK_CLOSE(
        canonical.site_log2,
        25.1599408017, 1e-7);
    BOOST_CHECK(
        canonical.site_count_manifest_derived);
    BOOST_CHECK(
        canonical.
            covers_selected_relation_local_topology);
    BOOST_CHECK(!canonical.production_theorem);
    BOOST_CHECK_CLOSE(
        canonical.q192_fri_bcs_bits,
        101.7735372173, 1e-7);
    BOOST_CHECK_CLOSE(
        canonical.maximum_single_lane_fri_bcs_bits,
        101.7735372173, 1e-7);
    BOOST_CHECK_EQUAL(
        canonical.fri_saturation_queries, 140U);
    BOOST_CHECK_EQUAL(
        canonical.minimum_numeric_q_for_fri_100,
        138U);
    BOOST_CHECK(
        canonical.
            fri_100_reachable_by_any_single_lane_q);
    BOOST_CHECK_EQUAL(
        canonical.
            minimum_currently_executable_q_for_fri_100,
        192U);
    BOOST_CHECK_CLOSE(
        canonical.trace_batching_bits,
        109.8398830988, 1e-7);
    BOOST_CHECK_CLOSE(
        canonical.constraint_batching_bits,
        109.8400591983, 1e-7);
    BOOST_CHECK_CLOSE(
        canonical.ctl_rational_identity_bits,
        255.1396196522, 1e-7);
    BOOST_CHECK_CLOSE(
        canonical.hash_binding_bits,
        102.8400591983, 1e-7);
    BOOST_CHECK_CLOSE(
        canonical.fs_sampler_liveness_bits,
        111.4957632904, 1e-7);
    BOOST_CHECK_CLOSE(
        canonical.known_false_accept_union_bits,
        101.2031426943, 1e-7);
    BOOST_CHECK(
        canonical.known_union_numeric_target_met);
    BOOST_REQUIRE_EQUAL(canonical.terms.size(), 8U);

    const auto& product =
        audit.conservative_product;
    BOOST_CHECK_EQUAL(
        product.sites, 12'221'217'422ULL);
    BOOST_CHECK_CLOSE(
        product.site_log2,
        33.5086689559, 1e-7);
    BOOST_CHECK(!product.site_count_manifest_derived);
    BOOST_CHECK(
        !product.
            covers_selected_relation_local_topology);
    BOOST_CHECK(!product.production_theorem);
    BOOST_CHECK_CLOSE(
        product.q192_fri_bcs_bits,
        93.4248090893, 1e-7);
    BOOST_CHECK_CLOSE(
        product.maximum_single_lane_fri_bcs_bits,
        93.4248090893, 1e-7);
    BOOST_CHECK_EQUAL(
        product.fri_saturation_queries, 140U);
    BOOST_CHECK_EQUAL(
        product.minimum_numeric_q_for_fri_100,
        0U);
    BOOST_CHECK(
        !product.
             fri_100_reachable_by_any_single_lane_q);
    BOOST_CHECK_EQUAL(
        product.
            minimum_currently_executable_q_for_fri_100,
        0U);
    BOOST_CHECK_CLOSE(
        product.trace_batching_bits,
        101.4911549446, 1e-7);
    BOOST_CHECK_CLOSE(
        product.constraint_batching_bits,
        101.4913310441, 1e-7);
    BOOST_CHECK_CLOSE(
        product.ctl_rational_identity_bits,
        246.7908914979, 1e-7);
    BOOST_CHECK_CLOSE(
        product.hash_binding_bits,
        94.4913310441, 1e-7);
    BOOST_CHECK_CLOSE(
        product.fs_sampler_liveness_bits,
        103.1470351362, 1e-7);
    BOOST_CHECK_CLOSE(
        product.known_false_accept_union_bits,
        92.8544145578, 1e-7);
    BOOST_CHECK(
        !product.known_union_numeric_target_met);

    BOOST_CHECK_EQUAL(
        audit.family_batched_proof_instances, 51ULL);
    const auto& family =
        audit.family_batched_candidate;
    BOOST_CHECK_EQUAL(family.sites, 51ULL);
    BOOST_CHECK(!family.site_count_manifest_derived);
    BOOST_CHECK(
        !family.covers_selected_relation_local_topology);
    BOOST_CHECK(!family.production_theorem);
    BOOST_CHECK_GT(family.q192_fri_bcs_bits, 120.0);
    BOOST_CHECK(
        family.known_union_numeric_target_met);
    BOOST_CHECK(
        !audit.shard_tree_economically_production_candidate);
    BOOST_CHECK(audit.family_linear_fold_executable);
    BOOST_CHECK(audit.family_zero_residual_fold_executable);
    BOOST_CHECK(audit.family_fold_proof_codec_executable);
    BOOST_CHECK(
        audit.nonlinear_trace_fold_explicitly_rejected);
    BOOST_CHECK(
        !audit.family_residual_bound_to_constraint_vm);
    BOOST_CHECK(
        !audit.family_batched_rows_absorbed_by_relation_theorems);
    BOOST_CHECK(
        !audit.family_batched_single_quotient_fri_executable);

    BOOST_REQUIRE_EQUAL(
        audit.relation_rows_policies.size(), 6U);
    const auto policy =
        [&](uint8_t lanes, uint32_t rows)
            -> const ledger::
                ExecutableRelationRowsPolicyScenarioV1& {
            const auto it = std::find_if(
                audit.relation_rows_policies.begin(),
                audit.relation_rows_policies.end(),
                [&](const auto& item) {
                    return
                        item.hash_parallel_lanes == lanes &&
                        item.relation_rows_per_site == rows;
                });
            BOOST_REQUIRE(
                it != audit.relation_rows_policies.end());
            return *it;
        };
    struct ExpectedPolicy {
        uint8_t lanes;
        uint32_t rows;
        uint64_t sites;
        double fri_bits;
        double additive_bits;
    };
    for (const ExpectedPolicy expected : {
             ExpectedPolicy{
                 4, 1U << 16, 66'480'699ULL,
                 100.9470458151, 100.3766512883},
             ExpectedPolicy{
                 4, 1U << 18, 37'488'397ULL,
                 101.7735372288, 101.2031427020},
             ExpectedPolicy{
                 4, 1U << 20, 30'240'318ULL,
                 102.0835080556, 101.5131135288},
             ExpectedPolicy{
                 7, 1U << 16, 55'124'366ULL,
                 101.2172912083, 100.6468966815},
             ExpectedPolicy{
                 7, 1U << 18, 26'132'068ULL,
                 102.2941600672, 101.7237655405},
             ExpectedPolicy{
                 7, 1U << 20, 18'883'992ULL,
                 102.7628175894, 102.1924230626},
         }) {
        const auto& item =
            policy(expected.lanes, expected.rows);
        BOOST_CHECK_EQUAL(item.total_sites, expected.sites);
        BOOST_CHECK(item.finite_manifest_derived);
        BOOST_CHECK(
            item.row_cap_supported_by_registered_builders);
        BOOST_CHECK(item.hash_vector_shape_supported);
        BOOST_CHECK_EQUAL(
            item.hash_proof_wrapper_executable,
            expected.lanes == 4);
        BOOST_CHECK(
            !item.production_memory_profile_measured);
        BOOST_CHECK(
            !item.recursive_scheduler_enforces_policy);
        BOOST_CHECK(!item.production_selectable);
        BOOST_CHECK_CLOSE(
            item.additive.q192_fri_bcs_bits,
            expected.fri_bits, 1e-7);
        BOOST_CHECK_CLOSE(
            item.additive.known_false_accept_union_bits,
            expected.additive_bits, 1e-7);
    }

    for (const auto& term : canonical.terms) {
        BOOST_CHECK(!term.reduction_complete);
    }
    for (const auto& term : product.terms) {
        BOOST_CHECK(!term.reduction_complete);
    }
    BOOST_CHECK(
        !audit.semantic_relation_closure_complete);
    BOOST_CHECK(
        !audit.normalized_recursive_verifier_executable);
    BOOST_CHECK(
        audit.canonical_heterogeneous_site_topology_derived);
    BOOST_CHECK(audit.deprecated_width_product_rejected);
    BOOST_CHECK(
        audit.universal_program_registry_binding_defined);
    BOOST_CHECK(
        !audit.
            universal_program_registry_consumed_in_recursion);
    BOOST_CHECK(
        !audit.exact_selected_topology_manifest_derived);
    BOOST_CHECK(
        !audit.
            ali_degree_and_constraint_manifest_complete);
    BOOST_CHECK(
        !audit.
            ctl_export_and_terminal_reduction_complete);
    BOOST_CHECK(
        !audit.hash_first_collision_hybrid_complete);
    BOOST_CHECK(!audit.fiat_shamir_replay_complete);
    BOOST_CHECK(
        !audit.nirop_oracle_separation_complete);
    BOOST_CHECK(
        !audit.pow_composition_theorem_complete);
    BOOST_CHECK(
        !audit.global_additive_theorem_complete);
    BOOST_CHECK(!audit.theorem_complete);
    BOOST_CHECK_EQUAL(audit.certified_bits, 0U);
    BOOST_CHECK(!audit.authority_eligible);
}

BOOST_AUTO_TEST_CASE(
    composed_floor_matches_threat_model_doc_and_is_gated_to_zero)
{
    namespace scen = matmul::v4::rc::soundness_scenarios;
    const auto audit =
        ledger::AssessExecutableGlobalSoundnessLedgerV1();
    const auto& floor = audit.composed_floor;

    // q* = 76 from the threat-model doc.
    BOOST_CHECK_EQUAL(floor.qstar, 76U);
    BOOST_CHECK_EQUAL(floor.stress_ceiling_q, 78U);

    // F(q*) = min(308-2q, 288-q, 256-2q) = min(156, 212, 104).
    BOOST_CHECK_CLOSE(floor.field_pair_bits, 156.0, 1e-9);
    BOOST_CHECK_CLOSE(floor.taxed_query_pair_bits, 212.0, 1e-9);
    BOOST_CHECK_CLOSE(floor.shared_collision_bits, 104.0, 1e-9);
    BOOST_CHECK(
        floor.binding_term ==
        scen::ComposedFloorBindingTerm::SharedCollision);

    // Per-site 104; global 79 after the round(log2(37.5M)) = 25 site union.
    BOOST_CHECK_CLOSE(
        floor.per_site_composed_floor_bits, 104.0, 1e-9);
    BOOST_CHECK_EQUAL(floor.global_sites, 37'488'397ULL);
    BOOST_CHECK_CLOSE(
        floor.site_union_charge_exact_bits, 25.1599408017, 1e-7);
    BOOST_CHECK_CLOSE(floor.site_union_charge_bits, 25.0, 1e-9);
    BOOST_CHECK_CLOSE(
        floor.global_composed_floor_bits, 79.0, 1e-9);

    // Transport dual-alpha screen (183.57) is non-binding above the floor.
    BOOST_CHECK_CLOSE(
        floor.transport_dual_alpha_screen_bits, 183.57, 1e-9);
    BOOST_CHECK(floor.transport_screen_non_binding);

    BOOST_CHECK(floor.per_site_meets_100);
    BOOST_CHECK(floor.per_site_meets_64);
    BOOST_CHECK(!floor.global_meets_100);
    BOOST_CHECK(floor.global_meets_64);
    BOOST_CHECK(floor.parameters_valid);

    // Exactly four explicit AUDIT-INPUT assumption lines, none flag-flipped.
    BOOST_REQUIRE_EQUAL(floor.assumptions.size(), 4U);
    for (const auto& line : floor.assumptions) {
        BOOST_CHECK(line.audit_input);
    }
    BOOST_CHECK(
        floor.assumptions[0].status ==
        scen::ComposedFloorAssumptionStatus::AssumedAuditInput);
    BOOST_CHECK_EQUAL(
        floor.assumptions[0].tag, "M2:poseidon2_binding");
    BOOST_CHECK(
        floor.assumptions[1].status ==
        scen::ComposedFloorAssumptionStatus::ProvenAuditInput);
    BOOST_CHECK_EQUAL(
        floor.assumptions[1].tag, "A2:lane_independence");
    BOOST_CHECK_EQUAL(
        floor.assumptions[2].tag, "field_bounds:m_f_154");
    BOOST_CHECK_EQUAL(
        floor.assumptions[3].tag,
        "hash_model:split_256bit_digest");

    // The composed integer targets the ledger would certify on gate-clear.
    BOOST_CHECK_EQUAL(
        audit.per_site_composed_floor_bits, 104U);
    BOOST_CHECK_EQUAL(
        audit.composed_certified_bits_target, 79U);

    // Ordered readiness interlock: gate 3 (fri_alg rbr/BCS) is closed; the
    // remaining gates are at their honest current (false) value, so the
    // interlock is NOT clear and certified_bits stays a computed 0.
    const auto& gate = audit.composition_gate;
    BOOST_CHECK(!gate.mathematical_verifier_ready);
    BOOST_CHECK(!gate.episode_relations_ready);
    BOOST_CHECK(!gate.recursive_aggregation_ready);
    // Gate 3 is closed (single-lane rbr/BCS reduction machine-checked); the
    // interlock still requires the remaining gates before certifying.
    BOOST_CHECK(gate.fri_alg_formal_soundness_ready);
    BOOST_CHECK(!gate.child_fiat_shamir_replay_closed);
    BOOST_CHECK(!gate.self_similar_fixed_point_closed);
    BOOST_CHECK(!gate.global_soundness_composition_proved);
    BOOST_CHECK(!gate.all_clear);

    // Live value stays 0 today because the interlock is open; but it is a
    // COMPUTED, gated zero, not a hard override: the target is non-zero.
    BOOST_CHECK(!audit.theorem_complete);
    BOOST_CHECK_EQUAL(audit.certified_bits, 0U);
    BOOST_CHECK(!audit.authority_eligible);
    BOOST_CHECK_GT(audit.composed_certified_bits_target, 0U);
}

BOOST_AUTO_TEST_CASE(
    global_additive_composition_machine_computes_79_additively)
{
    namespace scen = matmul::v4::rc::soundness_scenarios;

    // The composition function is a pure function of the composed floor and the
    // executable M-LINK/P2 epsilon; call it directly with the same inputs the
    // ledger uses so the test is self-contained and machine-checkable.
    const auto floor = scen::AssessComposedThreatModelFloorV1(
        scen::kThreatModelDefensibleMinQStar,
        ledger::kCanonicalProductionSites);
    const double mlink_eps = 94.13961948019406;  // 189-25.16-log2(52*2^24)-40
    const auto comp =
        ledger::ComposeExecutableGlobalAdditiveBoundV1(floor, mlink_eps);

    // (a) #1 statement-decomposition bridge: 341 = 256 leaves + 85 internal.
    BOOST_CHECK_EQUAL(comp.recursion_leaf_nodes, 256U);
    BOOST_CHECK_EQUAL(comp.recursion_internal_nodes, 85U);
    BOOST_CHECK_EQUAL(comp.recursion_total_nodes, 341U);
    BOOST_CHECK_EQUAL(comp.recursion_tree_depth, 5U);
    BOOST_CHECK_CLOSE(
        comp.recursion_node_union_log2_bits, 8.413627929024173, 1e-9);

    // (b) dual-lane A2: kappa = F(q*) per-site floor = 104 (shared-collision).
    BOOST_CHECK_CLOSE(comp.field_pair_bits, 156.0, 1e-9);
    BOOST_CHECK_CLOSE(comp.taxed_query_pair_bits, 212.0, 1e-9);
    BOOST_CHECK_CLOSE(comp.shared_collision_bits, 104.0, 1e-9);
    BOOST_CHECK_CLOSE(comp.dual_lane_binding_kappa_bits, 104.0, 1e-9);
    BOOST_CHECK_CLOSE(comp.per_node_extractor_kappa_bits, 104.0, 1e-9);

    // ADDITIVE union: 341*kappa -> kappa exponent minus a single +log2(341).
    BOOST_CHECK_CLOSE(
        comp.bridge_additive_union_bits, 95.58637207097583, 1e-9);
    // ...strictly tighter than the rejected depth-multiplicative alternative
    // d*log2(N) = 5 * 8.4136 = 42.07 bits of loss.
    BOOST_CHECK_CLOSE(
        comp.depth_multiplicative_comparison_bits,
        42.068139645120866, 1e-9);
    BOOST_CHECK(comp.extraction_loss_is_additive_not_multiplicative);
    BOOST_CHECK_LT(
        comp.recursion_node_union_log2_bits,
        comp.depth_multiplicative_comparison_bits);

    // (c) flat M-LINK/P2 + cross-hash (2^-88) + hash-collision (2^-128) terms.
    BOOST_CHECK_CLOSE(comp.mlink_p2_epsilon_bits, 94.13961948019406, 1e-9);
    BOOST_CHECK_CLOSE(comp.cross_hash_sha_bits, 88.0, 1e-9);
    BOOST_CHECK_CLOSE(comp.hash_collision_bits, 128.0, 1e-9);
    BOOST_CHECK_CLOSE(
        comp.flat_hash_link_lse_bits, 87.97968096843323, 1e-9);
    // Per-proof bridge bound = 341*kappa + 2^-128 + 2^-88 + eps_P2 (lse).
    BOOST_CHECK_CLOSE(
        comp.per_proof_bridge_bound_bits, 87.97229817606706, 1e-9);

    // (d) site-union charge: round(log2(37.5M)) = 25 bits.
    BOOST_CHECK_EQUAL(comp.global_sites, 37'488'397ULL);
    BOOST_CHECK_CLOSE(
        comp.site_union_charge_exact_bits, 25.159940801664856, 1e-9);
    BOOST_CHECK_CLOSE(comp.site_union_charge_bits, 25.0, 1e-9);
    BOOST_CHECK_CLOSE(comp.site_union_charged_floor_bits, 79.0, 1e-9);

    // Composed global value = min(site-union-charged floor, bridge bound) = 79,
    // reproducing the shipped composed-floor global.
    BOOST_CHECK_CLOSE(comp.global_composed_bits, 79.0, 1e-9);
    BOOST_CHECK_EQUAL(comp.global_certified_bits_target, 79U);
    BOOST_CHECK(comp.global_matches_shipped_composed_floor);
    BOOST_CHECK(comp.union_arithmetic_consistent);
    BOOST_CHECK(comp.poseidon2_binding_is_explicit_assumption);
    BOOST_CHECK(comp.machine_checked);
}

BOOST_AUTO_TEST_CASE(
    global_additive_theorem_gated_on_composition_and_gates_0_to_5)
{
    const auto audit =
        ledger::AssessExecutableGlobalSoundnessLedgerV1();
    const auto& comp = audit.global_additive_composition;

    // The ledger wires the same composition and it machine-checks to 79.
    BOOST_CHECK(comp.machine_checked);
    BOOST_CHECK(audit.global_additive_composition_machine_checked);
    BOOST_CHECK_EQUAL(comp.global_certified_bits_target, 79U);
    BOOST_CHECK_EQUAL(
        comp.global_certified_bits_target,
        audit.composed_certified_bits_target);

    // Gate 6 completes ONLY when the composition machine-checks AND gates 0-5
    // are true. The composition is machine-checked, but gates 0-5 are open, so
    // the theorem stays incomplete and gate 6 stays down. Honest flip.
    BOOST_CHECK(!audit.global_additive_theorem_complete);
    BOOST_CHECK(
        !audit.composition_gate.global_soundness_composition_proved);
    BOOST_CHECK(!audit.composition_gate.all_clear);
    BOOST_CHECK(!audit.theorem_complete);
    BOOST_CHECK_EQUAL(audit.certified_bits, 0U);

    // The theorem-complete predicate is exactly composition AND gates 0-5.
    const bool gates_0_to_5 =
        audit.composition_gate.mathematical_verifier_ready &&
        audit.composition_gate.episode_relations_ready &&
        audit.composition_gate.recursive_aggregation_ready &&
        audit.composition_gate.fri_alg_formal_soundness_ready &&
        audit.composition_gate.child_fiat_shamir_replay_closed &&
        audit.composition_gate.self_similar_fixed_point_closed;
    BOOST_CHECK_EQUAL(
        audit.global_additive_theorem_complete,
        audit.global_additive_composition_machine_checked &&
            gates_0_to_5);
    // Concretely: composition true, gates 0-5 false -> theorem false.
    BOOST_CHECK(!gates_0_to_5);
}

BOOST_AUTO_TEST_SUITE_END()
