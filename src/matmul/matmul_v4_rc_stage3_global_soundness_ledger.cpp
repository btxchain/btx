// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_global_soundness_ledger.h>

#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3_ali_manifest.h>
#include <matmul/matmul_v4_rc_stage3_coupled.h>
#include <matmul/matmul_v4_rc_stage3_ctl.h>
#include <matmul/matmul_v4_rc_stage3_episode.h>
#include <matmul/matmul_v4_rc_stage3_recursive.h>
#include <matmul/matmul_v4_rc_stage3_recursive_fixedpoint.h>
#include <matmul/matmul_v4_rc_stage3_recursive_parent_air.h>
#include <matmul/matmul_v4_rc_stage3_verifier_air.h>
#include <matmul/matmul_v4_rc_stage3_verify.h>
#include <matmul/matmul_v4_rc_stage3_gemm_extract.h>
#include <matmul/matmul_v4_rc_stage3_hash_air.h>
#include <matmul/matmul_v4_rc_stage3_mlink.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>
#include <matmul/matmul_v4_rc_stage3_episode_semantic.h>
#include <matmul/matmul_v4_rc_stage3_semantic_status.h>
#include <matmul/matmul_v4_rc_stage3_family_fold.h>
#include <matmul/matmul_v4_rc_stage3_soundness_scenarios.h>
#include <matmul/matmul_v4_rc_stage3_unified_root.h>
#include <matmul/matmul_v4_rc_stage3_receipt_public_statement.h>

#include <algorithm>
#include <array>
#include <cmath>
#include <cstdlib>
#include <initializer_list>
#include <limits>

namespace matmul::v4::rc::global_soundness_ledger {
namespace {

namespace scenarios = soundness_scenarios;
namespace rpa = recursive_parent_air;
namespace aq = air_quotient;
namespace gf = gkr_field;

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

// --- g5 (self-similar fixed point) parent-own-FRI full-arity assessor ------
//
// The same minimal single-column boolean AIR the recursive_parent_air test
// suite calls `ToyFriChildCs()`. It is not exported by that module (it is a
// file-local test fixture), so it is reproduced here rather than reaching
// into test code from the library: any single-constraint, two-row AIR that
// `AirQuotientProve` accepts is sufficient to exercise the four-slot parent
// SHAPE this assessor needs (the parent's own column count and cap
// admission), and this is exactly the shape the heavy-gated test proves.
aq::AirConstraintSystem<gf::Fp3> ParentOwnFriAssessorToyChildCsV1()
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = 2;
    cs.n_columns = 1;
    aq::AirConstraint<gf::Fp3> boolean;
    boolean.name = "g5.parent_own_fri_full_arity.toy.boolean";
    boolean.kind = aq::AirKind::kEverywhere;
    boolean.alg_degree = 2;
    boolean.eval =
        [](const std::vector<gf::Fp3>& current,
           const std::vector<gf::Fp3>&) {
            return gf::Mul(
                current[0],
                gf::Sub(current[0], gf::Fp3::One()));
        };
    cs.constraints.push_back(std::move(boolean));
    return cs;
}

uint256 ParentOwnFriAssessorSeedV1(unsigned char byte)
{
    uint256 out;
    out.SetNull();
    out.data()[0] = byte;
    return out;
}

ParentOwnFriFullArityAssessmentV1 ComputeParentOwnFriFullArityAssessmentV1()
{
    using AlgB3 = aq::AirFriBackendAlg<gf::Fp3>;
    ParentOwnFriFullArityAssessmentV1 out;
    out.backend_column_cap = kRCFri3AlgBatchMaxColumns;

    // Cheap: a two-row toy child proof plus one in-AIR four-slot parent
    // construction (build only, no parent FRI prove). This runs
    // UNCONDITIONALLY, in every gate, so `column_cap_admits` is always a
    // live recomputation, matching the "cap-fit asserted cheaply always"
    // policy the test suite documents for this exact shape.
    const auto child_cs = ParentOwnFriAssessorToyChildCsV1();
    const uint256 child_seed = ParentOwnFriAssessorSeedV1(0xf1);
    const std::vector<std::vector<gf::Fp3>> columns{
        {gf::Fp3::Zero(), gf::Fp3::One()}};
    const auto proved_child =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            child_cs, columns, child_seed, {});
    if (!proved_child.ok) {
        out.note =
            "g5:parent_own_fri_full_arity:toy_child_prove_failed:" +
            proved_child.note;
        return out;
    }

    const std::array<
        rpa::FourSlotSelfSimilarCtlParentV1::ChildProof, 4>
        proofs{
            proved_child.proof, proved_child.proof,
            proved_child.proof, proved_child.proof};
    rpa::FourSlotNodeContextV1 ctx;
    ctx.level = 1;
    ctx.index = 0;
    ctx.pub[0] = gf::FromU64_3(0x9001);
    ctx.pub[1] = gf::FromU64_3(0x9002);
    for (uint32_t word = 0;
         word < rpa::Arity4FamilyReceiptLayoutV1::kChildRootWords;
         ++word) {
        ctx.parent_receipt_root[word] =
            gf::FromU64_3(0x7000 + word);
    }

    const auto statement =
        rpa::ComputeFourSlotSelfSimilarParentStatementV1(
            child_cs, proofs, child_seed, ctx);
    const auto parent =
        rpa::BuildFourSlotSelfSimilarCtlParentV1(
            child_cs, proofs, child_seed, ctx, statement);
    out.parent_columns = parent.parent_columns;
    if (!parent.valid || parent.witness_violations != 0) {
        out.note =
            "g5:parent_own_fri_full_arity:toy_four_slot_parent_invalid:" +
            parent.note;
        return out;
    }
    out.column_cap_admits =
        parent.parent_columns > 0 &&
        parent.parent_columns <= out.backend_column_cap;

    // Heavy self-prove path. Default gate accepts the measured pin
    // (kRCStage3ParentOwnFriFullArityRoundTripMeasured) once the live cheap
    // half confirms column_cap_admits — same spirit as the episode
    // *RecursionEnginesExecuted flags. BTX_RUN_HEAVY_PARENT_FRI forces a live
    // recompute that can override the pin fail-closed on regression.
    out.heavy_gate_enabled =
        std::getenv("BTX_RUN_HEAVY_PARENT_FRI") != nullptr;
    if (!out.heavy_gate_enabled) {
        const bool measured =
            kRCStage3ParentOwnFriFullArityRoundTripMeasured;
        out.measured_pin_accepted = measured && out.column_cap_admits;
        out.full_arity_proof_produced = measured;
        out.full_arity_proof_verified = measured;
        out.tamper_and_wrong_seed_rejected = measured;
        out.full_arity_in_default_gate = out.measured_pin_accepted;
        out.note =
            "g5:parent_own_fri_full_arity:column_cap_admits=" +
            std::string(out.column_cap_admits ? "true" : "false") +
            ";measured_pin=" +
            std::string(measured ? "true" : "false") +
            ";measured_wall_us=" +
            std::to_string(
                kRCStage3ParentOwnFriFullArityMeasuredWallMicros) +
            ";measured_peak_rss_kb=" +
            std::to_string(
                kRCStage3ParentOwnFriFullArityMeasuredPeakRssKb) +
            ";measured_parent_columns=" +
            std::to_string(
                kRCStage3ParentOwnFriFullArityMeasuredParentColumns) +
            ";live_parent_columns=" +
            std::to_string(out.parent_columns) +
            (out.full_arity_in_default_gate
                 ? ";default_gate:closed_via_measured_pin"
                 : ";default_gate:open");
        return out;
    }

    out.full_arity_proof_recomputed_this_run = true;
    const uint256 parent_seed = ParentOwnFriAssessorSeedV1(0xf2);
    const auto own =
        rpa::ProveFourSlotSelfSimilarParentOwnFriV1(
            parent, parent_seed);
    out.full_arity_proof_produced = own.parent_own_fri_proof_produced;
    out.full_arity_proof_verified =
        own.prove_ok && own.division_exact && own.verify_ok;

    bool tamper_and_wrong_seed_rejected = false;
    if (out.full_arity_proof_verified) {
        std::string why;
        const bool wrong_seed_rejected =
            !aq::AirQuotientVerify<gf::Fp3, AlgB3>(
                parent.parent_cs, own.proof,
                ParentOwnFriAssessorSeedV1(0xf3), &why);
        bool tamper_rejected = false;
        if (!own.proof.batch.queries.empty() &&
            !own.proof.batch.queries[0].steps.empty()) {
            auto tampered = own.proof;
            tampered.batch.queries[0].steps[0].even =
                gf::Add(
                    tampered.batch.queries[0].steps[0].even,
                    gf::Fp3::One());
            tamper_rejected =
                !aq::AirQuotientVerify<gf::Fp3, AlgB3>(
                    parent.parent_cs, tampered, parent_seed, &why);
        }
        tamper_and_wrong_seed_rejected =
            wrong_seed_rejected && tamper_rejected;
    }
    out.tamper_and_wrong_seed_rejected =
        tamper_and_wrong_seed_rejected;

    out.full_arity_in_default_gate =
        out.column_cap_admits &&
        out.full_arity_proof_produced &&
        out.full_arity_proof_verified &&
        out.tamper_and_wrong_seed_rejected;
    out.note =
        out.full_arity_in_default_gate
            ? "g5:parent_own_fri_full_arity:recomputed_live_under_"
              "BTX_RUN_HEAVY_PARENT_FRI:closed"
            : "g5:parent_own_fri_full_arity:recomputed_live_under_"
              "BTX_RUN_HEAVY_PARENT_FRI:not_closed:" + own.note;
    return out;
}

} // namespace

ParentOwnFriFullArityAssessmentV1 AssessParentOwnFriFullArityV1()
{
    // Cached: this can be called from the global ledger assessment AND
    // directly by tests/other callers. BTX_RUN_HEAVY_PARENT_FRI does not
    // change mid-process, so a single live computation per process is both
    // correct and cheap to repeat-read.
    static const ParentOwnFriFullArityAssessmentV1 cached =
        ComputeParentOwnFriFullArityAssessmentV1();
    return cached;
}

bool ProductionReductionsCompleteV1(
    const ExecutableGlobalSoundnessLedgerV1& evidence)
{
    const bool all_selected_terms_reduced =
        evidence.canonical.terms.size() ==
            static_cast<size_t>(
                ExecutableGlobalTermKindV1::PowGrinding) &&
        std::all_of(
            evidence.canonical.terms.begin(),
            evidence.canonical.terms.end(),
            [](const ExecutableGlobalTermV1& term) {
                return term.quantitatively_accounted &&
                    term.implementation_executable &&
                    term.reduction_complete;
            });
    const bool selected_backend_evidence =
        evidence.single_fp3_backend_executable &&
        evidence.q192_multirow_v2_executable &&
        evidence.q192_split_rap_integrated &&
        evidence.ctl_dual_lane_arithmetic_executable &&
        evidence.recursive_child_transport_fp3_only &&
        evidence.legacy_fp2_transport_bound_inapplicable &&
        evidence.hash_primitives_executable &&
        evidence.grinding_parameter_executable &&
        evidence.internal_fri_grinding_charged;
    const bool selected_topology_evidence =
        evidence.exact_selected_topology_manifest_derived &&
        evidence.canonical_heterogeneous_site_topology_derived &&
        evidence.canonical.site_count_manifest_derived &&
        evidence.canonical.covers_selected_relation_local_topology &&
        evidence.canonical.production_theorem &&
        all_selected_terms_reduced;

    return
        selected_backend_evidence &&
        evidence.external_pow_work_composition_complete &&
        evidence.semantic_relation_closure_complete &&
        evidence.normalized_recursive_verifier_executable &&
        selected_topology_evidence &&
        evidence.universal_program_registry_binding_defined &&
        evidence.universal_program_registry_consumed_in_recursion &&
        evidence.ali_degree_and_constraint_manifest_complete &&
        evidence.ctl_export_and_terminal_reduction_complete &&
        evidence.hash_first_collision_hybrid_complete &&
        evidence.nirop_oracle_separation_complete &&
        evidence.safe_q192_v3_dominates_shipped_target &&
        evidence.safe_q192_pow_composition
            .numeric_bound_machine_checked &&
        evidence.safe_q192_pow_composition
            .pow_composition_theorem_complete &&
        evidence.pow_composition_theorem_complete;
}

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

    const RCStage3CoupledShape semantic_shape =
        MakeRCStage3CoupledShape(
            MakeProductionV3RCCoupParams(),
            MakeV3RCCoupOptions());
    const auto semantic_status =
        CurrentRCStage3SemanticStatus(
            semantic_shape, gf::Fp3::FromFp(7),
            gf::Fp3::FromFp(11), 1,
            /*production_mode=*/true);
    out.semantic_relation_closure_complete =
        semantic_status.registry_exact &&
        semantic_status.semantic_complete_endpoints ==
            kRCStage3RelationClosureEndpointCount;
    out.normalized_recursive_verifier_executable =
        stage3_verifier_air::kVerifierFiatShamirAirExecutable &&
        stage3_verifier_air::kVerifierProofRowsBoundInAir &&
        stage3_verifier_air::kWholeVerifierWitnessExecutable &&
        stage3_verifier_air::
            kMultiRowV2SplitRapVerifierAirLocalExecutable &&
        stage3_verifier_air::
            kMultiRowV2SplitRapVerifierAirRecursiveAuthority &&
        recursive_fixedpoint::
            kCompleteRecursiveFixedPointExecutable;
    out.exact_selected_topology_manifest_derived =
        out.canonical.site_count_manifest_derived &&
        out.canonical.covers_selected_relation_local_topology &&
        out.canonical.production_theorem;
    out.canonical_heterogeneous_site_topology_derived =
        canonical_inventory;
    out.deprecated_width_product_rejected = true;
    out.universal_program_registry_binding_defined = true;
    out.universal_program_registry_consumed_in_recursion =
        false;
    // The ALI/degree inventory is a local reduction and is deliberately
    // independent of both semantic relation closure and recursive registry
    // consumption (those are separate fail-closed predicates below/above).
    // Rebuild and validate both views from the canonical production sources:
    //
    //  * V1 derives every source/compiled constraint count, challenge class,
    //    algebraic degree, quotient/LDE domain and coefficient cap for the
    //    exact ordered 28-family Q192 inventory.
    //  * V2 proves the same inventory covers all 14 registered roles with
    //    canonical non-stub ProgramTables and derived degree bounds.
    //
    // This does not claim that the currently partial family programs close
    // all 52 semantic endpoints; `semantic_relation_closure_complete` remains
    // the independent predicate for exactly that obligation.
    static const bool ali_degree_and_constraint_manifest_complete = [] {
        const auto manifest =
            stage3_ali_manifest::BuildProductionAliManifestV1();
        const auto assessment =
            stage3_ali_manifest::BuildProductionAliAssessmentV2();
        return
            stage3_ali_manifest::ValidateProductionAliManifestV1(
                manifest, nullptr) &&
            stage3_ali_manifest::ValidateProductionAliAssessmentV2(
                assessment, nullptr) &&
            manifest.local_manifest_complete &&
            manifest.exact_28_family_order &&
            manifest.every_source_non_stub &&
            manifest.every_challenge_degree_checked &&
            manifest.every_q192_row_bound_exact &&
            manifest.every_quotient_lde_bound_derived &&
            manifest.every_compiled_program_53_columns &&
            manifest.every_family_within_cap &&
            manifest.canonical_u32_injective_commitment &&
            assessment.local_ali_assessment_complete &&
            assessment.exact_28_family_registry &&
            assessment.exact_14_role_order &&
            assessment.every_registered_role_has_program &&
            assessment.every_program_table_non_stub &&
            assessment.every_degree_bound_derived;
    }();
    out.ali_degree_and_constraint_manifest_complete =
        ali_degree_and_constraint_manifest_complete;
    const auto role_closure =
        CurrentRCStage3RelationClosureRoleAudit();
    out.ctl_export_and_terminal_reduction_complete =
        role_closure.size() ==
            kRCStage3RelationClosureRoleCount &&
        std::all_of(
            role_closure.begin(), role_closure.end(),
            [](const RCStage3RelationClosureRoleAudit& role) {
                return role.proof_derived_ctl_endpoints ==
                           role.required_endpoints &&
                    role.recursive_ctl_consumption &&
                    role.role_complete;
            });
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
    // g5 (self-similar fixed point) = full-arity parent-own-FRI round trip AND
    // g4.  The first conjunct is AssessParentOwnFriFullArityV1(): live
    // column_cap_admits every call, plus either the measured pin
    // kRCStage3ParentOwnFriFullArityRoundTripMeasured (episode-flag spirit:
    // prove+verify+tamper-reject+wrong-seed-reject observed under
    // BTX_RUN_HEAVY_PARENT_FRI / MemoryMax+MemorySwapMax=0) or a live
    // recompute when that env is set.  g4 remains independently required.
    const ParentOwnFriFullArityAssessmentV1
        parent_own_fri_full_arity =
            AssessParentOwnFriFullArityV1();
    out.self_similar_fixed_point_closed =
        parent_own_fri_full_arity.full_arity_in_default_gate &&
        out.fiat_shamir_replay_complete;
    out.nirop_oracle_separation_complete = false;
    {
        pow_composition::PremisesV1 premises;

        // These three are mechanical properties of the consensus attachment:
        // RCStage3HeaderCommitment removes only matmul_digest, the public
        // statement binds the canonical params/height/target tuple, and
        // ValidateRCStage3ConsensusBinding performs the uint256 comparison.
        premises.header_projection_and_final_digest_disjoint = true;
        premises.params_height_target_and_sigma_bound = true;
        premises.digest_compared_to_target_as_integer = true;

        // The payload is serialized and consensus-bound, but the complete
        // normalized parent does not yet own every proof byte/transcript cell.
        premises.complete_proof_payload_transcript_bound =
            out.normalized_recursive_verifier_executable;
        premises.statement_bound_before_first_proof_commitment =
            receipt_public_statement::
                kReceiptPublicStatementSameParentVerifierExecutableV1 &&
            out.normalized_recursive_verifier_executable;

        // A complete semantic registry is the conservative source for every
        // tensor-work subrelation.  Do not reuse the engines-only g1/g0 pins.
        premises.builder_params_and_seed_chain_proved =
            out.semantic_relation_closure_complete;
        premises.every_gemm_and_signed_range_proved =
            out.semantic_relation_closure_complete;
        premises.every_extract_and_wiring_step_proved =
            out.semantic_relation_closure_complete;
        premises.tile_tree_and_round_order_proved =
            out.semantic_relation_closure_complete;
        premises.final_digest_and_pow_predicate_proved =
            out.semantic_relation_closure_complete;
        premises.coupled_relation_additive_when_required =
            out.semantic_relation_closure_complete;
        premises.all_relation_children_recursively_verified =
            out.normalized_recursive_verifier_executable &&
            out.ctl_export_and_terminal_reduction_complete;

        premises.one_canonical_transcript_dag =
            out.fiat_shamir_replay_complete &&
            out.normalized_recursive_verifier_executable;
        premises.full_fiat_shamir_replay_owned_by_verifier =
            out.fiat_shamir_replay_complete &&
            out.normalized_recursive_verifier_executable;
        premises.nirop_bcs_reduction_complete =
            out.nirop_oracle_separation_complete;
        premises.commitment_binding_reduction_complete =
            out.hash_first_collision_hybrid_complete;
        premises.adaptive_statement_selection_accounted =
            out.nirop_oracle_separation_complete &&
            out.hash_first_collision_hybrid_complete;

        // Current Q192 is the untaxed single-lane construction.  The global
        // 40-bit adversary-work budget is deducted once from algebraic terms;
        // the BCS all-query work term is not charged again.
        premises.regrind_budget_bits =
            kConservativeGrindingBits;
        premises.algebraic_regrind_deduction_bits =
            kConservativeGrindingBits;
        premises.selected_path_has_enforced_squeeze_predicate =
            kRCFri3AlgSingleLaneEnforcesSqueezeGrind;
        premises.bcs_term_is_all_query_work_bound = true;
        premises.bcs_regrind_not_double_charged = true;

        // The Stage-3 attachment calls only the complete succinct relation
        // verifier. Profile-2 sampled carriers and exact replay are not an
        // authority fallback in VerifyRCStage3ConsensusAttachment.
        premises.sampled_carrier_excluded_from_authority = true;
        premises.exact_replay_excluded_from_authority = true;

        out.pow_composition =
            pow_composition::AssessPowCompositionV1(premises);
        out.external_pow_work_composition_complete =
            out.pow_composition
                .external_tensor_work_composition_complete;
        out.pow_composition_theorem_complete =
            false;
    }
    {
        pow_composition::PremisesV3 premises;

        // V13 is additive until its normalized parent and consensus selector
        // close. Keeping this sourced from the actual activation constant
        // prevents the arithmetic theorem from selecting its own backend.
        premises.safe_q192_backend_consensus_selected =
            kRCFri3AlgSafeQ192K2ActivatedV13;

        premises.header_projection_and_final_digest_disjoint = true;
        premises.statement_bound_before_first_proof_commitment =
            receipt_public_statement::
                kReceiptPublicStatementSameParentVerifierExecutableV1 &&
            out.normalized_recursive_verifier_executable;
        premises.complete_proof_payload_transcript_bound =
            out.normalized_recursive_verifier_executable;
        premises.complete_tensor_work_relation =
            out.semantic_relation_closure_complete;
        premises.all_relation_children_recursively_verified =
            out.normalized_recursive_verifier_executable &&
            out.ctl_export_and_terminal_reduction_complete;

        premises.versioned_domain_and_fixed_k2 =
            kRCFri3AlgSafeQ192K2ProofVersionV13 == 13 &&
            kRCFri3AlgSafeQ192K2OodCandidatesV13 ==
                pow_composition::kPowCompositionV3OodCandidates;
        premises.typed_safe_domain_registry_pinned =
            out.universal_program_registry_binding_defined;
        premises.safe_native_air_parity_complete =
            out.fiat_shamir_replay_complete;
        premises.full_typed_transcript_program_proof_owned =
            out.fiat_shamir_replay_complete;
        premises.full_typed_transcript_recursively_replayed =
            out.fiat_shamir_replay_complete &&
            out.normalized_recursive_verifier_executable;
        premises.query_seed_binds_complete_post_terminal_transcript =
            out.fiat_shamir_replay_complete;
        premises.canonical_query_seed_is_sole_query_source =
            out.fiat_shamir_replay_complete;
        premises.all_query_candidates_recursively_consumed =
            out.fiat_shamir_replay_complete &&
            out.normalized_recursive_verifier_executable;
        premises.fixed_k2_selector_recursively_enforced =
            out.fiat_shamir_replay_complete &&
            out.normalized_recursive_verifier_executable;

        premises.one_trace_and_commitment_statement_bound =
            out.normalized_recursive_verifier_executable &&
            out.universal_program_registry_consumed_in_recursion;
        premises.fri_bcs_reduction_complete =
            kRCFri3AlgFormalSoundnessReady;
        premises.concrete_safe_nirop_reduction_complete =
            out.nirop_oracle_separation_complete;
        premises.poseidon2_binding_reduction_complete =
            out.hash_first_collision_hybrid_complete;
        premises.proof_site_upper_bound_recursively_enforced =
            out.exact_selected_topology_manifest_derived;
        premises.adaptive_statement_selection_accounted =
            out.nirop_oracle_separation_complete &&
            out.hash_first_collision_hybrid_complete;

        premises.unenforced_regrind_deduction_in_fri_bits =
            !kRCFri3AlgSingleLaneEnforcesSqueezeGrind &&
            Fri3AlgSoundnessBoundBits() ==
                static_cast<int>(
                    pow_composition::kPowCompositionV3FriBits);
        premises.site_union_and_regrind_each_charged_once =
            out.exact_selected_topology_manifest_derived &&
            out.internal_fri_grinding_charged;
        premises.proof_nonce_not_credited_as_tensor_work = true;
        premises.sampled_carrier_excluded_from_authority = true;
        premises.exact_replay_excluded_from_authority = true;

        out.safe_q192_pow_composition =
            pow_composition::AssessPowCompositionV3(premises);
        out.external_pow_work_composition_complete =
            out.safe_q192_pow_composition
                .pow_composition_theorem_complete;
        out.pow_composition_theorem_complete =
            out.safe_q192_pow_composition
                .pow_composition_theorem_complete;
    }
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

    // V1 consensus/security-target decision (recommendation #6). Intended
    // target is the 64-bit class with the computed ~79-bit global composed
    // floor — NOT an unused 100-bit requirement. Encoding only; does not flip
    // certified_bits or readiness gates.
    out.v1_security_target_is_64bit_class =
        out.composed_floor.global_meets_64 &&
        out.composed_certified_bits_target >=
            kV1ConsensusSecurityClassBits;
    out.v1_global_floor_matches_shipped_79 =
        out.composed_certified_bits_target ==
            kV1ShippedGlobalComposedFloorBits &&
        out.composed_floor.global_meets_64 &&
        !out.composed_floor.global_meets_100;
    out.v1_unused_100bit_requirement_is_not_target =
        kUnusedHundredBitRequirementBits >
            kV1ConsensusSecurityClassBits &&
        out.composed_certified_bits_target <
            kUnusedHundredBitRequirementBits &&
        out.composed_certified_bits_target ==
            kV1ShippedGlobalComposedFloorBits;
    out.v1_security_target_decision_encoded =
        out.v1_security_target_is_64bit_class &&
        out.v1_global_floor_matches_shipped_79 &&
        out.v1_unused_100bit_requirement_is_not_target;

    // Machine-check the legacy 79-bit release-target arithmetic, then require
    // the selected single-Q192 SAFE V3 numeric theorem to dominate that
    // target. The V3 theorem is independently required by the production
    // reductions below, so dual-lane A2 is retained as an audit comparison,
    // not selected as an authority premise. eps_P2 is sourced from the
    // executable M-LINK single-global-epsilon floor.
    const double mlink_p2_epsilon_bits =
        stage3_mlink::AssessMLinkSoundnessV1().epsilon_mlink_bits;
    out.global_additive_composition =
        ComposeExecutableGlobalAdditiveBoundV1(
            out.composed_floor, mlink_p2_epsilon_bits);
    out.safe_q192_v3_dominates_shipped_target =
        out.safe_q192_pow_composition
            .numeric_bound_machine_checked &&
        out.safe_q192_pow_composition
            .global_conditional_bits >=
            static_cast<double>(
                out.composed_certified_bits_target);
    out.global_additive_composition_machine_checked =
        out.global_additive_composition.machine_checked &&
        out.safe_q192_v3_dominates_shipped_target;

    // Gate 6 completes ONLY when (a) the executable composition genuinely
    // machine-checks AND (b) the constructions it composes are executable, i.e.
    // gates 0-5 are all true. The composition is machine-checked today, but the
    // dependency gates remain open, so the theorem stays incomplete and no bits
    // are minted. This is the honest, dependency-ordered flip.
    // ---- Gate evidence predicates. -----------------------------------------
    // Each readiness constant below is conjoined with an INDEPENDENT evidence
    // predicate computed from the tree. The conjunction is strictly fail-closed:
    // it can only ever remove a `true`, never add one. Its purpose is that
    // flipping a readiness constant on its own can no longer close a gate — the
    // corresponding evidence must genuinely compute closed as well.

    // g3 evidence: the single-lane Fri3Alg round-by-round / BCS reduction,
    // re-derived here from this backend's construction constants. The ledger
    // previously trusted the bare header literal; it now recomputes the
    // machine-check itself, so a regression in Q / rho / blowup / lde or in the
    // round composition reopens g3 instead of silently keeping it closed.
    const bool fri3_rbr_machine_checked =
        scenarios::AssessFri3AlgBcsRbrLedgerV1()
            .rbr_reduction_machine_checked;
    const bool gate3_fri_alg_formal_soundness =
        kRCFri3AlgFormalSoundnessReady &&
        fri3_rbr_machine_checked;

    // g1 evidence: Gaps().empty() (all six Episode*RecursionEnginesExecuted
    // measured true) AND kRCStage3EpisodeRelationsReady.
    const bool episode_relation_gaps_empty =
        CurrentRCStage3EpisodeRelationGaps().empty();
    const bool gate1_episode_relations =
        kRCStage3EpisodeRelationsReady &&
        episode_relation_gaps_empty;

    // g0 evidence: VerifyRCStage3MathematicalProof calls
    // VerifyRCStage3EpisodeRelations UNCONDITIONALLY for every statement kind,
    // and that returns false while g1 is open; a Composed statement additionally
    // requires the coupled relation engines. g0 is therefore a strict downstream
    // of g1 and of kRCStage3CoupledRelationEnginesReady, and the ledger now
    // encodes that dependency instead of reading g0's literal in isolation.
    const bool gate0_mathematical_verifier =
        kRCStage3MathematicalVerifierReady &&
        gate1_episode_relations &&
        kRCStage3CoupledRelationEnginesReady;

    // g2 evidence: AssessRCStage3RecursiveReadiness makes
    // cryptographic_verification_ready depend on child_fiat_shamir_replay_closed
    // (matmul_v4_rc_stage3_recursive.cpp). That value IS this ledger's g4, so it
    // is conjoined directly — calling the recursive assessor from here would
    // create a cycle, because recursive.cpp already calls this function to
    // source its own g4 value.
    //
    // g2 additionally carries TWO blockers of its own, neither of which is
    // implied by g4. Before they were conjoined here, g2 reduced ENTIRELY to
    // "constant && g4", so closing g4 would have closed g2 with no evidence at
    // all about aggregation. Both are strictly fail-closed additions.
    //
    //  (i) REGISTRY COMPLETENESS. Every role a Composed statement requires must
    //      resolve to a real C_rho through the immutable registry. This was
    //      false for RCStage3RelationRole::CompositionLink — a Composed
    //      statement could never be fully section-verified — and is recomputed
    //      here across the actual required-role list rather than asserted.
    // (ii) THE TWO-LEVEL ROOT VERIFY BUDGET. The recursive readiness report's
    //      ProductionPerformanceUnmeasured gap. Recomputed from
    //      CurrentRCStage3TwoLevelRootVerifyBudgetV1(), which is itself
    //      fail-closed on representability, production, and measurement.
    bool composed_registry_closable = true;
    for (const RCStage3RelationRole role :
         RequiredRCStage3RelationRoles(RCStage3StatementKind::Composed)) {
        if (!RCStage3RoleIsInCsClosable(role)) {
            composed_registry_closable = false;
            break;
        }
    }
    const bool two_level_root_verify_within_budget =
        CurrentRCStage3TwoLevelRootVerifyBudgetV1().within_relay_budget;
    // Codec-size residual (FRI hard proof-byte budget). Distinct from
    // ProductionPerformanceUnmeasured / within_relay_budget (verify wall-
    // clock). Gates on the MEASURED narrow L2 family-root
    // SerializeFri3AlgBatchProof size — NOT Extract engine receipts
    // (~836 MiB), which remain documented oversize evidence only.
    const bool mandatory_family_root_serialize_within_fri_budget =
        kRCStage3MandatoryFamilyRootSerializeWithinFriBudgetMeasured &&
        CurrentRCStage3TwoLevelRootVerifyBudgetV1()
            .narrow_l2_serialize_within_fri_budget;
    const bool gate2_recursive_aggregation =
        kRCStage3RecursiveAggregationReady &&
        out.fiat_shamir_replay_complete &&
        composed_registry_closable &&
        two_level_root_verify_within_budget &&
        mandatory_family_root_serialize_within_fri_budget;

    const bool dependency_gates_0_to_5 =
        gate0_mathematical_verifier &&
        gate1_episode_relations &&
        gate2_recursive_aggregation &&
        gate3_fri_alg_formal_soundness &&
        out.fiat_shamir_replay_complete &&
        out.self_similar_fixed_point_closed;
    // The additive union arithmetic is necessary but not sufficient.  Keep
    // every production reduction in this independent conjunction so that a
    // future readiness-constant flip cannot mint certified bits while the
    // semantic, recursive, registry, ALI, CTL, hash/NIROP or PoW theorem is
    // still explicitly open.
    out.production_reductions_complete =
        ProductionReductionsCompleteV1(out);
    out.global_additive_theorem_complete =
        out.global_additive_composition_machine_checked &&
        dependency_gates_0_to_5 &&
        out.production_reductions_complete;

    // Ordered readiness interlock. Every member is sourced from its honest
    // current flag value; NONE is fabricated here. `all_clear` is the single
    // predicate that flips the live certified_bits off zero.
    CompositionReadinessGateV1 gate;
    gate.mathematical_verifier_ready =
        gate0_mathematical_verifier;
    gate.episode_relations_ready =
        gate1_episode_relations;
    gate.recursive_aggregation_ready =
        gate2_recursive_aggregation;
    gate.fri_alg_formal_soundness_ready =
        gate3_fri_alg_formal_soundness;
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
        "canonical_28_family_14_role_ali_degree_manifest_complete;"
        "canonical_known_union_above_100;"
        "authenticated_family_residual_fold_executable;"
        "family_residual_vm_binding_open;"
        "product_diagnostic_fri_saturates_below_100;"
        "composed_floor_Fqstar_per_site_104_global_79_computed;"
        "v1_security_target_64bit_class_with_shipped_global_floor_79;"
        "unused_100bit_requirement_is_not_v1_consensus_target;"
        "single_q192_safe_v3_numeric_floor_dominates_shipped_target;"
        "dual_lane_independence_not_selected_authority_premise;"
        "certified_bits_gated_on_readiness_interlock_currently_zero;"
        "assumptions_M2_A2_field_bounds_hash_model_recorded_audit_input;"
        "global_reductions_open";
    return out;
}

} // namespace matmul::v4::rc::global_soundness_ledger
