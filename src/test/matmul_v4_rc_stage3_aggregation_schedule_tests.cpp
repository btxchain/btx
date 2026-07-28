// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <matmul/matmul_v4_rc_air_quotient.h>
#include <matmul/matmul_v4_rc_air_quotient_alg.h>
#include <matmul/matmul_v4_rc_fri_ext3_alg.h>
#include <matmul/matmul_v4_rc_stage3_aggregation_schedule.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace scheduler =
    matmul::v4::rc::aggregation_scheduler;
namespace ss =
    matmul::v4::rc::soundness_scenarios;

namespace {

uint256 Filled(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

uint256 ParentCommitment(
    const scheduler::ParentWorkItem& work)
{
    HashWriter hash;
    hash << "BTX_RC_STAGE3_TEST_PARENT";
    hash << work.seed;
    hash << work.parent_site;
    return hash.GetHash();
}

scheduler::ParentReceipt Receipt(
    const scheduler::ParentWorkItem& work)
{
    scheduler::ParentReceipt out;
    out.work_seed = work.seed;
    out.parent_commitment = ParentCommitment(work);
    out.binding =
        scheduler::CommitProductionAggregationReceipt(
            work, out.parent_commitment);
    return out;
}

// ---------------------------------------------------------------------------
// Cryptographic child consumption helpers.
// ---------------------------------------------------------------------------

namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
using AlgB3 = aq::AirFriBackendAlg<gf::Fp3>;

/** Wrapper: the template comma cannot appear inside a Boost.Test macro. */
bool VerifyChildProof(const aq::AirConstraintSystem<gf::Fp3>& cs,
                      const scheduler::ChildProof& proof,
                      const uint256& seed, std::string* why)
{
    return aq::AirQuotientVerify<gf::Fp3, AlgB3>(cs, proof, seed, why);
}

struct RealChildren {
    aq::AirConstraintSystem<gf::Fp3> cs;
    std::vector<std::vector<gf::Fp3>> witness;
    scheduler::ChildProof proof;
    uint256 fs_seed;
};

/**
 * REAL RC Stage3 role AIR children: the CoupledPermutation C_rho assembled over
 * the canonical commitment manifests (real committed roots, real Merkle
 * siblings, real opening witness), proven with the real unmodified prover.
 * This is the same real-role child the parent-AIR lane consumes.
 */
RealChildren BuildRealRoleChild(unsigned char seed_byte)
{
    RealChildren out;
    const gf::Fp3 cell =
        gf::Fp3::FromFp(gf::FromU64(0x2bad10ULL));
    const auto product =
        rc::BuildRCStage3CoupledPermutationRoleAir(
            cell, 0, /*path_len=*/3, nullptr);
    BOOST_REQUIRE_MESSAGE(product.ok, product.note);
    BOOST_REQUIRE_EQUAL(
        matmul::v4::rc::air_recurse::CountWitnessViolationsOnH(
            product.cs, product.witness),
        0U);
    out.cs = product.cs;
    out.witness = product.witness;
    out.fs_seed = Filled(seed_byte);
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            out.cs, out.witness, out.fs_seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        VerifyChildProof(out.cs, proved.proof, out.fs_seed, &why),
        why);
    out.proof = proved.proof;
    return out;
}

/** Minimal-shape child (2 rows x 1 column) with a genuine FRI proof. */
RealChildren BuildToyChild(unsigned char seed_byte)
{
    RealChildren out;
    out.cs.n_rows = 2;
    out.cs.n_columns = 1;
    aq::AirConstraint<gf::Fp3> boolean;
    boolean.name = "aggregation.toy.boolean";
    boolean.kind = aq::AirKind::kEverywhere;
    boolean.alg_degree = 2;
    boolean.eval = [](const std::vector<gf::Fp3>& current,
                      const std::vector<gf::Fp3>&) {
        return gf::Mul(current[0],
                       gf::Sub(current[0], gf::Fp3::One()));
    };
    out.cs.constraints.push_back(std::move(boolean));
    out.witness = {{gf::Fp3::Zero(), gf::Fp3::One()}};
    out.fs_seed = Filled(seed_byte);
    const auto proved =
        aq::AirQuotientProve<gf::Fp3, AlgB3>(
            out.cs, out.witness, out.fs_seed, {});
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        VerifyChildProof(out.cs, proved.proof, out.fs_seed, &why),
        why);
    out.proof = proved.proof;
    return out;
}

/** Four slots of the identical real child (the self-similar arity-4 shape). */
scheduler::ParentChildProofBundle Bundle(const RealChildren& child)
{
    scheduler::ParentChildProofBundle bundle;
    bundle.child_cs = child.cs;
    bundle.child_fs_seed = child.fs_seed;
    for (auto& slot : bundle.child_proofs) slot = child.proof;
    return bundle;
}

/** First below-root parent ordinal whose job is a full arity-4 job. */
uint64_t FirstFullArityOrdinal(
    const scheduler::ProductionAggregationSchedule& schedule,
    const uint256& seed)
{
    for (uint64_t o = 0; o < schedule.below_root_parent_sites && o < 64; ++o) {
        std::string why;
        const auto work =
            scheduler::ProductionAggregationParentWorkItem(
                schedule, seed, o, &why);
        if (work.has_value() && work->child_count == 4) return o;
    }
    return UINT64_MAX;
}

bool RunHeavyRealChildren()
{
    const char* v = std::getenv("BTX_RUN_AGG_REAL_CHILDREN");
    return v != nullptr && v[0] == '1';
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_aggregation_schedule_tests)

BOOST_AUTO_TEST_CASE(
    exact_manifest_ranges_and_every_arity4_parent_are_recomputed)
{
    const auto manifest = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    BOOST_REQUIRE(!manifest.commitment.IsNull());
    const auto schedule =
        scheduler::BuildProductionAggregationSchedule(manifest);
    BOOST_REQUIRE(!schedule.commitment.IsNull());
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        scheduler::ValidateProductionAggregationSchedule(
            manifest, schedule, &why),
        why);

    BOOST_CHECK_EQUAL(schedule.arity, 4U);
    BOOST_CHECK_EQUAL(schedule.families.size(), 28U);
    BOOST_CHECK_EQUAL(schedule.roles.size(), 14U);
    BOOST_CHECK_EQUAL(
        schedule.relation_leaf_sites,
        manifest.relation_leaf_sites);
    BOOST_CHECK_EQUAL(
        schedule.below_root_parent_sites,
        manifest.below_root_aggregation_sites);
    BOOST_CHECK_EQUAL(
        schedule.final_tree_parent_sites,
        manifest.final_tree_aggregation_sites);
    BOOST_CHECK_EQUAL(
        schedule.total_proof_sites,
        manifest.total_proof_sites);

    uint64_t leaf_cursor{0};
    for (size_t i = 0; i < schedule.families.size(); ++i) {
        const auto& range = schedule.families[i];
        BOOST_CHECK_EQUAL(range.family_index, i);
        BOOST_CHECK(range.kind == manifest.entries[i].kind);
        BOOST_CHECK(range.role == manifest.entries[i].role);
        BOOST_CHECK_EQUAL(range.first_leaf_site, leaf_cursor);
        BOOST_CHECK_EQUAL(
            range.leaf_count,
            manifest.entries[i].proof_sites);
        leaf_cursor += range.leaf_count;
    }
    BOOST_CHECK_EQUAL(leaf_cursor, manifest.relation_leaf_sites);

    uint64_t ordinal{0};
    uint64_t parent_site_cursor = manifest.relation_leaf_sites;
    for (const auto& role : schedule.roles) {
        uint64_t expected_child_first = role.first_leaf_site;
        uint64_t expected_child_count = role.leaf_count;
        for (const auto& level : role.levels) {
            BOOST_CHECK_EQUAL(
                level.first_child_site, expected_child_first);
            BOOST_CHECK_EQUAL(
                level.child_count, expected_child_count);
            BOOST_CHECK_EQUAL(
                level.first_parent_site, parent_site_cursor);
            BOOST_CHECK_EQUAL(
                level.parent_count,
                (level.child_count + 3) / 4);

            const auto first =
                scheduler::ProductionAggregationParentWorkItem(
                    schedule, Filled(1), ordinal, &why);
            BOOST_REQUIRE_MESSAGE(first.has_value(), why);
            BOOST_CHECK_EQUAL(
                first->parent_site, level.first_parent_site);
            BOOST_CHECK_EQUAL(first->first_child_site,
                              level.first_child_site);

            const uint64_t last_ordinal =
                ordinal + level.parent_count - 1;
            const auto last =
                scheduler::ProductionAggregationParentWorkItem(
                    schedule, Filled(1), last_ordinal, &why);
            BOOST_REQUIRE_MESSAGE(last.has_value(), why);
            BOOST_CHECK_EQUAL(
                last->parent_site,
                level.first_parent_site +
                    level.parent_count - 1);
            BOOST_CHECK_GE(last->child_count, 1U);
            BOOST_CHECK_LE(last->child_count, 4U);

            ordinal += level.parent_count;
            parent_site_cursor += level.parent_count;
            expected_child_first = level.first_parent_site;
            expected_child_count = level.parent_count;
        }
        BOOST_CHECK_EQUAL(expected_child_count, 1U);
        BOOST_CHECK_EQUAL(role.root_site, expected_child_first);
    }
    BOOST_CHECK_EQUAL(
        ordinal, manifest.below_root_aggregation_sites);
    BOOST_CHECK_EQUAL(
        parent_site_cursor,
        manifest.relation_leaf_sites +
            manifest.below_root_aggregation_sites);
    BOOST_CHECK(
        !scheduler::ProductionAggregationParentWorkItem(
             schedule, Filled(1), ordinal, &why)
             .has_value());
}

BOOST_AUTO_TEST_CASE(
    omission_reorder_duplicate_count_and_arity_are_rejected)
{
    const auto manifest = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    const auto canonical =
        scheduler::BuildProductionAggregationSchedule(manifest);
    BOOST_REQUIRE(!canonical.commitment.IsNull());
    std::string why;

    auto omitted = canonical;
    omitted.families.pop_back();
    omitted.commitment =
        scheduler::CommitProductionAggregationSchedule(omitted);
    BOOST_CHECK(
        !scheduler::ValidateProductionAggregationSchedule(
            manifest, omitted, &why));

    auto reordered = canonical;
    std::swap(reordered.families[0], reordered.families[1]);
    reordered.commitment =
        scheduler::CommitProductionAggregationSchedule(reordered);
    BOOST_CHECK(
        !scheduler::ValidateProductionAggregationSchedule(
            manifest, reordered, &why));

    auto duplicated = canonical;
    duplicated.families[1] = duplicated.families[0];
    duplicated.commitment =
        scheduler::CommitProductionAggregationSchedule(duplicated);
    BOOST_CHECK(
        !scheduler::ValidateProductionAggregationSchedule(
            manifest, duplicated, &why));

    auto bad_count = canonical;
    --bad_count.families[0].leaf_count;
    bad_count.commitment =
        scheduler::CommitProductionAggregationSchedule(bad_count);
    BOOST_CHECK(
        !scheduler::ValidateProductionAggregationSchedule(
            manifest, bad_count, &why));

    auto bad_parent_count = canonical;
    BOOST_REQUIRE(!bad_parent_count.roles[0].levels.empty());
    --bad_parent_count.roles[0].levels[0].parent_count;
    bad_parent_count.commitment =
        scheduler::CommitProductionAggregationSchedule(
            bad_parent_count);
    BOOST_CHECK(
        !scheduler::ValidateProductionAggregationSchedule(
            manifest, bad_parent_count, &why));

    auto bad_arity = canonical;
    bad_arity.arity = 2;
    bad_arity.commitment =
        scheduler::CommitProductionAggregationSchedule(bad_arity);
    BOOST_CHECK(bad_arity.commitment.IsNull());
    BOOST_CHECK(
        !scheduler::ValidateProductionAggregationSchedule(
            manifest, bad_arity, &why));
}

BOOST_AUTO_TEST_CASE(
    binary_v1_schedule_is_exact_full_wide_eligible_and_soundness_screened)
{
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto arity4 =
        scheduler::BuildProductionAggregationSchedule(manifest);
    const auto binary =
        scheduler::BuildBinaryV1AggregationSchedule(manifest);
    BOOST_REQUIRE(!binary.commitment.IsNull());
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        scheduler::ValidateBinaryV1AggregationSchedule(
            manifest, binary, &why),
        why);
    BOOST_CHECK_EQUAL(binary.arity, 2U);
    BOOST_CHECK_EQUAL(binary.families.size(), 28U);
    BOOST_CHECK_EQUAL(binary.roles.size(), 14U);
    BOOST_CHECK_EQUAL(
        binary.relation_leaf_sites,
        manifest.relation_leaf_sites);
    BOOST_CHECK_GT(
        binary.below_root_parent_sites,
        arity4.below_root_parent_sites);
    BOOST_CHECK_EQUAL(
        binary.total_proof_sites,
        binary.relation_leaf_sites +
            binary.below_root_parent_sites +
            binary.final_tree_parent_sites);

    uint64_t ordinal = 0;
    for (const auto& role : binary.roles) {
        for (const auto& level : role.levels) {
            BOOST_CHECK_EQUAL(
                level.parent_count,
                (level.child_count + 1) / 2);
            const auto first =
                scheduler::BinaryV1AggregationParentWorkItem(
                    binary, Filled(77), ordinal, &why);
            BOOST_REQUIRE_MESSAGE(first.has_value(), why);
            BOOST_CHECK_GE(first->child_count, 1U);
            BOOST_CHECK_LE(first->child_count, 2U);
            const auto last =
                scheduler::BinaryV1AggregationParentWorkItem(
                    binary, Filled(77),
                    ordinal + level.parent_count - 1,
                    &why);
            BOOST_REQUIRE_MESSAGE(last.has_value(), why);
            BOOST_CHECK_GE(last->child_count, 1U);
            BOOST_CHECK_LE(last->child_count, 2U);
            ordinal += level.parent_count;
        }
    }
    BOOST_CHECK_EQUAL(
        ordinal, binary.below_root_parent_sites);

    const auto scenario =
        scheduler::AssessBinaryV1SoundnessScenario(manifest);
    BOOST_CHECK_EQUAL(
        scenario.exact_total_sites,
        binary.total_proof_sites);
    BOOST_CHECK_GE(
        scenario.union_bound_cap,
        scenario.exact_total_sites);
    BOOST_CHECK(
        (scenario.union_bound_cap &
         (scenario.union_bound_cap - 1)) == 0);
    BOOST_CHECK(
        scenario.every_parent_child_count_at_most_two);
    BOOST_CHECK(!scenario.every_parent_full_wide_eligible);
    BOOST_CHECK(
        scenario.numeric_exact_site_target_met);
    BOOST_CHECK(scenario.numeric_cap_target_met);
    BOOST_CHECK(!scenario.all_node_execution_complete);
    BOOST_CHECK(!scenario.theorem_complete);
    BOOST_CHECK(!scenario.authority_eligible);

    auto bad = binary;
    bad.roles[0].levels[0].parent_count--;
    bad.commitment =
        scheduler::CommitBinaryV1AggregationSchedule(bad);
    BOOST_CHECK(
        !scheduler::ValidateBinaryV1AggregationSchedule(
            manifest, bad, &why));

    BOOST_TEST_MESSAGE(
        "binary-v1 recursive scenario: leaves="
        << binary.relation_leaf_sites
        << " parents=" << binary.below_root_parent_sites
        << " exact_sites=" << scenario.exact_total_sites
        << " cap=2^" << scenario.union_bound_log2
        << " exact_bits="
        << scenario.exact_site_screen.all_query_work_bits
        << " cap_bits="
        << scenario.cap_screen.all_query_work_bits);
}

BOOST_AUTO_TEST_CASE(
    streaming_receipts_are_ordered_and_root_replay_fails)
{
    const auto manifest = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    const auto schedule =
        scheduler::BuildProductionAggregationSchedule(manifest);
    BOOST_REQUIRE(!schedule.commitment.IsNull());
    const uint256 root_a = Filled(101);
    const uint256 root_b = Filled(102);
    std::string why;

    uint64_t expected_ordinal{0};
    auto cursor_a =
        scheduler::BeginProductionAggregationExecution(
            schedule, root_a);
    const auto honest =
        [&](const scheduler::ParentWorkItem& work,
            std::string*) -> std::optional<
                scheduler::ParentReceipt> {
        BOOST_CHECK_EQUAL(
            work.parent_ordinal, expected_ordinal++);
        return Receipt(work);
    };
    BOOST_REQUIRE_MESSAGE(
        scheduler::ExecuteProductionAggregationPage(
            manifest, schedule, honest, 7, cursor_a, &why),
        why);
    BOOST_CHECK_EQUAL(cursor_a.next_parent_ordinal, 7U);
    BOOST_CHECK(!cursor_a.complete);

    const auto work_a =
        scheduler::ProductionAggregationParentWorkItem(
            schedule, root_a, 0, &why);
    const auto work_b =
        scheduler::ProductionAggregationParentWorkItem(
            schedule, root_b, 0, &why);
    BOOST_REQUIRE(work_a.has_value());
    BOOST_REQUIRE(work_b.has_value());
    BOOST_CHECK(work_a->seed != work_b->seed);
    const scheduler::ParentReceipt replayed = Receipt(*work_a);

    auto cursor_b =
        scheduler::BeginProductionAggregationExecution(
            schedule, root_b);
    const auto replay_callback =
        [&](const scheduler::ParentWorkItem&,
            std::string*) -> std::optional<
                scheduler::ParentReceipt> {
        return replayed;
    };
    BOOST_CHECK(
        !scheduler::ExecuteProductionAggregationPage(
            manifest, schedule, replay_callback, 1,
            cursor_b, &why));
    BOOST_CHECK_EQUAL(cursor_b.next_parent_ordinal, 0U);

    auto duplicate_cursor =
        scheduler::BeginProductionAggregationExecution(
            schedule, root_a);
    const scheduler::ParentReceipt first = Receipt(*work_a);
    const auto duplicate_callback =
        [&](const scheduler::ParentWorkItem&,
            std::string*) -> std::optional<
                scheduler::ParentReceipt> {
        return first;
    };
    BOOST_CHECK(
        !scheduler::ExecuteProductionAggregationPage(
            manifest, schedule, duplicate_callback, 2,
            duplicate_cursor, &why));
    BOOST_CHECK_EQUAL(
        duplicate_cursor.next_parent_ordinal, 1U);

    auto omitted_cursor =
        scheduler::BeginProductionAggregationExecution(
            schedule, root_a);
    omitted_cursor.next_parent_ordinal = 1;
    BOOST_CHECK(
        !scheduler::ExecuteProductionAggregationPage(
            manifest, schedule, honest, 1, omitted_cursor, &why));
}

BOOST_AUTO_TEST_CASE(structural_scheduler_does_not_claim_child_proofs)
{
    BOOST_CHECK(
        scheduler::
            kProductionAggregationStructuralSchedulerExecutable);
    BOOST_CHECK(
        !scheduler::
            kProductionAggregationCryptographicChildConsumptionReady);
}

// ===========================================================================
// PR-89: the aggregation tree cryptographically CONSUMES real child proofs.
//
// Every test below drives the SAME production scheduler
// (ExecuteProductionAggregationPage) that the structural tests above drive, but
// with the callback built by MakeCryptographicChildConsumingParentCallback.
// The receipt's parent_commitment is no longer derivable from the work item
// alone: it is a domain-separated hash of the work item AND the in-circuit
// parent statement h_nu, where h_nu is the AlgHash of the four children's full
// public IO sourced from the in-parent verifier's own terminal cells.  Without
// four accepted child proofs the commitment cannot be produced.
// ===========================================================================

/**
 * PROOF-LEVEL REJECTS.  Each mutation below is rejected by the REAL unmodified
 * air_quotient::AirQuotientVerify<Fp3, AirFriBackendAlg<Fp3>> — the FRI/AIR
 * verifier itself, not a witness-violation count — and that rejection
 * propagates: the consumption fails closed and the scheduler page aborts.
 *
 * The children are REAL RC Stage3 CoupledPermutation role C_rho proofs.
 */
BOOST_AUTO_TEST_CASE(
    tampered_real_child_proofs_are_rejected_by_the_real_fri_air_verifier)
{
    const RealChildren child = BuildRealRoleChild(0x51);
    BOOST_TEST_MESSAGE(
        "AGG_REAL_CHILD child_rows=" << child.cs.n_rows
        << " child_cols=" << child.cs.n_columns);

    const auto manifest = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    const auto schedule =
        scheduler::BuildProductionAggregationSchedule(manifest);
    const uint256 root = Filled(0x31);
    const uint64_t ordinal = FirstFullArityOrdinal(schedule, root);
    BOOST_REQUIRE(ordinal != UINT64_MAX);
    std::string why;
    const auto work =
        scheduler::ProductionAggregationParentWorkItem(
            schedule, root, ordinal, &why);
    BOOST_REQUIRE(work.has_value());
    BOOST_REQUIRE_EQUAL(work->child_count, 4U);

    // Every tamper is applied to slot 0 of an otherwise honest bundle.
    struct Case {
        const char* name;
        std::function<void(scheduler::ParentChildProofBundle&)> mutate;
    };
    auto& q0 = child.proof.batch.queries;
    BOOST_REQUIRE(!q0.empty());
    BOOST_REQUIRE(!q0[0].row.siblings.empty());
    BOOST_REQUIRE(!q0[0].steps.empty());
    BOOST_REQUIRE(!child.proof.batch.fold_challenges.empty());
    BOOST_REQUIRE(!child.proof.batch.evals_z1.empty());

    const std::vector<Case> cases{
        {"merkle_row_sibling",
         [](scheduler::ParentChildProofBundle& b) {
             b.child_proofs[0].batch.queries[0].row.siblings[0][0] =
                 gf::Add(
                     b.child_proofs[0].batch.queries[0].row.siblings[0][0],
                     gf::Fp{1});
         }},
        {"fri_fold_step_value",
         [](scheduler::ParentChildProofBundle& b) {
             auto& s = b.child_proofs[0].batch.queries[0].steps[0];
             s.even = gf::Add(s.even, gf::Fp3::One());
         }},
        {"fold_challenge_mismatch",
         [](scheduler::ParentChildProofBundle& b) {
             auto& fc = b.child_proofs[0].batch.fold_challenges[0];
             fc = gf::Add(fc, gf::Fp3::One());
         }},
        {"fri_final_value_remainder",
         [](scheduler::ParentChildProofBundle& b) {
             b.child_proofs[0].batch.final_value =
                 gf::Add(b.child_proofs[0].batch.final_value,
                         gf::Fp3::One());
         }},
        {"deep_ood_evaluation_quotient_identity",
         [](scheduler::ParentChildProofBundle& b) {
             b.child_proofs[0].batch.evals_z1[0] =
                 gf::Add(b.child_proofs[0].batch.evals_z1[0],
                         gf::Fp3::One());
         }},
        {"trace_binding_commitment",
         [](scheduler::ParentChildProofBundle& b) {
             uint256 t = b.child_proofs[0].trace_commit;
             *t.begin() = static_cast<unsigned char>(*t.begin() ^ 0x01);
             b.child_proofs[0].trace_commit = t;
         }},
    };

    uint32_t proof_level_rejects{0};
    for (const auto& c : cases) {
        auto bundle = Bundle(child);
        c.mutate(bundle);

        // (a) the real unmodified verifier rejects the tampered proof.
        std::string vwhy;
        const bool accepted =
            VerifyChildProof(bundle.child_cs, bundle.child_proofs[0],
                             bundle.child_fs_seed, &vwhy);
        BOOST_CHECK_MESSAGE(
            !accepted,
            std::string("tamper accepted by verifier: ") + c.name);
        if (accepted) continue;
        ++proof_level_rejects;
        BOOST_TEST_MESSAGE(
            std::string("AGG_PROOF_LEVEL_REJECT ") + c.name
            << " why=\"" << vwhy << "\"");

        // (b) consumption fails closed at stage 1, before any parent V_CS is
        //     built (so a bad child costs nothing to reject).
        const auto consumed =
            scheduler::ConsumeRealChildProofsForParent(*work, bundle);
        BOOST_CHECK(!consumed.valid);
        BOOST_CHECK_EQUAL(consumed.note,
                          "child_proof_rejected_by_verifier");
        BOOST_CHECK(!consumed.all_children_standalone_verified);
        BOOST_CHECK(consumed.parent_commitment.IsNull());
        BOOST_CHECK_EQUAL(consumed.parent_columns, 0U);

        // (c) the scheduler page aborts; the cursor does not advance.
        auto cursor =
            scheduler::BeginProductionAggregationExecution(schedule, root);
        cursor.next_parent_ordinal = 0;
        const auto source =
            [&](const scheduler::ParentWorkItem&,
                scheduler::ParentChildProofBundle& out,
                std::string*) {
                out = bundle;
                return true;
            };
        const auto callback =
            scheduler::MakeCryptographicChildConsumingParentCallback(
                source);
        std::string pwhy;
        BOOST_CHECK(!scheduler::ExecuteProductionAggregationPage(
            manifest, schedule, callback, 1, cursor, &pwhy));
        BOOST_CHECK_EQUAL(cursor.next_parent_ordinal, 0U);
    }
    BOOST_CHECK_GE(proof_level_rejects, 5U);

    // CROSS-SEED REPLAY (the cross-role / cross-block replay shape): an honest,
    // fully valid proof presented under a different Fiat-Shamir seed.  The
    // transcript no longer recomputes, so the real verifier rejects.
    {
        auto bundle = Bundle(child);
        bundle.child_fs_seed = Filled(0x52);
        std::string vwhy;
        BOOST_CHECK(!VerifyChildProof(
            bundle.child_cs, bundle.child_proofs[0],
            bundle.child_fs_seed, &vwhy));
        BOOST_TEST_MESSAGE(
            "AGG_PROOF_LEVEL_REJECT cross_seed_replay why=\"" << vwhy
            << "\"");
        const auto consumed =
            scheduler::ConsumeRealChildProofsForParent(*work, bundle);
        BOOST_CHECK(!consumed.valid);
        BOOST_CHECK_EQUAL(consumed.note,
                          "child_proof_rejected_by_verifier");
    }

    // NONZERO REMAINDER: a witness that does NOT satisfy C_rho, committed with
    // force_commit_on_inexact.  The quotient does not divide, and the real
    // verifier rejects the resulting proof.
    {
        auto bad_witness = child.witness;
        bad_witness[0][0] = gf::Add(bad_witness[0][0], gf::Fp3::One());
        BOOST_REQUIRE_GT(
            matmul::v4::rc::air_recurse::CountWitnessViolationsOnH(
                child.cs, bad_witness),
            0U);
        aq::AirProveOptions opt;
        opt.force_commit_on_inexact = true;
        const auto proved =
            aq::AirQuotientProve<gf::Fp3, AlgB3>(
                child.cs, bad_witness, child.fs_seed, opt);
        BOOST_REQUIRE(proved.ok);
        BOOST_CHECK(!proved.division_exact);
        std::string vwhy;
        BOOST_CHECK(!VerifyChildProof(
            child.cs, proved.proof, child.fs_seed, &vwhy));
        BOOST_TEST_MESSAGE(
            "AGG_PROOF_LEVEL_REJECT nonzero_remainder why=\"" << vwhy
            << "\"");
        auto bundle = Bundle(child);
        bundle.child_proofs[0] = proved.proof;
        const auto consumed =
            scheduler::ConsumeRealChildProofsForParent(*work, bundle);
        BOOST_CHECK(!consumed.valid);
        BOOST_CHECK_EQUAL(consumed.note,
                          "child_proof_rejected_by_verifier");
    }
}

/**
 * ACCEPT + BINDING.  A parent job is executed through the production scheduler
 * with the cryptographic callback: four real child FRI proofs are re-verified,
 * consumed in-AIR by the arity-4 parent V_CS, and the receipt is bound to the
 * in-circuit parent statement.
 *
 * This is a genuine 2-level, 4-child aggregation node (4 leaves -> 1 parent).
 */
BOOST_AUTO_TEST_CASE(
    parent_callback_cryptographically_consumes_four_real_child_proofs)
{
    const RealChildren child =
        RunHeavyRealChildren() ? BuildRealRoleChild(0x61)
                               : BuildToyChild(0x61);
    const auto manifest = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    const auto schedule =
        scheduler::BuildProductionAggregationSchedule(manifest);
    const uint256 root = Filled(0x41);
    const uint64_t ordinal = FirstFullArityOrdinal(schedule, root);
    BOOST_REQUIRE(ordinal != UINT64_MAX);
    std::string why;
    const auto work =
        scheduler::ProductionAggregationParentWorkItem(
            schedule, root, ordinal, &why);
    BOOST_REQUIRE(work.has_value());
    BOOST_REQUIRE_EQUAL(work->child_count, 4U);

    const auto bundle = Bundle(child);
    const auto consumed =
        scheduler::ConsumeRealChildProofsForParent(*work, bundle);
    BOOST_TEST_MESSAGE(
        "AGG_CONSUME real_children=" << RunHeavyRealChildren()
        << " child_cols=" << child.cs.n_columns
        << " vcs_cols=" << consumed.vcs_columns
        << " parent_cols=" << consumed.parent_columns
        << " parent_rows=" << consumed.parent_rows
        << " valid=" << consumed.valid
        << " violations=" << consumed.witness_violations
        << " note=\"" << consumed.note << "\"");
    BOOST_REQUIRE_MESSAGE(consumed.valid, consumed.note);

    BOOST_CHECK(consumed.all_children_standalone_verified);
    BOOST_CHECK_EQUAL(consumed.children_standalone_verified, 4U);
    BOOST_CHECK(consumed.all_children_verified_in_parent_air);
    BOOST_CHECK(
        consumed.terminal_lanes_sourced_from_in_parent_verifier);
    BOOST_CHECK(
        consumed.four_child_roots_sourced_from_verifier_outputs);
    BOOST_CHECK(consumed.parent_statement_equals_child_aggregation);
    BOOST_CHECK(consumed.self_similar_arity4_shape);
    BOOST_CHECK_EQUAL(consumed.witness_violations, 0U);
    BOOST_CHECK(!consumed.parent_statement.IsNull());
    BOOST_CHECK(!consumed.parent_commitment.IsNull());

    // GAP[8]: executable same-parent airq_lambda hosting may be true under P2
    // activation, but full recursion soundness (all kinds + parent FRI +
    // authority) remains fail-closed.
    if (rc::air_quotient::kAirChallengeP2Activated) {
        BOOST_CHECK(consumed.child_fiat_shamir_replayed_in_parent);
        BOOST_CHECK(consumed.recursion_soundness_admissible);
    } else {
        BOOST_CHECK(!consumed.child_fiat_shamir_replayed_in_parent);
        BOOST_CHECK(!consumed.recursion_soundness_admissible);
    }
    BOOST_CHECK(
        !scheduler::
            kProductionAggregationCryptographicChildConsumptionReady);

    // The commitment is NOT the structural work-item hash the old callback
    // returned; it is bound to the in-circuit parent statement.
    BOOST_CHECK(consumed.parent_commitment != ParentCommitment(*work));
    BOOST_CHECK(
        consumed.parent_commitment ==
        scheduler::CommitConsumedParentStatement(
            *work, consumed.parent_statement));

    // Drive the real scheduler with the cryptographic callback.  The cursor is
    // hash-chained from ordinal 0, so any prefix before the target ordinal is
    // walked structurally and only the target ordinal is consumed
    // cryptographically.
    auto cursor =
        scheduler::BeginProductionAggregationExecution(schedule, root);
    if (ordinal > 0) {
        const auto structural =
            [&](const scheduler::ParentWorkItem& w, std::string*)
            -> std::optional<scheduler::ParentReceipt> {
            return Receipt(w);
        };
        BOOST_REQUIRE(scheduler::ExecuteProductionAggregationPage(
            manifest, schedule, structural, ordinal, cursor, &why));
    }
    BOOST_REQUIRE_EQUAL(cursor.next_parent_ordinal, ordinal);

    std::vector<scheduler::CryptographicChildConsumption> trace;
    const auto source =
        [&](const scheduler::ParentWorkItem&,
            scheduler::ParentChildProofBundle& out, std::string*) {
            out = bundle;
            return true;
        };
    const auto callback =
        scheduler::MakeCryptographicChildConsumingParentCallback(
            source, &trace);
    const uint256 chain_before = cursor.receipt_chain;
    BOOST_REQUIRE_MESSAGE(
        scheduler::ExecuteProductionAggregationPage(
            manifest, schedule, callback, 1, cursor, &why),
        why);
    BOOST_CHECK_EQUAL(cursor.next_parent_ordinal, ordinal + 1);
    BOOST_CHECK(cursor.receipt_chain != chain_before);
    BOOST_REQUIRE_EQUAL(trace.size(), 1U);
    BOOST_CHECK(trace[0].valid);
    BOOST_CHECK(trace[0].parent_commitment ==
                consumed.parent_commitment);
    BOOST_CHECK_EQUAL(trace[0].parent_ordinal, ordinal);
}

/**
 * NODE BINDING.  The same four child proofs consumed at a different node
 * position yield a different parent statement, so a genuinely produced
 * commitment cannot be replayed at another site.  This is a property of the
 * in-circuit statement, not of the receipt hash: parent_statement itself
 * differs.
 */
BOOST_AUTO_TEST_CASE(
    consumed_parent_statement_is_bound_to_the_node_position)
{
    const RealChildren child =
        RunHeavyRealChildren() ? BuildRealRoleChild(0x71)
                               : BuildToyChild(0x71);
    const auto manifest = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    const auto schedule =
        scheduler::BuildProductionAggregationSchedule(manifest);
    const uint256 root = Filled(0x42);
    std::string why;

    uint64_t first = UINT64_MAX;
    uint64_t second = UINT64_MAX;
    for (uint64_t o = 0; o < schedule.below_root_parent_sites && o < 64;
         ++o) {
        const auto w =
            scheduler::ProductionAggregationParentWorkItem(
                schedule, root, o, &why);
        if (!w.has_value() || w->child_count != 4) continue;
        if (first == UINT64_MAX) first = o;
        else { second = o; break; }
    }
    BOOST_REQUIRE(first != UINT64_MAX);
    BOOST_REQUIRE(second != UINT64_MAX);

    const auto wa = scheduler::ProductionAggregationParentWorkItem(
        schedule, root, first, &why);
    const auto wb = scheduler::ProductionAggregationParentWorkItem(
        schedule, root, second, &why);
    BOOST_REQUIRE(wa.has_value() && wb.has_value());

    const auto ca =
        scheduler::ConsumeRealChildProofsForParent(*wa, Bundle(child));
    const auto cb =
        scheduler::ConsumeRealChildProofsForParent(*wb, Bundle(child));
    BOOST_REQUIRE_MESSAGE(ca.valid, ca.note);
    BOOST_REQUIRE_MESSAGE(cb.valid, cb.note);
    // The in-circuit statement itself differs (node context is absorbed).
    BOOST_CHECK(ca.parent_statement != cb.parent_statement);
    BOOST_CHECK(ca.parent_commitment != cb.parent_commitment);

    // Replaying node A's honest receipt AT NODE B is rejected by the
    // scheduler's receipt binding: walk the cursor structurally up to node B,
    // then present node A's genuine (commitment, binding) pair there.
    auto cursor =
        scheduler::BeginProductionAggregationExecution(schedule, root);
    const auto structural =
        [&](const scheduler::ParentWorkItem& w, std::string*)
        -> std::optional<scheduler::ParentReceipt> {
        return Receipt(w);
    };
    BOOST_REQUIRE(scheduler::ExecuteProductionAggregationPage(
        manifest, schedule, structural, second, cursor, &why));
    BOOST_REQUIRE_EQUAL(cursor.next_parent_ordinal, second);
    const auto replay =
        [&](const scheduler::ParentWorkItem&, std::string*)
        -> std::optional<scheduler::ParentReceipt> {
        scheduler::ParentReceipt r;
        r.work_seed = wa->seed;
        r.parent_commitment = ca.parent_commitment;
        r.binding = scheduler::CommitProductionAggregationReceipt(
            *wa, ca.parent_commitment);
        return r;
    };
    BOOST_CHECK(!scheduler::ExecuteProductionAggregationPage(
        manifest, schedule, replay, 1, cursor, &why));
    BOOST_CHECK_EQUAL(cursor.next_parent_ordinal, second);
}

/**
 * A WHOLE LEVEL OF THE TREE.  Four consecutive full-arity parent jobs are
 * executed through the production scheduler with the cryptographic callback.
 * Each node gets its OWN child constraint system and its OWN Fiat-Shamir seed,
 * so this is sixteen distinct real child FRI proofs reduced to four parents:
 * a genuine 16-leaf -> 4-parent level of the canonical arity-4 tree, with the
 * scheduler's hash chain binding all four consumed statements in order.
 *
 * A LEVEL is the deepest genuine composition available today.  Going one level
 * further (four parents -> one grandparent) requires the parent's own proof to
 * be admissible as a child, and the arity-4 parent V_CS is NOT a shape fixed
 * point: a 1-column child yields a 17108-column parent, so a parent-of-parents
 * V_CS is orders of magnitude beyond any backend cap.  That, not compute, is
 * what blocks the 341-node walk.
 */
BOOST_AUTO_TEST_CASE(
    a_full_level_of_four_parents_consumes_sixteen_real_child_proofs)
{
    const auto manifest = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    const auto schedule =
        scheduler::BuildProductionAggregationSchedule(manifest);
    const uint256 root = Filled(0x44);
    std::string why;

    // Four consecutive full-arity nodes starting at the first one.
    const uint64_t start = FirstFullArityOrdinal(schedule, root);
    BOOST_REQUIRE(start != UINT64_MAX);
    constexpr uint64_t kNodes = 4;
    std::vector<scheduler::ParentChildProofBundle> bundles;
    for (uint64_t j = 0; j < kNodes; ++j) {
        const auto w = scheduler::ProductionAggregationParentWorkItem(
            schedule, root, start + j, &why);
        BOOST_REQUIRE(w.has_value());
        BOOST_REQUIRE_EQUAL(w->child_count, 4U);
        // Distinct FS seed per node => distinct real child proofs.
        bundles.push_back(Bundle(BuildToyChild(
            static_cast<unsigned char>(0x90 + j))));
    }

    auto cursor =
        scheduler::BeginProductionAggregationExecution(schedule, root);
    if (start > 0) {
        const auto structural =
            [&](const scheduler::ParentWorkItem& w, std::string*)
            -> std::optional<scheduler::ParentReceipt> {
            return Receipt(w);
        };
        BOOST_REQUIRE(scheduler::ExecuteProductionAggregationPage(
            manifest, schedule, structural, start, cursor, &why));
    }

    std::vector<scheduler::CryptographicChildConsumption> trace;
    const auto source =
        [&](const scheduler::ParentWorkItem& w,
            scheduler::ParentChildProofBundle& out, std::string* swhy) {
            if (w.parent_ordinal < start ||
                w.parent_ordinal >= start + kNodes) {
                if (swhy != nullptr) *swhy = "no_children_for_ordinal";
                return false;
            }
            out = bundles[w.parent_ordinal - start];
            return true;
        };
    const auto callback =
        scheduler::MakeCryptographicChildConsumingParentCallback(
            source, &trace);
    const uint256 chain_before = cursor.receipt_chain;
    BOOST_REQUIRE_MESSAGE(
        scheduler::ExecuteProductionAggregationPage(
            manifest, schedule, callback, kNodes, cursor, &why),
        why);
    BOOST_CHECK_EQUAL(cursor.next_parent_ordinal, start + kNodes);
    BOOST_CHECK(cursor.receipt_chain != chain_before);
    BOOST_REQUIRE_EQUAL(trace.size(), kNodes);

    uint32_t consumed_children{0};
    for (uint64_t j = 0; j < kNodes; ++j) {
        BOOST_CHECK_MESSAGE(trace[j].valid, trace[j].note);
        BOOST_CHECK_EQUAL(trace[j].parent_ordinal, start + j);
        BOOST_CHECK_EQUAL(trace[j].children_standalone_verified, 4U);
        BOOST_CHECK(trace[j].all_children_verified_in_parent_air);
        BOOST_CHECK(trace[j].parent_statement_equals_child_aggregation);
        BOOST_CHECK_EQUAL(trace[j].witness_violations, 0U);
        BOOST_CHECK(!trace[j].parent_statement.IsNull());
        consumed_children += trace[j].children_standalone_verified;
        // Every node's statement is distinct: distinct children AND distinct
        // node context.
        for (uint64_t k = 0; k < j; ++k) {
            BOOST_CHECK(trace[j].parent_statement !=
                        trace[k].parent_statement);
        }
        // GAP[8] child_fs hosting (and thus recursion_soundness_admissible)
        // follows P2 activation; production Ready constexpr stays false.
        if (rc::air_quotient::kAirChallengeP2Activated) {
            BOOST_CHECK(trace[j].recursion_soundness_admissible);
        } else {
            BOOST_CHECK(!trace[j].recursion_soundness_admissible);
        }
    }
    BOOST_CHECK_EQUAL(consumed_children, 16U);
    BOOST_TEST_MESSAGE(
        "AGG_LEVEL nodes=" << kNodes
        << " consumed_child_proofs=" << consumed_children
        << " parent_cols=" << trace[0].parent_columns
        << " recursion_soundness_admissible=" << (rc::air_quotient::kAirChallengeP2Activated ? "true(P2)" : "false(GAP8)"));
}

/**
 * PARTIAL-ARITY NODES FAIL CLOSED.  A parent with fewer than four children is
 * an explicitly charged proof site that the arity-4 primitive cannot execute.
 * It is refused, never padded with a duplicated slot.
 */
BOOST_AUTO_TEST_CASE(partial_arity_parent_jobs_fail_closed)
{
    const RealChildren child = BuildToyChild(0x81);
    const auto manifest = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    const auto schedule =
        scheduler::BuildProductionAggregationSchedule(manifest);
    const uint256 root = Filled(0x43);
    std::string why;
    const uint64_t ordinal = FirstFullArityOrdinal(schedule, root);
    BOOST_REQUIRE(ordinal != UINT64_MAX);
    auto work = scheduler::ProductionAggregationParentWorkItem(
        schedule, root, ordinal, &why);
    BOOST_REQUIRE(work.has_value());
    work->child_count = 3;
    const auto consumed =
        scheduler::ConsumeRealChildProofsForParent(*work, Bundle(child));
    BOOST_CHECK(!consumed.valid);
    BOOST_CHECK_EQUAL(consumed.note,
                      "partial_arity_parent_not_consumable");
    BOOST_CHECK_EQUAL(consumed.children_standalone_verified, 0U);
}

BOOST_AUTO_TEST_SUITE_END()
