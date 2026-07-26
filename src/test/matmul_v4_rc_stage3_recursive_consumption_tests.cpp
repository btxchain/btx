// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_recursive_consumption.h>

#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <chrono>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;
namespace aq = matmul::v4::rc::air_quotient;
namespace gf = matmul::v4::rc::gkr_field;
namespace ar = matmul::v4::rc::air_recurse;
namespace consume = matmul::v4::rc::recursive_consumption;
namespace scheduler = matmul::v4::rc::aggregation_scheduler;
namespace ss = matmul::v4::rc::soundness_scenarios;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_recursive_consumption_tests,
    BasicTestingSetup)

namespace {

uint256 SeedByte(unsigned char value)
{
    uint256 out;
    std::fill(out.begin(), out.end(), value);
    return out;
}

aq::AirConstraintSystem<gf::Fp3> ToyChildCS()
{
    aq::AirConstraintSystem<gf::Fp3> out;
    out.n_rows = 2;
    out.n_columns = 1;
    out.preprocessed_pin_ood = true;
    return out;
}

ar::DualAlgAirProof ProveToy(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const uint256& seed,
    uint64_t a,
    uint64_t b)
{
    const std::vector<std::vector<gf::Fp3>> columns = {{
        gf::Fp3::FromFp(gf::FromU64(a)),
        gf::Fp3::FromFp(gf::FromU64(b))}};
    auto proved = aq::AirQuotientProve<
        gf::Fp3, ar::DualAlgB3>(cs, columns, seed, {});
    BOOST_REQUIRE_MESSAGE(
        proved.ok && proved.division_exact, proved.note);
    return proved.proof;
}

struct Fixture {
    ss::ProductionProofSiteManifest manifest;
    scheduler::ProductionAggregationSchedule schedule;
    uint256 root_seed;
    uint256 child_seed;
    aq::AirConstraintSystem<gf::Fp3> child_cs;
    std::vector<ar::DualAlgAirProof> children;
    consume::RecursiveParentArtifact artifact;
};

std::optional<uint64_t> FindParentOrdinalAtMost(
    const scheduler::ProductionAggregationSchedule& schedule,
    uint8_t max_children)
{
    uint64_t ordinal = 0;
    for (const auto& role : schedule.roles) {
        for (const auto& level : role.levels) {
            const uint8_t last_children = static_cast<uint8_t>(
                level.child_count -
                (level.parent_count - 1) * schedule.arity);
            if (last_children <= max_children) {
                return ordinal + level.parent_count - 1;
            }
            ordinal += level.parent_count;
        }
    }
    return std::nullopt;
}

Fixture BuildFixture(std::optional<uint64_t> requested_ordinal =
                         std::nullopt)
{
    Fixture out;
    out.manifest = ss::BuildProductionProofSiteManifest(
        ss::SelectedProductionProofSitePolicy());
    out.schedule =
        scheduler::BuildProductionAggregationSchedule(out.manifest);
    out.root_seed = SeedByte(0xa1);
    out.child_seed = SeedByte(0xb2);
    out.child_cs = ToyChildCS();
    std::string why;
    const uint64_t parent_ordinal =
        requested_ordinal.value_or(0);
    const auto work =
        scheduler::ProductionAggregationParentWorkItem(
            out.schedule, out.root_seed, parent_ordinal, &why);
    BOOST_REQUIRE_MESSAGE(work.has_value(), why);
    for (uint32_t i = 0; i < work->child_count; ++i) {
        out.children.push_back(ProveToy(
            out.child_cs, out.child_seed,
            2 * i + 1, 2 * i + 2));
    }
    out.artifact = consume::BuildRecursiveParentArtifact(
        out.manifest, out.schedule, out.root_seed, parent_ordinal,
        out.child_cs, out.children, out.child_seed);
    BOOST_REQUIRE_MESSAGE(out.artifact.valid, out.artifact.note);
    return out;
}

bool Verify(const Fixture& fixture,
            const consume::RecursiveParentArtifact& artifact,
            const uint256& root,
            std::string* why = nullptr)
{
    return consume::VerifyRecursiveParentArtifact(
        fixture.manifest, fixture.schedule, root,
        fixture.child_cs, artifact, why);
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_scheduler_work_consumes_real_v5_and_v6_proofs)
{
    static_assert(consume::kBoundedProofAwareReceiptExecutable);
    static_assert(
        consume::kFullWideCodecPreflightExecutable);
    static_assert(
        !consume::kFullWideVcsChildConsumptionExecutable);
    static_assert(
        !consume::kProductionRecursiveChildConsumptionReady);
    static_assert(
        !consume::kRecursiveConsumptionConsensusAuthority);

    const Fixture fixture = BuildFixture();
    std::string why;
    uint64_t verify_micros{0};
    BOOST_CHECK_MESSAGE(
        consume::VerifyRecursiveParentArtifact(
            fixture.manifest, fixture.schedule,
            fixture.root_seed, fixture.child_cs,
            fixture.artifact, &why, &verify_micros),
        why);
    BOOST_CHECK(!fixture.artifact.receipt.parent_commitment.IsNull());
    BOOST_CHECK(!fixture.artifact.receipt.binding.IsNull());
    BOOST_CHECK_EQUAL(
        fixture.artifact.source_children.size(),
        fixture.artifact.claimed_work.child_count);
    BOOST_CHECK(!fixture.artifact.full_vcs_families);
    auto cursor =
        scheduler::BeginProductionAggregationExecution(
            fixture.schedule, fixture.root_seed);
    const auto proof_callback =
        [&](const scheduler::ParentWorkItem& work,
            std::string*) -> std::optional<
                scheduler::ParentReceipt> {
        if (work != fixture.artifact.claimed_work) {
            return std::nullopt;
        }
        return fixture.artifact.receipt;
    };
    BOOST_REQUIRE_MESSAGE(
        scheduler::ExecuteProductionAggregationPage(
            fixture.manifest, fixture.schedule,
            proof_callback, 1, cursor, &why),
        why);
    BOOST_CHECK_EQUAL(cursor.next_parent_ordinal, 1U);
    BOOST_TEST_MESSAGE(
        "bounded scheduler recursive receipt: parent_prove_us="
        << fixture.artifact.parent_prove_micros
        << " v6_prove_us=" << fixture.artifact.v6_prove_micros
        << " verify_us=" << verify_micros
        << " children=" << fixture.artifact.source_children.size()
        << " parent_rows="
        << fixture.artifact.normalized_parent_rows
        << " parent_cols="
        << fixture.artifact.normalized_parent_columns
        << " parent_constraints="
        << fixture.artifact.normalized_parent_constraints
        << " parent_batch_bytes="
        << fixture.artifact.normalized_parent_batch_bytes
        << " parent_verify_us="
        << fixture.artifact.normalized_parent_verify_micros
        << " v6_rows=" << fixture.artifact.v6_rows
        << " v6_cols=" << fixture.artifact.v6_columns
        << " v6_constraints=" << fixture.artifact.v6_constraints
        << " v6_batch_bytes=" << fixture.artifact.v6_batch_bytes
        << " v6_verify_us="
        << fixture.artifact.v6_verify_micros);
}

BOOST_AUTO_TEST_CASE(
    exact_small_scheduler_node_fails_wide_codec_preflight_before_proving)
{
    const ss::ProductionProofSiteManifest manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const scheduler::ProductionAggregationSchedule schedule =
        scheduler::BuildProductionAggregationSchedule(manifest);
    const auto ordinal = FindParentOrdinalAtMost(
        schedule, consume::kFullWideLogicalChildCap);
    BOOST_REQUIRE(ordinal.has_value());

    Fixture fixture;
    fixture.manifest = manifest;
    fixture.schedule = schedule;
    fixture.root_seed = SeedByte(0xa1);
    fixture.child_seed = SeedByte(0xb2);
    fixture.child_cs = ToyChildCS();
    std::string why;
    const auto work =
        scheduler::ProductionAggregationParentWorkItem(
            schedule, fixture.root_seed, *ordinal, &why);
    BOOST_REQUIRE_MESSAGE(work.has_value(), why);
    BOOST_REQUIRE_LE(
        work->child_count,
        consume::kFullWideLogicalChildCap);
    for (uint32_t i = 0; i < work->child_count; ++i) {
        fixture.children.push_back(ProveToy(
            fixture.child_cs, fixture.child_seed,
            2 * i + 1, 2 * i + 2));
    }
    const consume::FullWideVcsPreflight preflight =
        consume::AssessFullWideVcsPreflight(
            fixture.child_cs, fixture.children,
            fixture.child_seed);
    BOOST_REQUIRE_MESSAGE(preflight.valid, preflight.note);
    BOOST_CHECK_EQUAL(
        preflight.logical_children, work->child_count);
    BOOST_CHECK_EQUAL(
        preflight.normalized_lanes,
        2 * work->child_count);
    BOOST_CHECK_GT(preflight.parent_constraints, 0U);
    BOOST_CHECK(preflight.backend_columns_supported);
    BOOST_CHECK(!preflight.proof_codec_supported);
    BOOST_CHECK(!preflight.self_similar_shape);
    BOOST_CHECK(!preflight.executable);
    BOOST_CHECK_GT(
        preflight.minimum_query_value_bytes_per_lane,
        preflight.codec_bytes_per_lane);

    BOOST_TEST_MESSAGE(
        std::dec
        << "full-wide scheduled parent rejected before proving: ordinal="
        << *ordinal
        << " children="
        << static_cast<uint32_t>(work->child_count)
        << " rows="
        << preflight.parent_rows
        << " cols="
        << preflight.parent_columns
        << " constraints="
        << preflight.parent_constraints
        << " minimum_lane_bytes="
        << preflight.minimum_query_value_bytes_per_lane
        << " codec_cap="
        << preflight.codec_bytes_per_lane);
}

BOOST_AUTO_TEST_CASE(
    valid_child_substitution_and_parent_substitution_fail)
{
    const Fixture fixture = BuildFixture();
    std::string why;

    // This is a different, independently valid proof under the same child
    // relation and seed. It is not the proof committed by the normalized
    // parent or the algebraic V6 transcript.
    auto child_substitution = fixture.artifact;
    child_substitution.source_children[0] =
        ProveToy(fixture.child_cs, fixture.child_seed, 91, 92);
    BOOST_CHECK(
        !Verify(fixture, child_substitution,
                fixture.root_seed, &why));

    Fixture other = fixture;
    other.root_seed = SeedByte(0xa2);
    other.artifact = consume::BuildRecursiveParentArtifact(
        other.manifest, other.schedule, other.root_seed, 0,
        other.child_cs, other.children, other.child_seed);
    BOOST_REQUIRE_MESSAGE(other.artifact.valid, other.artifact.note);
    auto parent_substitution = fixture.artifact;
    parent_substitution.normalized_parent =
        other.artifact.normalized_parent;
    BOOST_CHECK(
        !Verify(fixture, parent_substitution,
                fixture.root_seed, &why));
}

BOOST_AUTO_TEST_CASE(
    wrong_range_role_level_and_root_are_rejected)
{
    const Fixture fixture = BuildFixture();
    std::string why;

    auto range = fixture.artifact;
    ++range.claimed_work.first_child_site;
    BOOST_CHECK(!Verify(fixture, range, fixture.root_seed, &why));

    auto role = fixture.artifact;
    role.claimed_work.role =
        rc::RCStage3RelationRole::CompositionLink;
    BOOST_CHECK(!Verify(fixture, role, fixture.root_seed, &why));

    auto level = fixture.artifact;
    ++level.claimed_work.level;
    BOOST_CHECK(!Verify(fixture, level, fixture.root_seed, &why));

    BOOST_CHECK(
        !Verify(fixture, fixture.artifact, SeedByte(0xa3), &why));
}

BOOST_AUTO_TEST_CASE(
    transcript_and_v6_binding_mutations_are_rejected)
{
    const Fixture fixture = BuildFixture();
    std::string why;

    auto transcript = fixture.artifact;
    transcript.source_children[0]
        .batch.repeated.lane_child_binding[0].begin()[0] ^= 1U;
    BOOST_CHECK(
        !Verify(fixture, transcript, fixture.root_seed, &why));

    auto v6_proof = fixture.artifact;
    BOOST_REQUIRE(
        !v6_proof.v6_binding_proof.batch.queries.empty());
    BOOST_REQUIRE(
        !v6_proof.v6_binding_proof.batch.queries[0]
             .row.values.empty());
    v6_proof.v6_binding_proof.batch.queries[0]
        .row.values[0] =
        gf::Add(
            v6_proof.v6_binding_proof.batch.queries[0]
                .row.values[0],
            gf::Fp3::One());
    BOOST_CHECK(
        !Verify(fixture, v6_proof, fixture.root_seed, &why));

    auto receipt = fixture.artifact;
    receipt.receipt.binding.begin()[0] ^= 1U;
    BOOST_CHECK(
        !Verify(fixture, receipt, fixture.root_seed, &why));
}

BOOST_AUTO_TEST_SUITE_END()
