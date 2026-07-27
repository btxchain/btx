// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>
#include <matmul/matmul_v4_rc_stage3_relation_closure.h>

#include <algorithm>

namespace rc = matmul::v4::rc;
namespace ut = rc::universal_topology;
namespace ss = rc::soundness_scenarios;
namespace sch = rc::aggregation_scheduler;
namespace cb = rc::constraint_bytecode;
namespace aq = rc::air_quotient;
namespace gf = rc::gkr_field;
using gf::Fp3;

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_production_family_programs_tests)

namespace {

Fp3 U(uint64_t value) { return gf::FromU64_3(value); }

/** Same structural stub the topology tests use for the aggregation
 * verifiers; those are out of this lane's scope (universal_parent_verifier /
 * normalized_root_verifier), so both stay the pre-existing placeholder. */
cb::ProgramTable OneColumnProgram(rc::RCStage3RelationRole role)
{
    cb::ProgramTable table;
    table.role = role;
    table.current_width = 1;
    table.next_width = 1;
    cb::Program program;
    program.role = role;
    program.kind = aq::AirKind::kEverywhere;
    program.declared_degree = 1;
    program.current_width = 1;
    program.next_width = 1;
    program.instructions.push_back(
        {cb::Opcode::Current, 0, 0, Fp3::Zero()});
    table.programs.push_back(std::move(program));
    BOOST_REQUIRE(cb::ValidateProgramTable(table));
    return table;
}

size_t FindFamilyIndex(
    const ss::ProductionProofSiteManifest& manifest,
    ss::ProductionProofSiteKind kind)
{
    const auto it = std::find_if(
        manifest.entries.begin(), manifest.entries.end(),
        [kind](const ss::ProductionProofSiteEntry& e) {
            return e.kind == kind;
        });
    BOOST_REQUIRE(it != manifest.entries.end());
    return static_cast<size_t>(it - manifest.entries.begin());
}

std::vector<Fp3> EvaluateAll(
    const cb::ProgramTable& table,
    const std::vector<Fp3>& current,
    const std::vector<Fp3>& next)
{
    std::vector<Fp3> results;
    results.reserve(table.programs.size());
    for (const auto& program : table.programs) {
        Fp3 value;
        BOOST_REQUIRE(cb::EvaluateProgram(program, current, next, value));
        results.push_back(value);
    }
    return results;
}

bool AllZero(const std::vector<Fp3>& values)
{
    return std::all_of(
        values.begin(), values.end(),
        [](const Fp3& v) { return gf::IsZero(v); });
}

bool AnyNonzero(const std::vector<Fp3>& values)
{
    return std::any_of(
        values.begin(), values.end(),
        [](const Fp3& v) { return !gf::IsZero(v); });
}

} // namespace

BOOST_AUTO_TEST_CASE(
    real_family_programs_are_wired_and_stubs_stay_honestly_incomplete)
{
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto sources =
        ut::BuildProductionFamilyProgramSourcesV1(manifest);
    BOOST_REQUIRE_EQUAL(sources.size(), manifest.entries.size());

    const size_t builder_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeBuilderCounterXof);
    const auto& builder = sources[builder_idx];
    BOOST_CHECK(
        builder.role ==
        rc::RCStage3RelationRole::EpisodeDeterministicBuilder);
    BOOST_CHECK_EQUAL(builder.program.current_width, 6U);
    BOOST_CHECK_EQUAL(builder.program.programs.size(), 5U);
    BOOST_REQUIRE_EQUAL(builder.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        builder.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeBuilderTrace));
    BOOST_CHECK(builder.semantic_relation_complete);

    const size_t digest_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeDigestSha256d);
    const auto& digest = sources[digest_idx];
    BOOST_CHECK(digest.role == rc::RCStage3RelationRole::EpisodeDigest);
    BOOST_CHECK_EQUAL(digest.program.current_width, 12U);
    BOOST_CHECK_EQUAL(digest.program.programs.size(), 14U);
    BOOST_REQUIRE_EQUAL(digest.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        digest.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeDigestPow));
    BOOST_CHECK(digest.semantic_relation_complete);

    const size_t tile_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeTileTreeSha256d);
    const auto& tile = sources[tile_idx];
    BOOST_CHECK(tile.role == rc::RCStage3RelationRole::EpisodeTileTree);
    BOOST_CHECK_EQUAL(tile.program.current_width, 15U);
    BOOST_CHECK_EQUAL(tile.program.programs.size(), 16U);
    BOOST_REQUIRE_EQUAL(tile.semantic_endpoints.size(), 1U);
    BOOST_CHECK_EQUAL(
        tile.semantic_endpoints[0],
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeTileTreeStream));
    BOOST_CHECK(tile.semantic_relation_complete);

    // A site this session did not reach stays an honest, INCOMPLETE stub:
    // one column, one constraint, no endpoint claim -- not "complete" the way
    // the *_tests.cpp OneColumnProgram helper would mark it.
    const size_t untouched_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeGemmSumcheck);
    const auto& untouched = sources[untouched_idx];
    BOOST_CHECK_EQUAL(untouched.program.current_width, 1U);
    BOOST_CHECK_EQUAL(untouched.program.programs.size(), 1U);
    BOOST_CHECK(untouched.semantic_endpoints.empty());
    BOOST_CHECK(!untouched.semantic_relation_complete);

    const auto status =
        ut::AssessProductionFamilyProgramMigrationV1(sources);
    BOOST_CHECK_EQUAL(
        status.families_total,
        static_cast<uint32_t>(manifest.entries.size()));
    BOOST_CHECK_EQUAL(status.families_real, 3U);
    BOOST_CHECK_EQUAL(status.roles_with_real_program, 3U);
    BOOST_CHECK_EQUAL(status.roles_total, 14U);
    const std::vector<rc::RCStage3RelationRole> expected_roles{
        rc::RCStage3RelationRole::EpisodeDeterministicBuilder,
        rc::RCStage3RelationRole::EpisodeTileTree,
        rc::RCStage3RelationRole::EpisodeDigest};
    BOOST_CHECK(status.real_roles == expected_roles);
    const std::vector<uint16_t> expected_endpoints{
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeBuilderTrace),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeTileTreeStream),
        static_cast<uint16_t>(
            rc::RCStage3RelationEndpoint::EpisodeDigestPow)};
    auto sorted_expected = expected_endpoints;
    std::sort(sorted_expected.begin(), sorted_expected.end());
    BOOST_CHECK(status.real_endpoints == sorted_expected);
}

BOOST_AUTO_TEST_CASE(
    production_registry_accepts_real_families_and_stays_honestly_incomplete)
{
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto schedule =
        sch::BuildProductionAggregationSchedule(manifest);
    const auto sources = ut::BuildProductionFamilyProgramSourcesV1(manifest);
    const auto verifier =
        OneColumnProgram(rc::RCStage3RelationRole::CompositionLink);

    const auto registry = ut::BuildProductionProgramRegistryV1(
        manifest, schedule, sources, verifier, verifier);
    BOOST_REQUIRE(!registry.external_registry_commitment.IsNull());
    // Honest: only 3 of 28 families are real, so the registry-wide
    // completeness flag must stay false. A registry that flips this true
    // from stub-only or partially-real families would be exactly the
    // structural-only theatre this module exists to avoid.
    BOOST_CHECK(!registry.every_semantic_relation_complete);
    BOOST_CHECK(ut::ValidateProductionProgramRegistryV1(
        manifest, schedule, registry,
        registry.external_registry_commitment,
        registry.recursive_registry_commitment));

    const size_t builder_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeBuilderCounterXof);
    const auto& builder_entry = registry.families[builder_idx];
    BOOST_CHECK_EQUAL(builder_entry.maximum_columns, 6U);
    BOOST_CHECK_EQUAL(builder_entry.constraint_count, 5U);
    BOOST_CHECK_GE(builder_entry.maximum_constraint_degree, 2U);
    BOOST_CHECK(builder_entry.semantic_relation_complete);

    const size_t stub_idx = FindFamilyIndex(
        manifest, ss::ProductionProofSiteKind::EpisodeGemmSumcheck);
    const auto& stub_entry = registry.families[stub_idx];
    BOOST_CHECK_EQUAL(stub_entry.maximum_columns, 1U);
    BOOST_CHECK_EQUAL(stub_entry.constraint_count, 1U);
    BOOST_CHECK_EQUAL(stub_entry.maximum_constraint_degree, 1U);
    BOOST_CHECK(!stub_entry.semantic_relation_complete);

    // Non-vacuity of the wiring itself: tampering the real program's bytes
    // (not merely the stub) must change BOTH root commitments the registry
    // is pinned by, proving the ProgramTable content actually flows into
    // consensus-facing commitments rather than being decorative.
    auto tampered_sources = sources;
    auto& load = *std::find_if(
        tampered_sources[builder_idx]
            .program.programs.back()
            .instructions.begin(),
        tampered_sources[builder_idx]
            .program.programs.back()
            .instructions.end(),
        [](const cb::Instruction& instr) {
            return instr.opcode == cb::Opcode::Current;
        });
    load.lhs = (load.lhs + 1) %
        tampered_sources[builder_idx].program.current_width;
    const auto tampered_registry = ut::BuildProductionProgramRegistryV1(
        manifest, schedule, tampered_sources, verifier, verifier);
    BOOST_REQUIRE(!tampered_registry.external_registry_commitment.IsNull());
    BOOST_CHECK(
        tampered_registry.external_registry_commitment !=
        registry.external_registry_commitment);
    BOOST_CHECK(
        tampered_registry.recursive_registry_commitment !=
        registry.recursive_registry_commitment);
    BOOST_CHECK(!ut::ValidateProductionProgramRegistryV1(
        manifest, schedule, tampered_registry,
        registry.external_registry_commitment,
        registry.recursive_registry_commitment));
}

BOOST_AUTO_TEST_CASE(
    real_family_programs_have_satisfying_witnesses_and_reject_tampering)
{
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto sources = ut::BuildProductionFamilyProgramSourcesV1(manifest);

    // --- EpisodeDeterministicBuilder: mantissa/scale dequant, 6 columns. ---
    {
        const size_t idx = FindFamilyIndex(
            manifest, ss::ProductionProofSiteKind::EpisodeBuilderCounterXof);
        const auto& table = sources[idx].program;
        std::vector<Fp3> row{
            gf::FromSigned3(-7), U(2), U(0), U(1), U(4),
            gf::FromSigned3(-28)};
        const std::vector<Fp3> next(6, Fp3::Zero());
        BOOST_CHECK(AllZero(EvaluateAll(table, row, next)));
        auto tampered = row;
        tampered[5] = gf::FromSigned3(-27); // wrong output
        BOOST_CHECK(AnyNonzero(EvaluateAll(table, tampered, next)));
    }

    // --- EpisodeDigest: PoW borrow-chain, 12 columns, single-row slice
    // (first row: borrow=0; not the last row: borrow_out=0). Chosen so
    // target - digest - borrow + 256*borrow_out == the 8-bit difference:
    // 9 - 5 - 0 + 0 == 4 == 0b0000_0100.
    {
        const size_t idx = FindFamilyIndex(
            manifest, ss::ProductionProofSiteKind::EpisodeDigestSha256d);
        const auto& table = sources[idx].program;
        std::vector<Fp3> row(12, Fp3::Zero());
        row[0] = U(5);  // digest byte
        row[1] = U(9);  // target byte
        row[2] = U(0);  // borrow (first row)
        row[3] = U(0);  // borrow_out (not last row)
        row[4 + 2] = Fp3::One(); // difference = 4 -> bit 2 set
        const std::vector<Fp3> next(12, Fp3::Zero()); // next borrow == 0
        BOOST_CHECK(AllZero(EvaluateAll(table, row, next)));
        auto tampered = row;
        tampered[1] = U(10); // wrong target: difference no longer matches
        BOOST_CHECK(AnyNonzero(EvaluateAll(table, tampered, next)));
    }

    // --- EpisodeTileTree: signed-byte <-> octet bridge, 15 columns. ---
    {
        const size_t idx = FindFamilyIndex(
            manifest, ss::ProductionProofSiteKind::EpisodeTileTreeSha256d);
        const auto& table = sources[idx].program;
        std::vector<Fp3> row(15, Fp3::Zero());
        row[0] = Fp3::One();
        row[1] = U(9);
        row[2] = Fp3::FromFp(gf::FromSigned(-91));
        row[3] = Fp3::FromFp(gf::FromSigned(-91));
        row[4] = Fp3::FromFp(gf::FromSigned(-91));
        row[5] = U(0xa5);
        row[6] = Fp3::One();
        for (uint32_t bit = 0; bit < 8; ++bit) {
            row[7 + bit] = U((0xa5U >> bit) & 1U);
        }
        const std::vector<Fp3> next(15, Fp3::Zero());
        BOOST_CHECK(AllZero(EvaluateAll(table, row, next)));
        auto tampered = row;
        tampered[6] = Fp3::Zero(); // wrong sign bit
        BOOST_CHECK(AnyNonzero(EvaluateAll(table, tampered, next)));
    }
}

BOOST_AUTO_TEST_SUITE_END()
