// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_constraint_bytecode.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <vector>

namespace rc = matmul::v4::rc;
namespace cb = rc::constraint_bytecode;
namespace gf = matmul::v4::rc::gkr_field;
using gf::Fp3;

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_constraint_bytecode_tests,
    BasicTestingSetup)

namespace {

// A canonical single-program table:
//   r0 = Current[0]; r1 = Constant(k); r2 = r0 * r1  (declared degree 1).
// Distinct `k` gives distinct canonical bytes and therefore distinct SHA256d
// and AlgHash commitments, exercising the real (no-collision) reject paths.
cb::ProgramTable MakeTable(uint64_t k)
{
    cb::Program program;
    program.role = rc::RCStage3RelationRole::EpisodeGemm;
    program.constraint_ordinal = 0;
    program.kind = rc::air_quotient::AirKind::kEverywhere;
    program.declared_degree = 1;
    program.current_width = 1;
    program.next_width = 0;

    cb::Instruction load;
    load.opcode = cb::Opcode::Current;
    load.lhs = 0;

    cb::Instruction constant;
    constant.opcode = cb::Opcode::Constant;
    constant.constant = gf::FromU64_3(k);

    cb::Instruction mul;
    mul.opcode = cb::Opcode::Mul;
    mul.lhs = 0;
    mul.rhs = 1;

    program.instructions = {load, constant, mul};

    cb::ProgramTable table;
    table.role = program.role;
    table.current_width = program.current_width;
    table.next_width = program.next_width;
    table.programs = {program};
    return table;
}

cb::CrossHashFacts Facts(
    bool valid, bool ext_h, bool rec_h, bool ext_rec,
    bool ext_sha, bool rec_alg)
{
    cb::CrossHashFacts facts;
    facts.inputs_valid = valid;
    facts.ext_differs_from_honest = ext_h;
    facts.rec_differs_from_honest = rec_h;
    facts.ext_differs_from_rec = ext_rec;
    facts.ext_sha_matches_honest = ext_sha;
    facts.rec_alg_matches_honest = rec_alg;
    return facts;
}

} // namespace

BOOST_AUTO_TEST_CASE(builder_tables_are_valid_and_distinct)
{
    const auto a = MakeTable(1);
    const auto b = MakeTable(2);
    std::string why;
    BOOST_REQUIRE_MESSAGE(cb::ValidateProgramTable(a, &why), why);
    BOOST_REQUIRE_MESSAGE(cb::ValidateProgramTable(b, &why), why);
    BOOST_CHECK(
        cb::CommitProgramTable(a) != cb::CommitProgramTable(b));
    const auto alg_a = cb::CommitProgramTableAlgHash(a);
    const auto alg_b = cb::CommitProgramTableAlgHash(b);
    BOOST_CHECK(alg_a != alg_b);
}

BOOST_AUTO_TEST_CASE(
    canonical_program_relocation_recommits_shifted_columns)
{
    const auto table = MakeTable(7);
    rc::air_quotient::AirConstraintSystem<Fp3>
        child;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            table, 8, child, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        child.constraints.size(), 1U);
    const uint256 child_root =
        child.constraints[0]
            .canonical_program_table_root;

    rc::air_quotient::AirConstraintSystem<Fp3>
        parent;
    parent.n_rows = 8;
    parent.n_columns = 3;
    cb::CanonicalRelocationReportV1 report;
    BOOST_REQUIRE_MESSAGE(
        cb::AppendRelocatedAirConstraintsV1(
            child, 2, parent, report, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        parent.constraints.size(), 1U);
    BOOST_CHECK_EQUAL(
        report.canonical_constraints_relocated,
        1U);
    BOOST_CHECK_EQUAL(
        report.native_constraints_shifted, 0U);
    BOOST_CHECK_EQUAL(
        report.canonical_tables_recommitted,
        1U);
    BOOST_CHECK(
        report.every_claimed_provenance_valid);
    BOOST_CHECK(report.exact_order_preserved);
    BOOST_CHECK(
        parent.constraints[0]
            .canonical_program_table_root !=
        child_root);
    BOOST_CHECK_EQUAL(
        parent.constraints[0]
            .canonical_program_ordinal,
        0U);
    BOOST_CHECK(
        parent.constraints[0]
            .canonical_program_table_wire !=
        nullptr);

    const std::vector<Fp3> child_row{
        gf::FromU64_3(3)};
    const std::vector<Fp3> parent_row{
        gf::FromU64_3(91),
        gf::FromU64_3(92),
        gf::FromU64_3(3)};
    const Fp3 expected =
        child.constraints[0].eval(
            child_row, {});
    BOOST_CHECK(
        gf::Eq(
            expected,
            parent.constraints[0].eval(
                parent_row, parent_row)));

    auto changed_prefix = parent_row;
    changed_prefix[0] =
        gf::FromU64_3(1);
    BOOST_CHECK(
        gf::Eq(
            expected,
            parent.constraints[0].eval(
                changed_prefix,
                changed_prefix)));
    auto changed_child = parent_row;
    changed_child[2] =
        gf::FromU64_3(4);
    BOOST_CHECK(
        !gf::Eq(
            expected,
            parent.constraints[0].eval(
                changed_child,
                changed_child)));

    auto partial = child;
    partial.constraints[0]
        .canonical_program_table_wire.reset();
    auto untouched = parent;
    const size_t before =
        untouched.constraints.size();
    BOOST_CHECK(
        !cb::AppendRelocatedAirConstraintsV1(
            partial, 2, untouched,
            report, &why));
    BOOST_CHECK_EQUAL(
        untouched.constraints.size(), before);
}

// The core of the reduction: over the ENTIRE boolean event space the hybrid
// lemma must hold, i.e. a binding failure always extracts a SHA256d or AlgHash
// collision. This exercises the accept/extraction branches that cannot be
// physically realized with real hashes.
BOOST_AUTO_TEST_CASE(classifier_exhaustive_lemma_holds)
{
    for (int mask = 0; mask < 64; ++mask) {
        const bool ext_h = mask & 1;
        const bool rec_h = mask & 2;
        const bool ext_rec = mask & 4;
        const bool ext_sha = mask & 8;
        const bool rec_alg = mask & 16;
        const bool valid = mask & 32;

        const auto c = cb::ClassifyCrossHashChannels(
            Facts(valid, ext_h, rec_h, ext_rec, ext_sha, rec_alg));

        // The machine-checked theorem: the reduction lemma is universally true.
        BOOST_CHECK(c.reduction_lemma_holds);

        // Exactly one differing pair among three tables is impossible.
        const int differs = int{ext_h} + int{rec_h} + int{ext_rec};
        const bool consistent = valid && differs != 1;
        BOOST_CHECK_EQUAL(c.facts_consistent, consistent);

        // A cross-channel disagreement always yields a collision (the lemma).
        if (c.cross_channel_disagreement) {
            BOOST_CHECK(consistent);
            BOOST_CHECK(
                c.sha256d_collision_extracted ||
                c.alg_hash_collision_extracted);
            BOOST_CHECK(
                c.channel != cb::CrossHashCollisionChannel::None);
            BOOST_CHECK_EQUAL(
                c.certified_floor_bits,
                cb::kCrossHashBindingFloorBits);
        }

        // A pair-binding failure is exactly "some channel collided".
        BOOST_CHECK_EQUAL(
            c.pair_binding_failure,
            consistent &&
                (c.sha256d_collision_extracted ||
                 c.alg_hash_collision_extracted));

        const bool any_collision =
            c.sha256d_collision_extracted ||
            c.alg_hash_collision_extracted;
        BOOST_CHECK_EQUAL(
            c.certified_floor_bits,
            any_collision ? cb::kCrossHashBindingFloorBits : 0U);
        BOOST_CHECK_EQUAL(
            c.channel == cb::CrossHashCollisionChannel::None,
            !any_collision);
    }
}

BOOST_AUTO_TEST_CASE(classifier_extracts_each_channel)
{
    // The task's canonical scenario: two DISTINCT tables (honest T1 and a
    // single substituted T2 = ext = rec) agree under BOTH commitments. This is
    // a pair-binding failure yielding collisions on BOTH channels, but not a
    // cross-channel disagreement (the same table is on both channels).
    {
        const auto c = cb::ClassifyCrossHashChannels(
            Facts(true, true, true, false, true, true));
        BOOST_CHECK(c.facts_consistent);
        BOOST_CHECK(c.pair_binding_failure);
        BOOST_CHECK(!c.cross_channel_disagreement);
        BOOST_CHECK(c.sha256d_collision_extracted);
        BOOST_CHECK(c.alg_hash_collision_extracted);
        BOOST_CHECK_EQUAL(
            static_cast<int>(c.channel),
            static_cast<int>(cb::CrossHashCollisionChannel::Both));
    }
    // Cross-channel disagreement, only the SHA256d channel broken
    // (ext != honest on the SHA path, rec == honest on the AlgHash path).
    {
        const auto c = cb::ClassifyCrossHashChannels(
            Facts(true, true, false, true, true, true));
        BOOST_CHECK(c.cross_channel_disagreement);
        BOOST_CHECK(c.pair_binding_failure);
        BOOST_CHECK(c.sha256d_collision_extracted);
        BOOST_CHECK(!c.alg_hash_collision_extracted);
        BOOST_CHECK_EQUAL(
            static_cast<int>(c.channel),
            static_cast<int>(
                cb::CrossHashCollisionChannel::Sha256d));
    }
    // Cross-channel disagreement, only the AlgHash channel broken
    // (rec != honest on the AlgHash path, ext == honest on the SHA path).
    {
        const auto c = cb::ClassifyCrossHashChannels(
            Facts(true, false, true, true, true, true));
        BOOST_CHECK(c.cross_channel_disagreement);
        BOOST_CHECK(c.pair_binding_failure);
        BOOST_CHECK(!c.sha256d_collision_extracted);
        BOOST_CHECK(c.alg_hash_collision_extracted);
        BOOST_CHECK_EQUAL(
            static_cast<int>(c.channel),
            static_cast<int>(
                cb::CrossHashCollisionChannel::AlgHash));
    }
    // Inconsistent witness (exactly one differing pair) is refused.
    {
        const auto c = cb::ClassifyCrossHashChannels(
            Facts(true, false, false, true, true, true));
        BOOST_CHECK(!c.facts_consistent);
        BOOST_CHECK(!c.pair_binding_failure);
        BOOST_CHECK(!c.cross_channel_disagreement);
        BOOST_CHECK(c.reduction_lemma_holds);
    }
}

BOOST_AUTO_TEST_CASE(extract_real_reject_identical_tables)
{
    cb::CrossHashCollisionWitness witness;
    witness.honest = MakeTable(7);
    witness.external_candidate = MakeTable(7);
    witness.recursive_candidate = MakeTable(7);

    const auto c = cb::ExtractCrossHashCollision(witness);
    BOOST_CHECK(c.facts_consistent);
    BOOST_CHECK(!c.pair_binding_failure);
    BOOST_CHECK(!c.cross_channel_disagreement);
    BOOST_CHECK(!c.sha256d_collision_extracted);
    BOOST_CHECK(!c.alg_hash_collision_extracted);
    BOOST_CHECK_EQUAL(
        static_cast<int>(c.channel),
        static_cast<int>(cb::CrossHashCollisionChannel::None));
    BOOST_CHECK_EQUAL(c.certified_floor_bits, 0U);
    BOOST_CHECK(c.reduction_lemma_holds);
}

BOOST_AUTO_TEST_CASE(extract_real_reject_distinct_without_hash_break)
{
    // Distinct candidate on the external channel, but real SHA256d/AlgHash do
    // not collide, so no binding failure can be asserted from real inputs.
    cb::CrossHashCollisionWitness witness;
    witness.honest = MakeTable(1);
    witness.external_candidate = MakeTable(2);
    witness.recursive_candidate = MakeTable(1);

    const auto c = cb::ExtractCrossHashCollision(witness);
    BOOST_CHECK(c.facts_consistent);
    BOOST_CHECK(!c.pair_binding_failure);
    BOOST_CHECK(!c.cross_channel_disagreement);
    BOOST_CHECK(!c.sha256d_collision_extracted);
    BOOST_CHECK(!c.alg_hash_collision_extracted);
    BOOST_CHECK_EQUAL(
        static_cast<int>(c.channel),
        static_cast<int>(cb::CrossHashCollisionChannel::None));
    BOOST_CHECK(c.reduction_lemma_holds);
}

BOOST_AUTO_TEST_CASE(extract_invalid_inputs_fail_closed)
{
    cb::CrossHashCollisionWitness witness;
    witness.honest = MakeTable(1);
    witness.external_candidate = MakeTable(2);
    // An empty program table fails ValidateProgramTable.
    witness.recursive_candidate = cb::ProgramTable{};

    const auto c = cb::ExtractCrossHashCollision(witness);
    BOOST_CHECK(!c.facts_consistent);
    BOOST_CHECK(!c.pair_binding_failure);
    BOOST_CHECK(!c.cross_channel_disagreement);
    BOOST_CHECK(!c.sha256d_collision_extracted);
    BOOST_CHECK(!c.alg_hash_collision_extracted);
    BOOST_CHECK(c.reduction_lemma_holds);
}

BOOST_AUTO_TEST_CASE(global_flag_stays_false)
{
    const auto status = cb::AssessCrossHashBindingReduction();
    BOOST_CHECK_EQUAL(status.version, 1U);
    BOOST_CHECK_EQUAL(status.sha256d_floor_bits, 128U);
    BOOST_CHECK_EQUAL(status.alg_hash_floor_bits, 128U);
    BOOST_CHECK_EQUAL(status.cross_hash_floor_bits, 128U);
    BOOST_CHECK(status.pointwise_hybrid_lemma_machine_checked);
    BOOST_CHECK(status.serialization_injective_on_valid_tables);
    BOOST_CHECK(status.alg_hash_preimage_injective);

    // The global-theorem blockers remain open.
    BOOST_CHECK(
        !status.accepted_proof_two_preimage_extractor_executable);
    BOOST_CHECK(!status.adaptive_fs_extraction_loss_proved);
    BOOST_CHECK(!status.pow_grinding_loss_accounted);
    BOOST_CHECK(!status.global_cross_hash_binding_proved);

    // The per-instance commitment pair still reports the flag false.
    const auto pair =
        cb::CommitProgramTableForExternalAndRecursiveUse(
            MakeTable(3));
    BOOST_CHECK(pair.same_canonical_serialization);
    BOOST_CHECK(!pair.cross_hash_collision_binding_proved);
}

BOOST_AUTO_TEST_SUITE_END()
