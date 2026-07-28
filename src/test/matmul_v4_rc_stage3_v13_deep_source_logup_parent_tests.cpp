// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_backend.h>
#include <matmul/matmul_v4_rc_stage3_v13_complete_child_parent.h>
#include <matmul/matmul_v4_rc_stage3_v13_deep_source_logup_parent.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdlib>
#include <numeric>
#include <string>
#include <vector>

namespace parent =
    matmul::v4::rc::
        stage3_v13_deep_source_logup_parent;
namespace aq = matmul::v4::rc::air_quotient;
namespace backend =
    matmul::v4::rc::stage3_multirow_v11_backend;
namespace cb = matmul::v4::rc::constraint_bytecode;
namespace complete =
    matmul::v4::rc::
        stage3_v13_complete_child_parent;
namespace composer =
    matmul::v4::rc::stage3_air_parent_composer;
namespace dvm =
    matmul::v4::rc::stage3_multirow_v11_deep_vm;
namespace gf = matmul::v4::rc::gkr_field;
namespace mf =
    matmul::v4::rc::
        stage3_multirow_v11_merkle_fold;
namespace merkle =
    matmul::v4::rc::
        stage3_v13_merkle_fold_parent;
namespace proofabi =
    matmul::v4::rc::stage3_multirow_v11_proof_abi;
namespace quotient =
    matmul::v4::rc::
        stage3_v13_quotient_tape_parent;
namespace rv =
    matmul::v4::rc::stage3_multirow_v11_recursive_verifier;
namespace tape =
    matmul::v4::rc::stage3_multirow_v13_proof_tape_air;

namespace {

uint256 Seed(uint8_t tag)
{
    uint256 out;
    for (uint32_t index = 0;
         index < out.size(); ++index) {
        out.begin()[index] =
            static_cast<unsigned char>(
                tag + 19 * index);
    }
    if (out.IsNull()) out.begin()[0] = 1;
    return out;
}

inline constexpr uint32_t kChildRows = 256;

aq::AirConstraintSystem<gf::Fp3> TransitionAir()
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = kChildRows;
    cs.n_columns = 2;
    cs.constraints.push_back({
        "test.v13_deep_stream.counter",
        aq::AirKind::kTransition, 1,
        [](const auto& current,
           const auto& next) {
            return gf::Sub(
                gf::Sub(
                    next[0], current[0]),
                gf::Fp3::One());
        }});
    cs.constraints.push_back({
        "test.v13_deep_stream.double",
        aq::AirKind::kEverywhere, 1,
        [](const auto& current,
           const auto&) {
            return gf::Sub(
                current[1],
                gf::Mul(
                    current[0],
                    gf::Fp3::FromFp(2)));
        }});
    return cs;
}

std::vector<std::vector<gf::Fp3>>
TransitionTrace()
{
    std::vector<std::vector<gf::Fp3>> out(
        2, std::vector<gf::Fp3>(kChildRows));
    for (uint32_t row = 0;
         row < kChildRows; ++row) {
        out[0][row] =
            gf::Fp3::FromFp(row + 9);
        out[1][row] =
            gf::Mul(
                out[0][row],
                gf::Fp3::FromFp(2));
    }
    return out;
}

cb::Instruction Load(
    cb::Opcode opcode, uint32_t column)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = column;
    return out;
}

cb::Instruction Constant(uint64_t value)
{
    cb::Instruction out;
    out.opcode = cb::Opcode::Constant;
    out.constant = gf::Fp3::FromFp(value);
    return out;
}

cb::Instruction Binary(
    cb::Opcode opcode,
    uint32_t lhs,
    uint32_t rhs)
{
    cb::Instruction out;
    out.opcode = opcode;
    out.lhs = lhs;
    out.rhs = rhs;
    return out;
}

cb::ProgramTable TransitionPrograms()
{
    cb::Program transition;
    transition.role =
        matmul::v4::rc::
            RCStage3RelationRole::EpisodeGemm;
    transition.constraint_ordinal = 0;
    transition.kind =
        aq::AirKind::kTransition;
    transition.declared_degree = 1;
    transition.current_width = 2;
    transition.next_width = 2;
    transition.instructions = {
        Load(cb::Opcode::Next, 0),
        Load(cb::Opcode::Current, 0),
        Binary(cb::Opcode::Sub, 0, 1),
        Constant(1),
        Binary(cb::Opcode::Sub, 2, 3),
    };

    cb::Program everywhere;
    everywhere.role =
        matmul::v4::rc::
            RCStage3RelationRole::EpisodeGemm;
    everywhere.constraint_ordinal = 1;
    everywhere.kind =
        aq::AirKind::kEverywhere;
    everywhere.declared_degree = 1;
    everywhere.current_width = 2;
    everywhere.next_width = 2;
    everywhere.instructions = {
        Load(cb::Opcode::Current, 1),
        Load(cb::Opcode::Current, 0),
        Constant(2),
        Binary(cb::Opcode::Mul, 1, 2),
        Binary(cb::Opcode::Sub, 0, 3),
    };
    cb::ProgramTable out;
    out.role =
        matmul::v4::rc::
            RCStage3RelationRole::EpisodeGemm;
    out.current_width = 2;
    out.next_width = 2;
    out.programs = {transition, everywhere};
    return out;
}

struct FullFixture {
    uint256 seed{Seed(0x51)};
    aq::AirConstraintSystem<gf::Fp3>
        child_cs{TransitionAir()};
    std::vector<std::vector<gf::Fp3>>
        child_columns{TransitionTrace()};
    std::vector<uint32_t> base_columns{0};
    backend::AirProveResultV1 proved;
    backend::p2::ReceiptV1 transcript;
    cb::ProgramTable child_program{
        TransitionPrograms()};
    matmul::v4::rc::alg_hash::Digest
        child_program_root{};
    dvm::ProductV1 deep_product;
    std::vector<uint32_t> canonical_v13_words;
    tape::PublicShapeV1 shape{};
    tape::PublicBindingV1 binding{};
    tape::ProductV1 tape_product;

    FullFixture()
    {
        proved =
            backend::ProveAirQuotientV1(
                child_cs, child_columns,
                base_columns, seed);
        BOOST_REQUIRE_MESSAGE(
            proved.ok, proved.note);
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            backend::VerifyV1(
                proved.proximity.proof,
                &transcript, &why),
            why);
        BOOST_REQUIRE_MESSAGE(
            cb::ValidateProgramTable(
                child_program, &why),
            why);
        child_program_root =
            cb::CommitProgramTableAlgHash(
                child_program);
        deep_product =
            dvm::BuildProductV1(
                proved.proximity.proof,
                transcript,
                child_program,
                child_program_root,
                0, 1);
        BOOST_REQUIRE_MESSAGE(
            deep_product.valid,
            deep_product.note);
        auto envelope =
            proved.proximity.proof.envelope;
        envelope.split.version =
            aq::
                kAirQuotientSplitRapRowsSafeProofVersionV2;
        envelope.split.batch.version =
            matmul::v4::rc::
                kRCFri3AlgMultiRowSafeQ192K2ProofVersionV13;
        BOOST_REQUIRE_MESSAGE(
            proofabi::EncodeCanonicalSafeV13(
                envelope, canonical_v13_words,
                nullptr, &why),
            why);
        for (uint32_t word = 0;
             word <
                 envelope.public_fs_seed.size();
             ++word) {
            for (uint32_t byte = 0;
                 byte < 4; ++byte) {
                binding.public_fs_seed
                    .begin()[4 * word + byte] =
                    static_cast<unsigned char>(
                        envelope
                            .public_fs_seed[word] >>
                        (8 * byte));
            }
        }
        shape.trace_rows = child_cs.n_rows;
        shape.trace_columns = child_cs.n_columns;
        shape.quotient_len =
            envelope.split.batch
                .column_len.back();
        shape.n_coeffs =
            envelope.split.batch.n_coeffs;
        shape.base_column_indices =
            base_columns;
        binding.program_root = Seed(0x11);
        binding.statement_root = Seed(0x22);
        binding.proof_wire_root = Seed(0x33);
        binding.tape_root =
            tape::ComputeTapeRootV1(
                shape, binding,
                canonical_v13_words, &why);
        BOOST_REQUIRE_MESSAGE(
            binding.tape_root !=
                matmul::v4::rc::
                    alg_hash::Digest{},
            why);
        tape_product =
            tape::BuildProductV1(
                shape, binding,
                canonical_v13_words);
        BOOST_REQUIRE_MESSAGE(
            tape_product.valid,
            tape_product.note);
    }
};

size_t SourceValueWord(uint32_t address)
{
    return tape::kHeaderRecordsV1 +
        size_t{address} * 2 + 1;
}

aq::AirQuotientSplitRapRowsProveResult Prove(
    const parent::ProductV1& product,
    const uint256& seed,
    bool force_inexact)
{
    aq::AirProveOptions options;
    options.force_commit_on_inexact =
        force_inexact;
    return
        aq::AirQuotientProveRowsSplitRapSafeV2(
            product.cs, product.columns,
            product.r0_base_column_indices,
            seed, options,
            force_inexact
                ? nullptr
                : &product.r0_session);
}

aq::AirQuotientSplitRapRowsProveResult Prove(
    const complete::ProductV1& product,
    const uint256& seed,
    bool force_inexact)
{
    aq::AirProveOptions options;
    options.force_commit_on_inexact =
        force_inexact;
    return
        aq::AirQuotientProveRowsSplitRapSafeV2(
            product.cs, product.columns,
            product.r0_base_column_indices,
            seed, options,
            force_inexact
                ? nullptr
                : &product.r0_session);
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_deep_source_logup_parent_tests)

BOOST_AUTO_TEST_CASE(
    public_merkle_fold_scheduler_excludes_proof_values)
{
    tape::PublicShapeV1 shape;
    shape.trace_rows = 2;
    shape.trace_columns = 2;
    shape.quotient_len = 2;
    shape.n_coeffs = 2;
    shape.base_column_indices = {0};
    tape::PublicBindingV1 binding;
    binding.program_root = Seed(0x31);
    binding.statement_root = Seed(0x32);
    binding.public_fs_seed = Seed(0x33);
    binding.proof_wire_root = Seed(0x34);
    binding.tape_root = {1, 2, 3, 4};
    const rv::QueryRangeV1 range{
        .ordinal = 0,
        .first_query = 0,
        .query_count = 1,
    };
    merkle::PublicConstraintSystemsV1 first;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        merkle::BuildPublicConstraintSystemsV1(
            shape, binding, range,
            first, &why),
        why);
    BOOST_CHECK(first.valid);
    BOOST_CHECK(
        first.source_schedule_regenerated);
    BOOST_CHECK(
        first.task_schedule_regenerated);
    BOOST_CHECK(
        first.transformed_systems_rebuilt);
    BOOST_CHECK(first.proof_values_excluded);
    BOOST_CHECK_EQUAL(
        first.structural_hash_tasks,
        first.canonical_plan.hash_real_rows);
    BOOST_CHECK_EQUAL(
        first.structural_fold_rows,
        first.canonical_plan.fold_real_rows);

    // Public roots bind the tape but cannot change the verifier's callback,
    // row or preprocessed schedule.  They are deliberately absent from the
    // Merkle/fold structural constructor after source-key regeneration.
    auto second_binding = binding;
    second_binding.program_root =
        Seed(0xa1);
    second_binding.statement_root =
        Seed(0xa2);
    second_binding.proof_wire_root =
        Seed(0xa3);
    merkle::PublicConstraintSystemsV1 second;
    BOOST_REQUIRE_MESSAGE(
        merkle::BuildPublicConstraintSystemsV1(
            shape, second_binding,
            range, second, &why),
        why);
    BOOST_CHECK_EQUAL(
        first.hash_cs.n_rows,
        second.hash_cs.n_rows);
    BOOST_CHECK_EQUAL(
        first.hash_cs.n_columns,
        second.hash_cs.n_columns);
    BOOST_CHECK_EQUAL(
        first.hash_cs.constraints.size(),
        second.hash_cs.constraints.size());
    BOOST_CHECK_EQUAL(
        first.hash_cs.preprocessed.size(),
        second.hash_cs.preprocessed.size());
    BOOST_CHECK_EQUAL(
        first.fold_cs.n_rows,
        second.fold_cs.n_rows);
    BOOST_CHECK_EQUAL(
        first.fold_cs.n_columns,
        second.fold_cs.n_columns);
    BOOST_CHECK_EQUAL(
        first.fold_cs.constraints.size(),
        second.fold_cs.constraints.size());
    BOOST_CHECK_EQUAL(
        first.fold_cs.preprocessed.size(),
        second.fold_cs.preprocessed.size());
}

BOOST_AUTO_TEST_CASE(
    public_quotient_and_deep_base_rebuild_without_proof_values)
{
    tape::PublicShapeV1 shape;
    shape.trace_rows = 256;
    shape.trace_columns = 2;
    shape.quotient_len = 256;
    shape.n_coeffs = 256;
    shape.base_column_indices = {0};
    tape::PublicBindingV1 binding;
    binding.program_root = Seed(0x41);
    binding.statement_root = Seed(0x42);
    binding.public_fs_seed = Seed(0x43);
    binding.proof_wire_root = Seed(0x44);
    binding.tape_root = {1, 2, 3, 4};
    const auto program =
        TransitionPrograms();
    const auto program_root =
        cb::CommitProgramTableAlgHash(
            program);
    const rv::QueryRangeV1 range{
        .ordinal = 0,
        .first_query = 0,
        .query_count = 1,
    };
    quotient::PublicConstraintSystemV1
        quotient_cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        quotient::BuildPublicConstraintSystemV1(
            shape, binding, program,
            program_root, range,
            quotient_cs, &why),
        why);
    BOOST_CHECK(quotient_cs.valid);
    BOOST_CHECK(quotient_cs.tape_cs_rebuilt);
    BOOST_CHECK(quotient_cs.deep_cs_rebuilt);
    BOOST_CHECK(
        quotient_cs
            .exact_alias_schedule_rebuilt);
    BOOST_CHECK(
        quotient_cs.proof_values_excluded);
    BOOST_CHECK_EQUAL(
        quotient_cs.aliases.size(),
        dvm::kFp3TapeLimbsV1);

    parent::PublicBaseConstraintSystemV1
        deep_base;
    BOOST_REQUIRE_MESSAGE(
        parent::
            BuildPublicBaseConstraintSystemV1(
                shape, binding, program,
                program_root, range,
                deep_base, &why),
        why);
    BOOST_CHECK(deep_base.valid);
    BOOST_CHECK(
        deep_base.quotient_parent_rebuilt);
    BOOST_CHECK(
        deep_base
            .occurrence_schedule_rebuilt);
    BOOST_CHECK(
        deep_base
            .deterministic_constraints_rebuilt);
    BOOST_CHECK(
        deep_base.proof_values_excluded);
    BOOST_CHECK_EQUAL(
        deep_base.cs.n_columns,
        deep_base.layout.dependent_base);

    // A root that does not commit the supplied frozen ProgramTable must fail
    // before any verifier callback graph is returned.
    auto substituted_root = program_root;
    substituted_root[0] =
        gf::Add(
            substituted_root[0], 1);
    quotient::PublicConstraintSystemV1
        rejected;
    BOOST_CHECK(
        !quotient::
            BuildPublicConstraintSystemV1(
                shape, binding, program,
                substituted_root, range,
                rejected, &why));
    BOOST_CHECK(!rejected.valid);
}

BOOST_AUTO_TEST_CASE(
    public_complete_child_rebuilds_after_r0_without_proof_values)
{
    complete::PublicStatementV1 statement;
    statement.tape_shape.trace_rows = 256;
    statement.tape_shape.trace_columns = 2;
    statement.tape_shape.quotient_len = 256;
    statement.tape_shape.n_coeffs = 256;
    statement.tape_shape
        .base_column_indices = {0};
    statement.tape_binding.program_root =
        Seed(0x51);
    statement.tape_binding.statement_root =
        Seed(0x52);
    statement.tape_binding.public_fs_seed =
        Seed(0x53);
    statement.tape_binding.proof_wire_root =
        Seed(0x54);
    statement.tape_binding.tape_root =
        {1, 2, 3, 4};
    statement.range = {
        .ordinal = 0,
        .first_query = 0,
        .query_count = 1,
    };
    statement.child_program =
        TransitionPrograms();
    statement.child_program_root =
        cb::CommitProgramTableAlgHash(
            statement.child_program);
    statement.public_seed =
        Seed(0x55);
    const uint256 r0_root =
        Seed(0x56);

    complete::VerifierConstraintSystemV1
        rebuilt;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        complete::BuildConstraintSystemV1(
            statement, r0_root,
            rebuilt, &why),
        why);
    BOOST_CHECK(rebuilt.valid);
    BOOST_CHECK(
        rebuilt
            .deterministic_system_rebuilt);
    BOOST_CHECK(
        rebuilt.challenge_system_rebuilt);
    BOOST_CHECK(
        rebuilt.proof_values_excluded);
    BOOST_CHECK_EQUAL(
        rebuilt
            .r0_base_column_indices.size(),
        rebuilt.deep_finalization
            .parent_layout.dependent_base);
    BOOST_CHECK_EQUAL(
        rebuilt.cs
            .preprocessed_row_group_roots
            .size(),
        1U);
    BOOST_CHECK_EQUAL(
        rebuilt.shared_tape_aliases,
        rebuilt.deep_base.physical
            .tape_layout.End());

    // The frozen program table/root pair is a public verifier input. A root
    // substitution cannot select a different callback graph.
    auto substituted = statement;
    substituted.child_program_root[0] =
        gf::Add(
            substituted
                .child_program_root[0],
            1);
    complete::VerifierConstraintSystemV1
        rejected;
    BOOST_CHECK(
        !complete::BuildConstraintSystemV1(
            substituted, r0_root,
            rejected, &why));
    BOOST_CHECK(!rejected.valid);
}

BOOST_AUTO_TEST_CASE(
    bounded_dual_logup_parent_proves_and_rejects_all_structural_attacks)
{
    const uint256 seed = Seed(0x71);
    std::string why;
    const auto honest =
        parent::BuildBoundedCanaryV1(
            parent::CanaryMutationV1::Honest,
            seed, &why);
    BOOST_REQUIRE_MESSAGE(
        honest.valid,
        honest.note << " violations=" <<
            honest.violations);
    BOOST_REQUIRE_EQUAL(honest.violations, 0U);
    BOOST_CHECK(
        honest.dual_fp3_terminal_cancelled);
    BOOST_CHECK(
        honest.challenges_after_complete_r0);
    BOOST_CHECK(
        honest.canonical_u32_and_goldilocks_constrained);
    BOOST_CHECK(
        honest.physical_tape_stream_consumed);
    BOOST_CHECK(!honest.recursively_consumed);
    BOOST_CHECK(!honest.recursive_authority_ready);

    const auto proved = Prove(honest, seed, false);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRapSafeV2(
            honest.cs, proved.proof,
            honest.r0_base_column_indices,
            seed, &why),
        why);

    const std::array<parent::CanaryMutationV1, 5>
        attacks{
            parent::CanaryMutationV1::
                OmitOccurrence,
            parent::CanaryMutationV1::
                DuplicateOccurrence,
            parent::CanaryMutationV1::
                ReaddressOccurrence,
            parent::CanaryMutationV1::
                Fp3LimbSubstitution,
            parent::CanaryMutationV1::
                GoldilocksAliasXp,
        };
    for (const auto attack : attacks) {
        const auto forged =
            parent::BuildBoundedCanaryV1(
                attack, seed, &why);
        BOOST_CHECK(!forged.valid);
        BOOST_REQUIRE_GT(
            forged.violations, 0U);
        const auto forced =
            Prove(forged, seed, true);
        BOOST_REQUIRE_MESSAGE(
            forced.ok, forced.note);
        BOOST_REQUIRE(!forced.division_exact);
        BOOST_CHECK(
            !aq::AirQuotientVerifyRowsSplitRapSafeV2(
                forged.cs, forced.proof,
                forged.r0_base_column_indices,
                seed, &why));
    }
}

BOOST_AUTO_TEST_CASE(
    wider_parent_r0_precedes_deep_quotient_logup_challenges)
{
    const uint256 seed = Seed(0x72);
    std::string why;
    const auto standalone =
        parent::BuildBoundedCanaryV1(
            parent::CanaryMutationV1::Honest,
            seed, &why);
    BOOST_REQUIRE_MESSAGE(
        standalone.valid, standalone.note);

    parent::BaseProductV1 base;
    BOOST_REQUIRE_MESSAGE(
        parent::ExtractBaseProductV1(
            standalone, base, &why),
        why);
    BOOST_REQUIRE(base.valid);
    BOOST_CHECK(
        base.challenge_columns_absent);
    BOOST_CHECK(
        base.row_group_root_pending);

    aq::AirConstraintSystem<gf::Fp3>
        sibling_cs;
    sibling_cs.n_rows = base.cs.n_rows;
    sibling_cs.n_columns = 1;
    sibling_cs.constraints.push_back({
        "test.v13.deep_stream.sibling",
        aq::AirKind::kEverywhere, 1,
        [](const auto& current,
           const auto&) {
            return gf::Sub(
                current[0],
                gf::FromU64_3(7));
        }});
    std::vector<std::vector<gf::Fp3>>
        sibling_columns(
            1,
            std::vector<gf::Fp3>(
                sibling_cs.n_rows,
                gf::FromU64_3(7)));

    aq::AirConstraintSystem<gf::Fp3>
        combined_cs;
    std::vector<std::vector<gf::Fp3>>
        combined_columns;
    composer::ChildAttachmentV1
        sibling_attachment;
    composer::ChildAttachmentV1
        base_attachment;
    BOOST_REQUIRE_MESSAGE(
        composer::AppendChildV1(
            combined_cs, combined_columns,
            sibling_cs, sibling_columns,
            0, sibling_attachment, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        composer::AppendChildV1(
            combined_cs, combined_columns,
            base.cs, base.columns,
            1, base_attachment, &why),
        why);

    std::vector<uint32_t> parent_base_columns(
        combined_cs.n_columns);
    std::iota(
        parent_base_columns.begin(),
        parent_base_columns.end(), 0U);
    const auto parent_r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            combined_cs, combined_columns,
            parent_base_columns);
    BOOST_REQUIRE_MESSAGE(
        parent_r0.valid, parent_r0.note);
    BOOST_CHECK(
        parent_r0.base_row_commitment !=
        standalone.r0_session
            .base_row_commitment);

    // A child-local R0 does not cover the sibling and must be rejected before
    // any challenge-dependent columns enter the wider parent.
    auto stale_cs = combined_cs;
    auto stale_columns = combined_columns;
    parent::ParentFinalizationV1 stale;
    BOOST_CHECK(
        !parent::AppendFinalRelationToParentV1(
            base, base_attachment, seed,
            standalone.r0_session,
            stale_cs, stale_columns,
            stale, &why));

    parent::ParentFinalizationV1 final;
    BOOST_REQUIRE_MESSAGE(
        parent::AppendFinalRelationToParentV1(
            base, base_attachment, seed,
            parent_r0,
            combined_cs, combined_columns,
            final, &why),
        why);
    BOOST_REQUIRE(final.valid);
    BOOST_CHECK(
        final.exact_parent_r0_consumed);
    BOOST_CHECK(
        final
            .all_prior_parent_columns_prechallenge);
    BOOST_CHECK(
        final.dual_fp3_terminal_cancelled);
    BOOST_CHECK_EQUAL(
        final.r0_base_column_indices.size(),
        final.parent_layout.dependent_base);
    BOOST_CHECK(
        !gf::Eq(
            final.challenges.gamma[0],
            standalone.challenges.gamma[0]) ||
        !gf::Eq(
            final.challenges.alpha[0],
            standalone.challenges.alpha[0]));
    BOOST_REQUIRE_EQUAL(
        parent::CountViolationsV1(
            combined_cs, combined_columns),
        0U);

    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            combined_cs, combined_columns,
            final.r0_base_column_indices,
            seed, {}, &parent_r0);
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRapSafeV2(
            combined_cs, proved.proof,
            final.r0_base_column_indices,
            seed, &why),
        why);

    BOOST_REQUIRE(
        !proved.proof.batch.queries.empty());
    BOOST_REQUIRE(
        !proved.proof.batch
             .queries[0].steps.empty());
    auto tampered = proved.proof;
    tampered.batch.queries[0]
        .steps[0].even =
        gf::Add(
            tampered.batch.queries[0]
                .steps[0].even,
            gf::Fp3::One());
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRapSafeV2(
            combined_cs, tampered,
            final.r0_base_column_indices,
            seed, &why));
}

BOOST_AUTO_TEST_CASE(
    two_sibling_relations_share_one_global_r0_and_reject_dependent_forgery)
{
    const uint256 first_seed = Seed(0x73);
    const uint256 second_seed = Seed(0x74);
    std::string why;
    const auto standalone =
        parent::BuildBoundedCanaryV1(
            parent::CanaryMutationV1::Honest,
            first_seed, &why);
    BOOST_REQUIRE_MESSAGE(
        standalone.valid, standalone.note);
    parent::BaseProductV1 base;
    BOOST_REQUIRE_MESSAGE(
        parent::ExtractBaseProductV1(
            standalone, base, &why),
        why);

    aq::AirConstraintSystem<gf::Fp3> combined_cs;
    std::vector<std::vector<gf::Fp3>>
        combined_columns;
    composer::ChildAttachmentV1 first_attachment;
    composer::ChildAttachmentV1 second_attachment;
    BOOST_REQUIRE_MESSAGE(
        composer::AppendChildV1(
            combined_cs, combined_columns,
            base.cs, base.columns,
            0, first_attachment, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        composer::AppendChildV1(
            combined_cs, combined_columns,
            base.cs, base.columns,
            1, second_attachment, &why),
        why);
    std::vector<uint32_t> r0_columns(
        combined_cs.n_columns);
    std::iota(
        r0_columns.begin(),
        r0_columns.end(), 0U);
    const auto r0 =
        aq::AirQuotientBuildTwoEpochBaseRowSession(
            combined_cs, combined_columns,
            r0_columns);
    BOOST_REQUIRE_MESSAGE(r0.valid, r0.note);

    parent::ParentFinalizationV1 first;
    parent::ParentFinalizationV1 second;
    BOOST_REQUIRE_MESSAGE(
        parent::AppendFinalRelationToParentV1(
            base, first_attachment,
            first_seed, r0,
            combined_cs, combined_columns,
            first, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        parent::AppendFinalRelationToParentV1(
            base, second_attachment,
            second_seed, r0,
            combined_cs, combined_columns,
            second, &why),
        why);
    BOOST_REQUIRE(first.valid);
    BOOST_REQUIRE(second.valid);
    BOOST_CHECK(
        first.all_prior_parent_columns_prechallenge);
    BOOST_CHECK(
        !second.all_prior_parent_columns_prechallenge);
    BOOST_CHECK(
        first
            .all_deterministic_parent_columns_prechallenge);
    BOOST_CHECK(
        second
            .all_deterministic_parent_columns_prechallenge);
    BOOST_CHECK_EQUAL(
        combined_cs
            .preprocessed_row_group_roots.size(),
        1U);
    BOOST_CHECK(
        !gf::Eq(
            first.challenges.gamma[0],
            second.challenges.gamma[0]) ||
        !gf::Eq(
            first.challenges.alpha[0],
            second.challenges.alpha[0]));
    BOOST_REQUIRE_EQUAL(
        parent::CountViolationsV1(
            combined_cs, combined_columns),
        0U);

    const auto proved =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            combined_cs, combined_columns,
            r0_columns, first_seed, {}, &r0);
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRapSafeV2(
            combined_cs, proved.proof,
            r0_columns, first_seed, &why),
        why);

    combined_columns[
        second.parent_layout.running_base][0] =
        gf::Add(
            combined_columns[
                second.parent_layout
                    .running_base][0],
            gf::Fp3::One());
    BOOST_REQUIRE_GT(
        parent::CountViolationsV1(
            combined_cs, combined_columns),
        0U);
    aq::AirProveOptions force;
    force.force_commit_on_inexact = true;
    const auto forged =
        aq::AirQuotientProveRowsSplitRapSafeV2(
            combined_cs, combined_columns,
            r0_columns, first_seed,
            force, nullptr);
    BOOST_REQUIRE_MESSAGE(forged.ok, forged.note);
    BOOST_REQUIRE(!forged.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRapSafeV2(
            combined_cs, forged.proof,
            r0_columns, first_seed, &why));
}

BOOST_AUTO_TEST_CASE(
    full_physical_v13_stream_is_consumed_and_independent_retape_rejects)
{
    if (std::getenv(
            "BTX_RUN_V13_DEEP_STREAM_FULL") ==
        nullptr) {
        return;
    }
    FullFixture fixture;
    const rv::QueryRangeV1 range{
        .ordinal = 0,
        .first_query = 0,
        .query_count = 1,
    };
    parent::ProductV1 product;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        parent::BuildProductV1(
            fixture.tape_product,
            fixture.deep_product,
            fixture.child_program,
            fixture.child_program_root,
            range, fixture.seed,
            product, &why),
        why);
    BOOST_REQUIRE(product.valid);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK_EQUAL(
        product.layout.end -
            product.layout.original_columns,
        parent::kAdditionalColumnsV1);
    BOOST_REQUIRE_EQUAL(
        product.plan.occurrences.size(), 26U);
    BOOST_CHECK_EQUAL(
        product.plan.source_multiplicity_sum,
        product.plan.occurrences.size());
    BOOST_CHECK(
        product.every_occurrence_materialized);
    BOOST_CHECK(
        product.physical_tape_stream_consumed);
    BOOST_CHECK(
        product.dual_fp3_terminal_cancelled);
    BOOST_CHECK(
        product.challenges_after_complete_r0);
    BOOST_CHECK(!product.recursively_consumed);
    BOOST_CHECK(!product.recursive_authority_ready);

    // Retape one canonical source word and recompute the complete physical
    // tape root/witness.  Both children remain independently exact.  The
    // actual same-parent source stream must be the component that rejects.
    const auto target =
        std::find_if(
            product.plan.occurrences.begin(),
            product.plan.occurrences.end(),
            [](const auto& occurrence) {
                return occurrence.kind ==
                    parent::ConsumerKindV1::EvalZ1;
            });
    BOOST_REQUIRE(
        target != product.plan.occurrences.end());
    std::vector<uint32_t> forged_words =
        fixture.canonical_v13_words;
    forged_words[
        SourceValueWord(
            target->source_address)] ^= 1U;
    auto forged_binding = fixture.binding;
    forged_binding.tape_root =
        tape::ComputeTapeRootV1(
            fixture.shape, forged_binding,
            forged_words, &why);
    BOOST_REQUIRE_MESSAGE(
        forged_binding.tape_root !=
            matmul::v4::rc::
                alg_hash::Digest{},
        why);
    const auto forged_tape =
        tape::BuildProductV1(
            fixture.shape, forged_binding,
            forged_words);
    BOOST_REQUIRE_MESSAGE(
        forged_tape.valid,
        forged_tape.note);
    BOOST_REQUIRE_EQUAL(
        forged_tape.violations, 0U);
    BOOST_REQUIRE_EQUAL(
        dvm::RecountViolationsV1(
            fixture.deep_product,
            fixture.deep_product.columns),
        0U);

    parent::ProductV1 forged;
    BOOST_CHECK(
        !parent::BuildProductV1(
            forged_tape,
            fixture.deep_product,
            fixture.child_program,
            fixture.child_program_root,
            range, fixture.seed,
            forged, &why));
    BOOST_CHECK(!forged.valid);
}

BOOST_AUTO_TEST_CASE(
    complete_v13_child_parent_proves_and_dependent_cell_forgery_rejects)
{
    const bool run_full =
        std::getenv(
            "BTX_RUN_V13_COMPLETE_CHILD_PARENT") !=
        nullptr;
    const bool run_alias_only =
        std::getenv(
            "BTX_RUN_V13_COMPLETE_CHILD_PARENT_ALIAS_ONLY") !=
        nullptr;
    if (!run_full && !run_alias_only) {
        return;
    }
    FullFixture fixture;
    const rv::QueryRangeV1 range{
        .ordinal = 0,
        .first_query = 0,
        .query_count = 1,
    };
    parent::ProductV1 deep_parent;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        parent::BuildProductV1(
            fixture.tape_product,
            fixture.deep_product,
            fixture.child_program,
            fixture.child_program_root,
            range, fixture.seed,
            deep_parent, &why),
        why);
    const auto decoded =
        proofabi::DecodeCanonicalSafeV13(
            fixture.canonical_v13_words,
            &why);
    BOOST_REQUIRE_MESSAGE(
        decoded.has_value(), why);
    const auto shard =
        mf::BuildShardV1(
            *decoded, fixture.transcript,
            range.first_query,
            range.query_count);
    BOOST_REQUIRE_MESSAGE(
        shard.valid, shard.note);

    complete::ProductV1 product;
    BOOST_REQUIRE_MESSAGE(
        complete::BuildProductV1(
            *decoded, fixture.tape_product,
            shard, deep_parent,
            fixture.seed, product, &why),
        why);
    BOOST_REQUIRE(product.valid);
    BOOST_CHECK_EQUAL(product.violations, 0U);
    BOOST_CHECK(
        product.exact_shared_tape_binding);
    BOOST_CHECK(
        product.exact_shared_tape_cells_aliased);
    BOOST_CHECK(
        product.public_merkle_systems.valid);
    BOOST_CHECK(
        product.verifier_merkle_systems_rebuilt);
    BOOST_CHECK(
        product
            .verifier_constraint_system_rebuilt);
    BOOST_CHECK_EQUAL(
        product.shared_tape_aliases,
        fixture.tape_product.cs.n_columns);
    BOOST_CHECK(
        product.component_finalization.valid);
    BOOST_CHECK(
        product.merkle_fold_complete);
    BOOST_CHECK(
        product.quotient_deep_complete);
    BOOST_CHECK(
        product
            .every_deterministic_column_precedes_r0);
    BOOST_CHECK(
        product.terminal_acceptance_connected);
    BOOST_CHECK(product.proof_ready);
    BOOST_CHECK(!product.recursively_consumed);
    BOOST_CHECK(!product.authority_ready);

    // A second independently valid tape may carry the same proof words but a
    // different public program root.  Transplanting only its binding metadata
    // used to make the two locally valid tape witnesses look shared.  The
    // complete parent must reject because every physical tape column is now
    // equality-constrained across the Merkle and DEEP branches.
    auto alternate_binding =
        fixture.binding;
    alternate_binding.program_root =
        Seed(0x91);
    alternate_binding.tape_root =
        tape::ComputeTapeRootV1(
            fixture.shape,
            alternate_binding,
            fixture.canonical_v13_words,
            &why);
    BOOST_REQUIRE(
        alternate_binding.tape_root !=
        fixture.binding.tape_root);
    const auto alternate_tape =
        tape::BuildProductV1(
            fixture.shape,
            alternate_binding,
            fixture.canonical_v13_words);
    BOOST_REQUIRE_MESSAGE(
        alternate_tape.valid,
        alternate_tape.note);
    parent::ProductV1 alternate_deep_parent;
    BOOST_REQUIRE_MESSAGE(
        parent::BuildProductV1(
            alternate_tape,
            fixture.deep_product,
            fixture.child_program,
            fixture.child_program_root,
            range, fixture.seed,
            alternate_deep_parent, &why),
        why);
    BOOST_REQUIRE(
        alternate_deep_parent.valid);
    alternate_deep_parent.tape_binding =
        fixture.binding;
    complete::DeterministicComponentV1
        transplanted;
    BOOST_CHECK(
        !complete::BuildDeterministicComponentV1(
            *decoded, fixture.tape_product,
            shard, alternate_deep_parent,
            transplanted, &why));
    BOOST_CHECK(!transplanted.valid);
    if (run_alias_only) {
        BOOST_TEST_MESSAGE(
            "V13_COMPLETE_CHILD duplicate_valid_tape_"
            "metadata_transplant_reject=1 aliases=" <<
            product.shared_tape_aliases);
        return;
    }

    const auto prove_start =
        std::chrono::steady_clock::now();
    const auto proved =
        Prove(product, fixture.seed, false);
    const auto prove_ms =
        std::chrono::duration_cast<
            std::chrono::milliseconds>(
                std::chrono::steady_clock::now() -
                prove_start)
            .count();
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    BOOST_REQUIRE(proved.division_exact);
    const auto verify_start =
        std::chrono::steady_clock::now();
    complete::PublicStatementV1
        public_statement;
    public_statement.tape_shape =
        fixture.shape;
    public_statement.tape_binding =
        fixture.binding;
    public_statement.range = range;
    public_statement.child_program =
        fixture.child_program;
    public_statement.child_program_root =
        fixture.child_program_root;
    public_statement.public_seed =
        fixture.seed;
    BOOST_REQUIRE_MESSAGE(
        complete::VerifyProofV1(
            public_statement,
            proved.proof, &why),
        why);
    const auto verify_ms =
        std::chrono::duration_cast<
            std::chrono::milliseconds>(
                std::chrono::steady_clock::now() -
                verify_start)
            .count();
    std::vector<unsigned char> proof_wire;
    const size_t proof_bytes =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof, proof_wire);
    BOOST_REQUIRE_EQUAL(
        proof_bytes, proof_wire.size());
    BOOST_REQUIRE_NE(proof_bytes, 0U);

    // Every field that selects the verifier relation or transcript is public
    // input.  Reusing the honest proof under any substituted statement, or
    // substituting the R0 commitment from which the dependent relation is
    // sampled, must fail in the independently rebuilt verifier.
    auto changed_program =
        public_statement;
    changed_program.child_program
        .programs[0]
        .instructions[3]
        .constant =
            gf::Fp3::FromFp(2);
    BOOST_CHECK(
        !complete::VerifyProofV1(
            changed_program,
            proved.proof, &why));

    auto changed_program_root =
        public_statement;
    changed_program_root
        .child_program_root[0] =
            gf::Add(
                changed_program_root
                    .child_program_root[0],
                1);
    BOOST_CHECK(
        !complete::VerifyProofV1(
            changed_program_root,
            proved.proof, &why));

    auto changed_shape =
        public_statement;
    changed_shape.tape_shape.n_coeffs *= 2;
    BOOST_CHECK(
        !complete::VerifyProofV1(
            changed_shape,
            proved.proof, &why));

    auto changed_binding =
        public_statement;
    changed_binding
        .tape_binding.statement_root
        .begin()[0] ^= 1U;
    BOOST_CHECK(
        !complete::VerifyProofV1(
            changed_binding,
            proved.proof, &why));

    auto changed_range =
        public_statement;
    ++changed_range.range.first_query;
    BOOST_CHECK(
        !complete::VerifyProofV1(
            changed_range,
            proved.proof, &why));

    auto changed_seed =
        public_statement;
    changed_seed.public_seed.begin()[0] ^= 1U;
    BOOST_CHECK(
        !complete::VerifyProofV1(
            changed_seed,
            proved.proof, &why));

    auto changed_r0 = proved.proof;
    changed_r0.batch.groups[0]
        .row_commit.root[0] =
            gf::Add(
                changed_r0.batch.groups[0]
                    .row_commit.root[0],
                1);
    BOOST_CHECK(
        !complete::VerifyProofV1(
            public_statement,
            changed_r0, &why));

    // The running accumulator is post-R0 witness.  Altering it must be seen
    // by the complete relation scan and cannot be turned into a verifying
    // proof even when the prover is forced to commit an inexact quotient.
    const uint32_t dependent_column =
        product.deep_finalization
            .parent_layout.running_base;
    BOOST_REQUIRE_LT(
        dependent_column,
        product.columns.size());
    product.columns[dependent_column][0] =
        gf::Add(
            product.columns[dependent_column][0],
            gf::Fp3::One());
    product.violations =
        parent::CountViolationsV1(
            product.cs, product.columns);
    BOOST_REQUIRE_GT(product.violations, 0U);
    const auto forced =
        Prove(product, fixture.seed, true);
    BOOST_REQUIRE_MESSAGE(
        forced.ok, forced.note);
    BOOST_REQUIRE(!forced.division_exact);
    BOOST_CHECK(
        !complete::VerifyProofV1(
            public_statement,
            forced.proof, &why));
    BOOST_TEST_MESSAGE(
        "V13_COMPLETE_CHILD proof_bytes=" <<
            proof_bytes <<
        " prove_ms=" << prove_ms <<
        " verify_ms=" << verify_ms <<
        " rows=" << product.cs.n_rows <<
        " columns=" << product.cs.n_columns <<
        " dependent_cell_proof_reject=1");
}

BOOST_AUTO_TEST_SUITE_END()
