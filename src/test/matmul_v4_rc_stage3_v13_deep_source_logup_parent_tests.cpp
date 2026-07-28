// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_backend.h>
#include <matmul/matmul_v4_rc_stage3_v13_deep_source_logup_parent.h>

#include <algorithm>
#include <array>
#include <cstdlib>
#include <string>
#include <vector>

namespace parent =
    matmul::v4::rc::
        stage3_v13_deep_source_logup_parent;
namespace aq = matmul::v4::rc::air_quotient;
namespace backend =
    matmul::v4::rc::stage3_multirow_v11_backend;
namespace cb = matmul::v4::rc::constraint_bytecode;
namespace dvm =
    matmul::v4::rc::stage3_multirow_v11_deep_vm;
namespace gf = matmul::v4::rc::gkr_field;
namespace proofabi =
    matmul::v4::rc::stage3_multirow_v11_proof_abi;
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

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_deep_source_logup_parent_tests)

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

BOOST_AUTO_TEST_SUITE_END()
