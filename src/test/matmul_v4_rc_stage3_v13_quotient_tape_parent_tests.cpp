// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_backend.h>
#include <matmul/matmul_v4_rc_stage3_v13_quotient_tape_parent.h>

#include <algorithm>
#include <cstdlib>
#include <string>
#include <vector>

namespace parent =
    matmul::v4::rc::stage3_v13_quotient_tape_parent;
namespace aq = matmul::v4::rc::air_quotient;
namespace backend =
    matmul::v4::rc::stage3_multirow_v11_backend;
namespace cb = matmul::v4::rc::constraint_bytecode;
namespace dvm =
    matmul::v4::rc::stage3_multirow_v11_deep_vm;
namespace gf = matmul::v4::rc::gkr_field;
namespace rv =
    matmul::v4::rc::stage3_multirow_v11_recursive_verifier;
namespace tape =
    matmul::v4::rc::stage3_multirow_v13_proof_tape_air;
namespace proofabi =
    matmul::v4::rc::stage3_multirow_v11_proof_abi;

namespace {

inline constexpr uint32_t kChildRows = 256;

uint256 Seed(uint8_t tag)
{
    uint256 out;
    for (uint32_t index = 0;
         index < out.size();
         ++index) {
        out.begin()[index] =
            static_cast<unsigned char>(
                tag + 19 * index);
    }
    return out;
}

aq::AirConstraintSystem<gf::Fp3> TransitionAir()
{
    aq::AirConstraintSystem<gf::Fp3> cs;
    cs.n_rows = kChildRows;
    cs.n_columns = 2;
    cs.constraints.push_back({
        "test.v13_quotient.counter",
        aq::AirKind::kTransition, 1,
        [](const auto& current,
           const auto& next) {
            return gf::Sub(
                gf::Sub(
                    next[0], current[0]),
                gf::Fp3::One());
        }});
    cs.constraints.push_back({
        "test.v13_quotient.double",
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
         row < kChildRows;
         ++row) {
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

struct Fixture {
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

    Fixture()
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
        auto v13_envelope =
            proved.proximity.proof.envelope;
        v13_envelope.split.version =
            aq::
                kAirQuotientSplitRapRowsSafeProofVersionV2;
        v13_envelope.split.batch.version =
            matmul::v4::rc::
                kRCFri3AlgMultiRowSafeQ192K2ProofVersionV13;
        BOOST_REQUIRE_MESSAGE(
            proofabi::EncodeCanonicalSafeV13(
                v13_envelope,
                canonical_v13_words,
                nullptr, &why),
            why);
        for (uint32_t word = 0;
             word <
                 v13_envelope
                     .public_fs_seed.size();
             ++word) {
            for (uint32_t byte = 0;
                 byte < 4;
                 ++byte) {
                binding.public_fs_seed
                    .begin()[4 * word + byte] =
                    static_cast<unsigned char>(
                        v13_envelope
                            .public_fs_seed[word] >>
                        (8 * byte));
            }
        }
        shape.trace_rows = child_cs.n_rows;
        shape.trace_columns =
            child_cs.n_columns;
        BOOST_REQUIRE(
            !proved.proximity.proof.envelope
                 .split.batch.column_len.empty());
        shape.quotient_len =
            proved.proximity.proof.envelope
                .split.batch.column_len.back();
        shape.n_coeffs =
            proved.proximity.proof.envelope
                .split.batch.n_coeffs;
        shape.base_column_indices =
            base_columns;
        binding.program_root = Seed(0x11);
        binding.statement_root = Seed(0x22);
        binding.proof_wire_root = Seed(0x33);
        binding.tape_root =
            tape::ComputeTapeRootV1(
                shape, binding,
                canonical_v13_words,
                &why);
        BOOST_REQUIRE_MESSAGE(
            binding.tape_root !=
                matmul::v4::rc::
                    alg_hash::Digest{},
            why);
        const auto decoded =
            proofabi::DecodeCanonicalSafeV13(
                canonical_v13_words, &why);
        BOOST_REQUIRE_MESSAGE(
            decoded.has_value(), why);
        const auto tape_schedule =
            tape::BuildScheduleV1(
                shape, binding);
        BOOST_REQUIRE_MESSAGE(
            tape_schedule.valid,
            tape_schedule.note);
        BOOST_REQUIRE_EQUAL(
            decoded->sources.size(),
            tape_schedule.semantic_sources.size());
        for (uint32_t index = 0;
             index < decoded->sources.size();
             ++index) {
            const auto& record =
                tape_schedule.records[
                    tape::kPublicPrefixRecordsV1 +
                    tape::kHeaderRecordsV1 +
                    index];
            if (!record.fixed_value) continue;
            BOOST_REQUIRE_MESSAGE(
                decoded->sources[index].value ==
                    record.expected_value,
                "fixed tape source mismatch at address " <<
                    index << " kind=" <<
                    static_cast<uint32_t>(
                        record.key.kind) <<
                    " expected=" <<
                    record.expected_value <<
                    " actual=" <<
                    decoded->sources[index].value);
        }
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

parent::ProductV1 BoundedAliasCanary(
    uint32_t source_value,
    uint32_t sink_value)
{
    parent::ProductV1 out;
    out.cs.n_rows = 8;
    out.cs.n_columns = 34;
    out.columns.assign(
        out.cs.n_columns,
        std::vector<gf::Fp3>(
            out.cs.n_rows,
            gf::Fp3::Zero()));
    for (uint32_t row = 0;
         row < out.cs.n_rows;
         ++row) {
        out.columns[0][row] =
            gf::Fp3::FromFp(source_value);
        out.columns[1][row] =
            gf::Fp3::FromFp(sink_value);
        for (uint32_t bit = 0;
             bit < 32;
             ++bit) {
            out.columns[2 + bit][row] =
                gf::Fp3::FromFp(
                    (source_value >> bit) & 1U);
        }
    }
    for (uint32_t bit = 0;
         bit < 32;
         ++bit) {
        const uint32_t column = 2 + bit;
        out.cs.constraints.push_back({
            "test.v13_quotient_canary.bit",
            aq::AirKind::kEverywhere, 2,
            [column](
                const auto& current,
                const auto&) {
                return gf::Mul(
                    current[column],
                    gf::Sub(
                        current[column],
                        gf::Fp3::One()));
            }});
    }
    out.cs.constraints.push_back({
        "test.v13_quotient_canary.reconstruct",
        aq::AirKind::kEverywhere, 1,
        [](const auto& current,
           const auto&) {
            gf::Fp3 rebuilt =
                gf::Fp3::Zero();
            uint64_t weight = 1;
            for (uint32_t bit = 0;
                 bit < 32;
                 ++bit) {
                rebuilt = gf::Add(
                    rebuilt,
                    gf::Mul(
                        current[2 + bit],
                        gf::Fp3::FromFp(
                            weight)));
                weight <<= 1;
            }
            return gf::Sub(
                current[0], rebuilt);
        }});
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        parent::AppendOrdinaryCellAliasV1(
            out.cs, out.columns,
            {0, 0}, {1, 7},
            out, &why),
        why);
    out.violations =
        parent::CountViolationsV1(
            out.cs, out.columns);
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_v13_quotient_tape_parent_tests)

BOOST_AUTO_TEST_CASE(
    physical_quotient_family_accepts_and_coherent_tape_substitution_rejects)
{
    if (std::getenv(
            "BTX_RUN_V13_QUOTIENT_FULL") ==
        nullptr) {
        return;
    }
    Fixture fixture;
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
            range, product, &why),
        why);
    BOOST_REQUIRE(product.valid);
    BOOST_CHECK_EQUAL(
        product.aliases.size(),
        dvm::kFp3TapeLimbsV1);
    BOOST_CHECK_EQUAL(
        product.violations, 0U);
    BOOST_CHECK(
        product.tape_cells_ordinary);
    BOOST_CHECK(
        product.quotient_cells_ordinary);
    BOOST_CHECK(
        product.selectors_only_preprocessed);
    BOOST_CHECK(
        product
            .cross_row_transport_constrained);
    BOOST_CHECK(
        product.global_r0_pending);
    BOOST_CHECK(
        !product.recursively_consumed);
    BOOST_CHECK(
        !product.recursive_authority_ready);

    // Change a proof-owned quotient limb and recompute the entire V13 tape
    // witness and its public tape root.  The forged tape and unchanged DeepVM
    // verifier are independently exact; only their physical same-parent
    // equality is false.
    std::vector<uint32_t> forged_words =
        fixture.canonical_v13_words;
    const uint32_t source_address =
        product.aliases.front().source_address;
    forged_words[
        SourceValueWord(source_address)] ^= 1U;
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
            fixture.shape,
            forged_binding,
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
            range, forged, &why));
    BOOST_REQUIRE(
        !forged.valid);
    BOOST_REQUIRE_GT(
        forged.violations, 0U);
}

BOOST_AUTO_TEST_CASE(
    bounded_alias_construction_canary_accepts_and_rejects)
{
    // Construction canary: the exact ordinary-cell alias primitive used
    // by the full product is proved at bounded shape.  The forged instance
    // changes the
    // source value and all of its decomposition bits coherently, so its
    // local source relation remains exact and only the source/sink equality
    // rejects.
    std::string why;
    const uint256 proof_seed = Seed(0x91);
    const auto honest_canary =
        BoundedAliasCanary(17, 17);
    BOOST_REQUIRE_EQUAL(
        honest_canary.violations, 0U);
    const auto honest_proof =
        aq::AirQuotientProve<gf::Fp3>(
            honest_canary.cs,
            honest_canary.columns,
            proof_seed);
    BOOST_REQUIRE_MESSAGE(
        honest_proof.ok,
        honest_proof.note);
    BOOST_REQUIRE(
        honest_proof.division_exact);
    BOOST_REQUIRE_MESSAGE(
        aq::AirQuotientVerify<gf::Fp3>(
            honest_canary.cs,
            honest_proof.proof,
            proof_seed, &why),
        why);

    const auto forged_canary =
        BoundedAliasCanary(18, 17);
    BOOST_REQUIRE_GT(
        forged_canary.violations, 0U);
    aq::AirProveOptions force;
    force.force_commit_on_inexact = true;
    const auto forced =
        aq::AirQuotientProve<gf::Fp3>(
            forged_canary.cs,
            forged_canary.columns,
            proof_seed, force);
    BOOST_REQUIRE_MESSAGE(
        forced.ok, forced.note);
    BOOST_REQUIRE(
        !forced.division_exact);
    BOOST_CHECK(
        !aq::AirQuotientVerify<gf::Fp3>(
            forged_canary.cs,
            forced.proof,
            proof_seed, &why));
}

BOOST_AUTO_TEST_SUITE_END()
