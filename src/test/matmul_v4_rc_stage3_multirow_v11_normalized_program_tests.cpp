// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_multirow_v11_normalized_program.h>
#include <matmul/matmul_v4_rc_stage3_multirow_p2_consumer_bridge.h>

#include <algorithm>
#include <functional>
#include <limits>

namespace matmul::v4::rc::stage3_multirow_v11_normalized_program {
namespace {

namespace abi = stage3_multirow_v11_proof_abi;
namespace pc = stage3_multirow_p2_consumer_bridge;
namespace tp = stage3_multirow_p2_transcript;
using gf::Fp3;

Fp3 U(uint64_t value)
{
    return gf::FromU64_3(value);
}

Fri3AlgDigest D(uint64_t base)
{
    return {
        gf::FromU64(base), gf::FromU64(base + 1),
        gf::FromU64(base + 2), gf::FromU64(base + 3)};
}

tp::StatementV1 Statement()
{
    tp::StatementV1 statement;
    statement.public_fs_seed =
        *uint256::FromHex(
            "1123456789abcdef0123456789abcdef"
            "0123456789abcdef0123456789abcdef");
    statement.trace_rows = 512;
    statement.trace_columns = 5;
    statement.quotient_len = 1024;
    statement.n_coeffs = 1024;
    statement.blowup = kRCFriBlowup;
    statement.base_column_indices = {0, 1};
    statement.groups = {{
        {Fri3AlgMultiRowGroupRole::MainTrace, 0, 2, 16384, D(10)},
        {Fri3AlgMultiRowGroupRole::AuxiliaryTrace, 2, 3, 16384, D(20)},
        {Fri3AlgMultiRowGroupRole::Quotient, 5, 1, 16384, D(30)}}};
    statement.column_len = {512, 512, 512, 512, 512, 1024};
    for (uint32_t column = 0;
         column < statement.column_len.size(); ++column) {
        statement.evals_z1.push_back(U(100 + column));
        statement.evals_z2.push_back(U(200 + column));
    }
    uint32_t leaves = 16384;
    for (uint32_t fold = 0; fold < 11; ++fold) {
        statement.folds.push_back(
            {leaves, D(1000 + 10 * fold)});
        leaves >>= 1;
    }
    statement.final_value = U(9999);
    return statement;
}

Fri3AlgRowOpening Row(
    uint64_t value, uint32_t columns, uint32_t depth)
{
    Fri3AlgRowOpening out;
    for (uint32_t c = 0; c < columns; ++c) {
        out.values.push_back(U(value + 10 * c));
    }
    for (uint32_t i = 0; i < depth; ++i) {
        out.siblings.push_back(D(value + 100 + 10 * i));
    }
    return out;
}

abi::EnvelopeV1 Envelope(
    const tp::StatementV1& statement,
    const tp::ReceiptV1& receipt)
{
    abi::EnvelopeV1 out;
    for (uint32_t word = 0; word < 4; ++word) {
        const uint64_t value =
            statement.public_fs_seed.GetUint64(word);
        out.public_fs_seed[2 * word] =
            static_cast<uint32_t>(value);
        out.public_fs_seed[2 * word + 1] =
            static_cast<uint32_t>(value >> 32);
    }
    out.trace_columns = statement.trace_columns;
    out.quotient_len = statement.quotient_len;
    auto& split = out.split;
    split.version = 1;
    split.trace_rows = statement.trace_rows;
    split.base_column_indices =
        statement.base_column_indices;
    split.air_constraint_lambda = receipt.air_lambda;
    auto& batch = split.batch;
    batch.version = kRCFri3AlgMultiRowBatchProofVersion;
    batch.pow_grind_nonce = 0;
    batch.blowup = statement.blowup;
    batch.n_coeffs = statement.n_coeffs;
    for (const auto& group : statement.groups) {
        batch.groups.push_back({
            group.role, group.first_column, group.column_count,
            {group.root, group.n_leaves}});
    }
    batch.column_len = statement.column_len;
    batch.lambda = receipt.air_lambda;
    batch.z1 = receipt.z1;
    batch.z2 = receipt.z2;
    batch.evals_z1 = statement.evals_z1;
    batch.evals_z2 = statement.evals_z2;
    batch.w1 = receipt.w1;
    batch.w2 = receipt.w2;
    for (const auto& fold : statement.folds) {
        batch.fold_layers.push_back(
            {fold.root, fold.n_leaves});
    }
    batch.final_value = statement.final_value;
    batch.fold_challenges = receipt.fold_challenges;
    constexpr uint32_t depth = 14;
    batch.queries.resize(abi::kQueryCountV11);
    split.next_trace_group_rows.resize(abi::kQueryCountV11);
    for (uint32_t q = 0; q < abi::kQueryCountV11; ++q) {
        auto& query = batch.queries[q];
        query.index = receipt.queries[q].index;
        query.group_rows = {
            Row(2000 + 100 * q, 2, depth),
            Row(3000 + 100 * q, 3, depth),
            Row(4000 + 100 * q, 1, depth)};
        uint32_t index = query.index;
        for (uint32_t fold = 0;
             fold < receipt.fold_challenges.size(); ++fold) {
            Fri3AlgFoldStep step;
            const uint32_t half =
                (statement.n_coeffs * statement.blowup >> fold) / 2;
            step.even_index = index % half;
            step.odd_index = step.even_index + half;
            step.even = U(5000 + 100 * q + fold);
            step.odd = U(6000 + 100 * q + fold);
            for (uint32_t i = 0; i < depth - fold; ++i) {
                step.even_siblings.push_back(
                    D(7000 + 1000 * q + 20 * fold + i));
                step.odd_siblings.push_back(
                    D(8000 + 1000 * q + 20 * fold + i));
            }
            query.steps.push_back(std::move(step));
            index %= half;
        }
        split.next_trace_group_rows[q] = {
            Row(9000 + 100 * q, 2, depth),
            Row(10000 + 100 * q, 3, depth)};
    }
    return out;
}

pj::ProductV1 ParentProduct()
{
    const auto replay = tp::BuildProductV1(Statement());
    BOOST_REQUIRE_MESSAGE(replay.valid, replay.note);
    const auto consumer = pc::BuildProductV1(replay);
    BOOST_REQUIRE_MESSAGE(consumer.valid, consumer.note);
    std::vector<uint32_t> words;
    std::string why;
    const auto envelope =
        Envelope(replay.statement, replay.receipt);
    BOOST_REQUIRE_MESSAGE(
        abi::EncodeCanonicalV1(envelope, words, nullptr, &why),
        why);
    const auto decoded = abi::DecodeCanonicalV1(words, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    std::vector<abi::ParentPublicCellV1> parent;
    uint32_t parent_column = 100;
    for (const auto& source : decoded->sources) {
        if (source.ownership ==
            abi::OwnershipClassV1::PublicStatement) {
            parent.push_back({
                source.key, parent_column++, source.value});
        }
    }
    auto product = pj::BuildProductV1(
        *decoded, parent, replay, consumer);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    return product;
}

bool SameDigest(
    const alg_hash::Digest& a,
    const alg_hash::Digest& b)
{
    for (uint32_t i = 0; i < alg_hash::kAlgHashDigestLen; ++i) {
        if (gf::Canonical(a[i]) != gf::Canonical(b[i])) return false;
    }
    return true;
}

void Renumber(cb::ProgramTable& table)
{
    for (uint32_t i = 0; i < table.programs.size(); ++i) {
        table.programs[i].constraint_ordinal = i;
    }
}

cb::ProgramTable DegreeTable(
    air_quotient::AirKind kind,
    uint32_t degree,
    uint32_t width = 5000)
{
    cb::ProgramTable table;
    table.version = cb::kConstraintBytecodeVersion;
    table.role = RCStage3RelationRole::CompositionLink;
    table.current_width = width;
    table.next_width = width;
    table.challenge_width = 0;

    cb::Program program;
    program.version = cb::kConstraintBytecodeVersion;
    program.role = table.role;
    program.constraint_ordinal = 0;
    program.kind = kind;
    program.declared_degree = degree;
    program.current_width = width;
    program.next_width = width;
    program.challenge_width = 0;

    cb::Instruction first;
    first.opcode = cb::Opcode::Current;
    first.lhs = 0;
    program.instructions.push_back(first);
    uint32_t product = 0;
    for (uint32_t column = 1; column < degree; ++column) {
        cb::Instruction load;
        load.opcode = cb::Opcode::Current;
        load.lhs = column;
        program.instructions.push_back(load);
        const uint32_t loaded =
            static_cast<uint32_t>(program.instructions.size()) - 1;

        cb::Instruction multiply;
        multiply.opcode = cb::Opcode::Mul;
        multiply.lhs = product;
        multiply.rhs = loaded;
        program.instructions.push_back(multiply);
        product =
            static_cast<uint32_t>(program.instructions.size()) - 1;
    }
    table.programs.push_back(std::move(program));
    return table;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_multirow_v11_normalized_program_tests)

BOOST_AUTO_TEST_CASE(
    complete_native_lowering_is_exact_but_exceeds_vm_fixedpoint_cap)
{
    cb::ProgramTable table;
    ManifestV1 manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildCanonicalProgramTableV1(table, &manifest, &why), why);
    BOOST_CHECK_EQUAL(table.programs.size(), kExpectedProgramsV1);
    BOOST_CHECK_EQUAL(manifest.program_count, kExpectedProgramsV1);
    BOOST_CHECK_EQUAL(manifest.poseidon_programs, 472U);
    BOOST_CHECK_EQUAL(manifest.transcript_glue_programs, 42U);
    BOOST_CHECK_EQUAL(manifest.parent_join_programs, 762U);
    BOOST_CHECK_EQUAL(manifest.current_columns, 1298U);
    BOOST_CHECK_EQUAL(manifest.next_columns, 1298U);
    BOOST_CHECK_EQUAL(manifest.unlowered_relations, 0U);
    BOOST_CHECK(manifest.canonical_program_table);
    BOOST_CHECK(manifest.canonical_field_encodings);
    BOOST_CHECK(manifest.opcode_and_operand_bounds);
    BOOST_CHECK(manifest.exact_native_constraint_order);
    BOOST_CHECK(manifest.no_opaque_callbacks);
    BOOST_CHECK_GT(
        manifest.instruction_count,
        uint64_t{kFixedPointInstructionCapV1});
    BOOST_CHECK_EQUAL(
        manifest.poseidon_instructions +
            manifest.transcript_glue_instructions +
            manifest.parent_join_instructions,
        manifest.instruction_count);
    BOOST_CHECK(!manifest.instruction_cap_fits);
    BOOST_CHECK_EQUAL(manifest.query_count, 64U);
    BOOST_CHECK_EQUAL(manifest.exact_vm_real_rows, 1598080U);
    BOOST_CHECK_EQUAL(manifest.exact_vm_trace_rows, 1U << 21);
    BOOST_CHECK_EQUAL(manifest.exact_vm_max_constraint_degree, 2U);
    BOOST_CHECK_EQUAL(
        manifest.exact_vm_max_composed_degree,
        2U * ((1U << 21) - 1U) + 1U);
    BOOST_CHECK_EQUAL(
        manifest.exact_vm_quotient_len, 1U << 21);
    BOOST_CHECK_EQUAL(
        manifest.exact_vm_coefficient_rows, 1U << 21);
    BOOST_CHECK_EQUAL(manifest.exact_vm_lde_rows, 1U << 25);
    BOOST_CHECK(!manifest.trace_rows_fit);
    BOOST_CHECK(!manifest.lde_rows_fit);
    BOOST_CHECK(
        manifest.residual_mask &
        kResidualFixedPointInstructionCap);
    BOOST_CHECK(!manifest.canonical_program_executable);
    BOOST_CHECK(!manifest.recursive_authority_ready);
    BOOST_TEST_MESSAGE(
        "V11_NORMALIZED_PROGRAM exact_programs="
        << manifest.program_count
        << " exact_instructions=" << manifest.instruction_count
        << " poseidon_instructions="
        << manifest.poseidon_instructions
        << " transcript_instructions="
        << manifest.transcript_glue_instructions
        << " parent_join_instructions="
        << manifest.parent_join_instructions
        << " max_program_instructions="
        << manifest.max_program_instructions
        << " serialized_bytes=" << manifest.serialized_bytes
        << " q64_real_rows=" << manifest.exact_vm_real_rows
        << " trace_rows=" << manifest.exact_vm_trace_rows
        << " lde_rows=" << manifest.exact_vm_lde_rows
        << " fixedpoint_cap=" << manifest.fixedpoint_instruction_cap);
}

BOOST_AUTO_TEST_CASE(
    exact_quotient_domain_matches_air_system_and_q96_cap_boundary)
{
    constexpr uint32_t kQ96 = 96;
    const auto cubic =
        DegreeTable(air_quotient::AirKind::kEverywhere, 3);
    BOOST_REQUIRE(cb::ValidateProgramTable(cubic));
    const auto domain = AssessExecutionDomainV1(cubic, kQ96);
    BOOST_REQUIRE(domain.exact_degree_accounting);
    BOOST_CHECK_EQUAL(domain.real_rows, 480768U);
    BOOST_CHECK_EQUAL(domain.trace_rows, 1U << 19);
    BOOST_CHECK_EQUAL(domain.max_constraint_degree, 3U);
    BOOST_CHECK_EQUAL(domain.max_composed_degree, 1572861U);
    BOOST_CHECK_EQUAL(domain.quotient_len, 1048574U);
    BOOST_CHECK_EQUAL(domain.coefficient_rows, 1U << 20);
    BOOST_CHECK_EQUAL(domain.lde_rows, 1U << 24);
    BOOST_CHECK(domain.trace_rows_fit);
    BOOST_CHECK(domain.lde_rows_fit);
    BOOST_CHECK(domain.valid);

    air_quotient::AirConstraintSystem<Fp3> cs;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        cb::BuildAirConstraintSystemFromProgramTable(
            cubic, domain.trace_rows, cs, &why),
        why);
    BOOST_CHECK_EQUAL(
        domain.max_composed_degree,
        cs.MaxComposedDegreeBound());
    BOOST_CHECK_EQUAL(domain.quotient_len, cs.QuotientLen());

    const auto transition = AssessExecutionDomainV1(
        DegreeTable(air_quotient::AirKind::kTransition, 3),
        kQ96);
    BOOST_REQUIRE(transition.valid);
    BOOST_CHECK_EQUAL(transition.max_composed_degree, 1572862U);
    BOOST_CHECK_EQUAL(transition.quotient_len, 1048575U);
    BOOST_CHECK_EQUAL(transition.coefficient_rows, 1U << 20);
    BOOST_CHECK_EQUAL(transition.lde_rows, 1U << 24);

    const auto boundary = AssessExecutionDomainV1(
        DegreeTable(air_quotient::AirKind::kFirstRow, 3),
        kQ96);
    BOOST_REQUIRE(boundary.exact_degree_accounting);
    BOOST_CHECK_EQUAL(boundary.max_composed_degree, 2097148U);
    BOOST_CHECK_EQUAL(boundary.quotient_len, 1572861U);
    BOOST_CHECK_EQUAL(boundary.coefficient_rows, 1U << 21);
    BOOST_CHECK_EQUAL(boundary.lde_rows, 1U << 25);
    BOOST_CHECK(!boundary.lde_rows_fit);
    BOOST_CHECK(!boundary.valid);

    const auto quartic = AssessExecutionDomainV1(
        DegreeTable(air_quotient::AirKind::kEverywhere, 4),
        kQ96);
    BOOST_REQUIRE(quartic.exact_degree_accounting);
    BOOST_CHECK_EQUAL(quartic.max_composed_degree, 2097148U);
    BOOST_CHECK_EQUAL(quartic.coefficient_rows, 1U << 21);
    BOOST_CHECK_EQUAL(quartic.lde_rows, 1U << 25);
    BOOST_CHECK(!quartic.valid);

    auto understated = cubic;
    understated.programs[0].declared_degree = 2;
    BOOST_CHECK(!cb::ValidateProgramTable(understated));
    const auto rejected =
        AssessExecutionDomainV1(understated, kQ96);
    BOOST_CHECK(!rejected.exact_degree_accounting);
    BOOST_CHECK(!rejected.valid);
    BOOST_CHECK(!AssessExecutionDomainV1(cubic, 0).valid);
}

BOOST_AUTO_TEST_CASE(
    every_program_is_differentially_identical_to_real_parent_air)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildCanonicalProgramTableV1(table, nullptr, &why), why);
    const auto product = ParentProduct();
    const auto audit = AuditAgainstNativeV1(product, table, 3);
    BOOST_TEST_MESSAGE(
        "V11_NORMALIZED_DIFFERENTIAL evaluations="
        << audit.evaluations << " mismatches=" << audit.mismatches);
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK_EQUAL(audit.native_constraints, kExpectedProgramsV1);
    BOOST_CHECK_EQUAL(audit.bytecode_programs, kExpectedProgramsV1);
    BOOST_CHECK(audit.product_shape_exact);
    BOOST_CHECK(audit.every_native_constraint_lowered);
    BOOST_CHECK(audit.bit_exact);
}

BOOST_AUTO_TEST_CASE(
    omission_opcode_operand_and_order_attacks_reject)
{
    cb::ProgramTable honest;
    ManifestV1 manifest;
    std::string why;
    BOOST_REQUIRE(
        BuildCanonicalProgramTableV1(honest, &manifest, &why));

    auto omitted = honest;
    omitted.programs.pop_back();
    const auto omitted_assessment = AssessProgramTableV1(
        omitted, std::numeric_limits<uint32_t>::max());
    BOOST_CHECK(!omitted_assessment.no_opaque_callbacks);
    BOOST_CHECK_EQUAL(omitted_assessment.unlowered_relations, 1U);
    BOOST_CHECK(!ProgramRootMatchesV1(
        omitted, manifest.program_root));

    auto substituted = honest;
    bool opcode_changed = false;
    for (auto& program : substituted.programs) {
        for (auto& in : program.instructions) {
            if (in.opcode == cb::Opcode::Add) {
                in.opcode = cb::Opcode::Sub;
                opcode_changed = true;
                break;
            }
        }
        if (opcode_changed) break;
    }
    BOOST_REQUIRE(opcode_changed);
    BOOST_REQUIRE(cb::ValidateProgramTable(substituted, &why));
    BOOST_CHECK(!ProgramRootMatchesV1(
        substituted, manifest.program_root));

    cb::ProgramTable aliased;
    bool alias_found = false;
    for (uint32_t p = 0; p < honest.programs.size() && !alias_found; ++p) {
        for (uint32_t i = 0;
             i < honest.programs[p].instructions.size() && !alias_found;
             ++i) {
            const auto opcode =
                honest.programs[p].instructions[i].opcode;
            if (opcode != cb::Opcode::Add &&
                opcode != cb::Opcode::Sub &&
                opcode != cb::Opcode::Mul) continue;
            for (uint32_t replacement = 0;
                 replacement < i; ++replacement) {
                auto candidate = honest;
                candidate.programs[p].instructions[i].rhs = replacement;
                if (cb::ValidateProgramTable(candidate, nullptr) &&
                    !ProgramRootMatchesV1(
                        candidate, manifest.program_root)) {
                    aliased = std::move(candidate);
                    alias_found = true;
                    break;
                }
            }
        }
    }
    BOOST_REQUIRE_MESSAGE(
        alias_found,
        "expected a structurally valid operand-alias substitution");
    BOOST_CHECK(!ProgramRootMatchesV1(
        aliased, manifest.program_root));

    auto reordered = honest;
    std::swap(reordered.programs[0], reordered.programs[1]);
    Renumber(reordered);
    BOOST_REQUIRE(cb::ValidateProgramTable(reordered, &why));
    BOOST_CHECK(!ProgramRootMatchesV1(
        reordered, manifest.program_root));
}

BOOST_AUTO_TEST_CASE(
    raw_goldilocks_alias_root_rewrite_and_cap_plus_one_reject)
{
    cb::ProgramTable honest;
    ManifestV1 manifest;
    std::string why;
    BOOST_REQUIRE(
        BuildCanonicalProgramTableV1(honest, &manifest, &why));

    auto noncanonical = honest;
    bool changed = false;
    for (auto& program : noncanonical.programs) {
        for (auto& in : program.instructions) {
            if (in.opcode == cb::Opcode::Constant &&
                gf::IsZero(in.constant)) {
                in.constant.c0 = gf::kP;
                changed = true;
                break;
            }
        }
        if (changed) break;
    }
    BOOST_REQUIRE(changed);
    // The generic codec canonicalizes Fp3 on serialization.  The normalized
    // verifier's strict assessment must reject this raw x+p alias first.
    BOOST_CHECK(cb::ValidateProgramTable(noncanonical, &why));
    const auto canonicality = AssessProgramTableV1(
        noncanonical, std::numeric_limits<uint32_t>::max());
    BOOST_CHECK(!canonicality.canonical_field_encodings);
    BOOST_CHECK(
        canonicality.residual_mask &
        kResidualNoncanonicalFieldEncoding);
    BOOST_CHECK(!ProgramRootMatchesV1(
        noncanonical, manifest.program_root));

    auto rewritten_root = manifest.program_root;
    rewritten_root[0] =
        gf::Add(rewritten_root[0], gf::FromU64(1));
    BOOST_CHECK(!SameDigest(rewritten_root, manifest.program_root));
    BOOST_CHECK(!ProgramRootMatchesV1(honest, rewritten_root));
    BOOST_CHECK(ProgramRootMatchesV1(
        honest, manifest.program_root));

    BOOST_REQUIRE_GT(manifest.instruction_count, 0U);
    BOOST_REQUIRE_LE(
        manifest.instruction_count,
        uint64_t{std::numeric_limits<uint32_t>::max()});
    const auto cap_plus_one = AssessProgramTableV1(
        honest,
        static_cast<uint32_t>(manifest.instruction_count - 1));
    BOOST_CHECK_EQUAL(
        cap_plus_one.instruction_count,
        uint64_t{cap_plus_one.fixedpoint_instruction_cap} + 1);
    BOOST_CHECK(!cap_plus_one.instruction_cap_fits);
    BOOST_CHECK(
        cap_plus_one.residual_mask &
        kResidualFixedPointInstructionCap);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_multirow_v11_normalized_program
