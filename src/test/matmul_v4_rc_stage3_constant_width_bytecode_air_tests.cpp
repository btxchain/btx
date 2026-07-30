// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_constant_width_bytecode_air.h>
#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>
#include <matmul/matmul_v4_rc_stage3_role_bytecode.h>

#include <algorithm>
#include <chrono>

namespace matmul::v4::rc::constant_width_bytecode_air {
namespace {

namespace aq = air_quotient;
namespace ss = soundness_scenarios;
namespace ut = universal_topology;

bool DigestEqual(
    const alg_hash::Digest& a,
    const alg_hash::Digest& b)
{
    for (uint32_t i = 0; i < a.size(); ++i) {
        if (gf::Canonical(a[i]) !=
            gf::Canonical(b[i])) {
            return false;
        }
    }
    return true;
}

size_t ProofBytes(const ProofV1& proof)
{
    std::vector<unsigned char> encoded;
    const size_t bytes =
        vm::SerializeFamilyVmProofV1(
            proof.family, encoded);
    BOOST_REQUIRE_EQUAL(bytes, encoded.size());
    BOOST_REQUIRE_NE(bytes, 0U);
    return bytes;
}

const char* ProductionKindName(
    ss::ProductionProofSiteKind kind)
{
    using K = ss::ProductionProofSiteKind;
    switch (kind) {
    case K::EpisodeBuilderCounterXof:
        return "EpisodeBuilderCounterXof";
    case K::EpisodeGemmSumcheck:
        return "EpisodeGemmSumcheck";
    case K::EpisodeGemmOpenings:
        return "EpisodeGemmOpenings";
    case K::EpisodeSignedRange:
        return "EpisodeSignedRange";
    case K::EpisodeRangeExtractCtl:
        return "EpisodeRangeExtractCtl";
    case K::EpisodeExtractCore:
        return "EpisodeExtractCore";
    case K::EpisodeScaleSha:
        return "EpisodeScaleSha";
    case K::EpisodeExtractChaCha:
        return "EpisodeExtractChaCha";
    case K::EpisodeWiring:
        return "EpisodeWiring";
    case K::EpisodeTileTreeSha256d:
        return "EpisodeTileTreeSha256d";
    case K::EpisodeDigestSha256d:
        return "EpisodeDigestSha256d";
    case K::CoupledBankCounterXof:
        return "CoupledBankCounterXof";
    case K::CoupledBankCommitmentSha256d:
        return "CoupledBankCommitmentSha256d";
    case K::CoupledBank:
        return "CoupledBank";
    case K::CoupledLobeInitCounterXof:
        return "CoupledLobeInitCounterXof";
    case K::CoupledPageScheduleXof:
        return "CoupledPageScheduleXof";
    case K::CoupledGemm:
        return "CoupledGemm";
    case K::CoupledExchange:
        return "CoupledExchange";
    case K::CoupledExchangeXof:
        return "CoupledExchangeXof";
    case K::CoupledPermutation:
        return "CoupledPermutation";
    case K::CoupledPermutationXof:
        return "CoupledPermutationXof";
    case K::CoupledMix:
        return "CoupledMix";
    case K::CoupledMixXof:
        return "CoupledMixXof";
    case K::CoupledExtractCore:
        return "CoupledExtractCore";
    case K::CoupledExtractScaleSha:
        return "CoupledExtractScaleSha";
    case K::CoupledExtractChaCha:
        return "CoupledExtractChaCha";
    case K::CoupledBarrierSha256d:
        return "CoupledBarrierSha256d";
    case K::CoupledDigestSha256d:
        return "CoupledDigestSha256d";
    }
    return "Unknown";
}

gf::Fp PowBase(gf::Fp base, uint64_t exponent)
{
    gf::Fp out = 1;
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

gf::Fp3 Pow3(gf::Fp3 base, uint32_t exponent)
{
    gf::Fp3 out = gf::Fp3::One();
    while (exponent != 0) {
        if ((exponent & 1U) != 0) {
            out = gf::Mul(out, base);
        }
        base = gf::Mul(base, base);
        exponent >>= 1;
    }
    return out;
}

rba::QuotientDomainV1 Domain()
{
    rba::QuotientDomainV1 out;
    out.trace_rows = 4;
    out.evaluation_rows = 16;
    out.evaluation_omega =
        gf::Fp3::FromFp(
            PowBase(
                UINT64_C(0x185629dcda58878c),
                uint64_t{1} << 28));
    out.trace_omega =
        Pow3(out.evaluation_omega, 4);
    out.coset_shift =
        gf::FromU64_3(7);
    return out;
}

gf::Fp3 Selector(
    aq::AirKind kind,
    const rba::QuotientDomainV1& domain,
    const gf::Fp3& z)
{
    const gf::Fp3 zh =
        gf::Sub(
            Pow3(z, domain.trace_rows),
            gf::Fp3::One());
    const gf::Fp3 h_last =
        gf::Inv(domain.trace_omega);
    switch (kind) {
    case aq::AirKind::kEverywhere:
        return gf::Fp3::One();
    case aq::AirKind::kTransition:
        return gf::Sub(z, h_last);
    case aq::AirKind::kFirstRow:
        return gf::Mul(
            zh,
            gf::Inv(
                gf::Sub(
                    z, gf::Fp3::One())));
    case aq::AirKind::kLastRow:
        return gf::Mul(
            zh,
            gf::Inv(gf::Sub(z, h_last)));
    }
    return gf::Fp3::Zero();
}

void RecomputeQuotient(
    const cb::ProgramTable& table,
    const rba::QuotientDomainV1& domain,
    rba::QuotientOpeningRowV1& row,
    const std::vector<gf::Fp3>& challenges = {})
{
    gf::Fp3 weighted = gf::Fp3::Zero();
    gf::Fp3 power = gf::Fp3::One();
    for (const auto& program : table.programs) {
        gf::Fp3 terminal;
        if (table.challenge_width == 0) {
            BOOST_REQUIRE(
                cb::EvaluateProgram(
                    program, row.current,
                    row.next, terminal));
        } else {
            BOOST_REQUIRE_EQUAL(
                challenges.size(),
                table.challenge_width);
            BOOST_REQUIRE(
                cb::EvaluateProgram(
                    program, row.current,
                    row.next, challenges,
                    terminal));
        }
        weighted = gf::Add(
            weighted,
            gf::Mul(
                power,
                gf::Mul(
                    Selector(
                        program.kind,
                        domain,
                        row.evaluation_point),
                    terminal)));
        power = gf::Mul(
            power, row.constraint_lambda);
    }
    const gf::Fp3 zh =
        gf::Sub(
            Pow3(
                row.evaluation_point,
                domain.trace_rows),
            gf::Fp3::One());
    row.quotient_opening =
        gf::Mul(weighted, gf::Inv(zh));
}

std::vector<OpeningRowV1>
ChallengeRows(
    const cb::ProgramTable& table,
    const rba::QuotientDomainV1& domain,
    uint32_t count)
{
    std::vector<OpeningRowV1> out;
    std::vector<gf::Fp3> challenges(
        table.challenge_width);
    for (uint32_t column = 0;
         column < challenges.size(); ++column) {
        challenges[column] =
            gf::FromU64_3(17 + 6 * column);
    }
    for (uint32_t ordinal = 0;
         ordinal < count; ++ordinal) {
        OpeningRowV1 owned;
        auto& row = owned.quotient;
        row.current.resize(table.current_width);
        row.next.resize(table.next_width);
        for (uint32_t column = 0;
             column < row.current.size();
             ++column) {
            row.current[column] =
                gf::FromU64_3(
                    3 + ordinal * 31 + column);
        }
        for (uint32_t column = 0;
             column < row.next.size();
             ++column) {
            row.next[column] =
                gf::FromU64_3(
                    109 + ordinal * 37 + column);
        }
        row.constraint_lambda =
            gf::FromU64_3(41 + ordinal);
        row.query_index = 1 + 2 * ordinal;
        row.evaluation_point =
            gf::Mul(
                domain.coset_shift,
                Pow3(
                    domain.evaluation_omega,
                    row.query_index));
        row.next_evaluation_point =
            gf::Mul(
                domain.trace_omega,
                row.evaluation_point);
        owned.verifier_challenges =
            challenges;
        RecomputeQuotient(
            table, domain, row,
            owned.verifier_challenges);
        out.push_back(std::move(owned));
    }
    return out;
}

std::vector<rba::QuotientOpeningRowV1>
Rows(
    const cb::ProgramTable& table,
    const rba::QuotientDomainV1& domain,
    uint32_t count)
{
    std::vector<rba::QuotientOpeningRowV1> out;
    for (uint32_t ordinal = 0;
         ordinal < count; ++ordinal) {
        rba::QuotientOpeningRowV1 row;
        row.current.resize(
            table.current_width);
        row.next.resize(table.next_width);
        for (uint32_t column = 0;
             column < row.current.size();
             ++column) {
            row.current[column] =
                gf::FromU64_3(
                    2 + ordinal * 17 + column);
        }
        for (uint32_t column = 0;
             column < row.next.size();
             ++column) {
            row.next[column] =
                gf::FromU64_3(
                    101 + ordinal * 19 + column);
        }
        row.constraint_lambda =
            gf::FromU64_3(29 + ordinal);
        row.query_index =
            1 + 2 * ordinal;
        row.evaluation_point =
            gf::Mul(
                domain.coset_shift,
                Pow3(
                    domain.evaluation_omega,
                    row.query_index));
        row.next_evaluation_point =
            gf::Mul(
                domain.trace_omega,
                row.evaluation_point);
        RecomputeQuotient(
            table, domain, row);
        out.push_back(std::move(row));
    }
    return out;
}

cb::ProgramTable PowTable()
{
    cb::ProgramTable out;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3EpisodePowProgramTable(
            out, &why),
        why);
    return out;
}

cb::ProgramTable LargeTable()
{
    cb::ProgramTable out;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3ExtractMixProgramTable(
            RCStage3RelationRole::EpisodeExtract,
            out, &why),
        why);
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_constant_width_bytecode_air_tests)

BOOST_AUTO_TEST_CASE(
    production_tables_compile_to_identical_53_column_vm)
{
    const auto domain = Domain();
    const auto pow = PowTable();
    const auto large = LargeTable();
    const auto pow_compiled =
        CompileConstantWidthQuotientProgramV1(
            pow,
            cb::CommitProgramTableAlgHash(pow),
            domain, 192);
    const auto large_compiled =
        CompileConstantWidthQuotientProgramV1(
            large,
            cb::CommitProgramTableAlgHash(large),
            domain, 192);
    BOOST_REQUIRE_MESSAGE(
        pow_compiled.valid,
        pow_compiled.note);
    BOOST_REQUIRE_MESSAGE(
        large_compiled.valid,
        large_compiled.note);
    BOOST_CHECK_EQUAL(
        pow_compiled.padded_rows, 256U);
    BOOST_CHECK_EQUAL(
        large_compiled.padded_rows, 256U);
    BOOST_CHECK_EQUAL(
        pow_compiled.physical_columns,
        vm::kFamilyVmExecutableColumnsV1);
    BOOST_CHECK_EQUAL(
        large_compiled.physical_columns,
        pow_compiled.physical_columns);
    BOOST_CHECK_GT(
        large.current_width,
        pow.current_width * 4U);
    BOOST_CHECK_GT(
        large_compiled.original_instructions,
        pow_compiled.original_instructions * 4U);
    BOOST_CHECK(
        pow_compiled.current_next_sources_disjoint);
    BOOST_CHECK(
        large_compiled.current_next_sources_disjoint);
    BOOST_CHECK(
        pow_compiled.query_point_derived_from_index);
    BOOST_CHECK(
        pow_compiled.selector_derivation_compiled);
    BOOST_CHECK(
        pow_compiled.terminal_lambda_fold_compiled);
    BOOST_CHECK(
        pow_compiled.quotient_identity_compiled);
    BOOST_CHECK(
        pow_compiled.canonical_padding_schedule_compiled);
}

BOOST_AUTO_TEST_CASE(
    all_28_production_tables_have_exact_q192_capacity_inventory)
{
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto sources =
        ut::BuildProductionFamilyProgramSourcesV1(
            manifest);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ut::ValidateProductionFamilyProgramSourcesV1(
            manifest, sources, &why),
        why);
    BOOST_REQUIRE_EQUAL(sources.size(), 28U);

    const auto domain = Domain();
    uint32_t maximum_source_columns = 0;
    uint32_t maximum_original_width = 0;
    uint32_t maximum_segments = 0;
    uint64_t maximum_logical_rows = 0;
    for (const auto& source : sources) {
        const auto key =
            cb::CommitProgramTableAlgHash(
                source.program);
        const auto capacity =
            AssessVerticalVmCapacityV1(
                source.program, key,
                domain, 192);
        BOOST_REQUIRE_MESSAGE(
            capacity.valid,
            std::string(
                ProductionKindName(source.kind)) +
                ": " + capacity.note);
        const auto compiled =
            CompileConstantWidthQuotientProgramV1(
                source.program, key,
                domain, 192);
        BOOST_REQUIRE(compiled.valid);
        const auto family_plan =
            vm::BuildFamilyVmPlanV1(
                compiled.compiled_table,
                compiled.padded_rows);
        BOOST_REQUIRE_MESSAGE(
            family_plan.valid,
            family_plan.note);
        BOOST_CHECK_EQUAL(
            capacity.logical_vertical_rows,
            family_plan.logical_vertical_rows);
        BOOST_CHECK_EQUAL(
            capacity.padded_vertical_rows,
            family_plan.padded_vertical_rows);
        BOOST_CHECK_EQUAL(
            capacity.minimum_vm_segments,
            family_plan.minimum_vm_segments);
        BOOST_CHECK_EQUAL(
            capacity.fits_unsegmented_split_rap,
            family_plan.fits_single_split_rap);
        BOOST_CHECK_EQUAL(
            capacity.semantic_rows, 192U);
        BOOST_CHECK_EQUAL(
            capacity.padded_source_rows, 256U);
        BOOST_CHECK_EQUAL(
            capacity.physical_columns,
            vm::kFamilyVmExecutableColumnsV1);
        BOOST_CHECK_GE(
            capacity.minimum_vm_segments, 1U);
        BOOST_CHECK(
            !capacity.ordered_segment_roots_constrained);
        BOOST_CHECK(
            !capacity.boundary_machine_state_constrained);
        BOOST_CHECK(
            !capacity.terminal_segment_fold_constrained);
        BOOST_CHECK(
            !capacity.segmented_vertical_vm_executable);
        maximum_original_width =
            std::max(
                maximum_original_width,
                source.program.current_width);
        maximum_source_columns =
            std::max(
                maximum_source_columns,
                capacity.source_columns);
        maximum_segments =
            std::max(
                maximum_segments,
                capacity.minimum_vm_segments);
        maximum_logical_rows =
            std::max(
                maximum_logical_rows,
                capacity.logical_vertical_rows);
        BOOST_TEST_MESSAGE(
            "Q192 capacity family="
            << source.family_index
            << " kind="
            << ProductionKindName(source.kind)
            << " original_width="
            << source.program.current_width
            << " source_columns="
            << capacity.source_columns
            << " compiled_programs="
            << capacity.compiled_programs
            << " compiled_instructions="
            << capacity.compiled_instructions
            << " logical_rows="
            << capacity.logical_vertical_rows
            << " padded_rows="
            << capacity.padded_vertical_rows
            << " minimum_segments="
            << capacity.minimum_vm_segments
            << " fits_unsegmented="
            << capacity.fits_unsegmented_split_rap);
    }
    BOOST_TEST_MESSAGE(
        "Q192 capacity summary families="
        << sources.size()
        << " physical_columns="
        << vm::kFamilyVmExecutableColumnsV1
        << " maximum_original_width="
        << maximum_original_width
        << " maximum_source_columns="
        << maximum_source_columns
        << " maximum_logical_rows="
        << maximum_logical_rows
        << " coefficient_cap="
        << vm::kFamilyVmCoefficientCapV1
        << " maximum_minimum_segments="
        << maximum_segments
        << " segmentation_executable=0");
    BOOST_CHECK_EQUAL(maximum_segments, 1U);
}

BOOST_AUTO_TEST_CASE(
    real_pow_table_proof_and_program_tape_order_quotient_attacks)
{
    const auto domain = Domain();
    const auto table = PowTable();
    const auto key =
        cb::CommitProgramTableAlgHash(table);
    const auto rows = Rows(table, domain, 3);
    const uint256 seed = uint256::ONE;
    const uint256 registry = uint256::ONE;
    const auto prove_start =
        std::chrono::steady_clock::now();
    const auto proved =
        ProveConstantWidthBytecodeQuotientV1(
            table, key, domain, rows,
            29, registry, seed);
    const auto prove_ms =
        std::chrono::duration_cast<
            std::chrono::milliseconds>(
                std::chrono::steady_clock::now() -
                prove_start).count();
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    const auto verify_start =
        std::chrono::steady_clock::now();
    const auto audit =
        VerifyConstantWidthBytecodeQuotientV1(
            table, proved.public_inputs,
            proved.proof, seed);
    const auto verify_us =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
                std::chrono::steady_clock::now() -
                verify_start).count();
    BOOST_REQUIRE_MESSAGE(
        audit.valid, audit.note);
    BOOST_TEST_MESSAGE(
        "constant-width PoW proof_bytes="
        << ProofBytes(proved.proof)
        << " prove_ms=" << prove_ms
        << " verify_us=" << verify_us);
    BOOST_CHECK_EQUAL(
        audit.semantic_rows, 3U);
    BOOST_CHECK_EQUAL(
        audit.padded_rows, 4U);
    BOOST_CHECK_EQUAL(
        audit.physical_columns,
        vm::kFamilyVmExecutableColumnsV1);
    BOOST_CHECK(
        audit.caller_selected_program_key);
    BOOST_CHECK(
        audit.compiled_program_key_canonical);
    BOOST_CHECK(
        audit.current_next_source_cells_disjoint);
    BOOST_CHECK(
        audit.query_index_to_evaluation_point_in_vm);
    BOOST_CHECK(
        audit.selector_derivation_in_vm);
    BOOST_CHECK(
        audit.terminal_lambda_fold_in_vm);
    BOOST_CHECK(
        audit.quotient_vanishing_identity_in_vm);
    BOOST_CHECK(
        audit.canonical_padding_schedule_in_vm);
    BOOST_CHECK(
        audit.ordered_vm_phase0_root_exact);
    BOOST_CHECK(
        audit.split_rap_quotient_fri_verified);
    BOOST_CHECK(
        audit.constant_width_universal);
    BOOST_CHECK(!audit.registry_membership_proved);
    BOOST_CHECK(
        audit.challenge_loads_from_dedicated_tape);
    BOOST_CHECK(
        audit.challenge_tape_constant_across_active_rows);
    BOOST_CHECK(
        !audit.challenge_tape_owned_by_parent_fs);
    BOOST_CHECK(
        !audit.segmented_vertical_vm_executable);
    BOOST_CHECK(
        !audit.source_cells_owned_by_parent_pcs);
    BOOST_CHECK(
        !audit.query_schedule_owned_by_parent_fs);
    BOOST_CHECK(
        !audit.recursive_parent_consumes_this_verifier);
    BOOST_CHECK(!audit.recursive_fixed_point);
    BOOST_CHECK(!audit.production_authority_ready);

    // Program-key attack.
    {
        auto bad = proved.public_inputs;
        bad.selected_program_key[0] =
            gf::Add(
                bad.selected_program_key[0],
                gf::Fp(1));
        BOOST_CHECK(
            !VerifyConstantWidthBytecodeQuotientV1(
                 table, bad, proved.proof,
                 seed).valid);
    }
    // Opcode substitution in a still-canonical source table.
    {
        auto changed = table;
        auto& boolean =
            changed.programs.front();
        BOOST_REQUIRE(
            boolean.instructions.back().opcode ==
            cb::Opcode::Mul);
        boolean.instructions.back().opcode =
            cb::Opcode::Add;
        boolean.declared_degree = 1;
        BOOST_REQUIRE(
            cb::ValidateProgramTable(changed));
        BOOST_CHECK(
            !VerifyConstantWidthBytecodeQuotientV1(
                 changed,
                 proved.public_inputs,
                 proved.proof, seed).valid);
    }
    // A canonical compiled-program register route change is rejected by the
    // real FamilyVM verifier. Swapping the operands of a Sub preserves every
    // register-use multiplicity, so a multiset-only register check cannot
    // detect it; the canonical program key/schedule binding must.
    {
        const auto compiled =
            CompileConstantWidthQuotientProgramV1(
                table, key, domain,
                static_cast<uint32_t>(
                    rows.size()));
        BOOST_REQUIRE(compiled.valid);
        auto rerouted =
            compiled.compiled_table;
        bool changed = false;
        for (auto& program : rerouted.programs) {
            for (auto& instruction :
                 program.instructions) {
                if (instruction.opcode ==
                        cb::Opcode::Sub &&
                    instruction.lhs !=
                        instruction.rhs) {
                    std::swap(
                        instruction.lhs,
                        instruction.rhs);
                    changed = true;
                    break;
                }
            }
            if (changed) break;
        }
        BOOST_REQUIRE(changed);
        BOOST_REQUIRE(
            cb::ValidateProgramTable(rerouted));
        BOOST_CHECK(
            !DigestEqual(
                cb::CommitProgramTableAlgHash(
                    rerouted),
                compiled.compiled_program_key));
        BOOST_CHECK(
            !vm::VerifyFamilyVmV1(
                 rerouted,
                 proved.public_inputs.family,
                 proved.proof.family,
                 seed).valid);
    }
    // Proof-level source-tape mutation: a different valid quotient proof has
    // a different ordered R0 root and cannot be spliced under the old public
    // inputs.
    {
        auto changed_rows = rows;
        changed_rows[1].current[0] =
            gf::Add(
                changed_rows[1].current[0],
                gf::Fp3::One());
        RecomputeQuotient(
            table, domain, changed_rows[1]);
        const auto changed =
            ProveConstantWidthBytecodeQuotientV1(
                table, key, domain,
                changed_rows, 29,
                registry, seed);
        BOOST_REQUIRE(changed.ok);
        BOOST_CHECK(
            changed.public_inputs
                .ordered_vm_phase0_root !=
            proved.public_inputs
                .ordered_vm_phase0_root);
        BOOST_CHECK(
            !VerifyConstantWidthBytecodeQuotientV1(
                 table,
                 proved.public_inputs,
                 changed.proof, seed).valid);
    }
    // Proof-level order attack: each row is individually valid, but swapping
    // two authenticated query rows changes the phase-0 root.
    {
        auto reordered = rows;
        std::swap(reordered[0], reordered[1]);
        const auto changed =
            ProveConstantWidthBytecodeQuotientV1(
                table, key, domain,
                reordered, 29,
                registry, seed);
        BOOST_REQUIRE(changed.ok);
        BOOST_CHECK(
            changed.public_inputs
                .ordered_vm_phase0_root !=
            proved.public_inputs
                .ordered_vm_phase0_root);
        BOOST_CHECK(
            !VerifyConstantWidthBytecodeQuotientV1(
                 table,
                 proved.public_inputs,
                 changed.proof, seed).valid);
    }
    // Quotient mismatch cannot produce a proof.
    {
        auto bad = rows;
        bad[0].quotient_opening =
            gf::Add(
                bad[0].quotient_opening,
                gf::Fp3::One());
        BOOST_CHECK(
            !ProveConstantWidthBytecodeQuotientV1(
                 table, key, domain, bad,
                 29, registry, seed).ok);
    }
    // Query-index/tape mismatch cannot produce a proof.
    {
        auto bad = rows;
        ++bad[0].query_index;
        BOOST_CHECK(
            !ProveConstantWidthBytecodeQuotientV1(
                 table, key, domain, bad,
                 29, registry, seed).ok);
    }
    // A canonical codec-level proof mutation reaches the real verifier.
    {
        std::vector<unsigned char> wire;
        BOOST_REQUIRE(
            vm::SerializeFamilyVmProofV1(
                proved.proof.family,
                wire) > 0);
        wire.back() ^= 1U;
        const auto decoded =
            vm::DeserializeFamilyVmProofV1(wire);
        BOOST_REQUIRE(decoded.has_value());
        auto bad = proved.proof;
        bad.family = *decoded;
        BOOST_CHECK(
            !VerifyConstantWidthBytecodeQuotientV1(
                 table, proved.public_inputs,
                 bad, seed).valid);
    }
}

BOOST_AUTO_TEST_CASE(
    substantially_larger_production_table_proves_at_same_width)
{
    const auto domain = Domain();
    const auto table = LargeTable();
    const auto key =
        cb::CommitProgramTableAlgHash(table);
    const auto rows = Rows(table, domain, 1);
    const auto prove_start =
        std::chrono::steady_clock::now();
    const auto proved =
        ProveConstantWidthBytecodeQuotientV1(
            table, key, domain, rows,
            41, uint256::ONE,
            uint256::ONE);
    const auto prove_ms =
        std::chrono::duration_cast<
            std::chrono::milliseconds>(
                std::chrono::steady_clock::now() -
                prove_start).count();
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    const auto verify_start =
        std::chrono::steady_clock::now();
    const auto audit =
        VerifyConstantWidthBytecodeQuotientV1(
            table, proved.public_inputs,
            proved.proof, uint256::ONE);
    const auto verify_us =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
                std::chrono::steady_clock::now() -
                verify_start).count();
    BOOST_REQUIRE_MESSAGE(
        audit.valid, audit.note);
    BOOST_TEST_MESSAGE(
        "constant-width large proof_bytes="
        << ProofBytes(proved.proof)
        << " prove_ms=" << prove_ms
        << " verify_us=" << verify_us);
    BOOST_CHECK_EQUAL(
        audit.physical_columns,
        vm::kFamilyVmExecutableColumnsV1);
    BOOST_CHECK_GT(
        audit.original_programs, 50U);
    BOOST_CHECK_GT(
        audit.original_instructions, 500U);
    BOOST_CHECK(
        !audit.production_authority_ready);
}

BOOST_AUTO_TEST_CASE(
    verifier_challenge_tape_executes_but_parent_ownership_stays_false)
{
    cb::ProgramTable table;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildRCStage3CoupledPermutationTransportProgramTable(
            table, &why),
        why);
    BOOST_REQUIRE_GT(table.challenge_width, 0U);
    const auto domain = Domain();
    const auto key =
        cb::CommitProgramTableAlgHash(table);
    const auto compiled =
        CompileConstantWidthQuotientProgramV1(
            table, key, domain, 192);
    BOOST_REQUIRE_MESSAGE(
        compiled.valid, compiled.note);
    BOOST_CHECK(!compiled.challenge_free_source_table);
    BOOST_CHECK(
        compiled.challenge_loads_use_dedicated_tape);
    BOOST_CHECK(
        compiled.challenge_tape_constant_compiled);
    BOOST_CHECK_EQUAL(
        compiled.physical_columns,
        vm::kFamilyVmExecutableColumnsV1);

    const auto rows =
        ChallengeRows(table, domain, 2);
    const auto prove_start =
        std::chrono::steady_clock::now();
    const auto proved =
        ProveConstantWidthBytecodeQuotientV1(
            table, key, domain, rows,
            53, uint256::ONE,
            uint256::ONE);
    const auto prove_ms =
        std::chrono::duration_cast<
            std::chrono::milliseconds>(
                std::chrono::steady_clock::now() -
                prove_start).count();
    BOOST_REQUIRE_MESSAGE(
        proved.ok, proved.note);
    const auto verify_start =
        std::chrono::steady_clock::now();
    const auto audit =
        VerifyConstantWidthBytecodeQuotientV1(
            table, proved.public_inputs,
            proved.proof, uint256::ONE);
    const auto verify_us =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
                std::chrono::steady_clock::now() -
                verify_start).count();
    BOOST_REQUIRE_MESSAGE(
        audit.valid, audit.note);
    BOOST_TEST_MESSAGE(
        "constant-width challenge proof_bytes="
        << ProofBytes(proved.proof)
        << " prove_ms=" << prove_ms
        << " verify_us=" << verify_us);
    BOOST_CHECK(
        audit.challenge_loads_from_dedicated_tape);
    BOOST_CHECK(
        audit.challenge_tape_constant_across_active_rows);
    BOOST_CHECK(
        !audit.challenge_tape_owned_by_parent_fs);
    BOOST_CHECK(
        !audit.source_cells_owned_by_parent_pcs);
    BOOST_CHECK(
        !audit.recursive_parent_consumes_this_verifier);

    // A prover cannot use a different "verifier" challenge on one active
    // query row, even after recomputing a locally consistent quotient.
    auto split_challenge = rows;
    split_challenge[1].verifier_challenges[0] =
        gf::Add(
            split_challenge[1]
                .verifier_challenges[0],
            gf::Fp3::One());
    RecomputeQuotient(
        table, domain,
        split_challenge[1].quotient,
        split_challenge[1]
            .verifier_challenges);
    BOOST_CHECK(
        !ProveConstantWidthBytecodeQuotientV1(
             table, key, domain,
             split_challenge, 53,
             uint256::ONE,
             uint256::ONE).ok);

    // A different globally-constant challenge tape can make a valid proof,
    // but its ordered R0 root differs and the proof cannot be transplanted
    // under the original public statement.
    auto alternate_challenge = rows;
    for (auto& row : alternate_challenge) {
        row.verifier_challenges[0] =
            gf::Add(
                row.verifier_challenges[0],
                gf::Fp3::One());
        RecomputeQuotient(
            table, domain,
            row.quotient,
            row.verifier_challenges);
    }
    const auto alternate =
        ProveConstantWidthBytecodeQuotientV1(
            table, key, domain,
            alternate_challenge, 53,
            uint256::ONE,
            uint256::ONE);
    BOOST_REQUIRE_MESSAGE(
        alternate.ok, alternate.note);
    BOOST_CHECK(
        alternate.public_inputs
            .ordered_vm_phase0_root !=
        proved.public_inputs
            .ordered_vm_phase0_root);
    BOOST_CHECK(
        !VerifyConstantWidthBytecodeQuotientV1(
             table, proved.public_inputs,
             alternate.proof,
             uint256::ONE).valid);

    // Merely relabelling a Challenge load as a prover-owned Current load is a
    // distinct canonical program key, not an accepted compatibility path.
    auto relabelled = table;
    relabelled.challenge_width = 0;
    for (auto& program : relabelled.programs) {
        program.challenge_width = 0;
        for (auto& instruction :
             program.instructions) {
            if (instruction.opcode ==
                cb::Opcode::Challenge) {
                instruction.opcode =
                    cb::Opcode::Current;
            }
        }
    }
    BOOST_REQUIRE(
        cb::ValidateProgramTable(relabelled));
    BOOST_CHECK(
        !DigestEqual(
            cb::CommitProgramTableAlgHash(table),
            cb::CommitProgramTableAlgHash(
                relabelled)));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::constant_width_bytecode_air
