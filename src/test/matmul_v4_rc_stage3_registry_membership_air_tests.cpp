// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>
#include <matmul/matmul_v4_rc_stage3_registry_membership_air.h>

#include <algorithm>
#include <chrono>
#include <limits>

namespace matmul::v4::rc::stage3_registry_membership_air {
namespace {

namespace cb = constraint_bytecode;
namespace ss = soundness_scenarios;
namespace sch = aggregation_scheduler;

cb::ProgramTable OneColumnProgram(RCStage3RelationRole role)
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
        {cb::Opcode::Current, 0, 0, gf::Fp3::Zero()});
    table.programs.push_back(std::move(program));
    BOOST_REQUIRE(cb::ValidateProgramTable(table));
    return table;
}

ut::ProductionProgramRegistryV1 Registry()
{
    const auto manifest =
        ss::BuildProductionProofSiteManifest(
            ss::SelectedProductionProofSitePolicy());
    const auto schedule =
        sch::BuildProductionAggregationSchedule(manifest);
    const auto sources =
        ut::BuildProductionFamilyProgramSourcesV1(manifest);
    const auto verifier =
        OneColumnProgram(
            RCStage3RelationRole::CompositionLink);
    auto registry =
        ut::BuildProductionProgramRegistryV1(
            manifest, schedule, sources,
            verifier, verifier);
    BOOST_REQUIRE_EQUAL(
        registry.families.size(),
        ut::kProductionProgramFamilyCountV1);
    BOOST_REQUIRE(
        !registry.external_registry_commitment.IsNull());
    return registry;
}

bool Applies(aq::AirKind kind, uint32_t row, uint32_t rows)
{
    switch (kind) {
    case aq::AirKind::kEverywhere:
        return true;
    case aq::AirKind::kTransition:
        return row + 1 < rows;
    case aq::AirKind::kFirstRow:
        return row == 0;
    case aq::AirKind::kLastRow:
        return row + 1 == rows;
    }
    return false;
}

uint64_t Violations(
    const aq::AirConstraintSystem<gf::Fp3>& cs,
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    if (columns.size() != cs.n_columns) {
        return std::numeric_limits<uint64_t>::max();
    }
    for (const auto& column : columns) {
        if (column.size() != cs.n_rows) {
            return std::numeric_limits<uint64_t>::max();
        }
    }
    std::vector<gf::Fp3> current(cs.n_columns);
    std::vector<gf::Fp3> next(cs.n_columns);
    uint64_t violations = 0;
    for (uint32_t row = 0; row < cs.n_rows; ++row) {
        const uint32_t next_row = (row + 1) % cs.n_rows;
        for (uint32_t column = 0; column < cs.n_columns; ++column) {
            current[column] = columns[column][row];
            next[column] = columns[column][next_row];
        }
        for (const auto& constraint : cs.constraints) {
            if (Applies(constraint.kind, row, cs.n_rows) &&
                !gf::IsZero(constraint.eval(current, next))) {
                ++violations;
            }
        }
    }
    return violations;
}

bool DigestEqual(
    const alg_hash::Digest& a,
    const alg_hash::Digest& b)
{
    for (uint32_t limb = 0; limb < a.size(); ++limb) {
        if (gf::Canonical(a[limb]) != gf::Canonical(b[limb])) {
            return false;
        }
    }
    return true;
}

size_t ProofBytes(
    const aq::AirQuotientSplitRapRowsProof& proof)
{
    std::vector<unsigned char> bytes;
    const size_t written =
        aq::SerializeAirQuotientSplitRapRowsProof(proof, bytes);
    BOOST_REQUIRE_EQUAL(written, bytes.size());
    BOOST_REQUIRE_NE(written, 0U);
    return written;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_registry_membership_air_tests)

BOOST_AUTO_TEST_CASE(
    exact_registry_poseidon_replay_and_dynamic_selection_are_quadratic)
{
    const auto registry = Registry();
    for (const uint32_t index :
         {uint32_t{0},
          ut::kProductionProgramFamilyCountV1 - 1}) {
        const auto statement =
            BuildStatementV1(registry, index);
        const auto product =
            BuildProductV1(registry, statement);
        BOOST_REQUIRE_MESSAGE(product.valid, product.note);
        BOOST_CHECK_EQUAL(product.violations, 0U);
        BOOST_CHECK(product.exact_28_entry_order);
        BOOST_CHECK(product.exact_registry_alg_hash_replayed);
        BOOST_CHECK(product.preprocessed_values_root_pinned);
        BOOST_CHECK(product.dynamic_one_hot_selection_constrained);
        BOOST_CHECK(product.selected_tuple_constrained);
        BOOST_CHECK(product.u32_absorb_encoding_constrained);
        BOOST_CHECK(product.quadratic_poseidon);
        BOOST_CHECK_LE(product.max_constraint_degree, 2U);
        BOOST_CHECK_EQUAL(product.layout.n_columns, 780U);
        BOOST_CHECK_EQUAL(
            product.preprocessed_base_columns.size(), 22U);
        BOOST_CHECK(
            !product.preprocessed_row_group_root.IsNull());
        BOOST_CHECK(
            !product.recursive_parent_consumes_exports);
        BOOST_CHECK(!product.production_authority_ready);
        BOOST_TEST_MESSAGE(
            "registry-air index=" << index
            << " preimage_lanes=" << product.preimage_lanes
            << " sponge_blocks=" << product.sponge_blocks
            << " trace_rows=" << product.trace_rows
            << " trace_columns=" << product.layout.n_columns
            << " constraints=" << product.constraints
            << " max_degree=" << product.max_constraint_degree);
    }
    const auto first = BuildStatementV1(registry, 0);
    const auto last = BuildStatementV1(
        registry,
        ut::kProductionProgramFamilyCountV1 - 1);
    BOOST_CHECK(
        DigestEqual(
            first.registry_alg_root,
            last.registry_alg_root));
    BOOST_CHECK(
        !(first.selected == last.selected));
}

BOOST_AUTO_TEST_CASE(
    malformed_registry_claims_and_goldilocks_aliases_are_rejected)
{
    const auto registry = Registry();
    const auto statement = BuildStatementV1(registry, 7);
    const auto honest = BuildProductV1(registry, statement);
    BOOST_REQUIRE_MESSAGE(honest.valid, honest.note);

    {
        auto wrong = statement;
        wrong.registry_alg_root[0] =
            gf::Add(
                wrong.registry_alg_root[0],
                gf::FromU64(1));
        const auto product = BuildProductV1(registry, wrong);
        BOOST_CHECK(!product.valid);
        BOOST_CHECK_GT(product.violations, 0U);
    }
    {
        auto wrong = statement;
        wrong.selected.family_index =
            ut::kProductionProgramFamilyCountV1;
        const auto product = BuildProductV1(registry, wrong);
        BOOST_CHECK(!product.valid);
        BOOST_CHECK_GT(product.violations, 0U);
    }
    {
        auto reordered = registry;
        std::swap(reordered.families[0], reordered.families[1]);
        const auto product = BuildProductV1(reordered, statement);
        BOOST_CHECK(!product.valid);
        BOOST_CHECK(!product.exact_28_entry_order);
        BOOST_CHECK_GT(product.violations, 0U);
    }
    {
        auto key = registry;
        key.families[7].program.recursive_alg_hash[0] =
            gf::Add(
                key.families[7]
                    .program.recursive_alg_hash[0],
                gf::FromU64(1));
        const auto product = BuildProductV1(key, statement);
        BOOST_CHECK(!product.valid);
        BOOST_CHECK_GT(product.violations, 0U);
    }
    {
        auto schema = registry;
        schema.families[7]
            .public_input_schema
            .recursive_alg_hash[0] =
            gf::Add(
                schema.families[7]
                    .public_input_schema
                    .recursive_alg_hash[0],
                gf::FromU64(1));
        const auto product = BuildProductV1(schema, statement);
        BOOST_CHECK(!product.valid);
        BOOST_CHECK_GT(product.violations, 0U);
    }
    {
        auto role = registry;
        role.families[7].role =
            registry.families[8].role;
        const auto product = BuildProductV1(role, statement);
        BOOST_CHECK(!product.valid);
        BOOST_CHECK(!product.exact_28_entry_order);
        BOOST_CHECK_GT(product.violations, 0U);
    }
    {
        const auto manifest =
            ss::BuildProductionProofSiteManifest(
                ss::SelectedProductionProofSitePolicy());
        const auto schedule =
            sch::BuildProductionAggregationSchedule(manifest);
        auto sources =
            ut::BuildProductionFamilyProgramSourcesV1(manifest);
        sources[7].program =
            OneColumnProgram(sources[7].role);
        const auto verifier =
            OneColumnProgram(
                RCStage3RelationRole::CompositionLink);
        const auto stubbed =
            ut::BuildProductionProgramRegistryV1(
                manifest, schedule, sources,
                verifier, verifier);
        const auto product =
            BuildProductV1(stubbed, statement);
        BOOST_CHECK(!product.valid);
        BOOST_CHECK_GT(product.violations, 0U);
    }
    {
        auto columns = honest.columns;
        uint32_t other = statement.selected.family_index == 0 ? 1 : 0;
        columns[honest.layout.selector][other] = gf::Fp3::One();
        for (uint32_t row = 0; row < honest.trace_rows; ++row) {
            uint32_t count = 0;
            for (uint32_t prior = 0; prior < row; ++prior) {
                count += !gf::IsZero(
                    columns[honest.layout.selector][prior]);
            }
            columns[honest.layout.selector_prefix][row] =
                gf::FromU64_3(count);
        }
        BOOST_CHECK_GT(
            Violations(honest.cs, columns), 0U);
    }
    {
        auto columns = honest.columns;
        const uint64_t x =
            gf::Canonical(
                columns[honest.layout.Absorb(0)][0].c0);
        // Goldilocks p == 1 (mod 2^32): decompose x+p as a raw u64.
        // Its low 32 bits differ from x by one, while FromU64(x+p)
        // aliases x. The pinned u32 recomposition therefore rejects it.
        const unsigned __int128 alias =
            static_cast<unsigned __int128>(x) +
            static_cast<unsigned __int128>(gf::kP);
        const uint32_t low =
            static_cast<uint32_t>(alias);
        for (uint32_t bit = 0;
             bit < kRegistryAbsorbBitsV1;
             ++bit) {
            columns[
                honest.layout.AbsorbBit(0, bit)][0] =
                ((low >> bit) & 1U) != 0
                ? gf::Fp3::One()
                : gf::Fp3::Zero();
        }
        BOOST_CHECK_GT(
            Violations(honest.cs, columns), 0U);
    }
}

BOOST_AUTO_TEST_CASE(
    split_rap_registry_proof_verifies_and_rejects_root_and_wire_tampering)
{
    const auto registry = Registry();
    const auto statement = BuildStatementV1(registry, 17);
    const auto prove_start = std::chrono::steady_clock::now();
    const auto proved =
        ProveV1(registry, statement, uint256::ONE);
    const auto prove_ms =
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - prove_start).count();
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);

    const auto verify_start = std::chrono::steady_clock::now();
    const auto audit =
        VerifyV1(
            registry, statement,
            proved.proof, uint256::ONE);
    const auto verify_us =
        std::chrono::duration_cast<std::chrono::microseconds>(
            std::chrono::steady_clock::now() - verify_start).count();
    BOOST_REQUIRE_MESSAGE(audit.valid, audit.note);
    BOOST_CHECK(audit.split_rap_quotient_fri_verified);
    BOOST_CHECK(audit.exact_ordered_preprocessed_root);
    BOOST_CHECK(audit.dynamic_one_hot_selection_verified);
    BOOST_CHECK(audit.family_index_kind_role_bound);
    BOOST_CHECK(audit.program_and_schema_alg_hash_bound);
    BOOST_CHECK(audit.semantic_completeness_bound);
    BOOST_CHECK(
        !audit.recursive_parent_consumes_exports);
    BOOST_CHECK(!audit.production_authority_ready);

    const size_t proof_bytes = ProofBytes(proved.proof);
    BOOST_TEST_MESSAGE(
        "registry-air proof_bytes=" << proof_bytes
        << " prove_ms=" << prove_ms
        << " verify_us=" << verify_us
        << " trace_rows=" << audit.trace_rows
        << " trace_columns=" << audit.trace_columns
        << " constraints=" << audit.constraints);

    {
        const auto product =
            BuildProductV1(registry, statement);
        auto wrong_cs = product.cs;
        wrong_cs.preprocessed_row_group_roots[0]
            .root.begin()[0] ^= 1U;
        std::string why;
        BOOST_CHECK(
            !aq::AirQuotientVerifyRowsSplitRap(
                wrong_cs, proved.proof,
                product.preprocessed_base_columns,
                uint256::ONE, &why));
    }
    {
        std::vector<unsigned char> wire;
        BOOST_REQUIRE(
            aq::SerializeAirQuotientSplitRapRowsProof(
                proved.proof, wire) > 0);
        wire.back() ^= 1U;
        const auto decoded =
            aq::DeserializeAirQuotientSplitRapRowsProof(wire);
        BOOST_REQUIRE(decoded.has_value());
        BOOST_CHECK(
            !VerifyV1(
                 registry, statement,
                 *decoded, uint256::ONE).valid);
    }
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_registry_membership_air
