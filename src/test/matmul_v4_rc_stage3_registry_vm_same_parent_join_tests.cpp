// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_production_family_programs.h>
#include <matmul/matmul_v4_rc_stage3_registry_vm_same_parent_join.h>

#include <algorithm>
#include <chrono>

namespace matmul::v4::rc::stage3_registry_vm_same_parent_join {
namespace {

namespace cb = constraint_bytecode;
namespace ss = soundness_scenarios;
namespace sch = aggregation_scheduler;
namespace ut = universal_topology;

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
    return ut::BuildProductionProgramRegistryV1(
        manifest, schedule, sources,
        verifier, verifier);
}

cwa::PublicInputsV1 QuotientStatement(
    const registry_air::StatementV1& statement)
{
    cwa::PublicInputsV1 out;
    out.program_id =
        statement.selected.family_index;
    out.program_registry_alg_root =
        Fri3AlgDigestToUint256(
            statement.registry_alg_root);
    out.selected_program_key =
        statement.selected.program_alg_hash;
    return out;
}

VmChildStatementV1 Child(
    const registry_air::StatementV1& statement)
{
    return BuildVmChildStatementV1(
        statement, QuotientStatement(statement));
}

uint256 RootWithFirstLimb(uint64_t limb)
{
    uint256 out;
    for (uint32_t byte = 0; byte < 8; ++byte) {
        out.begin()[byte] =
            static_cast<unsigned char>(
                (limb >> (8 * byte)) & 0xffU);
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_registry_vm_same_parent_join_tests)

BOOST_AUTO_TEST_CASE(
    vm_child_consumes_exact_registry_cells_without_bridge_witness)
{
    const auto registry = Registry();
    const auto statement =
        registry_air::BuildStatementV1(registry, 17);
    const auto product =
        registry_air::BuildProductV1(
            registry, statement);
    BOOST_REQUIRE_MESSAGE(product.valid, product.note);
    auto cs = product.cs;
    auto columns = product.columns;
    const auto refs =
        CanonicalRegistryProducerRefsV1(
            product.layout);
    AppendResultV1 appended;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        AppendRegistryVmSameParentJoinV1(
            product, Child(statement), refs,
            cs, columns, appended, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        appended.valid, appended.note);
    BOOST_CHECK(appended.canonical_registry_uint256_encoding);
    BOOST_CHECK(appended.registry_air_source_constraints_resident);
    BOOST_CHECK(appended.exact_cell_aliases);
    BOOST_CHECK(appended.no_value_or_carrier_columns_added);
    BOOST_CHECK_EQUAL(appended.added_columns, 0U);
    BOOST_CHECK_EQUAL(
        appended.added_constraints,
        kRegistryVmDirectAliasesV1);
    BOOST_CHECK_EQUAL(appended.violations, 0U);
    BOOST_CHECK(
        appended.child_program_id_kind_role_consumes_registry_cells);
    BOOST_CHECK(
        appended.child_program_alg_hash_consumes_registry_cells);
    BOOST_CHECK(
        appended.child_schema_alg_hash_consumes_registry_cells);
    BOOST_CHECK(
        appended.child_semantic_completeness_consumes_registry_cell);
    BOOST_CHECK(
        appended.child_registry_root_consumes_registry_cells);
    BOOST_CHECK(
        !appended.complete_vm_child_verifier_same_parent);
    BOOST_CHECK(!appended.unified_root_consumes_bridge);
    BOOST_CHECK(!appended.production_authority_ready);

    const auto prove_start =
        std::chrono::steady_clock::now();
    const auto proved =
        aq::AirQuotientProveRowsSplitRap(
            cs, columns,
            product.preprocessed_base_columns,
            uint256::ONE);
    const auto prove_ms =
        std::chrono::duration_cast<
            std::chrono::milliseconds>(
                std::chrono::steady_clock::now() -
                prove_start).count();
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_CHECK(proved.division_exact);
    const auto verify_start =
        std::chrono::steady_clock::now();
    std::string verify_why;
    BOOST_CHECK_MESSAGE(
        aq::AirQuotientVerifyRowsSplitRap(
            cs, proved.proof,
            product.preprocessed_base_columns,
            uint256::ONE, &verify_why),
        verify_why);
    const auto verify_us =
        std::chrono::duration_cast<
            std::chrono::microseconds>(
                std::chrono::steady_clock::now() -
                verify_start).count();
    std::vector<unsigned char> wire;
    const size_t written =
        aq::SerializeAirQuotientSplitRapRowsProof(
            proved.proof, wire);
    BOOST_REQUIRE_EQUAL(written, wire.size());
    BOOST_REQUIRE_NE(written, 0U);
    BOOST_TEST_MESSAGE(
        "registry-vm-direct-alias proof_bytes="
        << written
        << " prove_ms=" << prove_ms
        << " verify_us=" << verify_us
        << " columns=" << cs.n_columns
        << " added_columns=" << appended.added_columns
        << " constraints=" << cs.constraints.size());
}

BOOST_AUTO_TEST_CASE(
    reordered_refs_family_substitutions_and_noncanonical_roots_reject)
{
    const auto registry = Registry();
    const auto statement =
        registry_air::BuildStatementV1(registry, 17);
    const auto product =
        registry_air::BuildProductV1(
            registry, statement);
    BOOST_REQUIRE(product.valid);
    const auto refs =
        CanonicalRegistryProducerRefsV1(
            product.layout);

    {
        auto reordered = refs;
        std::swap(
            reordered.selected.program_alg_hash.limb[0],
            reordered.selected.program_alg_hash.limb[1]);
        auto cs = product.cs;
        auto columns = product.columns;
        AppendResultV1 appended;
        std::string why;
        BOOST_CHECK(
            !AppendRegistryVmSameParentJoinV1(
                product, Child(statement),
                reordered, cs, columns,
                appended, &why));
    }
    {
        auto noncanonical = Child(statement);
        // p is the x+p encoding of field element x=0. The canonical
        // uint256 decoder rejects it before field embedding.
        noncanonical.quotient
            .program_registry_alg_root =
            RootWithFirstLimb(gf::kP);
        auto cs = product.cs;
        auto columns = product.columns;
        AppendResultV1 appended;
        std::string why;
        BOOST_CHECK(
            !AppendRegistryVmSameParentJoinV1(
                product, noncanonical, refs,
                cs, columns, appended, &why));
    }

    auto expect_mismatch =
        [&](const VmChildStatementV1& bad) {
            auto cs = product.cs;
            auto columns = product.columns;
            AppendResultV1 appended;
            std::string why;
            BOOST_REQUIRE_MESSAGE(
                AppendRegistryVmSameParentJoinV1(
                    product, bad, refs,
                    cs, columns, appended, &why),
                why);
            BOOST_CHECK(!appended.valid);
            BOOST_CHECK_GT(appended.violations, 0U);
            BOOST_CHECK_EQUAL(
                cs.n_columns,
                product.cs.n_columns);
        };

    {
        auto bad = Child(statement);
        ++bad.quotient.program_id;
        expect_mismatch(bad);
    }
    {
        auto bad = Child(statement);
        bad.kind = registry.families[18].kind;
        expect_mismatch(bad);
    }
    {
        auto bad = Child(statement);
        bad.role = registry.families[0].role;
        BOOST_REQUIRE(
            bad.role != statement.selected.role);
        expect_mismatch(bad);
    }
    {
        auto bad = Child(statement);
        bad.quotient.selected_program_key[0] =
            gf::Add(
                bad.quotient.selected_program_key[0],
                gf::FromU64(1));
        expect_mismatch(bad);
    }
    {
        auto bad = Child(statement);
        bad.selected_schema_alg_hash[0] =
            gf::Add(
                bad.selected_schema_alg_hash[0],
                gf::FromU64(1));
        expect_mismatch(bad);
    }
    {
        auto bad = Child(statement);
        bad.semantic_relation_complete =
            !bad.semantic_relation_complete;
        expect_mismatch(bad);
    }
    {
        auto bad = Child(statement);
        const auto decoded =
            Fri3AlgDigestFromUint256(
                bad.quotient
                    .program_registry_alg_root);
        BOOST_REQUIRE(decoded.has_value());
        auto digest = *decoded;
        digest[0] =
            gf::Add(digest[0], gf::FromU64(1));
        bad.quotient.program_registry_alg_root =
            Fri3AlgDigestToUint256(digest);
        expect_mismatch(bad);
    }
}

BOOST_AUTO_TEST_CASE(
    valid_unbridged_fri_proof_of_forged_child_statement_rejects_at_bridge)
{
    const auto registry = Registry();
    const auto statement =
        registry_air::BuildStatementV1(registry, 17);
    const auto product =
        registry_air::BuildProductV1(
            registry, statement);
    BOOST_REQUIRE(product.valid);

    // The registry parent alone has a genuinely valid quotient/FRI proof.
    const auto proved =
        registry_air::ProveV1(
            registry, statement, uint256::ONE);
    BOOST_REQUIRE_MESSAGE(proved.ok, proved.note);
    BOOST_REQUIRE(
        registry_air::VerifyV1(
            registry, statement,
            proved.proof, uint256::ONE).valid);

    // A parent omitting the direct consumer can claim any child program.
    // Once the exact cells are consumed by the child statement constraints,
    // that same valid FRI proof and the forged witness both reject.
    auto forged = Child(statement);
    forged.quotient.selected_program_key[0] =
        gf::Add(
            forged.quotient.selected_program_key[0],
            gf::FromU64(1));
    auto bridged_cs = product.cs;
    auto bridged_columns = product.columns;
    AppendResultV1 appended;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        AppendRegistryVmSameParentJoinV1(
            product, forged,
            CanonicalRegistryProducerRefsV1(
                product.layout),
            bridged_cs, bridged_columns,
            appended, &why),
        why);
    BOOST_CHECK(!appended.valid);
    BOOST_CHECK_GT(appended.violations, 0U);
    BOOST_CHECK(
        !aq::AirQuotientVerifyRowsSplitRap(
            bridged_cs, proved.proof,
            product.preprocessed_base_columns,
            uint256::ONE, &why));

    const auto forged_prove =
        aq::AirQuotientProveRowsSplitRap(
            bridged_cs, bridged_columns,
            product.preprocessed_base_columns,
            uint256::ONE);
    BOOST_CHECK(!forged_prove.ok);
    BOOST_CHECK(!forged_prove.division_exact);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::stage3_registry_vm_same_parent_join
