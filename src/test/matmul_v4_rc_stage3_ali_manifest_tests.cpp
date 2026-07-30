// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_ali_manifest.h>

#include <algorithm>
#include <limits>

namespace ali =
    matmul::v4::rc::stage3_ali_manifest;
namespace cb =
    matmul::v4::rc::constraint_bytecode;
namespace gf = matmul::v4::rc::gkr_field;
namespace sites =
    matmul::v4::rc::soundness_scenarios;
namespace topo =
    matmul::v4::rc::universal_topology;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_ali_manifest_tests)

namespace {

bool DigestZero(const ali::ah::Digest& digest)
{
    return std::all_of(
        digest.begin(), digest.end(),
        [](gf::Fp limb) {
            return limb == 0;
        });
}

void Recommit(ali::ProductionAliManifestV1& manifest)
{
    manifest.commitment =
        ali::ComputeProductionAliManifestCommitmentV1(
            manifest);
}

cb::ProgramTable OneColumnStub(
    matmul::v4::rc::RCStage3RelationRole role)
{
    cb::ProgramTable table;
    table.role = role;
    table.current_width = 1;
    table.next_width = 1;
    cb::Program program;
    program.role = role;
    program.current_width = 1;
    program.next_width = 1;
    program.instructions.push_back({
        cb::Opcode::Current, 0, 0, gf::Fp3::Zero()});
    table.programs.push_back(std::move(program));
    return table;
}

void Recommit(ali::ProductionAliAssessmentV2& assessment)
{
    assessment.commitment =
        ali::ComputeProductionAliAssessmentCommitmentV2(
            assessment);
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_28_family_q192_inventory_is_derived)
{
    const ali::ProductionAliManifestV1 manifest =
        ali::BuildProductionAliManifestV1();
    BOOST_REQUIRE_MESSAGE(
        manifest.local_manifest_complete,
        manifest.note);
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ali::ValidateProductionAliManifestV1(
            manifest, &why),
        why);
    BOOST_REQUIRE_EQUAL(
        manifest.families.size(),
        ali::kProductionAliFamilyCountV1);
    BOOST_CHECK(manifest.exact_28_family_order);
    BOOST_CHECK(manifest.every_source_key_derived);
    BOOST_CHECK(manifest.every_compiled_key_derived);
    BOOST_CHECK(manifest.every_source_non_stub);
    BOOST_CHECK(
        manifest.every_challenge_degree_checked);
    BOOST_CHECK(
        manifest.every_q192_row_bound_exact);
    BOOST_CHECK(
        manifest.every_quotient_lde_bound_derived);
    BOOST_CHECK(
        manifest.every_compiled_program_53_columns);
    BOOST_CHECK(manifest.every_family_within_cap);
    BOOST_CHECK(
        manifest.canonical_u32_injective_commitment);
    BOOST_CHECK(!manifest.recursive_root_consumed);
    BOOST_CHECK(!manifest.production_authority);
    BOOST_CHECK(!DigestZero(manifest.commitment));
    BOOST_CHECK_EQUAL(
        manifest.semantic_complete_families, 14U);
    BOOST_CHECK_EQUAL(
        manifest.semantic_partial_families, 14U);
    BOOST_CHECK_GT(
        manifest.families_with_challenge_loads, 0U);

    uint32_t challenge_loads = 0;
    for (uint32_t index = 0;
         index < manifest.families.size();
         ++index) {
        const auto& family = manifest.families[index];
        BOOST_CHECK_EQUAL(family.family_index, index);
        BOOST_CHECK_EQUAL(
            static_cast<uint32_t>(family.kind),
            index + 1);
        BOOST_CHECK_EQUAL(
            family.semantic_rows,
            ali::kProductionAliQueriesV1);
        BOOST_CHECK_EQUAL(
            family.padded_source_rows,
            ali::kProductionAliPaddedQueryRowsV1);
        BOOST_CHECK_EQUAL(
            family.compiled_physical_columns,
            ali::kProductionAliCompiledColumnsV1);
        BOOST_CHECK(family.source_table_canonical);
        BOOST_CHECK(family.source_table_non_stub);
        BOOST_CHECK(family.compiled_table_canonical);
        BOOST_CHECK(
            family.challenge_class_degree_checked);
        BOOST_CHECK(family.exact_q192_rows);
        BOOST_CHECK(
            family.quotient_and_lde_bounds_derived);
        BOOST_CHECK(family.within_coefficient_cap);
        BOOST_CHECK(family.constant_width_53);
        BOOST_CHECK_EQUAL(
            family.minimum_vm_segments, 1U);
        BOOST_CHECK_LE(
            family.vertical_padded_rows,
            family.coefficient_cap);
        BOOST_CHECK_EQUAL(
            family.source_n_lde,
            family.source_n_coeffs *
                matmul::v4::rc::kRCFriBlowup);
        BOOST_CHECK_EQUAL(
            family.compiled_n_lde,
            family.compiled_n_coeffs *
                matmul::v4::rc::kRCFriBlowup);
        challenge_loads +=
            family.source_challenge_loads;
    }
    // The production inventory contains post-commitment LogUp/CTL
    // challenges. This makes the explicit degree-one Challenge audit
    // non-vacuous.
    BOOST_CHECK_GT(challenge_loads, 0U);

    BOOST_TEST_MESSAGE(
        "ALI exact maxima: source_width="
        << manifest.maximum_source_width
        << " source_challenges="
        << manifest.maximum_source_challenge_width
        << " source_constraints="
        << manifest.maximum_source_constraints
        << " source_instructions="
        << manifest.maximum_source_instructions
        << " source_degree="
        << manifest.maximum_source_degree
        << " source_q="
        << manifest.maximum_source_quotient_len
        << " source_lde="
        << manifest.maximum_source_n_lde
        << " compiled_constraints="
        << manifest.maximum_compiled_constraints
        << " compiled_instructions="
        << manifest.maximum_compiled_instructions
        << " compiled_degree="
        << manifest.maximum_compiled_degree
        << " compiled_q="
        << manifest.maximum_compiled_quotient_len
        << " compiled_lde="
        << manifest.maximum_compiled_n_lde
        << " vertical_logical="
        << manifest.maximum_vertical_logical_rows
        << " vertical_padded="
        << manifest.maximum_vertical_padded_rows
        << " segments="
        << manifest.maximum_minimum_vm_segments);
}

BOOST_AUTO_TEST_CASE(
    omitted_reordered_duplicate_stub_and_key_substitution_reject)
{
    const auto honest =
        ali::BuildProductionAliManifestV1();
    BOOST_REQUIRE(honest.local_manifest_complete);

    auto omitted = honest;
    omitted.families.erase(
        omitted.families.begin() + 7);
    Recommit(omitted);
    BOOST_CHECK(
        !ali::ValidateProductionAliManifestV1(omitted));

    auto reordered = honest;
    std::swap(
        reordered.families[4],
        reordered.families[5]);
    Recommit(reordered);
    BOOST_CHECK(
        !ali::ValidateProductionAliManifestV1(reordered));

    auto duplicate = honest;
    duplicate.families[11] =
        duplicate.families[10];
    Recommit(duplicate);
    BOOST_CHECK(
        !ali::ValidateProductionAliManifestV1(duplicate));

    auto stub = honest;
    auto& family = stub.families[3];
    family.source_current_width = 1;
    family.source_next_width = 1;
    family.source_challenge_width = 0;
    family.source_constraint_count = 1;
    family.source_instruction_count = 1;
    family.source_challenge_loads = 0;
    family.source_max_degree = 1;
    family.source_table_non_stub = false;
    Recommit(stub);
    BOOST_CHECK(
        !ali::ValidateProductionAliManifestV1(stub));

    auto key = honest;
    key.families[9].source_program_key[0] =
        gf::Add(
            key.families[9].source_program_key[0],
            1);
    Recommit(key);
    BOOST_REQUIRE(!DigestZero(key.commitment));
    BOOST_CHECK(
        !ali::ValidateProductionAliManifestV1(key));
}

BOOST_AUTO_TEST_CASE(
    degree_row_cap_and_goldilocks_alias_substitution_reject)
{
    const auto honest =
        ali::BuildProductionAliManifestV1();
    BOOST_REQUIRE(honest.local_manifest_complete);

    auto degree = honest;
    ++degree.families[0].source_max_degree;
    Recommit(degree);
    BOOST_CHECK(
        !ali::ValidateProductionAliManifestV1(degree));

    auto row = honest;
    --row.families[1].semantic_rows;
    Recommit(row);
    BOOST_CHECK(
        !ali::ValidateProductionAliManifestV1(row));

    auto cap = honest;
    cap.families[2].coefficient_cap =
        cap.families[2].vertical_padded_rows - 1;
    Recommit(cap);
    BOOST_CHECK(
        !ali::ValidateProductionAliManifestV1(cap));

    auto x_plus_p = honest;
    // Raw p is the noncanonical x+p encoding of x=0. The commitment
    // builder rejects it before hashing instead of reducing it to zero.
    x_plus_p.families[3].compiled_program_key[2] =
        gf::kP;
    x_plus_p.commitment =
        ali::ComputeProductionAliManifestCommitmentV1(
            x_plus_p);
    BOOST_CHECK(DigestZero(x_plus_p.commitment));
    BOOST_CHECK(
        !ali::ValidateProductionAliManifestV1(x_plus_p));
}

BOOST_AUTO_TEST_CASE(
    every_source_domain_is_exactly_derived)
{
    namespace sites =
        matmul::v4::rc::soundness_scenarios;
    namespace topo =
        matmul::v4::rc::universal_topology;
    const auto site_manifest =
        sites::BuildProductionProofSiteManifest(
            sites::SelectedProductionProofSitePolicy());
    const auto sources =
        topo::BuildProductionFamilyProgramSourcesV1(
            site_manifest);
    BOOST_REQUIRE_EQUAL(
        sources.size(),
        ali::kProductionAliFamilyCountV1);
    for (const auto& source : sources) {
        ali::rba::QuotientDomainV1 domain;
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            ali::BuildProductionAliSourceDomainV1(
                source.program, domain, &why),
            why);
        BOOST_CHECK_EQUAL(
            domain.trace_rows,
            ali::kProductionAliPaddedQueryRowsV1);
        BOOST_CHECK_GE(
            domain.evaluation_rows,
            domain.trace_rows);
        BOOST_CHECK_EQUAL(
            domain.evaluation_rows %
                domain.trace_rows,
            0U);
        BOOST_CHECK(
            gf::Eq(
                domain.coset_shift,
                gf::Fp3::FromFp(7)));
    }
}

BOOST_AUTO_TEST_CASE(
    role_complete_v2_assessment_reports_exact_current_semantic_gap)
{
    const auto assessment =
        ali::BuildProductionAliAssessmentV2();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ali::ValidateProductionAliAssessmentV2(
            assessment, &why),
        why);
    BOOST_REQUIRE(
        assessment.local_ali_assessment_complete);
    BOOST_CHECK(assessment.exact_28_family_registry);
    BOOST_CHECK(assessment.exact_14_role_order);
    BOOST_CHECK(
        assessment.every_registered_role_has_program);
    BOOST_CHECK(
        assessment.every_program_table_non_stub);
    BOOST_CHECK(
        assessment.every_degree_bound_derived);
    BOOST_CHECK_EQUAL(assessment.family_count, 28U);
    BOOST_CHECK_EQUAL(assessment.role_count, 14U);
    BOOST_CHECK_EQUAL(
        assessment.semantic_complete_families, 14U);
    BOOST_CHECK_EQUAL(
        assessment.semantic_partial_families, 14U);
    BOOST_CHECK_EQUAL(
        assessment.partial_family_residuals.size(), 14U);
    BOOST_CHECK_EQUAL(assessment.fully_semantic_roles, 0U);
    BOOST_CHECK_EQUAL(
        assessment.required_semantic_endpoints, 52U);
    BOOST_CHECK_EQUAL(
        assessment.locally_complete_semantic_endpoints, 14U);
    BOOST_CHECK(
        !assessment.semantic_relation_manifest_complete);
    BOOST_CHECK(!assessment.recursive_root_consumed);
    BOOST_CHECK(!assessment.production_authority);
    BOOST_CHECK(!DigestZero(assessment.commitment));

    uint32_t families = 0;
    uint64_t source_constraints = 0;
    uint64_t source_instructions = 0;
    uint64_t compiled_constraints = 0;
    uint64_t compiled_instructions = 0;
    uint32_t required_endpoints = 0;
    uint32_t complete_endpoints = 0;
    for (const auto& role : assessment.roles) {
        BOOST_CHECK_GT(role.family_count, 0U);
        BOOST_CHECK(role.every_table_non_stub);
        BOOST_CHECK(role.every_degree_bound_derived);
        BOOST_CHECK_GT(role.required_semantic_endpoints, 0U);
        BOOST_CHECK_LT(
            role.locally_complete_semantic_endpoints,
            role.required_semantic_endpoints);
        if (role.semantic_partial_families == 0) {
            BOOST_CHECK(role.every_family_locally_complete);
            BOOST_CHECK_EQUAL(
                role.residual_obligations_or, 0U);
        } else {
            BOOST_CHECK(
                !role.every_family_locally_complete);
            BOOST_CHECK_NE(
                role.residual_obligations_or, 0U);
        }
        BOOST_CHECK(!role.complete_endpoint_coverage);
        families += role.family_count;
        required_endpoints +=
            role.required_semantic_endpoints;
        complete_endpoints +=
            role.locally_complete_semantic_endpoints;
        source_constraints += role.source_constraints;
        source_instructions += role.source_instructions;
        compiled_constraints += role.compiled_constraints;
        compiled_instructions += role.compiled_instructions;
    }
    BOOST_CHECK_EQUAL(families, assessment.family_count);
    BOOST_CHECK_EQUAL(
        required_endpoints,
        assessment.required_semantic_endpoints);
    BOOST_CHECK_EQUAL(
        complete_endpoints,
        assessment.locally_complete_semantic_endpoints);
    BOOST_CHECK_EQUAL(
        source_constraints, assessment.source_constraints);
    BOOST_CHECK_EQUAL(
        source_instructions, assessment.source_instructions);
    BOOST_CHECK_EQUAL(
        compiled_constraints,
        assessment.compiled_constraints);
    BOOST_CHECK_EQUAL(
        compiled_instructions,
        assessment.compiled_instructions);

    BOOST_TEST_MESSAGE(
        "ALI role assessment: families="
        << assessment.family_count
        << " roles=" << assessment.role_count
        << " complete_families="
        << assessment.semantic_complete_families
        << " partial_families="
        << assessment.semantic_partial_families
        << " fully_semantic_roles="
        << assessment.fully_semantic_roles
        << " complete_endpoints="
        << assessment.locally_complete_semantic_endpoints
        << "/" << assessment.required_semantic_endpoints
        << " source_constraints="
        << assessment.source_constraints
        << " source_instructions="
        << assessment.source_instructions
        << " compiled_constraints="
        << assessment.compiled_constraints
        << " compiled_instructions="
        << assessment.compiled_instructions);
}

BOOST_AUTO_TEST_CASE(
    source_assessment_rejects_missing_duplicate_stub_unknown_opcode_degree_overflow_and_transplant)
{
    const auto site_manifest =
        sites::BuildProductionProofSiteManifest(
            sites::SelectedProductionProofSitePolicy());
    const auto canonical =
        topo::BuildProductionFamilyProgramSourcesV1(
            site_manifest);
    BOOST_REQUIRE_EQUAL(canonical.size(), 28U);

    const auto rejected = [&](const auto& sources,
                              const std::string& tag) {
        ali::ProductionAliAssessmentV2 assessment;
        std::string why;
        BOOST_CHECK_MESSAGE(
            !ali::BuildProductionAliAssessmentFromSourcesV2(
                site_manifest, sources, assessment, &why),
            tag);
        BOOST_CHECK_MESSAGE(!why.empty(), tag);
    };

    auto missing = canonical;
    missing.erase(missing.begin() + 7);
    rejected(missing, "missing");

    auto duplicate = canonical;
    duplicate[7] = duplicate[6];
    rejected(duplicate, "duplicate");

    auto partial = std::find_if(
        canonical.begin(), canonical.end(),
        [](const auto& source) {
            return !source.semantic_relation_complete;
        });
    BOOST_REQUIRE(partial != canonical.end());
    auto stub = canonical;
    const size_t partial_index =
        static_cast<size_t>(partial - canonical.begin());
    stub[partial_index].program =
        OneColumnStub(stub[partial_index].role);
    rejected(stub, "stub");

    auto unknown_opcode = canonical;
    BOOST_REQUIRE(
        !unknown_opcode[0].program.programs.empty());
    BOOST_REQUIRE(
        !unknown_opcode[0].program.programs[0]
             .instructions.empty());
    unknown_opcode[0].program.programs[0]
        .instructions[0].opcode =
        static_cast<cb::Opcode>(255);
    rejected(unknown_opcode, "unknown_opcode");

    auto degree_overflow = canonical;
    auto& overflow_program =
        degree_overflow[0].program.programs[0];
    overflow_program.instructions.clear();
    overflow_program.instructions.push_back({
        cb::Opcode::Current, 0, 0, gf::Fp3::Zero()});
    uint32_t previous = 0;
    for (uint32_t bit = 0; bit < 32; ++bit) {
        overflow_program.instructions.push_back({
            cb::Opcode::Mul,
            previous,
            previous,
            gf::Fp3::Zero()});
        previous = static_cast<uint32_t>(
            overflow_program.instructions.size() - 1);
    }
    overflow_program.declared_degree =
        std::numeric_limits<uint32_t>::max();
    rejected(degree_overflow, "degree_overflow");

    size_t transplant_from = canonical.size();
    size_t transplant_to = canonical.size();
    for (size_t i = 0; i < canonical.size(); ++i) {
        for (size_t j = i + 1; j < canonical.size(); ++j) {
            if (canonical[i].role == canonical[j].role) {
                transplant_from = i;
                transplant_to = j;
                break;
            }
        }
        if (transplant_from != canonical.size()) break;
    }
    BOOST_REQUIRE(transplant_from != canonical.size());
    auto transplant = canonical;
    std::swap(
        transplant[transplant_from].program,
        transplant[transplant_to].program);
    rejected(transplant, "same_role_program_transplant");
}

BOOST_AUTO_TEST_CASE(
    v2_summary_omission_duplicate_transplant_and_false_completion_reject)
{
    const auto honest =
        ali::BuildProductionAliAssessmentV2();
    BOOST_REQUIRE(honest.local_ali_assessment_complete);

    auto omitted = honest;
    omitted.roles.erase(omitted.roles.begin() + 3);
    Recommit(omitted);
    BOOST_CHECK(DigestZero(omitted.commitment));
    BOOST_CHECK(
        !ali::ValidateProductionAliAssessmentV2(omitted));

    auto duplicate = honest;
    duplicate.roles[3] = duplicate.roles[2];
    Recommit(duplicate);
    BOOST_REQUIRE(!DigestZero(duplicate.commitment));
    BOOST_CHECK(
        !ali::ValidateProductionAliAssessmentV2(duplicate));

    auto transplanted_degree = honest;
    ++transplanted_degree.roles[2].maximum_source_degree;
    Recommit(transplanted_degree);
    BOOST_REQUIRE(
        !DigestZero(transplanted_degree.commitment));
    BOOST_CHECK(
        !ali::ValidateProductionAliAssessmentV2(
            transplanted_degree));

    auto false_complete = honest;
    false_complete.semantic_partial_families = 0;
    false_complete.fully_semantic_roles = 14;
    false_complete.partial_family_residuals.clear();
    false_complete.semantic_relation_manifest_complete = true;
    false_complete.production_authority = true;
    Recommit(false_complete);
    BOOST_REQUIRE(!DigestZero(false_complete.commitment));
    BOOST_CHECK(
        !ali::ValidateProductionAliAssessmentV2(
            false_complete));
}

BOOST_AUTO_TEST_SUITE_END()
