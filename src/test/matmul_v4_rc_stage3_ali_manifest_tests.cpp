// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_ali_manifest.h>

#include <algorithm>

namespace ali =
    matmul::v4::rc::stage3_ali_manifest;
namespace gf = matmul::v4::rc::gkr_field;

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

BOOST_AUTO_TEST_SUITE_END()
