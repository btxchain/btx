// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_safe_v12_domain_registry.h>

#include <algorithm>

namespace registry =
    matmul::v4::rc::stage3_safe_v12_domain_registry;
namespace fsair =
    matmul::v4::rc::stage3_safe_v12_fs_air;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_safe_v12_domain_registry_tests)

namespace {

fsair::ManifestV12 Manifest()
{
    const fsair::ShapeV12 shape{
        /*child_w=*/3,
        /*child_n_rows=*/8,
        /*child_quotient_len=*/16,
        /*n_coeffs=*/64,
        /*n_lde=*/1024,
        /*n_folds=*/6,
    };
    fsair::ManifestV12 manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        fsair::BuildManifestV12(shape, manifest, &why), why);
    return manifest;
}

} // namespace

BOOST_AUTO_TEST_CASE(
    exact_domains_io_tags_and_root_pin_are_executable)
{
    const auto manifest = Manifest();
    registry::TranscriptDomainRegistryV12 built;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        registry::BuildTranscriptDomainRegistryV12(
            manifest, built, &why),
        why);
    BOOST_CHECK(
        registry::ValidateTranscriptDomainRegistryV12(
            manifest, built, &why));
    BOOST_CHECK(built.manifest_rebuilt_from_shape);
    BOOST_CHECK(built.exact_five_channel_inventory);
    BOOST_CHECK(built.io_patterns_fixed);
    BOOST_CHECK(built.pairwise_domains_distinct);
    BOOST_CHECK(built.pairwise_tags_distinct);
    BOOST_CHECK(built.all_tags_fill_capacity);
    BOOST_CHECK(built.root_field_native);
    BOOST_CHECK(std::any_of(
        built.root.begin(), built.root.end(),
        [](gf::Fp lane) { return lane != 0; }));

    const auto security =
        registry::AssessSafeCrossOracleParametersV12(built);
    BOOST_CHECK_EQUAL(
        security.arithmetic_capacity_elements, 4U);
    BOOST_CHECK_EQUAL(security.tag_elements, 4U);
    BOOST_CHECK_EQUAL(security.registry_oracles, 5U);
    BOOST_CHECK_GT(
        security.ideal_permutation_capacity_bits, 127.0);
    BOOST_CHECK(security.fixed_io_patterns);
    BOOST_CHECK(security.pairwise_domain_separators);
    BOOST_CHECK(security.full_capacity_tags);
    BOOST_CHECK(
        security.safe_cross_oracle_parameter_target_met);
    BOOST_CHECK(
        !security.
             concrete_poseidon2_permutation_assumption_registered);
    BOOST_CHECK(
        !security.registry_root_recursively_consumed);
    BOOST_CHECK(
        !security.conditional_cross_oracle_reduction_complete);

    registry::DomainRegistryRootPinAirV12 pin;
    BOOST_REQUIRE_MESSAGE(
        registry::BuildDomainRegistryRootPinAirV12(
            built, built.root, pin, &why),
        why);
    BOOST_CHECK(pin.valid);
    BOOST_CHECK_EQUAL(
        pin.verifier_owned_preprocessed_columns, 4U);
    BOOST_CHECK_EQUAL(
        pin.proof_owned_preprocessed_columns, 0U);
    BOOST_CHECK_EQUAL(pin.equality_constraints, 4U);
    BOOST_CHECK_EQUAL(pin.violations, 0U);
    BOOST_CHECK(!pin.recursively_consumed);
    BOOST_CHECK(
        registry::ValidateDomainRegistryRootPinAirV12(
            built, built.root, pin, &why));
}

BOOST_AUTO_TEST_CASE(
    domain_tag_call_order_and_root_substitutions_reject)
{
    const auto manifest = Manifest();
    registry::TranscriptDomainRegistryV12 built;
    std::string why;
    BOOST_REQUIRE(
        registry::BuildTranscriptDomainRegistryV12(
            manifest, built, &why));

    auto changed_domain = manifest;
    changed_domain.fri_lane[1].typed_domain.push_back(1);
    BOOST_CHECK(
        !registry::ValidateTranscriptDomainRegistryV12(
            changed_domain, built, &why));

    auto changed_tag = manifest;
    changed_tag.fri_lane[0].safe_manifest.tag[0] =
        gf::Add(
            changed_tag.fri_lane[0].safe_manifest.tag[0],
            1);
    BOOST_CHECK(
        !registry::ValidateTranscriptDomainRegistryV12(
            changed_tag, built, &why));

    auto changed_call = manifest;
    std::swap(
        changed_call.fri_lane[0].calls[0],
        changed_call.fri_lane[0].calls[1]);
    BOOST_CHECK(
        !registry::ValidateTranscriptDomainRegistryV12(
            changed_call, built, &why));

    auto changed_registry = built;
    changed_registry.entries[1].lane = 1;
    BOOST_CHECK(
        !registry::ValidateTranscriptDomainRegistryV12(
            manifest, changed_registry, &why));

    auto wrong_root = built.root;
    wrong_root[0] = gf::Add(wrong_root[0], 1);
    registry::DomainRegistryRootPinAirV12 rejected;
    BOOST_CHECK(
        !registry::BuildDomainRegistryRootPinAirV12(
            built, wrong_root, rejected, &why));

    auto noncanonical_root = built.root;
    noncanonical_root[0] = gf::kP;
    BOOST_CHECK(
        !registry::BuildDomainRegistryRootPinAirV12(
            built, noncanonical_root, rejected, &why));

    registry::DomainRegistryRootPinAirV12 honest;
    BOOST_REQUIRE(
        registry::BuildDomainRegistryRootPinAirV12(
            built, built.root, honest, &why));
    honest.columns[4][0] =
        gf::Add(honest.columns[4][0], gf::Fp3::One());
    BOOST_CHECK(
        !registry::ValidateDomainRegistryRootPinAirV12(
            built, built.root, honest, &why));
}

BOOST_AUTO_TEST_SUITE_END()
