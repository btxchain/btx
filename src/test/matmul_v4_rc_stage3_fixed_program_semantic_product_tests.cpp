// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_fixed_program_semantic_product.h>

#include <chrono>

namespace product =
    matmul::v4::rc::fixed_program_semantic_product;
namespace ha = matmul::v4::rc::stage3_hash_air;
namespace gf = matmul::v4::rc::gkr_field;
namespace sites = matmul::v4::rc::soundness_scenarios;

namespace {

uint256 Seed(uint8_t tag)
{
    uint256 out;
    for (uint32_t i = 0; i < out.size(); ++i) {
        out.begin()[i] = static_cast<uint8_t>(tag + 13U * i);
    }
    return out;
}

ha::ShaManifest Sha(uint8_t tag)
{
    ha::ShaManifest out;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildShaManifest(
            std::vector<uint8_t>{tag, uint8_t(tag + 1U)},
            ha::ShaMode::Single, out, &why),
        why);
    return out;
}

ha::CounterXofManifest Xof(uint8_t tag)
{
    ha::CounterXofManifest out;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildCounterXofManifest(
            Seed(tag), tag, ha::CounterXofMode::RawBytes,
            1, out, &why),
        why);
    return out;
}

ha::ChaChaConsumptionManifest ChaCha(uint8_t tag)
{
    std::array<uint8_t, 32> key{};
    for (uint32_t i = 0; i < key.size(); ++i) {
        key[i] = static_cast<uint8_t>(tag + i);
    }
    ha::ChaChaConsumptionManifest out;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildChaChaConsumptionManifest(
            key, tag, tag + 1U, 0, 1, out, &why),
        why);
    return out;
}

product::FamilyInputsV1 Inputs()
{
    using K = sites::ProductionProofSiteKind;
    return {{
        {K::EpisodeScaleSha, Sha(1)},
        {K::EpisodeExtractChaCha, ChaCha(2)},
        {K::CoupledBankCounterXof, Xof(3)},
        {K::CoupledBankCommitmentSha256d, Sha(4)},
        {K::CoupledLobeInitCounterXof, Xof(5)},
        {K::CoupledPageScheduleXof, Xof(6)},
        {K::CoupledExchangeXof, Xof(7)},
        {K::CoupledPermutationXof, Xof(8)},
        {K::CoupledMixXof, Xof(9)},
        {K::CoupledExtractScaleSha, Sha(10)},
        {K::CoupledExtractChaCha, ChaCha(11)},
    }};
}

uint64_t EncodedChildBytes(
    const ha::FixedProgramVerticalProvenanceAirProof& proof)
{
    std::vector<unsigned char> batch;
    const size_t batch_bytes =
        matmul::v4::rc::SerializeFri3BatchProof(
            proof.quotient.batch, batch);
    BOOST_REQUIRE_EQUAL(batch_bytes, batch.size());
    uint64_t total = 4 + batch.size() + 32 + 4;
    for (const auto& query : proof.quotient.next_openings) {
        total += 4;
        for (const auto& path : query) {
            total += 4 + 24 + 4 + 32 * path.siblings.size();
        }
    }
    return total;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_fixed_program_semantic_product_tests)

BOOST_AUTO_TEST_CASE(
    all_11_schedule_is_typed_exact_and_fail_closed_before_recursion)
{
    const auto inputs = Inputs();
    product::ProductManifestV1 manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        product::BuildProductManifestV1(
            inputs, manifest, &why),
        why);
    BOOST_CHECK_EQUAL(
        manifest.families.size(), product::kFamilyCountV1);
    BOOST_CHECK(manifest.canonical_family_order);
    BOOST_CHECK(manifest.immutable_schedule_derived);
    BOOST_CHECK(manifest.opcode_selector_children_required);
    BOOST_CHECK(manifest.internal_ssa_copy_children_required);
    BOOST_CHECK(manifest.boundary_public_pins_required);
    BOOST_CHECK(manifest.exact_input_manifest_aggregation);
    BOOST_CHECK(!manifest.production_manifest_derived);
    BOOST_CHECK(!manifest.production_all_instance_aggregation);
    BOOST_CHECK(manifest.public_boundary_values);
    BOOST_CHECK(!manifest.proof_owned_output_exports);
    BOOST_CHECK(!manifest.caller_manifests_bound_to_role_proofs);
    BOOST_CHECK(!manifest.recursive_child_consumed);
    BOOST_CHECK(!manifest.semantic_closure);
    BOOST_CHECK(!manifest.production_authority);
    BOOST_CHECK_EQUAL(manifest.sha_boundary_count, 9U);
    BOOST_CHECK_EQUAL(manifest.chacha_boundary_count, 2U);

    auto reorder = inputs;
    std::swap(reorder[4], reorder[5]);
    product::ProductManifestV1 rejected;
    BOOST_CHECK(
        !product::BuildProductManifestV1(
            reorder, rejected, &why));

    auto duplicate = inputs;
    duplicate[5] = duplicate[4];
    BOOST_CHECK(
        !product::BuildProductManifestV1(
            duplicate, rejected, &why));

    auto omit = inputs;
    omit[8].kind =
        sites::ProductionProofSiteKind::CoupledMix;
    BOOST_CHECK(
        !product::BuildProductManifestV1(
            omit, rejected, &why));

    auto program_substitution = inputs;
    program_substitution[0].payload = ChaCha(70);
    BOOST_CHECK(
        !product::BuildProductManifestV1(
            program_substitution, rejected, &why));

    uint32_t decoded = 0;
    BOOST_REQUIRE(product::DecodeCanonicalU32V1(
        gf::Fp3{123, 0, 0}, decoded, &why));
    BOOST_CHECK_EQUAL(decoded, 123U);
    BOOST_CHECK(!product::DecodeCanonicalU32V1(
        gf::Fp3{gf::kP + 123U, 0, 0}, decoded, &why));
    BOOST_CHECK(!product::DecodeCanonicalU32V1(
        gf::Fp3{123, 1, 0}, decoded, &why));
}

BOOST_AUTO_TEST_CASE(
    all_11_roundtrip_and_proof_level_attacks_reject)
{
    const auto inputs = Inputs();
    const uint256 seed = Seed(0xd0);
    product::ProductProofV1 proof;
    std::string why;
    const auto prove_begin = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        product::ProveProductV1(
            inputs, seed, proof, &why),
        why);
    const auto prove_end = std::chrono::steady_clock::now();
    const auto verify_begin = std::chrono::steady_clock::now();
    BOOST_REQUIRE_MESSAGE(
        product::VerifyProductV1(
            inputs, seed, proof, &why),
        why);
    const auto verify_end = std::chrono::steady_clock::now();
    BOOST_CHECK_EQUAL(proof.sha.children.size(), 1U);
    BOOST_CHECK_EQUAL(proof.chacha.children.size(), 1U);

    // Forged/copy-substituted output: the typed manifest and child boundary
    // statement change, while the old quotient proof remains unchanged.
    // Replace the outer manifest too so rejection must occur inside the
    // quotient/FRI child rather than at outer structural equality.
    auto forged_output = inputs;
    forged_output[0].payload = Sha(44);
    auto forged_output_proof = proof;
    BOOST_REQUIRE(product::BuildProductManifestV1(
        forged_output, forged_output_proof.manifest, &why));
    BOOST_CHECK(!product::VerifyProductV1(
        forged_output, seed, forged_output_proof, &why));

    auto forged_chacha = inputs;
    forged_chacha[1].payload = ChaCha(45);
    auto forged_chacha_proof = proof;
    BOOST_REQUIRE(product::BuildProductManifestV1(
        forged_chacha, forged_chacha_proof.manifest, &why));
    BOOST_CHECK(!product::VerifyProductV1(
        forged_chacha, seed, forged_chacha_proof, &why));

    // Early structural boundary/root-pin corruption.
    auto wrong_boundary = proof;
    wrong_boundary.manifest.families[0]
        .boundary_pinned_output_root.begin()[0] ^= 1U;
    BOOST_CHECK(!product::VerifyProductV1(
        inputs, seed, wrong_boundary, &why));

    // Role/domain/program substitution in the product statement.
    auto wrong_role = proof;
    wrong_role.manifest.families[0].role =
        matmul::v4::rc::RCStage3RelationRole::CoupledMix;
    BOOST_CHECK(!product::VerifyProductV1(
        inputs, seed, wrong_role, &why));
    auto wrong_domain = proof;
    wrong_domain.manifest.families[0]
        .typed_domain.begin()[0] ^= 1U;
    BOOST_CHECK(!product::VerifyProductV1(
        inputs, seed, wrong_domain, &why));

    // Internal-wire/opening substitution is rejected by the actual
    // quotient/FRI verifier, not merely by a witness scan.
    auto wire = proof;
    BOOST_REQUIRE(!wire.sha.children.empty());
    BOOST_REQUIRE(!wire.sha.children[0]
                       .quotient.batch.queries.empty());
    BOOST_REQUIRE(!wire.sha.children[0]
                       .quotient.batch.queries[0]
                       .columns.empty());
    wire.sha.children[0]
        .quotient.batch.queries[0].columns[0].value =
        gf::Add(
            wire.sha.children[0]
                .quotient.batch.queries[0]
                .columns[0].value,
            gf::Fp3::One());
    BOOST_CHECK(!product::VerifyProductV1(
        inputs, seed, wire, &why));

    // Schedule omission at child-proof level.
    auto child_omit = proof;
    child_omit.sha.boundary_count -= 1U;
    BOOST_CHECK(!product::VerifyProductV1(
        inputs, seed, child_omit, &why));
    BOOST_CHECK(!product::VerifyProductV1(
        inputs, Seed(0xd1), proof, &why));

    uint64_t proof_bytes = 0;
    for (const auto& child : proof.sha.children) {
        proof_bytes += EncodedChildBytes(child);
    }
    for (const auto& child : proof.chacha.children) {
        proof_bytes += EncodedChildBytes(child);
    }
    BOOST_TEST_MESSAGE(
        "FIXED_PROGRAM_SEMANTIC_PRODUCT all11 sha_boundaries="
        << proof.sha.boundary_count
        << " chacha_boundaries=" << proof.chacha.boundary_count
        << " child_proof_bytes=" << proof_bytes
        << " prove_ms="
        << std::chrono::duration_cast<std::chrono::milliseconds>(
               prove_end - prove_begin).count()
        << " verify_ms="
        << std::chrono::duration_cast<std::chrono::milliseconds>(
               verify_end - verify_begin).count());
}

BOOST_AUTO_TEST_SUITE_END()
