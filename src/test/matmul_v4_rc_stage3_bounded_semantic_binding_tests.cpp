// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_bounded_semantic_binding.h>
#include <matmul/matmul_v4_rc_stage3_composition.h>

#include <array>

namespace {

namespace rc = matmul::v4::rc;

uint256 H(uint8_t value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{Span<const unsigned char>{
        bytes.data(), bytes.size()}};
}

rc::RCStage3SuccinctProof Statement()
{
    rc::RCStage3SuccinctProof out;
    out.statement = rc::RCStage3StatementKind::Composed;
    auto& p = out.public_inputs;
    p.height = 7;
    p.n_bits = 0x1d00ffffU;
    p.episode_profile = 2;
    p.coupled_profile = 4;
    p.transcript_version = rc::ENC_RC_V4;
    p.header_commitment = H(1);
    p.params_commitment = H(2);
    p.target = H(3);
    p.sigma = H(4);
    p.episode_digest = H(5);
    p.coupled_digest = H(6);
    p.program_consensus_pin.recursive_alg_hash_root = H(0x08);
    p.program_consensus_pin.external_sha256d_audit_root = H(0x09);
    p.program_consensus_pin.registry_binding = H(0x0a);
    const auto roles =
        rc::RequiredRCStage3RelationRoles(out.statement);
    for (uint32_t i = 0; i < roles.size(); ++i) {
        out.commitments.push_back(
            {roles[i], H(static_cast<uint8_t>(32 + i))});
        out.sections.push_back(
            {roles[i],
             {static_cast<unsigned char>(i), 0xa5, 0x5a}});
    }
    p.final_digest = rc::ComputeRCStage3FinalDigest(out);
    p.transcript_commitment =
        rc::ComputeRCStage3TranscriptCommitment(out);
    return out;
}

rc::RCStage3BoundedSemanticComposition Composition()
{
    rc::RCStage3BoundedSemanticComposition out;
    uint8_t value = 64;
    auto next = [&]() { return H(value++); };
    auto& e = out.episode;
    e.seed_chain.product_commitment = next();
    e.operand_xof.product_commitment = next();
    e.builder_trace.product_commitment = next();
    const auto params = rc::MakeToyRCEpisodeParams();
    const auto layout = rc::RCGkrTraceLayout(params);
    std::vector<rc::RCStage3GemmExtractLayerBindings> bindings(
        layout.layers.size());
    for (auto& binding : bindings) {
        binding.extract_prf = next();
        binding.operand_a_root = next();
        binding.operand_b_root = next();
        binding.gemm_y_root = next();
        binding.extract_input_root = next();
        binding.extract_output_root = next();
        binding.gemm_proof_root = next();
        binding.extract_recursive_root = next();
        binding.scale_schedule_root = next();
        binding.ctl_terminal_root = next();
    }
    std::string manifest_why;
    const auto manifest = rc::BuildRCStage3GemmExtractManifest(
        params, next(), bindings, &manifest_why);
    BOOST_REQUIRE_MESSAGE(manifest.has_value(), manifest_why);
    e.gemm_extract_manifest = *manifest;
    e.gemm.collection_commitment = next();
    e.signed_range.resize(1);
    const auto canonical_range_pin =
        rc::MakeRCStage3SignedRangePin(
            e.gemm_extract_manifest, 0, 0, &manifest_why);
    BOOST_REQUIRE_MESSAGE(
        canonical_range_pin.has_value(), manifest_why);
    auto& range_pin = e.signed_range[0].pin =
        *canonical_range_pin;
    for (uint32_t i = 0;
         i < range_pin.column_roots.size(); ++i) {
        range_pin.column_roots[i].root = next();
    }
    e.extract.collection_commitment = next();
    e.tile_stream.collection_commitment = next();
    e.extract_stream_ctl.collection_commitment = next();
    e.tile_stream_leaf_ctl.collection_commitment = next();
    e.tile_tree_hash_ctl.collection_commitment = next();
    e.wiring.product_commitment = next();
    e.root_chain.manifest.commitment = next();
    e.root_chain.round_roots_pin.pin_commitment = next();
    e.root_chain.hash_bundle.manifest_commitment = next();
    e.root_chain.hash_binding.memory_manifest
        .manifest_commitment = next();
    e.root_chain.digest_pin.pin_commitment = next();
    e.round_root_producers.collection_commitment = next();
    e.header_target.pin.pin_commitment = next();
    e.header_target.public_memory_manifest
        .manifest_commitment = next();
    e.pow_pin.pin_commitment = next();
    e.pow_proof.pin_commitment = e.pow_pin.pin_commitment;

    auto& c = out.coupled;
    c.bank.product_commitment = next();
    c.bank_root.manifest.commitment = next();
    c.bank_root.bank_bytes.semantic_memory_root = next();
    c.bank_root.bank_digest.semantic_memory_root = next();
    c.initial_state.product_commitment = next();
    c.gemm.product_commitment = next();
    c.signed_range.manifest.commitment = next();
    c.signed_range.value_roots_commitment = next();
    c.exchange_permutation.product_commitment = next();
    c.mix.product_commitment = next();
    c.extract.product_commitment = next();
    c.root_chain.barrier_inputs_pin.pin_commitment = next();
    c.root_chain.barrier_outputs_pin.pin_commitment = next();
    c.root_chain.digest_manifest.commitment = next();
    c.root_chain.digest_inputs_pin.pin_commitment = next();
    c.root_chain.digest_hash_bundle.manifest_commitment = next();
    c.root_chain.digest_value_pin.pin_commitment = next();
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_bounded_semantic_binding_tests)

BOOST_AUTO_TEST_CASE(
    canonical_manifest_roundtrip_and_mutations)
{
    const auto statement = Statement();
    const auto composition = Composition();
    rc::RCStage3BoundedSemanticBindingManifest manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3BoundedSemanticBindingManifest(
            statement, composition, manifest, &why),
        why);
    BOOST_CHECK_EQUAL(
        manifest.records.size(),
        rc::kRCStage3BoundedSemanticBindingRecordCount);
    std::vector<unsigned char> encoded;
    BOOST_REQUIRE_MESSAGE(
        rc::SerializeRCStage3BoundedSemanticBindingManifest(
            manifest, encoded, &why),
        why);
    const auto decoded =
        rc::DeserializeRCStage3BoundedSemanticBindingManifest(
            encoded, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    BOOST_CHECK(*decoded == manifest);

    auto changed = encoded;
    changed[45] ^= 1U;
    BOOST_CHECK(
        !rc::DeserializeRCStage3BoundedSemanticBindingManifest(
             changed, &why)
             .has_value());
    auto trailing = encoded;
    trailing.push_back(0);
    BOOST_CHECK(
        !rc::DeserializeRCStage3BoundedSemanticBindingManifest(
             trailing, &why)
             .has_value());
    auto reordered = manifest;
    std::swap(reordered.records[1], reordered.records[2]);
    reordered.manifest_commitment =
        rc::ComputeRCStage3BoundedSemanticBindingCommitment(
            reordered);
    BOOST_CHECK(
        !rc::SerializeRCStage3BoundedSemanticBindingManifest(
            reordered, encoded, &why));
}

BOOST_AUTO_TEST_CASE(
    proof_owned_envelope_binds_every_typed_identity)
{
    auto statement = Statement();
    const auto composition = Composition();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::AttachRCStage3BoundedSemanticBinding(
            statement, composition, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyRCStage3CompositionLink(statement, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3BoundedSemanticBinding(
            statement, composition, &why),
        why);

    std::vector<unsigned char> bytes;
    BOOST_REQUIRE_MESSAGE(
        rc::SerializeRCStage3Proof(statement, bytes, &why),
        why);
    const auto decoded =
        rc::DeserializeRCStage3Proof(bytes, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3BoundedSemanticBinding(
            *decoded, composition, &why),
        why);

    auto changed_sidecar = composition;
    changed_sidecar.coupled.mix.product_commitment = H(0xee);
    BOOST_CHECK(
        !rc::VerifyRCStage3BoundedSemanticBinding(
            statement, changed_sidecar, &why));

    auto changed_section = statement;
    changed_section.sections.back().proof.back() ^= 1U;
    BOOST_CHECK(
        !rc::VerifyRCStage3BoundedSemanticBinding(
            changed_section, composition, &why));

    auto changed_outer_root = statement;
    changed_outer_root.commitments.back().root = H(0xef);
    changed_outer_root.public_inputs.transcript_commitment =
        rc::ComputeRCStage3TranscriptCommitment(
            changed_outer_root);
    BOOST_CHECK(
        !rc::VerifyRCStage3BoundedSemanticBinding(
            changed_outer_root, composition, &why));

    auto changed_transcript = statement;
    changed_transcript.public_inputs.transcript_commitment = H(0xf0);
    BOOST_CHECK(
        !rc::VerifyRCStage3BoundedSemanticBinding(
            changed_transcript, composition, &why));

    BOOST_CHECK(
        !rc::AttachRCStage3BoundedSemanticBinding(
            statement, composition, &why));
    BOOST_CHECK(
        rc::kRCStage3BoundedSemanticCompositionDurablyCommitmentBound);
    BOOST_CHECK(
        !rc::kRCStage3BoundedSemanticCompositionDurablySerialized);
    BOOST_CHECK(
        !rc::kRCStage3BoundedSemanticCompositionAuthorityReady);
}

BOOST_AUTO_TEST_SUITE_END()
