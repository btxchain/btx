// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_episode_builder_operand_xof.h>

namespace {

namespace rc = matmul::v4::rc;
namespace ha = rc::stage3_hash_air;

uint256 H(unsigned char value)
{
    std::array<unsigned char, 32> bytes{};
    bytes.fill(value);
    return uint256{Span<const unsigned char>{
        bytes.data(), bytes.size()}};
}

void AppendLe32(std::vector<uint8_t>& out, uint32_t value)
{
    for (uint32_t shift = 0; shift < 32; shift += 8) {
        out.push_back(static_cast<uint8_t>(value >> shift));
    }
}

bool Fixture(
    rc::RCStage3SuccinctProof& statement,
    rc::RCEpisodeParams& params,
    rc::RCStage3EpisodeBuilderSeedChainProduct& parent,
    std::string* why)
{
    params = rc::MakeToyRCEpisodeParams();
    std::vector<uint256> roots{H(0x61)};
    ha::EpisodeDigestManifest digest;
    if (!ha::BuildEpisodeDigestManifest(
            roots.size(), roots, digest, why)) {
        return false;
    }
    statement = {};
    statement.statement = rc::RCStage3StatementKind::Episode;
    statement.public_inputs.height = 17;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.transcript_version = rc::ENC_RC_V4;
    statement.public_inputs.header_commitment = H(0x11);
    statement.public_inputs.params_commitment = H(0x22);
    statement.public_inputs.sigma = H(0x33);
    statement.public_inputs.episode_digest =
        digest.direct.digest;

    parent = {};
    parent.statement_commitment =
        rc::RCStage3EpisodeStatementCommitment(statement);
    parent.header_commitment =
        statement.public_inputs.header_commitment;
    parent.params_commitment =
        statement.public_inputs.params_commitment;
    parent.sigma = statement.public_inputs.sigma;
    parent.expected_rounds = 1;
    parent.round_root_manifest = digest;
    parent.steps.resize(1);
    parent.steps[0].round_index = 0;
    parent.steps[0].source = parent.sigma;
    std::vector<uint8_t> preimage(
        reinterpret_cast<const uint8_t*>(rc::kRCRoundTag),
        reinterpret_cast<const uint8_t*>(rc::kRCRoundTag) +
            sizeof(rc::kRCRoundTag) - 1);
    preimage.insert(
        preimage.end(), parent.sigma.begin(), parent.sigma.end());
    AppendLe32(preimage, 0);
    if (!ha::BuildShaManifest(
            preimage, ha::ShaMode::Single,
            parent.steps[0].sha, why)) {
        return false;
    }
    parent.params_product.memory_manifest.manifest_commitment =
        H(0x71);
    parent.round_roots_pin.pin_commitment = H(0x72);
    parent.seed_memory_manifest.manifest_commitment = H(0x73);
    parent.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderSeedChainProductCommitment(
            parent);
    return !parent.product_commitment.IsNull();
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_builder_operand_xof_tests)

BOOST_AUTO_TEST_CASE(canonical_operand_inventory_and_outputs_are_exact)
{
    rc::RCStage3SuccinctProof statement;
    rc::RCEpisodeParams params;
    rc::RCStage3EpisodeBuilderSeedChainProduct parent;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        Fixture(statement, params, parent, &why), why);
    rc::RCStage3EpisodeBuilderOperandXofProduct product;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeBuilderOperandXofProduct(
            statement, params, parent, product, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::ValidateRCStage3EpisodeBuilderOperandXofSchedule(
            statement, params, parent, product, &why),
        why);
    BOOST_REQUIRE_EQUAL(product.instances.size(), 8U);
    BOOST_CHECK_EQUAL(product.output_cells, 23232U);
    BOOST_CHECK(
        product.instances[0].kind ==
        rc::RCStage3EpisodeOperandKind::Q);
    BOOST_CHECK(
        product.instances[1].kind ==
        rc::RCStage3EpisodeOperandKind::K);
    BOOST_CHECK(
        product.instances[2].kind ==
        rc::RCStage3EpisodeOperandKind::V);
    BOOST_CHECK(
        product.instances[3].kind ==
        rc::RCStage3EpisodeOperandKind::X0);
    BOOST_CHECK(
        product.instances[4].kind ==
        rc::RCStage3EpisodeOperandKind::WUp);
    BOOST_CHECK(
        product.instances[5].kind ==
        rc::RCStage3EpisodeOperandKind::WDown);
    BOOST_CHECK_EQUAL(
        product.output_memory.total_instance_count,
        product.output_cells);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderOperandXofProduct(
            statement, params, parent, product, &why));
}

BOOST_AUTO_TEST_CASE(
    omission_order_counter_and_output_substitution_reject)
{
    rc::RCStage3SuccinctProof statement;
    rc::RCEpisodeParams params;
    rc::RCStage3EpisodeBuilderSeedChainProduct parent;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        Fixture(statement, params, parent, &why), why);
    rc::RCStage3EpisodeBuilderOperandXofProduct product;
    BOOST_REQUIRE_MESSAGE(
        rc::BuildRCStage3EpisodeBuilderOperandXofProduct(
            statement, params, parent, product, &why),
        why);

    auto reordered = product;
    std::swap(reordered.instances[0], reordered.instances[1]);
    reordered.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderOperandXofProductCommitment(
            reordered);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeBuilderOperandXofSchedule(
            statement, params, parent, reordered, &why));

    auto omitted = product;
    omitted.instances.pop_back();
    omitted.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderOperandXofProductCommitment(
            omitted);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeBuilderOperandXofSchedule(
            statement, params, parent, omitted, &why));

    auto counter = product;
    counter.instances[2].mantissa.domain ^= 1;
    counter.instances[2].mantissa.commitment =
        ha::CommitCounterXofManifest(
            counter.instances[2].mantissa);
    counter.instances[2].mantissa_proof.manifest_commitment =
        counter.instances[2].mantissa.commitment;
    counter.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderOperandXofProductCommitment(
            counter);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeBuilderOperandXofSchedule(
            statement, params, parent, counter, &why));

    auto output = product;
    output.instances[4].scale.output[0] ^= 1;
    output.instances[4].scale.commitment =
        ha::CommitCounterXofManifest(output.instances[4].scale);
    output.instances[4].scale_proof.manifest_commitment =
        output.instances[4].scale.commitment;
    output.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderOperandXofProductCommitment(
            output);
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeBuilderOperandXofSchedule(
            statement, params, parent, output, &why));

    auto derivation = product;
    derivation.instances[0].seed_derivations[0]
        .sha.preimage[0] ^= 1;
    BOOST_CHECK(
        !rc::ValidateRCStage3EpisodeBuilderOperandXofSchedule(
            statement, params, parent, derivation, &why));
}

BOOST_AUTO_TEST_CASE(
    audit_is_honest_about_ancestors_and_production_streaming)
{
    const auto open =
        rc::CurrentRCStage3EpisodeBuilderOperandXofAudit(
            true, false);
    BOOST_CHECK(open.local_relation_complete);
    BOOST_CHECK(open.exact_unique_operand_schedule);
    BOOST_CHECK(open.seed_derivation_sha_executable);
    BOOST_CHECK(open.all_counter_xof_children_executable);
    BOOST_CHECK(!open.chacha_required_by_consensus);
    BOOST_CHECK(open.output_memory_equality_executable);
    BOOST_CHECK(!open.producer_provenance_complete);
    BOOST_CHECK(!open.semantic_complete);
    BOOST_CHECK(!open.production_streaming_manifest_complete);

    const auto closed =
        rc::CurrentRCStage3EpisodeBuilderOperandXofAudit(
            true, true);
    BOOST_CHECK(closed.producer_provenance_complete);
    BOOST_CHECK(closed.semantic_complete);
    BOOST_CHECK(!closed.production_streaming_manifest_complete);
    BOOST_CHECK(!closed.remaining.empty());
}

BOOST_AUTO_TEST_SUITE_END()
