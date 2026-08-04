// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_episode_builder_seed_chain.h>
#include <matmul/matmul_v4_rc_stage3_consensus.h>
#include <matmul/matmul_v4_rc_stage3_provenance_graph.h>
#include <test/util/setup_common.h>

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

rc::RCEpisodeParams Params()
{
    auto params = rc::MakeToyRCEpisodeParams();
    params.rounds = 2;
    return params;
}

bool BuildStatementAndDigest(
    rc::RCStage3SuccinctProof& statement,
    ha::EpisodeDigestManifest& digest,
    std::string* why)
{
    std::vector<uint256> roots{H(0x61), H(0x62)};
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
    return true;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(
    matmul_v4_rc_stage3_episode_builder_seed_chain_tests,
    BasicTestingSetup)

BOOST_AUTO_TEST_CASE(
    all_round_sha_proofs_and_seed_memory_execute)
{
    const auto params = Params();
    rc::RCStage3SuccinctProof statement;
    ha::EpisodeDigestManifest digest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        BuildStatementAndDigest(statement, digest, &why), why);
    rc::RCStage3EpisodeBuilderSeedChainProduct product;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, digest, product, &why),
        why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, product, &why),
        why);
    BOOST_REQUIRE_EQUAL(product.steps.size(), 2U);
    BOOST_CHECK(
        product.steps[0].source ==
        statement.public_inputs.sigma);
    BOOST_CHECK(
        product.steps[1].source ==
        digest.round_roots[0]);
    BOOST_CHECK_EQUAL(
        product.seed_memory_manifest.logical_rows, 16U);
    BOOST_CHECK_EQUAL(
        product.seed_memory_manifest.n_rows, 16U);
    BOOST_CHECK(
        product.product_commitment ==
        rc::ComputeRCStage3EpisodeBuilderSeedChainProductCommitment(
            product));

    auto reordered = product;
    std::swap(reordered.steps[0], reordered.steps[1]);
    reordered.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderSeedChainProductCommitment(
            reordered);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, reordered, &why));

    auto omitted = product;
    omitted.steps.pop_back();
    omitted.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderSeedChainProductCommitment(
            omitted);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, omitted, &why));

    auto source_substitution = product;
    source_substitution.steps[1].source = H(0xee);
    source_substitution.product_commitment =
        rc::ComputeRCStage3EpisodeBuilderSeedChainProductCommitment(
            source_substitution);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, source_substitution, &why));

    auto seed_root_substitution = product;
    seed_root_substitution.seed_memory_manifest
        .canonical_value_root = H(0xdd);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, seed_root_substitution, &why));

    auto hash_proof_omission = product;
    hash_proof_omission.steps[0].hash_proof.proofs.clear();
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, hash_proof_omission, &why));

    auto params_substitution = product;
    params_substitution.params_product.memory_manifest
        .canonical_value_root = H(0xcc);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, params_substitution, &why));

    auto round_root_substitution = product;
    round_root_substitution.round_roots_pin.value_root = H(0xbb);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, round_root_substitution, &why));

    auto changed_statement = statement;
    changed_statement.public_inputs.header_commitment = H(0xaa);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeBuilderSeedChainProduct(
            changed_statement, params, product, &why));
}

BOOST_AUTO_TEST_CASE(
    audit_never_infers_transitive_producer_completion)
{
    const auto open =
        rc::CurrentRCStage3EpisodeBuilderSeedChainAudit(
            true, true, false);
    BOOST_CHECK(open.local_relation_complete);
    BOOST_CHECK(open.exact_all_instance_sha_execution);
    BOOST_CHECK(open.final_seed_words_memory_link);
    BOOST_CHECK(open.endpoint1_params_product_executed);
    BOOST_CHECK(open.round_root_vector_executed);
    BOOST_CHECK(!open.producer_provenance_complete);
    BOOST_CHECK(!open.semantic_complete);
    BOOST_CHECK(!open.recursively_consumed);
    BOOST_CHECK(!open.remaining.empty());

    const auto closed =
        rc::CurrentRCStage3EpisodeBuilderSeedChainAudit(
            true, true, true);
    BOOST_CHECK(closed.producer_provenance_complete);
    BOOST_CHECK(closed.semantic_complete);
    BOOST_CHECK(!closed.recursively_consumed);
    BOOST_CHECK(
        rc::kRCStage3EpisodeBuilderSeedChainLocalProductExecutable);
    BOOST_CHECK(
        !rc::kRCStage3EpisodeBuilderSeedChainRecursivelyConsumed);
}

BOOST_AUTO_TEST_CASE(
    proved_round_chain_derives_every_extract_prf_and_rejects_substitution)
{
    auto params = rc::MakeToyRCEpisodeParams();
    params.rounds = 1;
    CBlockHeader header;
    header.nVersion = 4;
    header.hashPrevBlock = H(0x41);
    header.hashMerkleRoot = H(0x42);
    header.nTime = 123456;
    header.nBits = 0x207fffffU;
    header.nNonce = 7;

    ha::EpisodeDigestManifest digest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildEpisodeDigestManifest(
            1, std::vector<uint256>{H(0x61)},
            digest, &why),
        why);
    rc::RCStage3SuccinctProof statement;
    statement.statement = rc::RCStage3StatementKind::Episode;
    statement.public_inputs.height = 17;
    statement.public_inputs.episode_profile = 2;
    statement.public_inputs.transcript_version = rc::ENC_RC_V4;
    statement.public_inputs.header_commitment =
        rc::RCStage3HeaderCommitment(header);
    statement.public_inputs.params_commitment = H(0x22);
    statement.public_inputs.sigma =
        matmul::v4::DeriveSigma(header);
    statement.public_inputs.episode_digest =
        digest.direct.digest;

    rc::RCStage3EpisodeBuilderSeedChainProduct seed_chain;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeBuilderSeedChainProduct(
            statement, params, digest, seed_chain, &why),
        why);
    const auto canonical =
        rc::RCGkrEpisodeLayerProvenance(
            header, params, digest.round_roots);
    BOOST_REQUIRE(!canonical.empty());
    std::vector<rc::RCStage3GemmExtractLayerBindings> bindings(
        canonical.size());
    for (uint32_t ordinal = 0;
         ordinal < bindings.size(); ++ordinal) {
        auto& binding = bindings[ordinal];
        binding.extract_prf =
            canonical[ordinal].extract_prf;
        binding.operand_a_root = H(0x51 + ordinal);
        binding.operand_b_root = H(0x61 + ordinal);
        binding.gemm_y_root = H(0x71 + ordinal);
        binding.extract_input_root = H(0x81 + ordinal);
        binding.extract_output_root = H(0x91 + ordinal);
        binding.gemm_proof_root = H(0xa1 + ordinal);
        binding.extract_recursive_root = H(0xb1 + ordinal);
        binding.scale_schedule_root = H(0xc1 + ordinal);
        binding.ctl_terminal_root = H(0xd1 + ordinal);
    }
    const auto manifest =
        rc::BuildRCStage3GemmExtractManifest(
            params,
            rc::RCStage3EpisodeStatementCommitment(statement),
            bindings, &why);
    BOOST_REQUIRE_MESSAGE(manifest.has_value(), why);
    BOOST_CHECK_MESSAGE(
        rc::VerifyRCStage3EpisodeExtractPrfDerivation(
            header, statement, params, seed_chain,
            *manifest, &why),
        why);

    auto changed_bindings = bindings;
    changed_bindings[0].extract_prf = H(0xee);
    const auto changed_manifest =
        rc::BuildRCStage3GemmExtractManifest(
            params,
            rc::RCStage3EpisodeStatementCommitment(statement),
            changed_bindings, &why);
    BOOST_REQUIRE_MESSAGE(changed_manifest.has_value(), why);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeExtractPrfDerivation(
            header, statement, params, seed_chain,
            *changed_manifest, &why));

    auto changed_header = header;
    ++changed_header.nNonce64;
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeExtractPrfDerivation(
            changed_header, statement, params, seed_chain,
            *manifest, &why));

    auto changed_chain = seed_chain;
    changed_chain.round_roots_pin.value_root = H(0xef);
    BOOST_CHECK(
        !rc::VerifyRCStage3EpisodeExtractPrfDerivation(
            header, statement, params, changed_chain,
            *manifest, &why));
}

BOOST_AUTO_TEST_SUITE_END()
