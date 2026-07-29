// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <boost/test/unit_test.hpp>

#include <matmul/matmul_v4_rc_stage3_episode_terminal_alg.h>

#include <algorithm>
#include <cstdlib>
#include <vector>

namespace rc = matmul::v4::rc;
namespace terminal_alg =
    rc::episode_terminal_alg;
namespace digest =
    rc::episode_digest_all_instance;
namespace ha = rc::stage3_hash_air;
namespace tape =
    rc::stage3_multirow_v13_proof_tape_air;
namespace gf = rc::gkr_field;

namespace {

uint256 Root(uint8_t byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

rc::RCStage3SuccinctProof Statement(
    const uint256& episode_digest)
{
    rc::RCStage3SuccinctProof out;
    out.statement =
        rc::RCStage3StatementKind::Episode;
    auto& inputs = out.public_inputs;
    inputs.height = 92;
    // Exact largest non-overflowing compact target.  The target bytes below
    // are the canonical decode of this nBits value, not a detached fixture.
    inputs.n_bits = 0x2100ffffU;
    inputs.episode_profile = 2;
    inputs.transcript_version = rc::ENC_RC_V4;
    inputs.header_commitment = Root(0x11);
    inputs.params_commitment = Root(0x22);
    inputs.sigma = Root(0x33);
    inputs.target.SetNull();
    inputs.target.data()[30] = 0xff;
    inputs.target.data()[31] = 0xff;
    inputs.episode_digest = episode_digest;
    inputs.final_digest = episode_digest;
    inputs.program_consensus_pin
        .recursive_alg_hash_root = Root(0x08);
    inputs.program_consensus_pin
        .external_sha256d_audit_root = Root(0x09);
    inputs.program_consensus_pin
        .registry_binding = Root(0x0a);
    return out;
}

digest::TapeChallengeContextV1 TapeContext()
{
    digest::TapeChallengeContextV1 out;
    out.shape.trace_rows = 2;
    out.shape.trace_columns = 2;
    out.shape.quotient_len = 2;
    out.shape.n_coeffs = 2;
    out.shape.base_column_indices = {0};
    out.binding.program_root = Root(0x71);
    out.binding.statement_root = Root(0x72);
    out.binding.public_fs_seed = Root(0x73);
    out.binding.proof_wire_root = Root(0x74);
    out.binding.tape_root = {1, 2, 3, 4};
    out.source_inventory_root =
        tape::ComputeShardSourceInventoryRootV2(
            out.shape, out.binding);
    out.shard_count =
        static_cast<uint32_t>(
            tape::BuildShardPlansV2(
                out.shape, out.binding).size());
    return out;
}

} // namespace

BOOST_AUTO_TEST_SUITE(
    matmul_v4_rc_stage3_episode_terminal_alg_tests)

BOOST_AUTO_TEST_CASE(
    public_terminal_alg_inventory_is_fail_closed)
{
    BOOST_CHECK_EQUAL(
        terminal_alg::kChildCountV1, 5U);
    BOOST_CHECK(
        terminal_alg::
            kPublicTerminalAlgExecutableV1);
    BOOST_CHECK(
        !terminal_alg::
            kNormalizedRecursiveConsumedV1);
    BOOST_CHECK(
        !terminal_alg::kProductionAuthorityV1);
    terminal_alg::ProductV1 empty;
    BOOST_CHECK(
        terminal_alg::CommitProductV1(empty)
            .IsNull());
}

BOOST_AUTO_TEST_CASE(
    five_public_terminal_alg_proofs_retain_and_reject_attacks)
{
    if (std::getenv(
            "BTX_RUN_STAGE3_EPISODE_TERMINAL_ALG") ==
        nullptr) {
        BOOST_TEST_MESSAGE(
            "set BTX_RUN_STAGE3_EPISODE_TERMINAL_ALG=1 "
            "for digest/header/pow Alg proofs");
        return;
    }
    std::string why;
    // The digest family is intentionally pinned to the production episode
    // round count even in this proof-level fixture.
    std::vector<ha::TileTreeManifest> trees(
        rc::MakeDatacenterRCEpisodeParams().rounds);
    std::vector<uint256> roots;
    for (uint32_t round = 0;
         round < trees.size(); ++round) {
        const std::vector<uint8_t> stream{
            static_cast<uint8_t>(round + 1U),
            static_cast<uint8_t>(0x40U + round),
        };
        BOOST_REQUIRE_MESSAGE(
            ha::BuildTileTreeManifest(
                stream, 32, trees[round], &why),
            why);
        roots.push_back(trees[round].root);
    }
    ha::EpisodeDigestManifest manifest;
    BOOST_REQUIRE_MESSAGE(
        ha::BuildEpisodeDigestManifest(
            roots.size(), roots, manifest, &why),
        why);
    const auto statement =
        Statement(manifest.direct.digest);
    const auto tape_context = TapeContext();
    digest::ProductV1 digest_product;
    BOOST_REQUIRE_MESSAGE(
        digest::ProveProductV1(
            statement, manifest, tape_context,
            digest_product, &why),
        why);
    rc::RCStage3EpisodeHeaderTargetProduct
        header_target;
    BOOST_REQUIRE_MESSAGE(
        rc::ProveRCStage3EpisodeHeaderTargetProduct(
            statement, header_target, &why),
        why);
    terminal_alg::ProductV1 product;
    BOOST_REQUIRE_MESSAGE(
        terminal_alg::ProveProductV1(
            statement, tape_context,
            digest_product, header_target,
            product, &why),
        why);
    BOOST_CHECK_MESSAGE(
        terminal_alg::VerifyProductV1(
            statement, tape_context,
            digest_product, header_target,
            product, &why),
        why);
    std::vector<
        terminal_alg::RecursiveChildInputV1>
        children;
    BOOST_REQUIRE_MESSAGE(
        terminal_alg::BuildRecursiveChildInputsV1(
            statement, tape_context,
            digest_product, header_target,
            product, children, &why),
        why);
    BOOST_REQUIRE_EQUAL(children.size(), 5U);
    for (uint32_t slot = 0;
         slot < children.size(); ++slot) {
        BOOST_CHECK(
            children[slot].cs
                .preprocessed_roots.empty());
        BOOST_CHECK(
            children[slot].cs
                .preprocessed_pin_ood);
        BOOST_CHECK_EQUAL(
            children[slot].cs.preprocessed.size(),
            children[slot].cs.n_columns);
        std::vector<unsigned char> proof_bytes;
        BOOST_REQUIRE_MESSAGE(
            rc::SerializeAirQuotientProofAlg(
                children[slot].proof,
                proof_bytes, &why),
            why);
        const auto retained =
            rc::DeserializeAirQuotientProofAlg(
                proof_bytes, &why);
        BOOST_REQUIRE_MESSAGE(
            retained.has_value(), why);
        std::vector<unsigned char> canonical;
        BOOST_REQUIRE_MESSAGE(
            rc::SerializeAirQuotientProofAlg(
                *retained, canonical, &why),
            why);
        BOOST_CHECK(canonical == proof_bytes);
        BOOST_REQUIRE_MESSAGE(
            (rc::air_quotient::AirQuotientVerify<
                gf::Fp3,
                rc::air_quotient::
                    AirFriBackendAlg<gf::Fp3>>(
                        children[slot].cs,
                        *retained,
                        children[slot].public_fs_seed,
                        &why)),
            why);
        BOOST_CHECK(
            rc::recursive_fixedpoint::
                ComputeNormalizedAlgAirProofCommitment(
                    *retained) ==
            product.children[slot]
                .proof_commitment);
    }
    {
        auto changed_pin = children[0].cs;
        BOOST_REQUIRE(
            !changed_pin.preprocessed.empty());
        changed_pin.preprocessed[0].second[0] =
            gf::Add(
                changed_pin.preprocessed[0].second[0],
                gf::Fp3::One());
        BOOST_CHECK(
            !(rc::air_quotient::AirQuotientVerify<
                gf::Fp3,
                rc::air_quotient::
                    AirFriBackendAlg<gf::Fp3>>(
                        changed_pin,
                        children[0].proof,
                        children[0].public_fs_seed,
                        &why)));
    }

    {
        auto attack = product;
        std::swap(
            attack.children[0].proof,
            attack.children[1].proof);
        std::swap(
            attack.children[0].proof_commitment,
            attack.children[1].proof_commitment);
        attack.product_commitment =
            terminal_alg::CommitProductV1(attack);
        BOOST_CHECK(
            !terminal_alg::VerifyProductV1(
                statement, tape_context,
                digest_product, header_target,
                attack, &why));
    }
    {
        auto attack = product;
        attack.children[1].source_statement =
            Root(0xd1);
        attack.product_commitment =
            terminal_alg::CommitProductV1(attack);
        BOOST_CHECK(
            !terminal_alg::VerifyProductV1(
                statement, tape_context,
                digest_product, header_target,
                attack, &why));
    }
    {
        auto attack = product;
        BOOST_REQUIRE(
            !attack.children[4].proof.batch
                 .queries.empty());
        BOOST_REQUIRE(
            !attack.children[4].proof.batch
                 .queries[0].row.values.empty());
        attack.children[4].proof.batch
            .queries[0].row.values[0] =
            gf::Add(
                attack.children[4].proof.batch
                    .queries[0].row.values[0],
                gf::Fp3::One());
        attack.children[4].proof_commitment =
            rc::recursive_fixedpoint::
                ComputeNormalizedAlgAirProofCommitment(
                    attack.children[4].proof);
        attack.product_commitment =
            terminal_alg::CommitProductV1(attack);
        BOOST_CHECK(
            !terminal_alg::VerifyProductV1(
                statement, tape_context,
                digest_product, header_target,
                attack, &why));
    }
    {
        auto divergent = digest_product;
        divergent.endpoint_binding_root =
            Root(0xd2);
        BOOST_CHECK(
            !terminal_alg::VerifyProductV1(
                statement, tape_context,
                divergent, header_target,
                product, &why));
    }

}

BOOST_AUTO_TEST_SUITE_END()
