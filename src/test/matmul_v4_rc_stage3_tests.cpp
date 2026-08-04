// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3.h>

#include <primitives/block.h>
#include <primitives/transaction.h>
#include <streams.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_tests, BasicTestingSetup)

namespace {

uint256 Filled(unsigned char byte)
{
    uint256 out;
    std::fill(out.begin(), out.end(), byte);
    return out;
}

rc::RCStage3SuccinctProof MakeProof(rc::RCStage3StatementKind statement)
{
    rc::RCStage3SuccinctProof proof;
    proof.statement = statement;
    auto& p = proof.public_inputs;
    p.height = 42;
    p.n_bits = 0x207fffff;
    p.episode_profile = statement == rc::RCStage3StatementKind::Coupled ? 0 : 2;
    p.coupled_profile = statement == rc::RCStage3StatementKind::Episode ? 0 : 3;
    p.transcript_version = 4;
    p.program_consensus_pin.recursive_alg_hash_root = Filled(0x09);
    p.program_consensus_pin.external_sha256d_audit_root = Filled(0x0a);
    p.program_consensus_pin.registry_binding = Filled(0x0b);
    p.header_commitment = Filled(0x11);
    p.params_commitment = Filled(0x22);
    p.target = Filled(0x7f);
    p.sigma = Filled(0x33);
    p.episode_digest =
        statement == rc::RCStage3StatementKind::Coupled ? uint256{} : Filled(0x44);
    p.coupled_digest =
        statement == rc::RCStage3StatementKind::Episode ? uint256{} : Filled(0x55);
    p.final_digest = Filled(0x66);
    p.transcript_commitment = Filled(0x77);

    const auto roles = rc::RequiredRCStage3RelationRoles(statement);
    for (size_t i = 0; i < roles.size(); ++i) {
        proof.commitments.push_back({roles[i], Filled(static_cast<unsigned char>(0x80 + i))});
        proof.sections.push_back(
            {roles[i], {static_cast<unsigned char>(i), 0xa5, 0x5a}});
    }
    return proof;
}

} // namespace

BOOST_AUTO_TEST_CASE(stage3_authority_is_fail_closed)
{
    BOOST_CHECK(!rc::kRCStage3SuccinctAuthorityReady);
    BOOST_CHECK(!rc::kRCStage3ProductionProgramRegistryReady);
    BOOST_CHECK(rc::RCProofAuthority::SampledPrefilter != rc::RCProofAuthority::SuccinctV1);
    BOOST_CHECK_EQUAL(rc::kRCStage3Profile2AccumulatorBounds.qkt_abs_max, 294'912);
    BOOST_CHECK_EQUAL(rc::kRCStage3Profile2AccumulatorBounds.sv_abs_max, 1'811'939'328);
    BOOST_CHECK_EQUAL(rc::kRCStage3Profile2AccumulatorBounds.up_abs_max, 9'437'184);
    BOOST_CHECK_EQUAL(rc::kRCStage3Profile2AccumulatorBounds.down_residual_abs_max, 37'748'784);
}

BOOST_AUTO_TEST_CASE(stage3_required_roles_are_complete_and_composed)
{
    const auto episode =
        rc::RequiredRCStage3RelationRoles(rc::RCStage3StatementKind::Episode);
    const auto coupled =
        rc::RequiredRCStage3RelationRoles(rc::RCStage3StatementKind::Coupled);
    const auto composed =
        rc::RequiredRCStage3RelationRoles(rc::RCStage3StatementKind::Composed);

    BOOST_CHECK_EQUAL(episode.size(), 6U);
    BOOST_CHECK_EQUAL(coupled.size(), 8U);
    BOOST_CHECK_EQUAL(composed.size(), episode.size() + coupled.size() + 1);
    BOOST_CHECK(std::equal(episode.begin(), episode.end(), composed.begin()));
    BOOST_CHECK(std::equal(coupled.begin(), coupled.end(), composed.begin() + episode.size()));
    BOOST_CHECK(composed.back() == rc::RCStage3RelationRole::CompositionLink);
}

BOOST_AUTO_TEST_CASE(stage3_canonical_codec_roundtrip)
{
    const auto proof = MakeProof(rc::RCStage3StatementKind::Composed);
    std::vector<unsigned char> bytes;
    std::string why;
    BOOST_REQUIRE_MESSAGE(rc::SerializeRCStage3Proof(proof, bytes, &why), why);
    const auto decoded = rc::DeserializeRCStage3Proof(bytes, &why);
    BOOST_REQUIRE_MESSAGE(decoded.has_value(), why);
    BOOST_CHECK(*decoded == proof);

    std::vector<unsigned char> bytes2;
    BOOST_REQUIRE(rc::SerializeRCStage3Proof(*decoded, bytes2, &why));
    BOOST_CHECK(bytes2 == bytes);
}

BOOST_AUTO_TEST_CASE(stage3_word_pack_is_canonical_and_durable)
{
    const auto proof = MakeProof(rc::RCStage3StatementKind::Composed);
    std::vector<uint32_t> words;
    std::string why;
    BOOST_REQUIRE_MESSAGE(rc::PackRCStage3ProofWords(proof, words, &why), why);
    BOOST_CHECK(rc::IsRCStage3ProofWords(words));
    const auto unpacked = rc::UnpackRCStage3ProofWords(words, &why);
    BOOST_REQUIRE_MESSAGE(unpacked.has_value(), why);
    BOOST_CHECK(*unpacked == proof);

    // matrix_c_data is already part of full-block network/disk serialization.
    CBlock block;
    block.nVersion = 1;
    block.nBits = 0x207fffff;
    block.matrix_c_data = words;
    CMutableTransaction coinbase;
    coinbase.vin.resize(1);
    coinbase.vout.resize(1);
    block.vtx.push_back(MakeTransactionRef(coinbase));

    DataStream stream;
    ParamsStream writer{stream, TX_WITH_WITNESS};
    writer << block;
    CBlock decoded_block;
    ParamsStream reader{stream, TX_WITH_WITNESS};
    reader >> decoded_block;
    BOOST_CHECK(decoded_block.matrix_c_data == words);
    const auto from_block = rc::UnpackRCStage3ProofWords(decoded_block.matrix_c_data, &why);
    BOOST_REQUIRE_MESSAGE(from_block.has_value(), why);
    BOOST_CHECK(*from_block == proof);
}

BOOST_AUTO_TEST_CASE(stage3_codec_rejects_incomplete_or_noncanonical_relations)
{
    std::string why;
    auto proof = MakeProof(rc::RCStage3StatementKind::Composed);

    auto missing = proof;
    missing.sections.pop_back();
    BOOST_CHECK(!rc::ValidateRCStage3ProofStructure(missing, &why));
    BOOST_CHECK(why.find("section_role_count") != std::string::npos);

    auto reordered = proof;
    std::swap(reordered.sections[0], reordered.sections[1]);
    BOOST_CHECK(!rc::ValidateRCStage3ProofStructure(reordered, &why));
    BOOST_CHECK(why.find("section_role_order") != std::string::npos);

    auto empty = proof;
    empty.sections[0].proof.clear();
    BOOST_CHECK(!rc::ValidateRCStage3ProofStructure(empty, &why));
    BOOST_CHECK(why.find("empty_relation_proof") != std::string::npos);

    auto no_link = proof;
    no_link.commitments.pop_back();
    no_link.sections.pop_back();
    BOOST_CHECK(!rc::ValidateRCStage3ProofStructure(no_link, &why));
    BOOST_CHECK(why.find("commitment_role_count") != std::string::npos);

    auto sampled = proof;
    sampled.authority = rc::RCProofAuthority::SampledPrefilter;
    BOOST_CHECK(!rc::ValidateRCStage3ProofStructure(sampled, &why));
    BOOST_CHECK(why.find("non_succinct_authority") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(stage3_codec_rejects_truncation_trailing_and_word_malleability)
{
    const auto proof = MakeProof(rc::RCStage3StatementKind::Episode);
    std::string why;
    std::vector<unsigned char> bytes;
    BOOST_REQUIRE(rc::SerializeRCStage3Proof(proof, bytes, &why));

    auto truncated = bytes;
    truncated.pop_back();
    BOOST_CHECK(!rc::DeserializeRCStage3Proof(truncated, &why).has_value());

    auto trailing = bytes;
    trailing.push_back(0);
    BOOST_CHECK(!rc::DeserializeRCStage3Proof(trailing, &why).has_value());
    BOOST_CHECK(why.find("trailing_bytes") != std::string::npos);

    auto unknown_version = bytes;
    unknown_version[4] = 3;
    BOOST_CHECK(!rc::DeserializeRCStage3Proof(unknown_version, &why).has_value());
    BOOST_CHECK(why.find("bad_version") != std::string::npos);

    // Program authority roots are a bijective packing of four canonical
    // Goldilocks limbs. p itself is not a field element and must not admit a
    // second encoding of the same recursive registry.
    auto noncanonical_program_root = bytes;
    constexpr size_t PROGRAM_ROOT_OFFSET{32};
    const std::array<unsigned char, 8> goldilocks_p_le{
        0x01, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff};
    std::copy(
        goldilocks_p_le.begin(), goldilocks_p_le.end(),
        noncanonical_program_root.begin() + PROGRAM_ROOT_OFFSET);
    BOOST_CHECK(!rc::DeserializeRCStage3Proof(
        noncanonical_program_root, &why).has_value());
    BOOST_CHECK(
        why.find("program_pin_alg_hash_root") !=
        std::string::npos);

    auto padded_proof = proof;
    while (true) {
        std::vector<uint32_t> probe;
        BOOST_REQUIRE(rc::PackRCStage3ProofWords(padded_proof, probe, &why));
        if ((probe[1] % 4) != 0) break;
        padded_proof.sections[0].proof.push_back(0x42);
    }
    std::vector<uint32_t> words;
    BOOST_REQUIRE(rc::PackRCStage3ProofWords(padded_proof, words, &why));
    auto extra_word = words;
    extra_word.push_back(0);
    BOOST_CHECK(!rc::UnpackRCStage3ProofWords(extra_word, &why).has_value());
    BOOST_CHECK(why.find("noncanonical_word_count") != std::string::npos);

    auto nonzero_padding = words;
    nonzero_padding.back() |= 0xff000000U;
    BOOST_CHECK(!rc::UnpackRCStage3ProofWords(nonzero_padding, &why).has_value());
    BOOST_CHECK(why.find("nonzero_word_padding") != std::string::npos);

    auto oversized_claim = words;
    oversized_claim[1] = static_cast<uint32_t>(rc::kRCStage3MaxProofBytes + 1);
    BOOST_CHECK(!rc::UnpackRCStage3ProofWords(oversized_claim, &why).has_value());
    BOOST_CHECK(why.find("bad_word_byte_length") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
