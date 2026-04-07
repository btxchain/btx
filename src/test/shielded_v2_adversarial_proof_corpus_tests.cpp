// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <test/shielded_v2_adversarial_proof_corpus.h>

#include <core_io.h>
#include <crypto/ml_kem.h>
#include <hash.h>
#include <shielded/account_registry.h>
#include <shielded/merkle_tree.h>
#include <shielded/note_encryption.h>
#include <shielded/ringct/matrict.h>
#include <shielded/ringct/ring_signature.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/v2_proof.h>
#include <shielded/v2_send.h>
#include <test/util/smile2_placeholder_utils.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_account_registry_test_util.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <string>
#include <vector>

namespace {

namespace v2proof = shielded::v2::proof;

struct V2SendCorpusFixture
{
    CTransaction tx;
    shielded::ShieldedMerkleTree tree;
};

[[nodiscard]] ShieldedNote MakeNote(CAmount value, unsigned char seed)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = uint256{seed};
    note.rho = uint256{static_cast<unsigned char>(seed + 1)};
    note.rcm = uint256{static_cast<unsigned char>(seed + 2)};
    return note;
}

[[nodiscard]] shielded::ShieldedMerkleTree BuildTree(const uint256& real_member,
                                                     size_t real_index)
{
    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        if (i == real_index) {
            tree.Append(real_member);
            continue;
        }
        HashWriter hw;
        hw << std::string{"BTX_ShieldedV2_Adversarial_Corpus_Test_RingMember_V1"}
           << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }
    return tree;
}

[[nodiscard]] std::vector<uint64_t> BuildRingPositions()
{
    std::vector<uint64_t> positions;
    positions.reserve(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        positions.push_back(i);
    }
    return positions;
}

[[nodiscard]] std::vector<uint256> BuildRingMembers(const shielded::ShieldedMerkleTree& tree,
                                                    const std::vector<uint64_t>& positions)
{
    std::vector<uint256> members;
    members.reserve(positions.size());
    for (const uint64_t pos : positions) {
        const auto commitment = tree.CommitmentAt(pos);
        BOOST_REQUIRE(commitment.has_value());
        members.push_back(*commitment);
    }
    return members;
}

[[nodiscard]] std::vector<smile2::wallet::SmileRingMember> BuildSmileRingMembers(
    const std::vector<uint256>& ring_commitments,
    const ShieldedNote& real_note,
    const uint256& real_commitment,
    size_t real_index)
{
    std::vector<smile2::wallet::SmileRingMember> members;
    members.reserve(ring_commitments.size());
    for (const uint256& commitment : ring_commitments) {
        members.push_back(
            smile2::wallet::BuildPlaceholderRingMember(smile2::wallet::SMILE_GLOBAL_SEED, commitment));
    }

    auto real_member = smile2::wallet::BuildRingMemberFromNote(smile2::wallet::SMILE_GLOBAL_SEED,
                                                               real_note,
                                                               real_commitment);
    if (!real_member.has_value()) {
        return {};
    }
    members[real_index] = *real_member;
    return members;
}

[[nodiscard]] mlkem::KeyPair BuildRecipientKeyPair(unsigned char seed)
{
    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> key_seed{};
    key_seed.fill(seed);
    return mlkem::KeyGenDerand(key_seed);
}

[[nodiscard]] shielded::EncryptedNote BuildEncryptedNote(const ShieldedNote& note,
                                                         const mlkem::PublicKey& recipient_pk,
                                                         unsigned char kem_seed_byte,
                                                         unsigned char nonce_byte)
{
    std::array<uint8_t, mlkem::ENCAPS_SEEDBYTES> kem_seed{};
    kem_seed.fill(kem_seed_byte);
    std::array<uint8_t, 12> nonce{};
    nonce.fill(nonce_byte);
    return shielded::NoteEncryption::EncryptDeterministic(note, recipient_pk, kem_seed, nonce);
}

[[nodiscard]] V2SendCorpusFixture BuildBaseFixture()
{
    const std::vector<unsigned char> spending_key(32, 0x42);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0x61);
    const ShieldedNote output_note = MakeNote(/*value=*/4900, /*seed=*/0x71);

    const size_t real_index = 3;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_note.GetCommitment(), real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x81);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x91, /*nonce_byte=*/0xa1);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input;
    spend_input.note = input_note;
    spend_input.note_commitment = input_note.GetCommitment();
    spend_input.account_leaf_hint = shielded::registry::MakeDirectSendAccountLeafHint();
    spend_input.ring_positions = ring_positions;
    spend_input.ring_members = ring_members;
    spend_input.smile_ring_members = BuildSmileRingMembers(ring_members,
                                                           input_note,
                                                           spend_input.note_commitment,
                                                           real_index);
    BOOST_REQUIRE(!spend_input.smile_ring_members.empty());
    spend_input.real_index = real_index;
    BOOST_REQUIRE(test::shielded::AttachAccountRegistryWitness(spend_input));

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = 17;

    std::string reject_reason;
    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xAA); // deterministic test entropy
    auto built = shielded::v2::BuildV2SendTransaction(tx_template,
                                                      tree.Root(),
                                                      {spend_input},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()});
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    return {CTransaction{built->tx}, tree};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_v2_adversarial_proof_corpus_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(v2_send_adversarial_corpus_builds_expected_variants)
{
    const auto fixture = BuildBaseFixture();

    std::string reject_reason;
    auto corpus = btx::test::shielded::BuildV2SendAdversarialProofCorpus(
        EncodeHexTx(fixture.tx),
        reject_reason);
    BOOST_REQUIRE_MESSAGE(corpus.has_value(), reject_reason);

    BOOST_CHECK_EQUAL(corpus->family_name, "v2_send");
    BOOST_CHECK_EQUAL(corpus->base_txid_hex, fixture.tx.GetHash().GetHex());
    BOOST_CHECK_EQUAL(corpus->base_wtxid_hex, fixture.tx.GetWitnessHash().GetHex());
    BOOST_REQUIRE_EQUAL(corpus->variants.size(), 5U);
    BOOST_CHECK_EQUAL(corpus->variants[0].id, "proof_payload_truncated");
    BOOST_CHECK_EQUAL(corpus->variants[1].id, "proof_payload_appended_junk");
    BOOST_CHECK_EQUAL(corpus->variants[2].id, "witness_real_index_oob");
    BOOST_CHECK_EQUAL(corpus->variants[3].id, "statement_digest_mismatch");
    BOOST_CHECK_EQUAL(corpus->variants[4].id, "ring_challenge_tamper");
    BOOST_CHECK_EQUAL(corpus->variants[0].expected_reject_reason, "bad-shielded-proof-encoding");
    BOOST_CHECK_EQUAL(corpus->variants[4].expected_failure_stage, "proof_verify");
}

BOOST_AUTO_TEST_CASE(v2_send_adversarial_corpus_matches_local_parse_and_verify_failures)
{
    const auto fixture = BuildBaseFixture();

    std::string reject_reason;
    auto corpus = btx::test::shielded::BuildV2SendAdversarialProofCorpus(
        EncodeHexTx(fixture.tx),
        reject_reason);
    BOOST_REQUIRE_MESSAGE(corpus.has_value(), reject_reason);

    for (const auto& variant : corpus->variants) {
        BOOST_TEST_CONTEXT("variant=" << variant.id) {
        CMutableTransaction mutated;
        if (!DecodeHexTx(mutated, variant.tx_hex)) {
            // Structural witness corruption can now be rejected during tx decode
            // before the local proof parser is reached.
            BOOST_CHECK_EQUAL(variant.expected_failure_stage, "witness_parse");
            continue;
        }
        BOOST_REQUIRE(mutated.shielded_bundle.v2_bundle.has_value());
        const auto& bundle = *mutated.shielded_bundle.v2_bundle;

        const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(CTransaction{mutated});
        reject_reason.clear();
        auto context = v2proof::ParseV2SendProof(bundle, statement, reject_reason);

        if (variant.expected_failure_stage == "proof_verify") {
            BOOST_REQUIRE(context.has_value());
            auto ring_members = v2proof::BuildV2SendRingMembers(bundle, *context, fixture.tree, reject_reason);
            BOOST_REQUIRE_MESSAGE(ring_members.has_value(), reject_reason);
            BOOST_CHECK(!v2proof::VerifyV2SendProof(bundle, *context, *ring_members));
            continue;
        }

        BOOST_CHECK(!context.has_value());
        BOOST_CHECK_EQUAL(reject_reason, variant.expected_reject_reason);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
