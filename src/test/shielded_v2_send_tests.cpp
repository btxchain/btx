// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <crypto/sha256.h>
#include <crypto/ml_kem.h>
#include <hash.h>
#include <kernel/mempool_options.h>
#include <policy/policy.h>
#include <pqkey.h>
#include <shielded/account_registry.h>
#include <shielded/merkle_tree.h>
#include <shielded/note_encryption.h>
#include <shielded/smile2/verify_dispatch.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/validation.h>
#include <shielded/v2_proof.h>
#include <shielded/v2_send.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/smile2_placeholder_utils.h>
#include <test/util/setup_common.h>
#include <streams.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace {

namespace v2proof = shielded::v2::proof;

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
                                                     size_t real_index,
                                                     size_t ring_size = shielded::lattice::RING_SIZE)
{
    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < ring_size; ++i) {
        if (i == real_index) {
            tree.Append(real_member);
            continue;
        }
        HashWriter hw;
        hw << std::string{"BTX_ShieldedV2_Send_Test_RingMember_V1"} << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }
    return tree;
}

[[nodiscard]] shielded::ShieldedMerkleTree BuildTree(
    const std::vector<std::pair<size_t, uint256>>& real_members,
    size_t ring_size = shielded::lattice::RING_SIZE)
{
    std::map<size_t, uint256> real_member_map;
    for (const auto& [index, commitment] : real_members) {
        real_member_map.emplace(index, commitment);
    }

    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < ring_size; ++i) {
        const auto it = real_member_map.find(i);
        if (it != real_member_map.end()) {
            tree.Append(it->second);
            continue;
        }
        HashWriter hw;
        hw << std::string{"BTX_ShieldedV2_Send_Test_RingMember_V1"} << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }
    return tree;
}

[[nodiscard]] std::vector<uint64_t> BuildRingPositions(size_t ring_size = shielded::lattice::RING_SIZE)
{
    std::vector<uint64_t> positions;
    positions.reserve(ring_size);
    for (size_t i = 0; i < ring_size; ++i) {
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

[[nodiscard]] shielded::v2::V2SendSpendInput MakeDirectSpendInput(
    const ShieldedNote& note,
    const std::vector<uint64_t>& ring_positions,
    const std::vector<uint256>& ring_members,
    size_t real_index,
    std::optional<uint256> note_commitment = std::nullopt,
    std::vector<smile2::wallet::SmileRingMember> smile_ring_members = {})
{
    shielded::v2::V2SendSpendInput spend_input;
    spend_input.note = note;
    const uint256 effective_note_commitment = note_commitment.value_or(note.GetCommitment());
    spend_input.note_commitment = effective_note_commitment;
    spend_input.account_leaf_hint = shielded::registry::MakeDirectSendAccountLeafHint();
    spend_input.ring_positions = ring_positions;
    spend_input.ring_members = ring_members;
    if (smile_ring_members.empty()) {
        smile_ring_members = BuildSmileRingMembers(ring_members,
                                                   note,
                                                   effective_note_commitment,
                                                   real_index);
    }
    spend_input.smile_ring_members = std::move(smile_ring_members);
    spend_input.real_index = real_index;
    BOOST_REQUIRE(test::shielded::AttachAccountRegistryWitness(spend_input));
    return spend_input;
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

[[nodiscard]] shielded::v2::LifecycleAddress MakeLifecycleAddress(CPQKey& signing_key,
                                                                  unsigned char seed)
{
    shielded::v2::LifecycleAddress address;
    address.version = 0x01;
    address.algo_byte = 0x00;
    const std::vector<unsigned char> pubkey = signing_key.GetPubKey();
    BOOST_REQUIRE_EQUAL(pubkey.size(), MLDSA44_PUBKEY_SIZE);
    CSHA256().Write(pubkey.data(), pubkey.size()).Finalize(address.pk_hash.begin());
    for (size_t i = 0; i < address.kem_public_key.size(); ++i) {
        address.kem_public_key[i] = static_cast<unsigned char>(seed + i);
    }
    address.has_kem_public_key = true;
    CSHA256()
        .Write(address.kem_public_key.data(), address.kem_public_key.size())
        .Finalize(address.kem_pk_hash.begin());
    BOOST_REQUIRE(address.IsValid());
    return address;
}

[[nodiscard]] shielded::v2::AddressLifecycleControl MakeLifecycleControl(
    shielded::v2::AddressLifecycleControlKind kind,
    CPQKey& subject_key,
    const shielded::v2::LifecycleAddress& subject,
    const std::optional<shielded::v2::LifecycleAddress>& successor,
    const uint256& note_commitment)
{
    shielded::v2::AddressLifecycleControl control;
    control.kind = kind;
    control.output_index = 0;
    control.subject = subject;
    control.has_successor = successor.has_value();
    if (successor.has_value()) {
        control.successor = *successor;
    }
    control.subject_spending_pubkey = subject_key.GetPubKey();
    const uint256 sighash = shielded::v2::ComputeAddressLifecycleControlSigHash(control,
                                                                                note_commitment);
    BOOST_REQUIRE(!sighash.IsNull());
    BOOST_REQUIRE(subject_key.Sign(sighash, control.signature));
    BOOST_REQUIRE(control.IsValid());
    BOOST_REQUIRE(shielded::v2::VerifyAddressLifecycleControl(control, note_commitment));
    return control;
}

void ReplaceV2SendWitness(shielded::v2::TransactionBundle& bundle, const v2proof::V2SendWitness& witness)
{
    DataStream witness_stream;
    witness_stream << witness;
    const auto* witness_begin = reinterpret_cast<const unsigned char*>(witness_stream.data());
    bundle.proof_payload.assign(witness_begin, witness_begin + witness_stream.size());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_v2_send_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(legacy_payload_wrapper_roundtrips_encrypted_note)
{
    const ShieldedNote note = MakeNote(/*value=*/640, /*seed=*/0x21);
    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x31);
    const mlkem::KeyPair wrong_recipient = BuildRecipientKeyPair(/*seed=*/0x32);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(note, recipient.pk, /*kem_seed_byte=*/0x41, /*nonce_byte=*/0x51);

    auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(payload.has_value());
    BOOST_CHECK(payload->IsValid());
    BOOST_CHECK(!payload->ephemeral_key.IsNull());
    BOOST_CHECK(payload->scan_domain == shielded::v2::ScanDomain::OPAQUE);
    BOOST_CHECK(payload->scan_hint == shielded::v2::ComputeOpaquePublicScanHint(encrypted_note));

    auto decoded = shielded::v2::DecodeLegacyEncryptedNotePayload(*payload);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(!shielded::v2::LegacyEncryptedNotePayloadMatchesRecipient(*payload, *decoded, recipient.pk));
    BOOST_CHECK(!shielded::v2::LegacyEncryptedNotePayloadMatchesRecipient(*payload, *decoded, wrong_recipient.pk));
    const auto decoded_serialized = decoded->Serialize();
    const auto encrypted_serialized = encrypted_note.Serialize();
    BOOST_CHECK_EQUAL_COLLECTIONS(decoded_serialized.begin(),
                                  decoded_serialized.end(),
                                  encrypted_serialized.begin(),
                                  encrypted_serialized.end());
}

BOOST_AUTO_TEST_CASE(legacy_payload_wrapper_binds_scan_domain)
{
    const ShieldedNote note = MakeNote(/*value=*/640, /*seed=*/0x24);
    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x34);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(note, recipient.pk, /*kem_seed_byte=*/0x44, /*nonce_byte=*/0x54);

    auto payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(payload.has_value());

    auto decoded = shielded::v2::DecodeLegacyEncryptedNotePayload(*payload);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(payload->scan_domain == shielded::v2::ScanDomain::OPAQUE);
    BOOST_CHECK(!shielded::v2::LegacyEncryptedNotePayloadMatchesRecipient(*payload, *decoded, recipient.pk));

    shielded::v2::EncryptedNotePayload wrong_domain = *payload;
    wrong_domain.scan_domain = shielded::v2::ScanDomain::BATCH;
    BOOST_CHECK(!shielded::v2::LegacyEncryptedNotePayloadMatchesRecipient(wrong_domain, *decoded, recipient.pk));

    shielded::v2::EncryptedNotePayload wrong_ephemeral = *payload;
    wrong_ephemeral.ephemeral_key = uint256{0x99};
    BOOST_CHECK(!shielded::v2::DecodeLegacyEncryptedNotePayload(wrong_ephemeral).has_value());
}

BOOST_AUTO_TEST_CASE(builder_uses_chain_bound_statement_digest_after_disable_height)
{
    const ShieldedNote input_note = MakeNote(/*value=*/800, /*seed=*/0x41);
    const uint256 input_commitment = input_note.GetCommitment();
    const size_t real_index{5};
    const auto ring_positions = BuildRingPositions();
    const auto tree = BuildTree(input_commitment, real_index);
    const auto ring_members = BuildRingMembers(tree, ring_positions);
    const auto spend_input = MakeDirectSpendInput(input_note, ring_positions, ring_members, real_index);

    const ShieldedNote output_note = MakeNote(/*value=*/725, /*seed=*/0x52);
    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x62);
    const auto output_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x72, /*nonce_byte=*/0x82),
        recipient.pk,
        shielded::v2::ScanDomain::OPAQUE);
    BOOST_REQUIRE(output_payload.has_value());

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *output_payload;
    BOOST_REQUIRE(output_input.IsValid());

    std::array<unsigned char, 32> spending_key{};
    spending_key.fill(0x11);
    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0x22);

    const auto& main_consensus = Params().GetConsensus();
    const auto alt_params = CreateChainParams(*m_node.args, ChainType::SHIELDEDV2DEV);
    BOOST_REQUIRE(alt_params != nullptr);

    std::string reject_reason;
    auto main_built = shielded::v2::BuildV2SendTransaction(
        CMutableTransaction{},
        tree.Root(),
        {spend_input},
        {output_input},
        /*fee=*/75,
        Span<const unsigned char>{spending_key.data(), spending_key.size()},
        reject_reason,
        Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()},
        &main_consensus,
        main_consensus.nShieldedMatRiCTDisableHeight);
    BOOST_REQUIRE_MESSAGE(main_built.has_value(), reject_reason);

    reject_reason.clear();
    auto alt_built = shielded::v2::BuildV2SendTransaction(
        CMutableTransaction{},
        tree.Root(),
        {spend_input},
        {output_input},
        /*fee=*/75,
        Span<const unsigned char>{spending_key.data(), spending_key.size()},
        reject_reason,
        Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()},
        &alt_params->GetConsensus(),
        alt_params->GetConsensus().nShieldedMatRiCTDisableHeight);
    BOOST_REQUIRE_MESSAGE(alt_built.has_value(), reject_reason);

    const CTransaction main_tx{main_built->tx};
    const CTransaction alt_tx{alt_built->tx};
    const auto* main_bundle = main_tx.GetShieldedBundle().GetV2Bundle();
    const auto* alt_bundle = alt_tx.GetShieldedBundle().GetV2Bundle();
    BOOST_REQUIRE(main_bundle != nullptr);
    BOOST_REQUIRE(alt_bundle != nullptr);
    BOOST_CHECK_EQUAL(main_bundle->header.family_id, shielded::v2::TransactionFamily::V2_GENERIC);
    BOOST_CHECK_EQUAL(alt_bundle->header.family_id, shielded::v2::TransactionFamily::V2_GENERIC);
    BOOST_CHECK_EQUAL(main_bundle->header.proof_envelope.proof_kind, shielded::v2::ProofKind::GENERIC_OPAQUE);
    BOOST_CHECK_EQUAL(alt_bundle->header.proof_envelope.proof_kind, shielded::v2::ProofKind::GENERIC_OPAQUE);
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(*main_bundle,
                                                      shielded::v2::TransactionFamily::V2_SEND));
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(*alt_bundle,
                                                      shielded::v2::TransactionFamily::V2_SEND));
    BOOST_REQUIRE_EQUAL(main_bundle->output_chunks.size(), 1U);
    BOOST_REQUIRE_EQUAL(alt_bundle->output_chunks.size(), 1U);
    BOOST_CHECK_EQUAL(main_bundle->output_chunks.front().output_count,
                      std::get<shielded::v2::SendPayload>(main_bundle->payload).outputs.size());
    BOOST_CHECK_EQUAL(alt_bundle->output_chunks.front().output_count,
                      std::get<shielded::v2::SendPayload>(alt_bundle->payload).outputs.size());
    BOOST_CHECK(std::get<shielded::v2::SendPayload>(main_bundle->payload).output_encoding ==
                shielded::v2::SendOutputEncoding::SMILE_COMPACT_POSTFORK);
    BOOST_CHECK(std::get<shielded::v2::SendPayload>(alt_bundle->payload).output_encoding ==
                shielded::v2::SendOutputEncoding::SMILE_COMPACT_POSTFORK);

    const uint256 expected_main_digest = v2proof::ComputeV2SendStatementDigest(
        main_tx,
        main_consensus,
        main_consensus.nShieldedMatRiCTDisableHeight);
    const uint256 expected_alt_digest = v2proof::ComputeV2SendStatementDigest(
        alt_tx,
        alt_params->GetConsensus(),
        alt_params->GetConsensus().nShieldedMatRiCTDisableHeight);

    BOOST_CHECK_EQUAL(main_bundle->header.proof_envelope.statement_digest, expected_main_digest);
    BOOST_CHECK_EQUAL(alt_bundle->header.proof_envelope.statement_digest, expected_alt_digest);
    BOOST_CHECK(main_bundle->header.proof_envelope.statement_digest !=
                alt_bundle->header.proof_envelope.statement_digest);
}

BOOST_AUTO_TEST_CASE(prefork_shield_only_send_keeps_legacy_bundle_without_output_chunks)
{
    const ShieldedNote output_note = MakeNote(/*value=*/725, /*seed=*/0x45);
    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x55);
    const auto output_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x65, /*nonce_byte=*/0x75),
        recipient.pk,
        shielded::v2::ScanDomain::OPAQUE);
    BOOST_REQUIRE(output_payload.has_value());

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *output_payload;
    BOOST_REQUIRE(output_input.IsValid());

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.vin = {CTxIn{COutPoint{Txid::FromUint256(uint256{0x91}), 0}}};

    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(tx_template,
                                                      uint256{},
                                                      {},
                                                      {output_input},
                                                      /*fee=*/0,
                                                      {},
                                                      reject_reason);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);

    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK_EQUAL(bundle->header.family_id, shielded::v2::TransactionFamily::V2_SEND);
    BOOST_CHECK_EQUAL(bundle->header.proof_envelope.proof_kind, shielded::v2::ProofKind::NONE);
    BOOST_CHECK(bundle->output_chunks.empty());
    BOOST_CHECK_EQUAL(bundle->header.output_chunk_count, 0U);
    BOOST_CHECK(bundle->header.output_chunk_root.IsNull());
}

BOOST_AUTO_TEST_CASE(postfork_direct_send_encoding_elides_value_balance_on_wire)
{
    const ShieldedNote input_note = MakeNote(/*value=*/800, /*seed=*/0x47);
    const auto input_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note);
    BOOST_REQUIRE(input_account.has_value());
    const uint256 input_commitment = smile2::ComputeCompactPublicAccountHash(*input_account);
    const auto account_leaf_commitment = shielded::registry::ComputeAccountLeafCommitmentFromNote(
        input_note,
        input_commitment,
        shielded::registry::MakeDirectSendAccountLeafHint());
    BOOST_REQUIRE(account_leaf_commitment.has_value());
    const auto account_registry_witness =
        test::shielded::MakeSingleLeafRegistryWitness(input_commitment, *input_account);
    BOOST_REQUIRE(account_registry_witness.has_value());

    shielded::v2::SpendDescription spend;
    spend.nullifier = uint256{0x71};
    spend.merkle_anchor = uint256{0x72};
    spend.account_leaf_commitment = *account_leaf_commitment;
    spend.account_registry_proof = account_registry_witness->second;

    const ShieldedNote output_note = MakeNote(/*value=*/725, /*seed=*/0x58);
    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x68);
    auto output_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        output_note);
    BOOST_REQUIRE(output_account.has_value());
    const auto output_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x78, /*nonce_byte=*/0x88),
        recipient.pk,
        shielded::v2::ScanDomain::OPAQUE);
    BOOST_REQUIRE(output_payload.has_value());

    shielded::v2::OutputDescription output;
    output.note_class = shielded::v2::NoteClass::USER;
    output.smile_account = *output_account;
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*output_account);
    output.value_commitment = smile2::ComputeSmileOutputCoinHash(output_account->public_coin);
    output.encrypted_note = *output_payload;

    shielded::v2::SendPayload payload;
    payload.spend_anchor = spend.merkle_anchor;
    payload.account_registry_anchor = account_registry_witness->first;
    payload.spends = {spend};
    payload.output_encoding = shielded::v2::SendOutputEncoding::SMILE_COMPACT_POSTFORK;
    payload.output_note_class = shielded::v2::NoteClass::USER;
    payload.output_scan_domain = shielded::v2::ScanDomain::OPAQUE;
    payload.outputs = {output};
    payload.value_balance = 75;
    payload.fee = 75;

    BOOST_REQUIRE(payload.IsValid());
    BOOST_REQUIRE(payload.output_encoding == shielded::v2::SendOutputEncoding::SMILE_COMPACT_POSTFORK);
    BOOST_CHECK_EQUAL(payload.value_balance, payload.fee);

    shielded::v2::SendPayload legacy_payload = payload;
    legacy_payload.output_encoding = shielded::v2::SendOutputEncoding::SMILE_COMPACT;

    DataStream compact_postfork_stream;
    compact_postfork_stream << payload;
    DataStream legacy_compact_stream;
    legacy_compact_stream << legacy_payload;
    BOOST_CHECK_EQUAL(legacy_compact_stream.size(), compact_postfork_stream.size() + sizeof(CAmount));

    shielded::v2::SendPayload decoded_payload;
    compact_postfork_stream >> decoded_payload;
    BOOST_CHECK(decoded_payload.output_encoding ==
                shielded::v2::SendOutputEncoding::SMILE_COMPACT_POSTFORK);
    BOOST_CHECK_EQUAL(decoded_payload.value_balance, decoded_payload.fee);
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_matches_contextual_verifier)
{
    const std::vector<unsigned char> spending_key(32, 0x42);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0x61);
    const ShieldedNote output_note = MakeNote(/*value=*/4900, /*seed=*/0x71);

    const auto input_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note);
    BOOST_REQUIRE(input_account.has_value());
    const uint256 input_chain_commitment = smile2::ComputeCompactPublicAccountHash(*input_account);

    const size_t real_index = 3;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_chain_commitment, real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);
    const std::vector<smile2::wallet::SmileRingMember> smile_ring_members =
        BuildSmileRingMembers(ring_members, input_note, input_chain_commitment, real_index);
    BOOST_REQUIRE_EQUAL(smile_ring_members.size(), ring_members.size());

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x81);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x91, /*nonce_byte=*/0xa1);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input =
        MakeDirectSpendInput(input_note,
                             ring_positions,
                             ring_members,
                             real_index,
                             input_chain_commitment,
                             smile_ring_members);

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
    BOOST_CHECK(built->IsValid());
    BOOST_CHECK(reject_reason.empty());
    BOOST_CHECK(built->witness.use_smile);

    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK(bundle->IsValid());
    BOOST_CHECK(shielded::v2::BundleHasSemanticFamily(*bundle,
                                                      shielded::v2::TransactionFamily::V2_SEND));

    const auto& payload = std::get<shielded::v2::SendPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.spends.size(), 1U);
    BOOST_REQUIRE_EQUAL(payload.outputs.size(), 1U);
    BOOST_CHECK_EQUAL(payload.fee, 100);
    BOOST_CHECK_EQUAL(payload.value_balance, payload.fee);
    BOOST_CHECK(payload.spends[0].merkle_anchor == tree.Root());
    BOOST_CHECK(payload.spends[0].note_commitment.IsNull());
    const auto expected_account_leaf_commitment = shielded::registry::ComputeAccountLeafCommitmentFromNote(
        input_note,
        input_chain_commitment,
        shielded::registry::MakeDirectSendAccountLeafHint());
    BOOST_REQUIRE(expected_account_leaf_commitment.has_value());
    BOOST_CHECK_EQUAL(payload.spends[0].account_leaf_commitment, *expected_account_leaf_commitment);
    BOOST_REQUIRE(payload.outputs[0].smile_account.has_value());
    BOOST_CHECK(payload.outputs[0].note_commitment ==
                smile2::ComputeCompactPublicAccountHash(*payload.outputs[0].smile_account));
    BOOST_CHECK_EQUAL(built->witness.spends[0].real_index, 0U);
    BOOST_CHECK_EQUAL_COLLECTIONS(built->witness.spends[0].ring_positions.begin(),
                                  built->witness.spends[0].ring_positions.end(),
                                  ring_positions.begin(),
                                  ring_positions.end());

    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(CTransaction{built->tx});
    BOOST_CHECK(statement.IsValid());
    BOOST_CHECK(statement.envelope.proof_kind == shielded::v2::ProofKind::DIRECT_SMILE);
    BOOST_CHECK(bundle->header.proof_envelope.statement_digest == statement.envelope.statement_digest);

    auto context = v2proof::ParseV2SendProof(*bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_CHECK(v2proof::VerifyV2SendProof(*bundle, *context, {smile_ring_members}));

    auto decoded = shielded::v2::DecodeLegacyEncryptedNotePayload(payload.outputs[0].encrypted_note);
    BOOST_REQUIRE(decoded.has_value());
    BOOST_CHECK(payload.outputs[0].encrypted_note.scan_domain == shielded::v2::ScanDomain::OPAQUE);
    BOOST_CHECK(payload.outputs[0].encrypted_note.scan_hint ==
                shielded::v2::ComputeOpaquePublicScanHint(*decoded));
    BOOST_CHECK(!shielded::v2::LegacyEncryptedNotePayloadMatchesRecipient(payload.outputs[0].encrypted_note,
                                                                          *decoded,
                                                                          recipient.pk));
    auto decrypted = shielded::NoteEncryption::TryDecrypt(*decoded, recipient.pk, recipient.sk);
    BOOST_REQUIRE(decrypted.has_value());
    BOOST_CHECK_EQUAL(decrypted->value, output_note.value);
    BOOST_CHECK(decrypted->GetCommitment() == output_note.GetCommitment());
    BOOST_CHECK(decrypted->GetCommitment() != payload.outputs[0].note_commitment);
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_accepts_transparent_outputs)
{
    const std::vector<unsigned char> spending_key(32, 0x42);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0x62);
    const ShieldedNote output_note = MakeNote(/*value=*/4300, /*seed=*/0x72);

    const auto input_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note);
    BOOST_REQUIRE(input_account.has_value());
    const uint256 input_chain_commitment = smile2::ComputeCompactPublicAccountHash(*input_account);

    const size_t real_index = 4;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_chain_commitment, real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);
    const std::vector<smile2::wallet::SmileRingMember> smile_ring_members =
        BuildSmileRingMembers(ring_members, input_note, input_chain_commitment, real_index);
    BOOST_REQUIRE_EQUAL(smile_ring_members.size(), ring_members.size());

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x82);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x92, /*nonce_byte=*/0xa2);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input =
        MakeDirectSpendInput(input_note,
                             ring_positions,
                             ring_members,
                             real_index,
                             input_chain_commitment,
                             smile_ring_members);

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = 19;
    tx_template.vout.emplace_back(/*value=*/600, CScript{} << OP_TRUE);

    std::string reject_reason;
    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xAB);
    auto built = shielded::v2::BuildV2SendTransaction(tx_template,
                                                      tree.Root(),
                                                      {spend_input},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()});
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_CHECK(built->IsValid());

    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK(bundle->IsValid());
    BOOST_REQUIRE_EQUAL(built->tx.vout.size(), 1U);
    BOOST_CHECK_EQUAL(built->tx.vout[0].nValue, 600);

    const auto& payload = std::get<shielded::v2::SendPayload>(bundle->payload);
    BOOST_CHECK_EQUAL(payload.fee, 100);
    BOOST_CHECK_EQUAL(payload.value_balance, 700);

    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(CTransaction{built->tx});
    BOOST_REQUIRE(statement.IsValid());

    auto context = v2proof::ParseV2SendProof(*bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_CHECK(v2proof::VerifyV2SendProof(*bundle, *context, {smile_ring_members}));
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_supports_proofless_transparent_deposits)
{
    const ShieldedNote output_note = MakeNote(/*value=*/4900, /*seed=*/0x73);
    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x83);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x93, /*nonce_byte=*/0xa3);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;
    BOOST_REQUIRE(output_input.IsValid());

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = 29;
    tx_template.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{0x91}), 0});

    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(tx_template,
                                                      uint256{},
                                                      {},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      {},
                                                      reject_reason);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_CHECK(built->IsValid());

    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_CHECK(bundle->IsValid());

    const auto& payload = std::get<shielded::v2::SendPayload>(bundle->payload);
    BOOST_CHECK(payload.spends.empty());
    BOOST_CHECK(payload.spend_anchor.IsNull());
    BOOST_CHECK(payload.account_registry_anchor.IsNull());
    BOOST_CHECK(payload.output_encoding == shielded::v2::SendOutputEncoding::LEGACY);
    BOOST_CHECK_EQUAL(payload.fee, 100);
    BOOST_CHECK_EQUAL(payload.value_balance, -output_note.value);
    BOOST_CHECK(bundle->proof_payload.empty());
    BOOST_CHECK(bundle->header.proof_envelope.proof_kind == shielded::v2::ProofKind::NONE);

    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(CTransaction{built->tx});
    BOOST_REQUIRE(statement.IsValid());
    BOOST_CHECK(statement.envelope.proof_kind == shielded::v2::ProofKind::NONE);

    auto context = v2proof::ParseV2SendProof(*bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_CHECK(v2proof::VerifyV2SendProof(*bundle, *context, std::vector<std::vector<uint256>>{}));
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_roundtrips_through_transaction_serialization)
{
    const std::vector<unsigned char> spending_key(32, 0x24);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0x34);
    const ShieldedNote output_note = MakeNote(/*value=*/4900, /*seed=*/0x44);

    const size_t real_index = 5;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_note.GetCommitment(), real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x54);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x64, /*nonce_byte=*/0x74);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input =
        MakeDirectSpendInput(input_note, ring_positions, ring_members, real_index);

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = 33;

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

    DataStream ss;
    ss << TX_WITH_WITNESS(CTransaction{built->tx});

    CMutableTransaction decoded_mutable;
    ss >> TX_WITH_WITNESS(decoded_mutable);
    BOOST_CHECK(ss.empty());

    CTransaction decoded_tx{std::move(decoded_mutable)};
    BOOST_REQUIRE(decoded_tx.HasShieldedBundle());
    BOOST_REQUIRE(decoded_tx.GetShieldedBundle().HasV2Bundle());

    const auto* decoded_bundle = decoded_tx.GetShieldedBundle().GetV2Bundle();
    BOOST_REQUIRE(decoded_bundle != nullptr);
    BOOST_REQUIRE(shielded::v2::BundleHasSemanticFamily(*decoded_bundle,
                                                        shielded::v2::TransactionFamily::V2_SEND));

    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(decoded_tx);
    BOOST_REQUIRE(statement.IsValid());

    auto context = v2proof::ParseV2SendProof(*decoded_bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(context->witness.spends.size(), 1U);
    BOOST_CHECK_EQUAL(context->witness.spends[0].real_index, 0U);
    BOOST_CHECK_EQUAL_COLLECTIONS(context->witness.spends[0].ring_positions.begin(),
                                  context->witness.spends[0].ring_positions.end(),
                                  ring_positions.begin(),
                                  ring_positions.end());
}

BOOST_AUTO_TEST_CASE(build_prefork_v2_send_lifecycle_transaction_roundtrips_through_transaction_serialization)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;
    const int32_t prefork_height = activation_height - 1;

    CPQKey subject_key;
    CPQKey successor_key;
    subject_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    successor_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(subject_key.IsValid());
    BOOST_REQUIRE(successor_key.IsValid());

    const ShieldedNote output_note = MakeNote(/*value=*/10000, /*seed=*/0x77);
    const auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        output_note);
    BOOST_REQUIRE(smile_account.has_value());
    const uint256 note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);

    const auto recipient = BuildRecipientKeyPair(/*seed=*/0x87);
    const auto encrypted_note = BuildEncryptedNote(output_note,
                                                   recipient.pk,
                                                   /*kem_seed_byte=*/0x97,
                                                   /*nonce_byte=*/0xA7);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::OPAQUE);
    BOOST_REQUIRE(encrypted_payload.has_value());

    const auto subject = MakeLifecycleAddress(subject_key, 0x20);
    const auto successor = MakeLifecycleAddress(successor_key, 0x40);

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::OPERATOR;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;
    output_input.lifecycle_control = MakeLifecycleControl(
        shielded::v2::AddressLifecycleControlKind::ROTATE,
        subject_key,
        subject,
        successor,
        note_commitment);

    std::string reject_reason;
    CMutableTransaction tx_template;
    tx_template.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{0x91}), 0},
                                 CScript{},
                                 0xffffffff);

    auto built = shielded::v2::BuildV2SendTransaction(tx_template,
                                                      uint256::ZERO,
                                                      {},
                                                      {output_input},
                                                      /*fee=*/10000,
                                                      {},
                                                      reject_reason,
                                                      {},
                                                      &consensus,
                                                      prefork_height);
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_REQUIRE(built->IsValid());

    DataStream ss;
    ss << TX_WITH_WITNESS(CTransaction{built->tx});

    CMutableTransaction decoded_mutable;
    ss >> TX_WITH_WITNESS(decoded_mutable);
    BOOST_CHECK(ss.empty());

    CTransaction decoded_tx{std::move(decoded_mutable)};
    BOOST_REQUIRE(decoded_tx.HasShieldedBundle());
    BOOST_REQUIRE(decoded_tx.GetShieldedBundle().HasV2Bundle());
    const auto* bundle = decoded_tx.GetShieldedBundle().GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE(shielded::v2::BundleHasSemanticFamily(*bundle,
                                                        shielded::v2::TransactionFamily::V2_SEND));
    BOOST_CHECK_EQUAL(bundle->header.family_id, shielded::v2::TransactionFamily::V2_SEND);

    const auto& payload = std::get<shielded::v2::SendPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.lifecycle_controls.size(), 1U);
    BOOST_CHECK_EQUAL(payload.output_note_class, shielded::v2::NoteClass::OPERATOR);
    BOOST_CHECK_EQUAL(payload.output_scan_domain, shielded::v2::ScanDomain::OPAQUE);
    BOOST_CHECK(!payload.legacy_omit_lifecycle_controls_count);
    BOOST_CHECK(shielded::v2::VerifyAddressLifecycleControl(payload.lifecycle_controls.front(),
                                                            payload.outputs.front().note_commitment));
}

BOOST_AUTO_TEST_CASE(build_postfork_v2_send_rejects_lifecycle_controls)
{
    const auto& consensus = Params().GetConsensus();
    const int32_t activation_height = consensus.nShieldedMatRiCTDisableHeight;

    CPQKey subject_key;
    CPQKey successor_key;
    subject_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    successor_key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(subject_key.IsValid());
    BOOST_REQUIRE(successor_key.IsValid());

    const ShieldedNote output_note = MakeNote(/*value=*/10000, /*seed=*/0x79);
    const auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        output_note);
    BOOST_REQUIRE(smile_account.has_value());
    const uint256 note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);

    const auto recipient = BuildRecipientKeyPair(/*seed=*/0x89);
    const auto encrypted_note = BuildEncryptedNote(output_note,
                                                   recipient.pk,
                                                   /*kem_seed_byte=*/0x99,
                                                   /*nonce_byte=*/0xA9);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::OPAQUE);
    BOOST_REQUIRE(encrypted_payload.has_value());

    const auto subject = MakeLifecycleAddress(subject_key, 0x22);
    const auto successor = MakeLifecycleAddress(successor_key, 0x44);

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::OPERATOR;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;
    output_input.lifecycle_control = MakeLifecycleControl(
        shielded::v2::AddressLifecycleControlKind::ROTATE,
        subject_key,
        subject,
        successor,
        note_commitment);

    std::string reject_reason;
    CMutableTransaction tx_template;
    tx_template.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{0x92}), 0},
                                 CScript{},
                                 0xffffffff);

    auto built = shielded::v2::BuildV2SendTransaction(tx_template,
                                                      uint256::ZERO,
                                                      {},
                                                      {output_input},
                                                      /*fee=*/10000,
                                                      {},
                                                      reject_reason,
                                                      {},
                                                      &consensus,
                                                      activation_height);
    BOOST_CHECK(!built.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-v2-builder-lifecycle-control");
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_stays_within_standard_policy_weight_for_single_input_two_outputs)
{
    const std::vector<unsigned char> spending_key(32, 0x52);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0x62);
    const ShieldedNote output_note_a = MakeNote(/*value=*/2000, /*seed=*/0x72);
    const ShieldedNote output_note_b = MakeNote(/*value=*/2900, /*seed=*/0x82);

    const size_t real_index = 7;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_note.GetCommitment(), real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);

    const mlkem::KeyPair recipient_a = BuildRecipientKeyPair(/*seed=*/0x92);
    const mlkem::KeyPair recipient_b = BuildRecipientKeyPair(/*seed=*/0xa2);
    const shielded::EncryptedNote encrypted_note_a =
        BuildEncryptedNote(output_note_a, recipient_a.pk, /*kem_seed_byte=*/0xb2, /*nonce_byte=*/0xc2);
    const shielded::EncryptedNote encrypted_note_b =
        BuildEncryptedNote(output_note_b, recipient_b.pk, /*kem_seed_byte=*/0xd2, /*nonce_byte=*/0xe2);
    auto encrypted_payload_a = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note_a,
        recipient_a.pk,
        shielded::v2::ScanDomain::USER);
    auto encrypted_payload_b = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note_b,
        recipient_b.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload_a.has_value());
    BOOST_REQUIRE(encrypted_payload_b.has_value());

    shielded::v2::V2SendSpendInput spend_input =
        MakeDirectSpendInput(input_note, ring_positions, ring_members, real_index);

    shielded::v2::V2SendOutputInput output_input_a;
    output_input_a.note_class = shielded::v2::NoteClass::USER;
    output_input_a.note = output_note_a;
    output_input_a.encrypted_note = *encrypted_payload_a;

    shielded::v2::V2SendOutputInput output_input_b;
    output_input_b.note_class = shielded::v2::NoteClass::USER;
    output_input_b.note = output_note_b;
    output_input_b.encrypted_note = *encrypted_payload_b;

    CMutableTransaction tx_template;
    tx_template.version = CTransaction::CURRENT_VERSION;
    tx_template.nLockTime = 51;

    std::string reject_reason;
    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xAA); // deterministic test entropy
    auto built = shielded::v2::BuildV2SendTransaction(tx_template,
                                                      tree.Root(),
                                                      {spend_input},
                                                      {output_input_a, output_input_b},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()});
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);

    const CTransaction tx{built->tx};
    const int64_t policy_weight = GetShieldedPolicyWeight(tx);
    const size_t serialized_size = ::GetSerializeSize(TX_WITH_WITNESS(tx));
    kernel::MemPoolOptions opts;
    std::string reason;

    // Direct-spend v2_send remains standard under the shielded policy limit.
    BOOST_CHECK_LE(policy_weight, MAX_STANDARD_SHIELDED_POLICY_WEIGHT);
    BOOST_CHECK_MESSAGE(IsStandardTx(tx, opts, reason),
                        strprintf("wallet-shaped v2_send remained non-standard: "
                                  "reason=%s policy_weight=%d serialized_size=%u",
                                  reason,
                                  policy_weight,
                                  static_cast<unsigned int>(serialized_size)));
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_rejects_fee_only_without_shielded_outputs)
{
    const std::vector<unsigned char> spending_key(32, 0x53);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0x63);

    const size_t real_index = 7;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_note.GetCommitment(), real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);

    shielded::v2::V2SendSpendInput spend_input =
        MakeDirectSpendInput(input_note, ring_positions, ring_members, real_index);

    std::string reject_reason;
    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xAB);
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      {spend_input},
                                                      {},
                                                      /*fee=*/5000,
                                                      spending_key,
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(),
                                                                                rng_entropy.size()});
    BOOST_CHECK(!built.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-v2-builder-output-count");
}

BOOST_AUTO_TEST_CASE(v2_send_verify_cost_scales_with_ring_size)
{
    const ShieldedNote input_note = MakeNote(/*value=*/30 * COIN, /*seed=*/0x61);
    const auto recipient = BuildRecipientKeyPair(0x71);
    const ShieldedNote output_note = MakeNote(/*value=*/29 * COIN, /*seed=*/0x81);
    const auto input_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note);
    BOOST_REQUIRE(input_account.has_value());
    const uint256 input_chain_commitment = smile2::ComputeCompactPublicAccountHash(*input_account);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, 0x72, 0x73);
    auto payload =
        shielded::v2::EncodeLegacyEncryptedNotePayload(encrypted_note, recipient.pk, shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(payload.has_value());
    const shielded::v2::V2SendOutputInput output_input{
        shielded::v2::NoteClass::USER,
        output_note,
        *payload,
        std::nullopt,
    };
    const auto tree = BuildTree(input_chain_commitment, /*real_index=*/3);
    const auto ring_positions = BuildRingPositions();
    const auto ring_members = BuildRingMembers(tree, ring_positions);
    const auto smile_ring_members =
        BuildSmileRingMembers(ring_members, input_note, input_chain_commitment, /*real_index=*/3);
    BOOST_REQUIRE_EQUAL(smile_ring_members.size(), ring_members.size());
    const auto spend_input = MakeDirectSpendInput(input_note,
                                                 ring_positions,
                                                 ring_members,
                                                 /*real_index=*/3,
                                                 input_chain_commitment,
                                                 smile_ring_members);

    std::string reject_reason;
    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0x44);
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      {spend_input},
                                                      {output_input},
                                                      /*fee=*/COIN,
                                                      std::vector<unsigned char>(32, 0x11),
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()});
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);

    const auto ring8_bundle = built->tx.shielded_bundle;
    auto ring32_bundle = built->tx.shielded_bundle;
    auto* mutable_bundle = ring32_bundle.v2_bundle ? &*ring32_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(mutable_bundle != nullptr);
    auto witness = v2proof::ParseV2SendWitness(*mutable_bundle, reject_reason);
    BOOST_REQUIRE_MESSAGE(witness.has_value(), reject_reason);
    BOOST_REQUIRE_EQUAL(witness->spends.size(), 1U);
    witness->spends.front().ring_positions = BuildRingPositions(/*ring_size=*/32);
    BOOST_REQUIRE(witness->IsValid(/*expected_input_count=*/1, /*expected_output_count=*/1));
    ReplaceV2SendWitness(*mutable_bundle, *witness);

    BOOST_CHECK_EQUAL(GetShieldedVerifyCost(ring8_bundle), 115U);
    BOOST_CHECK_EQUAL(GetShieldedVerifyCost(ring32_bundle), 415U);
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_supports_multi_input_shared_ring_and_distributed_fee)
{
    constexpr size_t ring_size{16};
    const std::vector<unsigned char> spending_key(32, 0x6A);
    const ShieldedNote input_note_a = MakeNote(/*value=*/60, /*seed=*/0x11);
    const ShieldedNote input_note_b = MakeNote(/*value=*/500, /*seed=*/0x21);
    const ShieldedNote output_note = MakeNote(/*value=*/460, /*seed=*/0x31);

    const auto input_account_a = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_a);
    const auto input_account_b = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_b);
    BOOST_REQUIRE(input_account_a.has_value());
    BOOST_REQUIRE(input_account_b.has_value());
    const uint256 input_chain_commitment_a = smile2::ComputeCompactPublicAccountHash(*input_account_a);
    const uint256 input_chain_commitment_b = smile2::ComputeCompactPublicAccountHash(*input_account_b);

    const size_t real_index_a = 2;
    const size_t real_index_b = 9;
    const shielded::ShieldedMerkleTree tree = BuildTree({
        {real_index_a, input_chain_commitment_a},
        {real_index_b, input_chain_commitment_b},
    }, ring_size);
    const std::vector<uint64_t> ring_positions = BuildRingPositions(ring_size);
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);

    std::vector<smile2::wallet::SmileRingMember> shared_smile_ring_members;
    shared_smile_ring_members.reserve(ring_members.size());
    for (const auto& commitment : ring_members) {
        shared_smile_ring_members.push_back(
            smile2::wallet::BuildPlaceholderRingMember(smile2::wallet::SMILE_GLOBAL_SEED, commitment));
    }
    auto real_member_a = smile2::wallet::BuildRingMemberFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_a,
        input_chain_commitment_a);
    auto real_member_b = smile2::wallet::BuildRingMemberFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_b,
        input_chain_commitment_b);
    BOOST_REQUIRE(real_member_a.has_value());
    BOOST_REQUIRE(real_member_b.has_value());
    shared_smile_ring_members[real_index_a] = *real_member_a;
    shared_smile_ring_members[real_index_b] = *real_member_b;

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x41);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x51, /*nonce_byte=*/0x61);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input_a =
        MakeDirectSpendInput(input_note_a,
                             ring_positions,
                             ring_members,
                             real_index_a,
                             input_chain_commitment_a,
                             shared_smile_ring_members);
    shielded::v2::V2SendSpendInput spend_input_b =
        MakeDirectSpendInput(input_note_b,
                             ring_positions,
                             ring_members,
                             real_index_b,
                             input_chain_commitment_b,
                             shared_smile_ring_members);
    std::vector<shielded::v2::V2SendSpendInput> spend_inputs{spend_input_a, spend_input_b};
    BOOST_REQUIRE(test::shielded::AttachAccountRegistryWitnesses(spend_inputs));
    spend_input_a = spend_inputs[0];
    spend_input_b = spend_inputs[1];

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    std::string reject_reason;
    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xAA);
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      {spend_input_a, spend_input_b},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()});
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);

    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    BOOST_REQUIRE_EQUAL(built->witness.spends.size(), 2U);
    BOOST_CHECK_EQUAL_COLLECTIONS(built->witness.spends[0].ring_positions.begin(),
                                  built->witness.spends[0].ring_positions.end(),
                                  built->witness.spends[1].ring_positions.begin(),
                                  built->witness.spends[1].ring_positions.end());
    BOOST_CHECK_EQUAL(built->witness.spends[0].real_index, 0U);
    BOOST_CHECK_EQUAL(built->witness.spends[1].real_index, 0U);

    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(CTransaction{built->tx});
    BOOST_REQUIRE(statement.IsValid());

    auto context = v2proof::ParseV2SendProof(*bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_CHECK(v2proof::VerifyV2SendProof(*bundle,
                                           *context,
                                           {shared_smile_ring_members, shared_smile_ring_members}));
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_rejects_three_input_direct_smile_spends)
{
    const std::vector<unsigned char> spending_key(32, 0x6B);
    const ShieldedNote input_note_a = MakeNote(/*value=*/300, /*seed=*/0x12);
    const ShieldedNote input_note_b = MakeNote(/*value=*/320, /*seed=*/0x22);
    const ShieldedNote input_note_c = MakeNote(/*value=*/340, /*seed=*/0x32);
    const ShieldedNote output_note = MakeNote(/*value=*/900, /*seed=*/0x42);

    const auto input_account_a = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_a);
    const auto input_account_b = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_b);
    const auto input_account_c = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_c);
    BOOST_REQUIRE(input_account_a.has_value());
    BOOST_REQUIRE(input_account_b.has_value());
    BOOST_REQUIRE(input_account_c.has_value());
    const uint256 input_chain_commitment_a = smile2::ComputeCompactPublicAccountHash(*input_account_a);
    const uint256 input_chain_commitment_b = smile2::ComputeCompactPublicAccountHash(*input_account_b);
    const uint256 input_chain_commitment_c = smile2::ComputeCompactPublicAccountHash(*input_account_c);

    const size_t real_index_a = 1;
    const size_t real_index_b = 3;
    const size_t real_index_c = 6;
    const shielded::ShieldedMerkleTree tree = BuildTree({
        {real_index_a, input_chain_commitment_a},
        {real_index_b, input_chain_commitment_b},
        {real_index_c, input_chain_commitment_c},
    });
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);

    std::vector<smile2::wallet::SmileRingMember> shared_smile_ring_members;
    shared_smile_ring_members.reserve(ring_members.size());
    for (const auto& commitment : ring_members) {
        shared_smile_ring_members.push_back(
            smile2::wallet::BuildPlaceholderRingMember(smile2::wallet::SMILE_GLOBAL_SEED, commitment));
    }
    const auto real_member_a = smile2::wallet::BuildRingMemberFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_a,
        input_chain_commitment_a);
    const auto real_member_b = smile2::wallet::BuildRingMemberFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_b,
        input_chain_commitment_b);
    const auto real_member_c = smile2::wallet::BuildRingMemberFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_c,
        input_chain_commitment_c);
    BOOST_REQUIRE(real_member_a.has_value());
    BOOST_REQUIRE(real_member_b.has_value());
    BOOST_REQUIRE(real_member_c.has_value());
    shared_smile_ring_members[real_index_a] = *real_member_a;
    shared_smile_ring_members[real_index_b] = *real_member_b;
    shared_smile_ring_members[real_index_c] = *real_member_c;

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x52);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x62, /*nonce_byte=*/0x72);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    std::vector<shielded::v2::V2SendSpendInput> spend_inputs{
        MakeDirectSpendInput(input_note_a,
                             ring_positions,
                             ring_members,
                             real_index_a,
                             input_chain_commitment_a,
                             shared_smile_ring_members),
        MakeDirectSpendInput(input_note_b,
                             ring_positions,
                             ring_members,
                             real_index_b,
                             input_chain_commitment_b,
                             shared_smile_ring_members),
        MakeDirectSpendInput(input_note_c,
                             ring_positions,
                             ring_members,
                             real_index_c,
                             input_chain_commitment_c,
                             shared_smile_ring_members),
    };
    BOOST_REQUIRE(test::shielded::AttachAccountRegistryWitnesses(spend_inputs));

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      spend_inputs,
                                                      {output_input},
                                                      /*fee=*/60,
                                                      spending_key,
                                                      reject_reason);
    BOOST_CHECK(!built.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-v2-builder-smile-limits");
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_rejects_missing_shared_smile_ring_members)
{
    const std::vector<unsigned char> spending_key(32, 0x6A);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0x16);
    const ShieldedNote output_note = MakeNote(/*value=*/4900, /*seed=*/0x26);
    const size_t real_index = 2;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_note.GetCommitment(), real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x46);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x56, /*nonce_byte=*/0x66);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    auto spend_input = MakeDirectSpendInput(input_note, ring_positions, ring_members, real_index);
    spend_input.smile_ring_members.clear();

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xAB);
    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      {spend_input},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(),
                                                                                rng_entropy.size()});
    BOOST_CHECK(!built.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-v2-builder-smile-ring-members");
}

BOOST_AUTO_TEST_CASE(parse_v2_send_proof_rejects_legacy_native_witness_under_direct_smile_statement)
{
    const std::vector<unsigned char> spending_key(32, 0x73);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0x17);
    const ShieldedNote output_note = MakeNote(/*value=*/4900, /*seed=*/0x27);

    const auto input_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note);
    BOOST_REQUIRE(input_account.has_value());
    const uint256 input_chain_commitment = smile2::ComputeCompactPublicAccountHash(*input_account);
    const size_t real_index = 3;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_chain_commitment, real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);
    const std::vector<smile2::wallet::SmileRingMember> smile_ring_members =
        BuildSmileRingMembers(ring_members, input_note, input_chain_commitment, real_index);
    BOOST_REQUIRE_EQUAL(smile_ring_members.size(), ring_members.size());

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x37);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x47, /*nonce_byte=*/0x57);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input =
        MakeDirectSpendInput(input_note,
                             ring_positions,
                             ring_members,
                             real_index,
                             input_chain_commitment,
                             smile_ring_members);

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xC1);
    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      {spend_input},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(),
                                                                                rng_entropy.size()});
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_REQUIRE(built->witness.use_smile);

    CMutableTransaction mutated_tx = built->tx;
    BOOST_REQUIRE(mutated_tx.shielded_bundle.v2_bundle.has_value());
    auto& mutated_bundle = *mutated_tx.shielded_bundle.v2_bundle;
    const auto statement = v2proof::DescribeV2SendStatement(CTransaction{mutated_tx});
    BOOST_REQUIRE(statement.IsValid());
    DataStream witness_stream{mutated_bundle.proof_payload};
    const size_t witness_size = witness_stream.size();
    uint8_t witness_version{0};
    uint64_t spend_count{0};
    witness_stream >> witness_version;
    witness_stream >> COMPACTSIZE(spend_count);
    BOOST_REQUIRE_EQUAL(spend_count, 1U);
    v2proof::V2SendSpendWitness serialized_spend;
    witness_stream >> serialized_spend;
    const size_t proof_tag_offset = witness_size - witness_stream.size();
    BOOST_REQUIRE_LT(proof_tag_offset, mutated_bundle.proof_payload.size());
    mutated_bundle.proof_payload[proof_tag_offset] = v2proof::V2SendWitness::PROOF_TAG_MATRICT;

    reject_reason.clear();
    auto mutated_context = v2proof::ParseV2SendProof(mutated_bundle, statement, reject_reason);
    BOOST_CHECK(!mutated_context.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-proof-encoding");
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_supports_multi_input_shared_smile_ring_and_rejects_drifted_snapshots)
{
    constexpr size_t ring_size{16};
    const std::vector<unsigned char> spending_key(32, 0x7A);
    const ShieldedNote input_note_a = MakeNote(/*value=*/60, /*seed=*/0x15);
    const ShieldedNote input_note_b = MakeNote(/*value=*/500, /*seed=*/0x25);
    const ShieldedNote output_note = MakeNote(/*value=*/460, /*seed=*/0x35);

    const auto input_account_a = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_a);
    const auto input_account_b = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_b);
    BOOST_REQUIRE(input_account_a.has_value());
    BOOST_REQUIRE(input_account_b.has_value());
    const uint256 input_chain_commitment_a = smile2::ComputeCompactPublicAccountHash(*input_account_a);
    const uint256 input_chain_commitment_b = smile2::ComputeCompactPublicAccountHash(*input_account_b);

    const size_t real_index_a = 2;
    const size_t real_index_b = 9;
    const shielded::ShieldedMerkleTree tree = BuildTree({
        {real_index_a, input_chain_commitment_a},
        {real_index_b, input_chain_commitment_b},
    }, ring_size);
    const std::vector<uint64_t> ring_positions = BuildRingPositions(ring_size);
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);

    std::vector<smile2::wallet::SmileRingMember> shared_smile_ring_members;
    shared_smile_ring_members.reserve(ring_members.size());
    for (const auto& commitment : ring_members) {
        shared_smile_ring_members.push_back(
            smile2::wallet::BuildPlaceholderRingMember(smile2::wallet::SMILE_GLOBAL_SEED, commitment));
    }
    auto real_member_a = smile2::wallet::BuildRingMemberFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_a,
        input_chain_commitment_a);
    auto real_member_b = smile2::wallet::BuildRingMemberFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note_b,
        input_chain_commitment_b);
    BOOST_REQUIRE(real_member_a.has_value());
    BOOST_REQUIRE(real_member_b.has_value());
    shared_smile_ring_members[real_index_a] = *real_member_a;
    shared_smile_ring_members[real_index_b] = *real_member_b;

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x45);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x55, /*nonce_byte=*/0x65);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input_a = MakeDirectSpendInput(input_note_a,
                                                                        ring_positions,
                                                                        ring_members,
                                                                        real_index_a,
                                                                        input_chain_commitment_a,
                                                                        shared_smile_ring_members);
    shielded::v2::V2SendSpendInput spend_input_b = MakeDirectSpendInput(input_note_b,
                                                                        ring_positions,
                                                                        ring_members,
                                                                        real_index_b,
                                                                        input_chain_commitment_b,
                                                                        shared_smile_ring_members);
    std::vector<shielded::v2::V2SendSpendInput> spend_inputs{spend_input_a, spend_input_b};
    BOOST_REQUIRE(test::shielded::AttachAccountRegistryWitnesses(spend_inputs));
    spend_input_a = spend_inputs[0];
    spend_input_b = spend_inputs[1];

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xDA);
    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      {spend_input_a, spend_input_b},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()});
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_REQUIRE(built->witness.use_smile);

    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    const auto& payload = std::get<shielded::v2::SendPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.spends.size(), 2U);
    for (size_t i = 0; i < payload.spends.size(); ++i) {
        BOOST_CHECK(payload.spends[i].value_commitment ==
                    smile2::ComputeSmileDirectInputBindingHash(
                        Span<const smile2::wallet::SmileRingMember>{shared_smile_ring_members.data(),
                                                                    shared_smile_ring_members.size()},
                        payload.spends[i].merkle_anchor,
                        static_cast<uint32_t>(i),
                        payload.spends[i].nullifier));
    }

    const auto statement = v2proof::DescribeV2SendStatement(CTransaction{built->tx});
    BOOST_REQUIRE(statement.IsValid());
    auto context = v2proof::ParseV2SendProof(*bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_CHECK(v2proof::VerifyV2SendProof(*bundle,
                                           *context,
                                           {shared_smile_ring_members, shared_smile_ring_members}));

    auto drifted_ring = shared_smile_ring_members;
    BOOST_REQUIRE(!drifted_ring.empty());
    BOOST_REQUIRE(!drifted_ring[0].public_coin.t_msg.empty());
    drifted_ring[0].public_coin.t_msg[0].coeffs[0] =
        smile2::mod_q(drifted_ring[0].public_coin.t_msg[0].coeffs[0] + 1);
    BOOST_CHECK(!v2proof::VerifyV2SendProof(*bundle, *context, {shared_smile_ring_members, drifted_ring}));
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_uses_smile_commitments_for_direct_smile_outputs)
{
    const std::vector<unsigned char> spending_key(32, 0x5A);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0x14);
    const ShieldedNote output_note = MakeNote(/*value=*/4900, /*seed=*/0x24);

    const auto input_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note);
    BOOST_REQUIRE(input_account.has_value());
    const uint256 input_chain_commitment = smile2::ComputeCompactPublicAccountHash(*input_account);

    const size_t real_index = 6;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_chain_commitment, real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);
    const std::vector<smile2::wallet::SmileRingMember> smile_ring_members =
        BuildSmileRingMembers(ring_members, input_note, input_chain_commitment, real_index);
    BOOST_REQUIRE_EQUAL(smile_ring_members.size(), ring_members.size());

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x34);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x44, /*nonce_byte=*/0x54);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input = MakeDirectSpendInput(input_note,
                                                                      ring_positions,
                                                                      ring_members,
                                                                      real_index,
                                                                      input_chain_commitment,
                                                                      smile_ring_members);

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xAA);
    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      {spend_input},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()});
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_CHECK(built->witness.use_smile);

    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    const auto& payload = std::get<shielded::v2::SendPayload>(bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.spends.size(), 1U);
    BOOST_REQUIRE_EQUAL(payload.outputs.size(), 1U);
    BOOST_REQUIRE(payload.outputs[0].smile_account.has_value());
    const auto expected_smile_account_leaf_commitment =
        shielded::registry::ComputeAccountLeafCommitmentFromNote(
            input_note,
            input_chain_commitment,
            shielded::registry::MakeDirectSendAccountLeafHint());
    BOOST_REQUIRE(expected_smile_account_leaf_commitment.has_value());
    BOOST_CHECK_EQUAL(payload.spends[0].account_leaf_commitment,
                      *expected_smile_account_leaf_commitment);
    BOOST_CHECK(payload.spends[0].value_commitment ==
                smile2::ComputeSmileDirectInputBindingHash(
                    Span<const smile2::wallet::SmileRingMember>{smile_ring_members.data(),
                                                                smile_ring_members.size()},
                    payload.spends[0].merkle_anchor,
                    0,
                    payload.spends[0].nullifier));
    BOOST_CHECK(payload.outputs[0].note_commitment ==
                smile2::ComputeCompactPublicAccountHash(*payload.outputs[0].smile_account));
    BOOST_CHECK(payload.outputs[0].value_commitment ==
                smile2::ComputeSmileOutputCoinHash(payload.outputs[0].smile_account->public_coin));

    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(CTransaction{built->tx});
    BOOST_REQUIRE(statement.IsValid());
    BOOST_CHECK(statement.envelope.proof_kind == shielded::v2::ProofKind::DIRECT_SMILE);

    auto context = v2proof::ParseV2SendProof(*bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_CHECK(v2proof::VerifyV2SendProof(*bundle, *context, {smile_ring_members}));

    auto mutated_bundle = *bundle;
    auto& mutated_payload = std::get<shielded::v2::SendPayload>(mutated_bundle.payload);
    mutated_payload.value_balance = 0;
    mutated_bundle.header.payload_digest = shielded::v2::ComputeSendPayloadDigest(mutated_payload);

    CMutableTransaction mutated_tx = built->tx;
    mutated_tx.shielded_bundle.v2_bundle = mutated_bundle;
    const auto mutated_statement = v2proof::DescribeV2SendStatement(CTransaction{mutated_tx});
    BOOST_REQUIRE(mutated_statement.IsValid());
    mutated_bundle.header.proof_envelope.statement_digest = mutated_statement.envelope.statement_digest;
    mutated_tx.shielded_bundle.v2_bundle = mutated_bundle;

    reject_reason.clear();
    auto mutated_context = v2proof::ParseV2SendProof(*mutated_tx.shielded_bundle.v2_bundle,
                                                     mutated_statement,
                                                     reject_reason);
    BOOST_REQUIRE_MESSAGE(mutated_context.has_value(), reject_reason);
    BOOST_CHECK(!v2proof::VerifyV2SendProof(*mutated_tx.shielded_bundle.v2_bundle,
                                            *mutated_context,
                                            {smile_ring_members}));

    DataStream direct_send_stream;
    direct_send_stream << *bundle;
    shielded::v2::TransactionBundle decoded_bundle;
    direct_send_stream >> decoded_bundle;
    const auto& decoded_payload = std::get<shielded::v2::SendPayload>(decoded_bundle.payload);
    BOOST_CHECK(decoded_payload.output_encoding == shielded::v2::SendOutputEncoding::SMILE_COMPACT);
    BOOST_REQUIRE_EQUAL(decoded_payload.spends.size(), 1U);
    BOOST_CHECK(decoded_payload.spends[0].value_commitment.IsNull());
    BOOST_REQUIRE_EQUAL(decoded_payload.outputs.size(), 1U);
    BOOST_REQUIRE(decoded_payload.outputs[0].smile_account.has_value());
    BOOST_REQUIRE(decoded_payload.outputs[0].smile_public_key.has_value());
    BOOST_CHECK(decoded_payload.outputs[0].smile_public_key->public_key ==
                decoded_payload.outputs[0].smile_account->public_key);

    CMutableTransaction decoded_tx = built->tx;
    decoded_tx.shielded_bundle.v2_bundle = decoded_bundle;
    const auto decoded_statement = v2proof::DescribeV2SendStatement(CTransaction{decoded_tx});
    BOOST_REQUIRE(decoded_statement.IsValid());

    reject_reason.clear();
    auto decoded_context = v2proof::ParseV2SendProof(*decoded_tx.shielded_bundle.v2_bundle,
                                                     decoded_statement,
                                                     reject_reason);
    BOOST_REQUIRE_MESSAGE(decoded_context.has_value(), reject_reason);
    BOOST_CHECK(v2proof::VerifyV2SendProof(*decoded_tx.shielded_bundle.v2_bundle,
                                           *decoded_context,
                                           {smile_ring_members}));
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_roundtrips_smile_witness_without_mutating_output_coins)
{
    const std::vector<unsigned char> spending_key(32, 0x6B);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0x18);
    const ShieldedNote output_note = MakeNote(/*value=*/4900, /*seed=*/0x28);

    const auto input_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note);
    BOOST_REQUIRE(input_account.has_value());
    const uint256 input_chain_commitment = smile2::ComputeCompactPublicAccountHash(*input_account);

    const size_t real_index = 4;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_chain_commitment, real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);
    const std::vector<smile2::wallet::SmileRingMember> smile_ring_members =
        BuildSmileRingMembers(ring_members, input_note, input_chain_commitment, real_index);
    BOOST_REQUIRE_EQUAL(smile_ring_members.size(), ring_members.size());

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x38);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x48, /*nonce_byte=*/0x58);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input = MakeDirectSpendInput(input_note,
                                                                      ring_positions,
                                                                      ring_members,
                                                                      real_index,
                                                                      input_chain_commitment,
                                                                      smile_ring_members);

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xBC);
    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      {spend_input},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()});
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_REQUIRE(built->witness.use_smile);

    DataStream ss;
    ss << TX_WITH_WITNESS(CTransaction{built->tx});

    CMutableTransaction decoded_mutable;
    ss >> TX_WITH_WITNESS(decoded_mutable);
    BOOST_CHECK(ss.empty());

    const CTransaction decoded_tx{std::move(decoded_mutable)};
    const auto* decoded_bundle = decoded_tx.GetShieldedBundle().GetV2Bundle();
    BOOST_REQUIRE(decoded_bundle != nullptr);

    const auto statement = v2proof::DescribeV2SendStatement(decoded_tx);
    BOOST_REQUIRE(statement.IsValid());

    auto context = v2proof::ParseV2SendProof(*decoded_bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_REQUIRE(context->witness.use_smile);
    BOOST_CHECK_EQUAL_COLLECTIONS(context->witness.smile_proof_bytes.begin(),
                                  context->witness.smile_proof_bytes.end(),
                                  built->witness.smile_proof_bytes.begin(),
                                  built->witness.smile_proof_bytes.end());
    BOOST_REQUIRE_EQUAL(context->witness.smile_output_coins.size(), built->witness.smile_output_coins.size());
    for (size_t i = 0; i < context->witness.smile_output_coins.size(); ++i) {
        BOOST_CHECK(context->witness.smile_output_coins[i].t0 ==
                    built->witness.smile_output_coins[i].t0);
        BOOST_CHECK(context->witness.smile_output_coins[i].t_msg ==
                    built->witness.smile_output_coins[i].t_msg);
    }
    BOOST_CHECK(v2proof::VerifyV2SendProof(*decoded_bundle, *context, {smile_ring_members}));
}

BOOST_AUTO_TEST_CASE(parse_v2_send_proof_rejects_tampered_smile_output_coin_witness)
{
    const std::vector<unsigned char> spending_key(32, 0x6C);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0x19);
    const ShieldedNote output_note = MakeNote(/*value=*/4900, /*seed=*/0x29);

    const auto input_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note);
    BOOST_REQUIRE(input_account.has_value());
    const uint256 input_chain_commitment = smile2::ComputeCompactPublicAccountHash(*input_account);

    const size_t real_index = 4;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_chain_commitment, real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);
    const std::vector<smile2::wallet::SmileRingMember> smile_ring_members =
        BuildSmileRingMembers(ring_members, input_note, input_chain_commitment, real_index);
    BOOST_REQUIRE_EQUAL(smile_ring_members.size(), ring_members.size());

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x39);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x49, /*nonce_byte=*/0x59);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input = MakeDirectSpendInput(input_note,
                                                                      ring_positions,
                                                                      ring_members,
                                                                      real_index,
                                                                      input_chain_commitment,
                                                                      smile_ring_members);

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xBD);
    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      {spend_input},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()});
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);
    BOOST_REQUIRE(built->witness.use_smile);

    auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);
    auto mutated_bundle = *bundle;
    BOOST_REQUIRE(!mutated_bundle.proof_payload.empty());
    mutated_bundle.proof_payload.back() ^= 0x01;

    const auto statement = v2proof::DescribeV2SendStatement(CTransaction{built->tx});
    BOOST_REQUIRE(statement.IsValid());

    reject_reason.clear();
    auto context = v2proof::ParseV2SendProof(mutated_bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);
    BOOST_CHECK(!v2proof::VerifyV2SendProof(mutated_bundle, *context, {smile_ring_members}));
}

BOOST_AUTO_TEST_CASE(parse_v2_send_proof_rejects_mutated_direct_smile_statement_digest)
{
    const std::vector<unsigned char> spending_key(32, 0x42);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0x61);
    const ShieldedNote output_note = MakeNote(/*value=*/4900, /*seed=*/0x71);

    const auto input_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note);
    BOOST_REQUIRE(input_account.has_value());
    const uint256 input_chain_commitment = smile2::ComputeCompactPublicAccountHash(*input_account);

    const size_t real_index = 3;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_chain_commitment, real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);
    const std::vector<smile2::wallet::SmileRingMember> smile_ring_members =
        BuildSmileRingMembers(ring_members, input_note, input_chain_commitment, real_index);
    BOOST_REQUIRE_EQUAL(smile_ring_members.size(), ring_members.size());

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x81);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x91, /*nonce_byte=*/0xa1);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input =
        MakeDirectSpendInput(input_note,
                             ring_positions,
                             ring_members,
                             real_index,
                             input_chain_commitment,
                             smile_ring_members);

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    std::string reject_reason;
    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xD4);
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      {spend_input},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()});
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);

    CMutableTransaction mutated = built->tx;
    BOOST_REQUIRE(mutated.shielded_bundle.v2_bundle.has_value());
    auto& envelope = mutated.shielded_bundle.v2_bundle->header.proof_envelope;
    envelope.statement_digest = uint256{0x99};

    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(CTransaction{mutated});
    BOOST_REQUIRE(statement.IsValid());
    BOOST_CHECK(statement.envelope.proof_kind == shielded::v2::ProofKind::DIRECT_SMILE);

    reject_reason.clear();
    auto context = v2proof::ParseV2SendProof(*mutated.shielded_bundle.v2_bundle, statement, reject_reason);
    BOOST_CHECK(!context.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(build_v2_send_ring_members_rejects_non_redacted_spend_metadata)
{
    const std::vector<unsigned char> spending_key(32, 0x42);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0x61);
    const ShieldedNote output_note = MakeNote(/*value=*/4900, /*seed=*/0x71);

    const auto input_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        input_note);
    BOOST_REQUIRE(input_account.has_value());
    const uint256 input_chain_commitment = smile2::ComputeCompactPublicAccountHash(*input_account);

    const size_t real_index = 3;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_chain_commitment, real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);
    const std::vector<smile2::wallet::SmileRingMember> smile_ring_members =
        BuildSmileRingMembers(ring_members, input_note, input_chain_commitment, real_index);
    BOOST_REQUIRE_EQUAL(smile_ring_members.size(), ring_members.size());

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0x81);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x91, /*nonce_byte=*/0xa1);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input =
        MakeDirectSpendInput(input_note,
                             ring_positions,
                             ring_members,
                             real_index,
                             input_chain_commitment,
                             smile_ring_members);

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    std::string reject_reason;
    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xE5);
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      {spend_input},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason,
                                                      Span<const unsigned char>{rng_entropy.data(), rng_entropy.size()});
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);

    const auto* bundle = built->tx.shielded_bundle.GetV2Bundle();
    BOOST_REQUIRE(bundle != nullptr);

    const v2proof::ProofStatement statement = v2proof::DescribeV2SendStatement(CTransaction{built->tx});
    BOOST_REQUIRE(statement.IsValid());

    auto context = v2proof::ParseV2SendProof(*bundle, statement, reject_reason);
    BOOST_REQUIRE_MESSAGE(context.has_value(), reject_reason);

    auto mutated = *bundle;
    auto& witness = context->witness;
    witness.spends[0].real_index = 1;
    DataStream witness_stream;
    witness_stream << witness;
    mutated.proof_payload.assign(reinterpret_cast<const uint8_t*>(witness_stream.data()),
                                 reinterpret_cast<const uint8_t*>(witness_stream.data()) +
                                     witness_stream.size());

    reject_reason.clear();
    std::map<uint256, smile2::CompactPublicAccount> public_accounts{{input_chain_commitment, *input_account}};
    const auto account_leaf_commitment = shielded::registry::ComputeAccountLeafCommitmentFromNote(
        input_note,
        input_chain_commitment,
        shielded::registry::MakeDirectSendAccountLeafHint());
    BOOST_REQUIRE(account_leaf_commitment.has_value());
    std::map<uint256, uint256> account_leaf_commitments{{input_chain_commitment, *account_leaf_commitment}};
    auto rebuilt_rings = v2proof::BuildV2SendSmileRingMembers(mutated,
                                                              *context,
                                                              tree,
                                                              public_accounts,
                                                              account_leaf_commitments,
                                                              reject_reason);
    BOOST_CHECK(!rebuilt_rings.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-proof");
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_rejects_invalid_real_member)
{
    const std::vector<unsigned char> spending_key(32, 0x42);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0xb1);
    const ShieldedNote output_note = MakeNote(/*value=*/4900, /*seed=*/0xc1);

    const size_t real_index = 5;
    const shielded::ShieldedMerkleTree tree = BuildTree(uint256{0xd1}, real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0xe1);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0xf1, /*nonce_byte=*/0x11);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input =
        MakeDirectSpendInput(input_note, ring_positions, ring_members, real_index);

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      {spend_input},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason);
    BOOST_CHECK(!built.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-v2-builder-input");
}

BOOST_AUTO_TEST_CASE(build_v2_send_transaction_rejects_missing_account_leaf_hint)
{
    const std::vector<unsigned char> spending_key(32, 0x42);
    const ShieldedNote input_note = MakeNote(/*value=*/5000, /*seed=*/0xd1);
    const ShieldedNote output_note = MakeNote(/*value=*/4900, /*seed=*/0xe1);

    const size_t real_index = 4;
    const shielded::ShieldedMerkleTree tree = BuildTree(input_note.GetCommitment(), real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(tree, ring_positions);

    const mlkem::KeyPair recipient = BuildRecipientKeyPair(/*seed=*/0xf1);
    const shielded::EncryptedNote encrypted_note =
        BuildEncryptedNote(output_note, recipient.pk, /*kem_seed_byte=*/0x11, /*nonce_byte=*/0x21);
    auto encrypted_payload = shielded::v2::EncodeLegacyEncryptedNotePayload(
        encrypted_note,
        recipient.pk,
        shielded::v2::ScanDomain::USER);
    BOOST_REQUIRE(encrypted_payload.has_value());

    auto spend_input = MakeDirectSpendInput(input_note, ring_positions, ring_members, real_index);
    spend_input.account_leaf_hint.reset();

    shielded::v2::V2SendOutputInput output_input;
    output_input.note_class = shielded::v2::NoteClass::USER;
    output_input.note = output_note;
    output_input.encrypted_note = *encrypted_payload;

    std::string reject_reason;
    auto built = shielded::v2::BuildV2SendTransaction(CMutableTransaction{},
                                                      tree.Root(),
                                                      {spend_input},
                                                      {output_input},
                                                      /*fee=*/100,
                                                      spending_key,
                                                      reject_reason);
    BOOST_CHECK(!built.has_value());
    BOOST_CHECK_EQUAL(reject_reason, "bad-shielded-v2-builder-input");
}

BOOST_AUTO_TEST_SUITE_END()
