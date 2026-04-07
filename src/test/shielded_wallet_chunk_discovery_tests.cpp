// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <consensus/amount.h>
#include <crypto/ml_kem.h>
#include <logging.h>
#include <interfaces/chain.h>
#include <kernel/chain.h>
#include <hash.h>
#include <noui.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <streams.h>
#include <shielded/smile2/wallet_bridge.h>
#include <shielded/v2_ingress.h>
#include <shielded/v2_send.h>
#include <support/allocators/secure.h>
#include <test/util/setup_common.h>
#include <test/util/shielded_account_registry_test_util.h>
#include <test/util/smile2_placeholder_utils.h>
#include <test/util/shielded_v2_egress_fixture.h>
#include <wallet/shielded_coins.h>
#include <wallet/shielded_wallet.h>
#include <wallet/test/util.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <functional>
#include <list>
#include <memory>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace {

using namespace shielded::v2;

template <size_t N>
std::array<uint8_t, N> DeriveSeed(std::string_view tag, uint32_t index)
{
    std::array<uint8_t, N> seed{};
    size_t offset{0};
    uint32_t counter{0};
    while (offset < seed.size()) {
        HashWriter hw;
        hw << std::string{tag} << index << counter;
        const uint256 digest = hw.GetSHA256();
        const size_t copy_len = std::min(seed.size() - offset, static_cast<size_t>(uint256::size()));
        std::copy_n(digest.begin(), copy_len, seed.begin() + offset);
        offset += copy_len;
        ++counter;
    }
    return seed;
}

mlkem::KeyPair BuildKeyPair(std::string_view tag, uint32_t index)
{
    return mlkem::KeyGenDerand(DeriveSeed<mlkem::KEYGEN_SEEDBYTES>(tag, index));
}

uint256 DeriveUint256(std::string_view tag, uint32_t index)
{
    const auto seed = DeriveSeed<uint256::size()>(tag, index);
    uint256 value;
    std::copy(seed.begin(), seed.end(), value.begin());
    if (value.IsNull()) {
        value.begin()[0] = 1;
    }
    return value;
}

ShieldedNote MakeNote(const uint256& recipient_pk_hash, CAmount value, uint32_t seed)
{
    ShieldedNote note;
    note.value = value;
    note.recipient_pk_hash = recipient_pk_hash;
    note.rho = DeriveUint256("BTX_ShieldedV2_ChunkScan_NoteRho", seed);
    note.rcm = DeriveUint256("BTX_ShieldedV2_ChunkScan_NoteRcm", seed);
    if (!note.IsValid()) {
        throw std::runtime_error("invalid shielded note fixture");
    }
    return note;
}

shielded::EncryptedNote EncryptNote(const ShieldedNote& note,
                                    const mlkem::PublicKey& recipient_pk,
                                    uint32_t index)
{
    return shielded::NoteEncryption::EncryptDeterministic(
        note,
        recipient_pk,
        DeriveSeed<mlkem::ENCAPS_SEEDBYTES>("BTX_ShieldedV2_ChunkScan_KEM", index),
        DeriveSeed<12>("BTX_ShieldedV2_ChunkScan_Nonce", index));
}

OutputDescription BuildOutput(const ShieldedNote& note,
                              const mlkem::PublicKey& recipient_pk,
                              ScanDomain scan_domain,
                              uint32_t seed,
                              NoteClass note_class = NoteClass::USER)
{
    const shielded::EncryptedNote encrypted_note =
        EncryptNote(note, recipient_pk, seed);
    const auto payload = EncodeLegacyEncryptedNotePayload(encrypted_note, recipient_pk, scan_domain);
    if (!payload.has_value()) {
        throw std::runtime_error("failed to encode shielded_v2 payload fixture");
    }

    OutputDescription output;
    output.note_class = note_class;
    auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        note);
    if (!smile_account.has_value()) {
        throw std::runtime_error("failed to build output smile account fixture");
    }
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
    output.value_commitment = DeriveUint256("BTX_ShieldedV2_ChunkScan_ValueCommitment", seed);
    output.smile_account = std::move(*smile_account);
    output.encrypted_note = *payload;
    if (!output.IsValid()) {
        throw std::runtime_error("invalid output fixture");
    }
    return output;
}

V2IngressSettlementWitness BuildIngressProofSettlementWitness(const shielded::BridgeBatchStatement& statement,
                                                              const shielded::BridgeProofDescriptor& descriptor,
                                                              unsigned char seed = 0xd1)
{
    const std::vector<shielded::BridgeProofDescriptor> descriptors{descriptor};

    shielded::BridgeProofReceipt receipt;
    receipt.statement_hash = shielded::ComputeBridgeBatchStatementHash(statement);
    receipt.proof_system_id = descriptor.proof_system_id;
    receipt.verifier_key_hash = descriptor.verifier_key_hash;
    receipt.public_values_hash = uint256{seed};
    receipt.proof_commitment = uint256{static_cast<unsigned char>(seed + 1)};
    if (!receipt.IsValid()) {
        throw std::runtime_error("invalid ingress proof receipt fixture");
    }

    auto descriptor_proof = shielded::BuildBridgeProofPolicyProof(descriptors, descriptor);
    if (!descriptor_proof.has_value()) {
        throw std::runtime_error("failed to build ingress descriptor proof fixture");
    }

    V2IngressSettlementWitness witness;
    witness.proof_receipts = {receipt};
    witness.proof_receipt_descriptor_proofs = {*descriptor_proof};
    if (!witness.IsValid()) {
        throw std::runtime_error("invalid ingress settlement witness fixture");
    }
    return witness;
}

shielded::ShieldedMerkleTree BuildSpendTree(const uint256& real_member, size_t real_index)
{
    shielded::ShieldedMerkleTree tree;
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        if (i == real_index) {
            tree.Append(real_member);
            continue;
        }
        HashWriter hw;
        hw << std::string{"BTX_ShieldedV2_ChunkScan_SpendRingMember_V1"} << static_cast<uint64_t>(i);
        tree.Append(hw.GetSHA256());
    }
    return tree;
}

std::vector<uint64_t> BuildRingPositions()
{
    std::vector<uint64_t> positions;
    positions.reserve(shielded::lattice::RING_SIZE);
    for (size_t i = 0; i < shielded::lattice::RING_SIZE; ++i) {
        positions.push_back(i);
    }
    return positions;
}

std::vector<uint256> BuildRingMembers(const shielded::ShieldedMerkleTree& tree,
                                      const std::vector<uint64_t>& positions)
{
    std::vector<uint256> members;
    members.reserve(positions.size());
    for (const uint64_t position : positions) {
        const auto commitment = tree.CommitmentAt(position);
        if (!commitment.has_value()) {
            throw std::runtime_error("missing ring member fixture");
        }
        members.push_back(*commitment);
    }
    return members;
}

std::vector<smile2::wallet::SmileRingMember> BuildIngressSpendSmileRingMembers(
    const std::vector<uint256>& ring_members,
    const ShieldedNote& real_note,
    const uint256& real_note_commitment,
    size_t real_index)
{
    std::vector<smile2::wallet::SmileRingMember> members;
    members.reserve(ring_members.size());
    for (size_t i = 0; i < ring_members.size(); ++i) {
        if (i == real_index) {
            const auto account_leaf_commitment = shielded::registry::ComputeAccountLeafCommitmentFromNote(
                real_note,
                real_note_commitment,
                shielded::registry::MakeDirectSendAccountLeafHint());
            if (!account_leaf_commitment.has_value()) {
                throw std::runtime_error("failed to build real ingress smile ring member fixture");
            }
            auto member = smile2::wallet::BuildRingMemberFromNote(
                smile2::wallet::SMILE_GLOBAL_SEED,
                real_note,
                real_note_commitment,
                *account_leaf_commitment);
            if (!member.has_value()) {
                throw std::runtime_error("failed to encode real ingress smile ring member fixture");
            }
            members.push_back(std::move(*member));
            continue;
        }
        members.push_back(smile2::wallet::BuildPlaceholderRingMember(
            smile2::wallet::SMILE_GLOBAL_SEED,
            ring_members[i]));
    }
    return members;
}

shielded::v2::V2IngressLeafInput BuildIngressLeafInput(unsigned char seed, CAmount amount, CAmount fee)
{
    shielded::v2::V2IngressLeafInput leaf;
    leaf.bridge_leaf.kind = shielded::BridgeBatchLeafKind::SHIELD_CREDIT;
    leaf.bridge_leaf.wallet_id = uint256{seed};
    leaf.bridge_leaf.destination_id = uint256{static_cast<unsigned char>(seed + 1)};
    leaf.bridge_leaf.amount = amount;
    leaf.bridge_leaf.authorization_hash = uint256{static_cast<unsigned char>(seed + 2)};
    leaf.l2_id = uint256{static_cast<unsigned char>(seed + 3)};
    leaf.fee = fee;
    if (!leaf.IsValid()) {
        throw std::runtime_error("invalid ingress leaf fixture");
    }
    return leaf;
}

class ScopedLogCapture
{
public:
    ScopedLogCapture()
    {
        m_callback = LogInstance().PushBackCallback(
            [this](const std::string& line) { m_lines.push_back(line); });
        noui_test_redirect();
    }

    ~ScopedLogCapture()
    {
        noui_reconnect();
        LogInstance().DeleteCallback(m_callback);
    }

    [[nodiscard]] bool Contains(std::string_view needle) const
    {
        return std::any_of(m_lines.begin(), m_lines.end(), [&](const std::string& line) {
            return line.find(needle) != std::string::npos;
        });
    }

private:
    std::list<std::function<void(const std::string&)>>::iterator m_callback;
    std::vector<std::string> m_lines;
};

struct ShieldedWalletChunkDiscoverySetup : public TestChain100Setup
{
    wallet::CWallet wallet;
    std::shared_ptr<wallet::CShieldedWallet> shielded_wallet;
    wallet::ShieldedAddress owned_addr;
    mlkem::PublicKey owned_kem_pk{};

    ShieldedWalletChunkDiscoverySetup()
        : TestChain100Setup{ChainType::REGTEST},
          wallet(m_node.chain.get(), "", wallet::CreateMockableWalletDatabase())
    {
        BOOST_REQUIRE(wallet.LoadWallet() == wallet::DBErrors::LOAD_OK);
        SecureString passphrase{"test-passphrase"};
        BOOST_REQUIRE(wallet.EncryptWallet(passphrase));
        BOOST_REQUIRE(wallet.Unlock(passphrase));
        wallet.m_shielded_wallet = std::make_shared<wallet::CShieldedWallet>(wallet);
        shielded_wallet = wallet.m_shielded_wallet;
        LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
        owned_addr = shielded_wallet->GenerateNewAddress();
        BOOST_REQUIRE(shielded_wallet->GetKEMPublicKey(owned_addr, owned_kem_pk));
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(shielded_wallet_chunk_discovery_tests, ShieldedWalletChunkDiscoverySetup)

BOOST_AUTO_TEST_CASE(v2_scan_discovers_owned_outputs_across_multiple_local_keysets)
{
    LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
    const auto secondary_addr = shielded_wallet->GenerateNewAddress();
    mlkem::PublicKey secondary_kem_pk{};
    BOOST_REQUIRE(shielded_wallet->GetKEMPublicKey(secondary_addr, secondary_kem_pk));

    OutputDescription primary_output = BuildOutput(
        MakeNote(owned_addr.pk_hash, 13 * COIN, 0x51),
        owned_kem_pk,
        ScanDomain::USER,
        0x61);
    OutputDescription secondary_output = BuildOutput(
        MakeNote(secondary_addr.pk_hash, 17 * COIN, 0x52),
        secondary_kem_pk,
        ScanDomain::USER,
        0x62);
    const auto fixture = test::shielded::BuildV2EgressReceiptFixture(
        std::vector<OutputDescription>{primary_output, secondary_output});

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(CTransaction{fixture.tx}));
    shielded_wallet->ScanBlock(block, /*height=*/1);

    const auto notes = shielded_wallet->GetUnspentNotes(/*min_depth=*/0);
    BOOST_REQUIRE_EQUAL(notes.size(), 2U);
    std::vector<CAmount> values;
    values.reserve(notes.size());
    for (const auto& coin : notes) {
        values.push_back(coin.note.value);
    }
    std::sort(values.begin(), values.end());
    BOOST_CHECK_EQUAL(values[0], 13 * COIN);
    BOOST_CHECK_EQUAL(values[1], 17 * COIN);
}

BOOST_AUTO_TEST_CASE(revoked_address_is_rejected_after_postfork_privacy_boundary)
{
    wallet::ShieldedAddress revoked_addr;
    {
        LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
        revoked_addr = shielded_wallet->GenerateNewAddress();
        BOOST_REQUIRE(shielded_wallet->RevokeAddress(revoked_addr));

        const auto lifecycle = shielded_wallet->GetAddressLifecycle(revoked_addr);
        BOOST_REQUIRE(lifecycle.has_value());
        BOOST_CHECK_EQUAL(lifecycle->state, wallet::ShieldedAddressLifecycleState::REVOKED);

        const int32_t activation_height = Params().GetConsensus().nShieldedMatRiCTDisableHeight;
        const auto prefork_resolution = shielded_wallet->ResolveLifecycleDestination(revoked_addr, activation_height - 1);
        BOOST_REQUIRE(prefork_resolution.has_value());
        BOOST_CHECK(*prefork_resolution == revoked_addr);

        const auto postfork_resolution = shielded_wallet->ResolveLifecycleDestination(revoked_addr, activation_height);
        BOOST_CHECK(!postfork_resolution.has_value());
    }
}

BOOST_AUTO_TEST_CASE(block_scan_discovers_owned_egress_output_only_when_chunks_are_canonical)
{
    const mlkem::KeyPair foreign_recipient_a = BuildKeyPair("BTX_ShieldedV2_ChunkScan_Foreign", 1);
    const mlkem::KeyPair foreign_recipient_b = BuildKeyPair("BTX_ShieldedV2_ChunkScan_Foreign", 2);

    const ShieldedNote foreign_note_a = MakeNote(uint256{0x61}, 7 * COIN, 0x71);
    const ShieldedNote foreign_note_b = MakeNote(uint256{0x62}, 9 * COIN, 0x81);
    const ShieldedNote owned_note = MakeNote(owned_addr.pk_hash, 11 * COIN, 0x91);

    std::vector<OutputDescription> outputs{
        BuildOutput(foreign_note_a, foreign_recipient_a.pk, ScanDomain::BATCH, 0xa1),
        BuildOutput(foreign_note_b, foreign_recipient_b.pk, ScanDomain::BATCH, 0xa2),
        BuildOutput(owned_note, owned_kem_pk, ScanDomain::BATCH, 0xa3),
    };
    const auto fixture = test::shielded::BuildV2EgressReceiptFixture(
        outputs,
        {2, 1},
        foreign_note_a.value + foreign_note_b.value + owned_note.value);
    const CTransaction tx{fixture.tx};

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(tx));

    LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
    shielded_wallet->ScanBlock(block, /*height=*/1);

    const auto notes = shielded_wallet->GetUnspentNotes(/*min_depth=*/0);
    BOOST_REQUIRE_EQUAL(notes.size(), 1U);
    BOOST_CHECK_EQUAL(notes[0].note.value, owned_note.value);
    const auto owned_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        owned_note);
    BOOST_REQUIRE(owned_account.has_value());
    BOOST_CHECK(notes[0].commitment == smile2::ComputeCompactPublicAccountHash(*owned_account));

    const auto cached_view = shielded_wallet->GetCachedTransactionView(tx.GetHash());
    BOOST_REQUIRE(cached_view.has_value());
    BOOST_REQUIRE_EQUAL(cached_view->family, "v2_egress_batch");
    BOOST_REQUIRE_EQUAL(cached_view->outputs.size(), outputs.size());
    BOOST_REQUIRE_EQUAL(cached_view->output_chunks.size(), 2U);
    BOOST_CHECK(!cached_view->outputs[0].is_ours);
    BOOST_CHECK(!cached_view->outputs[1].is_ours);
    BOOST_CHECK(cached_view->outputs[2].is_ours);
    BOOST_CHECK_EQUAL(cached_view->outputs[2].amount, owned_note.value);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[0].scan_domain, "opaque");
    BOOST_CHECK_EQUAL(cached_view->output_chunks[0].first_output_index, 0U);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[0].output_count, 2U);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[0].owned_output_count, 0U);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[0].owned_amount, 0);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[1].scan_domain, "opaque");
    BOOST_CHECK_EQUAL(cached_view->output_chunks[1].first_output_index, 2U);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[1].output_count, 1U);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[1].owned_output_count, 1U);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[1].owned_amount, owned_note.value);
    BOOST_CHECK(!cached_view->output_chunks[1].scan_hint_commitment.IsNull());
    BOOST_CHECK(!cached_view->output_chunks[1].ciphertext_commitment.IsNull());
}

BOOST_AUTO_TEST_CASE(mempool_scan_skips_egress_outputs_when_chunk_commitment_is_tampered)
{
    const ShieldedNote owned_note = MakeNote(owned_addr.pk_hash, 5 * COIN, 0xb1);
    const mlkem::KeyPair foreign_recipient_a = BuildKeyPair("BTX_ShieldedV2_ChunkScan_Foreign", 3);
    const mlkem::KeyPair foreign_recipient_b = BuildKeyPair("BTX_ShieldedV2_ChunkScan_Foreign", 4);
    std::vector<OutputDescription> outputs{
        BuildOutput(owned_note, owned_kem_pk, ScanDomain::BATCH, 0xb2),
        BuildOutput(MakeNote(uint256{0x73}, 6 * COIN, 0xb3),
                    foreign_recipient_a.pk,
                    ScanDomain::BATCH,
                    0xb4),
        BuildOutput(MakeNote(uint256{0x74}, 7 * COIN, 0xb5),
                    foreign_recipient_b.pk,
                    ScanDomain::BATCH,
                    0xb6),
    };
    auto fixture = test::shielded::BuildV2EgressReceiptFixture(
        outputs,
        {2, 1},
        owned_note.value + 6 * COIN + 7 * COIN);
    fixture.tx.shielded_bundle.v2_bundle->output_chunks[0].scan_hint_commitment = uint256{0xcc};
    const CTransaction tx{fixture.tx};

    LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
    shielded_wallet->TransactionAddedToMempool(tx);

    BOOST_CHECK(!shielded_wallet->GetCachedTransactionView(tx.GetHash()).has_value());
}

BOOST_AUTO_TEST_CASE(mempool_scan_caches_egress_chunk_summaries_for_canonical_bundle)
{
    const mlkem::KeyPair foreign_recipient_a = BuildKeyPair("BTX_ShieldedV2_ChunkScan_Foreign", 5);
    const mlkem::KeyPair foreign_recipient_b = BuildKeyPair("BTX_ShieldedV2_ChunkScan_Foreign", 6);
    const ShieldedNote foreign_note_a = MakeNote(uint256{0x75}, 3 * COIN, 0xc1);
    const ShieldedNote foreign_note_b = MakeNote(uint256{0x76}, 4 * COIN, 0xc2);
    const ShieldedNote owned_note_a = MakeNote(owned_addr.pk_hash, 5 * COIN, 0xc3);
    const ShieldedNote owned_note_b = MakeNote(owned_addr.pk_hash, 6 * COIN, 0xc4);

    std::vector<OutputDescription> outputs{
        BuildOutput(foreign_note_a, foreign_recipient_a.pk, ScanDomain::BATCH, 0xc5),
        BuildOutput(owned_note_a, owned_kem_pk, ScanDomain::BATCH, 0xc6),
        BuildOutput(foreign_note_b, foreign_recipient_b.pk, ScanDomain::BATCH, 0xc7),
        BuildOutput(owned_note_b, owned_kem_pk, ScanDomain::BATCH, 0xc8),
    };
    const auto fixture = test::shielded::BuildV2EgressReceiptFixture(
        outputs,
        {2, 2},
        foreign_note_a.value + owned_note_a.value + foreign_note_b.value + owned_note_b.value);
    const CTransaction tx{fixture.tx};

    LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
    shielded_wallet->TransactionAddedToMempool(tx);

    const auto cached_view = shielded_wallet->GetCachedTransactionView(tx.GetHash());
    BOOST_REQUIRE(cached_view.has_value());
    BOOST_REQUIRE_EQUAL(cached_view->family, "v2_egress_batch");
    BOOST_REQUIRE_EQUAL(cached_view->output_chunks.size(), 2U);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[0].first_output_index, 0U);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[0].output_count, 2U);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[0].owned_output_count, 1U);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[0].owned_amount, owned_note_a.value);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[1].first_output_index, 2U);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[1].output_count, 2U);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[1].owned_output_count, 1U);
    BOOST_CHECK_EQUAL(cached_view->output_chunks[1].owned_amount, owned_note_b.value);
}

CTransaction BuildMinimalV2SendTransaction(const uint256& recipient_pk_hash,
                                           const mlkem::PublicKey& recipient_kem_pk,
                                           CAmount value,
                                           uint32_t seed)
{
    const ShieldedNote note = MakeNote(recipient_pk_hash, value, seed);
    const shielded::EncryptedNote encrypted_note = EncryptNote(note, recipient_kem_pk, seed + 1);
    auto encrypted_payload = EncodeLegacyEncryptedNotePayload(encrypted_note,
                                                              recipient_kem_pk,
                                                              ScanDomain::USER);
    if (!encrypted_payload.has_value()) {
        throw std::runtime_error("failed to encode v2_send payload fixture");
    }

    OutputDescription output;
    output.note_class = NoteClass::USER;
    auto smile_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        note);
    if (!smile_account.has_value()) {
        throw std::runtime_error("failed to build v2_send smile account fixture");
    }
    output.note_commitment = smile2::ComputeCompactPublicAccountHash(*smile_account);
    output.value_commitment = DeriveUint256("BTX_ShieldedV2_ChunkScan_V2SendValueCommitment", seed);
    output.smile_account = std::move(*smile_account);
    output.encrypted_note = *encrypted_payload;
    if (!output.IsValid()) {
        throw std::runtime_error("invalid v2_send output fixture");
    }

    SendPayload payload;
    payload.spend_anchor = DeriveUint256("BTX_ShieldedV2_ChunkScan_V2SendSpendAnchor", seed);
    payload.outputs = {output};
    payload.fee = 0;
    payload.value_balance = -note.value;

    ProofEnvelope envelope;
    envelope.proof_kind = ProofKind::DIRECT_MATRICT;
    envelope.membership_proof_kind = ProofComponentKind::MATRICT;
    envelope.amount_proof_kind = ProofComponentKind::RANGE;
    envelope.balance_proof_kind = ProofComponentKind::BALANCE;
    envelope.settlement_binding_kind = SettlementBindingKind::NONE;
    envelope.statement_digest = DeriveUint256("BTX_ShieldedV2_ChunkScan_V2SendStatementDigest", seed);

    TransactionBundle tx_bundle;
    tx_bundle.header.family_id = TransactionFamily::V2_SEND;
    tx_bundle.header.proof_envelope = envelope;
    tx_bundle.header.payload_digest = ComputeSendPayloadDigest(payload);
    tx_bundle.payload = payload;
    tx_bundle.proof_payload = {static_cast<unsigned char>(seed & 0xff)};

    CMutableTransaction tx;
    tx.version = CTransaction::CURRENT_VERSION;
    tx.nLockTime = seed;
    tx.shielded_bundle.v2_bundle = tx_bundle;
    return CTransaction{tx};
}

BOOST_AUTO_TEST_CASE(unencrypted_wallet_runtime_paths_skip_master_seed_noise)
{
    wallet::CWallet unencrypted_wallet(
        m_node.chain.get(),
        "",
        wallet::CreateMockableWalletDatabase());
    BOOST_REQUIRE(unencrypted_wallet.LoadWallet() == wallet::DBErrors::LOAD_OK);

    const mlkem::KeyPair foreign_recipient = BuildKeyPair("BTX_ShieldedV2_ChunkScan_Foreign", 77);
    const CTransaction tx = BuildMinimalV2SendTransaction(uint256{0x99},
                                                          foreign_recipient.pk,
                                                          2 * COIN,
                                                          0xf1);
    CBlock block;
    block.vtx.push_back(MakeTransactionRef(tx));

    ScopedLogCapture logs;
    unencrypted_wallet.m_shielded_wallet = std::make_shared<wallet::CShieldedWallet>(unencrypted_wallet);
    auto local_shielded = unencrypted_wallet.m_shielded_wallet;

    {
        LOCK2(unencrypted_wallet.cs_wallet, local_shielded->cs_shielded);
        local_shielded->TransactionAddedToMempool(tx);
        local_shielded->ScanBlock(block, /*height=*/1);
        const auto report = local_shielded->VerifyKeyIntegrity();
        BOOST_CHECK_EQUAL(report.total_keys, 0);
        BOOST_CHECK(!report.master_seed_available);
        BOOST_CHECK_EQUAL(report.notes_total, 0);
        BOOST_CHECK(local_shielded->GetUnspentNotes(/*min_depth=*/0).empty());
        BOOST_CHECK(!local_shielded->GetCachedTransactionView(tx.GetHash()).has_value());
    }

    BOOST_CHECK(!logs.Contains("CShieldedWallet::GetMasterSeed: refusing shielded seed access for unencrypted wallet"));
    BOOST_CHECK(!logs.Contains("CShieldedWallet::CatchUpToChainTip skipped: no keys loaded"));
}

BOOST_AUTO_TEST_CASE(wallet_builds_receipt_backed_egress_batch_and_caches_chunk_views)
{
    wallet::ShieldedAddress second_addr;
    mlkem::PublicKey second_kem_pk{};
    {
        LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
        second_addr = shielded_wallet->GenerateNewAddress();
        BOOST_REQUIRE(shielded_wallet->GetKEMPublicKey(second_addr, second_kem_pk));
    }

    std::vector<shielded::BridgeProofDescriptor> descriptors;
    descriptors.push_back({uint256{0xd1}, uint256{0xd2}});
    auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(
        Span<const shielded::BridgeProofDescriptor>{descriptors.data(), descriptors.size()},
        /*required_receipts=*/1);
    BOOST_REQUIRE(proof_policy.has_value());

    std::vector<std::pair<wallet::ShieldedAddress, CAmount>> wallet_recipients{
        {owned_addr, 8 * COIN},
        {second_addr, 9 * COIN},
    };
    std::vector<shielded::v2::V2EgressRecipient> statement_recipients{
        {owned_addr.pk_hash, owned_kem_pk, 8 * COIN},
        {second_addr.pk_hash, second_kem_pk, 9 * COIN},
    };

    shielded::v2::V2EgressStatementTemplate statement_template;
    statement_template.ids.bridge_id = uint256{0xd3};
    statement_template.ids.operation_id = uint256{0xd4};
    statement_template.domain_id = uint256{0xd5};
    statement_template.source_epoch = 12;
    statement_template.data_root = uint256{0xd6};
    statement_template.proof_policy = *proof_policy;

    std::string reject_reason;
    auto statement = shielded::v2::BuildV2EgressStatement(
        statement_template,
        Span<const shielded::v2::V2EgressRecipient>{statement_recipients.data(), statement_recipients.size()},
        reject_reason);
    BOOST_REQUIRE_MESSAGE(statement.has_value(), reject_reason);

    shielded::BridgeProofReceipt imported_receipt;
    imported_receipt.statement_hash = shielded::ComputeBridgeBatchStatementHash(*statement);
    imported_receipt.proof_system_id = descriptors[0].proof_system_id;
    imported_receipt.verifier_key_hash = descriptors[0].verifier_key_hash;
    imported_receipt.public_values_hash = uint256{0xd7};
    imported_receipt.proof_commitment = uint256{0xd8};
    BOOST_REQUIRE(imported_receipt.IsValid());

    std::optional<CMutableTransaction> built_tx;
    {
        LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
        built_tx = shielded_wallet->CreateV2EgressBatch(*statement,
                                                        descriptors,
                                                        descriptors[0],
                                                        {imported_receipt},
                                                        imported_receipt,
                                                        wallet_recipients,
                                                        {1, 1});
        BOOST_REQUIRE(built_tx.has_value());
        const CTransaction tx{*built_tx};
        shielded_wallet->TransactionAddedToMempool(tx);
        const auto cached_view = shielded_wallet->GetCachedTransactionView(tx.GetHash());
        BOOST_REQUIRE(cached_view.has_value());
        BOOST_REQUIRE_EQUAL(cached_view->family, "v2_egress_batch");
        BOOST_REQUIRE_EQUAL(cached_view->outputs.size(), 2U);
        BOOST_REQUIRE_EQUAL(cached_view->output_chunks.size(), 2U);
        BOOST_CHECK(cached_view->outputs[0].is_ours);
        BOOST_CHECK(cached_view->outputs[1].is_ours);
        BOOST_CHECK_EQUAL(cached_view->outputs[0].amount, 8 * COIN);
        BOOST_CHECK_EQUAL(cached_view->outputs[1].amount, 9 * COIN);
        BOOST_CHECK_EQUAL(cached_view->output_chunks[0].owned_output_count, 1U);
        BOOST_CHECK_EQUAL(cached_view->output_chunks[0].owned_amount, 8 * COIN);
        BOOST_CHECK_EQUAL(cached_view->output_chunks[1].owned_output_count, 1U);
        BOOST_CHECK_EQUAL(cached_view->output_chunks[1].owned_amount, 9 * COIN);
    }
}

BOOST_AUTO_TEST_CASE(imported_viewing_key_tracks_live_v2_send_after_prior_rescan)
{
    const mlkem::KeyPair historical_key = BuildKeyPair("BTX_ShieldedV2_ChunkScan_ViewOnly", 10);
    const mlkem::KeyPair live_key = BuildKeyPair("BTX_ShieldedV2_ChunkScan_ViewOnly", 11);
    const uint256 historical_pk_hash = DeriveUint256("BTX_ShieldedV2_ChunkScan_ViewOnlyPkHash", 10);
    const uint256 live_pk_hash = DeriveUint256("BTX_ShieldedV2_ChunkScan_ViewOnlyPkHash", 11);
    const CAmount historical_value = 25 * COIN / 100;
    const CAmount live_value = 35 * COIN / 100;

    const CTransaction historical_tx =
        BuildMinimalV2SendTransaction(historical_pk_hash, historical_key.pk, historical_value, 0xf1);
    const CTransaction live_tx =
        BuildMinimalV2SendTransaction(live_pk_hash, live_key.pk, live_value, 0xf2);

    CBlock historical_block;
    historical_block.vtx.push_back(MakeTransactionRef(historical_tx));
    CBlock live_block;
    live_block.vtx.push_back(MakeTransactionRef(live_tx));

    LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);

    BOOST_REQUIRE(shielded_wallet->ImportViewingKey(
        std::vector<unsigned char>(historical_key.sk.begin(), historical_key.sk.end()),
        std::vector<unsigned char>(historical_key.pk.begin(), historical_key.pk.end()),
        historical_pk_hash));
    shielded_wallet->Rescan(/*start_height=*/0);
    shielded_wallet->ScanBlock(historical_block, /*height=*/1);

    auto notes = shielded_wallet->GetUnspentNotes(/*min_depth=*/1);
    BOOST_REQUIRE_EQUAL(notes.size(), 1U);
    const auto historical_summary = shielded_wallet->GetShieldedBalanceSummary(/*min_depth=*/1);
    BOOST_CHECK_EQUAL(historical_summary.spendable, 0);
    BOOST_CHECK_EQUAL(historical_summary.watchonly, historical_value);
    BOOST_CHECK_EQUAL(historical_summary.spendable_note_count, 0);
    BOOST_CHECK_EQUAL(historical_summary.watchonly_note_count, 1);
    BOOST_CHECK_EQUAL(shielded_wallet->GetShieldedBalance(/*min_depth=*/1), 0);

    BOOST_REQUIRE(shielded_wallet->ImportViewingKey(
        std::vector<unsigned char>(live_key.sk.begin(), live_key.sk.end()),
        std::vector<unsigned char>(live_key.pk.begin(), live_key.pk.end()),
        live_pk_hash));

    shielded_wallet->TransactionAddedToMempool(live_tx);
    BOOST_REQUIRE(shielded_wallet->GetCachedTransactionView(live_tx.GetHash()).has_value());
    shielded_wallet->TransactionRemovedFromMempool(live_tx);
    shielded_wallet->ScanBlock(live_block, /*height=*/2);

    notes = shielded_wallet->GetUnspentNotes(/*min_depth=*/1);
    BOOST_REQUIRE_EQUAL(notes.size(), 2U);
    const auto live_summary = shielded_wallet->GetShieldedBalanceSummary(/*min_depth=*/1);
    BOOST_CHECK_EQUAL(live_summary.spendable, 0);
    BOOST_CHECK_EQUAL(live_summary.watchonly, historical_value + live_value);
    BOOST_CHECK_EQUAL(live_summary.spendable_note_count, 0);
    BOOST_CHECK_EQUAL(live_summary.watchonly_note_count, 2);
    BOOST_CHECK_EQUAL(shielded_wallet->GetShieldedBalance(/*min_depth=*/1), 0);
}

BOOST_AUTO_TEST_CASE(imported_viewing_key_survives_wallet_mempool_to_block_callbacks)
{
    const mlkem::KeyPair live_key = BuildKeyPair("BTX_ShieldedV2_ChunkScan_ViewOnlyWallet", 21);
    const uint256 live_pk_hash = DeriveUint256("BTX_ShieldedV2_ChunkScan_ViewOnlyWalletPkHash", 21);
    const CAmount live_value = 35 * COIN / 100;
    const CTransaction live_tx =
        BuildMinimalV2SendTransaction(live_pk_hash, live_key.pk, live_value, 0xf4);
    const int tip_height = m_node.chain->getHeight().value_or(0);
    const uint256 tip_hash = m_node.chain->getBlockHash(tip_height);
    int64_t tip_max_time{0};
    BOOST_REQUIRE(m_node.chain->findBlock(tip_hash, interfaces::FoundBlock().maxTime(tip_max_time)));

    CBlock live_block;
    live_block.vtx.push_back(MakeTransactionRef(live_tx));
    live_block.nTime = static_cast<uint32_t>(tip_max_time);

    {
        LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
        BOOST_REQUIRE(shielded_wallet->ImportViewingKey(
            std::vector<unsigned char>(live_key.sk.begin(), live_key.sk.end()),
            std::vector<unsigned char>(live_key.pk.begin(), live_key.pk.end()),
            live_pk_hash));
        BOOST_REQUIRE_NE(wallet.GetBirthTime(), std::numeric_limits<int64_t>::max());
        BOOST_CHECK_LE(wallet.GetBirthTime(), tip_max_time);
    }

    wallet.transactionAddedToMempool(MakeTransactionRef(live_tx));

    const uint256 live_block_hash = live_block.GetHash();
    interfaces::BlockInfo info(live_block_hash);
    info.height = 101;
    info.data = &live_block;
    info.chain_time_max = static_cast<unsigned int>(tip_max_time);
    wallet.blockConnected(ChainstateRole::NORMAL, info);

    LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
    const auto notes = shielded_wallet->GetUnspentNotes(/*min_depth=*/0);
    BOOST_REQUIRE_EQUAL(notes.size(), 1U);
    BOOST_CHECK_EQUAL(notes.front().note.value, live_value);
    BOOST_CHECK(!notes.front().is_mine_spend);
}

BOOST_AUTO_TEST_CASE(block_scan_deduplicates_v2_send_commitments_across_transactions)
{
    const CAmount value = 17 * COIN / 100;
    const CTransaction first_tx =
        BuildMinimalV2SendTransaction(owned_addr.pk_hash, owned_kem_pk, value, 0xf5);

    CMutableTransaction second_mutable{first_tx};
    second_mutable.nLockTime += 1;
    const CTransaction second_tx{second_mutable};

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(first_tx));
    block.vtx.push_back(MakeTransactionRef(second_tx));

    LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
    shielded_wallet->ScanBlock(block, /*height=*/1);

    const auto notes = shielded_wallet->GetUnspentNotes(/*min_depth=*/0);
    BOOST_REQUIRE_EQUAL(notes.size(), 1U);
    BOOST_CHECK_EQUAL(notes.front().note.value, value);
    BOOST_CHECK_EQUAL(shielded_wallet->GetShieldedBalance(/*min_depth=*/0), value);
    BOOST_CHECK(shielded_wallet->GetCachedTransactionView(first_tx.GetHash()).has_value());
    BOOST_CHECK(!shielded_wallet->GetCachedTransactionView(second_tx.GetHash()).has_value());
}

BOOST_AUTO_TEST_CASE(block_scan_rejects_v2_send_credit_when_smile_account_mismatches_note)
{
    const CAmount value = 19 * COIN / 100;
    const CTransaction tx =
        BuildMinimalV2SendTransaction(owned_addr.pk_hash, owned_kem_pk, value, 0xf6);

    const ShieldedNote mismatched_note = MakeNote(owned_addr.pk_hash, value, 0xf7);
    const auto mismatched_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        mismatched_note);
    BOOST_REQUIRE(mismatched_account.has_value());

    CMutableTransaction mutable_tx{tx};
    auto* v2_bundle = mutable_tx.shielded_bundle.v2_bundle ? &*mutable_tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(v2_bundle != nullptr);
    auto& payload = std::get<SendPayload>(v2_bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.outputs.size(), 1U);
    payload.outputs[0].smile_account = *mismatched_account;
    v2_bundle->header.payload_digest = ComputeSendPayloadDigest(payload);
    const CTransaction tampered_tx{mutable_tx};

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(tampered_tx));

    LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
    shielded_wallet->ScanBlock(block, /*height=*/1);

    BOOST_CHECK(shielded_wallet->GetUnspentNotes(/*min_depth=*/0).empty());
    BOOST_CHECK_EQUAL(shielded_wallet->GetShieldedBalance(/*min_depth=*/0), 0);
    BOOST_CHECK(!shielded_wallet->GetCachedTransactionView(tampered_tx.GetHash()).has_value());
}

BOOST_AUTO_TEST_CASE(block_scan_keeps_owned_operator_notes_out_of_spendable_balance)
{
    const CAmount value = 23 * COIN / 100;
    const CTransaction tx =
        BuildMinimalV2SendTransaction(owned_addr.pk_hash, owned_kem_pk, value, 0xf8);

    CMutableTransaction mutable_tx{tx};
    auto* v2_bundle = mutable_tx.shielded_bundle.v2_bundle ? &*mutable_tx.shielded_bundle.v2_bundle : nullptr;
    BOOST_REQUIRE(v2_bundle != nullptr);
    auto& payload = std::get<SendPayload>(v2_bundle->payload);
    BOOST_REQUIRE_EQUAL(payload.outputs.size(), 1U);
    payload.outputs[0].note_class = NoteClass::OPERATOR;
    v2_bundle->header.payload_digest = ComputeSendPayloadDigest(payload);
    const CTransaction operator_tx{mutable_tx};

    CBlock block;
    block.vtx.push_back(MakeTransactionRef(operator_tx));

    LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
    shielded_wallet->ScanBlock(block, /*height=*/1);

    BOOST_CHECK(shielded_wallet->GetUnspentNotes(/*min_depth=*/0).empty());
    BOOST_CHECK_EQUAL(shielded_wallet->GetShieldedBalance(/*min_depth=*/0), 0);

    const auto cached_view = shielded_wallet->GetCachedTransactionView(operator_tx.GetHash());
    BOOST_REQUIRE(cached_view.has_value());
    BOOST_REQUIRE_EQUAL(cached_view->outputs.size(), 1U);
    BOOST_CHECK(cached_view->outputs[0].is_ours);
    BOOST_CHECK_EQUAL(cached_view->outputs[0].amount, value);
}

BOOST_AUTO_TEST_CASE(wallet_caches_reserve_outputs_from_built_ingress_batch)
{
    wallet::ShieldedAddress reserve_addr;
    mlkem::PublicKey reserve_kem_pk{};
    {
        LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
        reserve_addr = shielded_wallet->GenerateNewAddress();
        BOOST_REQUIRE(shielded_wallet->GetKEMPublicKey(reserve_addr, reserve_kem_pk));
    }

    const ShieldedNote spend_input_note = MakeNote(DeriveUint256("BTX_ShieldedV2_Ingress_TestInput", 1),
                                                   40 * COIN,
                                                   0xe1);
    const auto spend_account = smile2::wallet::BuildCompactPublicAccountFromNote(
        smile2::wallet::SMILE_GLOBAL_SEED,
        spend_input_note);
    BOOST_REQUIRE(spend_account.has_value());
    const uint256 spend_note_commitment = smile2::ComputeCompactPublicAccountHash(*spend_account);
    const size_t spend_real_index = 5;
    const shielded::ShieldedMerkleTree spend_tree =
        BuildSpendTree(spend_note_commitment, spend_real_index);
    const std::vector<uint64_t> ring_positions = BuildRingPositions();
    const std::vector<uint256> ring_members = BuildRingMembers(spend_tree, ring_positions);
    const auto smile_ring_members = BuildIngressSpendSmileRingMembers(
        ring_members,
        spend_input_note,
        spend_note_commitment,
        spend_real_index);

    std::vector<shielded::v2::V2IngressLeafInput> ingress_leaves{
        BuildIngressLeafInput(0xe3, 19 * COIN, 1 * COIN),
    };

    std::vector<shielded::BridgeProofDescriptor> descriptors;
    descriptors.push_back({uint256{0xe4}, uint256{0xe5}});
    auto proof_policy = shielded::BuildBridgeProofPolicyCommitment(
        Span<const shielded::BridgeProofDescriptor>{descriptors.data(), descriptors.size()},
        /*required_receipts=*/1);
    BOOST_REQUIRE(proof_policy.has_value());

    shielded::v2::V2IngressStatementTemplate statement_template;
    statement_template.ids.bridge_id = uint256{0xe6};
    statement_template.ids.operation_id = uint256{0xe7};
    statement_template.domain_id = uint256{0xe8};
    statement_template.source_epoch = 14;
    statement_template.data_root = uint256{0xe9};
    statement_template.proof_policy = *proof_policy;

    std::string reject_reason;
    const auto statement = shielded::v2::BuildV2IngressStatement(
        statement_template,
        Span<const shielded::v2::V2IngressLeafInput>{ingress_leaves.data(), ingress_leaves.size()},
        reject_reason);
    BOOST_REQUIRE_MESSAGE(statement.has_value(), reject_reason);

    const ShieldedNote reserve_note = MakeNote(reserve_addr.pk_hash, 20 * COIN, 0xea);
    const shielded::EncryptedNote reserve_encrypted_note =
        EncryptNote(reserve_note, reserve_kem_pk, /*index=*/0xeb);
    auto reserve_payload = EncodeLegacyEncryptedNotePayload(reserve_encrypted_note,
                                                            reserve_kem_pk,
                                                            ScanDomain::RESERVE);
    BOOST_REQUIRE(reserve_payload.has_value());

    shielded::v2::V2SendSpendInput spend_input;
    spend_input.note = spend_input_note;
    spend_input.note_commitment = spend_note_commitment;
    spend_input.account_leaf_hint = shielded::registry::MakeDirectSendAccountLeafHint();
    spend_input.ring_positions = ring_positions;
    spend_input.ring_members = ring_members;
    spend_input.smile_ring_members = smile_ring_members;
    spend_input.real_index = spend_real_index;
    BOOST_REQUIRE(test::shielded::AttachAccountRegistryWitness(spend_input));

    shielded::v2::V2SendOutputInput reserve_output;
    reserve_output.note_class = NoteClass::RESERVE;
    reserve_output.note = reserve_note;
    reserve_output.encrypted_note = *reserve_payload;

    shielded::v2::V2IngressBuildInput build_input;
    build_input.statement = *statement;
    build_input.spend_inputs = {spend_input};
    build_input.reserve_outputs = {reserve_output};
    build_input.ingress_leaves = ingress_leaves;
    build_input.settlement_witness = BuildIngressProofSettlementWitness(*statement, descriptors.front());

    std::array<unsigned char, 32> rng_entropy{};
    rng_entropy.fill(0xed);
    auto built = shielded::v2::BuildV2IngressBatchTransaction(CMutableTransaction{},
                                                              spend_tree.Root(),
                                                              build_input,
                                                              std::vector<unsigned char>(32, 0xec),
                                                              reject_reason,
                                                              Span<const unsigned char>{rng_entropy.data(),
                                                                                       rng_entropy.size()});
    BOOST_REQUIRE_MESSAGE(built.has_value(), reject_reason);

    {
        LOCK2(wallet.cs_wallet, shielded_wallet->cs_shielded);
        const CTransaction tx{built->tx};
        shielded_wallet->TransactionAddedToMempool(tx);

        const auto cached_view = shielded_wallet->GetCachedTransactionView(tx.GetHash());
        BOOST_REQUIRE(cached_view.has_value());
        BOOST_REQUIRE_EQUAL(cached_view->family, "v2_ingress_batch");
        BOOST_REQUIRE_EQUAL(cached_view->outputs.size(), 1U);
        BOOST_CHECK(cached_view->outputs[0].is_ours);
        BOOST_CHECK_EQUAL(cached_view->outputs[0].amount, 20 * COIN);
        BOOST_CHECK(cached_view->output_chunks.empty());
    }
}

BOOST_AUTO_TEST_CASE(shielded_coin_serialization_roundtrip_preserves_optional_account_leaf_hint)
{
    wallet::ShieldedCoin coin;
    coin.note = MakeNote(DeriveUint256("BTX_ShieldedV2_ChunkScan_SerializedNotePkHash", 90), 1234, 91);
    coin.commitment = DeriveUint256("BTX_ShieldedV2_ChunkScan_SerializedCommitment", 92);
    coin.nullifier = DeriveUint256("BTX_ShieldedV2_ChunkScan_SerializedNullifier", 93);
    coin.tree_position = 17;
    coin.confirmation_height = 42;
    coin.spent_height = 45;
    coin.is_spent = true;
    coin.is_mine_spend = true;
    coin.block_hash = DeriveUint256("BTX_ShieldedV2_ChunkScan_SerializedBlockHash", 94);

    const uint256 settlement_digest =
        DeriveUint256("BTX_ShieldedV2_ChunkScan_SerializedSettlementDigest", 95);
    coin.account_leaf_hint = shielded::registry::MakeIngressAccountLeafHint(settlement_digest);
    BOOST_REQUIRE(coin.account_leaf_hint.has_value());

    DataStream with_hint_stream;
    with_hint_stream << coin;

    wallet::ShieldedCoin decoded_with_hint;
    with_hint_stream >> decoded_with_hint;

    BOOST_CHECK_EQUAL(decoded_with_hint.note.value, coin.note.value);
    BOOST_CHECK_EQUAL(decoded_with_hint.note.recipient_pk_hash, coin.note.recipient_pk_hash);
    BOOST_CHECK_EQUAL(decoded_with_hint.note.rho, coin.note.rho);
    BOOST_CHECK_EQUAL(decoded_with_hint.note.rcm, coin.note.rcm);
    BOOST_CHECK_EQUAL(decoded_with_hint.commitment, coin.commitment);
    BOOST_CHECK_EQUAL(decoded_with_hint.nullifier, coin.nullifier);
    BOOST_CHECK_EQUAL(decoded_with_hint.tree_position, coin.tree_position);
    BOOST_CHECK_EQUAL(decoded_with_hint.confirmation_height, coin.confirmation_height);
    BOOST_CHECK_EQUAL(decoded_with_hint.spent_height, coin.spent_height);
    BOOST_CHECK_EQUAL(decoded_with_hint.is_spent, coin.is_spent);
    BOOST_CHECK_EQUAL(decoded_with_hint.is_mine_spend, coin.is_mine_spend);
    BOOST_CHECK_EQUAL(decoded_with_hint.block_hash, coin.block_hash);
    BOOST_REQUIRE(decoded_with_hint.account_leaf_hint.has_value());
    BOOST_CHECK_EQUAL(decoded_with_hint.account_leaf_hint->version,
                      coin.account_leaf_hint->version);
    BOOST_CHECK_EQUAL(decoded_with_hint.account_leaf_hint->domain,
                      coin.account_leaf_hint->domain);
    BOOST_CHECK_EQUAL(decoded_with_hint.account_leaf_hint->settlement_binding_digest,
                      coin.account_leaf_hint->settlement_binding_digest);
    BOOST_CHECK_EQUAL(decoded_with_hint.account_leaf_hint->output_binding_digest,
                      coin.account_leaf_hint->output_binding_digest);

    coin.account_leaf_hint.reset();

    DataStream without_hint_stream;
    without_hint_stream << coin;

    wallet::ShieldedCoin decoded_without_hint;
    without_hint_stream >> decoded_without_hint;

    BOOST_CHECK(!decoded_without_hint.account_leaf_hint.has_value());
    BOOST_CHECK_EQUAL(decoded_without_hint.note.value, coin.note.value);
    BOOST_CHECK_EQUAL(decoded_without_hint.commitment, coin.commitment);
    BOOST_CHECK_EQUAL(decoded_without_hint.nullifier, coin.nullifier);
}

BOOST_AUTO_TEST_SUITE_END()
