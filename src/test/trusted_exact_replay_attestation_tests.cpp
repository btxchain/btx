// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/trusted_exact_replay_attestation.h>

#include <streams.h>
#include <test/util/setup_common.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstddef>
#include <set>
#include <stdexcept>
#include <thread>
#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

using namespace matmul::trusted;
using namespace std::chrono_literals;

const uint256 REPLAY_AUTHORITY_CONTEXT{uint256::ONE};

uint256 TestHash(uint8_t marker)
{
    uint256 out;
    out.data()[0] = marker;
    return out;
}

std::vector<CKey> MakeKeys(size_t count)
{
    std::vector<CKey> keys(count);
    for (auto& key : keys) key.MakeNewKey(/*fCompressed=*/true);
    return keys;
}

ExactReplayStatement MakeStatement(const uint256& chain,
                                   const uint256& block,
                                   int32_t height)
{
    ExactReplayStatement statement;
    statement.chain_id = chain;
    statement.block_hash = block;
    statement.block_height = height;
    statement.replay_authority_context = REPLAY_AUTHORITY_CONTEXT;
    return statement;
}

StoreConfig MakeConfig(const uint256& chain,
                       const std::vector<CKey>& keys,
                       size_t threshold)
{
    StoreConfig config;
    config.chain_id = chain;
    config.replay_authority_context = REPLAY_AUTHORITY_CONTEXT;
    config.threshold = threshold;
    for (const auto& key : keys) {
        config.trusted_signers.push_back(key.GetPubKey());
    }
    return config;
}

ExactReplayAttestation MustSign(const ExactReplayStatement& statement,
                                const CKey& key)
{
    auto attestation{SignStatement(statement, key)};
    BOOST_REQUIRE(attestation.has_value());
    return *attestation;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(trusted_exact_replay_attestation_tests,
                         BasicTestingSetup)

BOOST_AUTO_TEST_CASE(statement_signature_serialization_and_context)
{
    const auto keys{MakeKeys(2)};
    const uint256 chain{TestHash(0x11)};
    const uint256 block{TestHash(0x22)};
    const auto statement{MakeStatement(chain, block, 123)};
    const auto attestation{MustSign(statement, keys[0])};
    const std::set<CPubKey> trusted{keys[0].GetPubKey()};

    BOOST_CHECK(CPubKey::CheckLowS(attestation.signature));
    BOOST_CHECK_EQUAL(
        VerifyResultName(VerifyAttestation(
            attestation, chain, REPLAY_AUTHORITY_CONTEXT, block, 123,
            trusted)),
        "valid");

    DataStream statement_stream;
    statement_stream << statement;
    BOOST_CHECK_EQUAL(statement_stream.size(), 103U);
    BOOST_CHECK_EQUAL(std::to_integer<uint8_t>(statement_stream[0]),
                      ExactReplayStatement::CURRENT_VERSION);
    // V2 appends authority context after the legacy fields, preserving the
    // V1 block-hash offset used by bounded relay inspection.
    BOOST_CHECK_EQUAL(std::to_integer<uint8_t>(statement_stream[33]),
                      block.data()[0]);
    BOOST_CHECK_EQUAL(std::to_integer<uint8_t>(statement_stream[71]),
                      REPLAY_AUTHORITY_CONTEXT.data()[0]);

    auto v1_statement{statement};
    v1_statement.version = 1;
    DataStream v1_statement_stream;
    v1_statement_stream << v1_statement;
    BOOST_CHECK_EQUAL(v1_statement_stream.size(), 71U);
    ExactReplayStatement decoded_v1;
    decoded_v1.replay_authority_context = REPLAY_AUTHORITY_CONTEXT;
    v1_statement_stream >> decoded_v1;
    BOOST_CHECK_EQUAL(decoded_v1.version, 1U);
    BOOST_CHECK(decoded_v1.replay_authority_context.IsNull());

    DataStream stream;
    stream << attestation;
    ExactReplayAttestation decoded;
    stream >> decoded;
    BOOST_CHECK(decoded == attestation);
    BOOST_CHECK(StatementHash(decoded.statement) == StatementHash(statement));
    auto other_context_statement{statement};
    other_context_statement.replay_authority_context = TestHash(0x10);
    BOOST_CHECK(StatementHash(other_context_statement) !=
                StatementHash(statement));

    BOOST_CHECK(VerifyAttestation(
                    attestation, TestHash(0x12),
                    REPLAY_AUTHORITY_CONTEXT, block, 123, trusted) ==
                VerifyResult::WrongChain);
    BOOST_CHECK(VerifyAttestation(
                    attestation, chain, REPLAY_AUTHORITY_CONTEXT,
                    TestHash(0x23), 123, trusted) ==
                VerifyResult::WrongBlock);
    BOOST_CHECK(VerifyAttestation(
                    attestation, chain, REPLAY_AUTHORITY_CONTEXT,
                    block, 124, trusted) ==
                VerifyResult::WrongHeight);
    BOOST_CHECK(VerifyAttestation(
                    attestation, chain, TestHash(0x24), block, 123,
                    trusted) ==
                VerifyResult::WrongReplayAuthorityContext);

    auto altered{attestation};
    altered.statement.version = 1;
    BOOST_CHECK(VerifyAttestation(
                    altered, chain, REPLAY_AUTHORITY_CONTEXT, block, 123,
                    trusted) == VerifyResult::UnsupportedVersion);
    altered = attestation;
    altered.statement.profile++;
    BOOST_CHECK(VerifyAttestation(
                    altered, chain, REPLAY_AUTHORITY_CONTEXT, block, 123,
                    trusted) == VerifyResult::WrongMatMulContext);
    altered = attestation;
    altered.statement.replay_authority_context = TestHash(0x25);
    BOOST_CHECK(VerifyAttestation(
                    altered, chain, REPLAY_AUTHORITY_CONTEXT, block, 123,
                    trusted) ==
                VerifyResult::WrongReplayAuthorityContext);
    // 3.4: old-context flood is rejected on statement fields BEFORE secp.
    // A garbage signature must not change the result to InvalidSignature.
    {
        auto cheap{attestation};
        cheap.statement.replay_authority_context = TestHash(0x25);
        cheap.signature = {0x00, 0x01, 0x02};
        BOOST_CHECK(VerifyAttestationCrypto(cheap, chain, REPLAY_AUTHORITY_CONTEXT,
                                            block, 123) ==
                    VerifyResult::WrongReplayAuthorityContext);
        BOOST_CHECK(VerifyAttestation(cheap, chain, REPLAY_AUTHORITY_CONTEXT, block,
                                      123, trusted) ==
                    VerifyResult::WrongReplayAuthorityContext);
    }
    // Even a verifier configured for the altered context rejects the original
    // signature: the V2 domain signs the context bytes themselves.
    BOOST_CHECK(VerifyAttestation(
                    altered, chain, TestHash(0x25), block, 123,
                    trusted) == VerifyResult::InvalidSignature);

    const std::set<CPubKey> other_trust{keys[1].GetPubKey()};
    BOOST_CHECK(VerifyAttestation(
                    attestation, chain, REPLAY_AUTHORITY_CONTEXT, block, 123,
                    other_trust) ==
                VerifyResult::UntrustedSigner);

    altered = attestation;
    altered.signature.back() ^= 1;
    BOOST_CHECK(VerifyAttestation(
                    altered, chain, REPLAY_AUTHORITY_CONTEXT, block, 123,
                    trusted) == VerifyResult::InvalidSignature);
    // Add a redundant R padding byte while keeping the lax-DER value intact.
    // The attestation layer must reject this malleable encoding itself.
    altered = attestation;
    altered.signature.insert(altered.signature.begin() + 4, 0);
    ++altered.signature[1];
    ++altered.signature[3];
    BOOST_CHECK(VerifyAttestation(
                    altered, chain, REPLAY_AUTHORITY_CONTEXT, block, 123,
                    trusted) == VerifyResult::InvalidSignature);
    altered = attestation;
    altered.signature.assign(CPubKey::SIGNATURE_SIZE + 1, 0);
    BOOST_CHECK(VerifyAttestation(
                    altered, chain, REPLAY_AUTHORITY_CONTEXT, block, 123,
                    trusted) == VerifyResult::InvalidSignature);
    altered = attestation;
    altered.signer = CPubKey{};
    BOOST_CHECK(VerifyAttestation(
                    altered, chain, REPLAY_AUTHORITY_CONTEXT, block, 123,
                    trusted) == VerifyResult::InvalidSigner);
}

BOOST_AUTO_TEST_CASE(config_validation_and_local_signer)
{
    const auto keys{MakeKeys(2)};
    const uint256 chain{TestHash(0x31)};
    auto config{MakeConfig(chain, keys, 2)};
    config.local_signer = keys[0];
    AttestationStore store{config};

    ExactReplayAttestation produced;
    BOOST_CHECK(store.SignLocal(TestHash(0x32), 7, &produced) ==
                AddResult::Accepted);
    BOOST_CHECK(produced.signer == keys[0].GetPubKey());
    BOOST_CHECK(produced.statement.replay_authority_context ==
                REPLAY_AUTHORITY_CONTEXT);
    BOOST_CHECK(store.LocalSignerPubKey() == keys[0].GetPubKey());
    BOOST_CHECK(!store.HasQuorum(TestHash(0x32), 7));
    BOOST_CHECK(store.SignLocal(TestHash(0x33), 7) == AddResult::HeightOccupied);
    BOOST_CHECK(store.SignLocal(TestHash(0x32), 7) == AddResult::Duplicate);
    // A dual-attest already on the wire must still load. Minting stays refused.
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, TestHash(0x33), 7), keys[0]),
                         TestHash(0x33), 7) == AddResult::Accepted);
    BOOST_CHECK(store.SignLocal(TestHash(0x34), 7) == AddResult::HeightOccupied);

    // Relayed stolen-WIF vote on a competing hash must not jam SignLocal.
    // M=2: one pin vote is not quorum, so the honest attestor still signs.
    const auto keys_m2{MakeKeys(2)};
    auto config_m2{MakeConfig(chain, keys_m2, 2)};
    config_m2.local_signer = keys_m2[0];
    AttestationStore store_m2{config_m2};
    BOOST_CHECK(store_m2.Add(MustSign(MakeStatement(chain, TestHash(0x40), 8), keys_m2[0]),
                             TestHash(0x40), 8) == AddResult::Accepted);
    BOOST_CHECK(store_m2.SignLocal(TestHash(0x41), 8) == AddResult::Accepted);
    BOOST_CHECK(!store_m2.HasQuorum(TestHash(0x40), 8));
    BOOST_CHECK(!store_m2.HasQuorum(TestHash(0x41), 8));

    auto no_local{MakeConfig(chain, keys, 1)};
    AttestationStore no_local_store{no_local};
    BOOST_CHECK(no_local_store.SignLocal(TestHash(0x32), 7) ==
                AddResult::NoLocalSigner);

    auto bad{MakeConfig(chain, keys, 0)};
    BOOST_CHECK_THROW(AttestationStore{bad}, std::invalid_argument);
    bad = MakeConfig(chain, keys, 3);
    BOOST_CHECK_THROW(AttestationStore{bad}, std::invalid_argument);
    bad = MakeConfig(chain, keys, 1);
    bad.trusted_signers.push_back(keys[0].GetPubKey());
    BOOST_CHECK_THROW(AttestationStore{bad}, std::invalid_argument);
    bad = MakeConfig(chain, keys, 1);
    bad.local_signer = MakeKeys(1)[0];
    BOOST_CHECK_THROW(AttestationStore{bad}, std::invalid_argument);
    bad = MakeConfig(chain, keys, 1);
    bad.replay_authority_context.SetNull();
    BOOST_CHECK_THROW(AttestationStore{bad}, std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(reorg_releases_mint_slot_inbound_cannot)
{
    const auto keys{MakeKeys(2)};
    const uint256 chain{TestHash(0x61)};
    const uint256 hash_a{TestHash(0x62)};
    const uint256 hash_b{TestHash(0x63)};
    const uint256 hash_c{TestHash(0x64)};
    auto config{MakeConfig(chain, keys, /*threshold=*/2)};
    config.local_signer = keys[0];
    config.open_attestors = true;
    AttestationStore store{config};

    ExactReplayAttestation minted_a;
    BOOST_REQUIRE(store.SignLocal(hash_a, 20, &minted_a) == AddResult::Accepted);
    BOOST_CHECK(store.LocalMintedHash(20) == hash_a);
    BOOST_CHECK(store.SignLocal(hash_b, 20) == AddResult::HeightOccupied);

    // Inbound competing hash (stolen-WIF copy of the local pin key) must not
    // release the mint slot. Add() is the P2P path.
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, hash_c, 20), keys[0]),
                          hash_c, 20) == AddResult::Accepted);
    BOOST_CHECK(store.LocalMintedHash(20) == hash_a);
    BOOST_CHECK(!store.IsOffActiveChain(20, hash_c));
    BOOST_CHECK(store.SignLocal(hash_b, 20) == AddResult::HeightOccupied);

    // Disconnecting a hash this node did not mint also must not release.
    BOOST_CHECK(!store.NotifyActiveChainBlockDisconnected(20, hash_c));
    BOOST_CHECK(store.LocalMintedHash(20) == hash_a);
    BOOST_CHECK(store.SignLocal(hash_b, 20) == AddResult::HeightOccupied);

    // Own validated reorg of the minted hash releases the slot.
    BOOST_CHECK(store.NotifyActiveChainBlockDisconnected(20, hash_a));
    BOOST_CHECK(!store.LocalMintedHash(20).has_value());
    BOOST_CHECK(store.IsOffActiveChain(20, hash_a));

    ExactReplayAttestation minted_b;
    BOOST_CHECK(store.SignLocal(hash_b, 20, &minted_b) == AddResult::Accepted);
    BOOST_CHECK(store.LocalMintedHash(20) == hash_b);
    BOOST_CHECK(minted_b.statement.block_hash == hash_b);
    BOOST_CHECK_EQUAL(store.GetAttestations(hash_b, 20).size(), 1);
    BOOST_CHECK(store.GetAttestations(hash_a, 20).size() >= 1);

    // Open attestor who signed the disconnected hash can re-sign the new one
    // without being frozen for equivocation.
    const auto extra{MakeKeys(1)};
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, hash_a, 21), extra[0]),
                          hash_a, 21) == AddResult::Heard);
    store.NotifyActiveChainBlockDisconnected(21, hash_a);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, hash_b, 21), extra[0]),
                          hash_b, 21) == AddResult::Heard);
    BOOST_CHECK(!store.IsFrozenOpenSigner(extra[0].GetPubKey()));
}

BOOST_AUTO_TEST_CASE(competing_quorum_still_occupies_after_reorg_of_other_hash)
{
    const auto keys{MakeKeys(2)};
    const uint256 chain{TestHash(0x71)};
    const uint256 hash_a{TestHash(0x72)};
    const uint256 hash_b{TestHash(0x73)};
    const uint256 hash_c{TestHash(0x74)};
    auto config{MakeConfig(chain, keys, /*threshold=*/2)};
    config.local_signer = keys[0];
    AttestationStore store{config};

    BOOST_REQUIRE(store.SignLocal(hash_a, 30) == AddResult::Accepted);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, hash_c, 30), keys[0]),
                            hash_c, 30) == AddResult::Accepted);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, hash_c, 30), keys[1]),
                            hash_c, 30) == AddResult::Accepted);
    BOOST_CHECK(store.HasQuorum(hash_c, 30));
    BOOST_CHECK(store.SignLocal(hash_b, 30) == AddResult::HeightOccupied);

    // Reorging the hash we minted must not drop the competing-quorum guard
    // on a hash that is still off our chain (stolen-WIF / dual-attest jam).
    BOOST_CHECK(store.NotifyActiveChainBlockDisconnected(30, hash_a));
    BOOST_CHECK(!store.LocalMintedHash(30).has_value());
    BOOST_CHECK(store.SignLocal(hash_b, 30) == AddResult::HeightOccupied);
}

BOOST_AUTO_TEST_CASE(rpc_clear_local_mint_slots)
{
    const auto keys{MakeKeys(2)};
    const uint256 chain{TestHash(0x81)};
    auto config{MakeConfig(chain, keys, /*threshold=*/2)};
    config.local_signer = keys[0];
    AttestationStore store{config};

    BOOST_REQUIRE(store.SignLocal(TestHash(0x82), 40) == AddResult::Accepted);
    BOOST_REQUIRE(store.SignLocal(TestHash(0x83), 41) == AddResult::Accepted);
    BOOST_CHECK(store.SignLocal(TestHash(0x84), 40) == AddResult::HeightOccupied);

    BOOST_CHECK_EQUAL(store.ClearLocalMintSlots(40, 41), 2);
    BOOST_CHECK(!store.LocalMintedHash(40).has_value());
    BOOST_CHECK(!store.LocalMintedHash(41).has_value());
    BOOST_CHECK(store.SignLocal(TestHash(0x84), 40) == AddResult::Accepted);
    BOOST_CHECK_EQUAL(store.GetAttestations(TestHash(0x84), 40).size(), 1);
    BOOST_CHECK_EQUAL(store.ClearLocalMintSlots(40, 40), 1);
    BOOST_CHECK_EQUAL(store.ClearLocalMintSlots(40, 40), 0);
}

BOOST_AUTO_TEST_CASE(unique_signer_quorum_and_rejections)
{
    const auto keys{MakeKeys(3)};
    const uint256 chain{TestHash(0x41)};
    const uint256 block{TestHash(0x42)};
    const auto statement{MakeStatement(chain, block, 51)};
    AttestationStore store{MakeConfig(chain, keys, 2)};

    const auto first{MustSign(statement, keys[0])};
    BOOST_CHECK(store.Add(first, block, 51) == AddResult::Accepted);
    BOOST_CHECK(store.Add(first, block, 51) == AddResult::Duplicate);
    BOOST_CHECK(!store.HasQuorum(block, 51));
    BOOST_CHECK_EQUAL(store.GetAttestations(block, 51).size(), 1);

    const auto second{MustSign(statement, keys[1])};
    BOOST_CHECK(store.Add(second, block, 51) == AddResult::Accepted);
    BOOST_CHECK(store.HasQuorum(block, 51));
    BOOST_CHECK_EQUAL(store.GetAttestations(block, 51).size(), 2);

    BOOST_CHECK(store.Add(MustSign(statement, MakeKeys(1)[0]), block, 51) ==
                AddResult::UntrustedSigner);
    BOOST_CHECK(store.Add(first, TestHash(0x43), 51) ==
                AddResult::WrongBlock);
    BOOST_CHECK(store.Add(first, block, 52) == AddResult::WrongHeight);

    auto wrong_chain{MakeStatement(TestHash(0x44), block, 51)};
    BOOST_CHECK(store.Add(MustSign(wrong_chain, keys[2]), block, 51) ==
                AddResult::WrongChain);
    auto wrong_context{statement};
    wrong_context.replay_authority_context = TestHash(0x45);
    BOOST_CHECK(store.Add(MustSign(wrong_context, keys[2]), block, 51) ==
                AddResult::WrongReplayAuthorityContext);

    const StoreStats stats{store.GetStats()};
    BOOST_CHECK_EQUAL(stats.accepted, 2);
    BOOST_CHECK_EQUAL(stats.duplicates, 1);
    BOOST_CHECK_EQUAL(stats.rejected, 5);
    BOOST_CHECK_EQUAL(stats.quorum_transitions, 1);
    BOOST_CHECK_EQUAL(stats.stored_attestations, 2);
    BOOST_CHECK_EQUAL(stats.blocks_with_quorum, 1);
}

BOOST_AUTO_TEST_CASE(wait_quorum_no_lost_wakeup_cancel_and_timeout)
{
    const auto keys{MakeKeys(2)};
    const uint256 chain{TestHash(0x51)};
    const uint256 block{TestHash(0x52)};
    const auto statement{MakeStatement(chain, block, 88)};
    AttestationStore store{MakeConfig(chain, keys, 2)};
    BOOST_REQUIRE(store.Add(MustSign(statement, keys[0]), block, 88) ==
                  AddResult::Accepted);

    std::atomic<AddResult> producer_result{AddResult::InvalidSignature};
    std::thread producer{[&] {
        std::this_thread::sleep_for(10ms);
        producer_result.store(
            store.Add(MustSign(statement, keys[1]), block, 88));
    }};
    std::vector<ExactReplayAttestation> quorum;
    BOOST_CHECK(store.WaitForQuorum(block, 88, 1s, {}, &quorum) ==
                WaitResult::Quorum);
    producer.join();
    BOOST_CHECK(producer_result.load() == AddResult::Accepted);
    BOOST_CHECK_EQUAL(quorum.size(), 2);

    // Quorum existing before the wait must be observed immediately.
    BOOST_CHECK(store.WaitForQuorum(block, 88, 0ms) == WaitResult::Quorum);

    std::atomic_bool cancel{false};
    std::thread canceller{[&] {
        std::this_thread::sleep_for(10ms);
        cancel.store(true);
    }};
    BOOST_CHECK(store.WaitForQuorum(
                    TestHash(0x53), 89, 1s,
                    [&] { return cancel.load(); }) ==
                WaitResult::Cancelled);
    canceller.join();
    BOOST_CHECK(store.WaitForQuorum(TestHash(0x54), 90, 5ms) ==
                WaitResult::Timeout);

    const auto stats{store.GetStats()};
    BOOST_CHECK_EQUAL(stats.waits, 4);
    BOOST_CHECK_EQUAL(stats.wait_quorums, 2);
    BOOST_CHECK_EQUAL(stats.wait_cancellations, 1);
    BOOST_CHECK_EQUAL(stats.wait_timeouts, 1);
}

BOOST_AUTO_TEST_CASE(capacity_eviction_and_expiry)
{
    const auto keys{MakeKeys(3)};
    const uint256 chain{TestHash(0x61)};
    auto config{MakeConfig(chain, keys, 2)};
    config.max_blocks = 1;
    config.max_attestations = 2;
    config.ttl = 5ms;
    AttestationStore store{config};

    const uint256 first_block{TestHash(0x62)};
    const auto first_statement{MakeStatement(chain, first_block, 100)};
    BOOST_REQUIRE(store.Add(MustSign(first_statement, keys[0]),
                            first_block, 100) == AddResult::Accepted);
    BOOST_REQUIRE(store.Add(MustSign(first_statement, keys[1]),
                            first_block, 100) == AddResult::Accepted);
    BOOST_CHECK(store.Add(MustSign(first_statement, keys[2]),
                          first_block, 100) == AddResult::Capacity);

    const uint256 second_block{TestHash(0x63)};
    const auto second_statement{MakeStatement(chain, second_block, 101)};
    BOOST_CHECK(store.Add(MustSign(second_statement, keys[0]),
                          second_block, 101) == AddResult::Accepted);
    BOOST_CHECK(store.HasQuorum(first_block, 100));
    BOOST_CHECK_EQUAL(store.GetStats().evicted_blocks, 0);
    BOOST_CHECK_EQUAL(store.GetStats().stored_blocks, 2);
    BOOST_CHECK_EQUAL(store.GetStats().stored_attestations, 3);
    BOOST_CHECK_EQUAL(store.GetStats().capacity_rejections, 1);

    store.Erase(second_block, 101);
    BOOST_CHECK_EQUAL(store.GetStats().stored_blocks, 1);

    BOOST_REQUIRE(store.Add(MustSign(second_statement, keys[0]),
                            second_block, 101) == AddResult::Accepted);
    std::this_thread::sleep_for(10ms);
    store.PruneExpired();
    BOOST_CHECK_EQUAL(store.GetStats().stored_blocks, 0);
    BOOST_CHECK_EQUAL(store.GetStats().expired_blocks, 2);
}

BOOST_AUTO_TEST_CASE(minority_votes_cannot_evict_quorum)
{
    const auto keys{MakeKeys(2)};
    const uint256 chain{TestHash(0x71)};
    auto config{MakeConfig(chain, keys, 2)};
    config.max_blocks = 2;
    config.max_attestations = 4;
    AttestationStore store{config};

    const uint256 quorum_block{TestHash(0x72)};
    const auto quorum_statement{
        MakeStatement(chain, quorum_block, 200)};
    BOOST_REQUIRE(store.Add(
        MustSign(quorum_statement, keys[0]),
        quorum_block, 200) == AddResult::Accepted);
    BOOST_REQUIRE(store.Add(
        MustSign(quorum_statement, keys[1]),
        quorum_block, 200) == AddResult::Accepted);

    const uint256 minority_a{TestHash(0x73)};
    const uint256 minority_b{TestHash(0x74)};
    BOOST_REQUIRE(store.Add(
        MustSign(MakeStatement(chain, minority_a, 201), keys[0]),
        minority_a, 201) == AddResult::Accepted);
    BOOST_REQUIRE(store.Add(
        MustSign(MakeStatement(chain, minority_b, 202), keys[0]),
        minority_b, 202) == AddResult::Accepted);

    BOOST_CHECK(store.HasQuorum(quorum_block, 200));
    BOOST_CHECK(store.GetAttestations(minority_a, 201).empty());
    BOOST_CHECK_EQUAL(
        store.GetAttestations(minority_b, 202).size(), 1);
    BOOST_CHECK_EQUAL(store.GetStats().evicted_blocks, 1);
}

BOOST_AUTO_TEST_CASE(sequential_quorums_advance_beyond_capacity)
{
    const auto keys{MakeKeys(2)};
    const uint256 chain{TestHash(0x81)};
    auto config{MakeConfig(chain, keys, 2)};
    config.max_blocks = 2;
    config.max_attestations = 4;
    AttestationStore store{config};

    constexpr int BLOCK_COUNT{6};
    std::array<uint256, BLOCK_COUNT> blocks;
    for (int i = 0; i < BLOCK_COUNT; ++i) {
        blocks[i] = TestHash(0x82 + i);
        const int32_t height{300 + i};
        const auto statement{MakeStatement(chain, blocks[i], height)};

        BOOST_REQUIRE(store.Add(
            MustSign(statement, keys[0]),
            blocks[i], height) == AddResult::Accepted);
        if (i >= 2) {
            // One bounded partial staging bucket may temporarily sit beside
            // the full completed-quorum set.
            const auto staged_stats{store.GetStats()};
            BOOST_CHECK_EQUAL(staged_stats.stored_blocks, 3);
            BOOST_CHECK_EQUAL(staged_stats.stored_attestations, 5);
            BOOST_CHECK_EQUAL(staged_stats.blocks_with_quorum, 2);
            BOOST_CHECK(store.HasQuorum(blocks[i - 1], height - 1));
        }

        BOOST_REQUIRE(store.Add(
            MustSign(statement, keys[1]),
            blocks[i], height) == AddResult::Accepted);
        const auto completed_stats{store.GetStats()};
        BOOST_CHECK_EQUAL(completed_stats.stored_blocks,
                          std::min(i + 1, 2));
        BOOST_CHECK_EQUAL(completed_stats.stored_attestations,
                          2 * std::min(i + 1, 2));
        BOOST_CHECK_EQUAL(completed_stats.blocks_with_quorum,
                          std::min(i + 1, 2));
        BOOST_CHECK(store.HasQuorum(blocks[i], height));
        if (i >= 2) {
            BOOST_CHECK(store.GetAttestations(
                            blocks[i - 2], height - 2).empty());
        }
    }

    const auto stats{store.GetStats()};
    BOOST_CHECK_EQUAL(stats.evicted_blocks, BLOCK_COUNT - 2);
    BOOST_CHECK_EQUAL(stats.capacity_rejections, 0);
    BOOST_CHECK_EQUAL(stats.quorum_transitions, BLOCK_COUNT);
}

BOOST_AUTO_TEST_CASE(export_all_and_durable_retention_skips_ttl)
{
    const auto keys{MakeKeys(1)};
    auto config{MakeConfig(TestHash(0x41), keys, /*threshold=*/1)};
    config.ttl = 1ms;
    AttestationStore store{config};
    store.SetDurableRetention(true);

    const uint256 block{TestHash(0x42)};
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(TestHash(0x41), block, 7),
                                     keys[0]),
                            block, 7) == AddResult::Accepted);
    std::this_thread::sleep_for(5ms);
    // WaitForQuorum would prune under TTL; durable retention must keep it.
    BOOST_CHECK(store.HasQuorum(block, 7));
    const auto exported{store.ExportAll()};
    BOOST_REQUIRE_EQUAL(exported.size(), 1U);
    BOOST_CHECK(exported[0].statement.block_hash == block);
}

BOOST_AUTO_TEST_CASE(verify_crypto_splits_membership)
{
    const auto keys{MakeKeys(2)};
    const uint256 chain{TestHash(0x51)};
    const uint256 block{TestHash(0x52)};
    const auto attestation{MustSign(MakeStatement(chain, block, 9), keys[0])};
    const std::set<CPubKey> pin{keys[1].GetPubKey()};

    BOOST_CHECK(VerifyAttestationCrypto(
                    attestation, chain, REPLAY_AUTHORITY_CONTEXT, block, 9) ==
                VerifyResult::Valid);
    BOOST_CHECK(VerifyAttestation(
                    attestation, chain, REPLAY_AUTHORITY_CONTEXT, block, 9,
                    pin) == VerifyResult::UntrustedSigner);
}

BOOST_AUTO_TEST_CASE(open_pin_quorum_remains_sufficient)
{
    const auto keys{MakeKeys(2)};
    const uint256 chain{TestHash(0x61)};
    const uint256 block{TestHash(0x62)};
    auto config{MakeConfig(chain, keys, /*threshold=*/1)};
    config.open_attestors = true;
    config.open_threshold = 2;
    AttestationStore store{config};

    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, block, 11), keys[0]),
                            block, 11) == AddResult::Accepted);
    BOOST_CHECK(store.HasQuorum(block, 11));
    BOOST_CHECK_EQUAL(store.OpenThreshold(), 2);
}

BOOST_AUTO_TEST_CASE(open_sybil_never_admits_or_quorum)
{
    const auto pin{MakeKeys(2)};
    const auto sybil{MakeKeys(3)};
    const uint256 chain{TestHash(0x71)};
    const uint256 honest{TestHash(0x72)};
    const uint256 fake{TestHash(0x73)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.open_attestors = true;
    config.open_threshold = 2;
    AttestationStore store{config};

    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, honest, 20), pin[0]),
                            honest, 20) == AddResult::Accepted);
    BOOST_CHECK(store.HasQuorum(honest, 20));

    for (const auto& key : sybil) {
        BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, fake, 21), key),
                              fake, 21) == AddResult::Heard);
    }
    BOOST_CHECK(!store.HasQuorum(fake, 21));
    BOOST_CHECK(store.AdmittedOpenSigners().empty());
    BOOST_CHECK_EQUAL(store.GetHeard(fake, 21).size(), 3);
}

BOOST_AUTO_TEST_CASE(open_admission_then_open_quorum)
{
    const auto pin{MakeKeys(2)};
    const auto open{MakeKeys(2)};
    const uint256 chain{TestHash(0x81)};
    const uint256 genesis_attested{TestHash(0x82)};
    const uint256 next{TestHash(0x83)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.open_attestors = true;
    config.open_threshold = 2;
    AttestationStore store{config};

    BOOST_REQUIRE(
        store.Add(MustSign(MakeStatement(chain, genesis_attested, 30), pin[0]),
                  genesis_attested, 30) == AddResult::Accepted);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, genesis_attested, 30),
                                   open[0]),
                          genesis_attested, 30) == AddResult::Heard);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, genesis_attested, 30),
                                   open[1]),
                          genesis_attested, 30) == AddResult::Heard);
    BOOST_CHECK_EQUAL(store.AdmittedOpenSigners().size(), 2);
    BOOST_CHECK(store.HasQuorum(genesis_attested, 30));
    BOOST_CHECK(store.HasOpenQuorum(genesis_attested, 30));

    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, next, 31), open[0]),
                          next, 31) == AddResult::Heard);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, next, 31), open[1]),
                          next, 31) == AddResult::Heard);
    BOOST_CHECK(store.HasOpenQuorum(next, 31));
    BOOST_CHECK(!store.HasQuorum(next, 31));
}

BOOST_AUTO_TEST_CASE(open_heard_rereplay_stays_heard)
{
    const auto pin{MakeKeys(1)};
    const auto open{MakeKeys(1)};
    const uint256 chain{TestHash(0x91)};
    const uint256 block{TestHash(0x92)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.open_attestors = true;
    AttestationStore store{config};
    const auto heard{MustSign(MakeStatement(chain, block, 40), open[0])};
    BOOST_CHECK(store.Add(heard, block, 40) == AddResult::Heard);
    BOOST_CHECK(store.Add(heard, block, 40) == AddResult::Heard);
    BOOST_CHECK_EQUAL(store.GetStats().duplicates, 0);
}

BOOST_AUTO_TEST_CASE(open_heard_then_pin_completes_admits)
{
    const auto pin{MakeKeys(1)};
    const auto extra{MakeKeys(1)};
    const uint256 chain{TestHash(0x91)};
    const uint256 block{TestHash(0x92)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.open_attestors = true;
    config.open_threshold = 2;
    AttestationStore store{config};

    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, block, 40), extra[0]),
                          block, 40) == AddResult::Heard);
    BOOST_CHECK(store.AdmittedOpenSigners().empty());
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, block, 40), pin[0]),
                            block, 40) == AddResult::Accepted);
    BOOST_CHECK(store.IsAdmittedOpenSigner(extra[0].GetPubKey()));
    BOOST_CHECK(store.HasQuorum(block, 40));
    BOOST_CHECK_EQUAL(store.GetHeard(block, 40).size(), 1);
}

BOOST_AUTO_TEST_CASE(open_equivocation_freezes_key)
{
    const auto pin{MakeKeys(1)};
    const auto extra{MakeKeys(1)};
    const uint256 chain{TestHash(0xa1)};
    const uint256 first{TestHash(0xa2)};
    const uint256 twin{TestHash(0xa3)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.open_attestors = true;
    AttestationStore store{config};

    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, first, 50), pin[0]),
                            first, 50) == AddResult::Accepted);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, first, 50), extra[0]),
                            first, 50) == AddResult::Heard);
    BOOST_CHECK(store.IsAdmittedOpenSigner(extra[0].GetPubKey()));
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, twin, 50), extra[0]),
                          twin, 50) == AddResult::Equivocation);
    BOOST_CHECK(store.IsFrozenOpenSigner(extra[0].GetPubKey()));
    BOOST_CHECK(!store.IsAdmittedOpenSigner(extra[0].GetPubKey()));
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, twin, 51), extra[0]),
                          twin, 51) == AddResult::FrozenSigner);
}

BOOST_AUTO_TEST_CASE(pin_refutation_blocks_open_quorum_only)
{
    const auto pin{MakeKeys(2)};
    const auto extra{MakeKeys(2)};
    const uint256 chain{TestHash(0xb1)};
    const uint256 boot{TestHash(0xb2)};
    const uint256 lunatic{TestHash(0xb3)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.open_attestors = true;
    config.open_threshold = 2;
    AttestationStore store{config};

    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, boot, 60), pin[0]),
                            boot, 60) == AddResult::Accepted);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, boot, 60), extra[0]),
                            boot, 60) == AddResult::Heard);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, boot, 60), extra[1]),
                            boot, 60) == AddResult::Heard);

    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, lunatic, 61), extra[0]),
                            lunatic, 61) == AddResult::Heard);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, lunatic, 61), extra[1]),
                            lunatic, 61) == AddResult::Heard);
    BOOST_CHECK(store.HasOpenQuorum(lunatic, 61));
    BOOST_CHECK(!store.HasQuorum(lunatic, 61));

    auto refute{SignRefutation(MakeStatement(chain, lunatic, 61), pin[1])};
    BOOST_REQUIRE(refute.has_value());
    BOOST_CHECK(store.AddRefutation(*refute, lunatic, 61) == AddResult::Accepted);
    BOOST_CHECK(!store.HasOpenQuorum(lunatic, 61));
    BOOST_CHECK(!store.HasQuorum(lunatic, 61));

    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, lunatic, 61), pin[0]),
                            lunatic, 61) == AddResult::Accepted);
    BOOST_CHECK(store.HasQuorum(lunatic, 61));
}

BOOST_AUTO_TEST_CASE(pin_refutation_requires_pin_threshold)
{
    const auto pin{MakeKeys(2)};
    const auto extra{MakeKeys(2)};
    const uint256 chain{TestHash(0xb4)};
    const uint256 boot{TestHash(0xb5)};
    const uint256 lunatic{TestHash(0xb6)};
    auto config{MakeConfig(chain, pin, /*threshold=*/2)};
    config.open_attestors = true;
    config.open_threshold = 2;
    AttestationStore store{config};

    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, boot, 70), pin[0]),
                            boot, 70) == AddResult::Accepted);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, boot, 70), pin[1]),
                            boot, 70) == AddResult::Accepted);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, boot, 70), extra[0]),
                            boot, 70) == AddResult::Heard);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, boot, 70), extra[1]),
                            boot, 70) == AddResult::Heard);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, lunatic, 71), extra[0]),
                            lunatic, 71) == AddResult::Heard);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, lunatic, 71), extra[1]),
                            lunatic, 71) == AddResult::Heard);
    BOOST_CHECK(store.HasOpenQuorum(lunatic, 71));

    auto first{SignRefutation(MakeStatement(chain, lunatic, 71), pin[0])};
    BOOST_REQUIRE(first.has_value());
    BOOST_CHECK(store.AddRefutation(*first, lunatic, 71) == AddResult::Accepted);
    BOOST_CHECK(store.HasOpenQuorum(lunatic, 71));

    auto second{SignRefutation(MakeStatement(chain, lunatic, 71), pin[1])};
    BOOST_REQUIRE(second.has_value());
    BOOST_CHECK(store.AddRefutation(*second, lunatic, 71) == AddResult::Accepted);
    BOOST_CHECK(!store.HasOpenQuorum(lunatic, 71));
}

BOOST_AUTO_TEST_CASE(open_directory_caps_admitted_and_signed_heights)
{
    const auto pin{MakeKeys(1)};
    const auto extra{MakeKeys(3)};
    const uint256 chain{TestHash(0xc4)};
    const uint256 boot{TestHash(0xc5)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.open_attestors = true;
    config.open_threshold = 2;
    config.max_admitted_open = 1;
    config.max_open_signed_heights = 2;
    AttestationStore store{config};

    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, boot, 80), pin[0]),
                            boot, 80) == AddResult::Accepted);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, boot, 80), extra[0]),
                          boot, 80) == AddResult::Heard);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, boot, 80), extra[1]),
                          boot, 80) == AddResult::Heard);
    BOOST_CHECK_EQUAL(store.AdmittedOpenSigners().size(), 1);
    BOOST_CHECK(store.IsAdmittedOpenSigner(extra[0].GetPubKey()));
    BOOST_CHECK(!store.IsAdmittedOpenSigner(extra[1].GetPubKey()));

    const uint256 h1{TestHash(0xc6)};
    const uint256 h2{TestHash(0xc7)};
    const uint256 h3{TestHash(0xc8)};
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, h1, 81), extra[2]),
                          h1, 81) == AddResult::Heard);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, h2, 82), extra[2]),
                          h2, 82) == AddResult::Heard);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, h3, 83), extra[2]),
                          h3, 83) == AddResult::Heard);
    const uint256 h1_twin{TestHash(0xc9)};
    // Height 81 was pruned by the signed-height cap, so a second hash at
    // that height is not an equivocation.
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, h1_twin, 81), extra[2]),
                          h1_twin, 81) == AddResult::Heard);
    BOOST_CHECK(!store.IsFrozenOpenSigner(extra[2].GetPubKey()));
}

BOOST_AUTO_TEST_CASE(open_signed_entries_capped_at_one_height)
{
    const auto pin{MakeKeys(1)};
    const auto extra{MakeKeys(4)};
    const uint256 chain{TestHash(0xd0)};
    const uint256 tip{TestHash(0xd1)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.open_attestors = true;
    config.max_open_signers_per_height = 2;
    config.max_open_signed_entries = 3;
    config.max_open_signed_heights = 16;
    AttestationStore store{config};

    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, tip, 100), pin[0]),
                            tip, 100) == AddResult::Accepted);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, tip, 100), extra[0]),
                          tip, 100) == AddResult::Heard);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, tip, 100), extra[1]),
                          tip, 100) == AddResult::Heard);
    BOOST_CHECK_EQUAL(store.OpenSignedEntryCount(), 2);
    // Third distinct open signer at the same height is heard but not
    // recorded, so a later twin is not an equivocation.
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, tip, 100), extra[2]),
                          tip, 100) == AddResult::Heard);
    BOOST_CHECK_EQUAL(store.OpenSignedEntryCount(), 2);
    const uint256 twin{TestHash(0xd2)};
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, twin, 100), extra[2]),
                          twin, 100) == AddResult::Heard);
    BOOST_CHECK(!store.IsFrozenOpenSigner(extra[2].GetPubKey()));

    const uint256 h2{TestHash(0xd3)};
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, h2, 101), extra[3]),
                          h2, 101) == AddResult::Heard);
    BOOST_CHECK_LE(store.OpenSignedEntryCount(), 3);
}

BOOST_AUTO_TEST_CASE(constructor_resolves_open_directory_cap_defaults)
{
    const auto pin{MakeKeys(1)};
    auto config{MakeConfig(TestHash(0xf0), pin, /*threshold=*/1)};
    config.open_attestors = true;
    AttestationStore store{config};
    BOOST_CHECK_EQUAL(store.MaxAdmittedOpen(), DEFAULT_MAX_ADMITTED_OPEN);
    BOOST_CHECK_EQUAL(store.MaxOpenSignedHeights(),
                      DEFAULT_MAX_OPEN_SIGNED_HEIGHTS);
    BOOST_CHECK_EQUAL(store.MaxOpenSignedEntries(),
                      DEFAULT_MAX_OPEN_SIGNED_ENTRIES);
    BOOST_CHECK_EQUAL(store.MaxFrozenOpen(), DEFAULT_MAX_FROZEN_OPEN);
    BOOST_CHECK_EQUAL(store.MaxRefutations(), DEFAULT_MAX_REFUTATIONS);
    BOOST_CHECK_EQUAL(store.MaxLogLeaves(), DEFAULT_MAX_LOG_LEAVES);
    BOOST_CHECK_EQUAL(store.MaxWindowChallenges(),
                      DEFAULT_MAX_WINDOW_CHALLENGES);
    BOOST_CHECK_EQUAL(store.MaxHeardAttestations(), 4096);
}

BOOST_AUTO_TEST_CASE(open_directory_ttl_prunes_heard_and_signed_heights)
{
    const auto pin{MakeKeys(1)};
    const auto extra{MakeKeys(1)};
    const uint256 chain{TestHash(0xf1)};
    const uint256 block{TestHash(0xf2)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.open_attestors = true;
    config.ttl = 1ms;
    AttestationStore store{config};

    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, block, 7), pin[0]),
                            block, 7) == AddResult::Accepted);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, block, 7), extra[0]),
                          block, 7) == AddResult::Heard);
    BOOST_CHECK_EQUAL(store.OpenSignedHeightCount(), 1);
    BOOST_CHECK_EQUAL(store.GetStats().heard_attestations, 1);

    std::this_thread::sleep_for(5ms);
    store.PruneExpired();
    BOOST_CHECK_EQUAL(store.OpenSignedHeightCount(), 0);
    BOOST_CHECK_EQUAL(store.GetStats().heard_attestations, 0);
    BOOST_CHECK_EQUAL(store.GetStats().open_signed_heights, 0);
    // Pin authority buckets are not the open-directory DoS surface; they
    // follow the same TTL unless durable retention is on.
    BOOST_CHECK_EQUAL(store.GetAttestations(block, 7).size(), 0);
}

BOOST_AUTO_TEST_CASE(open_directory_ttl_runs_under_durable_retention)
{
    const auto pin{MakeKeys(1)};
    const auto extra{MakeKeys(1)};
    const uint256 chain{TestHash(0xf3)};
    const uint256 block{TestHash(0xf4)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.open_attestors = true;
    config.ttl = 1ms;
    AttestationStore store{config};
    store.SetDurableRetention(true);

    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, block, 8), pin[0]),
                            block, 8) == AddResult::Accepted);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, block, 8), extra[0]),
                          block, 8) == AddResult::Heard);
    std::this_thread::sleep_for(5ms);
    store.PruneExpired();
    BOOST_CHECK_EQUAL(store.GetAttestations(block, 8).size(), 1);
    BOOST_CHECK_EQUAL(store.OpenSignedHeightCount(), 0);
    BOOST_CHECK_EQUAL(store.GetStats().heard_attestations, 0);
}

BOOST_AUTO_TEST_CASE(log_leaves_and_window_challenges_are_capped)
{
    const auto keys{MakeKeys(1)};
    const uint256 chain{TestHash(0xf5)};
    auto config{MakeConfig(chain, keys, /*threshold=*/1)};
    config.max_log_leaves = 2;
    config.max_window_challenges = 1;
    AttestationStore store{config};
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, TestHash(0x01), 1),
                                     keys[0]),
                            TestHash(0x01), 1) == AddResult::Accepted);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, TestHash(0x02), 2),
                                     keys[0]),
                            TestHash(0x02), 2) == AddResult::Accepted);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, TestHash(0x03), 3),
                                     keys[0]),
                            TestHash(0x03), 3) == AddResult::Accepted);
    BOOST_CHECK_EQUAL(store.LogHead().tree_size, 2);
    BOOST_CHECK(!store.LogInclusionProof(StatementHash(
                    MakeStatement(chain, TestHash(0x01), 1))).has_value());

    store.ChallengeWindowReplay(8, TestHash(0x0a));
    store.ChallengeWindowReplay(9, TestHash(0x0b));
    const auto challenges{store.WindowReplayChallenges()};
    BOOST_REQUIRE_EQUAL(challenges.size(), 1);
    BOOST_CHECK_EQUAL(challenges[0].height, 9);
}

BOOST_AUTO_TEST_CASE(frozen_open_set_is_capped)
{
    const auto pin{MakeKeys(1)};
    const auto extra{MakeKeys(4)};
    const uint256 chain{TestHash(0xe0)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.open_attestors = true;
    config.max_frozen_open = 2;
    config.max_open_signers_per_height = 16;
    AttestationStore store{config};
    const uint256 a{TestHash(0xe1)};
    const uint256 b{TestHash(0xe2)};
    for (size_t i = 0; i < extra.size(); ++i) {
        const int32_t height{static_cast<int32_t>(210 + i)};
        BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, a, height), extra[i]),
                              a, height) == AddResult::Heard);
        BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, b, height), extra[i]),
                              b, height) == AddResult::Equivocation);
    }
    BOOST_CHECK_EQUAL(store.FrozenOpenSigners().size(), 2);
}

BOOST_AUTO_TEST_CASE(refutation_ttl_prunes_buckets)
{
    const auto pin{MakeKeys(1)};
    const uint256 chain{TestHash(0xd5)};
    const uint256 hash{TestHash(0xd6)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.ttl = 1ms;
    AttestationStore store{config};
    auto refute{SignRefutation(MakeStatement(chain, hash, 91), pin[0])};
    BOOST_REQUIRE(refute.has_value());
    BOOST_CHECK(store.AddRefutation(*refute, hash, 91) == AddResult::Accepted);
    BOOST_CHECK_EQUAL(store.GetRefutations(hash, 91).size(), 1);
    std::this_thread::sleep_for(5ms);
    store.PruneExpired();
    BOOST_CHECK(store.GetRefutations(hash, 91).empty());
    BOOST_CHECK_EQUAL(store.GetStats().refutation_buckets, 0);
}

BOOST_AUTO_TEST_CASE(refutation_rejects_declared_height_not_in_index)
{
    const auto pin{MakeKeys(1)};
    const uint256 chain{TestHash(0xe1)};
    const uint256 hash{TestHash(0xe2)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    AttestationStore store{config};
    auto refute{SignRefutation(MakeStatement(chain, hash, 40), pin[0])};
    BOOST_REQUIRE(refute.has_value());
    // Caller supplies a height that is not the statement (and would not be
    // the block-index height). Must not occupy that map key.
    BOOST_CHECK(store.AddRefutation(*refute, hash, /*expected_height=*/99) ==
                AddResult::WrongHeight);
    BOOST_CHECK(store.GetRefutations(hash, 99).empty());
    BOOST_CHECK(store.GetRefutations(hash, 40).empty());
    BOOST_CHECK(store.AddRefutation(*refute, hash, 40) == AddResult::Accepted);
    BOOST_CHECK_EQUAL(store.GetRefutations(hash, 40).size(), 1);
}

BOOST_AUTO_TEST_CASE(refutation_map_is_capped)
{
    const auto pin{MakeKeys(1)};
    const uint256 chain{TestHash(0xd4)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.max_refutations = 2;
    AttestationStore store{config};
    for (int32_t height = 90; height < 94; ++height) {
        const uint256 hash{TestHash(static_cast<uint8_t>(height))};
        auto refute{SignRefutation(MakeStatement(chain, hash, height), pin[0])};
        BOOST_REQUIRE(refute.has_value());
        BOOST_CHECK(store.AddRefutation(*refute, hash, height) ==
                    AddResult::Accepted);
    }
    const uint256 first{TestHash(90)};
    auto replay{SignRefutation(MakeStatement(chain, first, 90), pin[0])};
    BOOST_REQUIRE(replay.has_value());
    // Oldest bucket was pruned; the same signer can store that height again.
    BOOST_CHECK(store.AddRefutation(*replay, first, 90) == AddResult::Accepted);
}

BOOST_AUTO_TEST_CASE(open_local_signer_need_not_be_pinned)
{
    const auto pin{MakeKeys(1)};
    const auto local{MakeKeys(1)};
    auto config{MakeConfig(TestHash(0xc1), pin, /*threshold=*/1)};
    config.open_attestors = true;
    config.local_signer = local[0];
    AttestationStore store{config};
    BOOST_CHECK(store.LocalSignerPubKey() == local[0].GetPubKey());
    ExactReplayAttestation produced;
    BOOST_CHECK(store.SignLocal(TestHash(0xc2), 7, &produced) == AddResult::Heard);
    BOOST_CHECK(produced.signer == local[0].GetPubKey());
}

BOOST_AUTO_TEST_CASE(attestation_transparency_log_inclusion)
{
    const auto keys{MakeKeys(1)};
    const uint256 chain{TestHash(0xd1)};
    auto config{MakeConfig(chain, keys, /*threshold=*/1)};
    AttestationStore store{config};
    const auto first{MustSign(MakeStatement(chain, TestHash(0xd2), 1), keys[0])};
    const auto second{MustSign(MakeStatement(chain, TestHash(0xd3), 2), keys[0])};
    BOOST_REQUIRE(store.Add(first, TestHash(0xd2), 1) == AddResult::Accepted);
    BOOST_REQUIRE(store.Add(second, TestHash(0xd3), 2) == AddResult::Accepted);
    const auto head{store.LogHead()};
    BOOST_CHECK_EQUAL(head.tree_size, 2);
    const auto proof{store.LogInclusionProof(StatementHash(first.statement))};
    BOOST_REQUIRE(proof.has_value());
    BOOST_CHECK(VerifyAttestationLogInclusion(*proof));
    BOOST_CHECK(proof->root == head.root);
}

BOOST_AUTO_TEST_CASE(window_replay_challenge_directory)
{
    const auto keys{MakeKeys(1)};
    const uint256 chain{TestHash(0xe1)};
    const uint256 block{TestHash(0xe2)};
    auto config{MakeConfig(chain, keys, /*threshold=*/1)};
    AttestationStore store{config};
    store.ChallengeWindowReplay(8, block);
    BOOST_CHECK(!store.WindowReplayAnswered(keys[0].GetPubKey()));
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, block, 8), keys[0]),
                            block, 8) == AddResult::Accepted);
    BOOST_CHECK(store.WindowReplayAnswered(keys[0].GetPubKey()));
}

BOOST_AUTO_TEST_CASE(blocklist_rejects_pinned_votes_even_if_in_pin)
{
    const auto keys{MakeKeys(3)};
    const uint256 chain{TestHash(0xf1)};
    const uint256 block{TestHash(0xf2)};
    auto config{MakeConfig(chain, keys, /*threshold=*/2)};
    config.blocklist = {keys[0].GetPubKey()};
    AttestationStore store{config};
    BOOST_CHECK(store.IsBlocked(keys[0].GetPubKey()));
    BOOST_CHECK(!store.IsAuthoritySigner(keys[0].GetPubKey()));
    BOOST_CHECK(store.IsAuthoritySigner(keys[1].GetPubKey()));
    BOOST_CHECK_EQUAL(store.UnblockedPinMembers(), 2U);
    BOOST_CHECK(store.PinQuorumReachable());
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, block, 9), keys[0]),
                          block, 9) == AddResult::BlocklistedSigner);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, block, 9), keys[1]),
                          block, 9) == AddResult::Accepted);
    BOOST_CHECK(!store.HasQuorum(block, 9));
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, block, 9), keys[2]),
                          block, 9) == AddResult::Accepted);
    BOOST_CHECK(store.HasQuorum(block, 9));
}

BOOST_AUTO_TEST_CASE(blocklist_fail_closed_config)
{
    const auto keys{MakeKeys(2)};
    auto too_small{MakeConfig(TestHash(0xf3), keys, /*threshold=*/2)};
    too_small.blocklist = {keys[0].GetPubKey()};
    BOOST_CHECK_THROW(AttestationStore{too_small}, std::invalid_argument);

    auto both_blocked{MakeConfig(TestHash(0xf4), keys, /*threshold=*/1)};
    both_blocked.blocklist = {keys[0].GetPubKey(), keys[1].GetPubKey()};
    BOOST_CHECK_THROW(AttestationStore{both_blocked}, std::invalid_argument);

    const auto three{MakeKeys(3)};
    auto ok{MakeConfig(TestHash(0xf5), three, /*threshold=*/2)};
    ok.blocklist = {three[0].GetPubKey()};
    BOOST_CHECK_NO_THROW(AttestationStore{ok});

    auto local_blocked{MakeConfig(TestHash(0xf6), three, /*threshold=*/2)};
    local_blocked.blocklist = {three[2].GetPubKey()};
    local_blocked.local_signer = three[2];
    BOOST_CHECK_THROW(AttestationStore{local_blocked}, std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(blocklist_open_admission_and_heard_rejected)
{
    const auto pin{MakeKeys(1)};
    const auto open{MakeKeys(2)};
    const uint256 chain{TestHash(0xf7)};
    const uint256 boot{TestHash(0xf8)};
    auto config{MakeConfig(chain, pin, /*threshold=*/1)};
    config.open_attestors = true;
    config.open_threshold = 2;
    config.blocklist = {open[0].GetPubKey()};
    AttestationStore store{config};
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, boot, 40), pin[0]),
                            boot, 40) == AddResult::Accepted);
    BOOST_CHECK(store.Add(MustSign(MakeStatement(chain, boot, 40), open[0]),
                          boot, 40) == AddResult::BlocklistedSigner);
    BOOST_CHECK(store.GetHeard(boot, 40).empty());
    BOOST_CHECK(!store.IsAdmittedOpenSigner(open[0].GetPubKey()));
    store.AdmitOpenSigner(open[0].GetPubKey());
    BOOST_CHECK(!store.IsAdmittedOpenSigner(open[0].GetPubKey()));
    std::set<CPubKey> admitted{open[0].GetPubKey(), open[1].GetPubKey()};
    store.RestoreOpenAttestors(admitted, {});
    BOOST_CHECK(!store.IsAdmittedOpenSigner(open[0].GetPubKey()));
    BOOST_CHECK(store.IsAdmittedOpenSigner(open[1].GetPubKey()));
}

BOOST_AUTO_TEST_CASE(blocklist_runtime_add_fail_closed_and_open_quorum)
{
    const auto pin{MakeKeys(2)};
    const auto open{MakeKeys(1)};
    const uint256 chain{TestHash(0xf9)};
    const uint256 boot{TestHash(0xfa)};
    auto config{MakeConfig(chain, pin, /*threshold=*/2)};
    config.open_attestors = true;
    config.open_threshold = 3;
    AttestationStore store{config};
    BOOST_CHECK(store.AddBlocklistedSigner(pin[0].GetPubKey()) ==
                BlocklistResult::WouldDisablePinQuorum);
    BOOST_CHECK(!store.IsBlocked(pin[0].GetPubKey()));
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, boot, 50), pin[0]),
                            boot, 50) == AddResult::Accepted);
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, boot, 50), pin[1]),
                            boot, 50) == AddResult::Accepted);
    BOOST_CHECK(store.HasQuorum(boot, 50));
    BOOST_REQUIRE(store.Add(MustSign(MakeStatement(chain, boot, 50), open[0]),
                            boot, 50) == AddResult::Heard);
    BOOST_CHECK(store.IsAdmittedOpenSigner(open[0].GetPubKey()));
    BOOST_CHECK(store.HasOpenQuorum(boot, 50));
    BOOST_CHECK(store.AddBlocklistedSigner(open[0].GetPubKey()) ==
                BlocklistResult::Blocked);
    BOOST_CHECK(!store.IsAdmittedOpenSigner(open[0].GetPubKey()));
    BOOST_CHECK(!store.HasOpenQuorum(boot, 50));
    BOOST_CHECK(store.GetHeard(boot, 50).empty());
    BOOST_CHECK(store.AddBlocklistedSigner(open[0].GetPubKey()) ==
                BlocklistResult::Duplicate);
}

BOOST_AUTO_TEST_CASE(blocklist_durable_miss_and_refute_and_local)
{
    const auto keys{MakeKeys(3)};
    const uint256 chain{TestHash(0xfb)};
    const uint256 block{TestHash(0xfc)};
    auto config{MakeConfig(chain, keys, /*threshold=*/2)};
    config.blocklist = {keys[0].GetPubKey()};
    config.local_signer = keys[1];
    AttestationStore store{config};
    const auto blocked_att{
        MustSign(MakeStatement(chain, block, 60), keys[0])};
    const auto honest_att{
        MustSign(MakeStatement(chain, block, 60), keys[1])};
    BOOST_CHECK(!store.HasQuorumFromAttestations(
        {blocked_att, honest_att}, block, 60));
    const auto second{
        MustSign(MakeStatement(chain, block, 60), keys[2])};
    BOOST_CHECK(store.HasQuorumFromAttestations(
        {blocked_att, honest_att, second}, block, 60));

    auto refute{SignRefutation(MakeStatement(chain, block, 60), keys[0])};
    BOOST_REQUIRE(refute.has_value());
    BOOST_CHECK(store.AddRefutation(*refute, block, 60) ==
                AddResult::BlocklistedSigner);

    BOOST_CHECK(store.SignLocal(block, 60) == AddResult::Accepted);
    auto blocked_local{MakeConfig(chain, keys, /*threshold=*/2)};
    blocked_local.local_signer = keys[1];
    AttestationStore live{blocked_local};
    BOOST_CHECK(live.AddBlocklistedSigner(keys[1].GetPubKey()) ==
                BlocklistResult::LocalSigner);
    BOOST_CHECK(!live.IsBlocked(keys[1].GetPubKey()));
}

BOOST_AUTO_TEST_SUITE_END()
