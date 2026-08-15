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

BOOST_AUTO_TEST_SUITE_END()
