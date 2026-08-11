// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/trusted_utxo_snapshot_attestation.h>

#include <streams.h>
#include <test/util/setup_common.h>

#include <vector>

#include <boost/test/unit_test.hpp>

namespace {

using namespace matmul::trusted;

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

UtxoSnapshotStatement MakeStatement(const uint256& chain,
                                    const uint256& block,
                                    int32_t height)
{
    UtxoSnapshotStatement statement;
    statement.chain_id = chain;
    statement.block_hash = block;
    statement.block_height = height;
    statement.hash_serialized = TestHash(0x33);
    statement.coins_count = 42;
    statement.m_chain_tx_count = 99;
    statement.shielded_state_commitment = TestHash(0x44);
    statement.replay_authority_context = TestHash(0x55);
    return statement;
}

UtxoSnapshotSignature MustSign(const UtxoSnapshotStatement& statement,
                               const CKey& key)
{
    auto attestation{SignUtxoSnapshotStatement(statement, key)};
    BOOST_REQUIRE(attestation.has_value());
    return *attestation;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(trusted_utxo_snapshot_attestation_tests,
                         BasicTestingSetup)

BOOST_AUTO_TEST_CASE(statement_signature_and_quorum)
{
    const auto keys{MakeKeys(3)};
    const uint256 chain{TestHash(0x11)};
    const uint256 block{TestHash(0x22)};
    const auto statement{MakeStatement(chain, block, 185001)};
    const std::set<CPubKey> trusted{
        keys[0].GetPubKey(), keys[1].GetPubKey(), keys[2].GetPubKey()};

    UtxoSnapshotManifest manifest;
    manifest.statement = statement;
    manifest.signatures.push_back(MustSign(statement, keys[0]));
    manifest.signatures.push_back(MustSign(statement, keys[1]));

    BOOST_CHECK_EQUAL(
        UtxoSnapshotVerifyResultName(VerifyUtxoSnapshotManifestSelfConsistent(
            manifest, chain, statement.replay_authority_context, trusted,
            /*threshold=*/2)),
        "valid");

    BOOST_CHECK(VerifyUtxoSnapshotManifestSelfConsistent(
                    manifest, chain, statement.replay_authority_context,
                    trusted, /*threshold=*/3) ==
                UtxoSnapshotVerifyResult::ThresholdNotMet);

    DataStream stream;
    stream << manifest;
    UtxoSnapshotManifest decoded;
    stream >> decoded;
    BOOST_CHECK(decoded == manifest);
    BOOST_CHECK(UtxoSnapshotStatementHash(decoded.statement) ==
                UtxoSnapshotStatementHash(statement));
}

BOOST_AUTO_TEST_CASE(reject_wrong_fields_duplicates_and_untrusted)
{
    const auto keys{MakeKeys(3)};
    const uint256 chain{TestHash(0x11)};
    const uint256 block{TestHash(0x22)};
    const auto statement{MakeStatement(chain, block, 185001)};
    const std::set<CPubKey> trusted{
        keys[0].GetPubKey(), keys[1].GetPubKey()};

    UtxoSnapshotManifest manifest;
    manifest.statement = statement;
    manifest.signatures.push_back(MustSign(statement, keys[0]));

    BOOST_CHECK(VerifyUtxoSnapshotManifestSelfConsistent(
                    manifest, TestHash(0x12),
                    statement.replay_authority_context, trusted, 1) ==
                UtxoSnapshotVerifyResult::WrongChain);
    BOOST_CHECK(VerifyUtxoSnapshotManifest(
                    manifest, chain, statement.replay_authority_context,
                    TestHash(0x23), statement.block_height,
                    statement.hash_serialized, statement.coins_count,
                    statement.m_chain_tx_count,
                    statement.shielded_state_commitment, trusted, 1) ==
                UtxoSnapshotVerifyResult::WrongBlock);
    BOOST_CHECK(VerifyUtxoSnapshotManifest(
                    manifest, chain, statement.replay_authority_context,
                    statement.block_hash, statement.block_height + 1,
                    statement.hash_serialized, statement.coins_count,
                    statement.m_chain_tx_count,
                    statement.shielded_state_commitment, trusted, 1) ==
                UtxoSnapshotVerifyResult::WrongHeight);
    BOOST_CHECK(VerifyUtxoSnapshotManifest(
                    manifest, chain, statement.replay_authority_context,
                    statement.block_hash, statement.block_height,
                    TestHash(0x34), statement.coins_count,
                    statement.m_chain_tx_count,
                    statement.shielded_state_commitment, trusted, 1) ==
                UtxoSnapshotVerifyResult::WrongHashSerialized);
    BOOST_CHECK(VerifyUtxoSnapshotManifest(
                    manifest, chain, statement.replay_authority_context,
                    statement.block_hash, statement.block_height,
                    statement.hash_serialized, statement.coins_count + 1,
                    statement.m_chain_tx_count,
                    statement.shielded_state_commitment, trusted, 1) ==
                UtxoSnapshotVerifyResult::WrongCoinsCount);
    BOOST_CHECK(VerifyUtxoSnapshotManifest(
                    manifest, chain, statement.replay_authority_context,
                    statement.block_hash, statement.block_height,
                    statement.hash_serialized, statement.coins_count,
                    statement.m_chain_tx_count + 1,
                    statement.shielded_state_commitment, trusted, 1) ==
                UtxoSnapshotVerifyResult::WrongChainTxCount);
    BOOST_CHECK(VerifyUtxoSnapshotManifest(
                    manifest, chain, statement.replay_authority_context,
                    statement.block_hash, statement.block_height,
                    statement.hash_serialized, statement.coins_count,
                    statement.m_chain_tx_count, uint256{}, trusted, 1) ==
                UtxoSnapshotVerifyResult::MissingShieldedCommitment);
    BOOST_CHECK(VerifyUtxoSnapshotManifest(
                    manifest, chain, statement.replay_authority_context,
                    statement.block_hash, statement.block_height,
                    statement.hash_serialized, statement.coins_count,
                    statement.m_chain_tx_count, TestHash(0x45), trusted, 1) ==
                UtxoSnapshotVerifyResult::WrongShieldedCommitment);
    BOOST_CHECK(VerifyUtxoSnapshotManifestSelfConsistent(
                    manifest, chain, TestHash(0x56), trusted, 1) ==
                UtxoSnapshotVerifyResult::WrongReplayAuthorityContext);

    auto dup{manifest};
    dup.signatures.push_back(MustSign(statement, keys[0]));
    BOOST_CHECK(VerifyUtxoSnapshotManifestSelfConsistent(
                    dup, chain, statement.replay_authority_context, trusted,
                    1) == UtxoSnapshotVerifyResult::DuplicateSigner);

    auto untrusted{manifest};
    untrusted.signatures = {MustSign(statement, keys[2])};
    BOOST_CHECK(VerifyUtxoSnapshotManifestSelfConsistent(
                    untrusted, chain, statement.replay_authority_context,
                    trusted, 1) ==
                UtxoSnapshotVerifyResult::UntrustedSigner);

    auto bad_sig{manifest};
    bad_sig.signatures[0].signature.back() ^= 0x01;
    BOOST_CHECK(VerifyUtxoSnapshotManifestSelfConsistent(
                    bad_sig, chain, statement.replay_authority_context, trusted,
                    1) == UtxoSnapshotVerifyResult::InvalidSignature);

    UtxoSnapshotManifest empty;
    empty.statement = statement;
    BOOST_CHECK(VerifyUtxoSnapshotManifestSelfConsistent(
                    empty, chain, statement.replay_authority_context, trusted,
                    1) == UtxoSnapshotVerifyResult::EmptyManifest);
}

BOOST_AUTO_TEST_CASE(consensus_style_refuse_without_signer_set)
{
    // A strict consensus node has no trusted signer set; the verify path must
    // never treat an empty set + threshold 0 as acceptance.
    const auto keys{MakeKeys(1)};
    const uint256 chain{TestHash(0x11)};
    const auto statement{MakeStatement(chain, TestHash(0x22), 10)};
    UtxoSnapshotManifest manifest;
    manifest.statement = statement;
    manifest.signatures.push_back(MustSign(statement, keys[0]));

    BOOST_CHECK(VerifyUtxoSnapshotManifestSelfConsistent(
                    manifest, chain, statement.replay_authority_context,
                    /*trusted_signers=*/{}, /*threshold=*/0) ==
                UtxoSnapshotVerifyResult::ThresholdNotMet);
    BOOST_CHECK(VerifyUtxoSnapshotManifestSelfConsistent(
                    manifest, chain, statement.replay_authority_context,
                    /*trusted_signers=*/{}, /*threshold=*/1) ==
                UtxoSnapshotVerifyResult::ThresholdNotMet);
}

BOOST_AUTO_TEST_SUITE_END()
