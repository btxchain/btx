// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// A signer withdraws its own vote for a block it disconnects. The withdrawal
// must not come back through the durable fallbacks of HasQuorum() and Get().

#include <key.h>
#include <matmul/trusted_exact_replay_attestation.h>
#include <node/matmul_trusted_attestations.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <util/fs.h>

extern "C" {
#include <libbitcoinpqc/ml_dsa.h>
}

#include <boost/test/unit_test.hpp>

#include <chrono>
#include <string>
#include <vector>

namespace {

CKey WithdrawNewKey()
{
    CKey key;
    key.MakeNewKey(/*fCompressed=*/true);
    return key;
}

uint256 WithdrawHex256(char digit)
{
    return uint256::FromHex(std::string(64, digit)).value();
}

struct WithdrawReset {
    ~WithdrawReset() { node::matmul_trusted::ResetForTest(); }
};

//! Signing node: local key plus one peer pin, M=2, durable archive.
struct WithdrawSignerNode {
    CKey local{WithdrawNewKey()};
    CKey peer{WithdrawNewKey()};
    uint256 chain{WithdrawHex256('8')};
    uint256 context{WithdrawHex256('9')};
    fs::path archive;

    explicit WithdrawSignerNode(fs::path path) : archive{std::move(path)} {}

    void Start() const
    {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = context;
        config.trusted_signers = {local.GetPubKey(), peer.GetPubKey()};
        config.threshold = 2;
        config.local_signer = local;
        std::string error;
        BOOST_REQUIRE_MESSAGE(node::matmul_trusted::Configure(
                                  std::move(config), /*trusted_mirror=*/false,
                                  /*serve=*/true, std::chrono::milliseconds{20}, error),
                              error);
        BOOST_REQUIRE_MESSAGE(node::matmul_trusted::OpenPersistence(archive, error), error);
    }
    void Flush() const
    {
        std::string error;
        BOOST_REQUIRE_MESSAGE(node::matmul_trusted::FlushPersistence(error), error);
    }
    //! Flush, drop all in-memory state, configure and load again.
    void Restart() const
    {
        Flush();
        node::matmul_trusted::ResetForTest();
        Start();
    }
    void AddSigned(const CKey& key, const uint256& hash, int32_t height) const
    {
        matmul::trusted::ExactReplayStatement statement;
        statement.chain_id = chain;
        statement.block_hash = hash;
        statement.block_height = height;
        statement.replay_authority_context = context;
        const auto att{matmul::trusted::SignStatement(statement, key)};
        BOOST_REQUIRE(att.has_value());
        BOOST_REQUIRE(node::matmul_trusted::Add(*att, hash, height) ==
                      matmul::trusted::AddResult::Accepted);
    }
    void PeerSign(const uint256& hash, int32_t height) const { AddSigned(peer, hash, height); }
    //! A copy of the local key's vote arriving over P2P, not signed by this node.
    void RelayLocal(const uint256& hash, int32_t height) const { AddSigned(local, hash, height); }
    //! Local vote plus the peer: a quorum that needs the local vote.
    void SignQuorum(const uint256& hash, int32_t height) const
    {
        BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(hash, height) ==
                      matmul::trusted::AddResult::Accepted);
        PeerSign(hash, height);
        BOOST_REQUIRE(node::matmul_trusted::HasQuorumInMemory(hash, height));
    }
    //! What a GETMMATTEST answer for (hash, height) would carry.
    bool ServesLocalVote(const uint256& hash, int32_t height) const
    {
        for (const auto& att : node::matmul_trusted::Get(hash, height)) {
            if (att.signer == local.GetPubKey()) return true;
        }
        return false;
    }
};

struct WithdrawPqKey {
    std::vector<unsigned char> pk;
    std::vector<unsigned char> sk;
};

WithdrawPqKey WithdrawMakePqKey(unsigned char seed_byte)
{
    WithdrawPqKey key{
        .pk = std::vector<unsigned char>(matmul::trusted::EXACT_REPLAY_ML_DSA_44_PK),
        .sk = std::vector<unsigned char>(matmul::trusted::EXACT_REPLAY_ML_DSA_44_SK),
    };
    const std::vector<unsigned char> seed(128, seed_byte);
    BOOST_REQUIRE_EQUAL(ml_dsa_44_keygen(key.pk.data(), key.sk.data(), seed.data(), seed.size()), 0);
    return key;
}

//! ML-DSA-44 signing node: local PQ key plus one PQ peer pin, M=2, durable archive.
struct WithdrawPqSignerNode {
    WithdrawPqKey local{WithdrawMakePqKey(0x41)};
    WithdrawPqKey peer{WithdrawMakePqKey(0x42)};
    uint256 chain{WithdrawHex256('8')};
    uint256 context{WithdrawHex256('9')};
    fs::path archive;

    explicit WithdrawPqSignerNode(fs::path path) : archive{std::move(path)} {}

    void Start() const
    {
        matmul::trusted::StoreConfig config;
        config.chain_id = chain;
        config.replay_authority_context = context;
        config.trusted_pq_signers = {local.pk, peer.pk};
        config.threshold = 2;
        config.local_pq_pk = local.pk;
        config.local_pq_sk = local.sk;
        std::string error;
        BOOST_REQUIRE_MESSAGE(node::matmul_trusted::Configure(
                                  std::move(config), /*trusted_mirror=*/false,
                                  /*serve=*/true, std::chrono::milliseconds{20}, error),
                              error);
        BOOST_REQUIRE_MESSAGE(node::matmul_trusted::OpenPersistence(archive, error), error);
    }
    void Flush() const
    {
        std::string error;
        BOOST_REQUIRE_MESSAGE(node::matmul_trusted::FlushPersistence(error), error);
    }
    void Restart() const
    {
        Flush();
        node::matmul_trusted::ResetForTest();
        Start();
    }
    //! Local PQ vote plus the PQ peer: a quorum that needs the local vote.
    void SignQuorum(const uint256& hash, int32_t height) const
    {
        BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(hash, height) ==
                      matmul::trusted::AddResult::Accepted);
        PeerSign(hash, height);
        BOOST_REQUIRE(node::matmul_trusted::HasQuorumInMemory(hash, height));
    }
    void PeerSign(const uint256& hash, int32_t height) const
    {
        matmul::trusted::ExactReplayStatement statement;
        statement.chain_id = chain;
        statement.block_hash = hash;
        statement.block_height = height;
        statement.replay_authority_context = context;
        const auto att{matmul::trusted::SignStatementMlDsa44(statement, peer.sk, peer.pk)};
        BOOST_REQUIRE(att.has_value());
        BOOST_REQUIRE(node::matmul_trusted::AddPq(*att, hash, height) ==
                      matmul::trusted::AddResult::Accepted);
    }
    //! What a GETMMATTEST answer for (hash, height) would carry on the PQ side.
    bool ServesLocalPqVote(const uint256& hash, int32_t height) const
    {
        for (const auto& att : node::matmul_trusted::GetPq(hash, height)) {
            if (att.signer == local.pk) return true;
        }
        return false;
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_trusted_withdraw_tests, BasicTestingSetup)

// Within one process the disconnect withdraws the local vote.
BOOST_AUTO_TEST_CASE(live_withdrawal_drops_local_vote)
{
    WithdrawReset reset;
    const WithdrawSignerNode node{m_args.GetDataDirNet() / "withdraw_live.dat"};
    const uint256 abandoned{WithdrawHex256('b')};
    node.Start();
    node.SignQuorum(abandoned, 30);
    BOOST_REQUIRE(node::matmul_trusted::NotifyActiveChainBlockDisconnected(30, abandoned));
    BOOST_CHECK(!node::matmul_trusted::HasQuorumInMemory(abandoned, 30));
}

// Live withdrawal, then the durable fallbacks.
BOOST_AUTO_TEST_CASE(withdrawn_vote_not_counted_or_served_from_durable)
{
    WithdrawReset reset;
    const WithdrawSignerNode node{m_args.GetDataDirNet() / "withdraw_durable.dat"};
    const uint256 abandoned{WithdrawHex256('b')};
    node.Start();
    node.SignQuorum(abandoned, 30);
    node.Flush(); // the local vote is now in the durable LevelDB record
    BOOST_REQUIRE(node.ServesLocalVote(abandoned, 30));

    BOOST_REQUIRE(node::matmul_trusted::NotifyActiveChainBlockDisconnected(30, abandoned));
    BOOST_REQUIRE(!node::matmul_trusted::HasQuorumInMemory(abandoned, 30));
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorum(abandoned, 30),
                        "HasQuorum's durable fallback counts the withdrawn local vote");
    BOOST_CHECK_MESSAGE(!node.ServesLocalVote(abandoned, 30),
                        "Get() (GETMMATTEST answer) returns the withdrawn local vote from disk");
}

// The same for a withdrawn local ML-DSA-44 vote.
BOOST_AUTO_TEST_CASE(withdrawn_pq_vote_not_counted_or_served_from_durable)
{
    WithdrawReset reset;
    const WithdrawPqSignerNode node{m_args.GetDataDirNet() / "withdraw_pq_durable.dat"};
    const uint256 abandoned{WithdrawHex256('b')};
    node.Start();
    node.SignQuorum(abandoned, 30);
    node.Flush(); // the local PQ vote is now in the durable LevelDB record
    BOOST_REQUIRE(node.ServesLocalPqVote(abandoned, 30));

    BOOST_REQUIRE(node::matmul_trusted::NotifyActiveChainBlockDisconnected(30, abandoned));
    BOOST_REQUIRE(!node::matmul_trusted::HasQuorumInMemory(abandoned, 30));
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorum(abandoned, 30),
                        "HasQuorum's durable fallback counts the withdrawn local PQ vote");
    BOOST_CHECK_MESSAGE(!node.ServesLocalPqVote(abandoned, 30),
                        "GetPq() returns the withdrawn local PQ vote from disk");

    // After a reload the withdrawn vote stays out of memory and out of the answers.
    node.Flush();
    node::matmul_trusted::ResetForTest();
    node.Start();
    BOOST_CHECK(!node::matmul_trusted::HasQuorumInMemory(abandoned, 30));
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorum(abandoned, 30),
                        "after a reload HasQuorum counts the withdrawn local PQ vote");
    BOOST_CHECK_MESSAGE(!node.ServesLocalPqVote(abandoned, 30),
                        "after a reload GetPq() returns the withdrawn local PQ vote");
}

// After a restart the store has the mint slot again, so the node's own reorg
// still withdraws the local vote and no second quorum with it forms at the
// same height.
BOOST_AUTO_TEST_CASE(withdrawal_after_restart_drops_local_vote)
{
    WithdrawReset reset;
    const WithdrawSignerNode node{m_args.GetDataDirNet() / "withdraw_restart.dat"};
    const uint256 abandoned{WithdrawHex256('b')};
    const uint256 replacement{WithdrawHex256('c')};
    node.Start();
    node.SignQuorum(abandoned, 30);
    node.Restart();
    BOOST_REQUIRE(node::matmul_trusted::HasQuorumInMemory(abandoned, 30));

    BOOST_REQUIRE(node::matmul_trusted::NotifyActiveChainBlockDisconnected(30, abandoned));
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorumInMemory(abandoned, 30),
                        "after a restart the disconnect leaves the withdrawn local vote live");

    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(replacement, 30) ==
                  matmul::trusted::AddResult::Accepted);
    node.PeerSign(replacement, 30);
    BOOST_REQUIRE(node::matmul_trusted::HasQuorumInMemory(replacement, 30));
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorumInMemory(abandoned, 30),
                        "two in-memory quorums carrying the local vote at one height");
}

// A relayed copy of the local key's vote is not the node's own vote. It does
// not take the mint slot in one process, and must not take it from disk
// after a restart either, so the node's reorg does not withdraw it.
BOOST_AUTO_TEST_CASE(relayed_local_key_vote_does_not_take_slot_after_restart)
{
    WithdrawReset reset;
    const WithdrawSignerNode node{m_args.GetDataDirNet() / "withdraw_relayed.dat"};
    const uint256 relayed{WithdrawHex256('d')};
    node.Start();
    node.RelayLocal(relayed, 31);
    node.PeerSign(relayed, 31);
    BOOST_REQUIRE(node::matmul_trusted::HasQuorumInMemory(relayed, 31));
    node.Restart();
    BOOST_REQUIRE(node::matmul_trusted::HasQuorumInMemory(relayed, 31));

    node::matmul_trusted::NotifyActiveChainBlockDisconnected(31, relayed);
    BOOST_CHECK_MESSAGE(node::matmul_trusted::HasQuorumInMemory(relayed, 31),
                        "after a restart a relayed copy of the local key took the mint slot");
}

// A vote the node withdrew before the restart does not bring its slot back,
// so the node can sign the hash it now follows.
BOOST_AUTO_TEST_CASE(withdrawn_vote_does_not_take_slot_after_restart)
{
    WithdrawReset reset;
    const WithdrawSignerNode node{m_args.GetDataDirNet() / "withdraw_tombstoned.dat"};
    const uint256 abandoned{WithdrawHex256('b')};
    const uint256 replacement{WithdrawHex256('c')};
    node.Start();
    node.SignQuorum(abandoned, 32);
    BOOST_REQUIRE(node::matmul_trusted::NotifyActiveChainBlockDisconnected(32, abandoned));
    node.Restart();
    BOOST_CHECK_MESSAGE(node::matmul_trusted::SignAuthoritative(replacement, 32) ==
                            matmul::trusted::AddResult::Accepted,
                        "after a restart the withdrawn vote holds the mint slot");
}

// A slot the operator cleared (clearmintedattestations) stays cleared.
BOOST_AUTO_TEST_CASE(cleared_slot_stays_cleared_after_restart)
{
    WithdrawReset reset;
    const WithdrawSignerNode node{m_args.GetDataDirNet() / "withdraw_cleared.dat"};
    node.Start();
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(WithdrawHex256('b'), 33) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE_EQUAL(node::matmul_trusted::ClearMintedAttestations(33, 33), 1U);
    node.Restart();
    BOOST_CHECK_MESSAGE(node::matmul_trusted::SignAuthoritative(WithdrawHex256('c'), 33) ==
                            matmul::trusted::AddResult::Accepted,
                        "after a restart the cleared mint slot is back");
}

// The restart case for the local ML-DSA-44 key.
BOOST_AUTO_TEST_CASE(pq_withdrawal_after_restart_drops_local_vote)
{
    WithdrawReset reset;
    const WithdrawPqSignerNode node{m_args.GetDataDirNet() / "withdraw_pq_restart.dat"};
    const uint256 abandoned{WithdrawHex256('b')};
    const uint256 replacement{WithdrawHex256('c')};
    node.Start();
    node.SignQuorum(abandoned, 30);
    node.Restart();
    BOOST_REQUIRE(node::matmul_trusted::HasQuorumInMemory(abandoned, 30));

    BOOST_REQUIRE(node::matmul_trusted::NotifyActiveChainBlockDisconnected(30, abandoned));
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorumInMemory(abandoned, 30),
                        "after a restart the disconnect leaves the withdrawn local PQ vote live");

    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(replacement, 30) ==
                  matmul::trusted::AddResult::Accepted);
    node.PeerSign(replacement, 30);
    BOOST_REQUIRE(node::matmul_trusted::HasQuorumInMemory(replacement, 30));
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorumInMemory(abandoned, 30),
                        "two in-memory quorums carrying the local PQ vote at one height");
}

// A reconnect brings the withdrawn vote back on disk without a new
// signature, so it must also give the slot back: a later disconnect has to
// withdraw the vote again, before and after a restart.
BOOST_AUTO_TEST_CASE(reconnect_gives_slot_back_for_second_withdrawal)
{
    WithdrawReset reset;
    const WithdrawSignerNode node{m_args.GetDataDirNet() / "withdraw_reconnect_twice.dat"};
    const uint256 abandoned{WithdrawHex256('b')};
    const uint256 replacement{WithdrawHex256('c')};
    node.Start();
    node.SignQuorum(abandoned, 34);
    BOOST_REQUIRE(node::matmul_trusted::NotifyActiveChainBlockDisconnected(34, abandoned));
    node::matmul_trusted::NotifyActiveChainBlockConnected(34, abandoned);

    (void)node::matmul_trusted::NotifyActiveChainBlockDisconnected(34, abandoned);
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(replacement, 34) ==
                  matmul::trusted::AddResult::Accepted);
    node.PeerSign(replacement, 34);
    node.Restart();
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorumInMemory(abandoned, 34),
                        "after reconnect, disconnect and restart the withdrawn local vote is live");
    BOOST_CHECK_MESSAGE(!node.ServesLocalVote(abandoned, 34),
                        "after reconnect, disconnect and restart Get() serves the withdrawn local vote");
    BOOST_CHECK(node::matmul_trusted::HasQuorumInMemory(replacement, 34));
}

BOOST_AUTO_TEST_CASE(reconnect_then_restart_still_withdraws)
{
    WithdrawReset reset;
    const WithdrawSignerNode node{m_args.GetDataDirNet() / "withdraw_reconnect_restart.dat"};
    const uint256 abandoned{WithdrawHex256('b')};
    const uint256 replacement{WithdrawHex256('c')};
    node.Start();
    node.SignQuorum(abandoned, 35);
    BOOST_REQUIRE(node::matmul_trusted::NotifyActiveChainBlockDisconnected(35, abandoned));
    node::matmul_trusted::NotifyActiveChainBlockConnected(35, abandoned);
    node.Restart();
    BOOST_REQUIRE(node::matmul_trusted::HasQuorumInMemory(abandoned, 35));

    (void)node::matmul_trusted::NotifyActiveChainBlockDisconnected(35, abandoned);
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorumInMemory(abandoned, 35),
                        "after reconnect and restart the disconnect leaves the local vote live");
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(replacement, 35) ==
                  matmul::trusted::AddResult::Accepted);
    node.PeerSign(replacement, 35);
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorumInMemory(abandoned, 35),
                        "two in-memory quorums carrying the local vote at one height");
}

// Only a tombstone written with the slot release gives the slot back. A
// relayed copy of the local key's vote must not get it from a reconnect
// either.
BOOST_AUTO_TEST_CASE(relayed_local_key_vote_does_not_take_slot_on_reconnect)
{
    WithdrawReset reset;
    const WithdrawSignerNode node{m_args.GetDataDirNet() / "withdraw_relayed_reconnect.dat"};
    const uint256 relayed{WithdrawHex256('d')};
    node.Start();
    node.RelayLocal(relayed, 37);
    node.PeerSign(relayed, 37);
    node.Restart();
    BOOST_REQUIRE(node::matmul_trusted::HasQuorumInMemory(relayed, 37));
    (void)node::matmul_trusted::NotifyActiveChainBlockDisconnected(37, relayed);
    node::matmul_trusted::NotifyActiveChainBlockConnected(37, relayed);

    (void)node::matmul_trusted::NotifyActiveChainBlockDisconnected(37, relayed);
    BOOST_CHECK_MESSAGE(node::matmul_trusted::HasQuorumInMemory(relayed, 37),
                        "a reconnect gave the mint slot to a relayed copy of the local key");
}

// The two reconnect cases for the local ML-DSA-44 key.
BOOST_AUTO_TEST_CASE(pq_reconnect_gives_slot_back_for_second_withdrawal)
{
    WithdrawReset reset;
    const WithdrawPqSignerNode node{m_args.GetDataDirNet() / "withdraw_pq_reconnect_twice.dat"};
    const uint256 abandoned{WithdrawHex256('b')};
    const uint256 replacement{WithdrawHex256('c')};
    node.Start();
    node.SignQuorum(abandoned, 34);
    BOOST_REQUIRE(node::matmul_trusted::NotifyActiveChainBlockDisconnected(34, abandoned));
    node::matmul_trusted::NotifyActiveChainBlockConnected(34, abandoned);

    (void)node::matmul_trusted::NotifyActiveChainBlockDisconnected(34, abandoned);
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(replacement, 34) ==
                  matmul::trusted::AddResult::Accepted);
    node.PeerSign(replacement, 34);
    node.Restart();
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorumInMemory(abandoned, 34),
                        "after reconnect, disconnect and restart the withdrawn local PQ vote is live");
    BOOST_CHECK_MESSAGE(!node.ServesLocalPqVote(abandoned, 34),
                        "after reconnect, disconnect and restart GetPq() serves the withdrawn local PQ vote");
    BOOST_CHECK(node::matmul_trusted::HasQuorumInMemory(replacement, 34));
}

BOOST_AUTO_TEST_CASE(pq_reconnect_then_restart_still_withdraws)
{
    WithdrawReset reset;
    const WithdrawPqSignerNode node{m_args.GetDataDirNet() / "withdraw_pq_reconnect_restart.dat"};
    const uint256 abandoned{WithdrawHex256('b')};
    const uint256 replacement{WithdrawHex256('c')};
    node.Start();
    node.SignQuorum(abandoned, 35);
    BOOST_REQUIRE(node::matmul_trusted::NotifyActiveChainBlockDisconnected(35, abandoned));
    node::matmul_trusted::NotifyActiveChainBlockConnected(35, abandoned);
    node.Restart();
    BOOST_REQUIRE(node::matmul_trusted::HasQuorumInMemory(abandoned, 35));

    (void)node::matmul_trusted::NotifyActiveChainBlockDisconnected(35, abandoned);
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorumInMemory(abandoned, 35),
                        "after reconnect and restart the disconnect leaves the local PQ vote live");
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(replacement, 35) ==
                  matmul::trusted::AddResult::Accepted);
    node.PeerSign(replacement, 35);
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorumInMemory(abandoned, 35),
                        "two in-memory quorums carrying the local PQ vote at one height");
    // Without a tombstone from that disconnect both quorums would come back.
    node.Restart();
    BOOST_CHECK_MESSAGE(!node::matmul_trusted::HasQuorumInMemory(abandoned, 35),
                        "after the next restart the withdrawn local PQ vote is live again");
    BOOST_CHECK(node::matmul_trusted::HasQuorumInMemory(replacement, 35));
}

// After a restart the wrapper knows every height this node signed, as
// without a restart, also for a PQ vote that has no quorum yet.
BOOST_AUTO_TEST_CASE(pq_local_signature_at_height_known_after_restart)
{
    WithdrawReset reset;
    const WithdrawPqSignerNode node{m_args.GetDataDirNet() / "withdraw_pq_signed_height.dat"};
    node.Start();
    BOOST_REQUIRE(node::matmul_trusted::SignAuthoritative(WithdrawHex256('b'), 36) ==
                  matmul::trusted::AddResult::Accepted);
    BOOST_REQUIRE(node::matmul_trusted::HasLocalSignatureAtHeight(WithdrawHex256('c'), 36));
    node.Restart();
    BOOST_CHECK_MESSAGE(node::matmul_trusted::HasLocalSignatureAtHeight(WithdrawHex256('c'), 36),
                        "after a restart the wrapper forgot the local PQ signature at this height");
}

BOOST_AUTO_TEST_SUITE_END()
