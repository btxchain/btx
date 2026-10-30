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
    void PeerSign(const uint256& hash, int32_t height) const
    {
        matmul::trusted::ExactReplayStatement statement;
        statement.chain_id = chain;
        statement.block_hash = hash;
        statement.block_height = height;
        statement.replay_authority_context = context;
        const auto att{matmul::trusted::SignStatement(statement, peer)};
        BOOST_REQUIRE(att.has_value());
        BOOST_REQUIRE(node::matmul_trusted::Add(*att, hash, height) ==
                      matmul::trusted::AddResult::Accepted);
    }
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

    // The vote stays on disk and the filter hides it, so a reconnect brings it back.
    node::matmul_trusted::NotifyActiveChainBlockConnected(30, abandoned);
    BOOST_CHECK(node::matmul_trusted::HasQuorum(abandoned, 30));
    BOOST_CHECK(node.ServesLocalVote(abandoned, 30));
}

BOOST_AUTO_TEST_SUITE_END()
