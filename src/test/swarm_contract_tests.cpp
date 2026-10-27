// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_funding_class.h>
#include <modelnet/swarm_raftlog.h>
#include <modelnet/swarm_timescale.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <unistd.h>

BOOST_FIXTURE_TEST_SUITE(swarm_contract_tests, BasicTestingSetup)

namespace {

fs::path Scratch(const char* name)
{
    fs::path path = fs::temp_directory_path();
    path /= fs::u8path(std::string(name) + "-" + std::to_string(::getpid()));
    fs::remove_all(path);
    fs::create_directories(path);
    return path;
}

} // namespace

BOOST_AUTO_TEST_CASE(funding_classes_stay_distinct)
{
    std::string err;
    modelnet::SwarmMoneyPosition position;
    BOOST_REQUIRE(modelnet::SwarmClassifyMoney("promise", 10, position, err));
    BOOST_CHECK(!position.counts_as_balance);
    BOOST_CHECK(!position.immediately_payable);
    BOOST_REQUIRE(modelnet::SwarmClassifyMoney("observed_utxo", 10, position, err));
    BOOST_CHECK(position.confirmed_backing);
    BOOST_CHECK(!position.immediately_payable);
    BOOST_REQUIRE(modelnet::SwarmClassifyMoney("escrow", 10, position, err));
    BOOST_CHECK(position.confirmed_backing);
    BOOST_CHECK(!position.immediately_payable);
    BOOST_REQUIRE(modelnet::SwarmClassifyMoney("channel_capacity", 10, position, err));
    BOOST_CHECK(position.immediately_payable);
    BOOST_REQUIRE(modelnet::SwarmClassifyMoney("earned_credit", 10, position, err));
    BOOST_CHECK(position.earned);
    BOOST_CHECK(!position.immediately_payable);
    BOOST_REQUIRE(modelnet::SwarmClassifyMoney("confirmed_settlement", 10, position, err));
    BOOST_CHECK(position.confirmed_backing);
    BOOST_CHECK(!position.immediately_payable);
    BOOST_REQUIRE(modelnet::SwarmClassifyMoney("evaluation_certificate", 10, position, err));
    BOOST_CHECK(!position.counts_as_balance);
    BOOST_CHECK_EQUAL(position.code, "NOT_MONEY");
    BOOST_REQUIRE(modelnet::SwarmClassifyMoney("hour-claim", 1, position, err));
    BOOST_CHECK_EQUAL(position.code, "NOT_CONTRIBUTION");
    BOOST_CHECK(!modelnet::SwarmAcceptCollateralUse(true, true, err));
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
    BOOST_CHECK(modelnet::SwarmAcceptCollateralUse(true, false, err));
}

BOOST_AUTO_TEST_CASE(timescales_fill_and_a_finding_can_be_reused)
{
    const fs::path dir = Scratch("btx-swarm-time");
    std::string err;
    BOOST_CHECK(!modelnet::SwarmRecordTimescale(dir, "immediate", "prompt", "secret", "", "", err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_REQUIRE(modelnet::SwarmRecordTimescale(dir, "immediate", "finding", "use the public parser", "", "", err));
    BOOST_REQUIRE(modelnet::SwarmRecordTimescale(dir, "short", "strategy", "retry the test", "", "", err));
    BOOST_REQUIRE(modelnet::SwarmRecordTimescale(dir, "medium", "adapter", "lora", "ckpt", "recipe", err));
    BOOST_REQUIRE(modelnet::SwarmRecordTimescale(dir, "long", "candidate", "gen", "ckpt", "", err));
    BOOST_CHECK(!modelnet::SwarmRecordTimescale(dir, "medium", "adapter", "lora", "", "recipe", err));
    BOOST_CHECK_EQUAL(err, "TIMESCALE_COMPAT");
    std::string found;
    BOOST_REQUIRE(modelnet::SwarmReuseFinding(dir, "public parser", found, err));
    BOOST_CHECK_EQUAL(found, "use the public parser");
    BOOST_CHECK(!modelnet::SwarmReuseFinding(dir, "missing", found, err));
    BOOST_CHECK_EQUAL(err, "NOT_FOUND");
    BOOST_CHECK(modelnet::SwarmWithinMemory(10, 20, err));
    BOOST_CHECK(!modelnet::SwarmWithinMemory(21, 20, err));
    BOOST_CHECK_EQUAL(err, "MEMORY_CAP");
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_CASE(command_log_persists_vote_and_keeps_the_prefix)
{
    const fs::path dir = Scratch("btx-swarm-raft");
    modelnet::SwarmCommandLog log;
    std::string err;
    BOOST_CHECK(!log.Open(dir, 0, err));
    BOOST_CHECK_EQUAL(err, "COMMITTEE");
    BOOST_REQUIRE(log.Open(dir, 3, err));
    BOOST_REQUIRE(log.Vote(1, "a", 0, 0, err));
    BOOST_CHECK_EQUAL(log.VotedFor(), "a");
    BOOST_CHECK(!log.Vote(1, "b", 0, 0, err));
    BOOST_CHECK_EQUAL(err, "VOTE");
    BOOST_REQUIRE(log.Append(1, 0, 0, "join", err));
    BOOST_CHECK(!log.Append(1, 0, 0, "again", err));
    BOOST_CHECK_EQUAL(err, "PREDECESSOR");
    BOOST_REQUIRE(log.Append(1, 1, 1, "stage", err));
    BOOST_REQUIRE(log.Commit(1, err));
    BOOST_CHECK(!log.Truncate(1, err));
    BOOST_CHECK_EQUAL(err, "COMMITTED_PREFIX");
    BOOST_CHECK_EQUAL(log.Entries().size(), 2U);

    modelnet::SwarmCommandLog restored;
    BOOST_REQUIRE(restored.Load(dir, err));
    BOOST_CHECK_EQUAL(restored.Term(), 1);
    BOOST_CHECK_EQUAL(restored.VotedFor(), "a");
    BOOST_CHECK_EQUAL(restored.CommitIndex(), 1);
    BOOST_CHECK_EQUAL(restored.Entries().size(), 2U);
    fs::remove_all(dir);
}

BOOST_AUTO_TEST_SUITE_END()
