// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_islandopt.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_islandopt_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(one_local_step_has_a_hash_and_moves_no_bytes)
{
    modelnet::SwarmIslandOpt opt;
    std::string err = "prior";
    BOOST_CHECK(opt.LocalStep(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(opt.steps(), 1U);
    BOOST_CHECK(!opt.state_hash().empty());
    BOOST_CHECK(opt.pending_hash().empty());
    BOOST_CHECK_EQUAL(opt.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(a_stale_remote_is_refused)
{
    modelnet::SwarmIslandOpt opt;
    std::string err;
    BOOST_REQUIRE(opt.LocalStep(err));
    const std::string local = opt.state_hash();
    BOOST_CHECK(!opt.AcceptRemote(opt.steps() + 1, "remote-hash", true, err));
    BOOST_CHECK_EQUAL(err, "NOT_ADMITTED");
    BOOST_CHECK_EQUAL(opt.state_hash(), local);
    BOOST_CHECK_EQUAL(opt.steps(), 1U);
    BOOST_CHECK(opt.pending_hash().empty());
    BOOST_CHECK_EQUAL(opt.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(a_next_step_remote_is_pending_and_does_not_replace_the_local_hash)
{
    modelnet::SwarmIslandOpt opt;
    std::string err;
    BOOST_REQUIRE(opt.LocalStep(err));
    const std::string local = opt.state_hash();
    BOOST_CHECK(!opt.AcceptRemote(opt.steps() + 1, "", false, err));
    BOOST_CHECK_EQUAL(err, "HASH");
    BOOST_CHECK_EQUAL(opt.state_hash(), local);
    BOOST_CHECK(opt.pending_hash().empty());

    BOOST_CHECK(!opt.AcceptRemote(opt.steps() + 2, "remote-later", false, err));
    BOOST_CHECK_EQUAL(err, "STALE");
    BOOST_CHECK_EQUAL(opt.state_hash(), local);
    BOOST_CHECK(opt.pending_hash().empty());

    BOOST_CHECK(opt.AcceptRemote(opt.steps() + 1, "remote-next", false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(opt.pending_hash(), "remote-next");
    BOOST_CHECK_EQUAL(opt.state_hash(), local);
    BOOST_CHECK_NE(opt.pending_hash(), opt.state_hash());
    BOOST_CHECK_EQUAL(opt.steps(), 1U);
    BOOST_CHECK_EQUAL(opt.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(reject_average_leaves_the_hash_in_place)
{
    modelnet::SwarmIslandOpt opt;
    std::string err;
    BOOST_REQUIRE(opt.LocalStep(err));
    const std::string local = opt.state_hash();
    BOOST_CHECK(opt.AcceptRemote(opt.steps() + 1, "remote-next", false, err));
    BOOST_CHECK(!opt.RejectAverage(err));
    BOOST_CHECK_EQUAL(err, "NOT_AVERAGED");
    BOOST_CHECK_EQUAL(opt.state_hash(), local);
    BOOST_CHECK_EQUAL(opt.pending_hash(), "remote-next");
    BOOST_CHECK_EQUAL(opt.steps(), 1U);
    BOOST_CHECK_EQUAL(opt.bytes_moved(), 0);
}

BOOST_AUTO_TEST_SUITE_END()
