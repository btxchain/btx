// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdout.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_holdout_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_suite_is_holdout)
{
    modelnet::SwarmHoldoutBook book;
    std::string err = "prior";
    modelnet::SwarmHoldoutOpen round;
    round.suite_id = "";
    round.holdout_digest = "digest-a";
    round.author_sees_holdout = false;
    round.precommitted = true;
    BOOST_CHECK(!book.Open(round, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK(!book.HasOpen());
    BOOST_CHECK(!book.Measured());

    round.suite_id = "suite-1";
    round.holdout_digest = "";
    BOOST_CHECK(!book.Open(round, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
    BOOST_CHECK(!book.HasOpen());
}

BOOST_AUTO_TEST_CASE(author_sees_holdout_is_leaked)
{
    modelnet::SwarmHoldoutBook book;
    std::string err;
    modelnet::SwarmHoldoutOpen round;
    round.suite_id = "suite-1";
    round.holdout_digest = "digest-a";
    round.author_sees_holdout = true;
    round.precommitted = true;
    BOOST_CHECK(!book.Open(round, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT_LEAKED");
    BOOST_CHECK(!book.HasOpen());
    BOOST_CHECK(!book.Measured());
}

BOOST_AUTO_TEST_CASE(suite_not_precommitted)
{
    modelnet::SwarmHoldoutBook book;
    std::string err;
    modelnet::SwarmHoldoutOpen round;
    round.suite_id = "suite-1";
    round.holdout_digest = "digest-a";
    round.author_sees_holdout = false;
    round.precommitted = false;
    BOOST_CHECK(!book.Open(round, err));
    BOOST_CHECK_EQUAL(err, "SUITE_NOT_PRECOMMITTED");
    BOOST_CHECK(!book.HasOpen());
    BOOST_CHECK(!book.Measured());
}

BOOST_AUTO_TEST_CASE(consume_leaves_measured_false_and_second_consume_is_gate)
{
    modelnet::SwarmHoldoutBook book;
    std::string err = "prior";
    modelnet::SwarmHoldoutOpen round;
    round.suite_id = "suite-1";
    round.holdout_digest = "digest-a";
    round.author_sees_holdout = false;
    round.precommitted = true;
    BOOST_CHECK(book.Open(round, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.HasOpen());
    BOOST_CHECK(!book.Measured());

    BOOST_CHECK(book.Consume(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!book.HasOpen());
    BOOST_CHECK(!book.Measured());

    BOOST_CHECK(!book.Consume(err));
    BOOST_CHECK_EQUAL(err, "GATE");
    BOOST_CHECK(!book.HasOpen());
    BOOST_CHECK(!book.Measured());
}

BOOST_AUTO_TEST_CASE(consumed_digest_is_holdout_reused)
{
    modelnet::SwarmHoldoutBook book;
    std::string err;
    modelnet::SwarmHoldoutOpen round;
    round.suite_id = "suite-1";
    round.holdout_digest = "digest-a";
    round.author_sees_holdout = false;
    round.precommitted = true;
    BOOST_REQUIRE(book.Open(round, err));
    BOOST_REQUIRE(book.Consume(err));

    BOOST_CHECK(!book.Open(round, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT_REUSED");
    BOOST_CHECK(!book.HasOpen());
    BOOST_CHECK(!book.Measured());
}

BOOST_AUTO_TEST_CASE(second_open_is_replay_and_consume_keeps_the_first_digest)
{
    modelnet::SwarmHoldoutBook book;
    std::string err;
    modelnet::SwarmHoldoutOpen first;
    first.suite_id = "suite-1";
    first.holdout_digest = "digest-first";
    first.author_sees_holdout = false;
    first.precommitted = true;
    BOOST_REQUIRE(book.Open(first, err));
    BOOST_CHECK(err.empty());

    modelnet::SwarmHoldoutOpen second = first;
    second.holdout_digest = "digest-second";
    BOOST_CHECK(!book.Open(second, err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(book.HasOpen());
    BOOST_CHECK(!book.Measured());

    BOOST_CHECK(book.Consume(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!book.Measured());

    BOOST_CHECK(!book.Open(first, err));
    BOOST_CHECK_EQUAL(err, "HOLDOUT_REUSED");

    BOOST_CHECK(book.Open(second, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.HasOpen());
    BOOST_CHECK(!book.Measured());
}

BOOST_AUTO_TEST_SUITE_END()
