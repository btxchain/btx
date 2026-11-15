// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_holdbook.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_holdbook_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_is_holdout)
{
    std::string err = "prior";
    modelnet::SwarmHoldBook book;
    book.holdout_id = "";
    book.members = 3;
    book.index = 1;
    book.want_rotate = false;
    book.want_score = false;
    const modelnet::SwarmHoldBookResult result = modelnet::SwarmUseHoldout(book, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.index, 0);
    BOOST_CHECK_EQUAL(result.members, 0);
    BOOST_CHECK_EQUAL(result.code, "HOLDOUT");
    BOOST_CHECK_EQUAL(err, "HOLDOUT");
}

BOOST_AUTO_TEST_CASE(members_zero_is_empty)
{
    std::string err = "prior";
    modelnet::SwarmHoldBook book;
    book.holdout_id = "hold";
    book.members = 0;
    book.index = 0;
    book.want_rotate = false;
    book.want_score = false;
    const modelnet::SwarmHoldBookResult result = modelnet::SwarmUseHoldout(book, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.index, 0);
    BOOST_CHECK_EQUAL(result.members, 0);
    BOOST_CHECK_EQUAL(result.code, "EMPTY");
    BOOST_CHECK_EQUAL(err, "EMPTY");
}

BOOST_AUTO_TEST_CASE(index_past_members_is_index)
{
    std::string err = "prior";
    modelnet::SwarmHoldBook book;
    book.holdout_id = "hold";
    book.members = 3;
    book.index = 5;
    book.want_rotate = false;
    book.want_score = false;
    const modelnet::SwarmHoldBookResult result = modelnet::SwarmUseHoldout(book, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.index, 0);
    BOOST_CHECK_EQUAL(result.members, 3);
    BOOST_CHECK_EQUAL(result.code, "INDEX");
    BOOST_CHECK_EQUAL(err, "INDEX");
}

BOOST_AUTO_TEST_CASE(want_rotate_is_not_rotating)
{
    std::string err = "prior";
    modelnet::SwarmHoldBook book;
    book.holdout_id = "hold";
    book.members = 3;
    book.index = 1;
    book.want_rotate = true;
    book.want_score = false;
    const modelnet::SwarmHoldBookResult result = modelnet::SwarmUseHoldout(book, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.index, 1);
    BOOST_CHECK_EQUAL(result.members, 3);
    BOOST_CHECK_EQUAL(result.code, "NOT_ROTATING");
    BOOST_CHECK_EQUAL(err, "NOT_ROTATING");
}

BOOST_AUTO_TEST_CASE(want_score_is_held)
{
    std::string err = "prior";
    modelnet::SwarmHoldBook book;
    book.holdout_id = "hold";
    book.members = 3;
    book.index = 1;
    book.want_rotate = false;
    book.want_score = true;
    const modelnet::SwarmHoldBookResult result = modelnet::SwarmUseHoldout(book, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.index, 1);
    BOOST_CHECK_EQUAL(result.members, 3);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmHoldBook book;
    book.holdout_id = "hold";
    book.members = 3;
    book.index = 1;
    book.want_rotate = false;
    book.want_score = false;
    const modelnet::SwarmHoldBookResult result = modelnet::SwarmUseHoldout(book, err);
    BOOST_CHECK(!result.rotated);
    BOOST_CHECK(!result.scored);
    BOOST_CHECK_EQUAL(result.index, 1);
    BOOST_CHECK_EQUAL(result.members, 3);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
