// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_headkeep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_headkeep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_head_id_is_head)
{
    modelnet::SwarmHeadKeep head;
    head.head_id = "";
    head.visible = 2;
    head.majority = false;
    head.want_hide = false;
    head.want_graduate = false;
    std::string err = "prior";
    const modelnet::SwarmHeadKeepResult result = modelnet::SwarmKeepHeads(head, err);
    BOOST_CHECK_EQUAL(result.hidden, false);
    BOOST_CHECK_EQUAL(result.graduated, false);
    BOOST_CHECK_EQUAL(result.visible, 0);
    BOOST_CHECK_EQUAL(result.code, "HEAD");
    BOOST_CHECK_EQUAL(err, "HEAD");
}

BOOST_AUTO_TEST_CASE(visible_zero_is_empty)
{
    modelnet::SwarmHeadKeep head;
    head.head_id = "head-1";
    head.visible = 0;
    head.majority = false;
    head.want_hide = false;
    head.want_graduate = false;
    std::string err = "prior";
    const modelnet::SwarmHeadKeepResult result = modelnet::SwarmKeepHeads(head, err);
    BOOST_CHECK_EQUAL(result.hidden, false);
    BOOST_CHECK_EQUAL(result.graduated, false);
    BOOST_CHECK_EQUAL(result.visible, 0);
    BOOST_CHECK_EQUAL(result.code, "EMPTY");
    BOOST_CHECK_EQUAL(err, "EMPTY");
}

BOOST_AUTO_TEST_CASE(majority_true_is_not_hidden)
{
    modelnet::SwarmHeadKeep head;
    head.head_id = "head-1";
    head.visible = 2;
    head.majority = true;
    head.want_hide = false;
    head.want_graduate = false;
    std::string err = "prior";
    const modelnet::SwarmHeadKeepResult result = modelnet::SwarmKeepHeads(head, err);
    BOOST_CHECK_EQUAL(result.hidden, false);
    BOOST_CHECK_EQUAL(result.graduated, false);
    BOOST_CHECK_EQUAL(result.visible, 2);
    BOOST_CHECK_EQUAL(result.code, "NOT_HIDDEN");
    BOOST_CHECK_EQUAL(err, "NOT_HIDDEN");
}

BOOST_AUTO_TEST_CASE(want_graduate_is_held)
{
    modelnet::SwarmHeadKeep head;
    head.head_id = "head-1";
    head.visible = 2;
    head.majority = false;
    head.want_hide = false;
    head.want_graduate = true;
    std::string err = "prior";
    const modelnet::SwarmHeadKeepResult result = modelnet::SwarmKeepHeads(head, err);
    BOOST_CHECK_EQUAL(result.hidden, false);
    BOOST_CHECK_EQUAL(result.graduated, false);
    BOOST_CHECK_EQUAL(result.visible, 2);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_is_noted)
{
    modelnet::SwarmHeadKeep head;
    head.head_id = "head-1";
    head.visible = 2;
    head.majority = false;
    head.want_hide = false;
    head.want_graduate = false;
    std::string err = "prior";
    const modelnet::SwarmHeadKeepResult result = modelnet::SwarmKeepHeads(head, err);
    BOOST_CHECK_EQUAL(result.hidden, false);
    BOOST_CHECK_EQUAL(result.graduated, false);
    BOOST_CHECK_EQUAL(result.visible, 2);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
