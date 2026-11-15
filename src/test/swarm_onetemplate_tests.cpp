// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_onetemplate.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_onetemplate_tests, BasicTestingSetup)

static modelnet::SwarmCloseTemplateNote NotedNote()
{
    modelnet::SwarmCloseTemplateNote note;
    note.positive_pools = 4;
    note.want_tx_per_pool = false;
    return note;
}

BOOST_AUTO_TEST_CASE(negative_positive_pools_are_close)
{
    modelnet::SwarmCloseTemplateNote note = NotedNote();
    note.positive_pools = -1;
    std::string err = "prior";
    const modelnet::SwarmCloseTemplateResult result = modelnet::SwarmNoteCloseTemplate(note, err);
    BOOST_CHECK_EQUAL(result.tx_count, 0);
    BOOST_CHECK_EQUAL(result.code, "CLOSE");
    BOOST_CHECK_EQUAL(err, "CLOSE");
}

BOOST_AUTO_TEST_CASE(negative_positive_pools_win_over_want_tx_per_pool)
{
    modelnet::SwarmCloseTemplateNote note = NotedNote();
    note.positive_pools = -1;
    note.want_tx_per_pool = true;
    std::string err = "prior";
    const modelnet::SwarmCloseTemplateResult result = modelnet::SwarmNoteCloseTemplate(note, err);
    BOOST_CHECK_EQUAL(result.tx_count, 0);
    BOOST_CHECK_EQUAL(result.code, "CLOSE");
    BOOST_CHECK_EQUAL(err, "CLOSE");
}

BOOST_AUTO_TEST_CASE(want_tx_per_pool_is_one_template)
{
    modelnet::SwarmCloseTemplateNote note = NotedNote();
    note.positive_pools = 4;
    note.want_tx_per_pool = true;
    std::string err = "prior";
    const modelnet::SwarmCloseTemplateResult result = modelnet::SwarmNoteCloseTemplate(note, err);
    BOOST_CHECK_EQUAL(result.tx_count, 0);
    BOOST_CHECK_EQUAL(result.code, "ONE_TEMPLATE");
    BOOST_CHECK_EQUAL(err, "ONE_TEMPLATE");
}

BOOST_AUTO_TEST_CASE(zero_pools_wanting_tx_per_pool_are_one_template)
{
    modelnet::SwarmCloseTemplateNote note = NotedNote();
    note.positive_pools = 0;
    note.want_tx_per_pool = true;
    std::string err = "prior";
    const modelnet::SwarmCloseTemplateResult result = modelnet::SwarmNoteCloseTemplate(note, err);
    BOOST_CHECK_EQUAL(result.tx_count, 0);
    BOOST_CHECK_EQUAL(result.code, "ONE_TEMPLATE");
    BOOST_CHECK_EQUAL(err, "ONE_TEMPLATE");
}

BOOST_AUTO_TEST_CASE(zero_positive_pools_are_empty)
{
    modelnet::SwarmCloseTemplateNote note = NotedNote();
    note.positive_pools = 0;
    std::string err = "prior";
    const modelnet::SwarmCloseTemplateResult result = modelnet::SwarmNoteCloseTemplate(note, err);
    BOOST_CHECK_EQUAL(result.tx_count, 0);
    BOOST_CHECK_EQUAL(result.code, "EMPTY");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(four_positive_pools_are_noted)
{
    modelnet::SwarmCloseTemplateNote note = NotedNote();
    note.positive_pools = 4;
    std::string err = "prior";
    const modelnet::SwarmCloseTemplateResult result = modelnet::SwarmNoteCloseTemplate(note, err);
    BOOST_CHECK_EQUAL(result.tx_count, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
