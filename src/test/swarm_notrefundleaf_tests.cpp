// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrefundleaf.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notrefundleaf_tests, BasicTestingSetup)

static modelnet::SwarmNotRefundLeaf NotedNote()
{
    modelnet::SwarmNotRefundLeaf note;
    note.channel_id = "channel-1";
    note.want_refund = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_channel_id_is_channel)
{
    modelnet::SwarmNotRefundLeaf note = NotedNote();
    note.channel_id.clear();
    note.want_refund = true;
    std::string err = "prior";
    const modelnet::SwarmNotRefundLeafResult result = modelnet::SwarmNoteNotRefundLeaf(note, err);
    BOOST_CHECK_EQUAL(result.code, "CHANNEL");
    BOOST_CHECK(!result.built);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "CHANNEL");
}

BOOST_AUTO_TEST_CASE(want_refund_is_held)
{
    modelnet::SwarmNotRefundLeaf note = NotedNote();
    note.want_refund = true;
    std::string err = "prior";
    const modelnet::SwarmNotRefundLeafResult result = modelnet::SwarmNoteNotRefundLeaf(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.built);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotRefundLeaf note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotRefundLeafResult result = modelnet::SwarmNoteNotRefundLeaf(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.built);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
