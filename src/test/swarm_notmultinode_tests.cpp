// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notmultinode.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notmultinode_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id)
{
    modelnet::SwarmNotMultiNode note;
    note.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmNotMultiNodeResult out = modelnet::SwarmNoteNotMultiNode(note, err);
    BOOST_CHECK_EQUAL(out.code, "NODE");
    BOOST_CHECK(!out.published);
    BOOST_CHECK(!out.paired);
    BOOST_CHECK_EQUAL(out.tokens_per_sec, 0);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_publish_out_of_scope)
{
    modelnet::SwarmNotMultiNode note;
    note.run_id = "run-multinode";
    note.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmNotMultiNodeResult out = modelnet::SwarmNoteNotMultiNode(note, err);
    BOOST_CHECK_EQUAL(out.code, "OUT_OF_SCOPE");
    BOOST_CHECK(!out.published);
    BOOST_CHECK(!out.paired);
    BOOST_CHECK_EQUAL(out.tokens_per_sec, 0);
    BOOST_CHECK_EQUAL(err, "OUT_OF_SCOPE");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotMultiNode note;
    note.run_id = "run-multinode";
    std::string err = "stale";
    const modelnet::SwarmNotMultiNodeResult out = modelnet::SwarmNoteNotMultiNode(note, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.published);
    BOOST_CHECK(!out.paired);
    BOOST_CHECK_EQUAL(out.tokens_per_sec, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
