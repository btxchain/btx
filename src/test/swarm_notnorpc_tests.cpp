// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorpc.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnorpc_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_method_id)
{
    modelnet::SwarmNotNoRpc note;
    note.want_add = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoRpcResult result = modelnet::SwarmNoteNotNoRpc(note, err);
    BOOST_CHECK_EQUAL(result.code, "METHOD");
    BOOST_CHECK(!result.added);
    BOOST_CHECK(!result.called);
    BOOST_CHECK_EQUAL(err, "METHOD");
}

BOOST_AUTO_TEST_CASE(want_add_not_added)
{
    modelnet::SwarmNotNoRpc note;
    note.method_id = "method-a";
    note.want_add = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoRpcResult result = modelnet::SwarmNoteNotNoRpc(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADDED");
    BOOST_CHECK(!result.added);
    BOOST_CHECK(!result.called);
    BOOST_CHECK_EQUAL(err, "NOT_ADDED");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmNotNoRpc note;
    note.method_id = "method-a";
    std::string err = "stale";
    const modelnet::SwarmNotNoRpcResult result = modelnet::SwarmNoteNotNoRpc(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.added);
    BOOST_CHECK(!result.called);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
