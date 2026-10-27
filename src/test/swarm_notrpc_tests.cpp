// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notrpc.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notrpc_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_method)
{
    modelnet::SwarmNotRpc note;
    note.want_add = true;
    std::string err = "stale";
    const modelnet::SwarmNotRpcResult result = modelnet::SwarmNoteNotRpc(note, err);
    BOOST_CHECK_EQUAL(result.code, "RPC");
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(err, "RPC");
}

BOOST_AUTO_TEST_CASE(want_add_not_added)
{
    modelnet::SwarmNotRpc note;
    note.method = "getinfo";
    note.want_add = true;
    std::string err = "stale";
    const modelnet::SwarmNotRpcResult result = modelnet::SwarmNoteNotRpc(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADDED");
    BOOST_CHECK(!result.added);
    BOOST_CHECK_EQUAL(err, "NOT_ADDED");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmNotRpc note;
    note.method = "getinfo";
    std::string err = "stale";
    const modelnet::SwarmNotRpcResult result = modelnet::SwarmNoteNotRpc(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.added);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
