// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notidentity.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notidentity_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_node_id)
{
    modelnet::SwarmNotIdentity note;
    note.want_bind = true;
    std::string err = "stale";
    const modelnet::SwarmNotIdentityResult result = modelnet::SwarmNoteNotIdentity(note, err);
    BOOST_CHECK_EQUAL(result.code, "NODE");
    BOOST_CHECK(!result.bound);
    BOOST_CHECK_EQUAL(err, "NODE");
}

BOOST_AUTO_TEST_CASE(want_bind_not_bound)
{
    modelnet::SwarmNotIdentity note;
    note.node_id = "n1";
    note.want_bind = true;
    std::string err = "stale";
    const modelnet::SwarmNotIdentityResult result = modelnet::SwarmNoteNotIdentity(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_BOUND");
    BOOST_CHECK(!result.bound);
    BOOST_CHECK_EQUAL(err, "NOT_BOUND");
}

BOOST_AUTO_TEST_CASE(noted_clears_err)
{
    modelnet::SwarmNotIdentity note;
    note.node_id = "n1";
    std::string err = "stale";
    const modelnet::SwarmNotIdentityResult result = modelnet::SwarmNoteNotIdentity(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.bound);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
