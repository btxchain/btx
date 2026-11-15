// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnetcost.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnetcost_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_peer_id_is_peer)
{
    std::string err = "prior";
    modelnet::SwarmNotNetCost note;
    note.want_publish = true;
    const modelnet::SwarmNotNetCostResult result = modelnet::SwarmNoteNotNetCost(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "PEER");
    BOOST_CHECK_EQUAL(err, "PEER");
}

BOOST_AUTO_TEST_CASE(want_publish_is_unmeasured)
{
    std::string err = "prior";
    modelnet::SwarmNotNetCost note;
    note.peer_id = "peer-netcost";
    note.want_publish = true;
    const modelnet::SwarmNotNetCostResult result = modelnet::SwarmNoteNotNetCost(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNetCost note;
    note.peer_id = "peer-netcost";
    note.want_publish = false;
    const modelnet::SwarmNotNetCostResult result = modelnet::SwarmNoteNotNetCost(note, err);
    BOOST_CHECK(!result.published);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
