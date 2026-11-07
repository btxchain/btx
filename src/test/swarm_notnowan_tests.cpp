// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowan.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnowan_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_island_id)
{
    modelnet::SwarmNotNoWan note;
    note.want_exchange = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoWanResult out = modelnet::SwarmNoteNotNoWan(note, err);
    BOOST_CHECK_EQUAL(out.code, "ISLAND");
    BOOST_CHECK(!out.exchanged);
    BOOST_CHECK(!out.bytes_moved);
    BOOST_CHECK_EQUAL(err, "ISLAND");
}

BOOST_AUTO_TEST_CASE(want_exchange_held)
{
    modelnet::SwarmNotNoWan note;
    note.island_id = "island-note";
    note.want_exchange = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoWanResult out = modelnet::SwarmNoteNotNoWan(note, err);
    BOOST_CHECK_EQUAL(out.code, "HELD");
    BOOST_CHECK(!out.exchanged);
    BOOST_CHECK(!out.bytes_moved);
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoWan note;
    note.island_id = "island-note";
    std::string err = "stale";
    const modelnet::SwarmNotNoWanResult out = modelnet::SwarmNoteNotNoWan(note, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.exchanged);
    BOOST_CHECK(!out.bytes_moved);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
