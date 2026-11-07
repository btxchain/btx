// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notfailover.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notfailover_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_coord_id)
{
    modelnet::SwarmNotFailover note;
    note.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmNotFailoverResult out = modelnet::SwarmNoteNotFailover(note, err);
    BOOST_CHECK_EQUAL(out.code, "COORD");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.failover_ms, 0);
    BOOST_CHECK(!out.continued);
    BOOST_CHECK_EQUAL(err, "COORD");
}

BOOST_AUTO_TEST_CASE(want_publish_unmeasured)
{
    modelnet::SwarmNotFailover note;
    note.coord_id = "coord-1";
    note.want_publish = true;
    std::string err = "stale";
    const modelnet::SwarmNotFailoverResult out = modelnet::SwarmNoteNotFailover(note, err);
    BOOST_CHECK_EQUAL(out.code, "UNMEASURED");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.failover_ms, 0);
    BOOST_CHECK(!out.continued);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotFailover note;
    note.coord_id = "coord-1";
    std::string err = "stale";
    const modelnet::SwarmNotFailoverResult out = modelnet::SwarmNoteNotFailover(note, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.published);
    BOOST_CHECK_EQUAL(out.failover_ms, 0);
    BOOST_CHECK(!out.continued);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
