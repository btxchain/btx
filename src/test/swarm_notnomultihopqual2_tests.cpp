// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnomultihopqual2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnomultihopqual2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_route_id_is_route)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMultiHopQual2 note;
    note.want_qualify = true;
    const modelnet::SwarmNotNoMultiHopQual2Result result = modelnet::SwarmNoteNotNoMultiHopQual2(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "ROUTE");
    BOOST_CHECK_EQUAL(err, "ROUTE");
}

BOOST_AUTO_TEST_CASE(want_qualify_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMultiHopQual2 note;
    note.route_id = "route-1";
    note.want_qualify = true;
    const modelnet::SwarmNotNoMultiHopQual2Result result = modelnet::SwarmNoteNotNoMultiHopQual2(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoMultiHopQual2 note;
    note.route_id = "route-1";
    note.want_qualify = false;
    const modelnet::SwarmNotNoMultiHopQual2Result result = modelnet::SwarmNoteNotNoMultiHopQual2(note, err);
    BOOST_CHECK(!result.qualified);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
