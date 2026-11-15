// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorvpub2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnorvpub2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_rendezvous_id_yields_rendezvous)
{
    modelnet::SwarmNotNoRvPub2 note;
    note.rendezvous_id.clear();
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoRvPub2Result result = modelnet::SwarmNoteNotNoRvPub2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "RENDEZVOUS");
    BOOST_CHECK_EQUAL(err, "RENDEZVOUS");
}

BOOST_AUTO_TEST_CASE(want_open_yields_held)
{
    modelnet::SwarmNotNoRvPub2 note;
    note.rendezvous_id = "rv-pub";
    note.want_open = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRvPub2Result result = modelnet::SwarmNoteNotNoRvPub2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(neither_yields_noted)
{
    modelnet::SwarmNotNoRvPub2 note;
    note.rendezvous_id = "rv-pub";
    note.want_open = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoRvPub2Result result = modelnet::SwarmNoteNotNoRvPub2(note, err);
    BOOST_CHECK(!result.opened);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
