// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnogovdrain2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnogovdrain2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_governor_id)
{
    modelnet::SwarmNotNoGovDrain2 note;
    note.governor_id.clear();
    note.idle = true;
    note.want_keep = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovDrain2Result result = modelnet::SwarmNoteNotNoGovDrain2(note, err);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "GOVERNOR");
    BOOST_CHECK_EQUAL(err, "GOVERNOR");
}

BOOST_AUTO_TEST_CASE(idle_drained)
{
    modelnet::SwarmNotNoGovDrain2 note;
    note.governor_id = "governor-1";
    note.idle = true;
    note.want_keep = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovDrain2Result result = modelnet::SwarmNoteNotNoGovDrain2(note, err);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "DRAINED");
    BOOST_CHECK_EQUAL(err, "DRAINED");
}

BOOST_AUTO_TEST_CASE(want_keep_held)
{
    modelnet::SwarmNotNoGovDrain2 note;
    note.governor_id = "governor-1";
    note.idle = false;
    note.want_keep = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovDrain2Result result = modelnet::SwarmNoteNotNoGovDrain2(note, err);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoGovDrain2 note;
    note.governor_id = "governor-1";
    note.idle = false;
    note.want_keep = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoGovDrain2Result result = modelnet::SwarmNoteNotNoGovDrain2(note, err);
    BOOST_CHECK_EQUAL(result.workers, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
