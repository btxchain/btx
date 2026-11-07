// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnostaleep.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnostaleep_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_lease_id_is_lease)
{
    std::string err = "prior";
    modelnet::SwarmNotNoStaleEp note;
    note.stale_epoch = true;
    note.want_admit = true;
    const modelnet::SwarmNotNoStaleEpResult result = modelnet::SwarmNoteNotNoStaleEp(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "LEASE");
    BOOST_CHECK_EQUAL(err, "LEASE");
}

BOOST_AUTO_TEST_CASE(stale_epoch_without_admit_is_stale_epoch)
{
    std::string err = "prior";
    modelnet::SwarmNotNoStaleEp note;
    note.lease_id = "lease-1";
    note.stale_epoch = true;
    note.want_admit = false;
    const modelnet::SwarmNotNoStaleEpResult result = modelnet::SwarmNoteNotNoStaleEp(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "STALE_EPOCH");
    BOOST_CHECK_EQUAL(err, "STALE_EPOCH");
}

BOOST_AUTO_TEST_CASE(want_admit_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoStaleEp note;
    note.lease_id = "lease-1";
    note.stale_epoch = false;
    note.want_admit = true;
    const modelnet::SwarmNotNoStaleEpResult result = modelnet::SwarmNoteNotNoStaleEp(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoStaleEp note;
    note.lease_id = "lease-1";
    note.stale_epoch = false;
    note.want_admit = false;
    const modelnet::SwarmNotNoStaleEpResult result = modelnet::SwarmNoteNotNoStaleEp(note, err);
    BOOST_CHECK(!result.admitted);
    BOOST_CHECK(!result.trained);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
