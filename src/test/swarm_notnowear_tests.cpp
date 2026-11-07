// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnowear.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnowear_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_device_id)
{
    modelnet::SwarmNotNoWear note;
    note.want_claim = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoWearResult out = modelnet::SwarmNoteNotNoWear(note, err);
    BOOST_CHECK_EQUAL(out.code, "DEVICE");
    BOOST_CHECK(!out.claimed);
    BOOST_CHECK_EQUAL(out.hours, 0);
    BOOST_CHECK_EQUAL(err, "DEVICE");
}

BOOST_AUTO_TEST_CASE(want_claim_unmeasured)
{
    modelnet::SwarmNotNoWear note;
    note.device_id = "device-wear";
    note.want_claim = true;
    std::string err = "stale";
    const modelnet::SwarmNotNoWearResult out = modelnet::SwarmNoteNotNoWear(note, err);
    BOOST_CHECK_EQUAL(out.code, "UNMEASURED");
    BOOST_CHECK(!out.claimed);
    BOOST_CHECK_EQUAL(out.hours, 0);
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(noted)
{
    modelnet::SwarmNotNoWear note;
    note.device_id = "device-wear";
    std::string err = "stale";
    const modelnet::SwarmNotNoWearResult out = modelnet::SwarmNoteNotNoWear(note, err);
    BOOST_CHECK_EQUAL(out.code, "NOTED");
    BOOST_CHECK(!out.claimed);
    BOOST_CHECK_EQUAL(out.hours, 0);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
