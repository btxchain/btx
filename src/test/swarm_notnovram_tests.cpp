// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnovram.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnovram_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_device_id_is_device)
{
    modelnet::SwarmNotNoVram note;
    note.vram_mib = 1;
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoVramResult result = modelnet::SwarmNoteNotNoVram(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.mib, 0);
    BOOST_CHECK_EQUAL(result.code, "DEVICE");
    BOOST_CHECK_EQUAL(err, "DEVICE");
}

BOOST_AUTO_TEST_CASE(nonzero_vram_is_unmeasured)
{
    modelnet::SwarmNotNoVram note;
    note.device_id = "device-1";
    note.vram_mib = 1;
    note.want_claim = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoVramResult result = modelnet::SwarmNoteNotNoVram(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.mib, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(want_claim_at_zero_is_unmeasured)
{
    modelnet::SwarmNotNoVram note;
    note.device_id = "device-1";
    note.vram_mib = 0;
    note.want_claim = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoVramResult result = modelnet::SwarmNoteNotNoVram(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.mib, 0);
    BOOST_CHECK_EQUAL(result.code, "UNMEASURED");
    BOOST_CHECK_EQUAL(err, "UNMEASURED");
}

BOOST_AUTO_TEST_CASE(plain_zero_is_noted)
{
    modelnet::SwarmNotNoVram note;
    BOOST_CHECK_EQUAL(note.vram_mib, 0);
    BOOST_CHECK(!note.want_claim);
    note.device_id = "device-1";
    std::string err = "prior";
    const modelnet::SwarmNotNoVramResult result = modelnet::SwarmNoteNotNoVram(note, err);
    BOOST_CHECK(!result.claimed);
    BOOST_CHECK_EQUAL(result.mib, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
