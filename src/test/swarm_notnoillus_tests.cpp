// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoillus.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoillus_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_split_id_is_split)
{
    std::string err = "prior";
    modelnet::SwarmNotNoIllus note;
    note.want_pay = true;
    const modelnet::SwarmNotNoIllusResult result = modelnet::SwarmNoteNotNoIllus(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SPLIT");
    BOOST_CHECK_EQUAL(err, "SPLIT");
}

BOOST_AUTO_TEST_CASE(want_pay_is_not_paid)
{
    std::string err = "prior";
    modelnet::SwarmNotNoIllus note;
    note.split_id = "split-1";
    note.want_pay = true;
    const modelnet::SwarmNotNoIllusResult result = modelnet::SwarmNoteNotNoIllus(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_PAID");
    BOOST_CHECK_EQUAL(err, "NOT_PAID");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoIllus note;
    note.split_id = "split-1";
    note.want_pay = false;
    const modelnet::SwarmNotNoIllusResult result = modelnet::SwarmNoteNotNoIllus(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
