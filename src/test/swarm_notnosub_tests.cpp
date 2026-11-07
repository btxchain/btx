// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnosub.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnosub_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_sub_id_is_sub)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSub note;
    note.want_charge = true;
    const modelnet::SwarmNotNoSubResult result = modelnet::SwarmNoteNotNoSub(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "SUB");
    BOOST_CHECK_EQUAL(err, "SUB");
}

BOOST_AUTO_TEST_CASE(want_charge_is_not_charged)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSub note;
    note.sub_id = "sub-1";
    note.want_charge = true;
    const modelnet::SwarmNotNoSubResult result = modelnet::SwarmNoteNotNoSub(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_CHARGED");
    BOOST_CHECK_EQUAL(err, "NOT_CHARGED");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoSub note;
    note.sub_id = "sub-1";
    note.want_charge = false;
    const modelnet::SwarmNotNoSubResult result = modelnet::SwarmNoteNotNoSub(note, err);
    BOOST_CHECK(!result.charged);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
