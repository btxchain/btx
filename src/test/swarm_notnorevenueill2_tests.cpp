// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnorevenueill2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnorevenueill2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_run_id_is_run)
{
    modelnet::SwarmNotNoRevenueIll2 note;
    note.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRevenueIll2Result result = modelnet::SwarmNoteNotNoRevenueIll2(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "RUN");
    BOOST_CHECK_EQUAL(err, "RUN");
}

BOOST_AUTO_TEST_CASE(want_pay_is_held)
{
    modelnet::SwarmNotNoRevenueIll2 note;
    note.run_id = "run-1";
    note.want_pay = true;
    std::string err = "prior";
    const modelnet::SwarmNotNoRevenueIll2Result result = modelnet::SwarmNoteNotNoRevenueIll2(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotNoRevenueIll2 note;
    note.run_id = "run-1";
    note.want_pay = false;
    std::string err = "prior";
    const modelnet::SwarmNotNoRevenueIll2Result result = modelnet::SwarmNoteNotNoRevenueIll2(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
