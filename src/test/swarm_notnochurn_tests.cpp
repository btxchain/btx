// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnochurn.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnochurn_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_worker_id_is_worker)
{
    std::string err = "prior";
    modelnet::SwarmNotNoChurn note;
    note.gone = true;
    note.want_pay = true;
    const modelnet::SwarmNotNoChurnResult result = modelnet::SwarmNoteNotNoChurn(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "WORKER");
    BOOST_CHECK_EQUAL(err, "WORKER");
}

BOOST_AUTO_TEST_CASE(gone_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoChurn note;
    note.worker_id = "worker-note";
    note.gone = true;
    note.want_pay = false;
    const modelnet::SwarmNotNoChurnResult result = modelnet::SwarmNoteNotNoChurn(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_pay_while_present_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoChurn note;
    note.worker_id = "worker-note";
    note.gone = false;
    note.want_pay = true;
    const modelnet::SwarmNotNoChurnResult result = modelnet::SwarmNoteNotNoChurn(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoChurn note;
    note.worker_id = "worker-note";
    note.gone = false;
    note.want_pay = false;
    const modelnet::SwarmNotNoChurnResult result = modelnet::SwarmNoteNotNoChurn(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
