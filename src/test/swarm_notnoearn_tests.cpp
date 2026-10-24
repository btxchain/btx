// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoearn.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoearn_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_receipt_id_is_receipt)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEarn note;
    note.settled = false;
    note.want_earn = true;
    const modelnet::SwarmNotNoEarnResult result = modelnet::SwarmNoteNotNoEarn(note, err);
    BOOST_CHECK_EQUAL(result.earned, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "RECEIPT");
    BOOST_CHECK_EQUAL(err, "RECEIPT");
}

BOOST_AUTO_TEST_CASE(unsettled_without_earn_is_before_settlement)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEarn note;
    note.receipt_id = "receipt-1";
    note.settled = false;
    note.want_earn = false;
    const modelnet::SwarmNotNoEarnResult result = modelnet::SwarmNoteNotNoEarn(note, err);
    BOOST_CHECK_EQUAL(result.earned, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "BEFORE_SETTLEMENT");
    BOOST_CHECK_EQUAL(err, "BEFORE_SETTLEMENT");
}

BOOST_AUTO_TEST_CASE(want_earn_is_held)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEarn note;
    note.receipt_id = "receipt-1";
    note.settled = true;
    note.want_earn = true;
    const modelnet::SwarmNotNoEarnResult result = modelnet::SwarmNoteNotNoEarn(note, err);
    BOOST_CHECK_EQUAL(result.earned, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoEarn note;
    note.receipt_id = "receipt-1";
    note.settled = true;
    note.want_earn = false;
    const modelnet::SwarmNotNoEarnResult result = modelnet::SwarmNoteNotNoEarn(note, err);
    BOOST_CHECK_EQUAL(result.earned, false);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
