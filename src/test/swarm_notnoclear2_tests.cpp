// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnoclear2.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notnoclear2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_batch_id_is_batch)
{
    std::string err = "prior";
    modelnet::SwarmNotNoClear2 note;
    note.want_clear = true;
    const modelnet::SwarmNotNoClear2Result result = modelnet::SwarmNoteNotNoClear2(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(result.code, "BATCH");
    BOOST_CHECK_EQUAL(err, "BATCH");
}

BOOST_AUTO_TEST_CASE(want_clear_is_not_paid)
{
    std::string err = "prior";
    modelnet::SwarmNotNoClear2 note;
    note.batch_id = "batch-1";
    note.want_clear = true;
    const modelnet::SwarmNotNoClear2Result result = modelnet::SwarmNoteNotNoClear2(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(result.code, "NOT_PAID");
    BOOST_CHECK_EQUAL(err, "NOT_PAID");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    std::string err = "prior";
    modelnet::SwarmNotNoClear2 note;
    note.batch_id = "batch-1";
    note.want_clear = false;
    const modelnet::SwarmNotNoClear2Result result = modelnet::SwarmNoteNotNoClear2(note, err);
    BOOST_CHECK(!result.paid);
    BOOST_CHECK_EQUAL(result.atoms, int64_t{0});
    BOOST_CHECK_EQUAL(result.l1_txs, 0);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
