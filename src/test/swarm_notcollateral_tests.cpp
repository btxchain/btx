// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notcollateral.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_notcollateral_tests, BasicTestingSetup)

static modelnet::SwarmNotCollateral NotedNote()
{
    modelnet::SwarmNotCollateral note;
    note.pool_id = "pool-1";
    note.want_reserve = false;
    return note;
}

BOOST_AUTO_TEST_CASE(empty_pool_id_is_pool)
{
    modelnet::SwarmNotCollateral note = NotedNote();
    note.pool_id.clear();
    std::string err = "prior";
    const modelnet::SwarmNotCollateralResult result = modelnet::SwarmNoteNotCollateral(note, err);
    BOOST_CHECK(!result.reserved);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(want_reserve_is_not_live)
{
    modelnet::SwarmNotCollateral note = NotedNote();
    note.want_reserve = true;
    std::string err = "prior";
    const modelnet::SwarmNotCollateralResult result = modelnet::SwarmNoteNotCollateral(note, err);
    BOOST_CHECK(!result.reserved);
    BOOST_CHECK_EQUAL(result.code, "NOT_LIVE");
    BOOST_CHECK_EQUAL(err, "NOT_LIVE");
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted)
{
    modelnet::SwarmNotCollateral note = NotedNote();
    std::string err = "prior";
    const modelnet::SwarmNotCollateralResult result = modelnet::SwarmNoteNotCollateral(note, err);
    BOOST_CHECK(!result.reserved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
