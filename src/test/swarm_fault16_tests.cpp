// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_fault16.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_fault16_tests, BasicTestingSetup)

static modelnet::SwarmFault16 DistinctPools()
{
    modelnet::SwarmFault16 in;
    in.pool_a = "pool-a";
    in.pool_b = "pool-b";
    in.collateral_id = "col-1";
    in.same_collateral = false;
    in.want_reserve = false;
    return in;
}

static void ExpectNeverReserved(const modelnet::SwarmFault16Result& result)
{
    BOOST_CHECK(!result.reserved);
    BOOST_CHECK(!result.broadcast);
    BOOST_CHECK(!result.committed);
}

BOOST_AUTO_TEST_CASE(empty_pool_a_is_pool)
{
    modelnet::SwarmFault16 in = DistinctPools();
    in.pool_a.clear();
    in.same_collateral = true;
    in.want_reserve = true;
    std::string err = "prior";
    const modelnet::SwarmFault16Result result = modelnet::SwarmRecoverFault16(in, err);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    ExpectNeverReserved(result);
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(empty_pool_b_is_pool)
{
    modelnet::SwarmFault16 in = DistinctPools();
    in.pool_b.clear();
    in.want_reserve = true;
    std::string err = "prior";
    const modelnet::SwarmFault16Result result = modelnet::SwarmRecoverFault16(in, err);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    ExpectNeverReserved(result);
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(empty_collateral_id_is_pool)
{
    modelnet::SwarmFault16 in = DistinctPools();
    in.collateral_id.clear();
    in.same_collateral = true;
    in.want_reserve = true;
    std::string err = "prior";
    const modelnet::SwarmFault16Result result = modelnet::SwarmRecoverFault16(in, err);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    ExpectNeverReserved(result);
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(all_ids_empty_is_pool)
{
    modelnet::SwarmFault16 in = DistinctPools();
    in.pool_a.clear();
    in.pool_b.clear();
    in.collateral_id.clear();
    std::string err = "prior";
    const modelnet::SwarmFault16Result result = modelnet::SwarmRecoverFault16(in, err);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    ExpectNeverReserved(result);
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(equal_pools_are_collateral_reuse_even_if_want_reserve)
{
    modelnet::SwarmFault16 in = DistinctPools();
    in.pool_b = in.pool_a;
    in.same_collateral = false;
    in.want_reserve = true;
    std::string err = "prior";
    const modelnet::SwarmFault16Result result = modelnet::SwarmRecoverFault16(in, err);
    BOOST_CHECK_EQUAL(result.code, "COLLATERAL_REUSE");
    BOOST_CHECK(!result.reserved);
    ExpectNeverReserved(result);
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
}

BOOST_AUTO_TEST_CASE(same_collateral_is_collateral_reuse_even_if_want_reserve)
{
    modelnet::SwarmFault16 in = DistinctPools();
    in.same_collateral = true;
    in.want_reserve = true;
    std::string err = "prior";
    const modelnet::SwarmFault16Result result = modelnet::SwarmRecoverFault16(in, err);
    BOOST_CHECK_EQUAL(result.code, "COLLATERAL_REUSE");
    BOOST_CHECK(!result.reserved);
    ExpectNeverReserved(result);
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
}

BOOST_AUTO_TEST_CASE(equal_pools_and_same_collateral_are_collateral_reuse)
{
    modelnet::SwarmFault16 in = DistinctPools();
    in.pool_b = in.pool_a;
    in.same_collateral = true;
    in.want_reserve = false;
    std::string err = "prior";
    const modelnet::SwarmFault16Result result = modelnet::SwarmRecoverFault16(in, err);
    BOOST_CHECK_EQUAL(result.code, "COLLATERAL_REUSE");
    ExpectNeverReserved(result);
    BOOST_CHECK_EQUAL(err, "COLLATERAL_REUSE");
}

BOOST_AUTO_TEST_CASE(want_reserve_is_held_and_clears_err)
{
    modelnet::SwarmFault16 in = DistinctPools();
    in.want_reserve = true;
    in.same_collateral = false;
    std::string err = "prior";
    const modelnet::SwarmFault16Result result = modelnet::SwarmRecoverFault16(in, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(!result.reserved);
    ExpectNeverReserved(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(plain_note_is_noted_and_clears_err)
{
    modelnet::SwarmFault16 in = DistinctPools();
    std::string err = "prior";
    const modelnet::SwarmFault16Result result = modelnet::SwarmRecoverFault16(in, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(!result.reserved);
    ExpectNeverReserved(result);
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
