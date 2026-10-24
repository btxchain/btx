// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_unfunded.h>
#include <test/util/setup_common.h>

#include <cstdint>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_unfunded_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_pool_id_or_negative_atoms_is_pool)
{
    std::string err = "prior";
    modelnet::SwarmPoolAdvert advert;
    advert.pool_id.clear();
    advert.funded = false;
    advert.advertised_atoms = 1000000;
    advert.want_advertise_balance = true;
    const modelnet::SwarmPoolAdvertResult empty_id = modelnet::SwarmNotePoolAdvert(advert, err);
    BOOST_CHECK(!empty_id.balance_advertised);
    BOOST_CHECK(!empty_id.spendable);
    BOOST_CHECK_EQUAL(empty_id.code, "POOL");
    BOOST_CHECK_EQUAL(err, "POOL");

    err = "prior";
    advert.pool_id = "pool-1";
    advert.funded = true;
    advert.advertised_atoms = -1;
    advert.want_advertise_balance = true;
    const modelnet::SwarmPoolAdvertResult negative = modelnet::SwarmNotePoolAdvert(advert, err);
    BOOST_CHECK(!negative.balance_advertised);
    BOOST_CHECK(!negative.spendable);
    BOOST_CHECK_EQUAL(negative.code, "POOL");
    BOOST_CHECK_EQUAL(err, "POOL");
}

BOOST_AUTO_TEST_CASE(unfunded_is_not_advertised_even_when_atoms_are_large)
{
    std::string err = "prior";
    modelnet::SwarmPoolAdvert advert;
    advert.pool_id = "pool-1";
    advert.funded = false;
    advert.advertised_atoms = 1000000;
    advert.want_advertise_balance = true;
    const modelnet::SwarmPoolAdvertResult result = modelnet::SwarmNotePoolAdvert(advert, err);
    BOOST_CHECK(!result.balance_advertised);
    BOOST_CHECK(!result.spendable);
    BOOST_CHECK_EQUAL(result.code, "UNFUNDED");
    BOOST_CHECK_EQUAL(err, "UNFUNDED");
}

BOOST_AUTO_TEST_CASE(want_advertise_balance_is_held)
{
    std::string err = "prior";
    modelnet::SwarmPoolAdvert advert;
    advert.pool_id = "pool-1";
    advert.funded = true;
    advert.advertised_atoms = 1000000;
    advert.want_advertise_balance = true;
    const modelnet::SwarmPoolAdvertResult result = modelnet::SwarmNotePoolAdvert(advert, err);
    BOOST_CHECK(!result.balance_advertised);
    BOOST_CHECK(!result.spendable);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(funded_note_is_noted_and_not_spendable)
{
    std::string err = "prior";
    modelnet::SwarmPoolAdvert advert;
    advert.pool_id = "pool-1";
    advert.funded = true;
    advert.advertised_atoms = 0;
    advert.want_advertise_balance = false;
    const modelnet::SwarmPoolAdvertResult result = modelnet::SwarmNotePoolAdvert(advert, err);
    BOOST_CHECK(!result.balance_advertised);
    BOOST_CHECK(!result.spendable);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
