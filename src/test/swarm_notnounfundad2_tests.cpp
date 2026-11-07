// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_notnounfundad2.h>
#include <test/util/setup_common.h>

#include <string>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_notnounfundad2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_pool_id_yields_pool)
{
    modelnet::SwarmNotNoUnfundAd2 note;
    note.pool_id.clear();
    note.unfunded = false;
    note.want_advertise = false;
    std::string err = "dirty";
    const modelnet::SwarmNotNoUnfundAd2Result result = modelnet::SwarmNoteNotNoUnfundAd2(note, err);
    BOOST_CHECK_EQUAL(result.code, "POOL");
    BOOST_CHECK_EQUAL(err, "POOL");
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(unfunded_true_want_advertise_false_yields_not_advertised)
{
    modelnet::SwarmNotNoUnfundAd2 note;
    note.pool_id = "pool";
    note.unfunded = true;
    note.want_advertise = false;
    std::string err = "dirty";
    const modelnet::SwarmNotNoUnfundAd2Result result = modelnet::SwarmNoteNotNoUnfundAd2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOT_ADVERTISED");
    BOOST_CHECK_EQUAL(err, "NOT_ADVERTISED");
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(want_advertise_true_unfunded_false_yields_held)
{
    modelnet::SwarmNotNoUnfundAd2 note;
    note.pool_id = "pool";
    note.unfunded = false;
    note.want_advertise = true;
    std::string err = "dirty";
    const modelnet::SwarmNotNoUnfundAd2Result result = modelnet::SwarmNoteNotNoUnfundAd2(note, err);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_CASE(neither_yields_noted)
{
    modelnet::SwarmNotNoUnfundAd2 note;
    note.pool_id = "pool";
    note.unfunded = false;
    note.want_advertise = false;
    std::string err = "dirty";
    const modelnet::SwarmNotNoUnfundAd2Result result = modelnet::SwarmNoteNotNoUnfundAd2(note, err);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!result.advertised);
    BOOST_CHECK_EQUAL(result.atoms, 0);
}

BOOST_AUTO_TEST_SUITE_END()
