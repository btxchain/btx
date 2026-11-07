// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_schedwit/codes.h>
#include <modelnet/swarm_schedwit/limits.h>
#include <modelnet/swarm_schedwit/swarm_schedwitness.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_schedwit_sign_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_witness_stays_unsigned)
{
    modelnet::SwarmSchedWitness plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.kept("wit-a"));
    BOOST_REQUIRE(plane.stored_witness("wit-a").empty());
    BOOST_REQUIRE(plane.sign_count() == 0);
    BOOST_REQUIRE(!plane.signed_ok());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(plane.automatic_spend() == "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());

    BOOST_REQUIRE(!plane.Sign("wit-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSchedWitnessNotSigned);
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE(plane.kept("wit-a"));
    BOOST_REQUIRE(plane.stored_witness("wit-a") == "wit-a");
    BOOST_REQUIRE(plane.sign_count() == 1);
    BOOST_REQUIRE(!plane.signed_ok());
    BOOST_REQUIRE(plane.signed_ok() == modelnet::kSwarmSchedWitnessSignedOk);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(plane.atoms_moved() == modelnet::kSwarmSchedWitnessAtomsMoved);
    BOOST_REQUIRE(plane.automatic_spend() == modelnet::kSwarmSchedWitnessAutomaticSpend);
    BOOST_REQUIRE(plane.automatic_spend() == "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE(plane.broadcast() == modelnet::kSwarmSchedWitnessBroadcast);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmSchedWitnessBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmSchedWitnessGpu);
}

BOOST_AUTO_TEST_CASE(a_second_distinct_witness_is_stored_beside_the_first)
{
    modelnet::SwarmSchedWitness plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Sign("wit-a", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSchedWitnessNotSigned);
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE(plane.kept("wit-a"));
    BOOST_REQUIRE(plane.stored_witness("wit-a") == "wit-a");
    BOOST_REQUIRE(!plane.signed_ok());

    err = "prior";
    BOOST_REQUIRE(!plane.Sign("wit-b", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSchedWitnessNotSigned);
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE(plane.kept("wit-a"));
    BOOST_REQUIRE(plane.kept("wit-b"));
    BOOST_REQUIRE(plane.stored_witness("wit-a") == "wit-a");
    BOOST_REQUIRE(plane.stored_witness("wit-b") == "wit-b");
    BOOST_REQUIRE(plane.sign_count() == 2);
    BOOST_REQUIRE(!plane.signed_ok());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(plane.automatic_spend() == "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_CASE(space_and_code_word_are_stored_and_stay_unsigned)
{
    modelnet::SwarmSchedWitness plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Sign(" ", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSchedWitnessNotSigned);
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE(plane.kept(" "));
    BOOST_REQUIRE(plane.stored_witness(" ") == " ");
    BOOST_REQUIRE(!plane.signed_ok());

    err = "prior";
    BOOST_REQUIRE(!plane.Sign("WITNESS", err));
    BOOST_REQUIRE(err == modelnet::kSwarmSchedWitnessNotSigned);
    BOOST_REQUIRE_EQUAL(err, "NOT_SIGNED");
    BOOST_REQUIRE(plane.kept("WITNESS"));
    BOOST_REQUIRE(plane.stored_witness("WITNESS") == "WITNESS");
    BOOST_REQUIRE(plane.kept(" "));
    BOOST_REQUIRE(plane.sign_count() == 2);
    BOOST_REQUIRE(!plane.signed_ok());
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(plane.automatic_spend() == "0");
    BOOST_REQUIRE(!plane.broadcast());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
}

BOOST_AUTO_TEST_SUITE_END()
