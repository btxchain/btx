// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_handoff/swarm_handoff.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void ExpectQuiet(const modelnet::SwarmHandoff& handoff)
{
    BOOST_CHECK(!handoff.spend_key_moved());
    BOOST_CHECK(!handoff.launched());
    BOOST_CHECK(!handoff.gpu());
    BOOST_CHECK(!handoff.broadcast());
    BOOST_CHECK(!handoff.connected());
    BOOST_CHECK_EQUAL(handoff.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(handoff.atoms_moved(), static_cast<int64_t>(0));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_handoff_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(conflict_keeps_the_first_payload)
{
    modelnet::SwarmHandoff handoff;
    std::string err = "prior";

    BOOST_CHECK(!handoff.Intent("", "body", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffIntent);
    BOOST_CHECK(handoff.payload("").empty());
    BOOST_CHECK_EQUAL(handoff.attempt(""), 0);

    BOOST_CHECK(!handoff.Intent("job", "", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffIntent);
    BOOST_CHECK(handoff.payload("job").empty());
    BOOST_CHECK_EQUAL(handoff.attempt("job"), 0);

    BOOST_REQUIRE(handoff.Intent("job", "first", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(handoff.payload("job"), "first");
    BOOST_CHECK_EQUAL(handoff.attempt("job"), 1);

    BOOST_CHECK(!handoff.Intent("job", "first", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffReplay);
    BOOST_CHECK_EQUAL(handoff.payload("job"), "first");
    BOOST_CHECK_EQUAL(handoff.attempt("job"), 1);

    BOOST_CHECK(!handoff.Intent("job", "second", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffConflict);
    BOOST_CHECK_EQUAL(handoff.payload("job"), "first");
    BOOST_CHECK_EQUAL(handoff.attempt("job"), 1);

    BOOST_CHECK(!handoff.Intent("job", "third", err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffConflict);
    BOOST_CHECK_EQUAL(handoff.payload("job"), "first");
    BOOST_CHECK_EQUAL(handoff.attempt("job"), 1);
    ExpectQuiet(handoff);
}

BOOST_AUTO_TEST_CASE(lease_rejects_equality_and_admits_the_prior_millisecond)
{
    modelnet::SwarmHandoff handoff;
    std::string err = "prior";

    BOOST_CHECK(!handoff.Lease("", 10, 9, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffWorker);
    BOOST_CHECK(!handoff.leased(""));

    BOOST_CHECK(!handoff.Lease("dest", 10, 10, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffExpired);
    BOOST_CHECK(!handoff.leased("dest"));
    BOOST_CHECK(!handoff.live("dest", 10));

    BOOST_CHECK(!handoff.Lease("dest", 10, 11, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffExpired);
    BOOST_CHECK(!handoff.leased("dest"));

    BOOST_CHECK(!handoff.Lease("dest", 0, -1, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffExpired);
    BOOST_CHECK(!handoff.leased("dest"));

    BOOST_REQUIRE(handoff.Lease("dest", 10, 9, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(handoff.leased("dest"));
    BOOST_CHECK_EQUAL(handoff.lease_until("dest"), static_cast<int64_t>(10));
    BOOST_CHECK(handoff.live("dest", 9));
    BOOST_CHECK(!handoff.live("dest", 10));

    BOOST_REQUIRE(handoff.Lease("edge", 1, 0, err));
    BOOST_CHECK(handoff.leased("edge"));
    BOOST_CHECK(handoff.live("edge", 0));
    BOOST_CHECK(!handoff.live("edge", 1));

    BOOST_CHECK(!handoff.Lease("dest", 10, 10, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffExpired);
    BOOST_CHECK(handoff.leased("dest"));
    BOOST_CHECK_EQUAL(handoff.lease_until("dest"), static_cast<int64_t>(10));
    ExpectQuiet(handoff);
}

BOOST_AUTO_TEST_CASE(refused_destination_stays_ambiguous)
{
    modelnet::SwarmHandoff handoff;
    std::string err = "prior";

    BOOST_REQUIRE(handoff.Intent("job", "body", err));
    BOOST_REQUIRE(handoff.Lease("dest", 10, 9, err));

    BOOST_CHECK(!handoff.Begin("missing", "dest", 10, 9, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffIntent);
    BOOST_CHECK(!handoff.open("missing"));

    BOOST_CHECK(!handoff.Begin("job", "other", 10, 9, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffExpired);
    BOOST_CHECK(!handoff.open("job"));

    BOOST_CHECK(!handoff.Begin("job", "dest", 10, 10, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffExpired);
    BOOST_CHECK(!handoff.open("job"));

    BOOST_REQUIRE(handoff.Begin("job", "dest", 10, 9, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(handoff.open("job"));
    BOOST_CHECK(!handoff.ambiguous("job"));
    BOOST_CHECK(!handoff.committed("job"));
    BOOST_CHECK(!handoff.atomic("job"));
    BOOST_CHECK(handoff.scoped());
    BOOST_CHECK_EQUAL(handoff.authority_destination(), "dest");
    BOOST_CHECK(handoff.authority_generation() != 0);
    BOOST_CHECK_EQUAL(handoff.owner(), modelnet::kSwarmHandoffSource);
    BOOST_CHECK(handoff.owner() != "dest");
    BOOST_CHECK_EQUAL(handoff.source_owner(), modelnet::kSwarmHandoffSource);
    BOOST_CHECK_EQUAL(handoff.effects(), 0);

    BOOST_CHECK(!handoff.Fence("job", false, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffAmbiguous);
    BOOST_CHECK(handoff.ambiguous("job"));
    BOOST_CHECK(!handoff.open("job"));
    BOOST_CHECK(!handoff.committed("job"));
    BOOST_CHECK(!handoff.atomic("job"));
    BOOST_CHECK(handoff.owner().empty());
    BOOST_CHECK(handoff.owner_of("job").empty());
    BOOST_CHECK(handoff.source_owner().empty());
    BOOST_CHECK_EQUAL(handoff.effects(), 1);

    BOOST_CHECK(!handoff.Fence("job", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffAmbiguous);
    BOOST_CHECK(handoff.ambiguous("job"));
    BOOST_CHECK(!handoff.committed("job"));
    BOOST_CHECK(!handoff.atomic("job"));
    BOOST_CHECK(handoff.owner().empty());
    BOOST_CHECK_EQUAL(handoff.effects(), 1);
    BOOST_CHECK_EQUAL(handoff.payload("job"), "body");
    ExpectQuiet(handoff);
}

BOOST_AUTO_TEST_CASE(committed_fence_gives_the_destination_ownership)
{
    modelnet::SwarmHandoff handoff;
    std::string err = "prior";

    BOOST_REQUIRE(handoff.Intent("job", "body", err));
    BOOST_REQUIRE(handoff.Lease("dest", 5, 4, err));
    BOOST_REQUIRE(handoff.Begin("job", "dest", 5, 4, err));
    BOOST_CHECK(handoff.owner() != "dest");

    BOOST_CHECK(!handoff.Fence("absent", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffHandoff);

    BOOST_REQUIRE(handoff.Fence("job", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(handoff.committed("job"));
    BOOST_CHECK(handoff.atomic("job"));
    BOOST_CHECK(!handoff.ambiguous("job"));
    BOOST_CHECK(!handoff.open("job"));
    BOOST_CHECK_EQUAL(handoff.owner(), "dest");
    BOOST_CHECK_EQUAL(handoff.owner_of("job"), "dest");
    BOOST_CHECK(handoff.source_owner().empty());
    BOOST_CHECK_EQUAL(handoff.effects(), 1);

    BOOST_CHECK(!handoff.Fence("job", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::kSwarmHandoffReplay);
    BOOST_CHECK_EQUAL(handoff.owner(), "dest");
    BOOST_CHECK_EQUAL(handoff.effects(), 1);
    BOOST_CHECK(!handoff.spend_key_moved());
    ExpectQuiet(handoff);
}

BOOST_AUTO_TEST_SUITE_END()
