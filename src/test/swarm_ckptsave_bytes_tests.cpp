// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptsave/codes.h>
#include <modelnet/swarm_ckptsave/limits.h>
#include <modelnet/swarm_ckptsave/swarm_ckptsave.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

namespace {

void RequireStill(const modelnet::SwarmCheckpointSave& plane)
{
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmCkptSaveBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmCkptSaveGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmCkptSaveLaunched);
    BOOST_REQUIRE(!plane.saved());
    BOOST_REQUIRE(plane.saved() == modelnet::kSwarmCkptSaveSaved);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_ckptsave_bytes_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(bytes_stay_zero)
{
    modelnet::SwarmCheckpointSave plane;
    std::string err = "prior";

    RequireStill(plane);

    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveCheckpoint);
    BOOST_REQUIRE_EQUAL(err, "CHECKPOINT");
    BOOST_REQUIRE(plane.request_count() == 0);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ckpt-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("ckpt-1"));
    BOOST_REQUIRE(plane.stored_name("ckpt-1") == "ckpt-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.saved());
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ckpt-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_name("ckpt-1") == "ckpt-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.saved());
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ckpt-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.stored_name("ckpt-2") == "ckpt-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    RequireStill(plane);

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveCheckpoint);
    BOOST_REQUIRE_EQUAL(err, "CHECKPOINT");
    BOOST_REQUIRE(plane.stored_name("ckpt-1") == "ckpt-1");
    BOOST_REQUIRE(plane.stored_name("ckpt-2") == "ckpt-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    RequireStill(plane);
}

BOOST_AUTO_TEST_SUITE_END()
