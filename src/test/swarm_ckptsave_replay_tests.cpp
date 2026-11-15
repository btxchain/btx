// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptsave/codes.h>
#include <modelnet/swarm_ckptsave/limits.h>
#include <modelnet/swarm_ckptsave/swarm_ckptsave.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_ckptsave_replay_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(second_request_of_the_same_name_is_replay)
{
    modelnet::SwarmCheckpointSave plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("ckpt-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("ckpt-1"));
    BOOST_REQUIRE(plane.stored_name("ckpt-1") == "ckpt-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.saved());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ckpt-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.requested("ckpt-1"));
    BOOST_REQUIRE(plane.stored_name("ckpt-1") == "ckpt-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.saved());
    BOOST_REQUIRE(plane.saved() == modelnet::kSwarmCkptSaveSaved);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ckpt-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.stored_name("ckpt-1") == "ckpt-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.saved());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(empty_name_is_checkpoint_before_replay)
{
    modelnet::SwarmCheckpointSave plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("ckpt-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");

    err = "prior";
    BOOST_REQUIRE(!plane.Request("", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveCheckpoint);
    BOOST_REQUIRE_EQUAL(err, "CHECKPOINT");
    BOOST_REQUIRE(plane.stored_name("ckpt-1") == "ckpt-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.saved());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first_when_another_name_is_stored)
{
    modelnet::SwarmCheckpointSave plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("ckpt-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ckpt-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ckpt-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveReplay);
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE(plane.requested("ckpt-1"));
    BOOST_REQUIRE(plane.requested("ckpt-2"));
    BOOST_REQUIRE(plane.stored_name("ckpt-1") == "ckpt-1");
    BOOST_REQUIRE(plane.stored_name("ckpt-2") == "ckpt-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.saved());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmCkptSaveBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
