// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ckptsave/codes.h>
#include <modelnet/swarm_ckptsave/limits.h>
#include <modelnet/swarm_ckptsave/swarm_ckptsave.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_ckptsave_request_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(stored_request_stays_unsaved)
{
    modelnet::SwarmCheckpointSave plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.requested("ckpt-1"));
    BOOST_REQUIRE(plane.stored_name("ckpt-1").empty());
    BOOST_REQUIRE(plane.request_count() == 0);
    BOOST_REQUIRE(!plane.saved());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());

    BOOST_REQUIRE(!plane.Request("ckpt-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("ckpt-1"));
    BOOST_REQUIRE(plane.stored_name("ckpt-1") == "ckpt-1");
    BOOST_REQUIRE(plane.request_count() == 1);
    BOOST_REQUIRE(!plane.saved());
    BOOST_REQUIRE(plane.saved() == modelnet::kSwarmCkptSaveSaved);
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(plane.bytes_moved() == modelnet::kSwarmCkptSaveBytesMoved);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(plane.gpu() == modelnet::kSwarmCkptSaveGpu);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(plane.launched() == modelnet::kSwarmCkptSaveLaunched);
}

BOOST_AUTO_TEST_CASE(a_second_distinct_name_is_stored_beside_the_first)
{
    modelnet::SwarmCheckpointSave plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request("ckpt-1", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("ckpt-1"));
    BOOST_REQUIRE(plane.stored_name("ckpt-1") == "ckpt-1");
    BOOST_REQUIRE(!plane.saved());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("ckpt-2", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("ckpt-1"));
    BOOST_REQUIRE(plane.requested("ckpt-2"));
    BOOST_REQUIRE(plane.stored_name("ckpt-1") == "ckpt-1");
    BOOST_REQUIRE(plane.stored_name("ckpt-2") == "ckpt-2");
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.saved());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_CASE(space_and_code_word_are_stored_and_stay_unsaved)
{
    modelnet::SwarmCheckpointSave plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.Request(" ", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.stored_name(" ") == " ");
    BOOST_REQUIRE(!plane.saved());

    err = "prior";
    BOOST_REQUIRE(!plane.Request("CHECKPOINT", err));
    BOOST_REQUIRE(err == modelnet::kSwarmCkptSaveHeld);
    BOOST_REQUIRE_EQUAL(err, "HELD");
    BOOST_REQUIRE(plane.requested("CHECKPOINT"));
    BOOST_REQUIRE(plane.stored_name("CHECKPOINT") == "CHECKPOINT");
    BOOST_REQUIRE(plane.requested(" "));
    BOOST_REQUIRE(plane.request_count() == 2);
    BOOST_REQUIRE(!plane.saved());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE(!plane.launched());
}

BOOST_AUTO_TEST_SUITE_END()
