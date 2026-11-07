// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_agentrun/swarm_agentrun.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstddef>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(swarm_agentrun_dag_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_plane_moves_nothing)
{
    modelnet::SwarmAgentRun plane;
    BOOST_REQUIRE_EQUAL(plane.task_count(), 0u);
    BOOST_REQUIRE(!plane.has_task("root"));
    BOOST_REQUIRE(plane.parent_of("root").empty());
    BOOST_REQUIRE(plane.capability_of("root").empty());
    BOOST_REQUIRE(plane.children_of("root").empty());
    BOOST_REQUIRE(plane.Trace().empty());
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(empty_id_is_task_and_stores_nothing)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.AddTask("", "", "plan", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE_EQUAL(plane.task_count(), 0u);
    BOOST_REQUIRE(!plane.has_task(""));
    BOOST_REQUIRE(plane.Trace().empty());

    err = "prior";
    BOOST_REQUIRE(!plane.AddTask("", "root", "plan", err));
    BOOST_REQUIRE_EQUAL(err, "TASK");
    BOOST_REQUIRE_EQUAL(plane.task_count(), 0u);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_CASE(unknown_parent_is_dependency_and_stores_nothing)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(!plane.AddTask("child", "missing", "draft", err));
    BOOST_REQUIRE_EQUAL(err, "DEPENDENCY");
    BOOST_REQUIRE(!plane.has_task("child"));
    BOOST_REQUIRE(!plane.has_task("missing"));
    BOOST_REQUIRE_EQUAL(plane.task_count(), 0u);
    BOOST_REQUIRE(plane.Trace().empty());

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    BOOST_REQUIRE(err.empty());
    err = "prior";
    BOOST_REQUIRE(!plane.AddTask("child", "other", "draft", err));
    BOOST_REQUIRE_EQUAL(err, "DEPENDENCY");
    BOOST_REQUIRE_EQUAL(plane.task_count(), 1u);
    BOOST_REQUIRE(plane.children_of("root").empty());
    BOOST_REQUIRE_EQUAL(plane.Trace().size(), 1u);
    BOOST_REQUIRE_EQUAL(plane.Trace().at(0), "AddTask");
}

BOOST_AUTO_TEST_CASE(empty_parent_is_a_root_and_duplicate_keeps_the_first)
{
    modelnet::SwarmAgentRun plane;
    std::string err = "prior";

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.has_task("root"));
    BOOST_REQUIRE(plane.parent_of("root").empty());
    BOOST_REQUIRE_EQUAL(plane.capability_of("root"), "plan");
    BOOST_REQUIRE(plane.children_of("root").empty());
    BOOST_REQUIRE_EQUAL(plane.task_count(), 1u);

    BOOST_REQUIRE(plane.AddTask("other", "", "", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE(plane.parent_of("other").empty());
    BOOST_REQUIRE(plane.capability_of("other").empty());
    BOOST_REQUIRE_EQUAL(plane.task_count(), 2u);

    err = "prior";
    BOOST_REQUIRE(!plane.AddTask("root", "", "replaced", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.capability_of("root"), "plan");
    BOOST_REQUIRE(plane.parent_of("root").empty());
    BOOST_REQUIRE_EQUAL(plane.task_count(), 2u);

    err = "prior";
    BOOST_REQUIRE(!plane.AddTask("root", "missing", "replaced", err));
    BOOST_REQUIRE_EQUAL(err, "DEPENDENCY");
    BOOST_REQUIRE_EQUAL(plane.capability_of("root"), "plan");
    BOOST_REQUIRE(plane.parent_of("root").empty());
    BOOST_REQUIRE(!plane.has_task("missing"));
    BOOST_REQUIRE_EQUAL(plane.task_count(), 2u);

    const std::vector<std::string> trace = plane.Trace();
    BOOST_REQUIRE_EQUAL(trace.size(), 2u);
    BOOST_REQUIRE_EQUAL(trace[0], "AddTask");
    BOOST_REQUIRE_EQUAL(trace[1], "AddTask");
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE(!plane.gpu());
    BOOST_REQUIRE_EQUAL(plane.automatic_spend(), "0");
}

BOOST_AUTO_TEST_CASE(root_with_two_children_keeps_insert_order)
{
    modelnet::SwarmAgentRun plane;
    std::string err;

    BOOST_REQUIRE(plane.AddTask("root", "", "plan", err));
    BOOST_REQUIRE(plane.AddTask("left", "root", "draft", err));
    BOOST_REQUIRE(plane.AddTask("right", "root", "review", err));
    BOOST_REQUIRE_EQUAL(plane.task_count(), 3u);
    BOOST_REQUIRE_EQUAL(plane.parent_of("left"), "root");
    BOOST_REQUIRE_EQUAL(plane.parent_of("right"), "root");
    BOOST_REQUIRE_EQUAL(plane.capability_of("left"), "draft");
    BOOST_REQUIRE_EQUAL(plane.capability_of("right"), "review");

    const std::vector<std::string> children = plane.children_of("root");
    BOOST_REQUIRE_EQUAL(children.size(), 2u);
    BOOST_REQUIRE_EQUAL(children[0], "left");
    BOOST_REQUIRE_EQUAL(children[1], "right");
    BOOST_REQUIRE(plane.children_of("left").empty());
    BOOST_REQUIRE(plane.children_of("right").empty());

    err = "prior";
    BOOST_REQUIRE(!plane.AddTask("left", "root", "other", err));
    BOOST_REQUIRE_EQUAL(err, "REPLAY");
    BOOST_REQUIRE_EQUAL(plane.capability_of("left"), "draft");
    BOOST_REQUIRE_EQUAL(plane.children_of("root").size(), 2u);
    BOOST_REQUIRE_EQUAL(plane.task_count(), 3u);

    BOOST_REQUIRE(plane.AddTask("leaf", "left", "note", err));
    BOOST_REQUIRE(err.empty());
    BOOST_REQUIRE_EQUAL(plane.parent_of("leaf"), "left");
    BOOST_REQUIRE_EQUAL(plane.children_of("left").size(), 1u);
    BOOST_REQUIRE_EQUAL(plane.children_of("left").at(0), "leaf");
    BOOST_REQUIRE_EQUAL(plane.task_count(), 4u);

    err = "prior";
    BOOST_REQUIRE(!plane.AddTask("loop", "loop", "cap", err));
    BOOST_REQUIRE_EQUAL(err, "DEPENDENCY");
    BOOST_REQUIRE(!plane.has_task("loop"));
    BOOST_REQUIRE_EQUAL(plane.Trace().size(), 4u);
    BOOST_REQUIRE(!plane.launched());
    BOOST_REQUIRE_EQUAL(plane.bytes_moved(), 0);
    BOOST_REQUIRE_EQUAL(plane.atoms_moved(), 0);
    BOOST_REQUIRE(!plane.broadcast());
}

BOOST_AUTO_TEST_SUITE_END()
