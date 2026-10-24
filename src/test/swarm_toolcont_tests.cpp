// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_toolcont.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_toolcont_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_begin_stays_idle)
{
    modelnet::SwarmToolContinuation cont;
    std::string err = "prior";
    BOOST_CHECK(!cont.Begin("", err));
    BOOST_CHECK_EQUAL(err, "TOOL");
    BOOST_CHECK_EQUAL(cont.Code(), "TOOL");
    BOOST_CHECK(cont.State() == modelnet::SwarmToolState::Idle);
    BOOST_CHECK(!cont.ToolExecuted());
    BOOST_CHECK(!cont.BytesMoved());
}

BOOST_AUTO_TEST_CASE(interrupt_before_begin_is_tool)
{
    modelnet::SwarmToolContinuation cont;
    std::string err = "prior";
    BOOST_CHECK(!cont.Interrupt(err));
    BOOST_CHECK_EQUAL(err, "TOOL");
    BOOST_CHECK_EQUAL(cont.Code(), "TOOL");
    BOOST_CHECK(cont.State() == modelnet::SwarmToolState::Idle);
    BOOST_CHECK(!cont.ToolExecuted());
    BOOST_CHECK(!cont.BytesMoved());
}

BOOST_AUTO_TEST_CASE(continue_without_result_stays_tool_wait)
{
    modelnet::SwarmToolContinuation cont;
    std::string err = "prior";
    BOOST_REQUIRE(cont.Begin("gen-1", err));
    BOOST_CHECK(err.empty());
    BOOST_REQUIRE(cont.Interrupt(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(cont.State() == modelnet::SwarmToolState::ToolWait);

    BOOST_CHECK(!cont.Continue(false, false, err));
    BOOST_CHECK_EQUAL(err, "TOOL_REQUIRED");
    BOOST_CHECK_EQUAL(cont.Code(), "TOOL_REQUIRED");
    BOOST_CHECK(cont.State() == modelnet::SwarmToolState::ToolWait);
    BOOST_CHECK(!cont.ToolExecuted());
    BOOST_CHECK(!cont.BytesMoved());
}

BOOST_AUTO_TEST_CASE(context_change_is_invalidated)
{
    modelnet::SwarmToolContinuation cont;
    std::string err = "prior";
    BOOST_REQUIRE(cont.Begin("gen-1", err));
    BOOST_REQUIRE(cont.Interrupt(err));
    BOOST_CHECK(cont.State() == modelnet::SwarmToolState::ToolWait);

    BOOST_CHECK(!cont.Continue(true, true, err));
    BOOST_CHECK_EQUAL(err, "INVALIDATED");
    BOOST_CHECK_EQUAL(cont.Code(), "INVALIDATED");
    BOOST_CHECK(cont.State() == modelnet::SwarmToolState::Invalidated);
    BOOST_CHECK(!cont.ToolExecuted());
    BOOST_CHECK(!cont.BytesMoved());
}

BOOST_AUTO_TEST_CASE(continue_with_result_is_continued)
{
    modelnet::SwarmToolContinuation cont;
    std::string err = "prior";
    BOOST_CHECK(cont.Begin("gen-1", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cont.Code(), "GENERATING");
    BOOST_CHECK(cont.State() == modelnet::SwarmToolState::Generating);
    BOOST_CHECK(!cont.ToolExecuted());
    BOOST_CHECK(!cont.BytesMoved());

    BOOST_CHECK(cont.Interrupt(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cont.Code(), "TOOL_WAIT");
    BOOST_CHECK(cont.State() == modelnet::SwarmToolState::ToolWait);
    BOOST_CHECK(!cont.ToolExecuted());
    BOOST_CHECK(!cont.BytesMoved());

    BOOST_CHECK(cont.Continue(true, false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(cont.Code(), "CONTINUED");
    BOOST_CHECK(cont.State() == modelnet::SwarmToolState::Continued);
    BOOST_CHECK(!cont.ToolExecuted());
    BOOST_CHECK(!cont.BytesMoved());
}

BOOST_AUTO_TEST_SUITE_END()
