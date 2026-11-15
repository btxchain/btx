// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_winbook.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_winbook_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_check_id_is_check)
{
    modelnet::SwarmWinBook book;
    book.vm_running = true;
    book.guest_agent = true;
    book.passthrough = false;
    book.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmWinBookResult result = modelnet::SwarmRecordWindows(book, err);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.started, false);
    BOOST_CHECK_EQUAL(result.code, "CHECK");
    BOOST_CHECK_EQUAL(err, "CHECK");
}

BOOST_AUTO_TEST_CASE(passthrough_true_is_not_started)
{
    modelnet::SwarmWinBook book;
    book.check_id = "check-1";
    book.vm_running = true;
    book.guest_agent = true;
    book.passthrough = true;
    book.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmWinBookResult result = modelnet::SwarmRecordWindows(book, err);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.started, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_STARTED");
    BOOST_CHECK_EQUAL(err, "NOT_STARTED");
}

BOOST_AUTO_TEST_CASE(guest_agent_missing_is_not_passed)
{
    modelnet::SwarmWinBook book;
    book.check_id = "check-1";
    book.vm_running = true;
    book.guest_agent = false;
    book.passthrough = false;
    book.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmWinBookResult result = modelnet::SwarmRecordWindows(book, err);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.started, false);
    BOOST_CHECK_EQUAL(result.code, "NOT_PASSED");
    BOOST_CHECK_EQUAL(err, "NOT_PASSED");
}

BOOST_AUTO_TEST_CASE(vm_not_running_is_absent)
{
    modelnet::SwarmWinBook book;
    book.check_id = "check-1";
    book.vm_running = false;
    book.guest_agent = true;
    book.passthrough = false;
    book.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmWinBookResult result = modelnet::SwarmRecordWindows(book, err);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.started, false);
    BOOST_CHECK_EQUAL(result.code, "ABSENT");
    BOOST_CHECK_EQUAL(err, "ABSENT");
}

BOOST_AUTO_TEST_CASE(want_pass_true_is_held)
{
    modelnet::SwarmWinBook book;
    book.check_id = "check-1";
    book.vm_running = true;
    book.guest_agent = true;
    book.passthrough = false;
    book.want_pass = true;
    std::string err = "prior";
    const modelnet::SwarmWinBookResult result = modelnet::SwarmRecordWindows(book, err);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.started, false);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK_EQUAL(err, "HELD");
}

BOOST_AUTO_TEST_CASE(want_pass_false_is_noted)
{
    modelnet::SwarmWinBook book;
    book.check_id = "check-1";
    book.vm_running = true;
    book.guest_agent = true;
    book.passthrough = false;
    book.want_pass = false;
    std::string err = "prior";
    const modelnet::SwarmWinBookResult result = modelnet::SwarmRecordWindows(book, err);
    BOOST_CHECK_EQUAL(result.passed, false);
    BOOST_CHECK_EQUAL(result.started, false);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
