// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp25/grp25.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp25& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(grp25_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_session_is_session)
{
    modelnet::Grp25 eng;
    std::string err;
    BOOST_CHECK(!eng.Open("", "memory", err));
    BOOST_CHECK_EQUAL(err, "SESSION");
    BOOST_CHECK(eng.engine_of("").empty());
    BOOST_CHECK(eng.text().empty());
    BOOST_CHECK_EQUAL(eng.tokens(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.launched());
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(memory_engine_opens)
{
    modelnet::Grp25 eng;
    std::string err = "prior";
    BOOST_CHECK(eng.Open("s", "memory", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.engine_of("s"), "memory");
    BOOST_CHECK(eng.text().empty());
    BOOST_CHECK_EQUAL(eng.tokens(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(vllm_pull_is_engine_absent)
{
    modelnet::Grp25 eng;
    std::string err;
    BOOST_CHECK(eng.Open("s", "vllm", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.engine_of("s"), "vllm");
    BOOST_CHECK(eng.Prompt("s", "abcdefghi", false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Pull("s", err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(eng.text().empty());
    BOOST_CHECK_EQUAL(eng.text().size(), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(eng.tokens(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(private_prompt_is_private_data)
{
    modelnet::Grp25 eng;
    std::string err;
    BOOST_CHECK(eng.Open("s", "memory", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.Prompt("s", "abcdefghi", true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(eng.text().empty());
    BOOST_CHECK_EQUAL(eng.tokens(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.engine_of("s"), "memory");
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(public_prompt_pulls_until_done)
{
    modelnet::Grp25 eng;
    std::string err;
    BOOST_CHECK(eng.Open("s", "memory", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.engine_of("s"), "memory");
    BOOST_CHECK(eng.Prompt("s", "abcdefghi", false, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.text().empty());
    BOOST_CHECK_EQUAL(eng.tokens(), static_cast<int64_t>(0));
    int steps = 0;
    while (eng.Pull("s", err)) {
        ++steps;
        if (steps > 8) break;
    }
    BOOST_CHECK_EQUAL(steps, 8);
    BOOST_CHECK_EQUAL(err, "DONE");
    BOOST_CHECK_EQUAL(eng.text(), "abcdefgh");
    BOOST_CHECK_EQUAL(eng.text().size(), static_cast<std::size_t>(8));
    BOOST_CHECK_EQUAL(eng.tokens(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
