// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/grp26/grp26.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::Grp26& eng)
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

BOOST_FIXTURE_TEST_SUITE(grp26_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(public_short_echo_stops_with_done)
{
    modelnet::Grp26 eng;
    std::string err = "prior";
    BOOST_CHECK(eng.Echo("s", "xy", err));
    BOOST_CHECK_EQUAL(err, "DONE");
    BOOST_CHECK_EQUAL(eng.text(), "xy");
    BOOST_CHECK(eng.text().size() <= static_cast<std::size_t>(8));
    BOOST_CHECK_EQUAL(eng.text().size(), static_cast<std::size_t>(2));
    BOOST_CHECK_EQUAL(eng.tokens(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.engine_of("s"), "memory");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.text(), "xy");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(public_prompt_longer_than_eight_stops_at_eight)
{
    modelnet::Grp26 eng;
    std::string err;
    BOOST_CHECK(eng.Echo("s", "abcdefghi", err));
    BOOST_CHECK_EQUAL(err, "DONE");
    BOOST_CHECK_EQUAL(eng.text(), "abcdefgh");
    BOOST_CHECK_EQUAL(eng.text().size(), static_cast<std::size_t>(8));
    BOOST_CHECK_EQUAL(eng.tokens(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.engine_of("s"), "memory");
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
    BOOST_CHECK_EQUAL(eng.text().size(), static_cast<std::size_t>(8));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(private_prompt_does_not_pull)
{
    modelnet::Grp26 eng;
    std::string err = "prior";
    BOOST_CHECK(!eng.Echo("s", "abcdefghi", true, err));
    BOOST_CHECK_EQUAL(err, "PRIVATE_DATA");
    BOOST_CHECK(eng.text().empty());
    BOOST_CHECK_EQUAL(eng.text().size(), static_cast<std::size_t>(0));
    BOOST_CHECK_EQUAL(eng.tokens(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.engine_of("s"), "memory");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
    BOOST_CHECK(eng.text().empty());
    BOOST_CHECK_EQUAL(eng.tokens(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(one_integer_step_then_another)
{
    modelnet::Grp26 eng;
    std::string err = "prior";
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(modelnet::IntegerDataset().size()), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(modelnet::IntegerDataset().size()));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Step(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().cursor), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.State().state_hash.empty());
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK(!eng.gpu());
    const modelnet::IntegerState after_one = eng.State();
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(after_one.step));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().cursor), static_cast<int64_t>(after_one.cursor));
    BOOST_CHECK_EQUAL(eng.State().weight, after_one.weight);
    BOOST_CHECK_EQUAL(eng.State().bias, after_one.bias);
    BOOST_CHECK_EQUAL(eng.State().momentum_w, after_one.momentum_w);
    BOOST_CHECK_EQUAL(eng.State().momentum_b, after_one.momentum_b);
    BOOST_CHECK_EQUAL(eng.State().state_hash, after_one.state_hash);
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK(eng.Step(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().cursor), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(modelnet::IntegerDataset().size()), static_cast<int64_t>(8));
    const modelnet::IntegerState after_two = eng.State();
    Idle(eng);
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(after_two.step));
    BOOST_CHECK_EQUAL(eng.State().state_hash, after_two.state_hash);
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(gpu_absent_leaves_unstepped_state)
{
    modelnet::Grp26 eng;
    std::string err = "prior";
    const modelnet::IntegerState before = eng.State();
    BOOST_CHECK_EQUAL(static_cast<int64_t>(before.step), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().cursor), static_cast<int64_t>(before.cursor));
    BOOST_CHECK_EQUAL(eng.State().weight, before.weight);
    BOOST_CHECK_EQUAL(eng.State().bias, before.bias);
    BOOST_CHECK_EQUAL(eng.State().state_hash, before.state_hash);
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(echo_and_step_stay_on_one_object)
{
    modelnet::Grp26 eng;
    std::string err;
    BOOST_CHECK(eng.Echo("s", "abcdefghi", err));
    BOOST_CHECK_EQUAL(err, "DONE");
    BOOST_CHECK_EQUAL(eng.text().size(), static_cast<std::size_t>(8));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Step(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text(), "abcdefgh");
    BOOST_CHECK_EQUAL(eng.text().size(), static_cast<std::size_t>(8));
    BOOST_CHECK_EQUAL(eng.tokens(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text().size(), static_cast<std::size_t>(8));
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    Idle(eng);
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.text().size(), static_cast<std::size_t>(8));
}

BOOST_AUTO_TEST_SUITE_END()
