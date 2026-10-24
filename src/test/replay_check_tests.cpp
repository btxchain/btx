// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/replay_check/replay_check.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::ReplayCheck& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified_v41());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(replay_check_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(zero_steps_is_steps)
{
    modelnet::ReplayCheck eng;
    std::string err = "prior";
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(modelnet::IntegerDataset().size()));
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.Run(0, err));
    BOOST_CHECK_EQUAL(err, "STEPS");
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.Stored().step), static_cast<int64_t>(0));
    BOOST_CHECK(eng.Stored().state_hash.empty());
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!eng.qualified_v41());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.broadcast());
    Idle(eng);
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
}

BOOST_AUTO_TEST_CASE(one_step_replay_matches)
{
    modelnet::ReplayCheck eng;
    std::string err = "prior";
    BOOST_CHECK(eng.Run(1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().cursor), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.Stored().step), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.State().state_hash, eng.Stored().state_hash);
    BOOST_CHECK_EQUAL(eng.State().weight, eng.Stored().weight);
    BOOST_CHECK_EQUAL(eng.State().bias, eng.Stored().bias);
    BOOST_CHECK_EQUAL(eng.State().momentum_w, eng.Stored().momentum_w);
    BOOST_CHECK_EQUAL(eng.State().momentum_b, eng.Stored().momentum_b);
    BOOST_CHECK(!eng.State().state_hash.empty());
    BOOST_CHECK(eng.Check(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(modelnet::IntegerDataset().size()));

    modelnet::IntegerTrainer fresh;
    std::string replay_err = "prior";
    BOOST_CHECK(fresh.Run(1, replay_err));
    BOOST_CHECK(fresh.ReplayMatches(eng.Stored(), replay_err));
    BOOST_CHECK(replay_err.empty());
    BOOST_CHECK_EQUAL(static_cast<int64_t>(fresh.State().step), static_cast<int64_t>(eng.State().step));
    BOOST_CHECK_EQUAL(fresh.State().state_hash, eng.State().state_hash);

    const modelnet::IntegerState after = eng.State();
    const std::string stored_hash = eng.Stored().state_hash;
    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(after.step));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().cursor), static_cast<int64_t>(after.cursor));
    BOOST_CHECK_EQUAL(eng.State().weight, after.weight);
    BOOST_CHECK_EQUAL(eng.State().bias, after.bias);
    BOOST_CHECK_EQUAL(eng.State().momentum_w, after.momentum_w);
    BOOST_CHECK_EQUAL(eng.State().momentum_b, after.momentum_b);
    BOOST_CHECK_EQUAL(eng.State().state_hash, after.state_hash);
    BOOST_CHECK_EQUAL(eng.Stored().state_hash, stored_hash);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK(!eng.qualified_v41());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.broadcast());
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.State().state_hash, after.state_hash);
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.Stored().state_hash, stored_hash);
    BOOST_CHECK(eng.Check(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
}

BOOST_AUTO_TEST_CASE(tampered_hash_is_id_mismatch)
{
    modelnet::ReplayCheck eng;
    std::string err = "prior";
    BOOST_CHECK(eng.Run(1, err));
    BOOST_CHECK(eng.Check(err));
    BOOST_CHECK(err.empty());
    const modelnet::IntegerState trainer_before = eng.State();
    BOOST_CHECK_EQUAL(static_cast<int64_t>(trainer_before.step), static_cast<int64_t>(1));
    BOOST_CHECK(!trainer_before.state_hash.empty());

    BOOST_CHECK(!eng.Tamper(err));
    BOOST_CHECK_EQUAL(err, "BTX035_ID_MISMATCH");
    BOOST_CHECK_EQUAL(eng.Stored().state_hash, "bad");
    BOOST_CHECK_EQUAL(eng.State().state_hash, trainer_before.state_hash);
    BOOST_CHECK_EQUAL(eng.State().weight, trainer_before.weight);
    BOOST_CHECK_EQUAL(eng.State().bias, trainer_before.bias);
    BOOST_CHECK_EQUAL(eng.State().momentum_w, trainer_before.momentum_w);
    BOOST_CHECK_EQUAL(eng.State().momentum_b, trainer_before.momentum_b);
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(trainer_before.step));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().cursor), static_cast<int64_t>(trainer_before.cursor));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.Stored().step), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.Stored().weight, trainer_before.weight);

    modelnet::IntegerTrainer fresh;
    std::string replay_err = "prior";
    BOOST_CHECK(fresh.Run(1, replay_err));
    BOOST_CHECK(fresh.ReplayMatches(eng.State(), replay_err));
    BOOST_CHECK(replay_err.empty());
    BOOST_CHECK(!fresh.ReplayMatches(eng.Stored(), replay_err));
    BOOST_CHECK_EQUAL(replay_err, "BTX035_ID_MISMATCH");
    BOOST_CHECK(!eng.Check(err));
    BOOST_CHECK_EQUAL(err, "BTX035_ID_MISMATCH");
    BOOST_CHECK_EQUAL(eng.State().state_hash, trainer_before.state_hash);

    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.State().state_hash, trainer_before.state_hash);
    BOOST_CHECK_EQUAL(eng.Stored().state_hash, "bad");
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK(!eng.qualified_v41());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK_EQUAL(eng.hosts(), 1);
    BOOST_CHECK_EQUAL(eng.physical_hosts(), 1);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(static_cast<int64_t>(modelnet::IntegerDataset().size()), static_cast<int64_t>(8));
    Idle(eng);
    BOOST_CHECK_EQUAL(eng.State().state_hash, trainer_before.state_hash);
    BOOST_CHECK_EQUAL(eng.Stored().state_hash, "bad");
    BOOST_CHECK_EQUAL(static_cast<int64_t>(eng.State().step), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_SUITE_END()
