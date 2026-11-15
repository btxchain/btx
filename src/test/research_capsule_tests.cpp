// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/research_capsule/research_capsule.h>
#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/training_integer.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

namespace {

void Idle(modelnet::ResearchCapsule& eng)
{
    std::string err;
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.broadcast());
    BOOST_CHECK(!eng.qualified_v41());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
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

BOOST_FIXTURE_TEST_SUITE(research_capsule_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_is_field)
{
    modelnet::ResearchCapsule eng;
    std::string err = "stale";
    BOOST_CHECK(!eng.Seal("", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(eng.Open("", err).empty());
    BOOST_CHECK_EQUAL(err, "CAPSULE");
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(modelnet::IntegerDataset().size()));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    Idle(eng);
}

BOOST_AUTO_TEST_CASE(seal_replay_pairs_and_release)
{
    modelnet::ResearchCapsule eng;
    std::string err = "stale";
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(modelnet::IntegerDataset().size()));

    modelnet::IntegerTrainer trainer;
    std::string step_err = "stale";
    BOOST_CHECK(trainer.Step(step_err));
    BOOST_CHECK(step_err.empty());
    const std::string expect = modelnet::IntegerStateHash(trainer.State());
    BOOST_CHECK(!expect.empty());

    BOOST_CHECK(eng.Seal("seal", err));
    BOOST_CHECK(err.empty());
    const std::string stored = eng.Open("seal", err);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(stored, expect);
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));

    BOOST_CHECK(!eng.Seal("seal", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(eng.Open("seal", err), expect);
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));

    const std::string missing = eng.Open("other", err);
    BOOST_CHECK(missing.empty());
    BOOST_CHECK_EQUAL(err, "CAPSULE");
    BOOST_CHECK_EQUAL(eng.Open("seal", err), expect);

    BOOST_CHECK(!eng.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK(!eng.gpu());
    BOOST_CHECK(!eng.Vendor(err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(eng.Open("seal", err), expect);
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK_EQUAL(err, "UNQUALIFIED");
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.qualified());
    BOOST_CHECK(!eng.qualified_v41());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.Open("seal", err), expect);
    BOOST_CHECK_EQUAL(eng.pairs(), static_cast<int64_t>(8));
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.physical_hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(err, "0");
    BOOST_CHECK_EQUAL(eng.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), "0");
    BOOST_CHECK(!eng.launched());
    BOOST_CHECK(!eng.broadcast());
    Idle(eng);
}

BOOST_AUTO_TEST_SUITE_END()
