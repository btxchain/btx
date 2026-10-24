// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_precision/dt_precision.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_precision_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(fp32_step_changes_master_and_fp8_does_not)
{
    modelnet::DtPrecision engine;
    BOOST_CHECK(std::fabs(engine.master() - 1.0) <= 1e-12);
    BOOST_CHECK_EQUAL(engine.profile(), modelnet::DT_PRECISION_FP32);
    BOOST_CHECK_EQUAL(engine.master_precision(), modelnet::DT_PRECISION_FP32);
    BOOST_CHECK(!engine.training_proved());
    BOOST_CHECK(!engine.low_precision_cache());
    BOOST_CHECK(!engine.gpu());
    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.broadcast());
    BOOST_CHECK_EQUAL(engine.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(engine.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.atoms_moved(), static_cast<int64_t>(0));

    std::string err = "prior";
    BOOST_CHECK(engine.SetProfile(modelnet::DT_PRECISION_FP32, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(engine.StepFp32(0.5, 0.1, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(std::fabs(engine.master() - 0.95) <= 1e-12);
    BOOST_CHECK(std::fabs(engine.master() - 1.0) > 1e-12);
    BOOST_CHECK(engine.training_proved());
    BOOST_CHECK_EQUAL(engine.master_precision(), "fp32");

    const double stepped = engine.master();
    BOOST_CHECK(!engine.SetProfile(modelnet::DT_PRECISION_FP8, err));
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(std::fabs(engine.master() - stepped) <= 1e-12);
    BOOST_CHECK(std::fabs(engine.master() - 0.95) <= 1e-12);
    BOOST_CHECK_EQUAL(engine.profile(), modelnet::DT_PRECISION_FP32);
    BOOST_CHECK(engine.training_proved());

    BOOST_CHECK(!engine.SetProfile(modelnet::DT_PRECISION_FP4, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(std::fabs(engine.master() - 0.95) <= 1e-12);
    BOOST_CHECK_EQUAL(engine.profile(), "fp32");

    BOOST_CHECK(!engine.SetProfile("int8", err));
    BOOST_CHECK_EQUAL(err, "PROFILE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_PRECISION_PROFILE);
    BOOST_CHECK(std::fabs(engine.master() - 0.95) <= 1e-12);
    BOOST_CHECK_EQUAL(engine.profile(), modelnet::DT_PRECISION_FP32);
    BOOST_CHECK_EQUAL(engine.master_precision(), modelnet::DT_PRECISION_FP32);

    BOOST_CHECK(!engine.gpu());
    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.broadcast());
    BOOST_CHECK_EQUAL(engine.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.atoms_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(bf16_then_step_fp32_is_refused)
{
    modelnet::DtPrecision engine;
    std::string err = "prior";
    BOOST_CHECK(std::fabs(engine.master() - 1.0) <= 1e-12);
    BOOST_CHECK(engine.SetProfile(modelnet::DT_PRECISION_BF16, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(engine.profile(), "bf16");
    BOOST_CHECK_EQUAL(engine.master_precision(), modelnet::DT_PRECISION_FP32);

    BOOST_CHECK(!engine.StepFp32(0.5, 0.1, err));
    BOOST_CHECK_EQUAL(err, "PROFILE");
    BOOST_CHECK_EQUAL(err, modelnet::DT_PRECISION_PROFILE);
    BOOST_CHECK(std::fabs(engine.master() - 1.0) <= 1e-12);
    BOOST_CHECK(!engine.training_proved());

    BOOST_CHECK(!engine.SetProfile("fp8", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(engine.profile(), modelnet::DT_PRECISION_BF16);
    BOOST_CHECK(std::fabs(engine.master() - 1.0) <= 1e-12);
    BOOST_CHECK(!engine.training_proved());

    BOOST_CHECK(!engine.SetProfile("fp4", err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(engine.profile(), "bf16");
    BOOST_CHECK(std::fabs(engine.master() - 1.0) <= 1e-12);

    BOOST_CHECK(!engine.SetProfile("", err));
    BOOST_CHECK_EQUAL(err, modelnet::DT_PRECISION_PROFILE);
    BOOST_CHECK_EQUAL(engine.profile(), modelnet::DT_PRECISION_BF16);
    BOOST_CHECK(std::fabs(engine.master() - 1.0) <= 1e-12);
    BOOST_CHECK(!engine.gpu());
    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.broadcast());
    BOOST_CHECK_EQUAL(engine.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.atoms_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(low_precision_cache_is_not_training_proof)
{
    modelnet::DtPrecision engine;
    std::string err = "prior";
    BOOST_CHECK(!engine.low_precision_cache());
    BOOST_CHECK(!engine.training_proved());
    BOOST_CHECK(engine.cache_tag().empty());

    BOOST_CHECK(engine.CacheLowPrecision(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(engine.low_precision_cache());
    BOOST_CHECK(!engine.training_proved());
    BOOST_CHECK(std::fabs(engine.master() - 1.0) <= 1e-12);
    BOOST_CHECK_EQUAL(engine.master_precision(), "fp32");
    BOOST_CHECK_EQUAL(engine.cache_tag(), "bf16");
    BOOST_CHECK_EQUAL(engine.cache_tag(), modelnet::DT_PRECISION_BF16);
    BOOST_CHECK_EQUAL(engine.profile(), modelnet::DT_PRECISION_FP32);

    BOOST_CHECK(!engine.gpu());
    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.broadcast());
    BOOST_CHECK_EQUAL(engine.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.atoms_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(engine.StepFp32(0.5, 0.1, err));
    BOOST_CHECK(std::fabs(engine.master() - 0.95) <= 1e-12);
    BOOST_CHECK(engine.low_precision_cache());
    BOOST_CHECK(engine.training_proved());
    BOOST_CHECK_EQUAL(engine.cache_tag(), modelnet::DT_PRECISION_BF16);
    BOOST_CHECK_EQUAL(engine.master_precision(), modelnet::DT_PRECISION_FP32);
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
