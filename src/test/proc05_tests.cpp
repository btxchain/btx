// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/proc05/proc05.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(proc05_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(local_affine_updates)
{
    modelnet::Proc05 eng;
    int64_t output = static_cast<int64_t>(99);
    std::string err = "stale";
    BOOST_CHECK(eng.Run("", true, static_cast<int64_t>(4), output, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.ran());
    BOOST_CHECK_EQUAL(output, static_cast<int64_t>(13));
    BOOST_CHECK_EQUAL(eng.last_output(), static_cast<int64_t>(13));

    BOOST_CHECK(eng.Run("", true, static_cast<int64_t>(0), output, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.ran());
    BOOST_CHECK_EQUAL(output, static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.last_output(), static_cast<int64_t>(1));

    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_CASE(provider_key_skips_output)
{
    modelnet::Proc05 eng;
    int64_t output = static_cast<int64_t>(99);
    std::string err = "stale";
    BOOST_CHECK(!eng.Run("sk", false, static_cast<int64_t>(-1), output, err));
    BOOST_CHECK_EQUAL(err, "PROVIDER");
    BOOST_CHECK_EQUAL(output, static_cast<int64_t>(99));
    BOOST_CHECK(!eng.ran());
    BOOST_CHECK_EQUAL(eng.last_output(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(missing_weights_skips_output)
{
    modelnet::Proc05 eng;
    int64_t output = static_cast<int64_t>(99);
    std::string err = "stale";
    BOOST_CHECK(!eng.Run("", false, static_cast<int64_t>(4), output, err));
    BOOST_CHECK_EQUAL(err, "MODEL");
    BOOST_CHECK_EQUAL(output, static_cast<int64_t>(99));
    BOOST_CHECK(!eng.ran());
    BOOST_CHECK_EQUAL(eng.last_output(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(negative_input_skips_output)
{
    modelnet::Proc05 eng;
    int64_t output = static_cast<int64_t>(99);
    std::string err = "stale";
    BOOST_CHECK(!eng.Run("", true, static_cast<int64_t>(-1), output, err));
    BOOST_CHECK_EQUAL(err, "BOUND");
    BOOST_CHECK_EQUAL(output, static_cast<int64_t>(99));
    BOOST_CHECK(!eng.ran());
    BOOST_CHECK_EQUAL(eng.last_output(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
