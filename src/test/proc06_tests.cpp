// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/proc06/proc06.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(proc06_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(matching_fingerprint_copies_page)
{
    modelnet::Proc06 eng;
    const std::vector<unsigned char> page{1, 2, 3, 4};
    std::string err = "stale";
    BOOST_CHECK(eng.Exchange("page", "fp", page, "fp", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.bytes_copied(), static_cast<int64_t>(page.size()));
    BOOST_CHECK(eng.received() == page);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_CASE(other_fingerprint_copies_nothing)
{
    modelnet::Proc06 eng;
    const std::vector<unsigned char> page{1, 2, 3, 4};
    std::string err = "stale";
    BOOST_CHECK(!eng.Exchange("page", "fp", page, "other", err));
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(eng.bytes_copied(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.received().empty());

    BOOST_CHECK(!eng.Exchange("page", "", page, "fp", err));
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(eng.bytes_copied(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.received().empty());

    BOOST_CHECK(!eng.Exchange("page", "fp", page, "", err));
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(eng.bytes_copied(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.received().empty());
}

BOOST_AUTO_TEST_CASE(empty_page_id_copies_nothing)
{
    modelnet::Proc06 eng;
    const std::vector<unsigned char> page{1, 2, 3, 4};
    std::string err = "stale";
    BOOST_CHECK(!eng.Exchange("", "fp", page, "fp", err));
    BOOST_CHECK_EQUAL(err, "KV");
    BOOST_CHECK_EQUAL(eng.bytes_copied(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.received().empty());

    const std::vector<unsigned char> none;
    BOOST_CHECK(!eng.Exchange("", "fp", none, "fp", err));
    BOOST_CHECK_EQUAL(err, "KV");
    BOOST_CHECK_EQUAL(eng.bytes_copied(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.received().empty());
}

BOOST_AUTO_TEST_CASE(empty_page_copies_nothing)
{
    modelnet::Proc06 eng;
    const std::vector<unsigned char> page;
    std::string err = "stale";
    BOOST_CHECK(!eng.Exchange("page", "fp", page, "fp", err));
    BOOST_CHECK_EQUAL(err, "EMPTY");
    BOOST_CHECK_EQUAL(eng.bytes_copied(), static_cast<int64_t>(0));
    BOOST_CHECK(eng.received().empty());
}

BOOST_AUTO_TEST_CASE(replay_keeps_first_page)
{
    modelnet::Proc06 eng;
    const std::vector<unsigned char> page{1, 2, 3, 4};
    const std::vector<unsigned char> later{9, 9, 9};
    std::string err = "stale";
    BOOST_CHECK(eng.Exchange("page", "fp", page, "fp", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.bytes_copied(), static_cast<int64_t>(page.size()));

    BOOST_CHECK(!eng.Exchange("page", "fp", page, "other", err));
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
    BOOST_CHECK(eng.received() == page);
    BOOST_CHECK_EQUAL(eng.bytes_copied(), static_cast<int64_t>(page.size()));

    BOOST_CHECK(!eng.Exchange("page", "fp", later, "fp", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(eng.received() == page);
    BOOST_CHECK_EQUAL(eng.bytes_copied(), static_cast<int64_t>(page.size()));
}

BOOST_AUTO_TEST_SUITE_END()
