// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_pages/nif_pages.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(nif_pages_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(window_position_page_and_absent_remote)
{
    modelnet::NifPages pages;
    std::string err;

    BOOST_CHECK(!pages.Bind("", "runtime-a", "realm-a", err));
    BOOST_CHECK_EQUAL(err, "FINGERPRINT");
    BOOST_CHECK_EQUAL(pages.cursor(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(pages.attention(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(pages.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!pages.Place(static_cast<int64_t>(4), static_cast<int64_t>(1), static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "WINDOW");
    BOOST_CHECK_EQUAL(pages.cursor(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(pages.attention(), static_cast<int64_t>(0));

    BOOST_CHECK(!pages.Place(static_cast<int64_t>(4), static_cast<int64_t>(5), static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "POSITION");
    BOOST_CHECK_EQUAL(pages.cursor(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(pages.attention(), static_cast<int64_t>(0));

    BOOST_CHECK(pages.Bind("model-a", "runtime-a", "realm-a", err));
    BOOST_CHECK(pages.Place(static_cast<int64_t>(4), static_cast<int64_t>(4), static_cast<int64_t>(2), err));
    BOOST_CHECK_EQUAL(pages.cursor(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(pages.attention(), static_cast<int64_t>(4));

    BOOST_CHECK(!pages.Place(static_cast<int64_t>(9), static_cast<int64_t>(1), static_cast<int64_t>(0), err));
    BOOST_CHECK_EQUAL(err, "WINDOW");
    BOOST_CHECK_EQUAL(pages.cursor(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(pages.attention(), static_cast<int64_t>(4));

    BOOST_CHECK(!pages.Place(static_cast<int64_t>(4), static_cast<int64_t>(5), static_cast<int64_t>(1), err));
    BOOST_CHECK_EQUAL(err, "POSITION");
    BOOST_CHECK_EQUAL(pages.cursor(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(pages.attention(), static_cast<int64_t>(4));

    BOOST_CHECK(!pages.MovePage({}, err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK_EQUAL(pages.bytes_moved(), static_cast<int64_t>(0));

    const std::vector<unsigned char> body{1, 2, 3, 4};
    BOOST_CHECK(pages.MovePage(body, err));
    BOOST_CHECK_EQUAL(pages.bytes_moved(), static_cast<int64_t>(4));

    const int64_t kept = pages.bytes_moved();
    BOOST_CHECK(!pages.MovePage({}, err));
    BOOST_CHECK_EQUAL(err, "PAGE");
    BOOST_CHECK_EQUAL(pages.bytes_moved(), kept);

    BOOST_CHECK(!pages.Remote("nixl", body, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(pages.bytes_moved(), kept);

    BOOST_CHECK(!pages.Remote("mooncake", body, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(pages.bytes_moved(), kept);

    BOOST_CHECK(!pages.Remote("rdma", body, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(pages.bytes_moved(), kept);

    BOOST_CHECK(!pages.all_rank_qualified());
    BOOST_CHECK(!pages.launched());
    BOOST_CHECK(!pages.gpu());
    BOOST_CHECK(!pages.broadcast());
    BOOST_CHECK_EQUAL(pages.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(pages.physical_hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_SUITE_END()
