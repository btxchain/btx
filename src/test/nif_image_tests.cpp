// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_image/nif_image.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(nif_image_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(short_digest_is_digest)
{
    modelnet::NifImage image;
    std::string err;
    const std::string short_digest(63, 'a');
    const std::string pinned(64, 'b');

    BOOST_CHECK(!image.Bind(short_digest, "software", "model", err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK(image.current().empty());
    BOOST_CHECK_EQUAL(image.startup_downloads(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(image.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(image.Bind(pinned, "software", "model", err));
    BOOST_CHECK_EQUAL(image.current(), pinned);

    BOOST_CHECK(!image.Bind(short_digest, "software", "model", err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK_EQUAL(image.current(), pinned);

    const std::string upper(64, 'A');
    BOOST_CHECK(!image.Bind(upper, "software", "model", err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK_EQUAL(image.current(), pinned);
    BOOST_CHECK(!image.image_qualified());
}

BOOST_AUTO_TEST_CASE(equal_authorities_store_nothing)
{
    modelnet::NifImage image;
    std::string err;
    const std::string first(64, 'a');
    const std::string second(64, 'c');

    BOOST_CHECK(!image.Bind(first, "authority", "authority", err));
    BOOST_CHECK_EQUAL(err, "AUTHORITY");
    BOOST_CHECK(image.current().empty());

    BOOST_CHECK(!image.Bind(first, "", "model", err));
    BOOST_CHECK_EQUAL(err, "AUTHORITY");
    BOOST_CHECK(image.current().empty());

    BOOST_CHECK(image.Bind(first, "software", "model", err));
    BOOST_CHECK_EQUAL(image.current(), first);

    BOOST_CHECK(!image.Bind(second, "same", "same", err));
    BOOST_CHECK_EQUAL(err, "AUTHORITY");
    BOOST_CHECK_EQUAL(image.current(), first);
    BOOST_CHECK(!image.image_qualified());
}

BOOST_AUTO_TEST_CASE(two_digests_roll_back_to_the_first)
{
    modelnet::NifImage image;
    std::string err;
    const std::string first(64, 'a');
    const std::string second(64, 'b');

    BOOST_CHECK(image.Bind(first, "soft-1", "model-1", err));
    BOOST_CHECK_EQUAL(image.current(), first);
    BOOST_CHECK(!image.Rollback(err));
    BOOST_CHECK_EQUAL(err, "EMPTY");
    BOOST_CHECK_EQUAL(image.current(), first);

    BOOST_CHECK(image.Bind(second, "soft-2", "model-2", err));
    BOOST_CHECK_EQUAL(image.current(), second);
    BOOST_CHECK(image.Rollback(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(image.current(), first);

    BOOST_CHECK(!image.Rollback(err));
    BOOST_CHECK_EQUAL(err, "EMPTY");
    BOOST_CHECK_EQUAL(image.current(), first);
    BOOST_CHECK(!image.image_qualified());
    BOOST_CHECK_EQUAL(image.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(download_leaves_startup_downloads_at_zero)
{
    modelnet::NifImage image;
    std::string err;
    const std::string pinned(64, 'd');

    BOOST_CHECK(image.Bind(pinned, "software", "model", err));
    BOOST_CHECK(!image.Download("closed", err));
    BOOST_CHECK_EQUAL(err, "DOWNLOAD");
    BOOST_CHECK_EQUAL(image.startup_downloads(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(image.current(), pinned);
    BOOST_CHECK_EQUAL(image.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK(!image.image_qualified());
}

BOOST_AUTO_TEST_CASE(execute_is_engine_absent)
{
    modelnet::NifImage image;
    std::string err;
    const std::string pinned(64, 'e');

    BOOST_CHECK(image.Bind(pinned, "software", "model", err));
    BOOST_CHECK(!image.Execute(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(image.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(image.startup_downloads(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(image.current(), pinned);
    BOOST_CHECK(!image.image_qualified());
    BOOST_CHECK(!image.launched());
    BOOST_CHECK(!image.gpu());
    BOOST_CHECK(!image.broadcast());
    BOOST_CHECK_EQUAL(image.automatic_spend(), "0");
}

BOOST_AUTO_TEST_SUITE_END()
