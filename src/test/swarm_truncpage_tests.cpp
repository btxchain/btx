// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_truncpage.h>
#include <cstdint>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_truncpage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_id_bad_expected_or_negative_received_is_page)
{
    std::string err = "prior";
    modelnet::SwarmTruncatedPage missing_id;
    missing_id.expected_bytes = 4096;
    missing_id.received_bytes = 4096;
    missing_id.compatible = true;
    const modelnet::SwarmTruncatedPageResult no_id = modelnet::SwarmNoteTruncatedPage(missing_id, err);
    BOOST_CHECK(!no_id.reusable);
    BOOST_CHECK(!no_id.bytes_moved);
    BOOST_CHECK_EQUAL(no_id.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");

    modelnet::SwarmTruncatedPage zero_expected;
    zero_expected.page_id = "page-a";
    zero_expected.expected_bytes = 0;
    zero_expected.received_bytes = 0;
    zero_expected.compatible = true;
    const modelnet::SwarmTruncatedPageResult no_expected = modelnet::SwarmNoteTruncatedPage(zero_expected, err);
    BOOST_CHECK(!no_expected.reusable);
    BOOST_CHECK(!no_expected.bytes_moved);
    BOOST_CHECK_EQUAL(no_expected.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");

    modelnet::SwarmTruncatedPage negative_expected;
    negative_expected.page_id = "page-a";
    negative_expected.expected_bytes = -1;
    negative_expected.received_bytes = 1;
    negative_expected.compatible = true;
    const modelnet::SwarmTruncatedPageResult bad_expected = modelnet::SwarmNoteTruncatedPage(negative_expected, err);
    BOOST_CHECK(!bad_expected.reusable);
    BOOST_CHECK(!bad_expected.bytes_moved);
    BOOST_CHECK_EQUAL(bad_expected.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");

    modelnet::SwarmTruncatedPage negative_received;
    negative_received.page_id = "page-a";
    negative_received.expected_bytes = 4096;
    negative_received.received_bytes = -1;
    negative_received.compatible = true;
    const modelnet::SwarmTruncatedPageResult bad_received = modelnet::SwarmNoteTruncatedPage(negative_received, err);
    BOOST_CHECK(!bad_received.reusable);
    BOOST_CHECK(!bad_received.bytes_moved);
    BOOST_CHECK_EQUAL(bad_received.code, "PAGE");
    BOOST_CHECK_EQUAL(err, "PAGE");
}

BOOST_AUTO_TEST_CASE(unequal_length_is_truncated_even_when_compatible)
{
    std::string err = "prior";
    modelnet::SwarmTruncatedPage short_page;
    short_page.page_id = "page-a";
    short_page.expected_bytes = 4096;
    short_page.received_bytes = 1024;
    short_page.compatible = true;
    const modelnet::SwarmTruncatedPageResult result = modelnet::SwarmNoteTruncatedPage(short_page, err);
    BOOST_CHECK(!result.reusable);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "TRUNCATED");
    BOOST_CHECK_EQUAL(err, "TRUNCATED");

    short_page.compatible = false;
    const modelnet::SwarmTruncatedPageResult still_truncated = modelnet::SwarmNoteTruncatedPage(short_page, err);
    BOOST_CHECK(!still_truncated.reusable);
    BOOST_CHECK(!still_truncated.bytes_moved);
    BOOST_CHECK_EQUAL(still_truncated.code, "TRUNCATED");
    BOOST_CHECK_EQUAL(err, "TRUNCATED");

    modelnet::SwarmTruncatedPage extra;
    extra.page_id = "page-a";
    extra.expected_bytes = 4096;
    extra.received_bytes = 8192;
    extra.compatible = true;
    const modelnet::SwarmTruncatedPageResult over = modelnet::SwarmNoteTruncatedPage(extra, err);
    BOOST_CHECK(!over.reusable);
    BOOST_CHECK(!over.bytes_moved);
    BOOST_CHECK_EQUAL(over.code, "TRUNCATED");
    BOOST_CHECK_EQUAL(err, "TRUNCATED");
}

BOOST_AUTO_TEST_CASE(matching_length_without_compat_is_incompatible)
{
    std::string err = "prior";
    modelnet::SwarmTruncatedPage page;
    page.page_id = "page-a";
    page.expected_bytes = 4096;
    page.received_bytes = 4096;
    page.compatible = false;
    const modelnet::SwarmTruncatedPageResult result = modelnet::SwarmNoteTruncatedPage(page, err);
    BOOST_CHECK(!result.reusable);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
}

BOOST_AUTO_TEST_CASE(held_is_not_reusable_and_moves_no_bytes)
{
    std::string err = "prior";
    modelnet::SwarmTruncatedPage page;
    page.page_id = "page-a";
    page.expected_bytes = 4096;
    page.received_bytes = 4096;
    page.compatible = true;
    const modelnet::SwarmTruncatedPageResult result = modelnet::SwarmNoteTruncatedPage(page, err);
    BOOST_CHECK(!result.reusable);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
