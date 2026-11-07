// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_kvshare.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(swarm_kvshare_tests, BasicTestingSetup)

static modelnet::SwarmKvShare NotedShare()
{
    modelnet::SwarmKvShare share;
    share.page_id = "kv-page";
    share.same_fingerprint = true;
    share.compatible = true;
    share.want_share = false;
    return share;
}

static void ExpectFlagsStayFalse(const modelnet::SwarmKvShareResult& result)
{
    BOOST_CHECK(!result.shared);
    BOOST_CHECK(!result.bytes_moved);
}

BOOST_AUTO_TEST_CASE(empty_page_id_is_kv)
{
    modelnet::SwarmKvShare share = NotedShare();
    share.page_id.clear();
    std::string err = "prior";
    const modelnet::SwarmKvShareResult result = modelnet::SwarmNoteKvShare(share, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "KV");
    BOOST_CHECK_EQUAL(err, "KV");
}

BOOST_AUTO_TEST_CASE(empty_page_id_wins_over_incompatible_and_want_share)
{
    modelnet::SwarmKvShare share = NotedShare();
    share.page_id.clear();
    share.same_fingerprint = false;
    share.compatible = false;
    share.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmKvShareResult result = modelnet::SwarmNoteKvShare(share, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "KV");
    BOOST_CHECK_EQUAL(err, "KV");
}

BOOST_AUTO_TEST_CASE(fingerprint_mismatch_is_incompatible)
{
    modelnet::SwarmKvShare share = NotedShare();
    share.same_fingerprint = false;
    share.compatible = true;
    share.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmKvShareResult result = modelnet::SwarmNoteKvShare(share, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
}

BOOST_AUTO_TEST_CASE(not_compatible_is_incompatible)
{
    modelnet::SwarmKvShare share = NotedShare();
    share.same_fingerprint = true;
    share.compatible = false;
    share.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmKvShareResult result = modelnet::SwarmNoteKvShare(share, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
}

BOOST_AUTO_TEST_CASE(both_match_flags_false_is_incompatible)
{
    modelnet::SwarmKvShare share = NotedShare();
    share.same_fingerprint = false;
    share.compatible = false;
    share.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmKvShareResult result = modelnet::SwarmNoteKvShare(share, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
}

BOOST_AUTO_TEST_CASE(fingerprint_mismatch_wins_when_want_share_is_true)
{
    modelnet::SwarmKvShare share = NotedShare();
    share.same_fingerprint = false;
    share.compatible = true;
    share.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmKvShareResult result = modelnet::SwarmNoteKvShare(share, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
}

BOOST_AUTO_TEST_CASE(not_compatible_wins_when_want_share_is_true)
{
    modelnet::SwarmKvShare share = NotedShare();
    share.same_fingerprint = true;
    share.compatible = false;
    share.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmKvShareResult result = modelnet::SwarmNoteKvShare(share, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "INCOMPATIBLE");
    BOOST_CHECK_EQUAL(err, "INCOMPATIBLE");
}

BOOST_AUTO_TEST_CASE(want_share_with_matching_page_is_held)
{
    modelnet::SwarmKvShare share = NotedShare();
    share.same_fingerprint = true;
    share.compatible = true;
    share.want_share = true;
    std::string err = "prior";
    const modelnet::SwarmKvShareResult result = modelnet::SwarmNoteKvShare(share, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK_EQUAL(result.code, "HELD");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_CASE(matching_page_without_want_share_is_noted)
{
    modelnet::SwarmKvShare share = NotedShare();
    share.same_fingerprint = true;
    share.compatible = true;
    share.want_share = false;
    std::string err = "prior";
    const modelnet::SwarmKvShareResult result = modelnet::SwarmNoteKvShare(share, err);
    ExpectFlagsStayFalse(result);
    BOOST_CHECK(share.same_fingerprint);
    BOOST_CHECK(share.compatible);
    BOOST_CHECK(!share.want_share);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
