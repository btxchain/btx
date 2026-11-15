// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_ownergone.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(swarm_ownergone_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_page_id_or_owner_id_is_cache)
{
    std::string err = "prior";
    modelnet::SwarmCacheOwnerRequest missing_page;
    missing_page.owner_id = "owner-a";
    missing_page.owner_present = true;
    missing_page.transfer_requested = true;
    const modelnet::SwarmCacheOwnerResult no_page = modelnet::SwarmNoteCacheOwner(missing_page, err);
    BOOST_CHECK(!no_page.noted);
    BOOST_CHECK(!no_page.bytes_moved);
    BOOST_CHECK_EQUAL(no_page.code, "CACHE");
    BOOST_CHECK_EQUAL(err, "CACHE");

    modelnet::SwarmCacheOwnerRequest missing_owner;
    missing_owner.page_id = "page-a";
    missing_owner.owner_present = true;
    missing_owner.transfer_requested = true;
    const modelnet::SwarmCacheOwnerResult no_owner = modelnet::SwarmNoteCacheOwner(missing_owner, err);
    BOOST_CHECK(!no_owner.noted);
    BOOST_CHECK(!no_owner.bytes_moved);
    BOOST_CHECK_EQUAL(no_owner.code, "CACHE");
    BOOST_CHECK_EQUAL(err, "CACHE");

    modelnet::SwarmCacheOwnerRequest both_empty;
    both_empty.owner_present = false;
    both_empty.transfer_requested = true;
    const modelnet::SwarmCacheOwnerResult empty = modelnet::SwarmNoteCacheOwner(both_empty, err);
    BOOST_CHECK(!empty.noted);
    BOOST_CHECK(!empty.bytes_moved);
    BOOST_CHECK_EQUAL(empty.code, "CACHE");
    BOOST_CHECK_EQUAL(err, "CACHE");
}

BOOST_AUTO_TEST_CASE(absent_owner_wins_over_transfer_request)
{
    std::string err = "prior";
    modelnet::SwarmCacheOwnerRequest request;
    request.page_id = "page-a";
    request.owner_id = "owner-a";
    request.owner_present = false;
    request.transfer_requested = true;
    const modelnet::SwarmCacheOwnerResult with_transfer = modelnet::SwarmNoteCacheOwner(request, err);
    BOOST_CHECK(!with_transfer.noted);
    BOOST_CHECK(!with_transfer.bytes_moved);
    BOOST_CHECK_EQUAL(with_transfer.code, "OWNER_ABSENT");
    BOOST_CHECK_EQUAL(err, "OWNER_ABSENT");

    request.transfer_requested = false;
    const modelnet::SwarmCacheOwnerResult without_transfer = modelnet::SwarmNoteCacheOwner(request, err);
    BOOST_CHECK(!without_transfer.noted);
    BOOST_CHECK(!without_transfer.bytes_moved);
    BOOST_CHECK_EQUAL(without_transfer.code, "OWNER_ABSENT");
    BOOST_CHECK_EQUAL(err, "OWNER_ABSENT");
}

BOOST_AUTO_TEST_CASE(transfer_request_is_engine_absent)
{
    std::string err = "prior";
    modelnet::SwarmCacheOwnerRequest request;
    request.page_id = "page-a";
    request.owner_id = "owner-a";
    request.owner_present = true;
    request.transfer_requested = true;
    const modelnet::SwarmCacheOwnerResult result = modelnet::SwarmNoteCacheOwner(request, err);
    BOOST_CHECK(!result.noted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
}

BOOST_AUTO_TEST_CASE(noted_does_not_move_bytes)
{
    std::string err = "prior";
    modelnet::SwarmCacheOwnerRequest request;
    request.page_id = "page-a";
    request.owner_id = "owner-a";
    request.owner_present = true;
    request.transfer_requested = false;
    const modelnet::SwarmCacheOwnerResult result = modelnet::SwarmNoteCacheOwner(request, err);
    BOOST_CHECK(result.noted);
    BOOST_CHECK(!result.bytes_moved);
    BOOST_CHECK_EQUAL(result.code, "NOTED");
    BOOST_CHECK(err.empty());
}

BOOST_AUTO_TEST_SUITE_END()
