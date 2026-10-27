// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_parentage/swarm_parentage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

static void ExpectFrozenInspectors(const modelnet::SwarmParentage& book)
{
    BOOST_CHECK(!book.trusted());
    BOOST_CHECK(!book.realm_promoted());
    BOOST_CHECK(!book.exact_replay_admitted());
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
    BOOST_CHECK_EQUAL(book.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_FIXTURE_TEST_SUITE(swarm_parentage_hub_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_card_stores_nothing)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_CHECK(!book.Hub("ckpt-a", "", err));
    BOOST_CHECK_EQUAL(err, "CARD");
    BOOST_CHECK(!book.bound("ckpt-a"));
    BOOST_CHECK(book.parent_of("ckpt-a").empty());
    BOOST_CHECK(!book.Hub("", "", err));
    BOOST_CHECK_EQUAL(err, "CARD");
    BOOST_CHECK(!book.bound(""));
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_CASE(card_is_not_authority)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_CHECK(!book.Hub("ckpt-a", "card-1", err));
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
    BOOST_CHECK(!book.bound("ckpt-a"));
    BOOST_CHECK(book.parent_of("ckpt-a").empty());
    BOOST_CHECK(book.recipe_of("ckpt-a").empty());
    BOOST_CHECK(book.dataset_of("ckpt-a").empty());
    BOOST_CHECK(book.license_of("ckpt-a").empty());
    BOOST_CHECK(!book.trusted());
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_CASE(card_does_not_replace_stored_parent)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Bind("ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!book.Hub("ckpt-a", "parent-b", err));
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
    BOOST_CHECK(book.bound("ckpt-a"));
    BOOST_CHECK_EQUAL(book.parent_of("ckpt-a"), "parent-a");
    BOOST_CHECK_EQUAL(book.recipe_of("ckpt-a"), "recipe-a");
    BOOST_CHECK_EQUAL(book.dataset_of("ckpt-a"), "dataset-a");
    BOOST_CHECK_EQUAL(book.license_of("ckpt-a"), "license-a");
    BOOST_CHECK(!book.trusted());
    BOOST_CHECK(!book.Hub("ckpt-a", "", err));
    BOOST_CHECK_EQUAL(err, "CARD");
    BOOST_CHECK_EQUAL(book.parent_of("ckpt-a"), "parent-a");
    BOOST_CHECK(!book.trusted());
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_CASE(hub_then_bind_still_stores)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_CHECK(!book.Hub("ckpt-a", "card-1", err));
    BOOST_CHECK_EQUAL(err, "NOT_AUTHORITY");
    BOOST_CHECK(!book.bound("ckpt-a"));
    BOOST_REQUIRE(book.Bind("ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.parent_of("ckpt-a"), "parent-a");
    BOOST_CHECK(!book.trusted());
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_SUITE_END()
