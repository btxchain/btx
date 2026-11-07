// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_parentage/swarm_parentage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

static void ExpectUnbound(const modelnet::SwarmParentage& book, const std::string& checkpoint)
{
    BOOST_CHECK(!book.bound(checkpoint));
    BOOST_CHECK(book.parent_of(checkpoint).empty());
    BOOST_CHECK(book.recipe_of(checkpoint).empty());
    BOOST_CHECK(book.dataset_of(checkpoint).empty());
    BOOST_CHECK(book.license_of(checkpoint).empty());
}

static void ExpectFrozenInspectors(const modelnet::SwarmParentage& book)
{
    BOOST_CHECK(!book.trusted());
    BOOST_CHECK(!book.realm_promoted());
    BOOST_CHECK(!book.exact_replay_admitted());
    BOOST_CHECK(!book.launched());
    BOOST_CHECK(!book.gpu());
    BOOST_CHECK_EQUAL(book.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_FIXTURE_TEST_SUITE(swarm_parentage_claim_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_checkpoint_is_lineage)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_CHECK(!book.Claim("", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    ExpectUnbound(book, "");
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_CASE(checkpoint_id_alone_stores_nothing)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_CHECK(!book.Claim("ckpt-alone", err));
    BOOST_CHECK_EQUAL(err, "NOT_TRUST");
    ExpectUnbound(book, "ckpt-alone");
    BOOST_CHECK(!book.Claim("ckpt-alone", err));
    BOOST_CHECK_EQUAL(err, "NOT_TRUST");
    ExpectUnbound(book, "ckpt-alone");
    BOOST_CHECK(!book.trusted());
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_CASE(claim_then_bind_is_the_first_store)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_CHECK(!book.Claim("ckpt-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_TRUST");
    ExpectUnbound(book, "ckpt-a");
    BOOST_REQUIRE(book.Bind("ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(book.bound("ckpt-a"));
    BOOST_CHECK_EQUAL(book.parent_of("ckpt-a"), "parent-a");
    BOOST_CHECK_EQUAL(book.recipe_of("ckpt-a"), "recipe-a");
    BOOST_CHECK_EQUAL(book.dataset_of("ckpt-a"), "dataset-a");
    BOOST_CHECK_EQUAL(book.license_of("ckpt-a"), "license-a");
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_CASE(claim_leaves_an_existing_binding)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Bind("ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a", err));
    BOOST_CHECK(!book.Claim("ckpt-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_TRUST");
    BOOST_CHECK(book.bound("ckpt-a"));
    BOOST_CHECK_EQUAL(book.parent_of("ckpt-a"), "parent-a");
    BOOST_CHECK(!book.Claim("ckpt-b", err));
    BOOST_CHECK_EQUAL(err, "NOT_TRUST");
    ExpectUnbound(book, "ckpt-b");
    BOOST_CHECK_EQUAL(book.parent_of("ckpt-a"), "parent-a");
    BOOST_CHECK_EQUAL(book.license_of("ckpt-a"), "license-a");
    BOOST_CHECK(!book.trusted());
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_SUITE_END()
