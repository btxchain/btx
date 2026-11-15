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

BOOST_FIXTURE_TEST_SUITE(swarm_parentage_trust_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unknown_checkpoint_is_lineage)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_CHECK(!book.Trust("ckpt-missing", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    BOOST_CHECK(!book.bound("ckpt-missing"));
    BOOST_CHECK(book.parent_of("ckpt-missing").empty());
    BOOST_CHECK(!book.Trust("", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    BOOST_CHECK(!book.bound(""));
    BOOST_CHECK(!book.trusted());
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_CASE(bound_checkpoint_is_not_trust)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Bind("ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a", err));
    BOOST_CHECK(!book.trusted());
    BOOST_CHECK(!book.Trust("ckpt-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_TRUST");
    BOOST_CHECK(book.bound("ckpt-a"));
    BOOST_CHECK_EQUAL(book.parent_of("ckpt-a"), "parent-a");
    BOOST_CHECK_EQUAL(book.recipe_of("ckpt-a"), "recipe-a");
    BOOST_CHECK_EQUAL(book.dataset_of("ckpt-a"), "dataset-a");
    BOOST_CHECK_EQUAL(book.license_of("ckpt-a"), "license-a");
    BOOST_CHECK(!book.trusted());
    BOOST_CHECK(!book.realm_promoted());
    BOOST_CHECK(!book.exact_replay_admitted());
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_CASE(license_text_does_not_become_trust)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Bind("ckpt-a", "parent-a", "recipe-a", "dataset-a", "trusted-text", err));
    BOOST_CHECK(!book.Trust("ckpt-a", err));
    BOOST_CHECK_EQUAL(err, "NOT_TRUST");
    BOOST_CHECK_EQUAL(book.license_of("ckpt-a"), "trusted-text");
    BOOST_CHECK(!book.trusted());
    BOOST_CHECK(!book.Trust("ckpt-b", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    BOOST_REQUIRE(book.Bind("ckpt-b", "parent-b", "recipe-b", "dataset-b", "license-b", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.parent_of("ckpt-a"), "parent-a");
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_SUITE_END()
