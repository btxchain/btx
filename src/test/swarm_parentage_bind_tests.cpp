// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_parentage/swarm_parentage.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

static void ExpectStored(const modelnet::SwarmParentage& book,
                         const std::string& checkpoint,
                         const std::string& parent,
                         const std::string& recipe,
                         const std::string& dataset,
                         const std::string& license)
{
    BOOST_CHECK(book.bound(checkpoint));
    BOOST_CHECK_EQUAL(book.parent_of(checkpoint), parent);
    BOOST_CHECK_EQUAL(book.recipe_of(checkpoint), recipe);
    BOOST_CHECK_EQUAL(book.dataset_of(checkpoint), dataset);
    BOOST_CHECK_EQUAL(book.license_of(checkpoint), license);
}

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

BOOST_FIXTURE_TEST_SUITE(swarm_parentage_bind_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_argument_is_lineage)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Bind("ckpt-keep", "parent-keep", "recipe-keep", "dataset-keep", "license-keep", err));
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!book.Bind("", "parent-a", "recipe-a", "dataset-a", "license-a", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    ExpectUnbound(book, "");

    BOOST_CHECK(!book.Bind("ckpt-a", "", "recipe-a", "dataset-a", "license-a", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    ExpectUnbound(book, "ckpt-a");

    BOOST_CHECK(!book.Bind("ckpt-a", "parent-a", "", "dataset-a", "license-a", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    ExpectUnbound(book, "ckpt-a");

    BOOST_CHECK(!book.Bind("ckpt-a", "parent-a", "recipe-a", "", "license-a", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    ExpectUnbound(book, "ckpt-a");

    BOOST_CHECK(!book.Bind("ckpt-a", "parent-a", "recipe-a", "dataset-a", "", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    ExpectUnbound(book, "ckpt-a");

    BOOST_CHECK(!book.Bind("", "", "", "", "", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    ExpectStored(book, "ckpt-keep", "parent-keep", "recipe-keep", "dataset-keep", "license-keep");
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_CASE(empty_parent_is_not_a_baseline_head)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_CHECK(!book.Bind("ckpt-head", "", "recipe-a", "dataset-a", "license-a", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    ExpectUnbound(book, "ckpt-head");
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_CASE(bind_stores_the_four_fields)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Bind("ckpt-a", "parent-a", "recipe v1", "dataset-a", "mit", err));
    BOOST_CHECK(err.empty());
    ExpectStored(book, "ckpt-a", "parent-a", "recipe v1", "dataset-a", "mit");
    ExpectUnbound(book, "ckpt-b");
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_CASE(replay_keeps_the_first)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Bind("ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a", err));
    BOOST_CHECK(!book.Bind("ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    ExpectStored(book, "ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a");
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_CASE(conflict_keeps_the_first)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Bind("ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a", err));

    BOOST_CHECK(!book.Bind("ckpt-a", "parent-b", "recipe-a", "dataset-a", "license-a", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    ExpectStored(book, "ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a");

    BOOST_CHECK(!book.Bind("ckpt-a", "parent-a", "recipe-b", "dataset-a", "license-a", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    ExpectStored(book, "ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a");

    BOOST_CHECK(!book.Bind("ckpt-a", "parent-a", "recipe-a", "dataset-b", "license-a", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    ExpectStored(book, "ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a");

    BOOST_CHECK(!book.Bind("ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-b", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    ExpectStored(book, "ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a");

    BOOST_CHECK(!book.Bind("ckpt-a", "parent-z", "recipe-z", "dataset-z", "license-z", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    ExpectStored(book, "ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a");

    BOOST_CHECK(!book.Bind("ckpt-a", "", "recipe-a", "dataset-a", "license-a", err));
    BOOST_CHECK_EQUAL(err, "LINEAGE");
    ExpectStored(book, "ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a");
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_CASE(second_checkpoint_is_independent)
{
    modelnet::SwarmParentage book;
    std::string err = "prior";
    BOOST_REQUIRE(book.Bind("ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a", err));
    BOOST_REQUIRE(book.Bind("ckpt-b", "parent-b", "recipe-b", "dataset-b", "license-b", err));
    BOOST_CHECK(err.empty());
    ExpectStored(book, "ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a");
    ExpectStored(book, "ckpt-b", "parent-b", "recipe-b", "dataset-b", "license-b");
    BOOST_CHECK(!book.Bind("ckpt-b", "parent-b", "recipe-b", "dataset-b", "license-b", err));
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK(!book.Bind("ckpt-a", "parent-b", "recipe-a", "dataset-a", "license-a", err));
    BOOST_CHECK_EQUAL(err, "CONFLICT");
    ExpectStored(book, "ckpt-a", "parent-a", "recipe-a", "dataset-a", "license-a");
    ExpectStored(book, "ckpt-b", "parent-b", "recipe-b", "dataset-b", "license-b");
    ExpectFrozenInspectors(book);
}

BOOST_AUTO_TEST_SUITE_END()
