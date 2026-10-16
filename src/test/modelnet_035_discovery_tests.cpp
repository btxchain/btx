// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/research_index.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_discovery_tests, BasicTestingSetup)

namespace {

modelnet::Digest48 Mark(unsigned char tag)
{
    modelnet::Digest48 id;
    id.data[0] = tag;
    return id;
}

} // namespace

BOOST_AUTO_TEST_CASE(discovery_isolation)
{
    using namespace modelnet;
    ResearchIndex index;
    const Digest48 author = Mark(7);
    std::string err;

    BOOST_REQUIRE(index.Announce("topic-a", Mark(1), author, false, "only-a", err));
    BOOST_REQUIRE(index.Announce("topic-b", Mark(1), author, false, "only-b", err));

    ResearchPage page_b;
    BOOST_REQUIRE(index.Query("topic-b", Digest48{}, 64, page_b, err));
    BOOST_REQUIRE_EQUAL(page_b.rows.size(), 1U);
    BOOST_CHECK_EQUAL(page_b.rows[0].summary, "only-b");
    BOOST_CHECK(!page_b.rows[0].negative);

    ResearchPage page_a;
    BOOST_REQUIRE(index.Query("topic-a", Digest48{}, 64, page_a, err));
    BOOST_REQUIRE_EQUAL(page_a.rows.size(), 1U);
    BOOST_CHECK_EQUAL(page_a.rows[0].summary, "only-a");
    BOOST_CHECK(page_a.rows[0].topic != page_b.rows[0].topic);
    BOOST_CHECK(page_a.rows[0].contribution_id == Mark(1));

    ResearchPage empty;
    BOOST_REQUIRE(index.Query("topic-c", Digest48{}, 64, empty, err));
    BOOST_CHECK(empty.rows.empty());
    BOOST_CHECK(err.empty());

    BOOST_CHECK(!index.Announce("Private Topic", Mark(9), author, false, "not-canonical", err));
    BOOST_CHECK_EQUAL(err, "BTX035_TOPIC");
    BOOST_CHECK(!index.Query("Private", Digest48{}, 64, page_a, err));
    BOOST_CHECK_EQUAL(err, "BTX035_TOPIC");
    BOOST_CHECK(page_a.rows.empty());

    BOOST_REQUIRE(index.Query("topic-a", Digest48{}, 64, page_a, err));
    BOOST_REQUIRE_EQUAL(page_a.rows.size(), 1U);
    BOOST_CHECK_EQUAL(page_a.rows[0].summary, "only-a");
}

BOOST_AUTO_TEST_CASE(negative_result_still_queryable)
{
    using namespace modelnet;
    ResearchIndex index;
    const Digest48 author = Mark(2);
    std::string err;

    BOOST_REQUIRE(index.Announce("holdout", Mark(1), author, true, "no gain on the holdout", err));
    BOOST_REQUIRE(index.Announce("holdout", Mark(2), author, false, "measured gain", err));

    ResearchPage page;
    BOOST_REQUIRE(index.Query("holdout", Digest48{}, 64, page, err));
    BOOST_REQUIRE_EQUAL(page.rows.size(), 2U);
    BOOST_CHECK(page.rows[0].contribution_id == Mark(1));
    BOOST_CHECK(page.rows[0].negative);
    BOOST_CHECK_EQUAL(page.rows[0].summary, "no gain on the holdout");
    BOOST_CHECK(page.rows[0].author_id == author);
    BOOST_CHECK(page.rows[1].contribution_id == Mark(2));
    BOOST_CHECK(!page.rows[1].negative);

    ResearchPage elsewhere;
    BOOST_REQUIRE(index.Query("other-holdout", Digest48{}, 64, elsewhere, err));
    BOOST_CHECK(elsewhere.rows.empty());
}

BOOST_AUTO_TEST_SUITE_END()
