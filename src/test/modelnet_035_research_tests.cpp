// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/crypto.h>
#include <modelnet/research_graph.h>
#include <span.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_research_tests, BasicTestingSetup)

namespace {

modelnet::Digest48 Mark(unsigned char tag)
{
    modelnet::Digest48 id;
    id.data[0] = tag;
    return id;
}

} // namespace

BOOST_AUTO_TEST_CASE(topic_id_is_domain_hash)
{
    using namespace modelnet;
    Digest48 id;
    std::string err;

    BOOST_CHECK(RejectCanonical("", err));
    BOOST_CHECK(!TopicId("", id, err));
    BOOST_CHECK_EQUAL(err, "BTX035_TOPIC");

    BOOST_CHECK(!RejectCanonical(" Topic", err));
    BOOST_CHECK_EQUAL(err, "BTX035_TOPIC");
    BOOST_CHECK(!TopicId("topic ", id, err));
    BOOST_CHECK_EQUAL(err, "BTX035_TOPIC");
    BOOST_CHECK(!RejectCanonical("sparseAttention", err));
    BOOST_CHECK_EQUAL(err, "BTX035_TOPIC");
    BOOST_CHECK(!TopicId("Sparse", id, err));
    BOOST_CHECK_EQUAL(err, "BTX035_TOPIC");

    BOOST_CHECK(RejectCanonical("sparse attention", err));
    const std::string label = "sparse-attention";
    BOOST_REQUIRE(TopicId(label, id, err));
    const Digest48 expect = DomainHash("BTX/035/Topic/v1.1",
                                       Span<const unsigned char>{UCharCast(label.data()), label.size()});
    BOOST_CHECK(id == expect);

    const std::string utf8 = "t\xc3\xb3pico";
    Digest48 utf8_id;
    BOOST_REQUIRE(TopicId(utf8, utf8_id, err));
    const Digest48 utf8_expect = DomainHash("BTX/035/Topic/v1.1",
                                            Span<const unsigned char>{UCharCast(utf8.data()), utf8.size()});
    BOOST_CHECK(utf8_id == utf8_expect);
    BOOST_CHECK(utf8_id != id);
}

BOOST_AUTO_TEST_CASE(negative_results_remain_queryable)
{
    using namespace modelnet;
    ResearchBook book;
    Digest48 topic;
    std::string err;
    BOOST_REQUIRE(TopicId("negative-retention", topic, err));
    const Digest48 contribution = Mark(1);
    const Digest48 author = Mark(2);

    BOOST_REQUIRE(book.Publish(topic, contribution, author, true, "no gain on the holdout", err));
    ResearchContribution row;
    BOOST_REQUIRE(book.Find(topic, contribution, row));
    BOOST_CHECK(row.negative);
    BOOST_CHECK_EQUAL(row.summary, "no gain on the holdout");
    BOOST_CHECK(row.author_id == author);

    BOOST_CHECK(!book.Publish(topic, contribution, author, false, "rewritten as a win", err));
    BOOST_CHECK_EQUAL(err, "BTX035_CONFLICT");
    BOOST_REQUIRE(book.Find(topic, contribution, row));
    BOOST_CHECK(row.negative);
    BOOST_CHECK_EQUAL(row.summary, "no gain on the holdout");

    const Digest48 positive = Mark(3);
    BOOST_REQUIRE(book.Publish(topic, positive, author, false, "measured gain", err));
    BOOST_REQUIRE(book.Find(topic, positive, row));
    BOOST_CHECK(!row.negative);

    ResearchPage page;
    BOOST_REQUIRE(book.Page(topic, Digest48{}, 64, page, err));
    BOOST_REQUIRE_EQUAL(page.rows.size(), 2U);
    BOOST_CHECK(page.rows[0].contribution_id == contribution);
    BOOST_CHECK(page.rows[0].negative);
    BOOST_CHECK(page.rows[1].contribution_id == positive);
    BOOST_CHECK(!page.rows[1].negative);
}

BOOST_AUTO_TEST_CASE(successor_grant_is_unequal)
{
    using namespace modelnet;
    ResearchBook book;
    const Digest48 parent = Mark(1);
    const Digest48 child = Mark(2);
    const Digest48 other = Mark(3);
    const Digest48 memory_a = Mark(4);
    const Digest48 memory_b = Mark(5);
    std::vector<Digest48> memories{memory_a, memory_b};
    std::string err;

    BOOST_CHECK(!book.AdoptSuccessor(parent, child, "parent-grant", "parent-grant", memories, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GRANT");
    BOOST_CHECK(book.MemoryOf(child).empty());

    BOOST_CHECK(!book.AdoptSuccessor(parent, child, "", "child-grant", memories, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GRANT");
    BOOST_CHECK(!book.AdoptSuccessor(parent, child, "parent-grant", "", memories, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GRANT");
    BOOST_CHECK(book.MemoryOf(child).empty());

    BOOST_REQUIRE(book.AdoptSuccessor(parent, other, "parent-grant", "other-grant", {}, err));
    BOOST_CHECK(book.MemoryOf(other).empty());

    BOOST_REQUIRE(book.AdoptSuccessor(parent, child, "parent-grant", "child-grant", memories, err));
    BOOST_CHECK(book.MemoryOf(child) == memories);
    memories.clear();
    const std::vector<Digest48> kept = book.MemoryOf(child);
    BOOST_REQUIRE_EQUAL(kept.size(), 2U);
    BOOST_CHECK(kept[0] == memory_a);
    BOOST_CHECK(kept[1] == memory_b);

    BOOST_CHECK(!book.AdoptSuccessor(parent, child, "same", "same", {}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GRANT");
    BOOST_CHECK(book.MemoryOf(child) == kept);
}

BOOST_AUTO_TEST_CASE(page_cursor_does_not_repeat)
{
    using namespace modelnet;
    ResearchBook book;
    Digest48 topic;
    Digest48 other_topic;
    std::string err;
    BOOST_REQUIRE(TopicId("page-order", topic, err));
    BOOST_REQUIRE(TopicId("other-topic", other_topic, err));
    const Digest48 author = Mark(9);

    BOOST_REQUIRE(book.Publish(topic, Mark(5), author, false, "e", err));
    BOOST_REQUIRE(book.Publish(topic, Mark(1), author, true, "a", err));
    BOOST_REQUIRE(book.Publish(topic, Mark(3), author, false, "c", err));
    BOOST_REQUIRE(book.Publish(topic, Mark(2), author, true, "b", err));
    BOOST_REQUIRE(book.Publish(topic, Mark(4), author, false, "d", err));
    BOOST_REQUIRE(book.Publish(other_topic, Mark(1), author, false, "elsewhere", err));

    ResearchPage rejected;
    BOOST_CHECK(!book.Page(topic, Digest48{}, 0, rejected, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PAGE");
    BOOST_CHECK(rejected.rows.empty());
    BOOST_CHECK(!book.Page(topic, Digest48{}, 65, rejected, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PAGE");

    ResearchPage first;
    BOOST_REQUIRE(book.Page(topic, Digest48{}, 2, first, err));
    BOOST_REQUIRE_EQUAL(first.rows.size(), 2U);
    BOOST_CHECK(first.rows[0].contribution_id == Mark(1));
    BOOST_CHECK(first.rows[0].negative);
    BOOST_CHECK(first.rows[1].contribution_id == Mark(2));
    BOOST_CHECK(first.next_cursor == Mark(2));

    ResearchPage second;
    BOOST_REQUIRE(book.Page(topic, first.next_cursor, 2, second, err));
    BOOST_REQUIRE_EQUAL(second.rows.size(), 2U);
    BOOST_CHECK(second.rows[0].contribution_id == Mark(3));
    BOOST_CHECK(second.rows[1].contribution_id == Mark(4));
    BOOST_CHECK(second.next_cursor == Mark(4));
    for (const auto& row : second.rows) {
        BOOST_CHECK(row.contribution_id != first.next_cursor);
    }

    ResearchPage third;
    BOOST_REQUIRE(book.Page(topic, second.next_cursor, 2, third, err));
    BOOST_REQUIRE_EQUAL(third.rows.size(), 1U);
    BOOST_CHECK(third.rows[0].contribution_id == Mark(5));
    BOOST_CHECK(third.next_cursor.IsNull());

    ResearchPage exact;
    BOOST_REQUIRE(book.Page(other_topic, Digest48{}, 2, exact, err));
    BOOST_REQUIRE_EQUAL(exact.rows.size(), 1U);
    BOOST_CHECK(exact.rows[0].summary == "elsewhere");
    BOOST_CHECK(exact.next_cursor.IsNull());

    ResearchPage full;
    BOOST_REQUIRE(book.Page(topic, Digest48{}, 64, full, err));
    BOOST_CHECK_EQUAL(full.rows.size(), 5U);
    BOOST_CHECK(full.next_cursor.IsNull());
}

BOOST_AUTO_TEST_CASE(departed_author_row_remains)
{
    using namespace modelnet;
    ResearchBook book;
    Digest48 topic;
    std::string err;
    BOOST_REQUIRE(TopicId("peer-departure", topic, err));
    const Digest48 leaving = Mark(1);
    const Digest48 staying = Mark(2);
    const Digest48 left_row = Mark(3);
    const Digest48 stayed_row = Mark(4);

    BOOST_REQUIRE(book.Publish(topic, left_row, leaving, true, "still on the record", err));
    BOOST_REQUIRE(book.Publish(topic, stayed_row, staying, false, "peer remains", err));
    BOOST_CHECK(book.HasPeer(leaving));
    BOOST_CHECK(book.HasPeer(staying));

    book.ContinueWithout(leaving);
    BOOST_CHECK(!book.HasPeer(leaving));
    BOOST_CHECK(book.HasPeer(staying));

    ResearchContribution row;
    BOOST_REQUIRE(book.Find(topic, left_row, row));
    BOOST_CHECK(row.negative);
    BOOST_CHECK(row.author_id == leaving);
    BOOST_CHECK_EQUAL(row.summary, "still on the record");
    BOOST_REQUIRE(book.Find(topic, stayed_row, row));
    BOOST_CHECK(row.author_id == staying);

    ResearchPage page;
    BOOST_REQUIRE(book.Page(topic, Digest48{}, 64, page, err));
    BOOST_REQUIRE_EQUAL(page.rows.size(), 2U);
    BOOST_CHECK(page.rows[0].author_id == leaving);
    BOOST_CHECK(page.rows[0].negative);
}

BOOST_AUTO_TEST_SUITE_END()
