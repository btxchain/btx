// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/workspace_journal.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_workspace_tests, BasicTestingSetup)

namespace {

std::vector<unsigned char> Bytes(const std::string& text)
{
    return std::vector<unsigned char>(text.begin(), text.end());
}

std::vector<unsigned char> ReadPath(const modelnet::WorkspaceBook& book, const std::string& name, const std::string& path)
{
    std::vector<unsigned char> out;
    BOOST_REQUIRE(book.Read(name, path, out));
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(open_tree_generation_one_second_open_fails)
{
    modelnet::WorkspaceBook book;
    std::string err;
    BOOST_CHECK(book.OpenTree("alpha", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Generation("alpha"), uint64_t{1});

    BOOST_CHECK(book.OpenTree("beta", err));
    BOOST_CHECK_EQUAL(book.Generation("beta"), uint64_t{1});

    BOOST_CHECK(!book.OpenTree("alpha", err));
    BOOST_CHECK_EQUAL(err, "BTX035_WORKSPACE");
    BOOST_CHECK_EQUAL(book.Generation("alpha"), uint64_t{1});

    BOOST_CHECK(!book.OpenTree("", err));
    BOOST_CHECK_EQUAL(err, "BTX035_WORKSPACE");
    BOOST_CHECK_EQUAL(book.Generation("missing"), uint64_t{0});
}

BOOST_AUTO_TEST_CASE(put_matches_generation_stale_does_not_write)
{
    modelnet::WorkspaceBook book;
    std::string err;
    BOOST_REQUIRE(book.OpenTree("alpha", err));
    const std::vector<unsigned char> first = Bytes("one");
    const std::vector<unsigned char> stale = Bytes("stale");
    const std::vector<unsigned char> second = Bytes("two");

    BOOST_CHECK(book.Put("alpha", 1, "a.txt", first, err));
    BOOST_CHECK(ReadPath(book, "alpha", "a.txt") == first);

    BOOST_CHECK(!book.Put("missing", 1, "a.txt", stale, err));
    BOOST_CHECK_EQUAL(err, "BTX035_WORKSPACE");

    BOOST_REQUIRE(book.Publish("alpha", 1, false, true, err));
    BOOST_CHECK_EQUAL(book.Generation("alpha"), uint64_t{2});

    BOOST_CHECK(!book.Put("alpha", 1, "a.txt", stale, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GENERATION");
    BOOST_CHECK(ReadPath(book, "alpha", "a.txt") == first);

    BOOST_CHECK(!book.Put("alpha", 9, "a.txt", stale, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GENERATION");
    BOOST_CHECK(ReadPath(book, "alpha", "a.txt") == first);

    BOOST_CHECK(book.Put("alpha", 2, "a.txt", second, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(ReadPath(book, "alpha", "a.txt") == second);
}

BOOST_AUTO_TEST_CASE(two_trees_same_path_are_independent)
{
    modelnet::WorkspaceBook book;
    std::string err;
    BOOST_REQUIRE(book.OpenTree("alpha", err));
    BOOST_REQUIRE(book.OpenTree("beta", err));
    const std::vector<unsigned char> left = Bytes("left");
    const std::vector<unsigned char> right = Bytes("right");

    BOOST_CHECK(book.Put("alpha", 1, "same.txt", left, err));
    BOOST_CHECK(book.Put("beta", 1, "same.txt", right, err));
    BOOST_CHECK(ReadPath(book, "alpha", "same.txt") == left);
    BOOST_CHECK(ReadPath(book, "beta", "same.txt") == right);

    BOOST_CHECK(modelnet::Conflict(left, right));
    BOOST_CHECK(!modelnet::Conflict(left, left));
    BOOST_CHECK(!modelnet::Conflict({}, {}));
    BOOST_CHECK(modelnet::Conflict(left, Bytes("lef")));
}

BOOST_AUTO_TEST_CASE(publish_conflict_and_stale_generation_fail)
{
    modelnet::WorkspaceBook book;
    std::string err;
    BOOST_REQUIRE(book.OpenTree("alpha", err));
    const std::vector<unsigned char> body = Bytes("body");
    BOOST_REQUIRE(book.Put("alpha", 1, "a.txt", body, err));

    BOOST_CHECK(!book.Publish("missing", 1, false, true, err));
    BOOST_CHECK_EQUAL(err, "BTX035_WORKSPACE");

    BOOST_CHECK(!book.Publish("alpha", 1, true, true, err));
    BOOST_CHECK_EQUAL(err, "BTX035_CONFLICT");
    BOOST_CHECK_EQUAL(book.Generation("alpha"), uint64_t{1});
    BOOST_CHECK(book.PublicationIds("alpha").empty());
    BOOST_CHECK(ReadPath(book, "alpha", "a.txt") == body);

    BOOST_CHECK(!book.Publish("alpha", 0, true, true, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GENERATION");
    BOOST_CHECK_EQUAL(book.Generation("alpha"), uint64_t{1});
    BOOST_CHECK(book.PublicationIds("alpha").empty());

    BOOST_CHECK(!book.Publish("alpha", 4, false, true, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GENERATION");
    BOOST_CHECK(ReadPath(book, "alpha", "a.txt") == body);

    BOOST_CHECK(book.Publish("alpha", 1, false, false, err));
    BOOST_CHECK_EQUAL(book.Generation("alpha"), uint64_t{2});
    BOOST_CHECK(book.PublicationIds("alpha").empty());
    const std::string unpublished = book.ExportPublic("alpha");
    BOOST_CHECK(unpublished.find("publication ") == std::string::npos);
    BOOST_CHECK(unpublished.find("generation 2") != std::string::npos);

    BOOST_CHECK(book.Publish("alpha", 2, false, true, err));
    const std::vector<uint64_t> ids = book.PublicationIds("alpha");
    BOOST_REQUIRE_EQUAL(ids.size(), 1u);
    BOOST_CHECK_EQUAL(ids[0], uint64_t{1});
    BOOST_CHECK_EQUAL(book.Generation("alpha"), uint64_t{3});
    BOOST_CHECK(book.ExportPublic("alpha").find("publication 1") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(undo_restores_previous_map_and_stops_at_one)
{
    modelnet::WorkspaceBook book;
    std::string err;
    BOOST_REQUIRE(book.OpenTree("alpha", err));
    const std::vector<unsigned char> v1 = Bytes("v1");
    const std::vector<unsigned char> v2 = Bytes("v2");
    const std::vector<unsigned char> extra = Bytes("extra");

    BOOST_CHECK(!book.Undo("alpha", err));
    BOOST_CHECK_EQUAL(err, "BTX035_UNDO");
    BOOST_CHECK_EQUAL(book.Generation("alpha"), uint64_t{1});

    BOOST_CHECK(!book.Undo("missing", err));
    BOOST_CHECK_EQUAL(err, "BTX035_WORKSPACE");

    BOOST_REQUIRE(book.Put("alpha", 1, "a.txt", v1, err));
    BOOST_REQUIRE(book.Publish("alpha", 1, false, true, err));
    BOOST_REQUIRE(book.Put("alpha", 2, "a.txt", v2, err));
    BOOST_REQUIRE(book.Put("alpha", 2, "b.txt", extra, err));

    BOOST_CHECK(book.Undo("alpha", err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(book.Generation("alpha"), uint64_t{1});
    BOOST_CHECK(ReadPath(book, "alpha", "a.txt") == v1);
    std::vector<unsigned char> gone;
    BOOST_CHECK(!book.Read("alpha", "b.txt", gone));
    BOOST_REQUIRE_EQUAL(book.PublicationIds("alpha").size(), 1u);
    BOOST_CHECK_EQUAL(book.PublicationIds("alpha")[0], uint64_t{1});

    BOOST_CHECK(!book.Undo("alpha", err));
    BOOST_CHECK_EQUAL(err, "BTX035_UNDO");
    BOOST_CHECK_EQUAL(book.Generation("alpha"), uint64_t{1});
    BOOST_CHECK(ReadPath(book, "alpha", "a.txt") == v1);
}

BOOST_AUTO_TEST_CASE(private_note_is_stored_and_omitted_from_export)
{
    modelnet::WorkspaceBook book;
    std::string err;
    const std::string secret = "PRIVNOTE-7f3a9c-do-not-export";
    BOOST_CHECK(!book.NotePrivate("alpha", secret, err));
    BOOST_CHECK_EQUAL(err, "BTX035_WORKSPACE");
    BOOST_CHECK_EQUAL(book.PrivateNoteCount("alpha"), 0u);

    BOOST_REQUIRE(book.OpenTree("alpha", err));
    BOOST_REQUIRE(book.Put("alpha", 1, "a.txt", Bytes("public-body"), err));
    BOOST_REQUIRE(book.Publish("alpha", 1, false, true, err));
    BOOST_CHECK(book.NotePrivate("alpha", secret, err));
    BOOST_CHECK(book.NotePrivate("alpha", secret + "-2", err));
    BOOST_CHECK_EQUAL(book.PrivateNoteCount("alpha"), 2u);

    const std::string exported = book.ExportPublic("alpha");
    BOOST_CHECK(exported.find(secret) == std::string::npos);
    BOOST_CHECK(exported.find(secret + "-2") == std::string::npos);
    BOOST_CHECK(exported.find("workspace alpha") != std::string::npos);
    BOOST_CHECK(exported.find("publication 1") != std::string::npos);
    BOOST_CHECK(exported.find("file a.txt ") != std::string::npos);
    BOOST_CHECK(book.ExportPublic("missing").empty());
}

BOOST_AUTO_TEST_CASE(complete_after_cancel_is_late_and_does_not_write)
{
    modelnet::WorkspaceBook book;
    std::string err;
    BOOST_REQUIRE(book.OpenTree("alpha", err));
    const std::vector<unsigned char> kept = Bytes("kept");
    const std::vector<unsigned char> nope = Bytes("nope");
    const std::vector<unsigned char> applied = Bytes("applied");
    const std::vector<unsigned char> again = Bytes("again");

    BOOST_REQUIRE(book.Put("alpha", 1, "a.txt", kept, err));
    BOOST_CHECK(book.Cancel("alpha", "hydrate-1", err));
    BOOST_CHECK(book.Cancel("alpha", "hydrate-1", err));

    BOOST_CHECK(!book.Complete("alpha", "hydrate-1", 1, "a.txt", nope, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LATE");
    BOOST_CHECK(ReadPath(book, "alpha", "a.txt") == kept);

    BOOST_CHECK(!book.Complete("missing", "hydrate-2", 1, "a.txt", nope, err));
    BOOST_CHECK_EQUAL(err, "BTX035_WORKSPACE");
    BOOST_CHECK(!book.Cancel("alpha", "", err));
    BOOST_CHECK_EQUAL(err, "BTX035_WORKSPACE");

    BOOST_CHECK(book.Complete("alpha", "hydrate-2", 1, "b.txt", applied, err));
    BOOST_CHECK(ReadPath(book, "alpha", "b.txt") == applied);
    BOOST_CHECK(!book.Complete("alpha", "hydrate-2", 1, "b.txt", again, err));
    BOOST_CHECK_EQUAL(err, "BTX035_LATE");
    BOOST_CHECK(ReadPath(book, "alpha", "b.txt") == applied);

    BOOST_CHECK(!book.Cancel("alpha", "hydrate-2", err));
    BOOST_CHECK_EQUAL(err, "BTX035_LATE");
    BOOST_CHECK(ReadPath(book, "alpha", "b.txt") == applied);

    BOOST_REQUIRE(book.Publish("alpha", 1, false, false, err));
    BOOST_CHECK_EQUAL(book.Generation("alpha"), uint64_t{2});
    BOOST_CHECK(!book.Complete("alpha", "hydrate-3", 1, "a.txt", nope, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GENERATION");
    BOOST_CHECK(ReadPath(book, "alpha", "a.txt") == kept);

    BOOST_CHECK(book.Complete("alpha", "hydrate-3", 2, "c.txt", applied, err));
    BOOST_CHECK(ReadPath(book, "alpha", "c.txt") == applied);
}

BOOST_AUTO_TEST_SUITE_END()
