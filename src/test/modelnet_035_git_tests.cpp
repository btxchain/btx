// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/git_snapshot.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <string>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_035_git_tests, BasicTestingSetup)

namespace {

std::string Id(char fill)
{
    return std::string(96, fill);
}

modelnet::GitRefUpdate Up(std::string ref, uint64_t sequence, std::string record, std::string previous = {})
{
    modelnet::GitRefUpdate update;
    update.refname = std::move(ref);
    update.sequence = sequence;
    update.record_id = std::move(record);
    update.previous_update_id = std::move(previous);
    return update;
}

} // namespace

BOOST_AUTO_TEST_CASE(blob_a_digest_is_sha384_not_sha1)
{
    // Preimage is ASCII "blob" || ' ' || "1" || 0x00 || 'a'.
    const unsigned char byte = 'a';
    std::string digest;
    std::string err;
    BOOST_REQUIRE(modelnet::GitObjectDigest("blob", Span<const unsigned char>(&byte, 1), digest, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(digest, "1adcbf5aea2ca919b25776a05ac40948173bbd72b7e324942ccebf7c67480423246df9a4a07e58fea1f4523705eab508");
    BOOST_CHECK_EQUAL(digest.size(), 96);
    BOOST_CHECK(modelnet::IsStrongGitDigest(digest));

    const unsigned char other = 'b';
    std::string changed;
    BOOST_REQUIRE(modelnet::GitObjectDigest("blob", Span<const unsigned char>(&other, 1), changed, err));
    BOOST_CHECK_NE(digest, changed);

    const std::string sha1 = "2e65efe2a145dda7ee51d1741299f848e5bf752e";
    BOOST_CHECK_EQUAL(sha1.size(), 40);
    BOOST_CHECK_NE(digest, sha1);
    BOOST_CHECK(!modelnet::IsStrongGitDigest(sha1));

    BOOST_CHECK(!modelnet::GitObjectDigest("BLOB", Span<const unsigned char>(&byte, 1), changed, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GIT_TYPE");
    BOOST_CHECK(!modelnet::GitObjectDigest("note", Span<const unsigned char>(&byte, 1), changed, err));
    BOOST_CHECK_EQUAL(err, "BTX035_GIT_TYPE");
}

BOOST_AUTO_TEST_CASE(unsafe_git_paths)
{
    const std::string nul_path("a\0b", 3);
    const std::vector<std::string> unsafe = {
        "",
        nul_path,
        "foo\\bar",
        "/abs",
        "foo//bar",
        "foo/../x",
        "foo/./x",
        ".",
        "..",
        "foo/",
        "foo:stream",
        "foo/bar.",
        "foo/bar ",
        ".git/config",
        "dir/.GIT/objects",
        "dir/.Git",
        "CON",
        "prn.txt",
        "Aux",
        "nul",
        "COM1",
        "com9.dat",
        "LPT1",
        "foo/lpt9.bin",
    };
    for (const std::string& path : unsafe) {
        std::string err;
        BOOST_CHECK_MESSAGE(!modelnet::SafeGitPath(path, err), path);
        BOOST_CHECK_EQUAL(err, "BTX035_PATH_UNSAFE");
    }

    const char* safe[] = {
        "src/modelnet/git_snapshot.cpp",
        "refs/heads/main",
        ".gitignore",
        "COM0",
        "COM10",
        "commit",
        "auxiliary",
        "foo/bar.txt",
    };
    for (const char* path : safe) {
        std::string err = "stale";
        BOOST_CHECK_MESSAGE(modelnet::SafeGitPath(path, err), path);
        BOOST_CHECK(err.empty());
    }
}

BOOST_AUTO_TEST_CASE(ref_journal_stage_faults_and_abandon)
{
    modelnet::RefJournal journal;
    std::string err;
    BOOST_CHECK(!journal.Publish(err));
    BOOST_CHECK_EQUAL(err, "BTX035_PUSH_STAGE");
    BOOST_CHECK(!journal.AuthorizeAndStage({}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_PUSH_STAGE");
    BOOST_CHECK(!journal.HasStaged());

    const std::string sha1 = "2e65efe2a145dda7ee51d1741299f848e5bf752e";
    BOOST_CHECK(!journal.AuthorizeAndStage({Up("refs/heads/main", 0, sha1)}, err));
    BOOST_CHECK_EQUAL(err, "BTX035_ID_MISMATCH");
    BOOST_CHECK(!journal.HasStaged());

    BOOST_REQUIRE(journal.AuthorizeAndStage({Up("refs/heads/main", 0, Id('a'))}, err));
    BOOST_CHECK(journal.HasStaged());
    const modelnet::Digest48 before = journal.JournalCommitment();
    BOOST_CHECK(before.IsNull());
    journal.AbandonStaged();
    BOOST_CHECK(!journal.HasStaged());
    BOOST_CHECK(journal.Committed().empty());
    BOOST_CHECK(!journal.Publish(err));
    BOOST_CHECK_EQUAL(err, "BTX035_PUSH_STAGE");
    BOOST_CHECK(journal.JournalCommitment() == before);

    BOOST_REQUIRE(journal.AuthorizeAndStage({
        Up("refs/heads/main", 0, Id('a')),
        Up("refs/heads/main", 1, Id('b'), Id('a')),
    }, err));
    BOOST_REQUIRE(journal.Publish(err));
    BOOST_CHECK(!journal.HasStaged());
    BOOST_REQUIRE(journal.Committed().count("refs/heads/main") == 1);
    BOOST_CHECK_EQUAL(journal.Committed().at("refs/heads/main").sequence, 1);
    BOOST_CHECK_EQUAL(journal.Committed().at("refs/heads/main").record_id, Id('b'));
    const modelnet::Digest48 committed_head = journal.JournalCommitment();
    BOOST_CHECK(!committed_head.IsNull());

    BOOST_REQUIRE(journal.AuthorizeAndStage({Up("refs/heads/other", 0, Id('c'))}, err));
    journal.AbandonStaged();
    BOOST_CHECK(!journal.HasStaged());
    BOOST_CHECK(journal.Committed().count("refs/heads/other") == 0);
    BOOST_CHECK(journal.JournalCommitment() == committed_head);
    BOOST_CHECK_EQUAL(journal.Committed().at("refs/heads/main").record_id, Id('b'));

    BOOST_REQUIRE(journal.AuthorizeAndStage({Up("refs/heads/main", 1, Id('b'), Id('a'))}, err));
    BOOST_CHECK(!journal.Publish(err));
    BOOST_CHECK_EQUAL(err, "BTX035_DUPLICATE");
    BOOST_CHECK(!journal.HasStaged());
    BOOST_CHECK_EQUAL(journal.Committed().at("refs/heads/main").record_id, Id('b'));
    BOOST_CHECK(journal.JournalCommitment() == committed_head);

    BOOST_REQUIRE(journal.AuthorizeAndStage({Up("refs/heads/main", 1, Id('d'), Id('a'))}, err));
    BOOST_CHECK(!journal.Publish(err));
    BOOST_CHECK_EQUAL(err, "BTX035_EQUIVOCATION");
    BOOST_CHECK(!journal.HasStaged());
    BOOST_CHECK_EQUAL(journal.Committed().at("refs/heads/main").sequence, 1);
    BOOST_CHECK(journal.JournalCommitment() == committed_head);

    BOOST_REQUIRE(journal.AuthorizeAndStage({Up("refs/heads/main", 0, Id('a'))}, err));
    BOOST_CHECK(!journal.Publish(err));
    BOOST_CHECK_EQUAL(err, "BTX035_ROLLBACK");
    BOOST_CHECK(!journal.HasStaged());
    BOOST_CHECK_EQUAL(journal.Committed().at("refs/heads/main").sequence, 1);

    BOOST_REQUIRE(journal.AuthorizeAndStage({Up("refs/heads/main", 3, Id('e'), Id('b'))}, err));
    BOOST_CHECK(!journal.Publish(err));
    BOOST_CHECK_EQUAL(err, "BTX035_GAP");
    BOOST_CHECK(!journal.HasStaged());
    BOOST_CHECK_EQUAL(journal.Committed().at("refs/heads/main").sequence, 1);

    BOOST_REQUIRE(journal.AuthorizeAndStage({Up("refs/heads/main", 2, Id('e'), Id('a'))}, err));
    BOOST_CHECK(!journal.Publish(err));
    BOOST_CHECK_EQUAL(err, "BTX035_GAP");
    BOOST_CHECK(!journal.HasStaged());

    BOOST_REQUIRE(journal.AuthorizeAndStage({Up("refs/heads/new", 0, Id('f'), Id('a'))}, err));
    BOOST_CHECK(!journal.Publish(err));
    BOOST_CHECK_EQUAL(err, "BTX035_GAP");
    BOOST_CHECK(journal.Committed().count("refs/heads/new") == 0);

    BOOST_REQUIRE(journal.AuthorizeAndStage({
        Up("refs/heads/ok", 0, Id('c')),
        Up("refs/heads/bad", 4, Id('d'), Id('c')),
    }, err));
    BOOST_CHECK(!journal.Publish(err));
    BOOST_CHECK_EQUAL(err, "BTX035_GAP");
    BOOST_CHECK(!journal.HasStaged());
    BOOST_CHECK(journal.Committed().count("refs/heads/ok") == 0);
    BOOST_CHECK(journal.Committed().count("refs/heads/bad") == 0);
    BOOST_CHECK_EQUAL(journal.Committed().at("refs/heads/main").record_id, Id('b'));
    BOOST_CHECK(journal.JournalCommitment() == committed_head);

    BOOST_REQUIRE(journal.AuthorizeAndStage({
        Up("refs/heads/left", 0, Id('c')),
        Up("refs/heads/right", 0, Id('d')),
    }, err));
    BOOST_REQUIRE(journal.Publish(err));
    BOOST_CHECK_EQUAL(journal.Committed().at("refs/heads/left").record_id, Id('c'));
    BOOST_CHECK_EQUAL(journal.Committed().at("refs/heads/right").record_id, Id('d'));
    BOOST_CHECK(journal.JournalCommitment() != committed_head);

    BOOST_CHECK(!journal.Publish(err));
    BOOST_CHECK_EQUAL(err, "BTX035_PUSH_STAGE");
}

BOOST_AUTO_TEST_SUITE_END()
