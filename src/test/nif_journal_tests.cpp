// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nif_journal/nif_journal.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>

namespace {

modelnet::NifRequestRecord Sample()
{
    modelnet::NifRequestRecord record;
    record.principal = "principal-1";
    record.receiver = "receiver-1";
    record.generation = "generation-1";
    record.attempt = "attempt-1";
    return record;
}

std::string Expected(const modelnet::NifRequestRecord& record, const std::string& outbox)
{
    return record.principal + "\n" + record.receiver + "\n" + record.generation + "\n" + record.attempt + "\n" + outbox + "\n";
}

std::string ReadAll(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    BOOST_REQUIRE(in);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

void ExpectIdle(const modelnet::NifJournal& journal)
{
    BOOST_CHECK(!journal.launched());
    BOOST_CHECK(!journal.gpu());
    BOOST_CHECK(!journal.broadcast());
    BOOST_CHECK(!journal.qualified());
    BOOST_CHECK_EQUAL(journal.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(journal.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(journal.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(journal.hosts(), static_cast<int64_t>(1));
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(nif_journal_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_fields_write_nothing)
{
    modelnet::NifJournal journal;
    const modelnet::NifRequestRecord full = Sample();
    std::string err = "prior";
    ExpectIdle(journal);

    BOOST_CHECK(!journal.Accept(fs::path{}, full, "box-1", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_JOURNAL_DIR);
    BOOST_CHECK_EQUAL(err, "DIR");
    BOOST_CHECK(!fs::exists(m_path_root / modelnet::NIF_JOURNAL_FILE));
    ExpectIdle(journal);

    const fs::path absent = m_path_root / "no-write";
    BOOST_CHECK(!fs::exists(absent));

    modelnet::NifRequestRecord missing_principal = full;
    missing_principal.principal.clear();
    BOOST_CHECK(!journal.Accept(absent, missing_principal, "box-1", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_JOURNAL_REQUEST);
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK(!fs::exists(absent));

    modelnet::NifRequestRecord missing_receiver = full;
    missing_receiver.receiver.clear();
    BOOST_CHECK(!journal.Accept(absent, missing_receiver, "box-1", true, err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK(!fs::exists(absent));

    modelnet::NifRequestRecord missing_generation = full;
    missing_generation.generation.clear();
    BOOST_CHECK(!journal.Accept(absent, missing_generation, "box-1", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_JOURNAL_REQUEST);
    BOOST_CHECK(!fs::exists(absent));

    modelnet::NifRequestRecord missing_attempt = full;
    missing_attempt.attempt.clear();
    BOOST_CHECK(!journal.Accept(absent, missing_attempt, "box-1", true, err));
    BOOST_CHECK_EQUAL(err, "REQUEST");
    BOOST_CHECK(!fs::exists(absent));

    BOOST_CHECK(!journal.Accept(absent, full, "", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_JOURNAL_OUTBOX);
    BOOST_CHECK_EQUAL(err, "OUTBOX");
    BOOST_CHECK(!fs::exists(absent));
    BOOST_CHECK(!fs::exists(m_path_root / modelnet::NIF_JOURNAL_FILE));
    ExpectIdle(journal);
    BOOST_CHECK_EQUAL(journal.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(journal_ok_false_writes_no_file)
{
    modelnet::NifJournal journal;
    const modelnet::NifRequestRecord record = Sample();
    const fs::path absent = m_path_root / "no-journal";
    std::string err = "prior";

    BOOST_CHECK(!fs::exists(absent));
    BOOST_CHECK(!journal.Accept(absent, record, "box-1", false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_JOURNAL_JOURNAL);
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK(!fs::exists(absent));
    BOOST_CHECK(!fs::exists(absent / modelnet::NIF_JOURNAL_FILE));
    BOOST_CHECK(!fs::exists(m_path_root / modelnet::NIF_JOURNAL_FILE));
    ExpectIdle(journal);
    BOOST_CHECK_EQUAL(journal.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_CASE(successful_write_then_replay_keeps_the_first_bytes)
{
    modelnet::NifJournal journal;
    const modelnet::NifRequestRecord record = Sample();
    const fs::path dir = m_path_root / "accepted";
    const fs::path file = dir / modelnet::NIF_JOURNAL_FILE;
    const std::string first = Expected(record, "box-1");
    std::string err = "prior";

    BOOST_CHECK(journal.Accept(dir, record, "box-1", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(fs::exists(file));
    BOOST_CHECK(!fs::exists(fs::u8path(file.utf8string() + ".tmp")));
    BOOST_CHECK_EQUAL(ReadAll(file), first);
    ExpectIdle(journal);
    BOOST_CHECK_EQUAL(journal.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(journal.hosts(), static_cast<int64_t>(1));

    modelnet::NifRequestRecord again = record;
    again.principal = "other-principal";
    BOOST_CHECK(!journal.Accept(dir, again, "other-box", false, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIF_JOURNAL_JOURNAL);
    BOOST_CHECK_EQUAL(ReadAll(file), first);

    BOOST_CHECK(!journal.Accept(dir, again, "other-box", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(err, "REPLAY");
    BOOST_CHECK_EQUAL(ReadAll(file), first);
    BOOST_CHECK(!fs::exists(fs::u8path(file.utf8string() + ".tmp")));
    ExpectIdle(journal);

    modelnet::NifJournal second;
    BOOST_CHECK(!second.Accept(dir, again, "other-box", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(ReadAll(file), first);
    ExpectIdle(second);
    BOOST_CHECK_EQUAL(second.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(second.hosts(), static_cast<int64_t>(1));
}

BOOST_AUTO_TEST_SUITE_END()
