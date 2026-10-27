// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_lineage/dt_lineage.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string>

BOOST_FIXTURE_TEST_SUITE(dt_lineage_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(failed_journal_keeps_starting_weight_and_replay_stays)
{
    modelnet::DtLineage line;
    std::string err = "stale";

    BOOST_CHECK(!line.Open(fs::path{}, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK(line.generation().empty());
    BOOST_CHECK_EQUAL(line.weight(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(line.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(line.Open(m_path_root, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(fs::exists(m_path_root));
    BOOST_CHECK_EQUAL(line.weight(), static_cast<int64_t>(1));
    BOOST_CHECK(line.generation().empty());

    BOOST_CHECK(!line.Commit("", static_cast<int64_t>(2), false, err));
    BOOST_CHECK_EQUAL(err, "GENERATION");
    BOOST_CHECK_EQUAL(line.weight(), static_cast<int64_t>(1));
    BOOST_CHECK(line.generation().empty());

    const fs::path journal = m_path_root / modelnet::DT_LINEAGE_JOURNAL_NAME;
    BOOST_CHECK(!line.Commit("gen", static_cast<int64_t>(9), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(line.weight(), static_cast<int64_t>(1));
    BOOST_CHECK(line.generation().empty());
    BOOST_CHECK(!fs::exists(journal));
    const fs::path tmp = fs::u8path(journal.utf8string() + ".tmp");
    BOOST_CHECK(!fs::exists(tmp));

    BOOST_CHECK(!line.Reload(err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK(line.generation().empty());
    BOOST_CHECK_EQUAL(line.weight(), static_cast<int64_t>(1));

    BOOST_CHECK(line.Commit("gen", static_cast<int64_t>(2), true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(line.generation(), "gen");
    BOOST_CHECK_EQUAL(line.weight(), static_cast<int64_t>(2));
    BOOST_CHECK(fs::exists(journal));
    BOOST_CHECK(!fs::exists(tmp));
    BOOST_CHECK_EQUAL(line.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!line.Commit("gen", static_cast<int64_t>(3), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(line.weight(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(line.generation(), "gen");

    BOOST_CHECK(!line.StepFailed(err));
    BOOST_CHECK_EQUAL(err, "STEP");
    BOOST_CHECK_EQUAL(line.weight(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(line.generation(), "gen");
    BOOST_CHECK_EQUAL(line.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!line.Commit("gen-b", static_cast<int64_t>(8), false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(line.weight(), static_cast<int64_t>(2));
    BOOST_CHECK_EQUAL(line.generation(), "gen");

    modelnet::DtLineage other;
    BOOST_CHECK_EQUAL(other.weight(), static_cast<int64_t>(1));
    BOOST_CHECK(other.generation().empty());
    BOOST_CHECK(other.Open(m_path_root, err));
    BOOST_CHECK(!other.Commit("gen", static_cast<int64_t>(3), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(other.weight(), static_cast<int64_t>(1));
    BOOST_CHECK(other.generation().empty());

    BOOST_CHECK(other.Reload(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(other.generation(), "gen");
    BOOST_CHECK_EQUAL(other.weight(), static_cast<int64_t>(2));
    BOOST_CHECK(!other.Commit("gen", static_cast<int64_t>(3), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(other.weight(), static_cast<int64_t>(2));

    BOOST_CHECK(line.Commit("gen-b", static_cast<int64_t>(4), true, err));
    BOOST_CHECK_EQUAL(line.generation(), "gen-b");
    BOOST_CHECK_EQUAL(line.weight(), static_cast<int64_t>(4));
    BOOST_CHECK(!line.Commit("gen", static_cast<int64_t>(3), true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(line.weight(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(line.generation(), "gen-b");

    modelnet::DtLineage loaded;
    BOOST_CHECK(loaded.Open(m_path_root, err));
    BOOST_CHECK(loaded.generation().empty());
    BOOST_CHECK(loaded.Reload(err));
    BOOST_CHECK_EQUAL(loaded.generation(), "gen-b");
    BOOST_CHECK_EQUAL(loaded.weight(), static_cast<int64_t>(4));
    BOOST_CHECK(!loaded.Commit("gen", static_cast<int64_t>(3), true, err));
    BOOST_CHECK_EQUAL(loaded.weight(), static_cast<int64_t>(4));
    BOOST_CHECK(!loaded.StepFailed(err));
    BOOST_CHECK_EQUAL(err, "STEP");
    BOOST_CHECK_EQUAL(loaded.weight(), static_cast<int64_t>(4));
    BOOST_CHECK_EQUAL(loaded.generation(), "gen-b");

    const fs::path empty_dir = m_path_root / "empty-journal";
    modelnet::DtLineage missing;
    BOOST_CHECK(missing.Open(empty_dir, err));
    BOOST_CHECK(!missing.Reload(err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK(missing.generation().empty());
    BOOST_CHECK_EQUAL(missing.weight(), static_cast<int64_t>(1));
    BOOST_CHECK_EQUAL(missing.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!line.launched());
    BOOST_CHECK(!line.gpu());
    BOOST_CHECK(!line.broadcast());
    BOOST_CHECK_EQUAL(line.automatic_spend(), "0");
    BOOST_CHECK_EQUAL(line.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(line.bytes_moved(), static_cast<int64_t>(0));
}

BOOST_AUTO_TEST_SUITE_END()
