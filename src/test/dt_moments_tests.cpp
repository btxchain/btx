// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_moments/dt_moments.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <fstream>
#include <iterator>
#include <string>

namespace {

std::string ReadFile(const fs::path& path)
{
    std::ifstream in(path, std::ios::binary);
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(dt_moments_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_state_nan_and_journal_false_write_nothing)
{
    modelnet::DtMoments engine;
    std::string err = "stale";

    BOOST_CHECK(engine.master().empty());
    BOOST_CHECK(engine.moment().empty());
    BOOST_CHECK(engine.scale().empty());
    BOOST_CHECK(engine.rng().empty());
    BOOST_CHECK(engine.scheduler().empty());
    BOOST_CHECK(!engine.qualified());
    BOOST_CHECK(!engine.hardware_qualified());
    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.gpu());
    BOOST_CHECK(!engine.broadcast());
    BOOST_CHECK_EQUAL(engine.hosts(), 1);
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(engine.automatic_spend(), "0");

    const fs::path journal = m_path_root / modelnet::DT_MOMENTS_JOURNAL_NAME;
    const fs::path tmp = m_path_root / "moments.journal.tmp";

    BOOST_CHECK(!engine.Commit(fs::path{}, "w0", "m1", "s1", "rng0", "adamw", true, err));
    BOOST_CHECK_EQUAL(err, "DIR");
    BOOST_CHECK(engine.moment().empty());
    BOOST_CHECK(!fs::exists(journal));

    BOOST_CHECK(!engine.Commit(m_path_root, "", "m1", "s1", "rng0", "adamw", true, err));
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK(!engine.Commit(m_path_root, "w0", "", "s1", "rng0", "adamw", true, err));
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK(!engine.Commit(m_path_root, "w0", "m1", "", "rng0", "adamw", true, err));
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK(!engine.Commit(m_path_root, "w0", "m1", "s1", "", "adamw", true, err));
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK(!engine.Commit(m_path_root, "w0", "m1", "s1", "rng0", "", true, err));
    BOOST_CHECK_EQUAL(err, "STATE");
    BOOST_CHECK(engine.master().empty());
    BOOST_CHECK(engine.moment().empty());
    BOOST_CHECK(!fs::exists(journal));
    BOOST_CHECK(!fs::exists(tmp));

    BOOST_CHECK(!engine.Commit(m_path_root, "nan", "m1", "s1", "rng0", "adamw", true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK(!engine.Commit(m_path_root, "w0", "m1", "s1", "rng0", "inf", true, err));
    BOOST_CHECK_EQUAL(err, "FINITE");
    BOOST_CHECK(engine.moment().empty());
    BOOST_CHECK(!fs::exists(journal));

    BOOST_CHECK(!engine.Commit(m_path_root, "w0", "m1", "s1", "rng0", "adamw", false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK(engine.master().empty());
    BOOST_CHECK(engine.moment().empty());
    BOOST_CHECK(engine.scale().empty());
    BOOST_CHECK(engine.rng().empty());
    BOOST_CHECK(engine.scheduler().empty());
    BOOST_CHECK(!fs::exists(journal));
    BOOST_CHECK(!fs::exists(tmp));
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));

    BOOST_CHECK(!engine.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK(engine.moment().empty());
    BOOST_CHECK(!engine.gpu());
}

BOOST_AUTO_TEST_CASE(failed_later_commit_keeps_first_moment_and_reload)
{
    modelnet::DtMoments engine;
    std::string err;

    const fs::path journal = m_path_root / modelnet::DT_MOMENTS_JOURNAL_NAME;
    const fs::path tmp = m_path_root / "moments.journal.tmp";
    const std::string body = "w0\nm1\ns1\nrng0\nadamw\n";

    BOOST_CHECK(engine.Commit(m_path_root, "w0", "m1", "s1", "rng0", "adamw", true, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(engine.master(), "w0");
    BOOST_CHECK_EQUAL(engine.moment(), "m1");
    BOOST_CHECK_EQUAL(engine.scale(), "s1");
    BOOST_CHECK_EQUAL(engine.rng(), "rng0");
    BOOST_CHECK_EQUAL(engine.scheduler(), "adamw");
    BOOST_CHECK(fs::exists(journal));
    BOOST_CHECK(!fs::exists(tmp));
    BOOST_CHECK_EQUAL(ReadFile(journal), body);
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.hosts(), 1);
    BOOST_CHECK(!engine.qualified());
    BOOST_CHECK(!engine.hardware_qualified());

    const std::string kept = ReadFile(journal);
    BOOST_CHECK(!engine.Commit(m_path_root, "w1", "m1", "s1", "rng1", "sgd", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(engine.master(), "w0");
    BOOST_CHECK_EQUAL(engine.moment(), "m1");
    BOOST_CHECK_EQUAL(engine.scale(), "s1");
    BOOST_CHECK_EQUAL(engine.rng(), "rng0");
    BOOST_CHECK_EQUAL(engine.scheduler(), "adamw");
    BOOST_CHECK_EQUAL(ReadFile(journal), kept);
    BOOST_CHECK(!fs::exists(tmp));

    BOOST_CHECK(!engine.Commit(m_path_root, "w2", "m2", "s1", "rng2", "adamw", false, err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK_EQUAL(engine.master(), "w0");
    BOOST_CHECK_EQUAL(engine.moment(), "m1");
    BOOST_CHECK_EQUAL(engine.scale(), "s1");
    BOOST_CHECK_EQUAL(engine.rng(), "rng0");
    BOOST_CHECK_EQUAL(engine.scheduler(), "adamw");
    BOOST_CHECK_EQUAL(ReadFile(journal), kept);
    BOOST_CHECK(!fs::exists(tmp));

    BOOST_CHECK(!engine.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(engine.moment(), "m1");
    BOOST_CHECK_EQUAL(engine.master(), "w0");
    BOOST_CHECK_EQUAL(ReadFile(journal), kept);
    BOOST_CHECK(!engine.launched());
    BOOST_CHECK(!engine.gpu());
    BOOST_CHECK(!engine.broadcast());
    BOOST_CHECK(!engine.qualified());
    BOOST_CHECK(!engine.hardware_qualified());
    BOOST_CHECK_EQUAL(engine.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(engine.hosts(), 1);
    BOOST_CHECK_EQUAL(engine.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);

    modelnet::DtMoments missing;
    BOOST_CHECK(!missing.Reload(m_path_root / "absent", err));
    BOOST_CHECK_EQUAL(err, "JOURNAL");
    BOOST_CHECK(missing.master().empty());
    BOOST_CHECK(missing.moment().empty());
    BOOST_CHECK(missing.scale().empty());
    BOOST_CHECK(missing.rng().empty());
    BOOST_CHECK(missing.scheduler().empty());
    BOOST_CHECK_EQUAL(missing.bytes_moved(), static_cast<int64_t>(0));

    modelnet::DtMoments loaded;
    BOOST_CHECK(loaded.master().empty());
    BOOST_CHECK(loaded.Reload(m_path_root, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(loaded.master(), "w0");
    BOOST_CHECK_EQUAL(loaded.moment(), "m1");
    BOOST_CHECK_EQUAL(loaded.scale(), "s1");
    BOOST_CHECK_EQUAL(loaded.rng(), "rng0");
    BOOST_CHECK_EQUAL(loaded.scheduler(), "adamw");
    BOOST_CHECK_EQUAL(ReadFile(journal), kept);

    BOOST_CHECK(!loaded.Commit(m_path_root, "w9", "m1", "other", "rng9", "sgd", true, err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_REPLAY);
    BOOST_CHECK_EQUAL(loaded.moment(), "m1");
    BOOST_CHECK_EQUAL(loaded.master(), "w0");
    BOOST_CHECK_EQUAL(ReadFile(journal), kept);

    BOOST_CHECK(!loaded.Gpu(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_ENGINE_ABSENT);
    BOOST_CHECK_EQUAL(loaded.moment(), "m1");
    BOOST_CHECK_EQUAL(loaded.scheduler(), "adamw");
    BOOST_CHECK(!loaded.qualified());
    BOOST_CHECK(!loaded.hardware_qualified());
    BOOST_CHECK_EQUAL(loaded.bytes_moved(), static_cast<int64_t>(0));
    BOOST_CHECK_EQUAL(loaded.hosts(), 1);
}

BOOST_AUTO_TEST_SUITE_END()
