// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/nifdt_contract/contract.h>
#include <modelnet/proc08/proc08.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <fstream>
#include <string>

BOOST_FIXTURE_TEST_SUITE(proc08_tests, BasicTestingSetup)

namespace {

constexpr std::uint64_t kFnvOffset = 14695981039346656037ULL;
constexpr std::uint64_t kFnvPrime = 1099511628211ULL;

std::string Hex64(std::uint64_t hash)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out(16, '0');
    for (int i = 0; i < 16; ++i) {
        const int shift = (15 - i) * 4;
        out[static_cast<std::size_t>(i)] = kHex[(hash >> shift) & 0xF];
    }
    return out;
}

std::uint64_t Fnv1a(std::uint64_t hash, const std::string& bytes)
{
    for (unsigned char b : bytes) {
        hash ^= b;
        hash *= kFnvPrime;
    }
    return hash;
}

void WriteBytes(const fs::path& path, const std::string& bytes)
{
    std::ofstream out{path, std::ios::binary};
    BOOST_REQUIRE(out);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    BOOST_REQUIRE(out);
}

struct TempDirs {
    fs::path evidence;
    fs::path outside;
    fs::path nested;
    fs::path nested_file;
    fs::path file_a;
    fs::path file_b;
    fs::path file_c;
    bool evidence_created{false};
    bool outside_created{false};

    explicit TempDirs(const fs::path& base)
    {
        evidence = base / "proc08-evidence";
        outside = base / "proc08-outside";
        nested = evidence / "sub";
        nested_file = nested / "z.txt";
        file_a = evidence / "a.txt";
        file_b = evidence / "b.txt";
        file_c = evidence / "c.txt";
        evidence_created = fs::create_directories(evidence);
        outside_created = fs::create_directories(outside);
    }

    ~TempDirs()
    {
        fs::remove(nested_file);
        fs::remove(nested);
        fs::remove(file_a);
        fs::remove(file_b);
        fs::remove(file_c);
        fs::remove(evidence);
        fs::remove(outside);
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(evidence_and_research_path)
{
    TempDirs dirs(m_path_root);
    BOOST_REQUIRE(dirs.evidence_created);
    BOOST_REQUIRE(dirs.outside_created);
    BOOST_REQUIRE(fs::is_directory(dirs.evidence));
    BOOST_REQUIRE(fs::is_directory(dirs.outside));
    BOOST_REQUIRE(fs::create_directories(dirs.nested));
    WriteBytes(dirs.nested_file, "nested");

    const std::string evidence = fs::PathToString(dirs.evidence);
    const std::string outside = fs::PathToString(dirs.outside);
    const std::string missing = fs::PathToString(m_path_root / "proc08-absent");

    modelnet::Proc08 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(!eng.research_outside());
    BOOST_CHECK(eng.digest().empty());
    BOOST_CHECK_EQUAL(eng.files_hashed(), 0);

    BOOST_CHECK(!eng.ReadEvidence("", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(eng.digest().empty());
    BOOST_CHECK_EQUAL(eng.files_hashed(), 0);

    BOOST_CHECK(!eng.ReadEvidence(missing, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(eng.digest().empty());
    BOOST_CHECK_EQUAL(eng.files_hashed(), 0);

    BOOST_CHECK(!eng.ReadEvidence(evidence, err));
    BOOST_CHECK_EQUAL(err, "EMPTY");
    BOOST_CHECK(eng.digest().empty());
    BOOST_CHECK_EQUAL(eng.files_hashed(), 0);
    BOOST_CHECK(!eng.release_qualified());

    WriteBytes(dirs.file_b, "beta");
    WriteBytes(dirs.file_a, "alpha");
    WriteBytes(dirs.file_c, "");

    const std::uint64_t expect = Fnv1a(Fnv1a(Fnv1a(kFnvOffset, "alpha"), "beta"), "");
    const std::string expect_hex = Hex64(expect);

    BOOST_CHECK(eng.ReadEvidence(evidence, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.files_hashed(), 3);
    BOOST_CHECK_EQUAL(eng.digest(), expect_hex);
    BOOST_CHECK_EQUAL(eng.digest().size(), 16U);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);

    BOOST_CHECK(eng.ReadEvidence(evidence, err));
    BOOST_CHECK_EQUAL(eng.digest(), expect_hex);
    BOOST_CHECK_EQUAL(eng.files_hashed(), 3);
    BOOST_CHECK(!eng.release_qualified());

    BOOST_CHECK(!eng.AcceptResearchPath("", evidence, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.research_outside());
    BOOST_CHECK(!eng.AcceptResearchPath(outside, "", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.research_outside());

    BOOST_CHECK(!eng.AcceptResearchPath(evidence, evidence, err));
    BOOST_CHECK_EQUAL(err, "INSIDE");
    BOOST_CHECK(!eng.research_outside());
    BOOST_CHECK(!eng.AcceptResearchPath(fs::PathToString(dirs.file_a), evidence, err));
    BOOST_CHECK_EQUAL(err, "INSIDE");
    BOOST_CHECK(!eng.research_outside());
    BOOST_CHECK(!eng.AcceptResearchPath(evidence + "/missing", evidence, err));
    BOOST_CHECK_EQUAL(err, "INSIDE");
    BOOST_CHECK(!eng.research_outside());

    BOOST_CHECK(!eng.AcceptResearchPath(missing, evidence, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.research_outside());

    err = "stale";
    BOOST_CHECK(eng.AcceptResearchPath(outside, evidence, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.research_outside());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
}

BOOST_AUTO_TEST_SUITE_END()
