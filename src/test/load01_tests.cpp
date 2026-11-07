// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/load01/load01.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <fstream>
#include <string>

BOOST_FIXTURE_TEST_SUITE(load01_tests, BasicTestingSetup)

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

std::string DigestOf(const std::string& bytes)
{
    std::uint64_t hash = kFnvOffset;
    for (unsigned char b : bytes) {
        hash ^= b;
        hash *= kFnvPrime;
    }
    return Hex64(hash);
}

void WriteBytes(const fs::path& path, const std::string& bytes)
{
    std::ofstream out{path, std::ios::binary};
    BOOST_REQUIRE(out);
    out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
    BOOST_REQUIRE(out);
}

struct TempFiles {
    fs::path file_a;
    fs::path file_b;
    fs::path dir;
    bool dir_created{false};

    explicit TempFiles(const fs::path& base)
    {
        file_a = base / "load01-a.bin";
        file_b = base / "load01-b.bin";
        dir = base / "load01-dir";
        dir_created = fs::create_directories(dir);
    }

    ~TempFiles()
    {
        fs::remove(file_a);
        fs::remove(file_b);
        fs::remove(dir);
    }
};

void ExpectUnqualified(const modelnet::Load01& eng)
{
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
}

} // namespace

BOOST_AUTO_TEST_CASE(legacy_integrity_file_accepts_second_path_without_qualification)
{
    TempFiles files(m_path_root);
    BOOST_REQUIRE(files.dir_created);
    BOOST_REQUIRE(fs::is_directory(files.dir));

    const std::string body_a = "alpha-ckpt";
    const std::string body_b = "beta-ckpt";
    WriteBytes(files.file_a, body_a);
    WriteBytes(files.file_b, body_b);

    const std::string path_a = fs::PathToString(files.file_a);
    const std::string path_b = fs::PathToString(files.file_b);
    const std::string path_dir = fs::PathToString(files.dir);
    const std::string missing = fs::PathToString(m_path_root / "load01-absent");
    const std::string digest_a = DigestOf(body_a);
    const std::string digest_b = DigestOf(body_b);
    const int64_t size_a = static_cast<int64_t>(body_a.size());

    modelnet::Load01 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.loaded());
    BOOST_CHECK_EQUAL(eng.bytes_read(), static_cast<int64_t>(0));
    ExpectUnqualified(eng);

    BOOST_CHECK(!eng.Load("", digest_a, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.loaded());
    BOOST_CHECK_EQUAL(eng.bytes_read(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Load(path_a, "", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(!eng.loaded());
    BOOST_CHECK_EQUAL(eng.bytes_read(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Load(missing, digest_a, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK(!eng.loaded());
    BOOST_CHECK_EQUAL(eng.bytes_read(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Load(path_dir, digest_a, err));
    BOOST_CHECK_EQUAL(err, "IO");
    BOOST_CHECK(!eng.loaded());
    BOOST_CHECK_EQUAL(eng.bytes_read(), static_cast<int64_t>(0));

    BOOST_CHECK(!eng.Load(path_a, std::string(16, '0'), err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK(!eng.loaded());
    BOOST_CHECK_EQUAL(eng.bytes_read(), static_cast<int64_t>(0));

    BOOST_CHECK(eng.Load(path_a, digest_a, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.loaded());
    BOOST_CHECK_EQUAL(eng.bytes_read(), size_a);
    BOOST_CHECK_EQUAL(digest_a.size(), 16U);
    ExpectUnqualified(eng);

    BOOST_CHECK(!eng.Load("", digest_b, err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK(eng.loaded());
    BOOST_CHECK_EQUAL(eng.bytes_read(), size_a);

    BOOST_CHECK(eng.Load(path_b, digest_b, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.loaded());
    BOOST_CHECK_EQUAL(eng.bytes_read(), static_cast<int64_t>(body_b.size()));
    ExpectUnqualified(eng);

    BOOST_CHECK(eng.Load(path_a, digest_a, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.loaded());
    BOOST_CHECK_EQUAL(eng.bytes_read(), size_a);
    ExpectUnqualified(eng);
}

BOOST_AUTO_TEST_SUITE_END()
