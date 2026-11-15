// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/cap02/cap02.h>
#include <modelnet/nifdt_contract/contract.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <fstream>
#include <string>

BOOST_FIXTURE_TEST_SUITE(cap02_tests, BasicTestingSetup)

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

struct TempDir {
    fs::path root;
    fs::path file_a;
    fs::path file_b;
    fs::path manifest;
    bool created{false};

    explicit TempDir(const fs::path& base)
    {
        root = base / "cap02-evidence";
        file_a = root / "a.txt";
        file_b = root / "b.txt";
        manifest = root / "manifest.txt";
        created = fs::create_directories(root);
    }

    ~TempDir()
    {
        fs::remove(file_a);
        fs::remove(file_b);
        fs::remove(manifest);
        fs::remove(root);
    }
};

} // namespace

BOOST_AUTO_TEST_CASE(qualify_manifest)
{
    TempDir dirs(m_path_root);
    BOOST_REQUIRE(dirs.created);
    BOOST_REQUIRE(fs::is_directory(dirs.root));

    const std::string dir = fs::PathToString(dirs.root);
    const std::string missing = fs::PathToString(m_path_root / "cap02-absent");

    modelnet::Cap02 eng;
    std::string err = "stale";

    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.files_checked(), 0);

    BOOST_CHECK(!eng.Qualify("", err));
    BOOST_CHECK_EQUAL(err, "FIELD");
    BOOST_CHECK_EQUAL(eng.files_checked(), 0);

    BOOST_CHECK(!eng.Qualify(missing, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.files_checked(), 0);

    BOOST_CHECK(!eng.Qualify(dir, err));
    BOOST_CHECK_EQUAL(err, "ABSENT");
    BOOST_CHECK_EQUAL(eng.files_checked(), 0);
    BOOST_CHECK(!eng.release_qualified());

    const std::string body_a = "alpha";
    const std::string body_b = "beta";
    WriteBytes(dirs.file_a, body_a);
    WriteBytes(dirs.file_b, body_b);
    const std::string hex_a = Hex64(Fnv1a(kFnvOffset, body_a));
    const std::string hex_b = Hex64(Fnv1a(kFnvOffset, body_b));
    WriteBytes(dirs.manifest, "a.txt " + hex_a + "\nb.txt " + hex_b + "\n");

    err = "stale";
    BOOST_CHECK(eng.Qualify(dir, err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(eng.files_checked(), 2);
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);

    WriteBytes(dirs.file_a, "alpha-tampered");
    BOOST_CHECK(!eng.Qualify(dir, err));
    BOOST_CHECK_EQUAL(err, "DIGEST");
    BOOST_CHECK_EQUAL(eng.files_checked(), 0);
    BOOST_CHECK(!eng.release_qualified());
}

BOOST_AUTO_TEST_SUITE_END()
