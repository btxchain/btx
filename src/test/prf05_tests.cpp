// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_disk.h>
#include <modelnet/prf05/prf05.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <fstream>
#include <iterator>
#include <string>
#include <system_error>

BOOST_FIXTURE_TEST_SUITE(prf05_tests, BasicTestingSetup)

namespace {

struct LabDirEnv {
    explicit LabDirEnv(const fs::path& dir)
    {
        const char* prev = std::getenv("BTX035_LAB_DIR");
        if (prev != nullptr) {
            m_had = true;
            m_prev = prev;
        }
        ::setenv("BTX035_LAB_DIR", PathToString(dir).c_str(), 1);
    }
    ~LabDirEnv()
    {
        if (m_had) {
            ::setenv("BTX035_LAB_DIR", m_prev.c_str(), 1);
        } else {
            ::unsetenv("BTX035_LAB_DIR");
        }
    }
    bool m_had{false};
    std::string m_prev;
};

std::string ReadFile(const fs::path& path)
{
    std::ifstream in(PathToString(path), std::ios::binary);
    BOOST_REQUIRE(in.good());
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

} // namespace

BOOST_AUTO_TEST_CASE(pass_latches)
{
    const fs::path missing = m_path_root / "prf05-missing";
    BOOST_CHECK(!fs::exists(missing));
    {
        LabDirEnv env(missing);
        modelnet::Prf05 early;
        std::string err = "stale";
        BOOST_CHECK(!early.Pass(err));
        BOOST_CHECK(!fs::exists(missing));
    }

    const fs::path dir = m_path_root / "prf05";
    fs::create_directories(dir);
    BOOST_REQUIRE(fs::is_directory(dir));
    const fs::path image = dir / "lab.json";
    const std::string truncated = "{\"automatic_spend_atoms\":\"0\"";
    {
        std::ofstream out(PathToString(image), std::ios::binary);
        out << truncated;
        BOOST_REQUIRE(out.good());
    }
    BOOST_REQUIRE(fs::is_regular_file(image));

    LabDirEnv env(dir);
    BOOST_CHECK_EQUAL(ReadFile(image), truncated);

    modelnet::LabDiskImage disk;
    std::string read_err = "stale";
    BOOST_CHECK(!modelnet::LoadLabDisk(disk, read_err));
    BOOST_CHECK_EQUAL(read_err, "BTX035_RECOVERY_REQUIRED");
    BOOST_CHECK_EQUAL(ReadFile(image), truncated);

    modelnet::Prf05 eng;
    std::string err = "stale";
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK_EQUAL(ReadFile(image), truncated);
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(!eng.passed());
    BOOST_CHECK(!eng.release_qualified());
    BOOST_CHECK(!eng.gpu_passed());
    BOOST_CHECK(!eng.windows_passed());
    BOOST_CHECK(!eng.hardware_qualified());
    BOOST_CHECK_EQUAL(eng.hosts(), static_cast<int64_t>(1));
    BOOST_CHECK(!eng.Release(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_UNQUALIFIED);
    BOOST_CHECK(!eng.Spend(err));
    BOOST_CHECK_EQUAL(err, modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK_EQUAL(eng.automatic_spend(), modelnet::NIFDT_AUTOMATIC_SPEND);
    BOOST_CHECK(fs::is_regular_file(image));
    BOOST_CHECK_EQUAL(ReadFile(image), truncated);
}

BOOST_AUTO_TEST_SUITE_END()
