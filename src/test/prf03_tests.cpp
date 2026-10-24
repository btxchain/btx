// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/admission_routes.h>
#include <modelnet/prf03/prf03.h>
#include <test/util/setup_common.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <cstdlib>
#include <string>
#include <system_error>

BOOST_FIXTURE_TEST_SUITE(prf03_tests, BasicTestingSetup)

namespace {

struct LabDir {
    std::string previous;
    bool had{false};
    explicit LabDir(const fs::path& dir)
    {
        const char* cur = std::getenv("BTX035_LAB_DIR");
        had = cur != nullptr;
        if (had) previous = cur;
        ::setenv("BTX035_LAB_DIR", PathToString(dir).c_str(), 1);
    }
    ~LabDir()
    {
        if (had) ::setenv("BTX035_LAB_DIR", previous.c_str(), 1);
        else ::unsetenv("BTX035_LAB_DIR");
    }
};

struct AdmissionGuard {
    ~AdmissionGuard() { modelnet::ClearAdmissionMemory(); }
};

} // namespace

BOOST_AUTO_TEST_CASE(pass_latches)
{
    BOOST_REQUIRE(!m_path_root.empty());
    const fs::path dir = m_path_root / "prf03";
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir);
    BOOST_REQUIRE(fs::is_directory(dir));

    LabDir lab(dir);
    AdmissionGuard admission;

    modelnet::Prf03 eng;
    std::string err;
    BOOST_CHECK(eng.Pass(err));
    BOOST_CHECK(err.empty());
    BOOST_CHECK(eng.Pass(err));
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
}

BOOST_AUTO_TEST_SUITE_END()
