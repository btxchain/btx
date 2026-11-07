// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_engine.h>
#include <modelnet/swarm_infer/engine_bind.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <string>
#include <system_error>

namespace {

struct TempRegularFile {
    explicit TempRegularFile(const fs::path& file) : path(file)
    {
        std::ofstream out(path);
        out << "not-an-engine\n";
        BOOST_REQUIRE(out.good());
    }
    ~TempRegularFile()
    {
        std::error_code ec;
        fs::remove(path, ec);
    }
    TempRegularFile(const TempRegularFile&) = delete;
    TempRegularFile& operator=(const TempRegularFile&) = delete;
    fs::path path;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(swarm_infer_bind_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(empty_name_is_engine_and_stores_nothing)
{
    const TempRegularFile file(m_path_root / "swarm-infer-empty-name.bin");
    std::string err = "prior";
    const modelnet::SwarmInferBinding binding = modelnet::SwarmInferProbeAndQualify("", file.path, err);
    BOOST_CHECK_EQUAL(binding.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
    BOOST_REQUIRE(!binding.stored);
    BOOST_REQUIRE(!binding.present);
    BOOST_REQUIRE(!binding.qualified);
    BOOST_REQUIRE(!binding.advertised);
    BOOST_REQUIRE(binding.name.empty());
    BOOST_REQUIRE(binding.binary.empty());
    BOOST_REQUIRE(binding.status.empty());
    BOOST_REQUIRE(fs::is_regular_file(file.path));
}

BOOST_AUTO_TEST_CASE(empty_path_is_engine_and_stores_nothing)
{
    std::string err = "prior";
    const modelnet::SwarmInferBinding binding = modelnet::SwarmInferProbeAndQualify("engine", fs::path{}, err);
    BOOST_CHECK_EQUAL(binding.code, "ENGINE");
    BOOST_CHECK_EQUAL(err, "ENGINE");
    BOOST_REQUIRE(!binding.stored);
    BOOST_REQUIRE(!binding.present);
    BOOST_REQUIRE(binding.name.empty());
    BOOST_REQUIRE(binding.binary.empty());
}

BOOST_AUTO_TEST_CASE(missing_file_is_engine_absent)
{
    const fs::path missing = m_path_root / "swarm-infer-missing.bin";
    std::error_code ec;
    fs::remove(missing, ec);
    std::string err = "prior";
    const modelnet::SwarmInferBinding binding = modelnet::SwarmInferProbeAndQualify("vllm", missing, err);
    BOOST_CHECK_EQUAL(binding.code, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(binding.status, "ENGINE_ABSENT");
    BOOST_CHECK_EQUAL(err, "ENGINE_ABSENT");
    BOOST_REQUIRE(binding.stored);
    BOOST_REQUIRE(!binding.present);
    BOOST_REQUIRE(!binding.qualified);
    BOOST_REQUIRE(!binding.advertised);
    BOOST_REQUIRE_EQUAL(binding.name, "vllm");
    BOOST_REQUIRE(!fs::exists(missing));
}

BOOST_AUTO_TEST_CASE(directory_is_engine_absent)
{
    const fs::path dir = m_path_root / "swarm-infer-not-a-file";
    BOOST_REQUIRE(fs::create_directory(dir));
    struct RemovePath {
        fs::path path;
        ~RemovePath()
        {
            std::error_code ec;
            fs::remove(path, ec);
        }
    } cleanup{dir};
    std::string err = "prior";
    const modelnet::SwarmInferBinding binding = modelnet::SwarmInferProbeAndQualify("sglang", dir, err);
    BOOST_CHECK_EQUAL(binding.code, "ENGINE_ABSENT");
    BOOST_REQUIRE(!binding.present);
    BOOST_REQUIRE(!binding.qualified);
    BOOST_REQUIRE(!binding.advertised);
    BOOST_REQUIRE(fs::is_directory(cleanup.path));
}

BOOST_AUTO_TEST_CASE(regular_file_is_installed_and_unqualified)
{
    const TempRegularFile file(m_path_root / "swarm-infer-installed.bin");
    std::string probe_err;
    modelnet::SwarmEngineStatus probed = modelnet::SwarmProbeEngine("torch", file.path, probe_err);
    BOOST_REQUIRE(probed.present);
    BOOST_REQUIRE_EQUAL(probed.code, "INSTALLED");
    BOOST_REQUIRE(!modelnet::SwarmQualifyEngine(probed, false, 0.0, probe_err));
    BOOST_REQUIRE(!probed.qualified);
    BOOST_REQUIRE(!probed.advertised);
    BOOST_REQUIRE_EQUAL(probe_err, "UNQUALIFIED");

    std::string err = "prior";
    const modelnet::SwarmInferBinding binding = modelnet::SwarmInferProbeAndQualify("torch", file.path, err);
    BOOST_REQUIRE(binding.stored);
    BOOST_REQUIRE(binding.present);
    BOOST_REQUIRE(!binding.qualified);
    BOOST_REQUIRE(!binding.advertised);
    BOOST_REQUIRE_EQUAL(binding.status, "INSTALLED");
    BOOST_REQUIRE_EQUAL(binding.code, "UNQUALIFIED");
    BOOST_REQUIRE_EQUAL(err, "UNQUALIFIED");
    BOOST_REQUIRE_EQUAL(binding.name, "torch");
    BOOST_REQUIRE(binding.binary == file.path);
    BOOST_REQUIRE(fs::is_regular_file(file.path));
}

BOOST_AUTO_TEST_SUITE_END()
