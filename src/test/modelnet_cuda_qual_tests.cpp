// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#if defined(BTX_MODEL_CUDA_QUALIFY_COMPILE)
#error "test_btx must not compile the CUDA qualification kernel stub"
#endif

#include <test/util/setup_common.h>

#include <crypto/common.h>
#include <modelnet/qualification.h>
#include <span.h>
#include <util/fs.h>

#include <boost/test/unit_test.hpp>

#include <cstdlib>
#include <fstream>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(modelnet_cuda_qual_tests, BasicTestingSetup)

namespace {

class EnvRestore
{
public:
    explicit EnvRestore(std::string key) : m_key(std::move(key))
    {
        if (const char* v = std::getenv(m_key.c_str())) {
            m_prev = std::string{v};
        }
    }
    ~EnvRestore()
    {
        if (m_prev) {
            setenv(m_key.c_str(), m_prev->c_str(), 1);
        } else {
            unsetenv(m_key.c_str());
        }
    }
    void Set(const char* v) { setenv(m_key.c_str(), v, 1); }
    void Unset() { unsetenv(m_key.c_str()); }

private:
    std::string m_key;
    std::optional<std::string> m_prev;
};

std::vector<unsigned char> MinimalSafeTensors()
{
    std::vector<unsigned char> st(10, 0);
    WriteLE64(st.data(), 2);
    st[8] = '{';
    st[9] = '}';
    return st;
}

fs::path WriteSafeTensors(const fs::path& dir, const std::string& name)
{
    fs::create_directories(dir);
    const fs::path path = dir / fs::PathFromString(name);
    const auto st = MinimalSafeTensors();
    std::ofstream out(path, std::ios::binary);
    BOOST_REQUIRE(out);
    out.write(reinterpret_cast<const char*>(st.data()), static_cast<std::streamsize>(st.size()));
    BOOST_REQUIRE(out);
    return path;
}

fs::path WriteBytes(const fs::path& dir, const std::string& name, Span<const unsigned char> bytes)
{
    fs::create_directories(dir);
    const fs::path path = dir / fs::PathFromString(name);
    std::ofstream out(path, std::ios::binary);
    BOOST_REQUIRE(out);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    BOOST_REQUIRE(out);
    return path;
}

} // namespace

BOOST_AUTO_TEST_CASE(looks_like_pickle_still_rejects)
{
    const unsigned char proto4[] = {0x80, 0x04, 0x95};
    BOOST_CHECK(modelnet::LooksLikePickle(Span<const unsigned char>{proto4, sizeof(proto4)}));
    const unsigned char proto2[] = {0x80, 0x02};
    BOOST_CHECK(modelnet::LooksLikePickle(Span<const unsigned char>{proto2, sizeof(proto2)}));
    const unsigned char too_new[] = {0x80, 0x06};
    BOOST_CHECK(!modelnet::LooksLikePickle(Span<const unsigned char>{too_new, sizeof(too_new)}));
    BOOST_CHECK(!modelnet::LooksLikePickle(Span<const unsigned char>{}));

    modelnet::QualReport report;
    BOOST_CHECK(modelnet::QualifyBytes("model.pkl", Span<const unsigned char>{proto4, sizeof(proto4)}, report) ==
                modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    BOOST_CHECK(report.result != modelnet::QualResult::RUNTIME_OBSERVED);

    const unsigned char junk[] = {1, 2, 3};
    BOOST_CHECK(modelnet::QualifyBytes("weights.pt", Span<const unsigned char>{junk, sizeof(junk)}, report) ==
                modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
}

BOOST_AUTO_TEST_CASE(qualify_file_is_structure_or_profile_only)
{
    BOOST_CHECK(!modelnet::ModelCudaQualifyKernelCompiled());

    const fs::path path = WriteSafeTensors(m_args.GetDataDirBase() / "cuda-qual", "model.safetensors");
    modelnet::QualReport report;
    const auto qr = modelnet::QualifyFile(fs::PathToString(path), report);
    BOOST_CHECK(qr == modelnet::QualResult::STRUCTURE_VERIFIED || qr == modelnet::QualResult::PROFILE_VERIFIED);
    BOOST_CHECK(qr != modelnet::QualResult::RUNTIME_OBSERVED);
    BOOST_CHECK(qr != modelnet::QualResult::NOT_RUN_CUDA_ISOLATION);
    BOOST_CHECK_EQUAL(std::string{modelnet::QualResultName(qr)}, "STRUCTURE_VERIFIED");
}

BOOST_AUTO_TEST_CASE(qualify_runtime_default_does_not_need_libcuda)
{
    const fs::path path = WriteSafeTensors(m_args.GetDataDirBase() / "cuda-qual", "runtime-default.safetensors");
    modelnet::QualReport report;
    modelnet::QualRuntimeOpts opts; // runtime_check=false, gpu unset, allow_validator_gpu=false
    const auto qr = modelnet::QualifyRuntime(fs::PathToString(path), opts, report);
    BOOST_CHECK(qr == modelnet::QualResult::NOT_RUN_CUDA_ISOLATION);
    BOOST_CHECK(qr != modelnet::QualResult::RUNTIME_OBSERVED);
    BOOST_CHECK(report.detail.find("-modelruntimecheck=0") != std::string::npos);
    BOOST_CHECK(report.detail.find("isolated worker not invoked") != std::string::npos);
    BOOST_CHECK_EQUAL(std::string{modelnet::QualResultName(qr)}, "NOT_RUN_CUDA_ISOLATION");
}

BOOST_AUTO_TEST_CASE(qualify_runtime_requires_modelgpu_when_check_enabled)
{
    const fs::path path = WriteSafeTensors(m_args.GetDataDirBase() / "cuda-qual", "runtime-nogpu.safetensors");
    modelnet::QualReport report;
    modelnet::QualRuntimeOpts opts;
    opts.runtime_check = true;
    const auto qr = modelnet::QualifyRuntime(fs::PathToString(path), opts, report);
    BOOST_CHECK(qr == modelnet::QualResult::NOT_RUN_RESOURCE_LIMIT);
    BOOST_CHECK(report.detail.find("-modelgpu") != std::string::npos);
    BOOST_CHECK(report.detail.find("non-validator") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(qualify_runtime_refuses_validator_and_default_mining_gpu)
{
    const fs::path path = WriteSafeTensors(m_args.GetDataDirBase() / "cuda-qual", "runtime-gpu0.safetensors");
    EnvRestore env{"BTX_VALIDATOR_GPU"};
    env.Unset();
    BOOST_CHECK_EQUAL(modelnet::ValidatorGpuIndex(), modelnet::DEFAULT_MINING_GPU_INDEX);
    BOOST_CHECK(modelnet::IsValidatorOrMiningGpu(0));

    modelnet::QualRuntimeOpts opts;
    opts.runtime_check = true;
    opts.gpu_index = 0;
    opts.allow_validator_gpu = false;
    modelnet::QualReport report;
    auto qr = modelnet::QualifyRuntime(fs::PathToString(path), opts, report);
    BOOST_CHECK(qr == modelnet::QualResult::NOT_RUN_CUDA_ISOLATION);
    BOOST_CHECK(report.detail.find("never cudaSetDevice") != std::string::npos);
    BOOST_CHECK(qr != modelnet::QualResult::RUNTIME_OBSERVED);

    env.Set("1");
    BOOST_CHECK_EQUAL(modelnet::ValidatorGpuIndex(), 1);
    BOOST_CHECK(modelnet::IsValidatorOrMiningGpu(0));
    BOOST_CHECK(modelnet::IsValidatorOrMiningGpu(1));
    BOOST_CHECK(!modelnet::IsValidatorOrMiningGpu(2));

    opts.gpu_index = 1;
    qr = modelnet::QualifyRuntime(fs::PathToString(path), opts, report);
    BOOST_CHECK(qr == modelnet::QualResult::NOT_RUN_CUDA_ISOLATION);
    BOOST_CHECK(report.detail.find("never cudaSetDevice") != std::string::npos);

    opts.gpu_index = 0;
    qr = modelnet::QualifyRuntime(fs::PathToString(path), opts, report);
    BOOST_CHECK(qr == modelnet::QualResult::NOT_RUN_CUDA_ISOLATION);

    // Opt-in still must not launch CUDA: the kernel stub is not compiled.
    opts.allow_validator_gpu = true;
    qr = modelnet::QualifyRuntime(fs::PathToString(path), opts, report);
    BOOST_CHECK(qr != modelnet::QualResult::RUNTIME_OBSERVED);
    BOOST_CHECK(qr == modelnet::QualResult::NOT_RUN_RESOURCE_LIMIT);
}

BOOST_AUTO_TEST_CASE(qualify_runtime_non_validator_gpu_still_not_compiled)
{
    const fs::path path = WriteSafeTensors(m_args.GetDataDirBase() / "cuda-qual", "runtime-gpu2.safetensors");
    EnvRestore env{"BTX_VALIDATOR_GPU"};
    env.Set("0");

    modelnet::QualRuntimeOpts opts;
    opts.runtime_check = true;
    opts.gpu_index = 2;
    opts.allow_validator_gpu = false;
    modelnet::QualReport report;
    const auto qr = modelnet::QualifyRuntime(fs::PathToString(path), opts, report);
    BOOST_CHECK(!modelnet::ModelCudaQualifyKernelCompiled());
    BOOST_CHECK(qr == modelnet::QualResult::NOT_RUN_RESOURCE_LIMIT);
    BOOST_CHECK(qr != modelnet::QualResult::RUNTIME_OBSERVED);
    BOOST_CHECK(report.detail.find("BTX_MODEL_CUDA_QUALIFY_COMPILE") != std::string::npos);
    BOOST_CHECK(report.detail.find("libcuda") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(qualify_runtime_never_executes_pickle)
{
    const unsigned char pickle[] = {0x80, 0x04, 0x95};
    const fs::path path = WriteBytes(m_args.GetDataDirBase() / "cuda-qual", "evil.pkl",
                                     Span<const unsigned char>{pickle, sizeof(pickle)});
    modelnet::QualRuntimeOpts opts;
    opts.runtime_check = true;
    opts.gpu_index = 2;
    opts.allow_validator_gpu = true;
    modelnet::QualReport report;
    const auto qr = modelnet::QualifyRuntime(fs::PathToString(path), opts, report);
    BOOST_CHECK(qr == modelnet::QualResult::REJECTED_UNSAFE_FORMAT);
    BOOST_CHECK(qr != modelnet::QualResult::RUNTIME_OBSERVED);
}

BOOST_AUTO_TEST_CASE(qualify_runtime_mock_worker_gpu01)
{
    const fs::path dir = m_args.GetDataDirBase() / "cuda-qual";
    const fs::path path = WriteSafeTensors(dir, "runtime-worker.safetensors");
    const fs::path worker = dir / fs::PathFromString("mock_cuda_qual_worker");
    {
        std::ofstream out(worker);
        BOOST_REQUIRE(out);
        out << "#!/usr/bin/env bash\n"
            << "echo \"GPU-01 RUNTIME_OBSERVED backend=mock $*\"\n";
        BOOST_REQUIRE(out);
    }
    BOOST_REQUIRE_EQUAL(::chmod(fs::PathToString(worker).c_str(), 0755), 0);

    EnvRestore worker_env{"BTX_CUDA_QUAL_WORKER"};
    EnvRestore share_env{"BTX_ALLOW_SHARED_GPU"};
    EnvRestore validator{"BTX_VALIDATOR_GPU"};
    worker_env.Set(fs::PathToString(worker).c_str());
    share_env.Unset();
    validator.Set("0");

    modelnet::QualRuntimeOpts opts;
    opts.runtime_check = true;
    opts.gpu_index = 2;
    opts.allow_validator_gpu = false;
    modelnet::QualReport report;
    const auto qr = modelnet::QualifyRuntime(fs::PathToString(path), opts, report);
    BOOST_CHECK_EQUAL(std::string{modelnet::QualResultName(qr)}, "RUNTIME_OBSERVED");
    BOOST_CHECK(qr == modelnet::QualResult::RUNTIME_OBSERVED);
    BOOST_CHECK(report.detail.find("GPU-01 RUNTIME_OBSERVED") != std::string::npos);
    BOOST_CHECK(report.detail.find("--gpu=2") != std::string::npos);
}

BOOST_AUTO_TEST_SUITE_END()
