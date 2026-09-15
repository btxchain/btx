// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/qualification.h>

#include <crypto/common.h>
#include <univalue.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <set>
#include <vector>

#ifndef WIN32
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
extern char** environ;
#endif

namespace modelnet {

const char* QualResultName(QualResult r)
{
    switch (r) {
    case QualResult::STRUCTURE_VERIFIED: return "STRUCTURE_VERIFIED";
    case QualResult::PROFILE_VERIFIED: return "PROFILE_VERIFIED";
    case QualResult::RUNTIME_OBSERVED: return "RUNTIME_OBSERVED";
    case QualResult::INVALID_MODEL: return "INVALID_MODEL";
    case QualResult::NOT_RUN_RESOURCE_LIMIT: return "NOT_RUN_RESOURCE_LIMIT";
    case QualResult::REJECTED_UNSAFE_FORMAT: return "REJECTED_UNSAFE_FORMAT";
    case QualResult::ENCRYPTED_UNQUALIFIED: return "ENCRYPTED_UNQUALIFIED";
    case QualResult::NOT_RUN_CUDA_ISOLATION: return "NOT_RUN_CUDA_ISOLATION";
    }
    return "UNKNOWN";
}

bool LooksLikePickle(Span<const unsigned char> bytes)
{
    if (bytes.size() < 2) return false;
    // Protocol 2/3/4 pickle opcodes start with 0x80 then a version byte.
    return bytes[0] == 0x80 && bytes[1] <= 5;
}

bool LooksLikeExecutable(const std::string& filename_hint, Span<const unsigned char> bytes)
{
    const auto lower = ToLower(filename_hint);
    if (lower.ends_with(".pt") || lower.ends_with(".pth") || lower.ends_with(".pkl") ||
        lower.ends_with(".py") || lower.ends_with(".so") || lower.ends_with(".dll") ||
        lower.ends_with(".ipynb") || lower.ends_with(".sh") || lower.ends_with(".cu")) {
        return true;
    }
    if (bytes.size() >= 4 && bytes[0] == 0x7f && bytes[1] == 'E' && bytes[2] == 'L' && bytes[3] == 'F') return true;
    if (bytes.size() >= 2 && bytes[0] == 'M' && bytes[1] == 'Z') return true;
    return LooksLikePickle(bytes);
}

namespace {

constexpr uint64_t MAX_ST_HEADER = 8ULL << 20;
constexpr uint64_t MAX_TENSORS = 200000;

QualResult QualifySafeTensors(Span<const unsigned char> header_and_maybe_body, uint64_t file_size, QualReport& report)
{
    if (header_and_maybe_body.size() < 8) {
        report.detail = "truncated safetensors";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    const uint64_t hlen = ReadLE64(header_and_maybe_body.data());
    report.header_bytes = hlen;
    if (hlen == 0 || hlen > MAX_ST_HEADER || 8 + hlen > header_and_maybe_body.size()) {
        report.detail = "safetensors header size";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    if (8 + hlen > file_size) {
        report.detail = "safetensors header size";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    std::string json(reinterpret_cast<const char*>(header_and_maybe_body.data() + 8), hlen);
    if (json.find('\0') != std::string::npos) {
        report.detail = "NUL in header";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    UniValue header;
    if (!header.read(json) || !header.isObject()) {
        report.detail = "safetensors header json";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    uint64_t tensors = 0;
    uint64_t max_end = 8 + hlen;
    static const std::set<std::string> dtypes{"F32", "F16", "BF16", "F64", "I8", "I16", "I32", "I64", "U8", "U16", "U32", "U64", "BOOL", "F8_E4M3", "F8_E5M2"};
    for (const auto& key : header.getKeys()) {
        if (key == "__metadata__") continue;
        ++tensors;
        const UniValue& t = header[key];
        if (!t.isObject() || !t.exists("dtype") || !t.exists("shape") || !t.exists("data_offsets")) {
            report.detail = "tensor missing fields";
            report.result = QualResult::INVALID_MODEL;
            return report.result;
        }
        if (!t["dtype"].isStr() || !dtypes.count(t["dtype"].get_str())) {
            report.detail = "unsupported dtype";
            report.result = QualResult::INVALID_MODEL;
            return report.result;
        }
        if (!t["shape"].isArray() || t["data_offsets"].size() != 2) {
            report.detail = "tensor geometry";
            report.result = QualResult::INVALID_MODEL;
            return report.result;
        }
        uint64_t numel = 1;
        for (const auto& d : t["shape"].getValues()) {
            const uint64_t dim = d.getInt<uint64_t>();
            if (dim > 0 && numel > (UINT64_MAX / dim)) {
                report.detail = "shape overflow";
                report.result = QualResult::INVALID_MODEL;
                return report.result;
            }
            numel *= dim;
        }
        const uint64_t begin = t["data_offsets"][0].getInt<uint64_t>();
        const uint64_t end = t["data_offsets"][1].getInt<uint64_t>();
        if (end < begin || 8 + hlen + end > file_size) {
            report.detail = "tensor offset";
            report.result = QualResult::INVALID_MODEL;
            return report.result;
        }
        max_end = std::max(max_end, 8 + hlen + end);
    }
    report.tensor_count = tensors;
    if (tensors > MAX_TENSORS) {
        report.detail = "too many tensors";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    if (max_end != file_size) {
        report.detail = "trailing or missing tensor bytes";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    report.result = QualResult::STRUCTURE_VERIFIED;
    report.level = AdmissionLevel::STRUCTURE_VERIFIED;
    report.detail = "safetensors structure ok; not a claim of safety or usefulness";
    return report.result;
}

QualResult QualifyGGUF(Span<const unsigned char> bytes, QualReport& report)
{
    if (bytes.size() < 24) {
        report.detail = "truncated gguf";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    if (std::memcmp(bytes.data(), "GGUF", 4) != 0) {
        report.detail = "not gguf";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    const uint32_t version = ReadLE32(bytes.data() + 4);
    if (version < 1 || version > 3) {
        report.detail = "unsupported gguf version";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    const uint64_t n_tensors = ReadLE64(bytes.data() + 8);
    const uint64_t n_kv = ReadLE64(bytes.data() + 16);
    report.tensor_count = n_tensors;
    if (n_tensors > MAX_TENSORS || n_kv > 1024) {
        report.detail = "gguf counts";
        report.result = QualResult::INVALID_MODEL;
        return report.result;
    }
    report.result = QualResult::STRUCTURE_VERIFIED;
    report.level = AdmissionLevel::STRUCTURE_VERIFIED;
    report.detail = "gguf magic/version/counts ok; tensor inventory not profile-matched";
    return report.result;
}

} // namespace

QualResult QualifyBytes(const std::string& filename_hint, Span<const unsigned char> bytes, QualReport& report)
{
    report = {};
    if (LooksLikeExecutable(filename_hint, bytes)) {
        report.result = QualResult::REJECTED_UNSAFE_FORMAT;
        report.detail = "rejected pickle/executable/script format";
        report.level = AdmissionLevel::FAILED;
        return report.result;
    }
    const auto lower = ToLower(filename_hint);
    if (bytes.size() >= 8 && std::memcmp(bytes.data(), "BTXENC2", 7) == 0) {
        report.result = QualResult::ENCRYPTED_UNQUALIFIED;
        report.level = AdmissionLevel::ENCRYPTED_UNQUALIFIED;
        report.detail = "ciphertext only; not a plaintext model check";
        return report.result;
    }
    if (lower.ends_with(".safetensors") || (bytes.size() >= 8 && bytes[0] < 8 && bytes[1] == 0)) {
        return QualifySafeTensors(bytes, bytes.size(), report);
    }
    if (lower.ends_with(".gguf") || (bytes.size() >= 4 && std::memcmp(bytes.data(), "GGUF", 4) == 0)) {
        return QualifyGGUF(bytes, report);
    }
    report.result = QualResult::REJECTED_UNSAFE_FORMAT;
    report.detail = "unsupported model container";
    report.level = AdmissionLevel::FAILED;
    return report.result;
}

QualResult QualifyFile(const std::string& path, QualReport& report)
{
    report = {};
    const auto lower = ToLower(path);
    if (LooksLikeExecutable(path, Span<const unsigned char>{})) {
        report.result = QualResult::REJECTED_UNSAFE_FORMAT;
        report.detail = "rejected pickle/executable/script format";
        report.level = AdmissionLevel::FAILED;
        return report.result;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        report.result = QualResult::INVALID_MODEL;
        report.detail = "cannot open";
        report.level = AdmissionLevel::FAILED;
        return report.result;
    }
    in.seekg(0, std::ios::end);
    const std::streamoff sz = in.tellg();
    if (sz < 0) {
        report.result = QualResult::INVALID_MODEL;
        report.detail = "stat failed";
        return report.result;
    }
    const uint64_t file_size = static_cast<uint64_t>(sz);
    in.seekg(0);
    unsigned char magic[24]{};
    const size_t want = std::min<uint64_t>(file_size, 24);
    in.read(reinterpret_cast<char*>(magic), static_cast<std::streamsize>(want));
    const auto prefix = Span<const unsigned char>{magic, static_cast<size_t>(in.gcount())};
    if (LooksLikePickle(prefix) || LooksLikeExecutable(path, prefix)) {
        report.result = QualResult::REJECTED_UNSAFE_FORMAT;
        report.detail = "rejected pickle/executable/script format";
        report.level = AdmissionLevel::FAILED;
        return report.result;
    }
    if (prefix.size() >= 8 && std::memcmp(magic, "BTXENC2", 7) == 0) {
        report.result = QualResult::ENCRYPTED_UNQUALIFIED;
        report.level = AdmissionLevel::ENCRYPTED_UNQUALIFIED;
        report.detail = "ciphertext only; not a plaintext model check";
        return report.result;
    }
    if (lower.ends_with(".gguf") || (prefix.size() >= 4 && std::memcmp(magic, "GGUF", 4) == 0)) {
        std::vector<unsigned char> head(prefix.begin(), prefix.end());
        return QualifyGGUF(head, report);
    }
    if (lower.ends_with(".safetensors") || (prefix.size() >= 2 && magic[1] == 0)) {
        if (file_size < 8) {
            report.result = QualResult::INVALID_MODEL;
            report.detail = "truncated safetensors";
            return report.result;
        }
        const uint64_t hlen = ReadLE64(magic);
        if (hlen == 0 || hlen > MAX_ST_HEADER || 8 + hlen > file_size) {
            report.result = QualResult::INVALID_MODEL;
            report.detail = "safetensors header size";
            return report.result;
        }
        std::vector<unsigned char> buf(8 + static_cast<size_t>(hlen));
        in.clear();
        in.seekg(0);
        in.read(reinterpret_cast<char*>(buf.data()), static_cast<std::streamsize>(buf.size()));
        if (static_cast<uint64_t>(in.gcount()) != buf.size()) {
            report.result = QualResult::INVALID_MODEL;
            report.detail = "truncated safetensors header";
            return report.result;
        }
        return QualifySafeTensors(buf, file_size, report);
    }
    report.result = QualResult::REJECTED_UNSAFE_FORMAT;
    report.detail = "unsupported model container";
    report.level = AdmissionLevel::FAILED;
    return report.result;
}

int ValidatorGpuIndex()
{
    if (const char* env = std::getenv("BTX_VALIDATOR_GPU")) {
        int32_t parsed = 0;
        if (ParseInt32(env, &parsed) && parsed >= 0) {
            return parsed;
        }
    }
    return DEFAULT_MINING_GPU_INDEX;
}

bool IsValidatorOrMiningGpu(int gpu_index)
{
    return gpu_index == DEFAULT_MINING_GPU_INDEX || gpu_index == ValidatorGpuIndex();
}

bool ModelCudaQualifyKernelCompiled()
{
#ifdef BTX_MODEL_CUDA_QUALIFY_COMPILE
    return true;
#else
    return false;
#endif
}

bool ModelWorkTakesConsensusLock()
{
    return false;
}

bool ModelWorkMayStarveExactReplay()
{
    return false;
}

namespace {

QualResult FinishNotRun(QualReport& report, QualResult result, std::string detail)
{
    report.result = result;
    report.level = AdmissionLevel::NOT_RUN_RESOURCE_LIMIT;
    report.detail = std::move(detail);
    return result;
}

#ifndef WIN32
std::string FindCudaQualWorker()
{
    if (const char* env = std::getenv("BTX_CUDA_QUAL_WORKER")) {
        if (env[0] != '\0') {
            if (::access(env, X_OK) == 0) return std::string{env};
            return {};
        }
    }
    const char* path_env = std::getenv("PATH");
    if (!path_env) return {};
    const std::string path{path_env};
    size_t start = 0;
    while (start <= path.size()) {
        const size_t colon = path.find(':', start);
        const std::string dir = path.substr(start, colon == std::string::npos ? std::string::npos : colon - start);
        const std::string cand = (dir.empty() ? std::string{"."} : dir) + "/cuda_qual_worker";
        if (::access(cand.c_str(), X_OK) == 0) return cand;
        if (colon == std::string::npos) break;
        start = colon + 1;
    }
    return {};
}

bool AllowSharedGpuFromEnv()
{
    const char* env = std::getenv("BTX_ALLOW_SHARED_GPU");
    return env && env[0] != '\0' && std::strcmp(env, "0") != 0;
}

QualResult SpawnIsolatedCudaWorker(const std::string& worker, int gpu, QualReport& report)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        return FinishNotRun(report, QualResult::NOT_RUN_RESOURCE_LIMIT, "isolated CUDA worker: pipe failed");
    }

    posix_spawn_file_actions_t actions;
    if (posix_spawn_file_actions_init(&actions) != 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return FinishNotRun(report, QualResult::NOT_RUN_RESOURCE_LIMIT, "isolated CUDA worker: spawn actions failed");
    }
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDOUT_FILENO);
    posix_spawn_file_actions_adddup2(&actions, pipefd[1], STDERR_FILENO);
    posix_spawn_file_actions_addclose(&actions, pipefd[0]);
    posix_spawn_file_actions_addclose(&actions, pipefd[1]);

    char gpu_arg[32];
    std::snprintf(gpu_arg, sizeof(gpu_arg), "--gpu=%d", gpu);
    char share_arg[] = "--allow-shared-gpu";
    char* argv[5];
    int argc_w = 0;
    argv[argc_w++] = const_cast<char*>(worker.c_str());
    argv[argc_w++] = gpu_arg;
    if (AllowSharedGpuFromEnv()) {
        argv[argc_w++] = share_arg;
    }
    argv[argc_w] = nullptr;

    pid_t pid = 0;
    const int rc_spawn = posix_spawn(&pid, worker.c_str(), &actions, nullptr, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    close(pipefd[1]);
    if (rc_spawn != 0) {
        close(pipefd[0]);
        return FinishNotRun(report, QualResult::NOT_RUN_RESOURCE_LIMIT, "isolated CUDA worker: posix_spawn failed");
    }

    std::string out;
    char buf[512];
    ssize_t nread = 0;
    while ((nread = read(pipefd[0], buf, sizeof(buf))) > 0) {
        out.append(buf, static_cast<size_t>(nread));
    }
    close(pipefd[0]);
    int status = 0;
    waitpid(pid, &status, 0);

    if (out.find("GPU-01 RUNTIME_OBSERVED") != std::string::npos) {
        report.result = QualResult::RUNTIME_OBSERVED;
        report.level = AdmissionLevel::RUNTIME_OBSERVED;
        report.detail = out;
        return QualResult::RUNTIME_OBSERVED;
    }
    return FinishNotRun(report, QualResult::NOT_RUN_RESOURCE_LIMIT,
                        "isolated CUDA worker did not report GPU-01 RUNTIME_OBSERVED: " + out);
}
#endif

#ifdef BTX_MODEL_CUDA_QUALIFY_COMPILE
// Dedicated in-process stub only. Default btxd / test_btx do not define this
// macro. Even when compiled, this does not cudaSetDevice: QualifyRuntime
// posix_spawns BTX_CUDA_QUAL_WORKER / PATH cuda_qual_worker instead.
QualResult RunIsolatedCudaQualKernel(int gpu_index, QualReport& report)
{
    (void)gpu_index;
    return FinishNotRun(report, QualResult::NOT_RUN_CUDA_ISOLATION,
                        "BTX_MODEL_CUDA_QUALIFY_COMPILE worker stub is in-process and still does not cudaSetDevice");
}
#endif

} // namespace

QualResult QualifyRuntime(const std::string& path, const QualRuntimeOpts& opts, QualReport& report)
{
    const QualResult static_q = QualifyFile(path, report);
    if (static_q != QualResult::STRUCTURE_VERIFIED && static_q != QualResult::PROFILE_VERIFIED) {
        return static_q;
    }

    if (!opts.runtime_check) {
        return FinishNotRun(report, QualResult::NOT_RUN_CUDA_ISOLATION,
                            "-modelruntimecheck=0 (default); CUDA runtime qualification not run; "
                            "isolated worker not invoked");
    }

    if (!opts.gpu_index.has_value()) {
        return FinishNotRun(report, QualResult::NOT_RUN_RESOURCE_LIMIT,
                            "operator must set -modelgpu to a non-validator device; "
                            "qualification does not inherit the validator/mining GPU");
    }

    const int gpu = *opts.gpu_index;
    if (gpu < 0) {
        return FinishNotRun(report, QualResult::NOT_RUN_RESOURCE_LIMIT,
                            "operator must set -modelgpu to a non-validator device");
    }

    if (!opts.allow_validator_gpu && IsValidatorOrMiningGpu(gpu)) {
        return FinishNotRun(report, QualResult::NOT_RUN_CUDA_ISOLATION,
                            "refusing validator/mining GPU (device 0 default, or BTX_VALIDATOR_GPU); "
                            "never cudaSetDevice on that index");
    }

#ifndef WIN32
    const std::string worker = FindCudaQualWorker();
    if (!worker.empty()) {
        return SpawnIsolatedCudaWorker(worker, gpu, report);
    }
#endif

#ifdef BTX_MODEL_CUDA_QUALIFY_COMPILE
    return RunIsolatedCudaQualKernel(gpu, report);
#else
    return FinishNotRun(report, QualResult::NOT_RUN_RESOURCE_LIMIT,
                        "CUDA qualification kernel is not compiled "
                        "(BTX_MODEL_CUDA_QUALIFY_COMPILE unset); libcuda not required");
#endif
}

} // namespace modelnet
