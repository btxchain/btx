// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Exact-build MatMul-v3 parent-rate half of the Epoch-A ASERT campaign.
//
// Usage:
//   matmul-v3-asert-calibration sigma TRIES SEED
//   matmul-v3-asert-calibration matmul TRIES SEED
//   matmul-v3-asert-calibration mixed TRIES SEED NBITS
//
// NBITS is an explicit, canonical, eight-hex-digit compact target.  Requiring
// it for mixed mode prevents a historical network snapshot from silently
// becoming a build-time constant.  Epoch-A derivation accepts mixed evidence
// only and checks the exact compact target chosen by the reviewed campaign.

#include <arith_uint256.h>
#include <bitcoin-build-info.h>
#include <chainparams.h>
#include <common/args.h>
#include <consensus/params.h>
#include <crypto/sha256.h>
#include <matmul/accelerated_solver.h>
#include <pow.h>
#include <primitives/block.h>
#include <uint256.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/translation.h>

const TranslateFn G_TRANSLATION_FUN{nullptr};

#include <array>
#include <charconv>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <limits>
#include <optional>
#include <string>
#include <string_view>

namespace {

constexpr std::string_view TOOL{"matmul-v3-asert-calibration"};
constexpr uint32_t SCHEMA_VERSION{3};

const char* EmbeddedRevision()
{
#ifdef BUILD_GIT_FULL_COMMIT
    return BUILD_GIT_FULL_COMMIT;
#else
    return "";
#endif
}

const char* EmbeddedFingerprint()
{
#ifdef BUILD_GIT_SOURCE_TREE_FINGERPRINT
    return BUILD_GIT_SOURCE_TREE_FINGERPRINT;
#else
    return "";
#endif
}

bool EmbeddedDirty()
{
#ifdef BUILD_GIT_DIRTY
    return BUILD_GIT_DIRTY != 0;
#else
    return true;
#endif
}

bool IsLowerHex(std::string_view value, size_t size)
{
    if (value.size() != size) return false;
    for (const char c : value) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

bool ParseUint64(std::string_view text, uint64_t& out, bool require_positive)
{
    if (text.empty() || text.front() == '+' || text.front() == '-') return false;
    uint64_t parsed{0};
    const auto [end, error]{std::from_chars(text.data(), text.data() + text.size(), parsed, 10)};
    if (error != std::errc{} || end != text.data() + text.size()) return false;
    if (require_positive && parsed == 0) return false;
    out = parsed;
    return true;
}

bool ParseCompact(std::string_view text, uint32_t& compact, arith_uint256& target)
{
    if (text.size() != 8) return false;
    uint32_t parsed{0};
    const auto [end, error]{std::from_chars(text.data(), text.data() + text.size(), parsed, 16)};
    if (error != std::errc{} || end != text.data() + text.size()) return false;
    bool negative{false};
    bool overflow{false};
    target.SetCompact(parsed, &negative, &overflow);
    if (negative || overflow || target == 0 || target.GetCompact() != parsed) return false;
    compact = parsed;
    return true;
}

std::optional<std::string> ExecutableSha256(const char* path)
{
    if (path == nullptr || path[0] == '\0') return std::nullopt;
    std::ifstream stream{path, std::ios::binary};
    if (!stream) return std::nullopt;

    CSHA256 hasher;
    std::array<unsigned char, 1 << 16> buffer{};
    while (stream) {
        stream.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        const std::streamsize count{stream.gcount()};
        if (count > 0) hasher.Write(buffer.data(), static_cast<size_t>(count));
    }
    if (!stream.eof()) return std::nullopt;

    std::array<unsigned char, CSHA256::OUTPUT_SIZE> digest{};
    hasher.Finalize(digest.data());
    return HexStr(digest);
}

std::string JsonEscape(std::string_view input)
{
    std::string out;
    out.reserve(input.size());
    constexpr char HEX[] = "0123456789abcdef";
    for (const unsigned char c : input) {
        switch (c) {
        case '\"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                out += "\\u00";
                out += HEX[c >> 4];
                out += HEX[c & 0x0f];
            } else {
                out.push_back(static_cast<char>(c));
            }
        }
    }
    return out;
}

int Usage(const char* argv0, std::string_view error = {})
{
    if (!error.empty()) std::fprintf(stderr, "error: %s\n", std::string{error}.c_str());
    std::fprintf(stderr,
                 "usage: %s sigma TRIES SEED\n"
                 "       %s matmul TRIES SEED\n"
                 "       %s mixed TRIES SEED NBITS\n",
                 argv0, argv0, argv0);
    return 2;
}

} // namespace

int main(int argc, char** argv)
{
    if (argc < 2) return Usage(argv[0], "a calibration mode is required");
    const std::string mode{argv[1]};
    if (mode != "sigma" && mode != "matmul" && mode != "mixed") {
        return Usage(argv[0], "mode must be exactly sigma, matmul, or mixed");
    }
    const int expected_argc{mode == "mixed" ? 5 : 4};
    if (argc != expected_argc) {
        return Usage(argv[0], mode == "mixed"
            ? "mixed mode requires TRIES, SEED, and an explicit compact NBITS"
            : "sigma/matmul mode requires exactly TRIES and SEED");
    }

    uint64_t tries{0};
    uint64_t seed_off{0};
    if (!ParseUint64(argv[2], tries, /*require_positive=*/true)) {
        return Usage(argv[0], "TRIES must be a positive canonical uint64 decimal");
    }
    if (!ParseUint64(argv[3], seed_off, /*require_positive=*/false)) {
        return Usage(argv[0], "SEED must be a canonical uint64 decimal");
    }
    if (!IsLowerHex(EmbeddedRevision(), 40) || !IsLowerHex(EmbeddedFingerprint(), 64) ||
        EmbeddedDirty()) {
        std::fprintf(stderr,
                     "error: calibration requires an exact clean 40-character revision "
                     "and 64-character implementation fingerprint\n");
        return 1;
    }
    const auto binary_sha256{ExecutableSha256(argv[0])};
    if (!binary_sha256 || !IsLowerHex(*binary_sha256, 64)) {
        std::fprintf(stderr,
                     "error: cannot hash the running calibration executable; invoke it "
                     "through an explicit readable path\n");
        return 1;
    }

    ArgsManager args;
    auto chainparams = CreateChainParams(args, ChainType::MAIN);
    auto consensus = chainparams->GetConsensus();

    consensus.fMatMulPOW = true;
    consensus.fSkipMatMulValidation = false;
    consensus.nMatMulDimension = 512;
    consensus.nMatMulMinDimension = 64;
    consensus.nMatMulTranscriptBlockSize = 16;
    consensus.nMatMulNoiseRank = 8;
    consensus.nMatMulNonceSeedHeight = 0;
    consensus.nMatMulParentMtpSeedHeight = 0;
    consensus.nMatMulProductDigestHeight = 0;
    consensus.nMatMulV4Height = std::numeric_limits<int32_t>::max();
    consensus.nMatMulBMX4CHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulDRLTHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulRCCoupledHeight = std::numeric_limits<int32_t>::max();

    uint32_t eps{18};
    uint32_t compact{0};
    arith_uint256 target;
    if (mode == "matmul") {
        eps = 255;
        target = arith_uint256{1};
        compact = target.GetCompact();
    } else if (mode == "mixed") {
        if (!ParseCompact(argv[4], compact, target)) {
            return Usage(argv[0], "NBITS must be a canonical, positive eight-digit compact hex target");
        }
    } else {
        target = arith_uint256{1};
        compact = target.GetCompact();
    }
    consensus.nMatMulPreHashEpsilonBits = eps;
    consensus.nMatMulPreHashEpsilonBitsUpgrade = eps;
    consensus.nMatMulPreHashEpsilonBitsUpgradeHeight = 0;

    const auto backend_selection{matmul::accelerated::ResolveMiningBackendFromEnvironment()};
    const auto backend_requirement{matmul::accelerated::ResolveBackendRequirementFromEnvironment()};
    const bool strict_backend{
        backend_selection.requested_known &&
        backend_selection.requested == backend_selection.active &&
        (backend_selection.active == matmul::backend::Kind::CUDA ||
         backend_selection.active == matmul::backend::Kind::METAL) &&
        backend_requirement.valid && backend_requirement.enabled &&
        matmul::accelerated::IsBackendRequirementSatisfied(
            backend_requirement, backend_selection)};
    if (!strict_backend) {
        std::fprintf(stderr,
                     "error: calibration requires an explicitly requested and required "
                     "CUDA or Metal backend with no selection fallback\n");
        return 1;
    }

    CBlockHeader header{};
    header.nVersion = 4;
    header.hashPrevBlock = uint256{"00000000000000000000000000000000000000000000000000000000000000a1"};
    header.hashMerkleRoot = uint256{"00000000000000000000000000000000000000000000000000000000000000a2"};
    header.nTime = 1780000000U;
    header.nBits = compact;
    header.nNonce64 = seed_off;
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulDimension);
    header.matmul_digest.SetNull();

    constexpr int32_t HEIGHT{200000};
    constexpr int64_t PARENT_MTP{1779999910};
    uint64_t max_tries{tries};

    matmul::accelerated::ResetMatMulBackendRuntimeStats();
    ResetMatMulSolveRuntimeStats();
    const auto t0{std::chrono::steady_clock::now()};
    const bool solved = SolveMatMul(header, consensus, max_tries, HEIGHT,
                                    /*abort_flag=*/nullptr,
                                    /*freivalds_payload_out=*/nullptr,
                                    /*share_target_override=*/nullptr,
                                    std::optional<int64_t>{PARENT_MTP});
    const auto t1{std::chrono::steady_clock::now()};
    const double wall_s{std::chrono::duration<double>(t1 - t0).count()};
    const uint64_t done{tries - max_tries};
    const auto backend_stats{matmul::accelerated::ProbeMatMulBackendRuntimeStats()};
    const auto solve_stats{ProbeMatMulSolveRuntimeStats()};

    const bool provider_is_cuda{backend_selection.active == matmul::backend::Kind::CUDA};
    const uint64_t provider_requests{provider_is_cuda
        ? backend_stats.requested_cuda : backend_stats.requested_metal};
    const uint64_t provider_successes{provider_is_cuda
        ? backend_stats.cuda_successes : backend_stats.metal_successes};
    const uint64_t cpu_fallbacks{backend_stats.metal_fallbacks_to_cpu +
                                 backend_stats.cuda_fallbacks_to_cpu};
    const bool needs_digests{mode != "sigma"};
    const bool complete{
        !solved && max_tries == 0 && done == tries && wall_s > 0.0 &&
        solve_stats.attempts == 1 && solve_stats.solved_attempts == 0 &&
        solve_stats.failed_attempts == 1 &&
        backend_stats.requested_cpu == 0 && backend_stats.requested_unknown == 0 &&
        backend_stats.metal_fallbacks_to_cpu == 0 &&
        backend_stats.cuda_fallbacks_to_cpu == 0 &&
        backend_stats.metal_digest_mismatches == 0 &&
        backend_stats.gpu_input_generation_failures == 0 &&
        backend_stats.last_metal_fallback_error.empty() &&
        backend_stats.last_cuda_fallback_error.empty() &&
        backend_stats.last_gpu_input_error.empty() &&
        provider_requests == backend_stats.digest_requests &&
        provider_successes == backend_stats.digest_requests &&
        (provider_is_cuda ? backend_stats.requested_metal == 0
                          : backend_stats.requested_cuda == 0) &&
        (!needs_digests || backend_stats.digest_requests > 0)};
    if (!complete) {
        std::fprintf(stderr,
                     "error: calibration sample was incomplete, solved early, or used a "
                     "CPU/backend fallback; no evidence JSON emitted\n");
        return 1;
    }

    const std::string requested{matmul::backend::ToString(backend_selection.requested)};
    const std::string active{matmul::backend::ToString(backend_selection.active)};
    const std::string reason{JsonEscape(backend_selection.reason)};
    std::printf(
        "MEASURE_JSON:{\"tool\":\"%s\",\"schema_version\":%u,"
        "\"source_revision\":\"%s\",\"source_tree_fingerprint\":\"%s\","
        "\"embedded_source_revision\":\"%s\",\"embedded_source_dirty\":false,"
        "\"binary_sha256\":\"%s\",\"mode\":\"%s\",\"eps\":%u,"
        "\"nBits\":\"%08x\",\"matmul_dimension\":%u,"
        "\"transcript_block_size\":%u,\"noise_rank\":%u,\"seed\":%llu,"
        "\"height\":%d,\"parent_mtp\":%lld,\"tries\":%llu,"
        "\"attempts_done\":%llu,\"wall_s\":%.9f,\"attempts_per_s\":%.9f,"
        "\"solved\":false,\"solve_runtime_attempts\":%llu,"
        "\"solve_runtime_solved_attempts\":%llu,"
        "\"solve_runtime_failed_attempts\":%llu,"
        "\"requested_backend\":\"%s\",\"active_backend\":\"%s\","
        "\"backend_selection_reason\":\"%s\","
        "\"required_backend_enabled\":true,\"required_backend_satisfied\":true,"
        "\"digest_requests\":%llu,\"requested_cpu\":%llu,"
        "\"requested_unknown\":%llu,\"requested_metal\":%llu,"
        "\"requested_cuda\":%llu,\"metal_successes\":%llu,"
        "\"cuda_successes\":%llu,\"metal_digest_mismatches\":%llu,"
        "\"metal_fallbacks_to_cpu\":%llu,\"cuda_fallbacks_to_cpu\":%llu,"
        "\"cpu_fallbacks\":%llu,\"gpu_input_generation_attempts\":%llu,"
        "\"gpu_input_generation_successes\":%llu,"
        "\"gpu_input_generation_failures\":%llu,"
        "\"last_metal_fallback_error\":\"\","
        "\"last_cuda_fallback_error\":\"\",\"last_gpu_input_error\":\"\"}\n",
        std::string{TOOL}.c_str(), SCHEMA_VERSION, EmbeddedRevision(),
        EmbeddedFingerprint(), EmbeddedRevision(), binary_sha256->c_str(), mode.c_str(),
        eps, compact, consensus.nMatMulDimension, consensus.nMatMulTranscriptBlockSize,
        consensus.nMatMulNoiseRank, static_cast<unsigned long long>(seed_off), HEIGHT,
        static_cast<long long>(PARENT_MTP), static_cast<unsigned long long>(tries),
        static_cast<unsigned long long>(done), wall_s,
        static_cast<double>(done) / wall_s,
        static_cast<unsigned long long>(solve_stats.attempts),
        static_cast<unsigned long long>(solve_stats.solved_attempts),
        static_cast<unsigned long long>(solve_stats.failed_attempts),
        requested.c_str(), active.c_str(), reason.c_str(),
        static_cast<unsigned long long>(backend_stats.digest_requests),
        static_cast<unsigned long long>(backend_stats.requested_cpu),
        static_cast<unsigned long long>(backend_stats.requested_unknown),
        static_cast<unsigned long long>(backend_stats.requested_metal),
        static_cast<unsigned long long>(backend_stats.requested_cuda),
        static_cast<unsigned long long>(backend_stats.metal_successes),
        static_cast<unsigned long long>(backend_stats.cuda_successes),
        static_cast<unsigned long long>(backend_stats.metal_digest_mismatches),
        static_cast<unsigned long long>(backend_stats.metal_fallbacks_to_cpu),
        static_cast<unsigned long long>(backend_stats.cuda_fallbacks_to_cpu),
        static_cast<unsigned long long>(cpu_fallbacks),
        static_cast<unsigned long long>(backend_stats.gpu_input_generation_attempts),
        static_cast<unsigned long long>(backend_stats.gpu_input_generation_successes),
        static_cast<unsigned long long>(backend_stats.gpu_input_generation_failures));
    return 0;
}
