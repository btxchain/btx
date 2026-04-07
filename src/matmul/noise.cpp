// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/noise.h>
#include <matmul/solver_runtime.h>

#include <hash.h>
#include <span.h>
#include <uint256.h>

#include <array>
#include <algorithm>
#include <cassert>
#include <cstdint>
#include <cstdlib>
#include <thread>
#include <vector>

namespace matmul::noise {
namespace {

std::array<uint8_t, 32> ToCanonicalBytes(const uint256& value)
{
    std::array<uint8_t, 32> out;
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = value.data()[out.size() - 1 - i];
    }
    return out;
}

uint256 CanonicalBytesToUint256(const uint8_t* bytes)
{
    std::array<unsigned char, 32> internal;
    for (size_t i = 0; i < internal.size(); ++i) {
        internal[i] = bytes[internal.size() - 1 - i];
    }
    return uint256{Span<const unsigned char>{internal.data(), internal.size()}};
}

Matrix FromSeedRect(const uint256& seed, uint32_t rows, uint32_t cols)
{
    assert(static_cast<uint64_t>(rows) * cols <= std::numeric_limits<uint32_t>::max());
    Matrix out(rows, cols);
    const auto profile = ProbeNoiseGenerationProfile(rows, cols);
    const auto fill_rows = [&](uint32_t row_begin, uint32_t row_end) {
        for (uint32_t row = row_begin; row < row_end; ++row) {
            for (uint32_t col = 0; col < cols; ++col) {
                out.at(row, col) = field::from_oracle(seed, row * cols + col);
            }
        }
    };

    if (profile.worker_count <= 1 || rows <= 1) {
        fill_rows(0, rows);
        return out;
    }

    // Align chunk boundaries to cache lines to prevent false sharing between
    // workers writing to adjacent rows. Apple M-series uses 128-byte cache lines.
    constexpr uint32_t kCacheLineBytes = 128;
    const uint32_t bytes_per_row = cols * sizeof(field::Element);
    const uint32_t rows_per_cache_line = (bytes_per_row > 0)
        ? std::max<uint32_t>(1, kCacheLineBytes / bytes_per_row)
        : 1;
    const uint32_t raw_chunk = (rows + profile.worker_count - 1) / profile.worker_count;
    const uint32_t chunk = (rows_per_cache_line > 1)
        ? ((raw_chunk + rows_per_cache_line - 1) / rows_per_cache_line) * rows_per_cache_line
        : raw_chunk;
    std::vector<std::thread> workers;
    workers.reserve(profile.worker_count);
    for (uint32_t worker = 0; worker < profile.worker_count; ++worker) {
        const uint32_t begin = worker * chunk;
        const uint32_t end = std::min<uint32_t>(begin + chunk, rows);
        if (begin >= end) {
            break;
        }
        workers.emplace_back(fill_rows, begin, end);
    }
    for (auto& worker : workers) {
        worker.join();
    }
    return out;
}

} // namespace

uint256 DeriveNoiseSeed(std::string_view domain_tag, const uint256& sigma)
{
    assert(domain_tag.size() == 18);

    const auto sigma_bytes = ToCanonicalBytes(sigma);

    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const uint8_t*>(domain_tag.data()), domain_tag.size());
    hasher.Write(sigma_bytes.data(), sigma_bytes.size());

    uint8_t digest[CSHA256::OUTPUT_SIZE];
    hasher.Finalize(digest);

    return CanonicalBytesToUint256(digest);
}

NoiseGenerationProfile ProbeNoiseGenerationProfile(uint32_t rows, uint32_t cols)
{
    const char* env_parallel = std::getenv("BTX_MATMUL_NOISE_PARALLEL");
    const auto make_profile = [&](bool parallel_supported, uint32_t worker_count, const char* reason) {
        return NoiseGenerationProfile{
            .parallel_supported = parallel_supported,
            .worker_count = ClampSolveWorkerThreads(worker_count),
            .reason = reason,
        };
    };
#if defined(__APPLE__)
    const uint64_t footprint = static_cast<uint64_t>(rows) * cols;
    constexpr uint64_t kParallelMinFootprint = 32768;

    if (env_parallel != nullptr && env_parallel[0] == '0') {
        return make_profile(true, 1, "parallel_forced_off");
    }
    if (env_parallel != nullptr && env_parallel[0] != '\0') {
        const uint32_t hw_threads = std::max<uint32_t>(1, std::thread::hardware_concurrency());
        return make_profile(true, std::max<uint32_t>(1, std::min<uint32_t>(rows, hw_threads)), "parallel_forced_on");
    }
    const uint32_t hw_threads = std::max<uint32_t>(1, std::thread::hardware_concurrency());
    if (hw_threads <= 1) {
        return make_profile(true, 1, "single_thread_runtime");
    }
    if (rows < 64) {
        return make_profile(true, 1, "serial_small_dimension");
    }
    if (footprint < kParallelMinFootprint) {
        return make_profile(true, 1, "serial_small_footprint");
    }
    return make_profile(true, std::min<uint32_t>(rows, hw_threads), "parallel_rows");
#else
    (void)rows;
    (void)cols;
    (void)env_parallel;
    return make_profile(false, 1, "parallel_disabled_on_platform");
#endif
}

NoisePair Generate(const uint256& sigma, uint32_t n, uint32_t r)
{
    const uint256 tag_el = DeriveNoiseSeed(TAG_EL, sigma);
    const uint256 tag_er = DeriveNoiseSeed(TAG_ER, sigma);
    const uint256 tag_fl = DeriveNoiseSeed(TAG_FL, sigma);
    const uint256 tag_fr = DeriveNoiseSeed(TAG_FR, sigma);

    return {
        .E_L = FromSeedRect(tag_el, n, r),
        .E_R = FromSeedRect(tag_er, r, n),
        .F_L = FromSeedRect(tag_fl, n, r),
        .F_R = FromSeedRect(tag_fr, r, n),
    };
}

} // namespace matmul::noise
