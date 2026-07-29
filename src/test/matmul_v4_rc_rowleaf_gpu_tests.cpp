// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <matmul/matmul_v4_rc_alg_hash.h>
#include <matmul/matmul_v4_rc_gkr_field.h>
#include <matmul/matmul_v4_rc_rowleaf_gpu.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <thread>
#include <vector>

namespace ah = matmul::v4::rc::alg_hash;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_rowleaf_gpu_tests, BasicTestingSetup)

namespace {

void SetProductionConstants()
{
    const auto& constants = ah::GetAlgHashConstants();
    BOOST_REQUIRE_EQUAL(
        BtxGpuRowLeafSetConstants(constants.rc_ext.front().data(),
                                  constants.rc_int.data(),
                                  constants.mu.data()),
        0);
}

uint64_t StructuredLane(uint32_t column, uint32_t limb, uint32_t row)
{
    static constexpr std::array<uint64_t, 8> edges{
        0, 1, gf::kP - 1, gf::kP, gf::kP + 1,
        UINT64_C(0xFFFFFFFFFFFFFFFF), UINT64_C(0xFFFFFFFF00000000),
        UINT64_C(0x00000000FFFFFFFF)};
    if (row < edges.size()) return edges[row];
    const uint64_t mixed =
        (uint64_t{column + 1} * UINT64_C(0x9E3779B97F4A7C15)) ^
        (uint64_t{limb + 7} * UINT64_C(0xD6E8FEB86659FD93)) ^
        (uint64_t{row} * UINT64_C(0xA0761D6478BD642F));
    // Include a noncanonical x+p representative whenever it fits in u64.
    const uint64_t x = mixed & UINT64_C(0xFFFFFFFF);
    return ((column + limb + row) & 3u) == 0 ? gf::kP + x : mixed;
}

std::vector<uint64_t> MakeLaneMajor(uint32_t width, uint32_t rows)
{
    std::vector<uint64_t> lanes(static_cast<size_t>(3) * width * rows);
    for (uint32_t column = 0; column < width; ++column) {
        for (uint32_t limb = 0; limb < 3; ++limb) {
            uint64_t* destination =
                lanes.data() + static_cast<size_t>(3 * column + limb) * rows;
            for (uint32_t row = 0; row < rows; ++row) {
                destination[row] = StructuredLane(column, limb, row);
            }
        }
    }
    return lanes;
}

std::vector<ah::Digest> CpuDigests(const std::vector<uint64_t>& lanes,
                                   uint32_t width, uint32_t rows)
{
    std::vector<ah::Digest> output(rows);
    std::vector<gf::Fp3> row_values(width);
    for (uint32_t row = 0; row < rows; ++row) {
        for (uint32_t column = 0; column < width; ++column) {
            row_values[column] = gf::Fp3{
                lanes[static_cast<size_t>(3 * column) * rows + row],
                lanes[static_cast<size_t>(3 * column + 1) * rows + row],
                lanes[static_cast<size_t>(3 * column + 2) * rows + row]};
        }
        output[row] = ah::LeafHashRow(row_values, row);
    }
    return output;
}

std::vector<ah::Digest> AcceleratedDigests(
    const std::vector<uint64_t>& lanes, uint32_t width, uint32_t rows,
    const std::vector<uint32_t>& chunks)
{
    void* context = nullptr;
    BOOST_REQUIRE_EQUAL(BtxGpuRowLeafBegin(rows, &context), 0);
    BOOST_REQUIRE(context != nullptr);
    const uint32_t total_lanes = 3 * width;
    uint32_t offset = 0;
    size_t chunk_index = 0;
    while (offset < total_lanes) {
        const uint32_t requested =
            chunks.empty() ? total_lanes : chunks[chunk_index++ % chunks.size()];
        const uint32_t count = std::min(requested, total_lanes - offset);
        BOOST_REQUIRE(count != 0);
        BOOST_REQUIRE_EQUAL(
            BtxGpuRowLeafAbsorb(
                context,
                lanes.data() + static_cast<size_t>(offset) * rows,
                count, offset),
            0);
        offset += count;
    }
    std::vector<ah::Digest> output(rows);
    static_assert(sizeof(ah::Digest) == 4 * sizeof(uint64_t));
    BOOST_REQUIRE_EQUAL(
        BtxGpuRowLeafFinalize(
            context, total_lanes,
            reinterpret_cast<uint64_t*>(output.data())),
        0);
    return output;
}

void RequireCanonicalAndEqual(const std::vector<ah::Digest>& expected,
                              const std::vector<ah::Digest>& actual)
{
    BOOST_REQUIRE_EQUAL(actual.size(), expected.size());
    for (size_t row = 0; row < expected.size(); ++row) {
        for (size_t limb = 0; limb < expected[row].size(); ++limb) {
            BOOST_TEST(actual[row][limb] < gf::kP);
            BOOST_TEST(actual[row][limb] == expected[row][limb],
                       "row=" << row << " limb=" << limb);
        }
    }
}

} // namespace

#if defined(__APPLE__) && defined(BTX_ENABLE_METAL)
BOOST_AUTO_TEST_CASE(metal_constants_are_immutable_and_concurrent_idempotent)
{
    if (BtxGpuRowLeafAvailable() == 0) return;
    const auto& constants = ah::GetAlgHashConstants();
    std::array<int, 8> results{};
    std::vector<std::thread> uploaders;
    uploaders.reserve(results.size());
    for (size_t i = 0; i < results.size(); ++i) {
        uploaders.emplace_back([&, i] {
            results[i] = BtxGpuRowLeafSetConstants(
                constants.rc_ext.front().data(),
                constants.rc_int.data(), constants.mu.data());
        });
    }
    for (std::thread& uploader : uploaders) uploader.join();
    for (int result : results) BOOST_TEST(result == 0);

    auto wrong_ext = constants.rc_ext;
    wrong_ext[0][0] ^= 1;
    BOOST_TEST(BtxGpuRowLeafSetConstants(
                   wrong_ext.front().data(), constants.rc_int.data(),
                   constants.mu.data()) != 0);
    // The rejected replacement must leave the initialized provider usable.
    SetProductionConstants();
}
#endif

BOOST_AUTO_TEST_CASE(streaming_poseidon2_accelerator_matches_cpu_edges)
{
    if (BtxGpuRowLeafAvailable() == 0) {
        BOOST_TEST_MESSAGE("No row-leaf accelerator; parity test skipped");
        return;
    }
    SetProductionConstants();

    // W=1..8 covers every total-length/padding residue reached by Fp3 rows.
    for (uint32_t width = 1; width <= 8; ++width) {
        constexpr uint32_t rows = 32;
        const std::vector<uint64_t> lanes = MakeLaneMajor(width, rows);
        const std::vector<ah::Digest> cpu = CpuDigests(lanes, width, rows);
        RequireCanonicalAndEqual(
            cpu, AcceleratedDigests(lanes, width, rows, {}));
        RequireCanonicalAndEqual(
            cpu, AcceleratedDigests(lanes, width, rows, {1, 2, 5, 3}));
    }
}

BOOST_AUTO_TEST_CASE(streaming_poseidon2_accelerator_rejects_bad_order)
{
    if (BtxGpuRowLeafAvailable() == 0) return;
    SetProductionConstants();
    constexpr uint32_t rows = 4;
    const std::vector<uint64_t> lanes = MakeLaneMajor(2, rows);
    void* context = nullptr;
    BOOST_REQUIRE_EQUAL(BtxGpuRowLeafBegin(rows, &context), 0);
    BOOST_REQUIRE(context != nullptr);
    BOOST_TEST(BtxGpuRowLeafAbsorb(context, lanes.data(), 1, 1) != 0);
    BOOST_REQUIRE_EQUAL(BtxGpuRowLeafAbsorb(context, lanes.data(), 1, 0), 0);
    std::array<uint64_t, rows * 4> output{};
    BOOST_TEST(BtxGpuRowLeafFinalize(context, 6, output.data()) != 0);
}

BOOST_AUTO_TEST_CASE(streaming_poseidon2_accelerator_chunk_crossing)
{
    if (BtxGpuRowLeafAvailable() == 0) return;
    SetProductionConstants();
    constexpr uint32_t width = 1025; // crosses the provider's 3072-lane cap
    constexpr uint32_t rows = 32;
    const std::vector<uint64_t> lanes = MakeLaneMajor(width, rows);
    const std::vector<ah::Digest> cpu = CpuDigests(lanes, width, rows);
    RequireCanonicalAndEqual(
        cpu, AcceleratedDigests(lanes, width, rows, {3075}));
}

BOOST_AUTO_TEST_CASE(streaming_poseidon2_accelerator_microbenchmark)
{
    if (std::getenv("BTX_RUN_METAL_ROWLEAF_BENCH") == nullptr ||
        BtxGpuRowLeafAvailable() == 0) {
        return;
    }
    SetProductionConstants();
    constexpr uint32_t width = 640;
    constexpr uint32_t rows = 1 << 15;
    const std::vector<uint64_t> lanes = MakeLaneMajor(width, rows);

    const auto gpu_start = std::chrono::steady_clock::now();
    const std::vector<ah::Digest> gpu =
        AcceleratedDigests(lanes, width, rows, {15});
    const double gpu_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - gpu_start).count();
    if (std::getenv("BTX_METAL_ROWLEAF_BENCH_GPU_ONLY") != nullptr) {
        for (const auto& digest : gpu) {
            for (uint64_t limb : digest) BOOST_TEST(limb < gf::kP);
        }
        BOOST_TEST_MESSAGE("rowleaf W=" << width << " rows=" << rows
                           << " Metal=" << gpu_seconds << "s");
        return;
    }

    const auto cpu_start = std::chrono::steady_clock::now();
    const std::vector<ah::Digest> cpu = CpuDigests(lanes, width, rows);
    const double cpu_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - cpu_start).count();
    RequireCanonicalAndEqual(cpu, gpu);
    BOOST_TEST_MESSAGE("rowleaf W=" << width << " rows=" << rows
                       << " Metal=" << gpu_seconds << "s CPU="
                       << cpu_seconds << "s speedup="
                       << cpu_seconds / gpu_seconds << "x");
}

BOOST_AUTO_TEST_SUITE_END()
