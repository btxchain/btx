// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_alg_hash_typed.h>
#include <matmul/matmul_v4_rc_rowleaf_gpu.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace ah = matmul::v4::rc::alg_hash;
namespace aht = matmul::v4::rc::alg_hash_typed;
namespace gf = matmul::v4::rc::gkr_field;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_alg_hash_typed_tests, BasicTestingSetup)

namespace {

bool DigestEqual(const ah::Digest& left, const ah::Digest& right)
{
    return std::equal(
        left.begin(), left.end(), right.begin(),
        [](gf::Fp a, gf::Fp b) {
            return gf::Canonical(a) == gf::Canonical(b);
        });
}

void RequireDigestEqual(
    const ah::Digest& expected, const ah::Digest& actual,
    uint32_t row = 0)
{
    for (uint32_t lane = 0; lane < ah::kAlgHashDigestLen; ++lane) {
        BOOST_TEST(actual[lane] < gf::kP);
        BOOST_TEST(actual[lane] == expected[lane],
                   "row=" << row << " lane=" << lane);
    }
}

void SetProductionConstants()
{
    const auto& constants = ah::GetAlgHashConstants();
    BOOST_REQUIRE_EQUAL(
        BtxGpuRowLeafSetConstants(
            constants.rc_ext.front().data(),
            constants.rc_int.data(), constants.mu.data()),
        0);
}

uint64_t StructuredLane(
    uint32_t column, uint32_t limb, uint32_t row)
{
    static constexpr std::array<uint64_t, 8> edges{{
        0, 1, gf::kP - 1, gf::kP, gf::kP + 1,
        UINT64_C(0xFFFFFFFFFFFFFFFF),
        UINT64_C(0xFFFFFFFF00000000),
        UINT64_C(0x00000000FFFFFFFF),
    }};
    if (row < edges.size()) return edges[row];
    const uint64_t mixed =
        (uint64_t{column + 1} * UINT64_C(0x9E3779B97F4A7C15)) ^
        (uint64_t{limb + 3} * UINT64_C(0xD6E8FEB86659FD93)) ^
        (uint64_t{row + 5} * UINT64_C(0xA0761D6478BD642F));
    const uint64_t x = mixed & UINT64_C(0xFFFF);
    return ((column + limb + row) & 3u) == 0
        ? gf::kP + x
        : mixed;
}

std::vector<std::vector<gf::Fp3>> MakeColumns(
    uint32_t width, uint32_t rows)
{
    std::vector<std::vector<gf::Fp3>> columns(
        width, std::vector<gf::Fp3>(rows));
    for (uint32_t column = 0; column < width; ++column) {
        for (uint32_t row = 0; row < rows; ++row) {
            columns[column][row] = {
                StructuredLane(column, 0, row),
                StructuredLane(column, 1, row),
                StructuredLane(column, 2, row),
            };
        }
    }
    return columns;
}

std::vector<uint64_t> ToLaneMajor(
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    const uint32_t width = static_cast<uint32_t>(columns.size());
    const uint32_t rows =
        static_cast<uint32_t>(columns.front().size());
    std::vector<uint64_t> lanes(
        static_cast<size_t>(3) * width * rows);
    for (uint32_t column = 0; column < width; ++column) {
        for (uint32_t row = 0; row < rows; ++row) {
            lanes[(static_cast<size_t>(3) * column) * rows + row] =
                columns[column][row].c0;
            lanes[(static_cast<size_t>(3) * column + 1) * rows + row] =
                columns[column][row].c1;
            lanes[(static_cast<size_t>(3) * column + 2) * rows + row] =
                columns[column][row].c2;
        }
    }
    return lanes;
}

std::vector<ah::Digest> MonolithicTyped(
    const std::vector<std::vector<gf::Fp3>>& columns)
{
    const uint32_t rows =
        static_cast<uint32_t>(columns.front().size());
    std::vector<ah::Digest> output(rows);
    std::vector<gf::Fp3> values(columns.size());
    for (uint32_t row = 0; row < rows; ++row) {
        for (size_t column = 0; column < columns.size(); ++column) {
            values[column] = columns[column][row];
        }
        output[row] = aht::RowLeafV12(values, row);
    }
    return output;
}

std::vector<ah::Digest> StreamingTyped(
    const std::vector<std::vector<gf::Fp3>>& columns,
    bool blocked)
{
    aht::StreamingRowHasherV12 hasher(
        static_cast<uint32_t>(columns.front().size()));
    std::string why;
    if (blocked) {
        BOOST_REQUIRE_MESSAGE(
            hasher.AbsorbColumnBlock(columns, columns.size(), &why), why);
    } else {
        for (const auto& column : columns) {
            BOOST_REQUIRE_MESSAGE(hasher.AbsorbColumn(column, &why), why);
        }
    }
    std::vector<ah::Digest> output;
    BOOST_REQUIRE_MESSAGE(hasher.Finalize(output, &why), why);
    return output;
}

std::vector<ah::Digest> Accelerated(
    const std::vector<std::vector<gf::Fp3>>& columns,
    bool typed, const std::vector<uint32_t>& chunks)
{
    const uint32_t rows =
        static_cast<uint32_t>(columns.front().size());
    const uint32_t width = static_cast<uint32_t>(columns.size());
    const std::vector<uint64_t> lanes = ToLaneMajor(columns);

    void* context = nullptr;
    if (typed) {
        aht::CapacityIvV12 iv{};
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            aht::CapacityIvForRoleV12(
                aht::RoleV12::MerkleRowLeaf, iv, &why),
            why);
        BOOST_REQUIRE_EQUAL(
            BtxGpuRowLeafBeginTyped(rows, iv.data(), &context), 0);
    } else {
        BOOST_REQUIRE_EQUAL(BtxGpuRowLeafBegin(rows, &context), 0);
    }
    BOOST_REQUIRE(context != nullptr);

    const uint32_t total_lanes = 3 * width;
    uint32_t offset = 0;
    size_t chunk = 0;
    while (offset < total_lanes) {
        const uint32_t requested = chunks.empty()
            ? total_lanes
            : chunks[chunk++ % chunks.size()];
        const uint32_t count =
            std::min(requested, total_lanes - offset);
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
    BOOST_REQUIRE_EQUAL(
        BtxGpuRowLeafFinalize(
            context, total_lanes,
            reinterpret_cast<uint64_t*>(output.data())),
        0);
    return output;
}

void RequireDigestVectorsEqual(
    const std::vector<ah::Digest>& expected,
    const std::vector<ah::Digest>& actual)
{
    BOOST_REQUIRE_EQUAL(expected.size(), actual.size());
    for (uint32_t row = 0; row < expected.size(); ++row) {
        RequireDigestEqual(expected[row], actual[row], row);
    }
}

} // namespace

BOOST_AUTO_TEST_CASE(v12_role_capacity_inventory_is_canonical_and_unique)
{
    const auto& roles = aht::AllRolesV12();
    BOOST_REQUIRE_EQUAL(roles.size(), aht::kRoleCountV12);
    std::set<aht::CapacityIvV12> unique;
    for (aht::RoleV12 role : roles) {
        aht::CapacityIvV12 iv{};
        std::string why;
        BOOST_REQUIRE_MESSAGE(
            aht::CapacityIvForRoleV12(role, iv, &why), why);
        for (gf::Fp lane : iv) BOOST_TEST(lane < gf::kP);
        BOOST_TEST(iv[0] == aht::kCapacityMagicV1);
        BOOST_TEST(iv[1] == static_cast<uint32_t>(role));
        BOOST_TEST(iv[2] == aht::kProtocolVersionV12);
        BOOST_TEST(iv[3] == aht::kTypedHashVersionV1);
        unique.insert(iv);
    }
    BOOST_TEST(unique.size() == roles.size());

    aht::CapacityIvV12 invalid{};
    std::string why;
    BOOST_TEST(!aht::CapacityIvForRoleV12(
        static_cast<aht::RoleV12>(0), invalid, &why));
    BOOST_TEST(!why.empty());
}

BOOST_AUTO_TEST_CASE(v12_fixed_and_variable_roles_are_disjoint)
{
    const std::vector<gf::Fp> lanes{1, 2, 3, 4};
    ah::Digest digest{};
    std::string why;
    BOOST_TEST(!aht::SpongeHashFpV12(
        aht::RoleV12::MerkleFoldLeaf, lanes, digest, &why));
    BOOST_TEST(!why.empty());
    why.clear();
    BOOST_TEST(!aht::SpongeHashFpV12(
        aht::RoleV12::MerkleInternalNode, lanes, digest, &why));
    BOOST_TEST(!why.empty());

    const gf::Fp3 noncanonical{
        gf::kP + 7, gf::kP + 11, gf::kP + 13};
    const gf::Fp3 canonical{7, 11, 13};
    RequireDigestEqual(
        aht::FoldLeafV12(canonical, 19),
        aht::FoldLeafV12(noncanonical, 19));

    ah::Digest left{{gf::kP + 1, gf::kP + 2, 3, 4}};
    ah::Digest left_canonical{{1, 2, 3, 4}};
    ah::Digest right{{5, 6, gf::kP + 7, gf::kP + 8}};
    ah::Digest right_canonical{{5, 6, 7, 8}};
    RequireDigestEqual(
        aht::CompressV12(left_canonical, right_canonical),
        aht::CompressV12(left, right));
}

BOOST_AUTO_TEST_CASE(v11_identical_preimage_is_separated_in_v12)
{
    constexpr uint64_t domain = UINT64_C(0x4d525032434f4546);
    constexpr uint32_t ordinal = 37;
    const ah::Digest seed{{101, 103, 107, 109}};
    const std::vector<gf::Fp> transcript{
        gf::FromU64(static_cast<uint32_t>(domain)),
        gf::FromU64(static_cast<uint32_t>(domain >> 32)),
        seed[0], seed[1], seed[2], seed[3],
        gf::FromU64(ordinal),
    };
    const std::vector<gf::Fp3> row{{
        {transcript[0], transcript[1], transcript[2]},
        {transcript[3], transcript[4], transcript[5]},
    }};

    // This is an equality of permutation inputs, not a found hash collision.
    const ah::Digest legacy_fs = ah::SpongeHashFp(transcript);
    const ah::Digest legacy_row = ah::LeafHashRow(row, ordinal);
    BOOST_TEST(DigestEqual(legacy_fs, legacy_row));

    ah::Digest typed_fs{};
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        aht::SpongeHashFpV12(
            aht::RoleV12::TranscriptBatchCoefficient,
            transcript, typed_fs, &why),
        why);
    const ah::Digest typed_row = aht::RowLeafV12(row, ordinal);
    BOOST_TEST(!DigestEqual(typed_fs, typed_row));
    BOOST_TEST(!DigestEqual(legacy_row, typed_row));
}

BOOST_AUTO_TEST_CASE(v12_monolithic_streaming_and_accelerator_match)
{
    if (BtxGpuRowLeafAvailable() != 0) SetProductionConstants();

    // W=1..8 covers every 3W+index+pad residue modulo rate 8. Multiple
    // power-of-two row domains cover the provider's allocation boundary and
    // make row-index binding part of the CPU/Metal differential.
    for (uint32_t rows : {1u, 2u, 8u, 32u}) {
        for (uint32_t width = 1; width <= 8; ++width) {
            const auto columns = MakeColumns(width, rows);
            const auto monolithic = MonolithicTyped(columns);
            RequireDigestVectorsEqual(
                monolithic, StreamingTyped(columns, false));
            RequireDigestVectorsEqual(
                monolithic, StreamingTyped(columns, true));
            if (BtxGpuRowLeafAvailable() != 0) {
                RequireDigestVectorsEqual(
                    monolithic, Accelerated(columns, true, {}));
                RequireDigestVectorsEqual(
                    monolithic,
                    Accelerated(columns, true, {1, 2, 5, 3}));
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(v12_provider_rejects_noncanonical_capacity_iv)
{
    if (BtxGpuRowLeafAvailable() == 0) return;
    SetProductionConstants();
    aht::CapacityIvV12 iv{};
    BOOST_REQUIRE(aht::CapacityIvForRoleV12(
        aht::RoleV12::MerkleRowLeaf, iv));
    iv[0] = gf::kP;
    void* context = reinterpret_cast<void*>(uintptr_t{1});
    BOOST_TEST(BtxGpuRowLeafBeginTyped(8, iv.data(), &context) != 0);
    BOOST_TEST(context == nullptr);
}

BOOST_AUTO_TEST_CASE(v11_legacy_rowleaf_parity_is_unchanged)
{
    constexpr uint32_t width = 5;
    constexpr uint32_t rows = 32;
    const auto columns = MakeColumns(width, rows);

    ah::StreamingRowHasher streaming(rows);
    std::string why;
    for (const auto& column : columns) {
        BOOST_REQUIRE_MESSAGE(streaming.AbsorbColumn(column, &why), why);
    }
    std::vector<ah::Digest> streamed;
    BOOST_REQUIRE_MESSAGE(streaming.Finalize(streamed, &why), why);

    std::vector<ah::Digest> monolithic(rows);
    std::vector<gf::Fp3> row_values(width);
    for (uint32_t row = 0; row < rows; ++row) {
        for (uint32_t column = 0; column < width; ++column) {
            row_values[column] = columns[column][row];
        }
        monolithic[row] = ah::LeafHashRow(row_values, row);
    }
    RequireDigestVectorsEqual(monolithic, streamed);

    if (BtxGpuRowLeafAvailable() != 0) {
        SetProductionConstants();
        RequireDigestVectorsEqual(
            monolithic, Accelerated(columns, false, {1, 7, 3}));
    }
}

BOOST_AUTO_TEST_SUITE_END()
