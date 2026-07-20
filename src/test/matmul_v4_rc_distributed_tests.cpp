// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/sha256.h>
#include <matmul/matmul_v4_rc_distributed.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstring>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_distributed_tests, BasicTestingSetup)

namespace {

uint256 MakeSeed(uint8_t fill)
{
    uint256 s;
    for (int i = 0; i < 32; ++i) s.data()[i] = fill;
    return s;
}

rc::DistSynthShape ToyShape()
{
    // m=n=32 (ExtractMX), k=128, seg_len=32 → 4 consensus segments.
    return rc::DistSynthShape{32, 32, 128, 32};
}

uint256 DeriveTagged(const uint256& seed, const char* tag)
{
    std::vector<unsigned char> buf;
    const size_t tag_len = std::strlen(tag);
    buf.insert(buf.end(), reinterpret_cast<const unsigned char*>(tag),
               reinterpret_cast<const unsigned char*>(tag) + tag_len);
    buf.insert(buf.end(), seed.begin(), seed.end());
    uint8_t d1[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(buf.data(), buf.size()).Finalize(d1);
    uint8_t d2[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(d1, sizeof(d1)).Finalize(d2);
    uint256 out;
    std::memcpy(out.data(), d2, 32);
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(dist_segment_ids_independent_of_device_count)
{
    const auto shape = ToyShape();
    BOOST_CHECK_EQUAL(rc::DistNumSegs(shape.k, shape.seg_len), 4u);

    for (uint32_t sid = 0; sid < 4; ++sid) {
        const uint32_t k0 = sid * shape.seg_len;
        BOOST_CHECK_EQUAL(rc::ConsensusSegmentId(k0, shape.seg_len), sid);
        for (uint32_t N : {1u, 2u, 4u, 8u}) {
            BOOST_CHECK_EQUAL(rc::DeviceForSegment(sid, N), sid % N);
            BOOST_CHECK_EQUAL(rc::ConsensusSegmentId(k0, shape.seg_len), sid);
        }
    }
}

BOOST_AUTO_TEST_CASE(dist_n_devices_and_reduce_orders_bit_exact)
{
    const auto seed = MakeSeed(0x5a);
    const auto shape = ToyShape();
    const auto orders = {rc::DistReduceOrder::TreeLeftToRight,
                         rc::DistReduceOrder::TreeRightToLeft,
                         rc::DistReduceOrder::PairwiseButterfly};

    rc::DistEpisodeResult baseline;
    bool have_baseline = false;

    for (uint32_t N : {1u, 2u, 4u, 8u}) {
        for (auto order : orders) {
            if (order == rc::DistReduceOrder::PairwiseButterfly && (N & (N - 1)) != 0) {
                continue;
            }
            const auto r = rc::RunSyntheticDistributed(seed, shape, N, order);
            BOOST_CHECK_EQUAL(r.n_segs, 4u);
            BOOST_CHECK_EQUAL(r.n_devices, N);
            BOOST_CHECK(!r.digest.IsNull());
            BOOST_CHECK_EQUAL(r.pre_extract_sum.size(), 32u * 32u);
            BOOST_CHECK_EQUAL(r.extracted.size(), 32u * 32u);

            if (!have_baseline) {
                baseline = r;
                have_baseline = true;
            } else {
                BOOST_CHECK(r.pre_extract_sum == baseline.pre_extract_sum);
                BOOST_CHECK(r.extracted == baseline.extracted);
                BOOST_CHECK(r.digest == baseline.digest);
            }
        }
    }
    BOOST_REQUIRE(have_baseline);
}

BOOST_AUTO_TEST_CASE(dist_device_reduce_matches_segment_sum)
{
    const auto seed = MakeSeed(0x11);
    const auto shape = ToyShape();
    std::vector<int8_t> A, B;
    rc::ExpandSynthOperands(seed, shape, A, B);

    for (uint32_t N : {1u, 2u, 4u, 8u}) {
        auto parts = rc::SimulateDevices(A, B, shape, N);
        const auto seg_sum = rc::SumSegmentPartials(parts.segs);
        for (auto order : {rc::DistReduceOrder::TreeLeftToRight,
                           rc::DistReduceOrder::TreeRightToLeft,
                           rc::DistReduceOrder::PairwiseButterfly}) {
            if (order == rc::DistReduceOrder::PairwiseButterfly && (N & (N - 1)) != 0) {
                continue;
            }
            const auto reduced = rc::ReduceDevicePartials(parts.per_device, order);
            BOOST_CHECK(reduced == seg_sum);
        }
    }
}

BOOST_AUTO_TEST_CASE(dist_extract_once_only_on_combined_sum)
{
    const auto seed = MakeSeed(0x22);
    const auto shape = ToyShape();
    const auto r = rc::RunSyntheticDistributed(seed, shape, /*n_devices=*/4,
                                               rc::DistReduceOrder::PairwiseButterfly);

    std::vector<int8_t> A, B;
    rc::ExpandSynthOperands(seed, shape, A, B);
    auto parts = rc::SimulateDevices(A, B, shape, 4);
    BOOST_REQUIRE_EQUAL(parts.segs.size(), 4u);

    const uint256 seed_extract = DeriveTagged(seed, "BTX_RC_DIST_EXTRACT_V1");
    const auto from_total = rc::ExtractOnce(seed_extract, r.pre_extract_sum, shape.m, shape.n);
    BOOST_CHECK(from_total == r.extracted);

    const auto from_seg0 = rc::ExtractOnce(seed_extract, parts.segs[0], shape.m, shape.n);
    BOOST_CHECK(from_seg0 != r.extracted);
}

BOOST_AUTO_TEST_SUITE_END()
