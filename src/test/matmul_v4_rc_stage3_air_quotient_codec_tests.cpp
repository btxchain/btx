// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// Whole-proof AirQuotientProof codec — the piece that did not exist.
//
// SCOPE. These tests exercise the CODEC: round-trip fidelity, canonicality, the
// untrusted-parse allocation ceiling, and MEASURED byte counts. They say nothing
// about whether any encoded proof is sound, and they do not require the narrow
// AIR to run (kNarrowVcsProductionReady is false) — a codec is testable on
// well-formed structures regardless.

#include <matmul/matmul_v4_rc_stage3_air_quotient_codec.h>

#include <boost/test/unit_test.hpp>
#include <test/util/setup_common.h>

#include <cstdint>
#include <string>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_stage3_air_quotient_codec_tests,
                         BasicTestingSetup)

namespace {

rc::gkr_field::Fp3 Fp3Of(uint64_t a, uint64_t b, uint64_t c)
{
    rc::gkr_field::Fp3 v;
    v.c0 = a % rc::gkr_field::kP;
    v.c1 = b % rc::gkr_field::kP;
    v.c2 = c % rc::gkr_field::kP;
    return v;
}

rc::Fri3AlgDigest DigestOf(uint64_t seed)
{
    rc::Fri3AlgDigest d{};
    for (size_t i = 0; i < rc::alg_hash::kAlgHashDigestLen; ++i) {
        d[i] = (seed * 0x9E3779B97F4A7C15ULL + i * 1315423911ULL) %
               rc::gkr_field::kP;
    }
    return d;
}

//! Build the next_openings structure the ROW-WISE contract actually specifies:
//! per query exactly TWO paths — [0] a full (W+1)-value row opening, [1] a
//! trace-binding opening with EMPTY values. This is deliberately NOT the
//! "3 rows + 3 row-paths" shape assumed by verify_cost_model.h.
std::vector<std::vector<rc::air_quotient::AirAlgRowPath>> MakeRowWiseOpenings(
    uint32_t queries, uint32_t w, uint32_t depth)
{
    std::vector<std::vector<rc::air_quotient::AirAlgRowPath>> out(queries);
    for (uint32_t q = 0; q < queries; ++q) {
        rc::air_quotient::AirAlgRowPath next_row;
        next_row.index = q * 7 + 1;
        next_row.values.reserve(w + 1);
        for (uint32_t i = 0; i <= w; ++i) {
            next_row.values.push_back(Fp3Of(q + i, i * 3 + 1, q * 5 + 2));
        }
        next_row.siblings.reserve(depth);
        for (uint32_t d = 0; d < depth; ++d) next_row.siblings.push_back(DigestOf(q * 64 + d));

        rc::air_quotient::AirAlgRowPath trace_bind;
        trace_bind.index = q;
        // values intentionally EMPTY — the leaf is recomputed from the batch.
        trace_bind.siblings.reserve(depth);
        for (uint32_t d = 0; d < depth; ++d) {
            trace_bind.siblings.push_back(DigestOf(q * 64 + d + 1000));
        }

        out[q].push_back(std::move(next_row));
        out[q].push_back(std::move(trace_bind));
    }
    return out;
}

} // namespace

BOOST_AUTO_TEST_CASE(wrapper_bytes_match_the_row_wise_layout_exactly)
{
    // The part that previously had NO serializer and was only estimated. Its
    // size must be derivable from the layout, and the derivation must match the
    // encoder to the byte.
    constexpr uint32_t Q{8};
    constexpr uint32_t W{546};   // the narrow parent width the codec lane measured
    constexpr uint32_t D{24};
    const auto openings = MakeRowWiseOpenings(Q, W, D);

    const size_t measured = rc::MeasuredAirQuotientWrapperBytes(openings);

    // Hand-derived from the documented layout:
    //   header 4+2+1+1 + batch_len 4 + trace_commit 32 + n_queries 4
    //   per query: 4 (n_paths)
    //     path[0]: 4 index + 4 count + (W+1)*24 values + 4 count + D*32 sibs
    //     path[1]: 4 index + 4 count + 0            + 4 count + D*32 sibs
    const size_t per_query = 4 + (4 + 4 + (W + 1) * 24 + 4 + D * 32) +
                             (4 + 4 + 0 + 4 + D * 32);
    const size_t expected = 4 + 2 + 1 + 1 + 4 + 32 + 4 + Q * per_query;
    BOOST_CHECK_EQUAL(measured, expected);

    // MEASURED per-query wrapper cost of THIS encoder at W=546, D=24.
    BOOST_TEST_MESSAGE("row-wise wrapper: per_query=" << per_query
                       << " B, total(Q=" << Q << ")=" << measured << " B");
    BOOST_CHECK_EQUAL(per_query, 14692U);

    // The codec lane's model of the same shape was 14,684 B/query:
    //     4 + [8 + (W+1)*24 + D*32] + [8 + 0 + D*32]
    // i.e. 8 bytes of per-path overhead. This encoder emits 12 (index +
    // n_values + n_siblings), because BOTH lengths are written explicitly
    // rather than inferred from W and the tree depth — an untrusted parser must
    // not have to derive a length from context it is also being asked to trust.
    // The cost is exactly 4 B per path, 8 B per query.
    const size_t lane_model_per_query = 4 + (8 + (W + 1) * 24 + D * 32) +
                                        (8 + 0 + D * 32);
    BOOST_CHECK_EQUAL(lane_model_per_query, 14684U);
    BOOST_CHECK_EQUAL(per_query - lane_model_per_query, 8U);
}

BOOST_AUTO_TEST_CASE(wrapper_size_scales_linearly_in_w_not_in_the_cost_model_shape)
{
    // The cost model charges 3 rows + 3 row-paths per query. The real layout is
    // 1 full row + 2 sibling sets. Pin the difference so a future change to
    // either side is visible rather than silently double-counted.
    constexpr uint32_t Q{4};
    constexpr uint32_t D{24};
    const size_t at_546 =
        rc::MeasuredAirQuotientWrapperBytes(MakeRowWiseOpenings(Q, 546, D));
    const size_t at_1092 =
        rc::MeasuredAirQuotientWrapperBytes(MakeRowWiseOpenings(Q, 1092, D));

    // Doubling W adds exactly Q*(W+1)*24 more value bytes and nothing else.
    BOOST_CHECK_EQUAL(at_1092 - at_546, static_cast<size_t>(Q) * 546 * 24);

    // The cost model's row_bytes term for the same shape, for comparison:
    // (2*(W+1) + W) * 24 per query — i.e. ~3x the value bytes this layout
    // actually emits.
    const size_t cost_model_row_bytes_546 = (2 * (546 + 1) + 546) * 24;
    const size_t actual_row_bytes_546 = (546 + 1) * 24;
    BOOST_CHECK(cost_model_row_bytes_546 > 2 * actual_row_bytes_546);
    BOOST_TEST_MESSAGE("W=546 per-query value bytes: layout="
                       << actual_row_bytes_546
                       << " cost_model=" << cost_model_row_bytes_546);
}

BOOST_AUTO_TEST_CASE(hostile_lengths_allocate_nothing)
{
    std::string why;

    // Empty, magic-less, and truncated inputs.
    BOOST_CHECK(!rc::DeserializeAirQuotientProofAlg({}, &why).has_value());
    BOOST_CHECK(!rc::DeserializeAirQuotientProofAlg({0, 1, 2, 3}, &why).has_value());

    // A well-formed header whose query count claims ~4 billion entries. If the
    // ceiling were checked after reserving, this test would die instead of
    // failing. The count must be refused against BOTH the hard cap and the
    // bytes actually remaining.
    std::vector<unsigned char> hostile;
    const auto put32 = [&hostile](uint32_t v) {
        for (int i = 0; i < 4; ++i) hostile.push_back(static_cast<unsigned char>(v >> (8 * i)));
    };
    put32(rc::kAirQuotientCodecMagic);
    hostile.push_back(static_cast<unsigned char>(rc::kAirQuotientCodecVersion & 0xFF));
    hostile.push_back(static_cast<unsigned char>(rc::kAirQuotientCodecVersion >> 8));
    hostile.push_back(static_cast<unsigned char>(rc::AirQuotientCodecLane::SingleAlg));
    hostile.push_back(0);            // reserved
    put32(0);                        // batch_len = 0
    for (int i = 0; i < 32; ++i) hostile.push_back(0); // trace_commit
    put32(0xFFFFFFFFu);              // n_queries — absurd

    BOOST_CHECK(!rc::DeserializeAirQuotientProofAlg(hostile, &why).has_value());
    BOOST_CHECK(why.find("queries") != std::string::npos);

    // Just under the hard query cap but still unbacked by input bytes.
    hostile.resize(hostile.size() - 4);
    put32(rc::kAirQuotientCodecMaxQueries);
    BOOST_CHECK(!rc::DeserializeAirQuotientProofAlg(hostile, &why).has_value());

    // A single query whose value count is at the column cap, with no bytes
    // behind it: must be refused by the "exceeds input" check, not attempted.
    std::vector<unsigned char> hostile2(hostile.begin(), hostile.end() - 4);
    const auto put32b = [&hostile2](uint32_t v) {
        for (int i = 0; i < 4; ++i) hostile2.push_back(static_cast<unsigned char>(v >> (8 * i)));
    };
    put32b(1);          // n_queries = 1
    put32b(1);          // n_paths = 1
    put32b(0);          // index
    put32b(1u << 20);   // n_values = kRCFri3AlgBatchMaxColumns, unbacked
    BOOST_CHECK(!rc::DeserializeAirQuotientProofAlg(hostile2, &why).has_value());
    BOOST_CHECK(why.find("exceeds_input") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(reserved_byte_and_lane_tag_are_enforced)
{
    std::vector<unsigned char> buf;
    const auto put32 = [&buf](uint32_t v) {
        for (int i = 0; i < 4; ++i) buf.push_back(static_cast<unsigned char>(v >> (8 * i)));
    };
    put32(rc::kAirQuotientCodecMagic);
    buf.push_back(static_cast<unsigned char>(rc::kAirQuotientCodecVersion & 0xFF));
    buf.push_back(static_cast<unsigned char>(rc::kAirQuotientCodecVersion >> 8));
    buf.push_back(0);   // lane = SingleAlg
    buf.push_back(1);   // reserved NON-ZERO
    put32(0);
    for (int i = 0; i < 32; ++i) buf.push_back(0);
    put32(0);

    std::string why;
    BOOST_CHECK(!rc::DeserializeAirQuotientProofAlg(buf, &why).has_value());
    BOOST_CHECK(why.find("nonzero_reserved") != std::string::npos);

    // Unknown lane tag.
    buf[7] = 0;    // reserved back to zero
    buf[6] = 99;   // lane
    BOOST_CHECK(!rc::DeserializeAirQuotientProofAlg(buf, &why).has_value());
    BOOST_CHECK(why.find("unknown_lane") != std::string::npos);

    // A DUAL-tagged payload must never decode through the SINGLE reader.
    buf[6] = static_cast<unsigned char>(rc::AirQuotientCodecLane::DualAlg);
    BOOST_CHECK(!rc::DeserializeAirQuotientProofAlg(buf, &why).has_value());
}

BOOST_AUTO_TEST_CASE(wrapper_bytes_are_the_previously_estimated_remainder)
{
    // Document what this codec actually replaces. EstimateAlgAirProofBytes
    // (matmul_v4_rc_air_recurse.cpp) modelled `next_openings` + `trace_commit`
    // because no encoder existed; the measurement below is produced by the
    // encoder itself and is therefore not a model at all.
    //
    // At the narrow parent shape the codec lane measured (W=546, D=24, Q=136)
    // this is the exact wrapper contribution to the 13,227,936 B artifact.
    constexpr uint32_t Q{136};
    constexpr uint32_t W{546};
    constexpr uint32_t D{24};
    const size_t wrapper =
        rc::MeasuredAirQuotientWrapperBytes(MakeRowWiseOpenings(Q, W, D));
    BOOST_TEST_MESSAGE("MEASURED wrapper bytes at W=546 D=24 Q=136: " << wrapper);

    // 136 * 14692 + 48 envelope bytes.
    BOOST_CHECK_EQUAL(wrapper, static_cast<size_t>(Q) * 14692U + 48U);
    // Against the codec lane's 14,684 B/query model the whole-artifact delta is
    // 136 * 8 = 1,088 B — immaterial next to the 13,227,936 B artifact and the
    // 16,000,000 B wire (0.827x becomes 0.8271x), but stated rather than
    // rounded away.
    BOOST_CHECK_EQUAL(wrapper - (static_cast<size_t>(Q) * 14684U + 48U), 1088U);
    // Sanity: the wrapper alone is multiple MB, i.e. it is not a rounding term
    // in any "does it fit" argument.
    BOOST_CHECK(wrapper > 1000000U);
    BOOST_CHECK(wrapper < rc::kAirQuotientCodecMaxBytes);
}

BOOST_AUTO_TEST_SUITE_END()
