// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_stage3_safe_v12.h>
#include <matmul/matmul_v4_rc_stage3_safe_v12_fs_air.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace matmul::v4::rc::safe_v12 {
namespace {

namespace fsair = stage3_safe_v12_fs_air;
namespace qsampler = stage3_safe_v12_query_sampler;

IoPatternV12 ExamplePattern()
{
    IoPatternBuilderV12 builder;
    IoPatternV12 pattern;
    BOOST_REQUIRE(builder.Absorb(5));
    BOOST_REQUIRE(builder.Absorb(3));
    BOOST_REQUIRE(builder.Squeeze(3));
    BOOST_REQUIRE(builder.Squeeze(3));
    BOOST_REQUIRE(builder.Absorb(4));
    BOOST_REQUIRE(builder.Absorb(1));
    BOOST_REQUIRE(builder.Squeeze(3));
    BOOST_REQUIRE(builder.Absorb(4));
    BOOST_REQUIRE(builder.Squeeze(3));
    BOOST_REQUIRE(builder.Squeeze(4));
    BOOST_REQUIRE(builder.Build(pattern));
    return pattern;
}

IoPatternV12 AggregateExamplePattern()
{
    IoPatternBuilderV12 builder;
    IoPatternV12 pattern;
    BOOST_REQUIRE(builder.Absorb(8));
    BOOST_REQUIRE(builder.Squeeze(6));
    BOOST_REQUIRE(builder.Absorb(5));
    BOOST_REQUIRE(builder.Squeeze(3));
    BOOST_REQUIRE(builder.Absorb(4));
    BOOST_REQUIRE(builder.Squeeze(7));
    BOOST_REQUIRE(builder.Build(pattern));
    return pattern;
}

std::vector<gf::Fp> Sequence(uint32_t first, uint32_t count)
{
    std::vector<gf::Fp> out(count);
    for (uint32_t i = 0; i < count; ++i) {
        out[i] = gf::FromU64(first + i);
    }
    return out;
}

ah::Digest TestDigest(uint64_t first)
{
    return {
        gf::FromU64(first),
        gf::FromU64(first + 1),
        gf::FromU64(first + 2),
        gf::FromU64(first + 3),
    };
}

fsair::ShapeV12 TestFsAirShape()
{
    return {
        /*child_w=*/3,
        /*child_n_rows=*/8,
        /*child_quotient_len=*/16,
        /*n_coeffs=*/64,
        /*n_lde=*/1024,
        /*n_folds=*/6,
    };
}

fsair::TranscriptInputsV12 TestFsAirInputs()
{
    fsair::TranscriptInputsV12 out;
    out.parent_statement.parent_fs_seed = TestDigest(10);
    out.proof_witness.trace_commit = TestDigest(20);
    for (uint32_t lane = 0;
         lane < fsair::kFriLaneCountV12; ++lane) {
        auto& one = out.proof_witness.fri_lane[lane];
        const uint64_t base = 100 + 100 * lane;
        one.pow_grind_nonce =
            UINT64_C(0x1234567800000000) + lane;
        one.shape_commit = TestDigest(base + 10);
        one.row_root = TestDigest(base + 20);
        one.ood_evaluation_commit = TestDigest(base + 30);
        for (uint32_t fold = 0; fold <= 6; ++fold) {
            one.fold_roots.push_back(
                TestDigest(base + 40 + 10 * fold));
        }
    }
    return out;
}

std::vector<gf::Fp> Slice(
    const std::vector<gf::Fp>& values, size_t begin, size_t end)
{
    return {values.begin() + begin, values.begin() + end};
}

std::vector<uint8_t> Domain(const char* text)
{
    return {
        reinterpret_cast<const uint8_t*>(text),
        reinterpret_cast<const uint8_t*>(text) + std::strlen(text)};
}

void RequireEqual(
    const std::vector<gf::Fp>& expected,
    const std::vector<gf::Fp>& actual)
{
    BOOST_REQUIRE_EQUAL(expected.size(), actual.size());
    for (size_t i = 0; i < expected.size(); ++i) {
        BOOST_TEST(actual[i] == expected[i], "lane=" << i);
    }
}

void RequireStateEqual(
    const ah::State& expected, const ah::State& actual)
{
    for (uint32_t lane = 0; lane < ah::kAlgHashT; ++lane) {
        BOOST_TEST(actual[lane] == expected[lane],
                   "state_lane=" << lane);
    }
}

void WriteBE64(
    std::array<uint8_t, 32>& bytes, uint32_t lane, uint64_t value)
{
    for (uint32_t i = 0; i < 8; ++i) {
        bytes[8 * lane + 7 - i] =
            static_cast<uint8_t>(value >> (8 * i));
    }
}

} // namespace

BOOST_AUTO_TEST_SUITE(matmul_v4_rc_stage3_safe_v12_tests)

BOOST_AUTO_TEST_CASE(canonical_pattern_aggregates_call_chunking)
{
    const IoPatternV12 pattern = ExamplePattern();
    const std::vector<IoSegmentV12> expected{{
        {IoKindV12::Absorb, 8},
        {IoKindV12::Squeeze, 6},
        {IoKindV12::Absorb, 5},
        {IoKindV12::Squeeze, 3},
        {IoKindV12::Absorb, 4},
        {IoKindV12::Squeeze, 7},
    }};
    BOOST_REQUIRE(pattern.segments == expected);
    BOOST_REQUIRE_EQUAL(pattern.exact_calls.size(), 10U);

    std::vector<uint32_t> words;
    std::vector<uint8_t> bytes;
    BOOST_REQUIRE(CanonicalIoWordsV12(pattern, words));
    BOOST_REQUIRE(CanonicalIoBytesV12(pattern, bytes));
    const std::vector<uint32_t> expected_words{
        UINT32_C(0x80000008), 6,
        UINT32_C(0x80000005), 3,
        UINT32_C(0x80000004), 7,
    };
    BOOST_TEST(words == expected_words);
    BOOST_REQUIRE_EQUAL(bytes.size(), 4 * words.size());
    BOOST_TEST(bytes[0] == 0x80);
    BOOST_TEST(bytes[3] == 0x08);
    BOOST_TEST(bytes[4] == 0x00);
    BOOST_TEST(bytes[7] == 0x06);

    IoPatternBuilderV12 direct;
    IoPatternV12 direct_pattern;
    BOOST_REQUIRE(direct.Absorb(8));
    BOOST_REQUIRE(direct.Squeeze(6));
    BOOST_REQUIRE(direct.Absorb(5));
    BOOST_REQUIRE(direct.Squeeze(3));
    BOOST_REQUIRE(direct.Absorb(4));
    BOOST_REQUIRE(direct.Squeeze(7));
    BOOST_REQUIRE(direct.Build(direct_pattern));
    BOOST_CHECK(direct_pattern.segments == pattern.segments);
    BOOST_CHECK(direct_pattern.exact_calls != pattern.exact_calls);

    std::array<gf::Fp, 4> a{};
    std::array<gf::Fp, 4> b{};
    BOOST_REQUIRE(DeriveTagV12(pattern, Domain("BTX_TEST_SAFE"), a));
    BOOST_REQUIRE(DeriveTagV12(
        direct_pattern, Domain("BTX_TEST_SAFE"), b));
    BOOST_TEST(a == b);
}

BOOST_AUTO_TEST_CASE(full_capacity_tag_is_canonical_framed_and_counted)
{
    const IoPatternV12 pattern = ExamplePattern();
    std::array<gf::Fp, 4> tag{};
    TagHashStatsV12 stats;
    BOOST_REQUIRE(DeriveTagV12(
        pattern, Domain("BTX_TAG_DOMAIN"), tag, &stats));
    const std::array<gf::Fp, 4> expected_tag{{
        UINT64_C(0xe70d2257e7b7d56c),
        UINT64_C(0xff011da2cf2fbef5),
        UINT64_C(0xe47df3891d0ecb61),
        UINT64_C(0x330468ee7c625204),
    }};
    BOOST_CHECK(tag == expected_tag);
    for (const gf::Fp lane : tag) BOOST_TEST(lane < gf::kP);
    BOOST_TEST(stats.canonical_io_bytes == 24U);
    BOOST_TEST(stats.framed_base_bytes == 135U);
    BOOST_TEST(stats.candidate_preimage_bytes == 143U);
    BOOST_TEST(stats.candidate_preimage_bytes ==
               stats.framed_base_bytes + 8);
    BOOST_TEST(stats.first_sha256_blocks_per_attempt == 3U);
    BOOST_TEST(stats.logical_h_queries == 1U);
    BOOST_TEST(stats.vector_attempts == 1U);
    BOOST_TEST(stats.rejected_vectors == 0U);
    BOOST_TEST(
        stats.rejected_vectors + 1 == stats.vector_attempts);
    BOOST_TEST(stats.sha256d_calls == stats.vector_attempts);
    BOOST_TEST(stats.sha256_compression_blocks == 4U);
    BOOST_TEST(
        stats.sha256_compression_blocks ==
        stats.vector_attempts *
            (stats.first_sha256_blocks_per_attempt + 1));

    std::array<gf::Fp, 4> different_domain{};
    BOOST_REQUIRE(DeriveTagV12(
        pattern, Domain("BTX_TAG_DOMAIN_2"), different_domain));
    BOOST_CHECK(tag != different_domain);

    IoPatternBuilderV12 changed_builder;
    IoPatternV12 changed;
    BOOST_REQUIRE(changed_builder.Absorb(9));
    BOOST_REQUIRE(changed_builder.Squeeze(6));
    BOOST_REQUIRE(changed_builder.Build(changed));
    std::array<gf::Fp, 4> different_io{};
    BOOST_REQUIRE(DeriveTagV12(
        changed, Domain("BTX_TAG_DOMAIN"), different_io));
    BOOST_CHECK(tag != different_io);

    std::array<uint8_t, 32> candidate{};
    std::array<gf::Fp, 4> accepted{};
    for (uint32_t lane = 0; lane < 4; ++lane) {
        WriteBE64(candidate, lane, gf::kP - 1 - lane);
    }
    BOOST_REQUIRE(AcceptTagVectorCandidateV12(candidate, accepted));
    for (uint32_t lane = 0; lane < 4; ++lane) {
        BOOST_TEST(accepted[lane] == gf::kP - 1 - lane);
    }
    WriteBE64(candidate, 2, gf::kP);
    BOOST_CHECK(!AcceptTagVectorCandidateV12(candidate, accepted));
    BOOST_CHECK(std::all_of(
        accepted.begin(), accepted.end(),
        [](gf::Fp lane) { return lane == 0; }));
}

BOOST_AUTO_TEST_CASE(
    online_safe_alternating_transitions_match_algorithms_1_and_2)
{
    const IoPatternV12 pattern = AggregateExamplePattern();
    const std::vector<uint8_t> domain = Domain("BTX_SAFE_PREFIX");
    const std::vector<gf::Fp> message = Sequence(1, 17);
    SafeTranscriptV12 online;
    BOOST_REQUIRE(online.Start(pattern, domain));

    std::array<gf::Fp, kSafeCapacityV12> tag{};
    BOOST_REQUIRE(DeriveTagV12(pattern, domain, tag));
    ah::State manual{};
    std::copy(
        tag.begin(), tag.end(), manual.begin() + kSafeRateV12);

    std::vector<gf::Fp> out0;
    BOOST_REQUIRE(online.Absorb(Slice(message, 0, 8)));
    for (uint32_t lane = 0; lane < 8; ++lane) {
        manual[lane] = gf::Add(manual[lane], message[lane]);
    }
    RequireStateEqual(manual, online.Snapshot().state);
    BOOST_TEST(online.Snapshot().permutation_calls == 0U);
    BOOST_REQUIRE(online.Squeeze(6, out0));
    ah::Permute(manual); // ABSORB -> SQUEEZE always permutes.
    RequireEqual(
        std::vector<gf::Fp>(manual.begin(), manual.begin() + 6),
        out0);
    RequireStateEqual(manual, online.Snapshot().state);
    BOOST_TEST(online.Snapshot().permutation_calls == 1U);

    std::vector<gf::Fp> out1;
    BOOST_REQUIRE(online.Absorb(Slice(message, 8, 13)));
    for (uint32_t lane = 0; lane < 5; ++lane) {
        manual[lane] =
            gf::Add(manual[lane], message[8 + lane]);
    }
    RequireStateEqual(manual, online.Snapshot().state);
    BOOST_TEST(online.Snapshot().permutation_calls == 1U);
    BOOST_REQUIRE(online.Squeeze(3, out1));
    ah::Permute(manual);
    RequireEqual(
        std::vector<gf::Fp>(manual.begin(), manual.begin() + 3),
        out1);
    RequireStateEqual(manual, online.Snapshot().state);
    BOOST_TEST(online.Snapshot().permutation_calls == 2U);

    std::vector<gf::Fp> out2;
    BOOST_REQUIRE(online.Absorb(Slice(message, 13, 17)));
    for (uint32_t lane = 0; lane < 4; ++lane) {
        manual[lane] =
            gf::Add(manual[lane], message[13 + lane]);
    }
    RequireStateEqual(manual, online.Snapshot().state);
    BOOST_REQUIRE(online.Squeeze(7, out2));
    ah::Permute(manual);
    RequireEqual(
        std::vector<gf::Fp>(manual.begin(), manual.begin() + 7),
        out2);
    RequireStateEqual(manual, online.Snapshot().state);
    BOOST_TEST(online.Snapshot().permutation_calls == 3U);
    BOOST_REQUIRE(online.Finish());
    BOOST_CHECK(
        online.Snapshot().lifecycle == LifecycleV12::Finished);
}

BOOST_AUTO_TEST_CASE(
    online_safe_call_decomposition_is_output_equivalent)
{
    const IoPatternV12 aggregate_pattern = AggregateExamplePattern();
    const IoPatternV12 split_pattern = ExamplePattern();
    const std::vector<uint8_t> domain = Domain("BTX_SAFE_CHUNKS");
    const std::vector<gf::Fp> message = Sequence(20, 17);
    std::array<gf::Fp, kSafeCapacityV12> aggregate_tag{};
    std::array<gf::Fp, kSafeCapacityV12> split_tag{};
    BOOST_REQUIRE(DeriveTagV12(
        aggregate_pattern, domain, aggregate_tag));
    BOOST_REQUIRE(DeriveTagV12(split_pattern, domain, split_tag));
    BOOST_CHECK(aggregate_tag == split_tag);

    SafeTranscriptV12 aggregate;
    SafeTranscriptV12 split;
    BOOST_REQUIRE(aggregate.Start(aggregate_pattern, domain));
    BOOST_REQUIRE(split.Start(split_pattern, domain));

    std::vector<gf::Fp> agg0;
    std::vector<gf::Fp> agg1;
    std::vector<gf::Fp> agg2;
    BOOST_REQUIRE(aggregate.Absorb(Slice(message, 0, 8)));
    BOOST_REQUIRE(aggregate.Squeeze(6, agg0));
    BOOST_REQUIRE(aggregate.Absorb(Slice(message, 8, 13)));
    BOOST_REQUIRE(aggregate.Squeeze(3, agg1));
    BOOST_REQUIRE(aggregate.Absorb(Slice(message, 13, 17)));
    BOOST_REQUIRE(aggregate.Squeeze(7, agg2));
    BOOST_REQUIRE(aggregate.Finish());

    std::vector<gf::Fp> part;
    std::vector<gf::Fp> split0;
    std::vector<gf::Fp> split1;
    std::vector<gf::Fp> split2;
    BOOST_REQUIRE(split.Absorb(Slice(message, 0, 5)));
    BOOST_REQUIRE(split.Absorb(Slice(message, 5, 8)));
    BOOST_REQUIRE(split.Squeeze(3, part));
    split0.insert(split0.end(), part.begin(), part.end());
    BOOST_REQUIRE(split.Squeeze(3, part));
    split0.insert(split0.end(), part.begin(), part.end());
    BOOST_REQUIRE(split.Absorb(Slice(message, 8, 12)));
    BOOST_REQUIRE(split.Absorb(Slice(message, 12, 13)));
    BOOST_REQUIRE(split.Squeeze(3, split1));
    BOOST_REQUIRE(split.Absorb(Slice(message, 13, 17)));
    BOOST_REQUIRE(split.Squeeze(3, part));
    split2.insert(split2.end(), part.begin(), part.end());
    BOOST_REQUIRE(split.Squeeze(4, part));
    split2.insert(split2.end(), part.begin(), part.end());
    BOOST_REQUIRE(split.Finish());

    RequireEqual(agg0, split0);
    RequireEqual(agg1, split1);
    RequireEqual(agg2, split2);
}

BOOST_AUTO_TEST_CASE(
    safecore_algorithm3_uses_zero_padding_and_exact_post_squeeze_call)
{
    const std::vector<gf::Fp> message = Sequence(100, 7);
    const std::vector<uint8_t> app_domain = Domain("HASH_DAG");
    ah::Digest digest{};
    SafeCoreResultV12 audit;
    BOOST_REQUIRE(SafeCoreDigestV12(
        aht::RoleV12::TranscriptFriSeed, app_domain,
        message, digest, &audit));

    BOOST_TEST(audit.output.size() == 4U);
    BOOST_TEST(audit.cost.absorb_poseidon_calls == 1U);
    BOOST_TEST(audit.cost.output_required_poseidon_calls == 1U);
    BOOST_TEST(
        audit.cost.published_algorithm_poseidon_calls == 2U);
    BOOST_TEST(
        audit.cost.published_algorithm_poseidon_air_rows == 2U);
    BOOST_TEST(audit.cost.poseidon_air_columns == 484U);

    // Independent manual Algorithm-3 first block: fixed IO binds length 7,
    // therefore the eighth lane is ZERO, not a 10* delimiter.
    ah::State manual{};
    std::copy(
        audit.tag.begin(), audit.tag.end(),
        manual.begin() + kSafeRateV12);
    for (uint32_t lane = 0; lane < message.size(); ++lane) {
        manual[lane] = message[lane];
    }
    BOOST_TEST(manual[7] == 0U);
    ah::Permute(manual);
    for (uint32_t lane = 0; lane < 4; ++lane) {
        BOOST_TEST(digest[lane] == manual[lane]);
    }
    ah::Permute(manual); // Algorithm 3 line 10, after output.
    RequireStateEqual(manual, audit.final_state);

    std::vector<gf::Fp> eight = message;
    eight.push_back(0);
    ah::Digest length8{};
    BOOST_REQUIRE(SafeCoreDigestV12(
        aht::RoleV12::TranscriptFriSeed, app_domain,
        eight, length8));
    // Same padded rate block, distinct IO=(7,4) vs IO=(8,4).
    BOOST_CHECK(digest != length8);
}

BOOST_AUTO_TEST_CASE(
    stateless_safecore_typed_roles_close_cross_role_identical_input)
{
    const std::vector<gf::Fp> message{
        11, 12, 13, 14, 15, 16, 17,
    };
    ah::Digest fs{};
    ah::Digest row{};
    BOOST_REQUIRE(SafeCoreDigestV12(
        aht::RoleV12::TranscriptBatchCoefficient, {}, message, fs));
    BOOST_REQUIRE(SafeCoreDigestV12(
        aht::RoleV12::MerkleRowLeaf, {}, message, row));
    BOOST_CHECK(fs != row);

    // Existing seed feedback is ordinary fixed-length M, not a schedule
    // violation and not a reason to require a continuous rewrite.
    std::vector<gf::Fp> feedback = message;
    feedback.insert(feedback.end(), fs.begin(), fs.end());
    ah::Digest next{};
    ah::Digest next_again{};
    BOOST_REQUIRE(SafeCoreDigestV12(
        aht::RoleV12::TranscriptFoldState, {}, feedback, next));
    BOOST_REQUIRE(SafeCoreDigestV12(
        aht::RoleV12::TranscriptFoldState, {}, feedback, next_again));
    BOOST_TEST(next == next_again);
}

BOOST_AUTO_TEST_CASE(
    published_safecore_blank_blocks_are_not_online_duplex_shortcut)
{
    IoPatternBuilderV12 builder;
    IoPatternV12 pattern;
    BOOST_REQUIRE(builder.Absorb(9));
    BOOST_REQUIRE(builder.Squeeze(10));
    BOOST_REQUIRE(builder.Absorb(3));
    BOOST_REQUIRE(builder.Squeeze(4));
    BOOST_REQUIRE(builder.Build(pattern));
    const auto domain = Domain("BTX_SAFE_MULTIBLOCK");
    const auto message = Sequence(200, 12);

    SafeTranscriptV12 online;
    BOOST_REQUIRE(online.Start(pattern, domain));
    std::vector<gf::Fp> first;
    std::vector<gf::Fp> second;
    BOOST_REQUIRE(online.Absorb(Slice(message, 0, 9)));
    BOOST_REQUIRE(online.Squeeze(10, first));
    SafeCorePrefixV12 prefix0;
    BOOST_REQUIRE(EvaluateSafeCorePrefixV12(
        pattern, domain, Slice(message, 0, 9), 0, prefix0));
    RequireEqual(prefix0.output, first);
    RequireStateEqual(
        prefix0.state_before_final_output_permutation,
        online.Snapshot().state);
    BOOST_TEST(prefix0.output_required_poseidon_calls == 3U);

    BOOST_REQUIRE(online.Absorb(Slice(message, 9, 12)));
    BOOST_REQUIRE(online.Squeeze(4, second));
    SafeCorePrefixV12 prefix1;
    BOOST_REQUIRE(EvaluateSafeCorePrefixV12(
        pattern, domain, message, 1, prefix1));
    // Published SAFECorePad Algorithm 2 line 5 inserts
    // ceil(10/8)=2 complete zero blocks between the absorb phases:
    //
    //   ceil(9/8) + ceil(10/8) + ceil(3/8) = 5 P calls.
    //
    // Online SAFE exposes the first output block directly and only needs one
    // further P for the second block, so its running duplex state has 4 calls.
    BOOST_TEST(prefix1.output_required_poseidon_calls == 5U);
    BOOST_TEST(online.Snapshot().permutation_calls == 4U);
    BOOST_CHECK(prefix1.output != second);

    std::array<gf::Fp, kSafeCapacityV12> tag{};
    BOOST_REQUIRE(DeriveTagV12(pattern, domain, tag));
    ah::State exact{};
    std::copy(
        tag.begin(), tag.end(), exact.begin() + kSafeRateV12);
    for (uint32_t lane = 0; lane < 8; ++lane) {
        exact[lane] = gf::Add(exact[lane], message[lane]);
    }
    ah::Permute(exact);
    exact[0] = gf::Add(exact[0], message[8]);
    ah::Permute(exact);
    ah::Permute(exact); // first SAFECorePad zero block
    ah::Permute(exact); // second SAFECorePad zero block
    for (uint32_t lane = 0; lane < 3; ++lane) {
        exact[lane] = gf::Add(exact[lane], message[9 + lane]);
    }
    ah::Permute(exact);
    RequireEqual(
        std::vector<gf::Fp>(exact.begin(), exact.begin() + 4),
        prefix1.output);
    RequireStateEqual(
        exact, prefix1.state_before_final_output_permutation);
    BOOST_REQUIRE(online.Finish());
}

BOOST_AUTO_TEST_CASE(schedule_misuse_and_noncanonical_lanes_fail_closed)
{
    IoPatternBuilderV12 builder;
    IoPatternV12 pattern;
    BOOST_REQUIRE(builder.Absorb(2));
    BOOST_REQUIRE(builder.Squeeze(4));
    BOOST_REQUIRE(builder.Build(pattern));
    const auto domain = Domain("BTX_SAFE_MISUSE");
    std::string why;
    std::vector<gf::Fp> output{99};

    SafeTranscriptV12 wrong_order;
    BOOST_REQUIRE(wrong_order.Start(pattern, domain));
    BOOST_CHECK(!wrong_order.Squeeze(1, output, &why));
    BOOST_TEST(output.empty());
    BOOST_CHECK(
        wrong_order.Snapshot().lifecycle == LifecycleV12::Failed);
    const SafeStateSnapshotV12 wrong_order_snapshot =
        wrong_order.Snapshot();
    BOOST_CHECK(std::all_of(
        wrong_order_snapshot.state.begin(),
        wrong_order_snapshot.state.end(),
        [](gf::Fp lane) { return lane == 0; }));

    SafeTranscriptV12 overrun;
    BOOST_REQUIRE(overrun.Start(pattern, domain));
    BOOST_CHECK(!overrun.Absorb({1, 2, 3}, &why));
    BOOST_CHECK(
        overrun.Snapshot().lifecycle == LifecycleV12::Failed);

    SafeTranscriptV12 noncanonical;
    BOOST_REQUIRE(noncanonical.Start(pattern, domain));
    BOOST_CHECK(!noncanonical.Absorb({1, gf::kP}, &why));
    BOOST_CHECK(
        noncanonical.Snapshot().lifecycle == LifecycleV12::Failed);

    SafeTranscriptV12 early_finish;
    BOOST_REQUIRE(early_finish.Start(pattern, domain));
    BOOST_REQUIRE(early_finish.Absorb({1, 2}));
    BOOST_CHECK(!early_finish.Finish(&why));
    BOOST_CHECK(
        early_finish.Snapshot().lifecycle == LifecycleV12::Failed);

    SafeTranscriptV12 double_start;
    BOOST_REQUIRE(double_start.Start(pattern, domain));
    BOOST_CHECK(!double_start.Start(pattern, domain, nullptr, &why));
    BOOST_CHECK(
        double_start.Snapshot().lifecycle == LifecycleV12::Failed);

    SafeTranscriptV12 wrong_chunking;
    BOOST_REQUIRE(wrong_chunking.Start(pattern, domain));
    BOOST_CHECK(!wrong_chunking.Absorb({1}, &why));
    BOOST_CHECK(
        wrong_chunking.Snapshot().lifecycle ==
        LifecycleV12::Failed);

    SafeCoreResultV12 result;
    BOOST_CHECK(!EvaluateSafeCoreV12(
        pattern, domain, {1}, 0, result, &why));
    BOOST_CHECK(!EvaluateSafeCoreV12(
        pattern, domain, {1, gf::kP}, 0, result, &why));
}

BOOST_AUTO_TEST_CASE(pattern_and_manifest_malformed_inputs_reject)
{
    std::string why;
    IoPatternV12 invalid{{
        {IoKindV12::Squeeze, 4},
        {IoKindV12::Absorb, 1},
    }, {}};
    BOOST_CHECK(!ValidateIoPatternV12(invalid, &why));

    IoPatternBuilderV12 zero;
    BOOST_CHECK(!zero.Absorb(0, &why));
    IoPatternV12 unused;
    BOOST_CHECK(!zero.Build(unused, &why));

    IoPatternBuilderV12 overflow;
    BOOST_REQUIRE(overflow.Absorb(kSafeMaxIoElementsPerPhase));
    BOOST_CHECK(!overflow.Absorb(1, &why));

    IoPatternV12 mismatched_exact{{
        {IoKindV12::Absorb, 2},
        {IoKindV12::Squeeze, 4},
    }, {
        {IoKindV12::Absorb, 1},
        {IoKindV12::Squeeze, 4},
    }};
    BOOST_CHECK(!ValidateIoPatternV12(mismatched_exact, &why));

    TranscriptPatternManifestBuilderV12 duplicate;
    BOOST_REQUIRE(duplicate.Absorb("commitment", 4));
    BOOST_CHECK(!duplicate.Squeeze("commitment", 4, &why));
    TranscriptPatternManifestV12 manifest;
    BOOST_CHECK(!duplicate.Build(Domain("BTX_MANIFEST"), manifest, &why));
}

BOOST_AUTO_TEST_CASE(exact_manifest_reports_rows_calls_and_fail_closed_gates)
{
    TranscriptPatternManifestBuilderV12 builder;
    BOOST_REQUIRE(builder.Absorb("public_statement", 5));
    BOOST_REQUIRE(builder.Absorb("trace_root", 3));
    BOOST_REQUIRE(builder.Squeeze("air_lambda", 3));
    BOOST_REQUIRE(builder.Squeeze("fri_seed", 3));
    BOOST_REQUIRE(builder.Absorb("ood_openings_a", 4));
    BOOST_REQUIRE(builder.Absorb("ood_openings_b", 1));
    BOOST_REQUIRE(builder.Squeeze("deep_weight", 3));
    BOOST_REQUIRE(builder.Absorb("fold_root", 4));
    BOOST_REQUIRE(builder.Squeeze("query_seed", 3));
    BOOST_REQUIRE(builder.Squeeze("query_candidate", 4));

    TranscriptPatternManifestV12 manifest;
    BOOST_REQUIRE(builder.Build(Domain("BTX_STAGE3_FS_V12"), manifest));
    BOOST_TEST(manifest.exact_calls.size() == 10U);
    BOOST_TEST(manifest.canonical_pattern.segments.size() == 6U);
    BOOST_TEST(manifest.canonical_pattern.exact_calls.size() == 10U);
    BOOST_TEST(manifest.canonical_io_words.size() == 6U);
    BOOST_TEST(manifest.canonical_io_bytes.size() == 24U);
    BOOST_TEST(manifest.absorb_elements == 17U);
    BOOST_TEST(manifest.squeeze_elements == 16U);
    BOOST_TEST(manifest.online_poseidon_calls == 3U);
    BOOST_TEST(manifest.online_poseidon_air_rows == 3U);
    BOOST_TEST(manifest.poseidon_air_columns == 484U);
    BOOST_TEST(manifest.tag_stats.logical_h_queries == 1U);
    BOOST_TEST(manifest.tag_stats.sha256d_calls >= 1U);

    BOOST_TEST(kFullCapacityTagHashImplementedV12);
    BOOST_TEST(kCanonicalAggregatedIoImplementedV12);
    BOOST_TEST(kExactOnlineIoCallScheduleImplementedV12);
    BOOST_TEST(kStatefulSafeApiImplementedV12);
    BOOST_TEST(kPublishedSafeCoreInterphasePadExactV12);
    BOOST_TEST(kOnlineAndSafeCoreInterphaseSemanticsSeparatedV12);
    BOOST_TEST(kStatelessSafeCoreImplementedV12);
    BOOST_TEST(kStatelessSafeCoreSupportsSeedFeedbackV12);
    BOOST_TEST(!kConcreteTagHashReductionCertifiedV12);
    BOOST_TEST(!kConcretePoseidonReductionCertifiedV12);
    BOOST_TEST(!kExactGlobalSafeQueryManifestEnforcedV12);
    BOOST_TEST(!kSafeDomainRegistryRootPinnedV12);
    BOOST_TEST(!kActiveNativeSafeMigrationV12);
    BOOST_TEST(!kRecursiveSafeAirExecutableV12);
    BOOST_TEST(!kNativeRecursiveSafeParityCertifiedV12);
    BOOST_TEST(!kStatelessSafeCoreAuthorityReadyV12);
    BOOST_TEST(!kSafeV12ProductionAuthorityReady);
}

BOOST_AUTO_TEST_CASE(
    pr95_v12_manifest_is_shape_fixed_typed_and_dual_q96)
{
    fsair::ManifestV12 manifest;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        fsair::BuildManifestV12(TestFsAirShape(), manifest, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        fsair::ValidateManifestV12(manifest, &why), why);
    BOOST_CHECK(manifest.proof_independent);
    BOOST_CHECK(manifest.exact_pr95_roles);
    BOOST_CHECK(manifest.q96_lanes_domain_independent);
    BOOST_CHECK(manifest.merkle_fs_capacity_classes_disjoint);
    BOOST_CHECK(manifest.lane_seeds_derived_from_common_parent);
    BOOST_CHECK(manifest.proof_witness_cells_not_preprocessed);
    BOOST_TEST(
        manifest.proof_dependent_preprocessed_columns == 0U);
    BOOST_CHECK(manifest.fits_static_domain_headroom);
    BOOST_CHECK(
        manifest.fri_lane[0].typed_domain !=
        manifest.fri_lane[1].typed_domain);
    BOOST_CHECK(
        manifest.fri_lane[0].safe_manifest.tag !=
        manifest.fri_lane[1].safe_manifest.tag);

    for (const auto& channel : manifest.fri_lane) {
        uint32_t query_vectors = 0;
        uint32_t coefficient_vectors = 0;
        for (const fsair::CallSpecV12& call : channel.calls) {
            BOOST_CHECK(fsair::IsFiatShamirRoleV12(call.typed_role));
            BOOST_CHECK(!fsair::IsMerkleRoleV12(call.typed_role));
            if (call.role ==
                fsair::CallRoleV12::SqueezeQueryVector) {
                ++query_vectors;
                BOOST_TEST(
                    call.items ==
                    fsair::kQueryCandidatesPerLaneV12);
                BOOST_TEST(
                    call.elements ==
                    3U * fsair::kQueryCandidatesPerLaneV12);
            }
            if (call.role ==
                fsair::CallRoleV12::
                    SqueezeBatchCoefficientVector) {
                ++coefficient_vectors;
                BOOST_TEST(call.items == 4U);
                BOOST_TEST(call.elements == 12U);
            }
        }
        BOOST_TEST(query_vectors == 1U);
        BOOST_TEST(coefficient_vectors == 1U);
    }

    BOOST_TEST(fsair::kProofIndependentManifestImplementedV12);
    BOOST_TEST(fsair::kDualQ96TypedDomainsImplementedV12);
    BOOST_TEST(fsair::kNativeAirDifferentialHarnessImplementedV12);
    BOOST_TEST(fsair::kPoseidonPermutationRowsExecutableV12);
    BOOST_TEST(!fsair::kProofPayloadMappingCompleteV12);
    BOOST_TEST(
        !fsair::kRecursiveIoWiringConstraintsExecutableV12);
    BOOST_TEST(!fsair::kSafeFsRegistryPinnedV12);
    BOOST_TEST(!fsair::kDualQ96NiropReductionCertifiedV12);
    BOOST_TEST(
        !fsair::kDualQ96CommonCommitmentHybridCertifiedV12);
    BOOST_TEST(!fsair::kSafeFsGlobalReductionCertifiedV12);
    BOOST_TEST(!fsair::kSafeFsAuthorityReadyV12);

    const fsair::ShapeV12 production{
        /*child_w=*/fsair::kProductionBatchColumnsV12 - 1,
        /*child_n_rows=*/UINT32_C(1) << 20,
        /*child_quotient_len=*/UINT32_C(1) << 23,
        /*n_coeffs=*/UINT32_C(1) << 20,
        /*n_lde=*/UINT32_C(1) << 24,
        /*n_folds=*/fsair::kProductionFoldsV12,
    };
    fsair::ManifestV12 production_manifest;
    BOOST_REQUIRE_MESSAGE(
        fsair::BuildManifestV12(
            production, production_manifest, &why),
        why);
    BOOST_CHECK(production_manifest.production_reference_shape);
    BOOST_CHECK(
        production_manifest.production_reference_cost_pinned);
    BOOST_TEST(
        production_manifest.total_poseidon_air_rows ==
        fsair::kProductionExpectedSafeAirRowsV12);
    BOOST_TEST(
        production_manifest.total_poseidon_air_rows == 2831U);
    BOOST_TEST(
        production_manifest.total_query_sampler_air_rows == 512U);
    BOOST_TEST(
        production_manifest.total_recursive_air_rows == 3343U);
    BOOST_TEST(
        production_manifest.query_sampler_air_columns == 562U);
    BOOST_TEST(
        production_manifest.
            production_query_exhaustion_bound_bits == 440U);
    BOOST_TEST(
        production_manifest.static_domain_headroom_rows == 56480U);
    BOOST_TEST(
        production_manifest.static_domain_margin_rows == 53137U);
    BOOST_CHECK(production_manifest.fits_static_domain_headroom);
}

BOOST_AUTO_TEST_CASE(
    pr95_v12_native_and_recursive_air_witness_are_differential_equal)
{
    fsair::ManifestV12 manifest;
    fsair::NativeExecutionV12 native;
    fsair::AirWitnessV12 witness;
    const fsair::TranscriptInputsV12 inputs = TestFsAirInputs();
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        fsair::BuildManifestV12(TestFsAirShape(), manifest, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        fsair::ExecuteNativeV12(manifest, inputs, native, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        fsair::BuildAirWitnessV12(manifest, inputs, witness, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        fsair::ValidateAirWitnessV12(
            manifest, inputs, witness, &why),
        why);
    BOOST_CHECK(native.independent_lane_tags);
    BOOST_CHECK(witness.native_differential_equal);
    BOOST_CHECK(witness.lane_order_bound);
    BOOST_CHECK(witness.valid);
    BOOST_TEST(
        native.fri_lane[0].query_indices.size() ==
        fsair::kQueriesPerLaneV12);
    BOOST_TEST(
        native.fri_lane[1].query_indices.size() ==
        fsair::kQueriesPerLaneV12);
    BOOST_CHECK(
        native.fri_lane[0].final_state !=
        native.fri_lane[1].final_state);

    const auto check_channel = [](const auto& channel) {
        BOOST_CHECK(channel.poseidon_constraints_zero);
        BOOST_CHECK(channel.io_wiring_checked);
        BOOST_CHECK(!channel.permutation_rows.empty());
        for (const auto& row : channel.permutation_rows) {
            BOOST_CHECK(row.constraints_zero);
            BOOST_TEST(
                row.decomposed_row.size() ==
                fsair::p2air::kFixedColumns);
        }
    };
    check_channel(witness.air_quotient);
    check_channel(witness.fri_lane[0]);
    check_channel(witness.fri_lane[1]);
    for (uint32_t lane = 0;
         lane < fsair::kFriLaneCountV12; ++lane) {
        const auto& sampler =
            witness.fri_lane[lane].query_sampler_air;
        BOOST_CHECK(
            witness.fri_lane[lane].query_sampler_air_valid);
        BOOST_CHECK(
            witness.fri_lane[lane].
                query_sampler_source_call_typed);
        BOOST_CHECK(sampler.valid);
        BOOST_TEST(sampler.cs.n_rows == 256U);
        BOOST_TEST(sampler.cs.n_columns == 562U);
        BOOST_TEST(sampler.selected_count == 96U);
        BOOST_TEST(sampler.selected_indices.size() == 96U);
        BOOST_TEST(sampler.violations == 0U);
        BOOST_TEST(sampler.max_alg_degree == 7U);
        BOOST_TEST(
            sampler.verifier_owned_preprocessed_columns == 1U);
        BOOST_TEST(
            sampler.proof_owned_preprocessed_columns == 0U);
        BOOST_CHECK(
            sampler.full_limb_canonicity_constrained);
        BOOST_CHECK(
            sampler.source_candidate_vector_shape_canonical);
        BOOST_CHECK(sampler.index_range_constrained);
        BOOST_CHECK(
            sampler.first_distinct_order_constrained);
        BOOST_CHECK(sampler.uniqueness_constrained);
        BOOST_CHECK(
            sampler.exact_q96_exhaustion_constrained);
        BOOST_CHECK(sampler.selected_outputs_constrained);
        BOOST_CHECK(
            !sampler.
                recursive_safe_source_equality_consumed);
    }
    BOOST_CHECK(
        fsair::kWithoutReplacementQuerySamplerAirExecutableV12);
    BOOST_CHECK(
        !fsair::
            kQuerySamplerSafeSourceEqualityRecursivelyConsumedV12);
    BOOST_CHECK(
        !fsair::kQuerySamplerSoleProductionQuerySourceV12);
    BOOST_CHECK(!fsair::kSafeFsAuthorityReadyV12);
}

BOOST_AUTO_TEST_CASE(
    pr95_v12_alias_order_domain_and_merged_lane_attacks_reject)
{
    fsair::ManifestV12 manifest;
    fsair::TranscriptInputsV12 inputs = TestFsAirInputs();
    fsair::AirWitnessV12 witness;
    std::string why;
    BOOST_REQUIRE(
        fsair::BuildManifestV12(TestFsAirShape(), manifest, &why));
    BOOST_REQUIRE(
        fsair::BuildAirWitnessV12(manifest, inputs, witness, &why));

    // Goldilocks alias B=x+p: never silently canonicalize proof-owned input.
    fsair::TranscriptInputsV12 alias = inputs;
    alias.proof_witness.trace_commit[0] = gf::kP + 5;
    fsair::AirWitnessV12 unused_witness;
    BOOST_CHECK(
        !fsair::BuildAirWitnessV12(
            manifest, alias, unused_witness, &why));

    // A same-width Z1/Z2 call-order swap would retain the same aggregated IO
    // tag. The canonical role/index manifest, not width alone, rejects it.
    fsair::ManifestV12 reordered = manifest;
    auto& calls = reordered.fri_lane[0].calls;
    const auto z1_bind = std::find_if(
        calls.begin(), calls.end(), [](const auto& call) {
            return call.role ==
                fsair::CallRoleV12::BindZ1Candidates;
        });
    const auto z2_bind = std::find_if(
        calls.begin(), calls.end(), [](const auto& call) {
            return call.role ==
                fsair::CallRoleV12::BindZ2Candidates;
        });
    BOOST_REQUIRE(z1_bind != calls.end());
    BOOST_REQUIRE(z2_bind != calls.end());
    std::iter_swap(z1_bind, z2_bind);
    BOOST_CHECK(!fsair::ValidateManifestV12(reordered, &why));

    // Build a fully self-consistent SAFE tag under a Merkle capacity domain.
    // It is still not an admissible FS manifest.
    fsair::ManifestV12 domain_swap = manifest;
    auto& swapped = domain_swap.fri_lane[0];
    std::vector<uint8_t> merkle_domain;
    BOOST_REQUIRE(TypedDomainV12(
        aht::RoleV12::MerkleRowLeaf, swapped.application_domain,
        merkle_domain, &why));
    TranscriptPatternManifestBuilderV12 rebuilt;
    for (const fsair::CallSpecV12& call : swapped.calls) {
        const bool ok =
            call.io_kind == IoKindV12::Absorb
            ? rebuilt.Absorb(call.label, call.elements, &why)
            : rebuilt.Squeeze(call.label, call.elements, &why);
        BOOST_REQUIRE_MESSAGE(ok, why);
    }
    BOOST_REQUIRE(rebuilt.Build(
        merkle_domain, swapped.safe_manifest, &why));
    swapped.typed_domain = merkle_domain;
    swapped.capacity_role = aht::RoleV12::MerkleRowLeaf;
    BOOST_CHECK(!fsair::ValidateManifestV12(domain_swap, &why));

    // Copying lane 0's complete valid witness into lane 1 cannot merge the
    // two Q96 repetitions: channel id, typed tag and every state differ.
    fsair::AirWitnessV12 merged = witness;
    merged.fri_lane[1] = merged.fri_lane[0];
    BOOST_CHECK(!fsair::ValidateAirWitnessV12(
        manifest, inputs, merged, &why));

    // Even copying only the locally valid Q96 sampler cannot merge lanes:
    // its lane id and its ordered source candidates belong to the typed
    // lane-0 SAFE transcript.
    fsair::AirWitnessV12 shared_sampler = witness;
    shared_sampler.fri_lane[1].query_sampler_air =
        shared_sampler.fri_lane[0].query_sampler_air;
    BOOST_CHECK(!fsair::ValidateAirWitnessV12(
        manifest, inputs, shared_sampler, &why));

    // A direct feedback-cell change is likewise rejected by reconstruction.
    fsair::AirWitnessV12 feedback = witness;
    auto& lane_calls =
        feedback.fri_lane[0].projected_execution.calls;
    const auto feedback_call = std::find_if(
        lane_calls.begin(), lane_calls.end(), [](const auto& call) {
            return call.spec.role ==
                fsair::CallRoleV12::
                    AbsorbBatchCoefficientVector;
        });
    BOOST_REQUIRE(feedback_call != lane_calls.end());
    feedback_call->values.back() =
        gf::Add(feedback_call->values.back(), 1);
    BOOST_CHECK(!fsair::ValidateAirWitnessV12(
        manifest, inputs, feedback, &why));
}

BOOST_AUTO_TEST_CASE(
    pr95_v12_without_replacement_sampler_rejects_exhaustion_duplicate_reorder_and_range_attacks)
{
    std::vector<gf::Fp> source(
        3 * qsampler::kCandidatesV12, gf::FromU64(0));
    for (uint32_t candidate = 0;
         candidate < qsampler::kCandidatesV12; ++candidate) {
        // Candidate 1 duplicates candidate 0. The canonical output must skip
        // it and continue with candidate 2, without changing transcript order.
        const uint32_t index =
            candidate == 1 ? 0 : candidate - (candidate > 1 ? 1 : 0);
        source[3 * candidate] = gf::FromU64(index);
        source[3 * candidate + 1] =
            gf::FromU64(10'000 + candidate);
        source[3 * candidate + 2] =
            gf::FromU64(20'000 + candidate);
    }

    std::vector<uint32_t> native;
    std::vector<uint32_t> ordinals;
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        qsampler::SelectFirstDistinctV12(
            source, 1024, native, &ordinals, &why),
        why);
    BOOST_TEST(native.size() == 96U);
    BOOST_TEST(ordinals.size() == 96U);
    BOOST_TEST(native[0] == 0U);
    BOOST_TEST(native[1] == 1U);
    BOOST_TEST(ordinals[0] == 0U);
    BOOST_TEST(ordinals[1] == 2U);

    qsampler::QuerySamplerAirV12 honest;
    BOOST_REQUIRE_MESSAGE(
        qsampler::BuildQuerySamplerAirV12(
            0, 1024, source, honest, &why),
        why);
    BOOST_REQUIRE_MESSAGE(
        qsampler::ValidateQuerySamplerAirV12(
            0, 1024, source, honest, &why),
        why);
    BOOST_CHECK(honest.selected_indices == native);
    BOOST_CHECK(honest.selected_candidate_ordinals == ordinals);

    // Exhaustion is an AIR failure, not a host-side advisory boolean.
    std::vector<gf::Fp> exhausted(
        3 * qsampler::kCandidatesV12, gf::FromU64(0));
    qsampler::QuerySamplerAirV12 exhausted_air;
    BOOST_CHECK(!qsampler::BuildQuerySamplerAirV12(
        0, 1024, exhausted, exhausted_air, &why));
    BOOST_TEST(exhausted_air.selected_count == 1U);
    BOOST_CHECK_GT(exhausted_air.violations, 0U);

    // Force the repeated candidate to be selected. The polynomial zero test
    // and first-distinct selector reject the changed witness.
    auto duplicate_selected = honest;
    duplicate_selected.columns[
        duplicate_selected.layout.selected][1] =
            gf::Fp3::One();
    BOOST_CHECK_GT(
        qsampler::CountQuerySamplerViolationsV12(
            duplicate_selected.cs,
            duplicate_selected.columns),
        0U);

    // A query output cannot duplicate or reorder another output while
    // retaining the state-machine transitions.
    auto duplicate_output = honest;
    const uint32_t last = qsampler::kTraceRowsV12 - 1;
    duplicate_output.columns[
        duplicate_output.layout.Output(1)][last] =
            duplicate_output.columns[
                duplicate_output.layout.Output(0)][last];
    BOOST_CHECK_GT(
        qsampler::CountQuerySamplerViolationsV12(
            duplicate_output.cs, duplicate_output.columns),
        0U);

    auto reordered_output = honest;
    std::swap(
        reordered_output.columns[
            reordered_output.layout.Output(0)][last],
        reordered_output.columns[
            reordered_output.layout.Output(1)][last]);
    BOOST_CHECK_GT(
        qsampler::CountQuerySamplerViolationsV12(
            reordered_output.cs, reordered_output.columns),
        0U);

    // An out-of-domain output violates the power-of-two mask relation.
    auto out_of_range = honest;
    out_of_range.columns[
        out_of_range.layout.index][0] =
            gf::Fp3::FromFp(gf::FromU64(1024));
    BOOST_CHECK_GT(
        qsampler::CountQuerySamplerViolationsV12(
            out_of_range.cs, out_of_range.columns),
        0U);

    // Reordering the typed SAFE candidate stream while retaining the old AIR
    // is rejected by exact source reconstruction.
    std::vector<gf::Fp> reordered_source = source;
    for (uint32_t lane = 0; lane < 3; ++lane) {
        std::swap(
            reordered_source[3 * 2 + lane],
            reordered_source[3 * 3 + lane]);
    }
    BOOST_CHECK(!qsampler::ValidateQuerySamplerAirV12(
        0, 1024, reordered_source, honest, &why));

    // The same candidate vector cannot be relabelled as the other lane.
    BOOST_CHECK(!qsampler::ValidateQuerySamplerAirV12(
        1, 1024, source, honest, &why));
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace matmul::v4::rc::safe_v12
