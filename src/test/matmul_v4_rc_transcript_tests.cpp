// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_transcript.h>
#include <primitives/block.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

namespace rc = matmul::v4::rc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_transcript_tests, BasicTestingSetup)

namespace {

CBlockHeader MakeRCHeader(uint64_t nonce)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    for (int i = 0; i < 32; ++i) {
        header.hashPrevBlock.data()[i] = static_cast<unsigned char>(0x51);
        header.hashMerkleRoot.data()[i] = static_cast<unsigned char>(0xa3);
        header.seed_a.data()[i] = static_cast<unsigned char>(0x11);
        header.seed_b.data()[i] = static_cast<unsigned char>(0x22);
    }
    return header;
}

/** Drive both sinks with the same toy flat-stream bytes (V1). */
template <typename Sink>
uint256 FeedFlatV1(Sink& sink, const std::vector<int8_t>& bytes)
{
    sink.BeginRound(0);
    sink.BeginPhase(1);
    sink.SubmitExtractedTensor(rc::RCSegType::ZExtracted, /*layer=*/0,
                               Span<const int8_t>{bytes.data(), bytes.size()});
    sink.EndPhase();
    return sink.EndRound();
}

} // namespace

BOOST_AUTO_TEST_CASE(rc_transcript_version_defaults_v1)
{
    BOOST_CHECK_EQUAL(rc::kRCTranscriptVersion, static_cast<uint32_t>(rc::kRCTranscriptVersionV1));
    BOOST_CHECK(rc::kRCTranscriptVersionV1 != rc::kRCTranscriptVersionV2);
    // Silent golden replacement is forbidden: any consensus-digest change must
    // bump kRCTranscriptVersion / ENC_RC_V* and retain prior goldens in
    // contrib/matmul-v4/rc-golden-gate.py (WS-F / Stage H invariant).
    BOOST_CHECK_EQUAL(rc::kRCTranscriptVersion, 1u);
}

BOOST_AUTO_TEST_CASE(rc_streaming_vs_resident_identical_root_toy)
{
    constexpr uint32_t t_leaf = 64;
    std::vector<int8_t> toy(t_leaf * 3 + 17, 0);
    for (size_t i = 0; i < toy.size(); ++i) {
        toy[i] = static_cast<int8_t>(i * 3 + 1);
    }

    rc::RCStreamingSink streamed(t_leaf, rc::kRCTranscriptVersionV1);
    rc::RCResidentSink resident(t_leaf, rc::kRCTranscriptVersionV1, /*retain_pages=*/true);

    const uint256 r_stream = FeedFlatV1(streamed, toy);
    const uint256 r_resident = FeedFlatV1(resident, toy);
    BOOST_CHECK(r_stream == r_resident);
    BOOST_CHECK(!r_stream.IsNull());

    // Resident retained pow2-padded leaf count for openings.
    BOOST_CHECK(!resident.Leaves().empty());
    BOOST_CHECK((resident.Leaves().size() & (resident.Leaves().size() - 1)) == 0);
    BOOST_CHECK(rc::RCTranscriptFoldRoot(resident.Leaves()) == r_resident);
}

BOOST_AUTO_TEST_CASE(rc_incremental_vs_materialized_root_equivalence)
{
    constexpr uint32_t t_leaf = 64;
    auto check = [&](const std::vector<int8_t>& bytes) {
        const uint256 materialized = rc::BuildTileTreeRoot(bytes, t_leaf);
        const uint256 via_helper =
            rc::RCTranscriptMaterializedFlatRoot(Span<const int8_t>{bytes}, t_leaf);
        BOOST_CHECK(materialized == via_helper);

        rc::RCStreamingSink sink(t_leaf, rc::kRCTranscriptVersionV1);
        // Uneven chunk submits to exercise the partial window.
        sink.BeginRound(0);
        sink.BeginPhase(1);
        size_t off = 0;
        const size_t chunks[] = {1, 7, 13, 32, 64, 100, 3};
        size_t ci = 0;
        while (off < bytes.size()) {
            const size_t n = std::min(chunks[ci % 7], bytes.size() - off);
            sink.SubmitSegment(rc::RCSegType::ZPartial, 0, static_cast<uint32_t>(ci),
                               Span<const unsigned char>{
                                   reinterpret_cast<const unsigned char*>(bytes.data() + off), n});
            off += n;
            ++ci;
        }
        sink.EndPhase();
        const uint256 incremental = sink.EndRound();
        BOOST_CHECK(incremental == materialized);

        // Frontier leaf count stays O(log) in soft WS vs full materialization.
        BOOST_CHECK_LT(sink.SoftWorkingSetBytes(),
                       std::max<size_t>(bytes.size() + 1024, 4096));
    };

    check({});
    check(std::vector<int8_t>(t_leaf, 0x11));
    check(std::vector<int8_t>(t_leaf * 3, 0x22));
    check(std::vector<int8_t>(t_leaf * 2 + 17, 0x33));
    check(std::vector<int8_t>(t_leaf * 8 + 5, 0x44));
}

BOOST_AUTO_TEST_CASE(rc_frontier_matches_fold_on_explicit_leaves)
{
    const uint256 pad = rc::RCTranscriptPadLeafHash();
    std::vector<uint256> leaves;
    for (uint32_t i = 0; i < 5; ++i) {
        unsigned char buf[32]{};
        buf[0] = static_cast<unsigned char>(i + 1);
        leaves.emplace_back(Span<const unsigned char>{buf, 32});
    }
    // Pad to 8 like RoundMerkleStream.
    while (leaves.size() < 8) leaves.push_back(pad);
    const uint256 folded = rc::RCTranscriptFoldRoot(leaves);

    rc::RCMerkleFrontier fr;
    for (uint32_t i = 0; i < 5; ++i) {
        unsigned char buf[32]{};
        buf[0] = static_cast<unsigned char>(i + 1);
        fr.AppendLeaf(uint256{Span<const unsigned char>{buf, 32}});
    }
    BOOST_CHECK(fr.FinalizeRoot(pad) == folded);
    BOOST_CHECK_LE(fr.FrontierSlots(), 4u); // log2(8)=3 + slack
}

BOOST_AUTO_TEST_CASE(rc_v2_typed_subroots_streaming_equals_resident)
{
    constexpr uint32_t t_leaf = 64;
    rc::RCStreamingSink streamed(t_leaf, rc::kRCTranscriptVersionV2);
    rc::RCResidentSink resident(t_leaf, rc::kRCTranscriptVersionV2, /*retain_pages=*/false);

    auto drive = [&](rc::RCTranscriptSink& sink) {
        sink.BeginRound(0);
        sink.BeginPhase(1);
        std::vector<int8_t> z(96, 7);
        sink.SubmitExtractedTensor(rc::RCSegType::ZExtracted, 0, z);
        sink.EndPhase();
        for (uint32_t l = 0; l < 2; ++l) {
            sink.BeginLayer(l);
            std::vector<int8_t> x(80, static_cast<int8_t>(10 + l));
            std::vector<int8_t> g(80, static_cast<int8_t>(20 + l));
            std::vector<unsigned char> dseg(40, static_cast<unsigned char>(30 + l));
            std::vector<int8_t> d(64, static_cast<int8_t>(40 + l));
            sink.SubmitExtractedTensor(rc::RCSegType::XAct, l, x);
            sink.SubmitExtractedTensor(rc::RCSegType::GGrad, l, g);
            sink.SubmitSegment(rc::RCSegType::DPartial, l, /*seg_id=*/0, dseg);
            sink.SubmitExtractedTensor(rc::RCSegType::DExtracted, l, d);
            sink.EndLayer();
        }
        return sink.EndRound();
    };

    const uint256 a = drive(streamed);
    const uint256 b = drive(resident);
    BOOST_CHECK(a == b);
    BOOST_CHECK(!a.IsNull());
    // V2 root must differ from V1 flat over a naive concatenation.
    rc::RCStreamingSink v1(t_leaf, rc::kRCTranscriptVersionV1);
    v1.BeginRound(0);
    v1.BeginPhase(1);
    std::vector<int8_t> z(96, 7);
    v1.SubmitExtractedTensor(rc::RCSegType::ZExtracted, 0, z);
    v1.EndPhase();
    const uint256 flat = v1.EndRound();
    BOOST_CHECK(a != flat);
}

BOOST_AUTO_TEST_CASE(rc_exec_mode_maps_checkpoint_digest_invariant)
{
    const auto header = MakeRCHeader(42);
    auto params = rc::MakeToyRCEpisodeParams();
    params.L_lyr = 4; // enough layers for StoreEvery4 to differ from StoreAll
    BOOST_REQUIRE(rc::ValidateRCEpisodeParams(params));

    const auto o_res = rc::OptionsForExecMode(rc::RCExecMode::Resident);
    const auto o_ckpt = rc::OptionsForExecMode(rc::RCExecMode::Checkpointed);
    const auto o_stream = rc::OptionsForExecMode(rc::RCExecMode::Streamed);

    BOOST_CHECK(o_res.checkpoint == rc::RCEpisodeOptions::Checkpoint::StoreAll);
    BOOST_CHECK(o_ckpt.checkpoint == rc::RCEpisodeOptions::Checkpoint::StoreEvery4);
    BOOST_CHECK(o_stream.checkpoint == rc::RCEpisodeOptions::Checkpoint::StoreOnlyX0);

    const uint256 d0 = rc::RecomputeResidentCurriculumReference(header, params, 0, o_res);
    const uint256 d1 = rc::RecomputeResidentCurriculumReference(header, params, 0, o_ckpt);
    const uint256 d2 = rc::RecomputeResidentCurriculumReference(header, params, 0, o_stream);
    BOOST_CHECK(d0 == d1);
    BOOST_CHECK(d1 == d2);

    // Default toy dims still hit the frozen V1 golden (exec-mode invariant).
    const auto toy = rc::MakeToyRCEpisodeParams();
    const uint256 golden =
        rc::RecomputeResidentCurriculumReference(header, toy, 0, o_stream);
    BOOST_CHECK_EQUAL(golden.GetHex(),
                      "5b1bff3c835b1c8e7816a2cccb181eb2fc30a99d97a971d73108c52a8238acd4");
}

BOOST_AUTO_TEST_CASE(rc_v1_sink_matches_episode_collected_stream_root)
{
    // V1 StreamingSink over the collected toy episode stream must match the
    // consensus round_root (preserves the fused-FFN episode golden).
    const auto header = MakeRCHeader(42);
    const auto params = rc::MakeToyRCEpisodeParams();
    std::vector<rc::RCRoundTranscript> rounds;
    const uint256 digest =
        rc::RecomputeResidentCurriculumReference(header, params, 0, {}, &rounds);
    BOOST_REQUIRE(!rounds.empty());
    BOOST_CHECK_EQUAL(digest.GetHex(),
                      "5b1bff3c835b1c8e7816a2cccb181eb2fc30a99d97a971d73108c52a8238acd4");

    rc::RCStreamingSink sink(params.T_leaf, rc::kRCTranscriptVersionV1);
    sink.BeginRound(0);
    sink.BeginPhase(1);
    sink.SubmitExtractedTensor(
        rc::RCSegType::ZExtracted, 0,
        Span<const int8_t>{rounds[0].stream.data(), rounds[0].stream.size()});
    sink.EndPhase();
    const uint256 from_sink = sink.EndRound();
    BOOST_CHECK(from_sink == rounds[0].round_root);
    BOOST_CHECK(from_sink == rc::BuildTileTreeRoot(rounds[0].stream, params.T_leaf));
}

#if defined(__linux__)
BOOST_AUTO_TEST_CASE(rc_streamed_soft_memory_note)
{
    // Soft note: StreamingSink working-set stays far below retained page bytes
    // for a multi-leaf toy buffer (not a production-dim proof).
    constexpr uint32_t t_leaf = 64;
    constexpr size_t n_bytes = t_leaf * 256; // 16 KiB payload
    std::vector<int8_t> buf(n_bytes, 0x5a);

    rc::RCStreamingSink streamed(t_leaf, rc::kRCTranscriptVersionV1);
    rc::RCResidentSink resident(t_leaf, rc::kRCTranscriptVersionV1, /*retain_pages=*/true);
    const uint256 a = FeedFlatV1(streamed, buf);
    const uint256 b = FeedFlatV1(resident, buf);
    BOOST_CHECK(a == b);

    const size_t stream_ws = streamed.SoftWorkingSetBytes();
    size_t page_bytes = 0;
    for (const auto& p : resident.Pages()) page_bytes += p.size();
    BOOST_TEST_MESSAGE("Streamed soft_ws=" << stream_ws << " Resident page_bytes=" << page_bytes
                                           << " frontier_note=O(log leaf_count)");
    BOOST_CHECK_LT(stream_ws, page_bytes);
    // Partial window (T_leaf) + O(log n) hashes ≪ full page retention.
    BOOST_CHECK_LT(stream_ws, t_leaf + 64 * 32);
}
#endif

BOOST_AUTO_TEST_SUITE_END()
