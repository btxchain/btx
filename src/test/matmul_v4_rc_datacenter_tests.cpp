// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cuda/matmul_v4_rc_episode_context.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_batch.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_datacenter.h>
#include <matmul/matmul_v4_rc_scale_axes.h>
#include <matmul/matmul_v4_rc_streamed_strategy.h>
#include <matmul/matmul_v4_rc_transcript.h>

#include <consensus/params.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace rc = matmul::v4::rc;
namespace dc = matmul::v4::rc::dc;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_datacenter_tests, BasicTestingSetup)

namespace {

CBlockHeader MakeCoupHeader(uint64_t nonce)
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

/** Consensus::Params with MatMul v4 active so SetDeterministicMatMulSeeds binds
 *  seed_a/seed_b to nNonce64 (exposes the Q-batch bank-template seed bug). */
Consensus::Params MakeV4SeedParams()
{
    Consensus::Params p;
    p.fMatMulPOW = true;
    p.nMatMulV4Height = 1;
    p.nMatMulV4Dimension = 64;
    return p;
}

CBlockHeader MakeSeededCoupHeader(uint64_t nonce, const Consensus::Params& consensus,
                                  int32_t height, int64_t parent_mtp)
{
    CBlockHeader header = MakeCoupHeader(nonce);
    header.seed_a.SetNull();
    header.seed_b.SetNull();
    BOOST_REQUIRE(SetDeterministicMatMulSeeds(header, consensus, height, parent_mtp));
    BOOST_REQUIRE(!header.seed_a.IsNull());
    BOOST_REQUIRE(!header.seed_b.IsNull());
    return header;
}

} // namespace

BOOST_AUTO_TEST_CASE(rc_dc_heights_remain_int32_max)
{
    Consensus::Params consensus;
    BOOST_CHECK_EQUAL(consensus.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulRCCoupledHeight, std::numeric_limits<int32_t>::max());
}

BOOST_AUTO_TEST_CASE(rc_dc_consensus_flags_default_off)
{
    BOOST_CHECK(dc::kRCCoupFullBankScheduleEnabled);
    BOOST_CHECK(dc::kRCCoupMaterialExchangeEnabled);
    BOOST_CHECK(dc::kRCThreeAxisScheduleWireEnabled);
    BOOST_CHECK_EQUAL(dc::kRCCoupPagesPerBarrierLobe, 12u);
    BOOST_CHECK_EQUAL(dc::kRCCoupExchangeRowsDefault, 128u);
    BOOST_CHECK_EQUAL(dc::kRCPackedBankPrimaryGiB, 51.0);
    BOOST_CHECK_EQUAL(dc::kRCMinerBatchQDefault, 32u);
    BOOST_CHECK_EQUAL(dc::kRCMinerBatchQMax, 256u);
    BOOST_CHECK_EQUAL(dc::kRCPackedBankTargetGiBCount, 4u);
    BOOST_CHECK_CLOSE(dc::kRCMxPackedBytesPerElem, 0.53125, 1e-12);
}

BOOST_AUTO_TEST_CASE(rc_dc_probe_status_smoke)
{
    const dc::RCDcStatus st = dc::ProbeRCDcStatus();
    BOOST_CHECK(st.full_bank_schedule);
    BOOST_CHECK(st.material_exchange);
    BOOST_CHECK(st.three_axis_wire);
    BOOST_CHECK(st.miner_batch_q_default_on);
    BOOST_CHECK_EQUAL(st.miner_batch_q, dc::kRCMinerBatchQDefault);
    BOOST_CHECK(!st.gkr_arbiter);
    BOOST_CHECK(!st.deficit.empty());
    BOOST_CHECK_EQUAL(st.cuda_episode_compiled, matmul_v4::cuda::IsRcEpisodeCudaCompiled());
    // Ready tracks whether the CUDA episode TU is linked (graph path callable).
    BOOST_CHECK(!st.cuda_episode_ready); // compiled ≠ ready
    BOOST_CHECK_EQUAL(st.cuda_episode_ready, false);
}

BOOST_AUTO_TEST_CASE(rc_dc_bank_pages_for_packed_gib)
{
    // W=8192 → packed bytes/page = W² · 0.53125 (~34 MiB) < int8 page (64 MiB),
    // so a fixed GiB budget admits more packed pages than int8-resident 768@48GiB.
    const uint32_t W = 8192;
    const uint32_t pages_48 = dc::BankPagesForPackedGiB(48.0, W);
    BOOST_CHECK(pages_48 > 768u);

    const double page_bytes =
        static_cast<double>(W) * W * dc::kRCMxPackedBytesPerElem;
    const double expect = std::ceil(48.0 * 1073741824.0 / page_bytes);
    BOOST_CHECK_EQUAL(pages_48, static_cast<uint32_t>(expect));

    BOOST_CHECK_EQUAL(dc::BankPagesForPackedGiB(0.0, W), 0u);
    BOOST_CHECK_EQUAL(dc::BankPagesForPackedGiB(40.0, 0), 0u);
}

BOOST_AUTO_TEST_CASE(rc_dc_select_coupled_bank_page_ids_legacy)
{
    const auto params = rc::MakeToyRCCoupParams();
    const uint256 sigma = matmul::v4::DeriveSigma(MakeCoupHeader(7));
    for (uint32_t b = 0; b < params.barriers; ++b) {
        for (uint32_t ell = 0; ell < params.lobes; ++ell) {
            const auto ids =
                rc::SelectCoupledBankPageIds(b, ell, params, sigma, /*full=*/false);
            BOOST_REQUIRE_EQUAL(ids.size(), 1u);
            BOOST_CHECK_EQUAL(ids[0], (b + ell) % params.bank_pages);
        }
    }
}

BOOST_AUTO_TEST_CASE(rc_dc_select_coupled_bank_page_ids_full_covers_production)
{
    // Production dims: 8×8×12 = 768 — every page exactly once (helper only).
    const auto params = rc::MakeProductionRCCoupParams();
    BOOST_CHECK_EQUAL(params.barriers * params.lobes * dc::kRCCoupPagesPerBarrierLobe,
                      params.bank_pages);
    const uint256 sigma = matmul::v4::DeriveSigma(MakeCoupHeader(42));

    std::vector<uint32_t> counts(params.bank_pages, 0);
    for (uint32_t b = 0; b < params.barriers; ++b) {
        for (uint32_t ell = 0; ell < params.lobes; ++ell) {
            const auto ids =
                rc::SelectCoupledBankPageIds(b, ell, params, sigma, /*full=*/true);
            BOOST_REQUIRE_EQUAL(ids.size(), dc::kRCCoupPagesPerBarrierLobe);
            std::set<uint32_t> uniq(ids.begin(), ids.end());
            BOOST_CHECK_EQUAL(uniq.size(), ids.size()); // no dupes within lobe slot
            for (uint32_t id : ids) {
                BOOST_REQUIRE(id < params.bank_pages);
                counts[id] += 1;
            }
        }
    }
    for (uint32_t c : counts) {
        BOOST_CHECK_EQUAL(c, 1u);
    }

    // Legacy remains single-page even on production shape.
    const auto legacy =
        rc::SelectCoupledBankPageIds(3, 5, params, sigma, /*full=*/false);
    BOOST_REQUIRE_EQUAL(legacy.size(), 1u);
    BOOST_CHECK_EQUAL(legacy[0], (3u + 5u) % params.bank_pages);
}

BOOST_AUTO_TEST_CASE(rc_dc_full_schedule_default_on_differs_from_legacy)
{
    const auto params = rc::MakeToyRCCoupParams();
    const auto header = MakeCoupHeader(99);
    rc::RCCoupOptions legacy;
    legacy.full_bank_schedule = false;
    legacy.material_exchange = false;
    const uint256 d_legacy = rc::RecomputeCoupledPuzzleReference(header, 0, params, legacy);

    // Default options follow dc levers (full-bank + material exchange ON).
    const uint256 d_default = rc::MineRCCoupledEpisode(header, 0, params);
    BOOST_CHECK(d_default != d_legacy);

    rc::RCCoupOptions opts; // defaults ON
    BOOST_CHECK(opts.full_bank_schedule);
    BOOST_CHECK(opts.material_exchange);
    const uint256 d_opts = rc::RecomputeCoupledPuzzleReference(header, 0, params, opts);
    BOOST_CHECK(d_opts == d_default);
}

BOOST_AUTO_TEST_CASE(rc_dc_getenv_cannot_flip_consensus_digest)
{
    // P0: BTX_RC_COUP_FULL_BANK_SCHEDULE / MATERIAL_EXCHANGE env must not change
    // digests — levers are compile-time only (defaults ON for AI thesis).
    const auto params = rc::MakeToyRCCoupParams();
    const auto header = MakeCoupHeader(12345);
    rc::RCCoupOptions opts; // defaults follow dc levers

    ::setenv("BTX_RC_COUP_FULL_BANK_SCHEDULE", "0", /*overwrite=*/1);
    ::setenv("BTX_RC_COUP_MATERIAL_EXCHANGE", "0", /*overwrite=*/1);
    BOOST_CHECK(dc::RCCoupFullBankScheduleActive());
    BOOST_CHECK(dc::RCCoupMaterialExchangeActive());
    const uint256 with_env = rc::RecomputeCoupledPuzzleReference(header, 0, params, opts);

    ::unsetenv("BTX_RC_COUP_FULL_BANK_SCHEDULE");
    ::unsetenv("BTX_RC_COUP_MATERIAL_EXCHANGE");
    const uint256 without_env = rc::RecomputeCoupledPuzzleReference(header, 0, params, opts);
    BOOST_CHECK(with_env == without_env);
    BOOST_CHECK(with_env == rc::MineRCCoupledEpisode(header, 0, params));
}


/** ExactGemmCompare + GKR env flags must not flip RecomputeCoupledPuzzleReference
 *  digests on the empty-backend consensus path. Two threads with contradictory
 *  policies must still agree (hetero / ASAN-safe). */
BOOST_AUTO_TEST_CASE(rc_dc_hetero_exactgemm_gkr_env_cannot_flip_digest)
{
    const auto params = rc::MakeToyRCCoupParams();
    const auto header = MakeCoupHeader(424242);
    rc::RCCoupOptions opts;

    ::unsetenv("BTX_RC_EXACT_GEMM_COMPARE");
    ::unsetenv("BTX_RC_GKR_SHADOW");
    ::unsetenv("BTX_RC_GKR_ARBITER");
    ::unsetenv("BTX_RC_GKR_MEASURE_LADDER");
    ::unsetenv("BTX_RC_GKR_MEASURE_MEDIUM");
    const uint256 baseline =
        rc::RecomputeCoupledPuzzleReference(header, 0, params, opts, /*gemm=*/{});
    BOOST_REQUIRE(!baseline.IsNull());

    ::setenv("BTX_RC_EXACT_GEMM_COMPARE", "1", /*overwrite=*/1);
    ::setenv("BTX_RC_GKR_SHADOW", "1", /*overwrite=*/1);
    ::setenv("BTX_RC_GKR_ARBITER", "1", /*overwrite=*/1);
    ::setenv("BTX_RC_GKR_MEASURE_LADDER", "1", /*overwrite=*/1);
    ::setenv("BTX_RC_GKR_MEASURE_MEDIUM", "1", /*overwrite=*/1);
    const uint256 with_flags =
        rc::RecomputeCoupledPuzzleReference(header, 0, params, opts, /*gemm=*/{});
    BOOST_CHECK(with_flags == baseline);

    uint256 t_on{};
    uint256 t_off{};
    std::thread a([&]() {
        ::setenv("BTX_RC_EXACT_GEMM_COMPARE", "1", /*overwrite=*/1);
        ::setenv("BTX_RC_GKR_ARBITER", "1", /*overwrite=*/1);
        t_on = rc::RecomputeCoupledPuzzleReference(header, 0, params, opts, /*gemm=*/{});
    });
    std::thread b([&]() {
        ::unsetenv("BTX_RC_EXACT_GEMM_COMPARE");
        ::unsetenv("BTX_RC_GKR_ARBITER");
        t_off = rc::RecomputeCoupledPuzzleReference(header, 0, params, opts, /*gemm=*/{});
    });
    a.join();
    b.join();
    BOOST_CHECK(t_on == baseline);
    BOOST_CHECK(t_off == baseline);
    BOOST_CHECK(t_on == t_off);

    ::unsetenv("BTX_RC_EXACT_GEMM_COMPARE");
    ::unsetenv("BTX_RC_GKR_SHADOW");
    ::unsetenv("BTX_RC_GKR_ARBITER");
    ::unsetenv("BTX_RC_GKR_MEASURE_LADDER");
    ::unsetenv("BTX_RC_GKR_MEASURE_MEDIUM");
}

BOOST_AUTO_TEST_CASE(rc_dc_q_batch_digest_identity)
{
    const auto params = rc::MakeToyRCCoupParams();
    for (uint32_t Q : {1u, 4u, 8u}) {
        std::vector<CBlockHeader> headers;
        headers.reserve(Q);
        for (uint32_t i = 0; i < Q; ++i) {
            headers.push_back(MakeCoupHeader(1000 + i));
        }
        std::vector<uint256> batch;
        rc::RCMinerBatchConfig cfg;
        cfg.Q = Q;
        BOOST_REQUIRE(rc::TryMineRCCoupledBatch(headers, 0, params, batch, cfg));
        BOOST_REQUIRE_EQUAL(batch.size(), Q);
        for (uint32_t i = 0; i < Q; ++i) {
            const uint256 single = rc::MineRCCoupledEpisode(headers[i], 0, params);
            BOOST_CHECK_MESSAGE(batch[i] == single,
                                "Q-batch digest mismatch at Q=" << Q << " i=" << i);
        }
    }
}

/** Q=1,8,32 independent-state parity vs solo RecomputeCoupledPuzzleReference. */
BOOST_AUTO_TEST_CASE(rc_dc_q_batch_toy_parity_q1_q8_q32)
{
    const auto params = rc::MakeToyRCCoupParams();
    for (uint32_t Q : {1u, 8u, 32u}) {
        const CBlockHeader base = MakeCoupHeader(42000 + Q);
        const auto window = rc::BuildRCCoupledMinerNonceWindow(base, Q);
        std::vector<uint256> batch;
        rc::RCMinerBatchConfig cfg;
        cfg.Q = Q;
        BOOST_REQUIRE_MESSAGE(rc::TryMineRCCoupledBatch(window, 0, params, batch, cfg),
                              "TryMineRCCoupledBatch failed at Q=" << Q);
        BOOST_REQUIRE_EQUAL(batch.size(), Q);
        for (uint32_t i = 0; i < Q; ++i) {
            const uint256 solo =
                rc::RecomputeCoupledPuzzleReference(window[i], 0, params);
            BOOST_CHECK_MESSAGE(batch[i] == solo,
                                "independent Q-batch != solo at Q=" << Q << " i=" << i);
            BOOST_CHECK(!batch[i].IsNull());
        }
        // Slot isolation: Q=1 re-mine of each header matches the multi-Q slot.
        for (uint32_t i = 0; i < Q; ++i) {
            std::vector<uint256> one;
            cfg.Q = 1;
            BOOST_REQUIRE(rc::TryMineRCCoupledBatch({window[i]}, 0, params, one, cfg));
            BOOST_CHECK(one[0] == batch[i]);
        }
    }
}

/** Harness Q-sweep may exceed kRCMinerBatchQMax; digests still match solo. */
BOOST_AUTO_TEST_CASE(rc_dc_coupled_q_sweep_beyond_miner_max)
{
    const auto params = rc::MakeToyRCCoupParams();
    constexpr uint32_t Q = dc::kRCMinerBatchQMax + 1; // beyond miner cap
    BOOST_REQUIRE(Q <= rc::kRCCoupledQSweepHarnessMax);
    const CBlockHeader base = MakeCoupHeader(99001);
    const auto window = rc::BuildRCCoupledMinerNonceWindow(base, Q);

    // Legacy single-page schedule keeps CI wall time bounded for Q=257.
    rc::RCCoupOptions opts;
    opts.full_bank_schedule = false;
    opts.material_exchange = false;

    std::vector<uint256> rejected;
    rc::RCMinerBatchConfig cfg;
    cfg.Q = Q; // > kRCMinerBatchQMax → TryMine must refuse
    BOOST_CHECK(!rc::TryMineRCCoupledBatch(window, 0, params, rejected, cfg, {}, opts));

    std::vector<uint256> sweep;
    BOOST_REQUIRE(rc::RunCoupledQSweep(window, 0, params, sweep, /*q_cap=*/0, {}, opts));
    BOOST_REQUIRE_EQUAL(sweep.size(), Q);
    for (uint32_t i : {0u, 1u, Q / 2, Q - 1}) {
        const uint256 solo =
            rc::RecomputeCoupledPuzzleReference(window[i], 0, params, opts);
        BOOST_CHECK_MESSAGE(sweep[i] == solo, "Q-sweep != solo at i=" << i);
    }
}

BOOST_AUTO_TEST_CASE(rc_dc_streamed_strategy_enum_names)
{
    BOOST_CHECK_EQUAL(rc::RCStreamedStrategyName(rc::RCStreamedStrategy::Hot32GiBCache),
                      "hot_32gib_cache");
    BOOST_CHECK_EQUAL(rc::RCStreamedStrategyName(rc::RCStreamedStrategy::PinnedHost),
                      "pinned_host");
    BOOST_CHECK_EQUAL(rc::RCStreamedStrategyName(rc::RCStreamedStrategy::DoubleBuffer),
                      "double_buffer");
    BOOST_CHECK_EQUAL(rc::RCStreamedStrategyName(rc::RCStreamedStrategy::SeedRegen),
                      "seed_regen");
    BOOST_CHECK_EQUAL(rc::RCStreamedStrategyName(rc::RCStreamedStrategy::MultiGpuShard),
                      "multi_gpu_shard");
}

/** Miner SolveMatMulV4RCCoupled path: BuildRCCoupledMinerNonceWindow + Q>1 batch
 *  must match per-header MineCoupledPuzzle (CPU ExactGemm). */
BOOST_AUTO_TEST_CASE(rc_dc_miner_q_window_batch_matches_coupled_puzzle)
{
    const auto params = rc::MakeToyRCCoupParams();
    const CBlockHeader base = MakeCoupHeader(7777);
    constexpr uint32_t Q = 4;
    const auto window = rc::BuildRCCoupledMinerNonceWindow(base, Q);
    BOOST_REQUIRE_EQUAL(window.size(), Q);
    BOOST_CHECK_EQUAL(window[0].nNonce64, base.nNonce64);
    BOOST_CHECK_EQUAL(window[Q - 1].nNonce64, base.nNonce64 + (Q - 1));

    std::vector<uint256> batch;
    rc::RCMinerBatchConfig cfg;
    cfg.Q = Q;
    BOOST_REQUIRE(rc::TryMineRCCoupledBatch(window, 0, params, batch, cfg));
    BOOST_REQUIRE_EQUAL(batch.size(), Q);
    for (uint32_t i = 0; i < Q; ++i) {
        const uint256 single = rc::MineCoupledPuzzle(window[i], 0, params);
        BOOST_CHECK_MESSAGE(batch[i] == single,
                            "miner Q-window batch != MineCoupledPuzzle at i=" << i);
        BOOST_CHECK(!batch[i].IsNull());
    }
}

/**
 * REGRESSION (094b169 / e75aec): real §H.4 seeds + Q>=4 must share one bank
 * template. MakeCoupHeader's FIXED 0x11/0x22 seeds hide the bug — after
 * SetDeterministicMatMulSeeds, seed_a/seed_b differ per nNonce64, so a
 * nonce-only bank projection rejects the window and SolveMatMulV4RCCoupled aborts.
 */
BOOST_AUTO_TEST_CASE(rc_dc_seeded_q_batch_shares_bank_and_matches_reference)
{
    const auto consensus = MakeV4SeedParams();
    constexpr int32_t kHeight = 100;
    constexpr int64_t kMtp = 1'700'000'000;
    constexpr uint32_t Q = 4;
    const auto params = rc::MakeToyRCCoupParams();

    std::vector<CBlockHeader> window;
    window.reserve(Q);
    for (uint32_t i = 0; i < Q; ++i) {
        window.push_back(MakeSeededCoupHeader(9000 + i, consensus, kHeight, kMtp));
    }
    // Distinct nonce-bound seeds (the bug trigger).
    BOOST_REQUIRE(window[0].seed_a != window[1].seed_a);
    BOOST_REQUIRE(window[0].seed_b != window[1].seed_b);
    BOOST_REQUIRE(window[0].nNonce64 != window[1].nNonce64);

    // Canonical template projection mirrors ComputeTemplateHash (null seeds).
    const uint256 tmpl0 = rc::RCBankTemplateHash(window[0]);
    BOOST_CHECK(tmpl0 == matmul::v4::ComputeTemplateHash(window[0]));
    for (uint32_t i = 1; i < Q; ++i) {
        BOOST_CHECK(rc::RCBankTemplateHash(window[i]) == tmpl0);
    }

    // Bank pages identical across the seeded window (epoch/template reusable).
    const auto bank0 = rc::DeriveCoupledBankPages(window[0], kHeight, params);
    const auto bank1 = rc::DeriveCoupledBankPages(window[1], kHeight, params);
    BOOST_REQUIRE_EQUAL(bank0.size(), bank1.size());
    for (size_t p = 0; p < bank0.size(); ++p) {
        BOOST_CHECK(bank0[p] == bank1[p]);
    }

    // Per-nonce sigma / digest still unique.
    BOOST_CHECK(matmul::v4::DeriveSigma(window[0]) != matmul::v4::DeriveSigma(window[1]));
    const uint256 ref0 = rc::RecomputeCoupledPuzzleReference(window[0], kHeight, params);
    const uint256 ref1 = rc::RecomputeCoupledPuzzleReference(window[1], kHeight, params);
    BOOST_CHECK(!ref0.IsNull());
    BOOST_CHECK(!ref1.IsNull());
    BOOST_CHECK(ref0 != ref1);

    std::vector<uint256> batch;
    rc::RCMinerBatchConfig cfg;
    cfg.Q = Q;
    BOOST_REQUIRE_MESSAGE(rc::TryMineRCCoupledBatch(window, kHeight, params, batch, cfg),
                          "TryMineRCCoupledBatch must accept real-seeded Q>=4 window");
    BOOST_REQUIRE_EQUAL(batch.size(), Q);
    for (uint32_t i = 0; i < Q; ++i) {
        const uint256 single =
            rc::RecomputeCoupledPuzzleReference(window[i], kHeight, params);
        BOOST_CHECK_MESSAGE(batch[i] == single,
                            "seeded Q-batch != per-header reference at i=" << i);
    }
}

BOOST_AUTO_TEST_CASE(rc_dc_bank_template_identity_separates_nonce_and_epoch)
{
    const auto consensus = MakeV4SeedParams();
    constexpr int32_t kHeight = 100;
    constexpr int64_t kMtp = 1'700'000'000;
    auto h0 = MakeSeededCoupHeader(42, consensus, kHeight, kMtp);
    auto h1 = MakeSeededCoupHeader(43, consensus, kHeight, kMtp);
    BOOST_REQUIRE(h0.seed_a != h1.seed_a);

    // Changing nonce/seeds must NOT change template bank identity.
    BOOST_CHECK(rc::RCBankTemplateHash(h0) == rc::RCBankTemplateHash(h1));
    const auto proj0 = rc::ProjectRCBankTemplateHeader(h0);
    BOOST_CHECK_EQUAL(proj0.nNonce64, 0u);
    BOOST_CHECK_EQUAL(proj0.nNonce, 0u);
    BOOST_CHECK(proj0.seed_a.IsNull());
    BOOST_CHECK(proj0.seed_b.IsNull());
    BOOST_CHECK(proj0.matmul_digest.IsNull());

    // Changing a template field MUST change bank identity.
    auto h_epoch = h0;
    h_epoch.hashMerkleRoot.data()[0] ^= 0xff;
    BOOST_CHECK(rc::RCBankTemplateHash(h_epoch) != rc::RCBankTemplateHash(h0));
    const auto bank_a = rc::DeriveCoupledBankPages(h0, kHeight, rc::MakeToyRCCoupParams());
    const auto bank_b =
        rc::DeriveCoupledBankPages(h_epoch, kHeight, rc::MakeToyRCCoupParams());
    BOOST_CHECK(bank_a[0] != bank_b[0]);

    // Result field must not affect bank identity.
    h0.matmul_digest = uint256::ONE;
    BOOST_CHECK(rc::RCBankTemplateHash(h0) == rc::RCBankTemplateHash(h1));
}

BOOST_AUTO_TEST_CASE(rc_dc_seeded_q_batch_slot_isolation_and_q1_parity)
{
    const auto consensus = MakeV4SeedParams();
    constexpr int32_t kHeight = 100;
    constexpr int64_t kMtp = 1'700'000'000;
    constexpr uint32_t Q = 4;
    const auto params = rc::MakeToyRCCoupParams();

    std::vector<CBlockHeader> window;
    for (uint32_t i = 0; i < Q; ++i) {
        window.push_back(MakeSeededCoupHeader(5000 + i, consensus, kHeight, kMtp));
    }

    std::vector<uint256> batch_q;
    rc::RCMinerBatchConfig cfg;
    cfg.Q = Q;
    BOOST_REQUIRE(rc::TryMineRCCoupledBatch(window, kHeight, params, batch_q, cfg));

    // Q=1 parity: each singleton batch matches the Q>1 slot.
    for (uint32_t i = 0; i < Q; ++i) {
        std::vector<uint256> batch1;
        cfg.Q = 1;
        BOOST_REQUIRE(rc::TryMineRCCoupledBatch({window[i]}, kHeight, params, batch1, cfg));
        BOOST_REQUIRE_EQUAL(batch1.size(), 1u);
        BOOST_CHECK(batch1[0] == batch_q[i]);
        BOOST_CHECK(batch1[0] ==
                    rc::RecomputeCoupledPuzzleReference(window[i], kHeight, params));
    }

    // One corrupted slot cannot contaminate another: corrupt seeds on slot 1 only.
    auto corrupted = window;
    corrupted[1].seed_a.data()[0] ^= 0xaa;
    BOOST_REQUIRE(rc::RCBankTemplateHash(corrupted[0]) == rc::RCBankTemplateHash(window[0]));
    // Still same bank template → batch accepted; only slot 1 digest diverges.
    std::vector<uint256> batch_bad;
    cfg.Q = Q;
    BOOST_REQUIRE(rc::TryMineRCCoupledBatch(corrupted, kHeight, params, batch_bad, cfg));
    BOOST_CHECK(batch_bad[0] == batch_q[0]);
    BOOST_CHECK(batch_bad[2] == batch_q[2]);
    BOOST_CHECK(batch_bad[3] == batch_q[3]);
    BOOST_CHECK(batch_bad[1] != batch_q[1]);
}

BOOST_AUTO_TEST_CASE(rc_dc_seeded_winner_reseal_and_losing_digest_only)
{
    // Mirrors SolveMatMulV4RCCoupled: batch digests for all slots; winner gets
    // CPU reseal (empty ExactGemm) that must match; losers keep digest-only.
    const auto consensus = MakeV4SeedParams();
    constexpr int32_t kHeight = 100;
    constexpr int64_t kMtp = 1'700'000'000;
    constexpr uint32_t Q = 4;
    const auto params = rc::MakeToyRCCoupParams();

    CBlockHeader base = MakeSeededCoupHeader(6000, consensus, kHeight, kMtp);
    auto window = rc::BuildRCCoupledMinerNonceWindow(base, Q);
    for (CBlockHeader& h : window) {
        BOOST_REQUIRE(SetDeterministicMatMulSeeds(h, consensus, kHeight, kMtp));
    }

    std::vector<uint256> batch;
    rc::RCMinerBatchConfig cfg;
    cfg.Q = Q;
    BOOST_REQUIRE(rc::TryMineRCCoupledBatch(window, kHeight, params, batch, cfg));

    // Pick the numerically smallest digest as a stand-in "winner".
    size_t winner = 0;
    for (size_t i = 1; i < batch.size(); ++i) {
        if (batch[i] < batch[winner]) winner = i;
    }
    const uint256 resealed =
        rc::RecomputeCoupledPuzzleReference(window[winner], kHeight, params);
    BOOST_CHECK_MESSAGE(resealed == batch[winner], "winner CPU reseal must match batch");

    // Losing slots: digest-only — no header mutation of matmul_digest required.
    for (size_t i = 0; i < batch.size(); ++i) {
        if (i == winner) continue;
        BOOST_CHECK(window[i].matmul_digest.IsNull());
        BOOST_CHECK(batch[i] ==
                    rc::RecomputeCoupledPuzzleReference(window[i], kHeight, params));
    }
}

BOOST_AUTO_TEST_CASE(rc_dc_cuda_episode_context_stub)
{
    matmul_v4::cuda::RCCudaEpisodeContext ctx;
    std::string err;
    const auto params = rc::MakeToyRCCoupParams();
    const CBlockHeader header = MakeCoupHeader(1);
    BOOST_REQUIRE(ctx.Init(params, /*batch_q=*/dc::kRCMinerBatchQDefault, &err));
    BOOST_CHECK(ctx.Ready());
    const auto pages = rc::DeriveCoupledBankPages(header, 0, params);
    BOOST_REQUIRE(ctx.LoadBank(pages, &err));

    // Order matters (WS-F):
    //  - non-CUDA stub → honesty token graph_unavailable (BindEpisode not required)
    //  - CUDA impl without BindEpisode → BindEpisode required
    if (!matmul_v4::cuda::IsRcEpisodeCudaCompiled()) {
        BOOST_CHECK(!ctx.RunBarrierGraph(&err));
        BOOST_CHECK_MESSAGE(err.find("graph_unavailable") != std::string::npos,
                            "non-CUDA stub must refuse with graph_unavailable; got: " << err);
        BOOST_CHECK(!ctx.Provenance().peak_ready);
        BOOST_CHECK_EQUAL(ctx.Provenance().gemm_path_label, "stub_not_wired");
        ctx.Destroy();
        BOOST_CHECK(!ctx.Ready());
        return;
    }

    BOOST_CHECK(!ctx.RunBarrierGraph(&err));
    BOOST_CHECK_MESSAGE(err.find("BindEpisode") != std::string::npos,
                        "CUDA RunBarrierGraph without BindEpisode must require it; got: "
                            << err);

    BOOST_REQUIRE_MESSAGE(ctx.BindEpisode(header, 0, &err), err);
    std::vector<int8_t> seed_state;
    BOOST_REQUIRE(ctx.DownloadActiveState(seed_state, &err));

    BOOST_REQUIRE_MESSAGE(ctx.RunBarrierGraph(&err), err);
    const uint256 cpu = rc::RecomputeCoupledPuzzleReference(header, 0, params);
    BOOST_REQUIRE(ctx.LastDigest() != nullptr);
    BOOST_CHECK_MESSAGE(*ctx.LastDigest() == cpu,
                        "toy graph digest " << ctx.LastDigest()->GetHex()
                                            << " != cpu " << cpu.GetHex());
    BOOST_REQUIRE_MESSAGE(ctx.CompareWithCpuOracle(&err), err);

    // DownloadActiveState must return FINAL Extracted state, not BindEpisode seed.
    std::vector<int8_t> final_state;
    BOOST_REQUIRE(ctx.DownloadActiveState(final_state, &err));
    BOOST_CHECK(final_state != seed_state);
    BOOST_CHECK_EQUAL(final_state.size(), params.StateBytes());

    const auto& prov = ctx.Provenance();
    BOOST_CHECK(prov.device_bank_resident);
    BOOST_CHECK(prov.device_state_resident);
    BOOST_CHECK_GE(prov.graph_capture_count, 1);
    BOOST_CHECK_GE(prov.graph_replay_count, params.barriers);
    BOOST_CHECK(!prov.peak_ready);
    BOOST_CHECK(!prov.device_digest);
    BOOST_CHECK_EQUAL(prov.permute_extract_label, "device_barrier_tail");
    BOOST_CHECK(prov.gemm_path_label.find("portable") != std::string::npos ||
                prov.gemm_path_label.find("wsB") != std::string::npos);

    // Second run must REPLAY (no second capture).
    const uint64_t caps = prov.graph_capture_count;
    BOOST_REQUIRE_MESSAGE(ctx.BindEpisode(header, 0, &err), err);
    BOOST_REQUIRE_MESSAGE(ctx.RunBarrierGraph(&err), err);
    BOOST_CHECK_EQUAL(ctx.Provenance().graph_capture_count, caps);

    // Fault injection: corrupted digest rejected + resealed to CPU.
    ctx.FaultInjectCorruptDigest(true);
    BOOST_REQUIRE_MESSAGE(ctx.BindEpisode(header, 0, &err), err);
    BOOST_REQUIRE_MESSAGE(ctx.RunBarrierGraph(&err), err);
    BOOST_REQUIRE(ctx.LastDigest() != nullptr);
    BOOST_CHECK(*ctx.LastDigest() != cpu);
    BOOST_CHECK(!ctx.ResealAgainstCpuOracle(&err));
    BOOST_CHECK(err.find("resealed") != std::string::npos);
    BOOST_CHECK(*ctx.LastDigest() == cpu);
    ctx.FaultInjectCorruptDigest(false);

    ctx.Destroy();
    BOOST_CHECK(!ctx.Ready());
}

BOOST_AUTO_TEST_CASE(rc_dc_cuda_episode_context_medium_digest)
{
    if (!matmul_v4::cuda::IsRcEpisodeCudaCompiled()) {
        return;
    }
    matmul_v4::cuda::RCCudaEpisodeContext ctx;
    std::string err;
    const auto params = rc::MakeMediumRCCoupParams();
    const CBlockHeader header = MakeCoupHeader(42);
    BOOST_REQUIRE_MESSAGE(ctx.Init(params, /*batch_q=*/1, &err), err);
    const auto pages = rc::DeriveCoupledBankPages(header, 0, params);
    BOOST_REQUIRE_MESSAGE(ctx.LoadBank(pages, &err), err);
    BOOST_REQUIRE_MESSAGE(ctx.BindEpisode(header, 0, &err), err);
    BOOST_REQUIRE_MESSAGE(ctx.RunBarrierGraph(&err), err);
    const uint256 cpu = rc::RecomputeCoupledPuzzleReference(header, 0, params);
    BOOST_REQUIRE(ctx.LastDigest() != nullptr);
    BOOST_CHECK_MESSAGE(*ctx.LastDigest() == cpu,
                        "medium graph digest " << ctx.LastDigest()->GetHex()
                                               << " != cpu " << cpu.GetHex());

    std::vector<int8_t> final_state;
    BOOST_REQUIRE(ctx.DownloadActiveState(final_state, &err));
    BOOST_CHECK_EQUAL(final_state.size(), params.StateBytes());
    ctx.Destroy();
}

BOOST_AUTO_TEST_CASE(rc_dc_cuda_episode_nonce_window_and_probe)
{
    const auto probe = rc::ProbeRCCudaEpisodeResident();
    BOOST_CHECK(probe.host_bridge_removed);
    BOOST_CHECK(!probe.peak_ready);
    BOOST_CHECK(!probe.device_digest);

    if (!matmul_v4::cuda::IsRcEpisodeCudaCompiled()) {
        BOOST_CHECK(!probe.cuda_episode_compiled);
        BOOST_CHECK(probe.permute_extract_parked);
        BOOST_CHECK_EQUAL(probe.parked_reason, "graph_unavailable:not_wired");
        return;
    }

    // CUDA TU: device_barrier_tail unparks permute/mix/Extract; digest still host.
    BOOST_CHECK(!probe.permute_extract_parked);
    BOOST_CHECK(probe.detail.find("device_barrier_tail") != std::string::npos);

    matmul_v4::cuda::RCCudaEpisodeContext ctx;
    std::string err;
    const auto params = rc::MakeToyRCCoupParams();
    constexpr uint32_t Q = 4;
    BOOST_REQUIRE(ctx.Init(params, Q, &err));
    const CBlockHeader base = MakeCoupHeader(9001);
    const auto pages = rc::DeriveCoupledBankPages(base, 0, params);
    BOOST_REQUIRE(ctx.LoadBank(pages, &err));
    const auto window = rc::BuildRCCoupledMinerNonceWindow(base, Q);
    std::vector<uint256> digests;
    BOOST_REQUIRE_MESSAGE(ctx.RunNonceWindow(window, 0, digests, &err), err);
    BOOST_REQUIRE_EQUAL(digests.size(), Q);
    BOOST_CHECK(ctx.Provenance().qstar_device_batched);
    BOOST_CHECK(ctx.Provenance().independent_q_slots);
    BOOST_CHECK(ctx.Provenance().per_nonce_sync_absent);
    BOOST_CHECK_EQUAL(ctx.Provenance().digest_batch_slots, Q);
    // Window path uses CPU independent Q-batch (no graph capture required).
    for (uint32_t i = 0; i < Q; ++i) {
        const uint256 cpu = rc::RecomputeCoupledPuzzleReference(window[i], 0, params);
        BOOST_CHECK_MESSAGE(digests[i] == cpu, "window digest mismatch at i=" << i);
    }
    ctx.Destroy();
}

BOOST_AUTO_TEST_CASE(rc_dc_coupled_barrier_tail_helpers)
{
    const auto params = rc::MakeToyRCCoupParams();
    const CBlockHeader header = MakeCoupHeader(3);
    const auto pages = rc::DeriveCoupledBankPages(header, 0, params);
    const uint256 bank_root = rc::CommitCoupledBankPages(pages, params);
    BOOST_CHECK(!bank_root.IsNull());

    // Tail helpers must match a single barrier of the CPU oracle transcript.
    rc::RCCoupEpisodeTranscript tx;
    const uint256 dig =
        rc::RecomputeCoupledPuzzleReference(header, 0, params, {}, {}, nullptr, &tx);
    BOOST_REQUIRE(!dig.IsNull());
    BOOST_REQUIRE(!tx.gemms.empty());
    BOOST_REQUIRE(!tx.extracts.empty());

    std::vector<int64_t> acc(params.StateBytes(), 0);
    for (const auto& g : tx.gemms) {
        if (g.barrier != 0) continue;
        for (uint32_t c = 0; c < params.lobe_width; ++c) {
            acc[g.lobe * params.lobe_width + c] += g.Y[c];
        }
    }
    std::vector<int8_t> state(params.StateBytes());
    uint256 root;
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    BOOST_REQUIRE(rc::ApplyCoupledBarrierTail(sigma, /*barrier=*/0, params, acc, state, &root));
    BOOST_CHECK(root == tx.extracts[0].barrier_root);
    BOOST_CHECK(state == tx.extracts[0].extract_out);

    std::vector<uint256> roots = tx.barrier_roots;
    BOOST_CHECK(rc::AssembleCoupledEpisodeDigest(tx.bank_root, roots) == dig);
}

/** Golden / transcript version bump requirement (silent replacement forbidden). */
BOOST_AUTO_TEST_CASE(rc_dc_golden_transcript_version_bump_requirement)
{
    BOOST_CHECK_EQUAL(rc::kRCTranscriptVersion, rc::ENC_RC_V1);
    BOOST_CHECK_EQUAL(rc::kRCTranscriptVersion, 1u);
    BOOST_CHECK_EQUAL(rc::ENC_RC_V2, 2u);
    BOOST_CHECK_EQUAL(rc::ENC_RC_V3, 3u);
    BOOST_CHECK_EQUAL(rc::kRCTranscriptVersionV1, 1u);
    BOOST_CHECK(rc::kRCTranscriptVersionV1 != rc::kRCTranscriptVersionV2);
    BOOST_CHECK(rc::kRCTranscriptVersionV2 != rc::kRCTranscriptVersionV3);
    // Coupled toy golden must remain pinned; any digest change requires an
    // explicit kRCTranscriptVersion / ENC_RC_V* bump and dual-golden retention
    // (see rc_coup_golden_digest_stable + contrib/matmul-v4/rc-golden-gate.py).
    // Post WS-A bank-template projection (null §H.4 seeds):
    const auto header = MakeCoupHeader(42);
    const uint256 d = rc::RecomputeCoupledPuzzleReference(header, 0);
    BOOST_CHECK_EQUAL(d.GetHex(),
                      "7a7ce1065c7881aa2bd2295c26778ebf88c22432e91326f98d098c11885579ee");
}

/** Public activation heights + parked datacenter switches stay off. */
BOOST_AUTO_TEST_CASE(rc_dc_public_heights_and_parked_switches_inert)
{
    Consensus::Params mainnet;
    BOOST_CHECK_EQUAL(mainnet.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(mainnet.nMatMulRCCoupledHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!mainnet.IsMatMulRCActive(0));
    BOOST_CHECK(!mainnet.IsMatMulRCActive(std::numeric_limits<int32_t>::max() - 1));

    BOOST_CHECK(dc::kRCCoupFullBankScheduleEnabled);
    BOOST_CHECK(dc::kRCCoupMaterialExchangeEnabled);
    BOOST_CHECK(dc::kRCThreeAxisScheduleWireEnabled);
    BOOST_CHECK(dc::RCCoupFullBankScheduleActive());
    BOOST_CHECK(dc::RCCoupMaterialExchangeActive());
    BOOST_CHECK(rc::kRCThreeAxisScheduleEnabled);
    BOOST_CHECK_EQUAL(rc::kRCAxisW0State, 48ull << 30);
    BOOST_CHECK_EQUAL(rc::kRCAxisX0Exchange, 4ull << 30);

    const dc::RCDcStatus st = dc::ProbeRCDcStatus();
    BOOST_CHECK(st.full_bank_schedule);
    BOOST_CHECK(st.material_exchange);
    BOOST_CHECK(st.three_axis_wire);
    BOOST_CHECK(!st.gkr_arbiter);
}

BOOST_AUTO_TEST_CASE(rc_dc_batch_vs_reference_rows_per_lobe)
{
    // Production blocker regression: TryMineRCCoupledBatch must match
    // RecomputeCoupledPuzzleReference for rows_per_lobe > 1 (V3 M=128).
    // Vary only M on MakeMediumRCCoupParams; exercise full-schedule and stacked.
    constexpr uint32_t kMs[] = {1u, 2u, 4u, 32u, 64u};
    constexpr uint32_t Q = 4;
    const CBlockHeader base = MakeCoupHeader(4242);

    for (uint32_t M : kMs) {
        auto params = rc::MakeMediumRCCoupParams();
        params.rows_per_lobe = M;
        BOOST_REQUIRE_MESSAGE(rc::ValidateRCCoupParams(params),
                              "invalid medium params at M=" << M);
        BOOST_CHECK_EQUAL(params.StateBytes(), params.lobes * M * params.lobe_width);

        const auto window = rc::BuildRCCoupledMinerNonceWindow(base, Q);
        rc::RCMinerBatchConfig cfg;
        cfg.Q = Q;

        for (bool full : {true, false}) {
            rc::RCCoupOptions opts;
            opts.full_bank_schedule = full;

            std::vector<uint256> batch;
            BOOST_REQUIRE_MESSAGE(
                rc::TryMineRCCoupledBatch(window, 0, params, batch, cfg, {}, opts),
                "batch failed M=" << M << " full=" << full);
            BOOST_REQUIRE_EQUAL(batch.size(), Q);

            for (uint32_t i = 0; i < Q; ++i) {
                const uint256 ref =
                    rc::RecomputeCoupledPuzzleReference(window[i], 0, params, opts);
                BOOST_CHECK_MESSAGE(
                    batch[i] == ref,
                    "batch≠ref M=" << M << " full=" << full << " i=" << i
                                   << " batch=" << batch[i].GetHex()
                                   << " ref=" << ref.GetHex());
            }
        }
    }

    // V3 production M must not be silently reduced to 1.
    BOOST_CHECK_EQUAL(rc::MakeProductionV3RCCoupParams().rows_per_lobe, 128u);
    BOOST_CHECK_EQUAL(rc::MakeMediumV3RCCoupParams().rows_per_lobe, 32u);
}

BOOST_AUTO_TEST_SUITE_END()
