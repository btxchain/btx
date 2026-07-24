// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chainparams.h>
#include <cuda/matmul_v4_rc_episode_context.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc.h>
#include <matmul/matmul_v4_rc_batch.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_datacenter.h>
#include <matmul/matmul_v4_rc_extract.h>
#include <matmul/matmul_v4_rc_freivalds_sampled.h>
#include <matmul/matmul_v4_rc_fri_ext3.h>
#include <matmul/matmul_v4_rc_gkr.h>
#include <matmul/matmul_v4_rc_scale_axes.h>
#include <matmul/matmul_v4_rc_streamed_strategy.h>
#include <matmul/matmul_v4_rc_transcript.h>
#include <node/matmul_verify_worker.h>

#include <common/args.h>
#include <consensus/params.h>
#include <matmul/matmul_v4_rc_scale.h>
#include <pow.h>
#include <util/chaintype.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <map>
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

/** F6: resident CUDA + stub MUST refuse rows_per_lobe != 1 (V3 M=128) rather
 *  than silently emit a wrong M=1 digest. */
BOOST_AUTO_TEST_CASE(rc_dc_cuda_episode_rows_per_lobe_gt1_fail_closed)
{
    matmul_v4::cuda::RCCudaEpisodeContext ctx;
    std::string err;
    auto params = rc::MakeToyRCCoupParams();
    params.rows_per_lobe = 128; // V3 production M
    BOOST_REQUIRE(rc::ValidateRCCoupParams(params));
    BOOST_CHECK(!ctx.Init(params, /*batch_q=*/1, &err));
    BOOST_CHECK_MESSAGE(err.find("rows_per_lobe") != std::string::npos,
                        "M>1 Init must fail-closed with rows_per_lobe reason; got: " << err);
    BOOST_CHECK(!ctx.Ready());

    // Medium V3 shape likewise refused.
    auto medium_v3 = rc::MakeMediumV3RCCoupParams();
    BOOST_REQUIRE_GE(medium_v3.rows_per_lobe, 2u);
    err.clear();
    BOOST_CHECK(!ctx.Init(medium_v3, /*batch_q=*/1, &err));
    BOOST_CHECK(err.find("rows_per_lobe") != std::string::npos);
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

// ---------------------------------------------------------------------------
// ENC_RC datacenter EPISODE PROFILE (nMatMulRCProfile==2 → MakeDatacenterRC…).
// Additive: profile 1 reproduces today's base params byte-for-byte; profile 2
// changes the fused-FFN datacenter profile axes. scratchpad/datacenter-episode-
// dimensions-design.md.
// ---------------------------------------------------------------------------

namespace {
bool RCEpisodeParamsEqual(const rc::RCEpisodeParams& a, const rc::RCEpisodeParams& b)
{
    return a.rounds == b.rounds && a.d_head == b.d_head && a.n_q == b.n_q &&
           a.n_ctx == b.n_ctx && a.L_lyr == b.L_lyr && a.d_model == b.d_model &&
           a.d_ff == b.d_ff && a.b_seq == b.b_seq && a.T_leaf == b.T_leaf;
}

CBlockHeader MakeDcRCHeader(uint64_t nonce)
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

// Consensus params that activate ENC_RC on a toy-dim, max-target regtest-like
// config at the given profile. Toy dims keep the episode CI-runnable; the profile
// selects the CONSENSUS AUTHORITY (1=ExactReplay, 2=Freivalds sampled).
Consensus::Params MakeRCActiveParams(uint32_t profile)
{
    Consensus::Params p;
    p.fMatMulPOW = true;
    p.nMatMulV4Height = 1;
    p.nMatMulRCHeight = 1;
    p.nMatMulRCProfile = profile;
    p.fMatMulRCUseToyDims = true;
    p.nMatMulV4Dimension = 256;
    p.powLimit = uint256{"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"};
    return p;
}
} // namespace

// (a) The datacenter dims are exactly the design's §3 proposal and pass the
//     structural validator + the epoch-0 int64/int32 accumulator invariants.
BOOST_AUTO_TEST_CASE(rc_dc_episode_datacenter_dims_valid)
{
    const rc::RCEpisodeParams dc = rc::MakeDatacenterRCEpisodeParams();
    BOOST_CHECK_EQUAL(dc.rounds, rc::kRCRoundsDC);
    BOOST_CHECK_EQUAL(dc.rounds, 8u);
    BOOST_CHECK_EQUAL(dc.L_lyr, rc::kRCLayersDC);
    BOOST_CHECK_EQUAL(dc.L_lyr, 24u);
    BOOST_CHECK_EQUAL(dc.b_seq, rc::kRCBatchSeqDC);
    BOOST_CHECK_EQUAL(dc.b_seq, 87552u);
    // Intensive dims held at epoch-0 values.
    BOOST_CHECK_EQUAL(dc.d_head, 128u);
    BOOST_CHECK_EQUAL(dc.n_q, 512u);
    BOOST_CHECK_EQUAL(dc.n_q, 4u * dc.d_head);
    BOOST_CHECK_EQUAL(dc.n_ctx, 786432u);
    BOOST_CHECK_EQUAL(dc.d_model, 4096u);
    BOOST_CHECK_EQUAL(dc.d_ff, 16384u);
    // T_leaf is RAISED for the datacenter profile (compute/hash margin lever,
    // aicompute-alignment-review.md §4) — 4× the epoch-0 1024.
    BOOST_CHECK_EQUAL(dc.T_leaf, rc::kRCTileLeafBytesDC);
    BOOST_CHECK_EQUAL(dc.T_leaf, 4096u);
    BOOST_CHECK(dc.T_leaf > rc::DefaultConsensusRCEpisodeParams().T_leaf);
    BOOST_CHECK(rc::ValidateRCEpisodeParams(dc));
}

BOOST_AUTO_TEST_CASE(rc_dc_x0_row_blocks_concat_byte_identical)
{
    const rc::RCEpisodeParams p = rc::MakeDatacenterRCEpisodeParams();
    BOOST_REQUIRE(rc::UseDatacenterRowBlockX0(p));
    BOOST_REQUIRE_EQUAL(p.b_seq % rc::kRCX0RowBlockRows, 0);
    uint256 seed_x0;
    for (size_t i = 0; i < 32; ++i) seed_x0.data()[i] = static_cast<unsigned char>(0x41 + i);

    const std::vector<int8_t> full = rc::ExpandX0ForEpisode(seed_x0, p);
    BOOST_REQUIRE_EQUAL(full.size(), static_cast<size_t>(p.b_seq) * p.d_model);
    const uint32_t n_blocks = p.b_seq / rc::kRCX0RowBlockRows;
    for (uint32_t b = 0; b < n_blocks; ++b) {
        const std::vector<int8_t> block = rc::ExpandX0RowBlockForEpisode(seed_x0, p, b);
        BOOST_REQUIRE_EQUAL(block.size(), static_cast<size_t>(rc::kRCX0RowBlockRows) * p.d_model);
        const auto first = full.begin() + static_cast<ptrdiff_t>(
                                            static_cast<size_t>(b) * rc::kRCX0RowBlockRows * p.d_model);
        BOOST_CHECK_EQUAL_COLLECTIONS(first, first + static_cast<ptrdiff_t>(block.size()),
                                      block.begin(), block.end());
    }
    for (uint32_t row : {0u, 31u, 32u, p.b_seq / 2u, p.b_seq - 1u}) {
        const std::vector<int8_t> one = rc::ExpandX0RowForEpisode(seed_x0, p, row);
        BOOST_REQUIRE_EQUAL(one.size(), p.d_model);
        const auto first = full.begin() + static_cast<ptrdiff_t>(static_cast<size_t>(row) * p.d_model);
        BOOST_CHECK_EQUAL_COLLECTIONS(first, first + static_cast<ptrdiff_t>(p.d_model),
                                      one.begin(), one.end());
    }
}

// (b) TotalRCEpisodeMacs(datacenter) equals the fused profile's absolute
//     2.257e15 MAC figure (4.514e15 FLOP). With base d_ff=4·d_model and the
//     datacenter b_seq lever raised to 87552, this is the exact 16422/1027 ratio.
BOOST_AUTO_TEST_CASE(rc_dc_episode_datacenter_mac_ratio)
{
    const uint64_t base_macs = rc::TotalRCEpisodeMacs(rc::DefaultConsensusRCEpisodeParams());
    const uint64_t dc_macs = rc::TotalRCEpisodeMacs(rc::MakeDatacenterRCEpisodeParams());
    BOOST_CHECK_EQUAL(base_macs, 141149805215744ull);  // 1.41e14
    BOOST_CHECK_EQUAL(dc_macs, 2257022493917184ull);   // 2.257e15
    const double ratio = static_cast<double>(dc_macs) / static_cast<double>(base_macs);
    BOOST_TEST_MESSAGE("fused datacenter/base MAC ratio: " << ratio);
    BOOST_CHECK_GT(ratio, 15.9);
    BOOST_CHECK_LT(ratio, 16.0);
    BOOST_CHECK_EQUAL(dc_macs / 137438953472ull, 16422ull); // 2^37 factor
    BOOST_CHECK_EQUAL(base_macs / 137438953472ull, 1027ull);
    // FLOP = 2× MAC.
    BOOST_CHECK_EQUAL(2ull * dc_macs, 4514044987834368ull); // 4.514e15
}

// (c) ADDITIVE GUARD: profile 1 (default) resolver output is byte-identical to
//     today's DefaultConsensusRCEpisodeParams(), and datacenter differs ONLY in
//     rounds/L_lyr/b_seq.
BOOST_AUTO_TEST_CASE(rc_dc_episode_profile1_byte_identical_guard)
{
    const rc::RCEpisodeParams base = rc::DefaultConsensusRCEpisodeParams();

    // Profile 1 stays AVAILABLE and byte-identical to the pre-datacenter base
    // (the network-wide default is now profile 2 — datacenter — so select 1
    // explicitly here).
    Consensus::Params p1;
    p1.nMatMulRCProfile = 1;
    const rc::RCEpisodeParams r1 = rc::ResolveRCEpisodeParams(p1, /*height=*/0);
    BOOST_CHECK_MESSAGE(RCEpisodeParamsEqual(r1, base),
                        "profile-1 resolver must reproduce base params byte-for-byte");

    // Datacenter holds most intensive GEMM dims at base, changes the fused profile
    // axes, and raises T_leaf (compute/hash margin lever, §4).
    const rc::RCEpisodeParams dc = rc::MakeDatacenterRCEpisodeParams();
    BOOST_CHECK_EQUAL(dc.d_head, base.d_head);
    BOOST_CHECK_EQUAL(dc.n_q, base.n_q);
    BOOST_CHECK_EQUAL(dc.n_ctx, base.n_ctx);   // n_ctx guardrail: never grows (§4)
    BOOST_CHECK_EQUAL(dc.d_model, base.d_model);
    BOOST_CHECK_EQUAL(dc.d_ff, base.d_ff);
    BOOST_CHECK(dc.T_leaf > base.T_leaf);      // raised, not held
    BOOST_CHECK(dc.rounds != base.rounds);
    BOOST_CHECK(dc.L_lyr != base.L_lyr);
    BOOST_CHECK(dc.b_seq != base.b_seq);
    BOOST_CHECK(!RCEpisodeParamsEqual(dc, base));
}

// (d) The profile selector is 1|2; the DEFAULT is now 2 (datacenter — owner-
//     authorized aggressive activation). Mainnet SELECTS profile 2 but keeps the
//     ACTIVATION height at INT32_MAX (gated on the no-inversion ratification).
BOOST_AUTO_TEST_CASE(rc_dc_episode_profile_selector_default_and_mainnet)
{
    Consensus::Params def;
    BOOST_CHECK_EQUAL(def.nMatMulRCProfile, 2u);  // datacenter is the default

    const auto main =
        CreateChainParams(ArgsManager{}, ChainType::MAIN)->GetConsensus();
    BOOST_CHECK_EQUAL(main.nMatMulRCProfile, 2u);
    // Height stays INT32_MAX: the datacenter profile is SELECTED but not ACTIVE
    // (finite public height rides BTX_MATMUL_NO_INVERSION_GATE_RATIFIED).
    BOOST_CHECK_EQUAL(main.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!main.IsMatMulRCActive(0));
    // Profile 2 resolves to the datacenter dims via the generic resolver.
    BOOST_CHECK(RCEpisodeParamsEqual(rc::ResolveRCEpisodeParams(main, 0),
                                     rc::MakeDatacenterRCEpisodeParams()));

    // Profile 1 remains available and resolves to the epoch-0 base dims.
    Consensus::Params base_params;
    base_params.nMatMulRCProfile = 1;
    BOOST_CHECK(RCEpisodeParamsEqual(rc::ResolveRCEpisodeParams(base_params, 0),
                                     rc::DefaultConsensusRCEpisodeParams()));

    // Toy dims still win over the profile on regtest (CI-scale mining).
    Consensus::Params dc_params;
    dc_params.nMatMulRCProfile = 2;
    dc_params.fMatMulRCUseToyDims = true;
    BOOST_CHECK(RCEpisodeParamsEqual(rc::ResolveRCEpisodeParams(dc_params, 0),
                                     rc::MakeToyRCEpisodeParams()));
}

// (e) REGTEST ACTIVATION: -regtestrcprofile=2 + a finite -regtestrcheight makes
//     the resolved episode the datacenter dims, and the RC family activates at
//     that height (mirrors rc_coup_unified_height_switch).
BOOST_AUTO_TEST_CASE(rc_dc_episode_regtest_profile2_activation)
{
    ArgsManager args;
    args.ForceSetArg("-regtestrcprofile", "2");
    args.ForceSetArg("-regtestrcheight", "150");
    const auto reg = CreateChainParams(args, ChainType::REGTEST)->GetConsensus();
    BOOST_CHECK_EQUAL(reg.nMatMulRCProfile, 2u);
    BOOST_CHECK_EQUAL(reg.nMatMulRCHeight, 150);

    // Predicate flips on at the height (and not before).
    BOOST_CHECK(!reg.IsMatMulRCActive(149));
    BOOST_CHECK(reg.IsMatMulRCActive(150));

    // At/after the height the resolved episode is the datacenter shape.
    const rc::RCEpisodeParams dc = rc::MakeDatacenterRCEpisodeParams();
    BOOST_CHECK(RCEpisodeParamsEqual(rc::ResolveRCEpisodeParams(reg, 150), dc));
    BOOST_CHECK(RCEpisodeParamsEqual(rc::ResolveRCEpisodeParams(reg, 5000), dc));

    // Regtest activation also couples the exact 16422/1027 ASERT loosen to the
    // datacenter profile + finite height (design §5).
    BOOST_CHECK_EQUAL(reg.nMatMulRCAsertRescaleNum, 16422);
    BOOST_CHECK_EQUAL(reg.nMatMulRCAsertRescaleDen, 1027);

    // Default regtest (no override) keeps the network-wide default profile 2 but
    // the RC family stays OFF (height INT32_MAX), so nothing activates.
    const auto reg_def =
        CreateChainParams(ArgsManager{}, ChainType::REGTEST)->GetConsensus();
    BOOST_CHECK_EQUAL(reg_def.nMatMulRCProfile, 2u);
    BOOST_CHECK_EQUAL(reg_def.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!reg_def.IsMatMulRCActive(0));
    // ASERT stays 1/1 while the height is INT32_MAX (coupled 16× applies only with
    // a finite activation height).
    BOOST_CHECK_EQUAL(reg_def.nMatMulRCAsertRescaleNum, 1);
    BOOST_CHECK_EQUAL(reg_def.nMatMulRCAsertRescaleDen, 1);
}

// ---------------------------------------------------------------------------
// CONSENSUS AUTHORITY CUTOVER (pow.cpp CheckMatMulProofOfWork_RC).
//   profile 2 → Freivalds sampled verifier is the accept/reject authority,
//     fail-closed if the episode proof is unavailable.
//   profile 1 → VerifyBoundedExactReplay, unchanged (no proof required).
// ---------------------------------------------------------------------------

// (c) Profile 2: ACCEPT an honest episode via the Freivalds path; REJECT when no
//     proof is stored (fail-closed); REJECT a tampered sampled layer.
BOOST_AUTO_TEST_CASE(rc_dc_authority_profile2_freivalds_accept_reject)
{
    Consensus::Params p = MakeRCActiveParams(/*profile=*/2);
    constexpr int32_t kHeight = 10;
    BOOST_REQUIRE(p.IsMatMulRCActive(kHeight));

    CBlockHeader header = MakeDcRCHeader(4242);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();

    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);   // toy dims
    BOOST_REQUIRE(RCEpisodeParamsEqual(params_rc, rc::MakeToyRCEpisodeParams()));
    header.matmul_digest = rc::MineRCEpisode(header, params_rc, kHeight);
    BOOST_REQUIRE(!header.matmul_digest.IsNull());

    const auto target = DeriveTarget(header.nBits, p.powLimit);
    BOOST_REQUIRE(target.has_value());

    // Fail-closed BEFORE any carrier is available (the non-mining-node halt).
    rc::RCFreivaldsCarrierStoreClear();
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(header, p, kHeight));

    // Build + store the honest sampled CARRIER (miner does this at winner time;
    // it is also exactly what the RCCARRIER relay carries). The consensus
    // authority now reads the CARRIER store, not the full-wire v7 proof store.
    const auto pr = rc::ProveWinnerEpisodeV7(header, params_rc, kHeight, *target,
                                             header.matmul_digest);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, "toy-dim v7 prove must succeed");
    rc::RCFreivaldsSampledCarrier carrier;
    std::string why;
    BOOST_REQUIRE(rc::BuildFreivaldsSampledCarrier(pr.proof, header, kHeight, *target, carrier, &why));
    rc::RCFreivaldsCarrierStorePut(header.GetHash(), carrier);

    // ACCEPT via the Freivalds sampled-carrier authority.
    BOOST_CHECK(CheckMatMulProofOfWork_RC(header, p, kHeight));

    // Clearing the carrier reverts to fail-closed reject.
    rc::RCFreivaldsCarrierStoreClear();
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(header, p, kHeight));

    // Tampered sampled layer: flip a carried committed output tile. Carrier v3
    // anchors the input row and recomputes the tile, so the forged output is
    // rejected.
    rc::RCFreivaldsSampledCarrier tampered = carrier;
    bool tampered_one = false;
    for (auto& e : tampered.sampled) {
        for (auto& t : e.tiles) {
            if (!t.extract_out.empty()) { t.extract_out[0] ^= 0x1; tampered_one = true; break; }
        }
        if (tampered_one) break;
    }
    BOOST_REQUIRE(tampered_one);
    rc::RCFreivaldsCarrierStorePut(header.GetHash(), tampered);
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(header, p, kHeight));
    rc::RCFreivaldsCarrierStoreClear();
}

// (c-FVT) FVT — Fully-Verified Terminal round (anti-grinding fix; design
//   doc/btx-matmul-v4.6-rc-antigrind-construction.md §4, consensus flag
//   Consensus::Params::nMatMulRCProfile2FullyVerifyTerminalRound).
//
//   Reproduces the "last-round grind" break at the carrier level (the same
//   construction as the audit's grind PoC): plant a provably-wrong output
//   tile in a TERMINAL-round wire witness (no GEMM re-run — a pure byte
//   flip), rebuild ONLY that round's Merkle root from the (mostly honest)
//   tampered stream, refresh claimed_digest/pow_bind (round_seeds are
//   untouched — the seed chain never depends on round_roots[R-1] because
//   nothing consumes the terminal root downstream), and re-derive a carrier
//   from the tampered proof. Because the terminal round's root feeds no
//   later seed, this "grind" costs one Merkle rebuild (no matmul) and, once
//   the 2-tile-per-unit sample happens to miss the corrupted tile, produces
//   a carrier the SAMPLED verifier (VerifyEpisodeFreivaldsSampledCarrier)
//   accepts on its own — exactly the pre-FVT vulnerable behavior.
//
//   Asserts: (1) the sampled verifier alone still accepts the cheat (sanity:
//   proves the gap is real); (2) with FVT explicitly disabled,
//   CheckMatMulProofOfWork_RC also accepts it (reproduces the pre-fix bug);
//   (3) with FVT at its default ON, CheckMatMulProofOfWork_RC REJECTS the
//   identical cheat carrier with reason v7fs:terminal_round_root_mismatch;
//   (4) an HONEST carrier still PASSES with FVT ON (strictly additive — no
//   honest carrier is newly rejected).
BOOST_AUTO_TEST_CASE(rc_dc_fvt_rejects_lastround_grind_accepts_honest)
{
    Consensus::Params p = MakeRCActiveParams(/*profile=*/2);
    BOOST_REQUIRE(p.nMatMulRCProfile2FullyVerifyTerminalRound); // FVT default ON
    constexpr int32_t kHeight = 10;
    BOOST_REQUIRE(p.IsMatMulRCActive(kHeight));

    // Multi-round toy episode (mirrors the grind PoC's params): rounds>=2 so
    // the terminal round is distinguishable from an interior round, and
    // enough layers that a terminal-round unit's tile space comfortably
    // exceeds kRCFreivaldsSegOutTiles (=2 opened tiles/unit), so a corrupted
    // tile can plausibly hide from the sample without an unbounded grind.
    rc::RCEpisodeParams params_rc = rc::MakeToyRCEpisodeParams();
    params_rc.rounds = 3;
    params_rc.L_lyr = 8;
    BOOST_REQUIRE(rc::ValidateRCEpisodeParams(params_rc));
    const uint32_t R = params_rc.rounds;

    CBlockHeader header = MakeDcRCHeader(0x7f7f7f);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();
    const uint256 real_digest =
        rc::RecomputeResidentCurriculumReference(header, params_rc, kHeight);
    BOOST_REQUIRE(!real_digest.IsNull());
    header.matmul_digest = real_digest;

    const auto target = DeriveTarget(header.nBits, p.powLimit);
    BOOST_REQUIRE(target.has_value());

    const auto pr = rc::ProveWinnerEpisodeV7(header, params_rc, kHeight, *target, real_digest);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, "toy-dim v7 prove must succeed");
    const rc::RCGkrProofV7& honest_proof = pr.proof;

    // --- Baseline: the HONEST carrier passes with FVT ON. ---
    {
        rc::RCFreivaldsSampledCarrier honest_carrier;
        std::string bwhy;
        BOOST_REQUIRE_MESSAGE(rc::BuildFreivaldsSampledCarrier(honest_proof, header, kHeight,
                                                                *target, honest_carrier, &bwhy),
                              bwhy);
        // The terminal round recomputes byte-identically from its own seed —
        // this is the "strictly additive" property FVT relies on.
        const uint256 recomputed_honest = rc::RecomputeRCRoundRoot(
            honest_carrier.round_seeds[R - 1], honest_carrier.episode_sigma,
            honest_carrier.episode);
        BOOST_CHECK_EQUAL(recomputed_honest.ToString(),
                          honest_carrier.round_roots[R - 1].ToString());

        rc::RCFreivaldsCarrierStoreClear();
        rc::RCFreivaldsCarrierStorePut(header.GetHash(), honest_carrier);
        BOOST_CHECK(CheckMatMulProofOfWork_RC(header, p, kHeight)); // FVT ON, honest -> ACCEPT
        rc::RCFreivaldsCarrierStoreClear();
    }

    // --- Construct the cheat: a terminal-round unit with tile_space large
    //     enough that a fixed corrupted tile can plausibly dodge the sample.
    const auto prov = rc::RCGkrEpisodeLayerProvenance(header, params_rc, honest_proof.round_roots);
    std::vector<uint32_t> last_round_units;
    for (uint32_t i = 0; i < prov.size(); ++i) {
        const bool in_stream = prov[i].kind == rc::RCGkrLayerKind::GemmPhase1SV ||
                               prov[i].kind == rc::RCGkrLayerKind::GemmPhase2Fwd;
        if (!in_stream || prov[i].round != R - 1) continue;
        const uint64_t tile_space =
            static_cast<uint64_t>(prov[i].m) * (prov[i].n / rc::kRCMxBlockLen);
        if (tile_space > rc::kRCFreivaldsSegOutTiles) last_round_units.push_back(i);
    }
    BOOST_REQUIRE_MESSAGE(!last_round_units.empty(),
                          "need a last-round unit with >kRCFreivaldsSegOutTiles output tiles");

    bool built_cheat = false;
    rc::RCFreivaldsSampledCarrier cheat_carrier;
    CBlockHeader cheat_header;
    for (uint32_t u : last_round_units) {
        if (built_cheat) break;
        const uint32_t m = prov[u].m;
        const uint32_t n = prov[u].n;
        const uint32_t nblk = n / rc::kRCMxBlockLen;
        const uint32_t rstar = m / 2;
        const uint32_t bstar = nblk / 2;
        const size_t ybase =
            static_cast<size_t>(rstar) * n + static_cast<size_t>(bstar) * rc::kRCMxBlockLen;

        constexpr int kMaxGrind = 4000;
        for (int g = 0; g < kMaxGrind && !built_cheat; ++g) {
            rc::RCGkrProofV7 tampered = honest_proof;
            CBlockHeader th = header;
            // Provably-wrong tile: overwrite it with a value guaranteed to
            // differ from the honest Extract output. NO GEMM is re-run.
            auto& eo = tampered.wires[u].extract_out;
            BOOST_REQUIRE_GE(eo.size(), ybase + rc::kRCMxBlockLen);
            for (uint32_t c = 0; c < rc::kRCMxBlockLen; ++c) {
                eo[ybase + c] = static_cast<int8_t>(
                    honest_proof.wires[u].extract_out[ybase + c] ^ (0x40 | ((g + c) & 0x3f)));
            }
            // Rebuild ONLY the terminal round's Merkle root from the mostly-
            // honest, one-tile-corrupted stream (a hash pass, no GEMM).
            const std::vector<int8_t> stream =
                rc::RCGkrReconstructRoundStream(tampered.wires, R - 1, params_rc);
            tampered.round_roots[R - 1] = rc::BuildTileTreeRoot(stream, params_rc.T_leaf);
            tampered.claimed_digest = rc::RCGkrEpisodeDigestFromRoots(tampered.round_roots);
            tampered.pow_bind = rc::RCGkrDerivePowBind(tampered.claimed_digest);
            // sigma = DeriveSigma(header) excludes matmul_digest, so it is
            // unaffected by re-pointing the header at the new digest.
            th.matmul_digest = tampered.claimed_digest;

            rc::RCFreivaldsSampledCarrier c;
            std::string bwhy;
            if (!rc::BuildFreivaldsSampledCarrier(tampered, th, kHeight, *target, c, &bwhy)) {
                continue;
            }
            std::string vwhy;
            if (!rc::VerifyEpisodeFreivaldsSampledCarrier(c, th, kHeight, *target, &vwhy)) {
                continue; // this trial's sample happened to hit the corrupted tile
            }
            // Confirm this really is a cheat: the committed terminal-round
            // tile provably differs from the honest output.
            bool differs = false;
            for (uint32_t c = 0; c < rc::kRCMxBlockLen; ++c) {
                if (tampered.wires[u].extract_out[ybase + c] !=
                    honest_proof.wires[u].extract_out[ybase + c]) {
                    differs = true;
                }
            }
            if (!differs) continue;

            cheat_carrier = c;
            cheat_header = th;
            built_cheat = true;
        }
    }
    BOOST_REQUIRE_MESSAGE(
        built_cheat,
        "could not construct a sampled-verifier-accepting terminal-round cheat "
        "(grind budget exhausted) -- cannot exercise the FVT regression without one");

    // Sanity: the cheat's terminal-round root does NOT match a real recompute
    // from its own seed (it was rebuilt from a corrupted wire stream) -- this
    // is exactly the mismatch FVT is meant to catch.
    const uint256 recomputed_cheat = rc::RecomputeRCRoundRoot(
        cheat_carrier.round_seeds[R - 1], cheat_carrier.episode_sigma, cheat_carrier.episode);
    BOOST_CHECK(recomputed_cheat.ToString() != cheat_carrier.round_roots[R - 1].ToString());

    // --- Pre-FVT-equivalent: the sampled verifier ALONE still accepts. ---
    {
        std::string vwhy;
        BOOST_CHECK_MESSAGE(
            rc::VerifyEpisodeFreivaldsSampledCarrier(cheat_carrier, cheat_header, kHeight,
                                                     *target, &vwhy),
            "sampled carrier verifier must (still) accept the cheat standalone -- "
            "that is the gap FVT closes: "
                << vwhy);
    }

    // --- FVT explicitly OFF: CheckMatMulProofOfWork_RC still accepts the
    //     cheat (reproduces the pre-fix vulnerable behavior). ---
    {
        Consensus::Params p_off = p;
        p_off.nMatMulRCProfile2FullyVerifyTerminalRound = false;
        rc::RCFreivaldsCarrierStoreClear();
        rc::RCFreivaldsCarrierStorePut(cheat_header.GetHash(), cheat_carrier);
        BOOST_CHECK(CheckMatMulProofOfWork_RC(cheat_header, p_off, kHeight));
        rc::RCFreivaldsCarrierStoreClear();
    }

    // --- FVT ON (default / consensus posture): the SAME cheat is REJECTED. ---
    {
        rc::RCFreivaldsCarrierStoreClear();
        rc::RCFreivaldsCarrierStorePut(cheat_header.GetHash(), cheat_carrier);
        BOOST_CHECK(!CheckMatMulProofOfWork_RC(cheat_header, p, kHeight));
        rc::RCFreivaldsCarrierStoreClear();
    }
}

// (c-λ) P2P/CONSENSUS PARITY on the sampling breadth λ. The RCCARRIER receiver
//   (net_processing.cpp, "if (msg_type == NetMsgType::RCCARRIER)") admits an
//   untrusted carrier to the process-local store only after the SAME ordered
//   gates the consensus path (CheckMatMulProofOfWork_RC profile-2 branch,
//   pow.cpp) applies: (vi) the 9-field episode-shape bind, (vi-b) the fixed-λ
//   bind carrier.lambda == kRCFreivaldsSampleCount, and (vii) the full
//   VerifyEpisodeFreivaldsSampledCarrier authentication. Step (vi-b) was the
//   audit gap: VerifyEpisodeFreivaldsSampledCarrier authenticates against the
//   carrier's OWN λ, so a carrier that shrank λ (fewer sampled units ⇒ a larger
//   deterrence residual ρ* ≈ ln κ/λ) authenticated + stored on the P2P path yet
//   FAILED consensus — a present-but-invalid store-pollution mismatch. This test
//   pins net-store admission == consensus admission on the λ dimension.
//
//   Why this is a shared-predicate-boundary test rather than a direct
//   ProcessMessage(RCCARRIER) drive: the receiver's INTERESTED-ONLY gate requires
//   a header present in the block index at a profile-2 ACTIVE height, but every
//   shipped chain pins nMatMulRCHeight = INT32_MAX (see rc_dc_public_heights_*),
//   so exercising the receiver would require mining a valid profile-2 block into
//   the index plus priming the per-peer ingress token bucket — disproportionate
//   for a one-predicate parity assertion. Instead we reproduce the receiver's
//   post-deserialize admission gates (vi/vi-b/vii) via the exact same shared
//   functions the receiver calls, and assert they agree with consensus.
BOOST_AUTO_TEST_CASE(rc_dc_rccarrier_net_store_lambda_matches_consensus)
{
    Consensus::Params p = MakeRCActiveParams(/*profile=*/2);
    constexpr int32_t kHeight = 10;
    BOOST_REQUIRE(p.IsMatMulRCActive(kHeight));

    CBlockHeader header = MakeDcRCHeader(0x1abda);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();
    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);   // toy dims
    header.matmul_digest = rc::MineRCEpisode(header, params_rc, kHeight);
    BOOST_REQUIRE(!header.matmul_digest.IsNull());
    const auto target = DeriveTarget(header.nBits, p.powLimit);
    BOOST_REQUIRE(target.has_value());

    const auto pr = rc::ProveWinnerEpisodeV7(header, params_rc, kHeight, *target,
                                             header.matmul_digest);
    BOOST_REQUIRE_MESSAGE(pr.timing.ok, "toy-dim v7 prove must succeed");

    // Honest carrier: λ = kRCFreivaldsSampleCount (the field Build stamps from the
    // λ argument). Reduced carrier: a smaller λ — internally consistent, so it
    // authenticates against its OWN λ, which is exactly why step (vii) alone lets
    // it through.
    rc::RCFreivaldsSampledCarrier honest;
    std::string why;
    BOOST_REQUIRE(rc::BuildFreivaldsSampledCarrier(pr.proof, header, kHeight, *target,
                                                   honest, &why));
    BOOST_REQUIRE_EQUAL(honest.lambda, rc::kRCFreivaldsSampleCount);

    // A λ strictly below the consensus constant (and, for the toy episode, below
    // the sampleable-unit count so it genuinely samples FEWER units).
    const uint32_t reduced_lambda = honest.sampled.size() > 4 ? 4u : 1u;
    BOOST_REQUIRE(reduced_lambda != rc::kRCFreivaldsSampleCount);
    rc::RCFreivaldsSampledCarrier reduced;
    BOOST_REQUIRE(rc::BuildFreivaldsSampledCarrier(pr.proof, header, kHeight, *target,
                                                   reduced, &why, reduced_lambda));
    BOOST_REQUIRE_EQUAL(reduced.lambda, reduced_lambda);
    BOOST_CHECK_LE(reduced.sampled.size(), honest.sampled.size());

    // Reproduce the RCCARRIER receiver's post-deserialize admission gates using
    // the SAME shared functions the receiver calls (net_processing.cpp steps
    // vi / vi-b / vii). Returns true iff the receiver would StorePut the carrier.
    const auto net_would_store = [&](const rc::RCFreivaldsSampledCarrier& c) -> bool {
        const auto& ce = c.episode;                       // (vi) 9-field shape bind
        if (!(ce.rounds == params_rc.rounds && ce.d_head == params_rc.d_head &&
              ce.n_q == params_rc.n_q && ce.n_ctx == params_rc.n_ctx &&
              ce.L_lyr == params_rc.L_lyr && ce.d_model == params_rc.d_model &&
              ce.b_seq == params_rc.b_seq && ce.T_leaf == params_rc.T_leaf &&
              ce.d_ff == params_rc.d_ff)) {
            return false;
        }
        if (c.lambda != rc::kRCFreivaldsSampleCount) {    // (vi-b) fixed-λ bind (the fix)
            return false;
        }
        std::string vwhy;                                 // (vii) full authentication
        return rc::VerifyEpisodeFreivaldsSampledCarrier(c, header, kHeight, *target, &vwhy);
    };

    // Consensus admission: does CheckMatMulProofOfWork_RC accept with this exact
    // carrier in the store?
    const auto consensus_accepts = [&](const rc::RCFreivaldsSampledCarrier& c) -> bool {
        rc::RCFreivaldsCarrierStoreClear();
        rc::RCFreivaldsCarrierStorePut(header.GetHash(), c);
        const bool ok = CheckMatMulProofOfWork_RC(header, p, kHeight);
        rc::RCFreivaldsCarrierStoreClear();
        return ok;
    };

    // The reduced carrier AUTHENTICATES against its own λ — so step (vii) alone
    // (the only carrier check the pre-fix receiver ran) would ADMIT it. It is the
    // λ bind, not the verify, that must stop it.
    BOOST_CHECK_MESSAGE(
        rc::VerifyEpisodeFreivaldsSampledCarrier(reduced, header, kHeight, *target, &why),
        "reduced-λ carrier must authenticate on its own λ (else the test proves nothing): "
            << why);

    // Parity, honest carrier: BOTH admit.
    BOOST_CHECK(net_would_store(honest));
    BOOST_CHECK(consensus_accepts(honest));
    BOOST_CHECK_EQUAL(net_would_store(honest), consensus_accepts(honest));

    // Parity, reduced-λ carrier: BOTH reject (the fix closes the mismatch).
    BOOST_CHECK(!net_would_store(reduced));
    BOOST_CHECK(!consensus_accepts(reduced));
    BOOST_CHECK_EQUAL(net_would_store(reduced), consensus_accepts(reduced));

    rc::RCFreivaldsCarrierStoreClear();
}

// (c'') CONSENSUS-CORRECTNESS: CheckMatMulProofOfWork_RC's `carrier_missing`
//       out-param must distinguish a MERELY-LATE carrier (transient; the compact-
//       block DEFER path) from a PRESENT-BUT-INVALID one (a permanent PoW fault).
//       This is the discriminator the block-accept path uses to avoid PERMANENTLY
//       rejecting a raced-but-valid profile-2 block whose carrier is simply late,
//       WITHOUT ever accepting without an authenticated carrier or reclassifying a
//       genuinely bad carrier as transient.
BOOST_AUTO_TEST_CASE(rc_dc_authority_profile2_carrier_missing_discriminates)
{
    Consensus::Params p = MakeRCActiveParams(/*profile=*/2);
    constexpr int32_t kHeight = 10;
    BOOST_REQUIRE(p.IsMatMulRCActive(kHeight));

    CBlockHeader header = MakeDcRCHeader(0x7373);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();
    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);   // toy dims
    header.matmul_digest = rc::MineRCEpisode(header, params_rc, kHeight);
    BOOST_REQUIRE(!header.matmul_digest.IsNull());
    const auto target = DeriveTarget(header.nBits, p.powLimit);
    BOOST_REQUIRE(target.has_value());

    // (1) MISSING carrier: fail-closed reject, AND flagged carrier_missing=true.
    //     This is the ONLY case the DEFER path may act on (request + retry).
    rc::RCFreivaldsCarrierStoreClear();
    {
        bool carrier_missing = false;
        BOOST_CHECK(!CheckMatMulProofOfWork_RC(header, p, kHeight, &carrier_missing));
        BOOST_CHECK(carrier_missing);   // transient, defer-eligible
    }

    // (2) PRESENT + VALID carrier: ACCEPT, and carrier_missing MUST be false — a
    //     missing carrier can never be the reason we accept. Establishes that
    //     acceptance requires a present, authenticated carrier.
    rc::RCFreivaldsSampledCarrier carrier;
    {
        const auto pr = rc::ProveWinnerEpisodeV7(header, params_rc, kHeight, *target,
                                                 header.matmul_digest);
        BOOST_REQUIRE(pr.timing.ok);
        std::string why;
        BOOST_REQUIRE(rc::BuildFreivaldsSampledCarrier(pr.proof, header, kHeight, *target,
                                                       carrier, &why));
    }
    rc::RCFreivaldsCarrierStorePut(header.GetHash(), carrier);
    {
        bool carrier_missing = true;   // must be cleared to false on the accept path
        BOOST_CHECK(CheckMatMulProofOfWork_RC(header, p, kHeight, &carrier_missing));
        BOOST_CHECK(!carrier_missing);
    }

    // (3) PRESENT + INVALID carrier (tampered sampled layer): PERMANENT reject,
    //     and carrier_missing MUST be false — a bad carrier is a real PoW fault,
    //     NEVER a transient defer. Misclassifying this as transient would let an
    //     attacker keep a bad block permanently deferrable; the out-param forbids
    //     it.
    rc::RCFreivaldsSampledCarrier tampered = carrier;
    bool tampered_one = false;
    for (auto& e : tampered.sampled) {
        for (auto& t : e.tiles) {
            if (!t.extract_out.empty()) { t.extract_out[0] ^= 0x1; tampered_one = true; break; }
        }
        if (tampered_one) break;
    }
    BOOST_REQUIRE(tampered_one);
    rc::RCFreivaldsCarrierStorePut(header.GetHash(), tampered);
    {
        bool carrier_missing = true;   // present-but-invalid ⇒ must be cleared false
        BOOST_CHECK(!CheckMatMulProofOfWork_RC(header, p, kHeight, &carrier_missing));
        BOOST_CHECK(!carrier_missing);   // permanent, NOT defer-eligible
    }

    // (4) The default-nullptr overload is unchanged (fail-closed on missing).
    rc::RCFreivaldsCarrierStoreClear();
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(header, p, kHeight));
    rc::RCFreivaldsCarrierStoreClear();
}

// (c') Profile 2: an episode proof committing SMALLER-than-consensus dims is
//      rejected — the episode shape is consensus-fixed, not prover-chosen.
BOOST_AUTO_TEST_CASE(rc_dc_authority_profile2_rejects_episode_shape_swap)
{
    // Consensus resolves DATACENTER dims (no toy); a proof carrying toy dims must
    // not be accepted for a datacenter-shaped consensus slot.
    Consensus::Params p = MakeRCActiveParams(/*profile=*/2);
    p.fMatMulRCUseToyDims = false;   // consensus dims = datacenter (profile 2)
    constexpr int32_t kHeight = 10;
    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);
    BOOST_REQUIRE(RCEpisodeParamsEqual(params_rc, rc::MakeDatacenterRCEpisodeParams()));

    CBlockHeader header = MakeDcRCHeader(99);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();

    // A toy-dim proof (cheap) stored against this header must be rejected by the
    // episode-shape bind before any accept — without materializing a real
    // datacenter episode (infeasible in a unit test).
    const auto toy = rc::MakeToyRCEpisodeParams();
    header.matmul_digest = rc::RecomputeResidentCurriculumReference(header, toy, kHeight);
    const auto target = DeriveTarget(header.nBits, p.powLimit);
    BOOST_REQUIRE(target.has_value());
    const auto pr = rc::ProveWinnerEpisodeV7(header, toy, kHeight, *target, header.matmul_digest);
    BOOST_REQUIRE(pr.timing.ok);
    rc::RCFreivaldsSampledCarrier toy_carrier;
    std::string why;
    BOOST_REQUIRE(rc::BuildFreivaldsSampledCarrier(pr.proof, header, kHeight, *target, toy_carrier, &why));
    rc::RCFreivaldsCarrierStorePut(header.GetHash(), toy_carrier);
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(header, p, kHeight));   // shape mismatch → reject
    rc::RCFreivaldsCarrierStoreClear();
}

// R-05 (FS/T-BIND audit): the profile-2 consensus carrier MUST bind the BLOCK
// target (nBits-derived), NEVER the pooled share_target_override. The FS seed
// (RCGkrFsSeedV7) absorbs the target and drives WHICH layers/tiles are sampled
// and in WHAT order; CheckMatMulProofOfWork_RC always recomputes that seed with
// the BLOCK target. Before the fix the solver built the carrier with the (easier)
// share target, so an honest pool-built candidate that ALSO met the block target
// shipped a carrier whose FS sample was bound to the share target — a validator
// recomputing with the block target selected a different sample set and REJECTED
// it, contradicting the SolveMatMul contract (a returned share meeting the block
// target is a fully consensus-valid block). This regression drives the REAL solver
// with an easier share target, lands a share whose digest ALSO meets the block
// target, round-trips the stored carrier through the P2P wire form, and asserts
// CheckMatMulProofOfWork_RC ACCEPTS — and that a carrier bound to the SHARE target
// (the pre-fix behaviour) is REJECTED under block-target verification.
BOOST_AUTO_TEST_CASE(rc_dc_carrier_binds_block_target_not_share_target)
{
    Consensus::Params p = MakeRCActiveParams(/*profile=*/2);
    constexpr int32_t kHeight = 10;
    BOOST_REQUIRE(p.IsMatMulRCActive(kHeight));
    BOOST_REQUIRE(p.IsMatMulV4Active(kHeight));
    BOOST_REQUIRE(p.GetMatMulEncodingProfile(kHeight) ==
                  Consensus::MatMulEncodingProfile::ENC_RC);

    const int64_t parent_mtp = 1'700'000'000;
    // Easiest possible share target (max powLimit). MakeDcRCHeader keeps
    // nBits=0x207fffff, so the BLOCK target is ~2^255 (~half of powLimit): the
    // share override is STRICTLY easier and ~50% of toy digests also meet the
    // block target.
    const uint256 easy_share_target{p.powLimit};

    // Drive the real solver with the easy share override, scanning start nonces
    // until a returned share ALSO meets the block target. With the fix the solver
    // stores a carrier ONLY when the digest meets the BLOCK target (the profile-2
    // ProveWinnerEpisodeV7 gate now uses the block target); a share that misses the
    // block target returns true but stores no carrier.
    CBlockHeader solved{};
    arith_uint256 block_target;
    bool got_lucky_share = false;
    for (uint64_t seed_nonce = 1; seed_nonce <= 64 && !got_lucky_share; ++seed_nonce) {
        rc::RCFreivaldsCarrierStoreClear();
        CBlockHeader candidate = MakeDcRCHeader(seed_nonce);
        candidate.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
        const auto bt = DeriveTarget(candidate.nBits, p.powLimit);
        BOOST_REQUIRE(bt.has_value());
        BOOST_REQUIRE_GT(UintToArith256(easy_share_target), *bt);  // share strictly easier

        uint64_t max_tries = 1;
        const bool solved_share = SolveMatMul(candidate, p, max_tries, kHeight,
                                              /*abort_flag=*/nullptr,
                                              /*freivalds_payload_out=*/nullptr,
                                              &easy_share_target, parent_mtp);
        if (!solved_share) continue;
        // The returned share digest meets the easy target by construction; keep it
        // only if it ALSO meets the block target (⇒ the solver stored the carrier).
        if (UintToArith256(candidate.matmul_digest) <= *bt &&
            rc::RCFreivaldsCarrierStoreHave(candidate.GetHash())) {
            solved = candidate;
            block_target = *bt;
            got_lucky_share = true;
        }
    }
    BOOST_REQUIRE_MESSAGE(got_lucky_share,
        "expected a share whose digest also meets the block target within the scan");

    // The solve exited on the EASIER share target, yet the digest is a genuine
    // block (meets the block target).
    BOOST_CHECK_LE(UintToArith256(solved.matmul_digest), block_target);
    BOOST_CHECK_LE(UintToArith256(solved.matmul_digest), UintToArith256(easy_share_target));
    BOOST_CHECK_GT(UintToArith256(easy_share_target), block_target);

    // (ACCEPT, with the fix) the solver-stored carrier, round-tripped through the
    // exact P2P wire form, is accepted by the consensus verifier (block target).
    rc::RCFreivaldsSampledCarrier from_solver;
    BOOST_REQUIRE(rc::RCFreivaldsCarrierStoreGet(solved.GetHash(), from_solver));
    std::vector<unsigned char> block_wire;
    rc::SerializeRCFreivaldsCarrier(from_solver, block_wire);
    rc::RCFreivaldsSampledCarrier round_tripped;
    std::string dwhy;
    BOOST_REQUIRE_MESSAGE(
        rc::DeserializeRCFreivaldsCarrierBounded(block_wire, round_tripped, &dwhy),
        "carrier wire round-trip failed: " << dwhy);
    rc::RCFreivaldsCarrierStoreClear();
    rc::RCFreivaldsCarrierStorePut(solved.GetHash(), round_tripped);
    BOOST_CHECK_MESSAGE(CheckMatMulProofOfWork_RC(solved, p, kHeight),
        "block-target-bound carrier must be ACCEPTED under block-target verification");

    // (WOULD-FAIL-BEFORE-FIX) build the carrier against the SHARE target — exactly
    // what the solver did before R-05 — and show block-target verification REJECTS
    // it. ProveWinnerEpisodeV7 succeeds against the easier share target (digest
    // meets it), but the FS seed is bound to the wrong target, so the validator
    // recomputes a different sample set/order and rejects.
    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);
    const auto share_pr = rc::ProveWinnerEpisodeV7(
        solved, params_rc, kHeight, UintToArith256(easy_share_target), solved.matmul_digest);
    BOOST_REQUIRE_MESSAGE(share_pr.timing.ok,
        "prove against the easier share target must succeed (digest meets share target)");
    rc::RCFreivaldsSampledCarrier share_carrier;
    std::string swhy;
    BOOST_REQUIRE(rc::BuildFreivaldsSampledCarrier(
        share_pr.proof, solved, kHeight, UintToArith256(easy_share_target), share_carrier, &swhy));
    rc::RCFreivaldsCarrierStoreClear();
    rc::RCFreivaldsCarrierStorePut(solved.GetHash(), share_carrier);
    BOOST_CHECK_MESSAGE(!CheckMatMulProofOfWork_RC(solved, p, kHeight),
        "share-target-bound carrier must be REJECTED under block-target verification (pre-fix defect)");

    // The two carriers genuinely differ (FS seed divergence ⇒ different sampled
    // set/order/tiles): the reject above is not vacuous.
    std::vector<unsigned char> share_wire;
    rc::SerializeRCFreivaldsCarrier(share_carrier, share_wire);
    BOOST_CHECK_MESSAGE(share_wire != block_wire,
        "share-bound and block-bound carriers must differ (FS seed is target-bound)");

    rc::RCFreivaldsCarrierStoreClear();
}

// ---------------------------------------------------------------------------
// RELAY: the sampled CARRIER — serialization (byte-exact + bounded) and the P2P
// availability seam that closes the non-mining-node halt. These exercise the
// object CheckMatMulProofOfWork_RC now consumes (RCFreivaldsCarrierStore) and
// the wire form net_processing relays (RCCARRIER).
// ---------------------------------------------------------------------------

namespace {
// Build a valid toy-dim carrier bound to `header` (miner side).
bool BuildToyCarrier(const CBlockHeader& header, const rc::RCEpisodeParams& params_rc,
                     int32_t height, const arith_uint256& target,
                     rc::RCFreivaldsSampledCarrier& out)
{
    const auto pr = rc::ProveWinnerEpisodeV7(header, params_rc, height, target,
                                             header.matmul_digest);
    if (!pr.timing.ok) return false;
    std::string why;
    return rc::BuildFreivaldsSampledCarrier(pr.proof, header, height, target, out, &why);
}

bool LayerInStreamBench(rc::RCGkrLayerKind k)
{
    return k == rc::RCGkrLayerKind::GemmPhase1SV || k == rc::RCGkrLayerKind::GemmPhase2Fwd;
}

uint64_t LayerStreamOffsetBench(const rc::RCEpisodeParams& p, rc::RCGkrLayerKind kind,
                                uint32_t layer)
{
    const uint64_t z = static_cast<uint64_t>(p.n_q) * p.d_head;
    const uint64_t per_l = static_cast<uint64_t>(p.b_seq) * p.d_model;
    if (kind == rc::RCGkrLayerKind::GemmPhase1SV) return 0;
    if (kind == rc::RCGkrLayerKind::GemmPhase2Fwd) return z + static_cast<uint64_t>(layer) * per_l;
    return 0;
}

std::vector<int8_t> TransposeI8Bench(const std::vector<int8_t>& src, uint32_t rows,
                                     uint32_t cols)
{
    std::vector<int8_t> out(static_cast<size_t>(rows) * cols);
    for (uint32_t i = 0; i < rows; ++i) {
        for (uint32_t j = 0; j < cols; ++j) {
            out[static_cast<size_t>(j) * rows + i] = src[static_cast<size_t>(i) * cols + j];
        }
    }
    return out;
}

void PutLE32Bench(unsigned char* p, uint32_t v)
{
    p[0] = static_cast<unsigned char>(v & 0xff);
    p[1] = static_cast<unsigned char>((v >> 8) & 0xff);
    p[2] = static_cast<unsigned char>((v >> 16) & 0xff);
    p[3] = static_cast<unsigned char>((v >> 24) & 0xff);
}

uint64_t SegPosU64Bench(const uint256& base_seed, uint32_t layer_index, uint32_t counter)
{
    constexpr size_t kTagLen = sizeof(rc::kRCFreivaldsSegPosTag) - 1;
    std::vector<unsigned char> buf(kTagLen + 32 + 8);
    std::memcpy(buf.data(), rc::kRCFreivaldsSegPosTag, kTagLen);
    std::memcpy(buf.data() + kTagLen, base_seed.data(), 32);
    PutLE32Bench(buf.data() + kTagLen + 32, layer_index);
    PutLE32Bench(buf.data() + kTagLen + 36, counter);
    const uint256 h = rc::Sha256dBytes(buf.data(), buf.size());
    uint64_t v = 0;
    for (int b = 0; b < 8; ++b) v |= static_cast<uint64_t>(h.data()[b]) << (8 * b);
    return v;
}

struct TilePlanBench {
    uint32_t row{0};
    uint32_t bcol{0};
};

std::vector<TilePlanBench> TilePositionsBench(const uint256& base_seed, uint32_t layer_index,
                                              uint32_t m, uint32_t n)
{
    std::vector<TilePlanBench> plans;
    if (m == 0 || n < rc::kRCMxBlockLen) return plans;
    const uint32_t n_blocks = n / rc::kRCMxBlockLen;
    const uint64_t tile_space = static_cast<uint64_t>(m) * n_blocks;
    const uint32_t want =
        static_cast<uint32_t>(std::min<uint64_t>(rc::kRCFreivaldsSegOutTiles, tile_space));
    std::vector<uint64_t> seen;
    uint32_t ctr = 0;
    const uint32_t max_iters = (want + 8u) * 64u + 4096u;
    while (plans.size() < want && ctr < max_iters) {
        const uint64_t t = SegPosU64Bench(base_seed, layer_index, ctr++);
        const uint32_t row = static_cast<uint32_t>(t % m);
        const uint32_t bcol = static_cast<uint32_t>((t / m) % n_blocks);
        const uint64_t key = (static_cast<uint64_t>(row) << 32) | bcol;
        if (std::find(seen.begin(), seen.end(), key) != seen.end()) continue;
        seen.push_back(key);
        plans.push_back(TilePlanBench{row, bcol});
    }
    return plans;
}

std::array<int8_t, rc::kRCMxBlockLen> ExtractBlockBench(const uint256& prf, uint32_t i,
                                                        uint32_t bj, const int64_t* acc_block)
{
    std::array<int8_t, rc::kRCMxBlockLen> out{};
    rc::ExtractMXTileInt64(prf, i, bj, acc_block, out.data());
    return out;
}

uint32_t BenchPrewarmInnerThreads(uint32_t total_threads)
{
    if (total_threads <= 1) return 1;
    if (const char* env = std::getenv("BTX_RC_CARRIER_PREWARM_INNER_THREADS")) {
        const unsigned long requested = std::strtoul(env, nullptr, 10);
        if (requested > 0) {
            return static_cast<uint32_t>(
                std::clamp<unsigned long>(requested, 1, total_threads));
        }
    }
    return std::min<uint32_t>(8, total_threads);
}

uint32_t PaddedLeafDepthBench(uint64_t stream_bytes, uint32_t t_leaf)
{
    uint64_t n = std::max<uint64_t>(1, (stream_bytes + t_leaf - 1) / t_leaf);
    uint32_t depth = 0;
    uint64_t p = 1;
    while (p < n) {
        p <<= 1;
        ++depth;
    }
    return depth;
}

uint256 LeafHashFromBytesBench(const std::vector<uint8_t>& leaf_bytes)
{
    std::vector<unsigned char> pre;
    pre.reserve(1 + leaf_bytes.size());
    pre.push_back(rc::kRCLeafTag);
    pre.insert(pre.end(), leaf_bytes.begin(), leaf_bytes.end());
    return rc::Sha256dBytes(pre.data(), pre.size());
}

uint256 FoldProofRootBench(uint256 cur, uint32_t index, const rc::RCMerkleProof& proof)
{
    uint32_t idx = index;
    for (const uint256& sib : proof.siblings) {
        unsigned char buf[1 + 64];
        buf[0] = rc::kRCNodeTag;
        if ((idx & 1u) == 0) {
            std::memcpy(buf + 1, cur.data(), 32);
            std::memcpy(buf + 1 + 32, sib.data(), 32);
        } else {
            std::memcpy(buf + 1, sib.data(), 32);
            std::memcpy(buf + 1 + 32, cur.data(), 32);
        }
        cur = rc::Sha256dBytes(buf, sizeof(buf));
        idx >>= 1;
    }
    return cur;
}

bool SimulateMerkleOpenBench(const std::vector<uint8_t>& leaf_bytes, uint32_t leaf_index,
                             const rc::RCMerkleProof& proof)
{
    const uint256 leaf = LeafHashFromBytesBench(leaf_bytes);
    const uint256 root = FoldProofRootBench(leaf, leaf_index, proof);
    return rc::VerifyMerkleProof(leaf, leaf_index, proof, root);
}

std::vector<uint32_t> SampleableIndicesBench(const std::vector<rc::RCGkrSampledLayerProv>& prov)
{
    std::vector<uint32_t> out;
    for (uint32_t i = 0; i < prov.size(); ++i) {
        if (LayerInStreamBench(prov[i].kind)) out.push_back(i);
    }
    return out;
}

struct ProdCarrierBenchReport {
    bool stopped_at_budget{false};
    double total_s{0.0};
    double regen_s{0.0};
    double recompute_s{0.0};
    double merkle_s{0.0};
    double first_layer_total_s{0.0};
    double first_layer_regen_s{0.0};
    double first_layer_recompute_s{0.0};
    double first_layer_merkle_s{0.0};
    uint32_t units_total{0};
    uint32_t sampled_total{0};
    uint32_t first_layer_index{0};
    uint32_t first_layer_kind{0};
    uint32_t first_m{0};
    uint32_t first_n{0};
    uint32_t first_k{0};
    uint64_t first_layer_regen_misses{0};
    uint64_t first_layer_regen_hits{0};
    uint64_t first_layer_regen_bytes{0};
    uint64_t first_layer_extract_tiles{0};
    uint32_t layers_checked{0};
    uint64_t extract_tiles{0};
    uint32_t merkle_openings{0};
    uint64_t merkle_hashes{0};
    uint32_t checked_merkle_openings{0};
    uint64_t checked_merkle_hashes{0};
    uint32_t first_layer_checked_merkle_openings{0};
    uint64_t first_layer_checked_merkle_hashes{0};
    size_t carrier_bytes{0};
    uint32_t tree_depth{0};
    uint64_t regen_misses{0};
    uint64_t regen_hits{0};
    uint64_t regen_bytes{0};
    uint64_t planned_regen_misses_full{0};
    uint64_t planned_regen_bytes_full{0};
    uint64_t recompute_macs{0};
    uint32_t threads{1};
    bool recompute_vectorized{false};
    uint64_t checksum{0};
};

ProdCarrierBenchReport RunProductionCarrierVerifierComputeBench()
{
    ProdCarrierBenchReport rep;
    constexpr int32_t kHeight = 10;
    Consensus::Params consensus = MakeRCActiveParams(/*profile=*/2);
    consensus.fMatMulRCUseToyDims = false;
    CBlockHeader header = MakeDcRCHeader(0xBEEFCACE);
    header.matmul_dim = static_cast<uint16_t>(consensus.nMatMulV4Dimension);
    header.nBits = UintToArith256(consensus.powLimit).GetCompact();
    const auto target = DeriveTarget(header.nBits, consensus.powLimit);
    BOOST_REQUIRE(target.has_value());
    const rc::RCEpisodeParams p = rc::ResolveRCEpisodeParams(consensus, kHeight);
    BOOST_REQUIRE(RCEpisodeParamsEqual(p, rc::MakeDatacenterRCEpisodeParams()));
    rep.recompute_vectorized = rc::RCDenseRowBlockVectorizedAvailable() ||
                               rc::RCDensePackedI8mmAvailable();

    const uint256 sigma = matmul::v4::DeriveSigma(header);
    std::vector<uint256> round_roots(p.rounds);
    uint256 prev = sigma;
    for (uint32_t r = 0; r < p.rounds; ++r) {
        round_roots[r] = rc::RCGkrRoundSeed(prev, 0xC0FFEEu + r);
        prev = round_roots[r];
    }
    const uint256 digest = rc::RCGkrEpisodeDigestFromRoots(round_roots);
    header.matmul_digest = digest;
    const uint256 pow_bind = rc::RCGkrDerivePowBind(digest);
    std::vector<uint256> round_seeds(p.rounds);
    for (uint32_t r = 0; r < p.rounds; ++r) {
        round_seeds[r] = rc::RCGkrRoundSeed(r == 0 ? sigma : round_roots[r - 1], r);
    }
    const uint256 base_seed =
        rc::RCGkrFsSeedV7(header, kHeight, p, *target, digest, sigma, round_roots);
    const std::vector<rc::RCGkrSampledLayerProv> prov =
        rc::RCGkrEpisodeLayerProvenance(header, p, round_roots);
    const std::vector<uint32_t> sampleable = SampleableIndicesBench(prov);
    const std::vector<uint32_t> units =
        rc::FreivaldsSampleLayers(base_seed, static_cast<uint32_t>(sampleable.size()),
                                  rc::kRCFreivaldsSampleCount);
    rep.units_total = static_cast<uint32_t>(sampleable.size());
    rep.sampled_total = static_cast<uint32_t>(units.size());

    const uint64_t round_stream_bytes =
        static_cast<uint64_t>(p.n_q) * p.d_head +
        static_cast<uint64_t>(p.L_lyr) * p.b_seq * p.d_model;
    rep.tree_depth = PaddedLeafDepthBench(round_stream_bytes, p.T_leaf);

    // Skeleton carrier with production dimensions and production proof/path
    // cardinalities. It is only used to measure byte size; the compute loop
    // below executes the same production-shape PRF/GEMM/Extract work as the
    // verifier and stops as soon as the 0.9s budget is exceeded.
    rc::RCFreivaldsSampledCarrier skeleton;
    skeleton.version = rc::kRCFreivaldsSampledCarrierVersion;
    skeleton.episode = p;
    skeleton.height = kHeight;
    skeleton.claimed_digest = digest;
    skeleton.pow_bind = pow_bind;
    skeleton.episode_sigma = sigma;
    skeleton.round_roots = round_roots;
    skeleton.round_seeds = round_seeds;
    skeleton.lambda = rc::kRCFreivaldsSampleCount;
    for (uint32_t u : units) {
        const uint32_t li = sampleable[u];
        const auto& lp = prov[li];
        rc::RCFreivaldsSampledLayer e;
        e.layer_index = li;
        e.round = lp.round;
        e.kind = lp.kind;
        e.m = lp.m;
        e.n = lp.n;
        e.k = lp.k;
        for (const TilePlanBench& pl : TilePositionsBench(base_seed, li, lp.m, lp.n)) {
            rc::RCFreivaldsSampledTile t;
            t.row = pl.row;
            t.bcol = pl.bcol;
            t.extract_out.assign(rc::kRCMxBlockLen, 0);
            t.stream_offset = LayerStreamOffsetBench(p, lp.kind, lp.layer) +
                              static_cast<uint64_t>(pl.row) * lp.n +
                              static_cast<uint64_t>(pl.bcol) * rc::kRCMxBlockLen;
            t.first_leaf = static_cast<uint32_t>(t.stream_offset / p.T_leaf);
            t.leaf_bytes.emplace_back(p.T_leaf, 0);
            t.leaf_proofs.emplace_back();
            t.leaf_proofs.back().siblings.resize(rep.tree_depth);
            ++rep.merkle_openings;
            rep.merkle_hashes += rep.tree_depth;
            if (lp.kind == rc::RCGkrLayerKind::GemmPhase2Fwd && lp.layer > 0) {
                t.a_row_leaf.assign(p.T_leaf, 0);
                t.a_row_proof.siblings.resize(rep.tree_depth);
                ++rep.merkle_openings;
                rep.merkle_hashes += rep.tree_depth;
            } else {
                t.a_prf_regen = true;
            }
            e.tiles.push_back(std::move(t));
        }
        skeleton.sampled.push_back(std::move(e));
    }
    std::vector<unsigned char> wire;
    rc::SerializeRCFreivaldsCarrier(skeleton, wire);
    rep.carrier_bytes = wire.size();

    struct PlannedRegenSeed {
        uint32_t rows{0};
        uint32_t cols{0};
        uint32_t uses{0};
    };
    std::map<uint256, PlannedRegenSeed> planned_regen_seed_bytes;
    auto note_planned_seed = [&](const uint256& seed, uint32_t rows, uint32_t cols) {
        auto it = planned_regen_seed_bytes.find(seed);
        if (it == planned_regen_seed_bytes.end()) {
            planned_regen_seed_bytes.emplace(seed, PlannedRegenSeed{rows, cols, 1});
        } else {
            BOOST_REQUIRE_EQUAL(it->second.rows, rows);
            BOOST_REQUIRE_EQUAL(it->second.cols, cols);
            ++it->second.uses;
        }
    };
    auto note_planned_x0_row = [&](const rc::RCGkrSampledOperandProv& xprov, uint32_t row,
                                   uint32_t d_model) {
        if (xprov.x0_row_blocks) {
            BOOST_REQUIRE_EQUAL(xprov.erows, p.b_seq);
            BOOST_REQUIRE_EQUAL(xprov.ecols, d_model);
            BOOST_REQUIRE_LT(row, p.b_seq);
            note_planned_seed(rc::DeriveX0RowBlockSeed(xprov.seed, row / rc::kRCX0RowBlockRows),
                              rc::kRCX0RowBlockRows, d_model);
        } else {
            note_planned_seed(xprov.seed, p.b_seq, d_model);
        }
    };
    for (uint32_t u : units) {
        const uint32_t li = sampleable[u];
        const auto& lp = prov[li];
        if (lp.kind == rc::RCGkrLayerKind::GemmPhase1SV) {
            const auto& qkt = prov[lp.a.src_idx];
            note_planned_seed(qkt.a.seed, p.n_q, p.d_head);
            note_planned_seed(qkt.b.seed, p.n_ctx, p.d_head);
            note_planned_seed(lp.b.seed, p.n_ctx, p.d_head);
        } else if (lp.kind == rc::RCGkrLayerKind::GemmPhase2Fwd) {
            const auto& up = prov[lp.a.src_idx];
            if (up.a.is_leaf) {
                for (const TilePlanBench& pl : TilePositionsBench(base_seed, li, lp.m, lp.n)) {
                    note_planned_x0_row(up.a, pl.row, p.d_model);
                }
            }
            note_planned_seed(up.b.seed, p.d_model, p.d_ff);
            note_planned_seed(lp.b.seed, p.d_ff, p.d_model);
        }
    }
    rep.planned_regen_misses_full = planned_regen_seed_bytes.size();
    rep.planned_regen_bytes_full = 0;
    for (const auto& [seed, shape] : planned_regen_seed_bytes) {
        (void)seed;
        rep.planned_regen_bytes_full += static_cast<uint64_t>(shape.rows) * shape.cols;
    }

    std::map<uint256, std::vector<int8_t>> regen;
    const bool use_packed_i8mm = rc::RCDensePackedI8mmAvailable();
    std::map<uint256, std::vector<int8_t>> transposed_w_up;
    auto elapsed = [&](std::chrono::steady_clock::time_point t0) {
        return std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    };
    auto regen_leaf = [&](const uint256& seed, uint32_t rows, uint32_t cols) -> const std::vector<int8_t>& {
        auto it = regen.find(seed);
        if (it != regen.end()) {
            ++rep.regen_hits;
            return it->second;
        }
        ++rep.regen_misses;
        rep.regen_bytes += static_cast<uint64_t>(rows) * cols;
        const auto t0 = std::chrono::steady_clock::now();
        // Match production prewarm: large leaves expand with Parallel even when
        // the outer bench loop is serial (threads=1). Byte-identical to scalar.
        uint32_t expand_threads = 1;
        if (rep.threads <= 1) {
            expand_threads = std::thread::hardware_concurrency();
            if (expand_threads == 0) expand_threads = 1;
        } else {
            expand_threads = rep.threads;
        }
        const std::vector<int8_t>& v =
            regen.emplace(seed, rc::ExpandMxDequantInt8Parallel(seed, rows, cols, expand_threads))
                .first->second;
        rep.regen_s += elapsed(t0);
        return v;
    };
    auto transpose_w_up = [&](const uint256& seed, const std::vector<int8_t>& src,
                              uint32_t rows, uint32_t cols) -> const std::vector<int8_t>& {
        auto it = transposed_w_up.find(seed);
        if (it != transposed_w_up.end()) return it->second;
        return transposed_w_up
            .emplace(seed, use_packed_i8mm ? rc::RCPackDenseI8mmOutputBlocks(src, rows, cols)
                                           : TransposeI8Bench(src, rows, cols))
            .first->second;
    };
    const bool full = std::getenv("BTX_RC_PROD_CARRIER_VERIFY_BENCH_FULL") != nullptr;
    if (const char* env_threads = std::getenv("BTX_RC_PROD_CARRIER_VERIFY_BENCH_THREADS")) {
        const unsigned long requested = std::strtoul(env_threads, nullptr, 10);
        rep.threads = static_cast<uint32_t>(std::clamp<unsigned long>(requested, 1, 64));
    }
    const auto t0 = std::chrono::steady_clock::now();
    const std::vector<uint8_t> dummy_leaf(p.T_leaf, 0);
    rc::RCMerkleProof dummy_proof;
    dummy_proof.siblings.resize(rep.tree_depth);
    if (rep.threads > 1) {
        struct SeedJob {
            uint256 seed;
            uint32_t rows{0};
            uint32_t cols{0};
            std::vector<int8_t> bytes;
        };
        std::vector<SeedJob> seed_jobs;
        seed_jobs.reserve(planned_regen_seed_bytes.size());
        uint64_t planned_uses = 0;
        for (const auto& [seed, shape] : planned_regen_seed_bytes) {
            seed_jobs.push_back(SeedJob{seed, shape.rows, shape.cols, {}});
            planned_uses += shape.uses;
        }
        rep.regen_misses = seed_jobs.size();
        rep.regen_hits = planned_uses > rep.regen_misses ? planned_uses - rep.regen_misses : 0;
        rep.regen_bytes = rep.planned_regen_bytes_full;
        auto run_parallel = [&](size_t n, const auto& fn) {
            std::atomic<size_t> next{0};
            std::vector<std::thread> workers;
            const size_t nth = std::min<size_t>(rep.threads, n == 0 ? 1 : n);
            workers.reserve(nth);
            for (size_t t = 0; t < nth; ++t) {
                workers.emplace_back([&]() {
                    for (;;) {
                        const size_t i = next.fetch_add(1, std::memory_order_relaxed);
                        if (i >= n) break;
                        fn(i);
                    }
                });
            }
            for (auto& w : workers) w.join();
        };

        std::sort(seed_jobs.begin(), seed_jobs.end(), [](const SeedJob& a, const SeedJob& b) {
            const uint64_t abytes = static_cast<uint64_t>(a.rows) * a.cols;
            const uint64_t bbytes = static_cast<uint64_t>(b.rows) * b.cols;
            if (abytes != bbytes) return abytes > bbytes;
            return a.seed < b.seed;
        });
        const auto t_regen = std::chrono::steady_clock::now();
        const uint32_t inner_threads = BenchPrewarmInnerThreads(rep.threads);
        const uint32_t outer_threads = std::max<uint32_t>(1, rep.threads / inner_threads);
        run_parallel(std::min<size_t>(seed_jobs.size(), outer_threads), [&](size_t worker) {
            for (size_t i = worker; i < seed_jobs.size(); i += outer_threads) {
            seed_jobs[i].bytes = rc::ExpandMxDequantInt8Parallel(seed_jobs[i].seed,
                                                                 seed_jobs[i].rows,
                                                                 seed_jobs[i].cols,
                                                                 inner_threads);
            }
        });
        rep.regen_s = elapsed(t_regen);
        for (auto& job : seed_jobs) {
            regen.emplace(job.seed, std::move(job.bytes));
        }

        struct TransposeJobBench {
            uint256 seed;
            uint32_t rows{0};
            uint32_t cols{0};
        };
        std::vector<TransposeJobBench> transpose_seeds;
        for (const auto& [seed, shape] : planned_regen_seed_bytes) {
            if ((shape.rows == p.d_model && shape.cols == p.d_ff) ||
                (shape.rows == p.d_ff && shape.cols == p.d_model)) {
                transpose_seeds.push_back(TransposeJobBench{seed, shape.rows, shape.cols});
            }
        }
        const auto t_transpose = std::chrono::steady_clock::now();
        std::vector<std::vector<int8_t>> transposed_jobs(transpose_seeds.size());
        run_parallel(transpose_seeds.size(), [&](size_t i) {
            const auto& W = regen.find(transpose_seeds[i].seed)->second;
            transposed_jobs[i] = use_packed_i8mm
                ? rc::RCPackDenseI8mmOutputBlocks(W, transpose_seeds[i].rows, transpose_seeds[i].cols)
                : TransposeI8Bench(W, transpose_seeds[i].rows, transpose_seeds[i].cols);
        });
        for (size_t i = 0; i < transpose_seeds.size(); ++i) {
            transposed_w_up.emplace(transpose_seeds[i].seed, std::move(transposed_jobs[i]));
        }
        rep.recompute_s += elapsed(t_transpose);

        struct UnitPartial {
            bool ok{true};
            uint64_t extract_tiles{0};
            uint32_t checked_merkle_openings{0};
            uint64_t checked_merkle_hashes{0};
            uint64_t recompute_macs{0};
            uint64_t checksum{0};
        };
        std::vector<UnitPartial> partials(units.size());
        const auto t_compute = std::chrono::steady_clock::now();
        run_parallel(units.size(), [&](size_t ui) {
            UnitPartial local;
            const uint32_t li = sampleable[units[ui]];
            const auto& lp = prov[li];
            const std::vector<TilePlanBench> tile_plans = TilePositionsBench(base_seed, li, lp.m, lp.n);
            auto finish_bench_tile = [&](const std::array<int8_t, rc::kRCMxBlockLen>& eo) {
                if (lp.kind == rc::RCGkrLayerKind::GemmPhase2Fwd && lp.layer > 0) {
                    if (!SimulateMerkleOpenBench(dummy_leaf, /*leaf_index=*/0, dummy_proof)) local.ok = false;
                    ++local.checked_merkle_openings;
                    local.checked_merkle_hashes += rep.tree_depth;
                }
                if (!SimulateMerkleOpenBench(dummy_leaf, /*leaf_index=*/0, dummy_proof)) local.ok = false;
                ++local.checked_merkle_openings;
                local.checked_merkle_hashes += rep.tree_depth;
                for (int8_t v : eo) local.checksum = local.checksum * 131u + static_cast<unsigned char>(v);
                ++local.extract_tiles;
            };
            if (lp.kind == rc::RCGkrLayerKind::GemmPhase1SV) {
                for (const TilePlanBench& pl : tile_plans) {
                    const auto& qkt = prov[lp.a.src_idx];
                    const uint32_t d_head = p.d_head;
                    const uint32_t n_ctx = lp.k;
                    local.recompute_macs += static_cast<uint64_t>(n_ctx) * d_head;
                    local.recompute_macs += static_cast<uint64_t>(n_ctx) * rc::kRCMxBlockLen;
                    const std::vector<int8_t>& Q = regen.find(qkt.a.seed)->second;
                    const std::vector<int8_t>& K = regen.find(qkt.b.seed)->second;
                    const std::vector<int8_t>& V = regen.find(lp.b.seed)->second;
                    std::vector<int8_t> S_row(n_ctx);
                    std::array<int64_t, rc::kRCMxBlockLen> blk{};
                    for (uint32_t bt = 0; bt < n_ctx / rc::kRCMxBlockLen; ++bt) {
                        for (uint32_t c = 0; c < rc::kRCMxBlockLen; ++c) {
                            const uint32_t t = bt * rc::kRCMxBlockLen + c;
                            int64_t acc = 0;
                            for (uint32_t d = 0; d < d_head; ++d) {
                                acc += static_cast<int64_t>(Q[static_cast<size_t>(pl.row) * d_head + d]) *
                                       static_cast<int64_t>(K[static_cast<size_t>(t) * d_head + d]);
                            }
                            blk[c] = acc;
                        }
                        const auto so = ExtractBlockBench(qkt.extract_prf, pl.row, bt, blk.data());
                        for (uint32_t c = 0; c < rc::kRCMxBlockLen; ++c)
                            S_row[bt * rc::kRCMxBlockLen + c] = so[c];
                    }
                    std::array<int64_t, rc::kRCMxBlockLen> yblk{};
                    const uint32_t out_col0 = pl.bcol * rc::kRCMxBlockLen;
                    rc::RCDenseRowBlockExactI8(S_row.data(), V.data(), n_ctx, d_head, out_col0,
                                               yblk.data());
                    const std::array<int8_t, rc::kRCMxBlockLen> eo =
                        ExtractBlockBench(lp.extract_prf, pl.row, pl.bcol, yblk.data());
                    finish_bench_tile(eo);
                }
            } else if (lp.kind == rc::RCGkrLayerKind::GemmPhase2Fwd) {
                const auto& up = prov[lp.a.src_idx];
                const uint32_t d_model = lp.n;
                const uint32_t d_ff = lp.k;
                const auto& xprov = up.a;
                const std::vector<int8_t>& W_down_t = transposed_w_up.find(lp.b.seed)->second;
                const std::vector<int8_t>& W_up_t = transposed_w_up.find(up.b.seed)->second;
                auto load_x_row = [&](const TilePlanBench& pl, std::vector<int8_t>& X_row) {
                    X_row.assign(d_model, 0);
                    if (xprov.is_leaf) {
                        if (xprov.x0_row_blocks) {
                            const uint32_t block = pl.row / rc::kRCX0RowBlockRows;
                            const uint32_t rel = pl.row % rc::kRCX0RowBlockRows;
                            const std::vector<int8_t>& X0 =
                                regen.find(rc::DeriveX0RowBlockSeed(xprov.seed, block))->second;
                            std::copy_n(X0.data() + static_cast<size_t>(rel) * d_model, d_model,
                                        X_row.data());
                        } else {
                            const std::vector<int8_t>& X0 = regen.find(xprov.seed)->second;
                            std::copy_n(X0.data() + static_cast<size_t>(pl.row) * d_model, d_model,
                                        X_row.data());
                        }
                    } else {
                        for (uint32_t d = 0; d < d_model; ++d) {
                            X_row[d] = static_cast<int8_t>((pl.row + d + lp.layer) & 0x7f);
                        }
                    }
                };
                for (size_t ti = 0; ti < tile_plans.size();) {
                    const bool paired = ti + 1 < tile_plans.size();
                    const TilePlanBench& pl0 = tile_plans[ti];
                    const TilePlanBench* pl1 = paired ? &tile_plans[ti + 1] : nullptr;
                    local.recompute_macs += static_cast<uint64_t>(d_model) * d_ff;
                    local.recompute_macs += static_cast<uint64_t>(d_ff) * rc::kRCMxBlockLen;
                    if (paired) {
                        local.recompute_macs += static_cast<uint64_t>(d_model) * d_ff;
                        local.recompute_macs += static_cast<uint64_t>(d_ff) * rc::kRCMxBlockLen;
                    }
                    std::vector<int8_t> X0;
                    std::vector<int8_t> X1;
                    load_x_row(pl0, X0);
                    if (paired) load_x_row(*pl1, X1);
                    std::vector<int8_t> H0(d_ff);
                    std::vector<int8_t> H1(paired ? d_ff : 0);
                    std::array<int64_t, rc::kRCMxBlockLen> blk{};
                    std::array<int64_t, rc::kRCMxBlockLen> blk1{};
                    for (uint32_t bj = 0; bj < d_ff / rc::kRCMxBlockLen; ++bj) {
                        const uint32_t col0 = bj * rc::kRCMxBlockLen;
                        if (paired) {
                            if (use_packed_i8mm) {
                                rc::RCDenseTwoRowsBlockPackedI8mmExactI8(X0.data(), X1.data(), W_up_t.data(),
                                                                         d_model, d_ff, col0,
                                                                         blk.data(), blk1.data());
                            } else {
                                rc::RCDenseTwoRowsBlockTransposedExactI8(X0.data(), X1.data(), W_up_t.data(),
                                                                         d_model, d_ff, col0,
                                                                         blk.data(), blk1.data());
                            }
                        } else {
                            if (use_packed_i8mm) {
                                rc::RCDenseRowBlockPackedI8mmExactI8(X0.data(), W_up_t.data(), d_model,
                                                                     d_ff, col0, blk.data());
                            } else {
                                rc::RCDenseRowBlockTransposedExactI8(X0.data(), W_up_t.data(), d_model,
                                                                     d_ff, col0, blk.data());
                            }
                        }
                        const auto h0 = ExtractBlockBench(up.extract_prf, pl0.row, bj, blk.data());
                        for (uint32_t c = 0; c < rc::kRCMxBlockLen; ++c)
                            H0[bj * rc::kRCMxBlockLen + c] = h0[c];
                        if (paired) {
                            const auto h1 = ExtractBlockBench(up.extract_prf, pl1->row, bj, blk1.data());
                            for (uint32_t c = 0; c < rc::kRCMxBlockLen; ++c)
                                H1[bj * rc::kRCMxBlockLen + c] = h1[c];
                        }
                    }
                    auto down_tile = [&](const TilePlanBench& pl, const std::vector<int8_t>& X_row,
                                         const std::vector<int8_t>& H_row) {
                        std::array<int64_t, rc::kRCMxBlockLen> yblk{};
                        const uint32_t out_col0 = pl.bcol * rc::kRCMxBlockLen;
                        if (use_packed_i8mm) {
                            rc::RCDenseRowBlockPackedI8mmExactI8(H_row.data(), W_down_t.data(), d_ff,
                                                                 d_model, out_col0, yblk.data());
                        } else {
                            rc::RCDenseRowBlockTransposedExactI8(H_row.data(), W_down_t.data(), d_ff,
                                                                 d_model, out_col0, yblk.data());
                        }
                        for (uint32_t c = 0; c < rc::kRCMxBlockLen; ++c) {
                            yblk[c] += static_cast<int64_t>(X_row[out_col0 + c]);
                        }
                        return ExtractBlockBench(lp.extract_prf, pl.row, pl.bcol, yblk.data());
                    };
                    finish_bench_tile(down_tile(pl0, X0, H0));
                    if (paired) finish_bench_tile(down_tile(*pl1, X1, H1));
                    ti += paired ? 2 : 1;
                }
            }
            partials[ui] = local;
        });
        rep.recompute_s += elapsed(t_compute);
        rep.layers_checked = static_cast<uint32_t>(units.size());
        for (const UnitPartial& part : partials) {
            BOOST_REQUIRE(part.ok);
            rep.extract_tiles += part.extract_tiles;
            rep.checked_merkle_openings += part.checked_merkle_openings;
            rep.checked_merkle_hashes += part.checked_merkle_hashes;
            rep.recompute_macs += part.recompute_macs;
            rep.checksum = rep.checksum * 1315423911u + part.checksum;
        }
        rep.merkle_s = 0.0;
        rep.total_s = elapsed(t0);
        rep.stopped_at_budget = !full && rep.total_s > 0.900;
        return rep;
    }
    for (uint32_t u : units) {
        const uint32_t li = sampleable[u];
        const auto& lp = prov[li];
        const auto t_layer = std::chrono::steady_clock::now();
        const double regen_s_before = rep.regen_s;
        const double recompute_s_before = rep.recompute_s;
        const double merkle_s_before = rep.merkle_s;
        const uint64_t regen_misses_before = rep.regen_misses;
        const uint64_t regen_hits_before = rep.regen_hits;
        const uint64_t regen_bytes_before = rep.regen_bytes;
        const uint64_t extract_tiles_before = rep.extract_tiles;
        if (rep.layers_checked == 0) {
            rep.first_layer_index = li;
            rep.first_layer_kind = static_cast<uint32_t>(lp.kind);
            rep.first_m = lp.m;
            rep.first_n = lp.n;
            rep.first_k = lp.k;
        }
        const double layer_t0 = elapsed(t0);
        const double layer_regen0 = rep.regen_s;
        const double layer_recompute0 = rep.recompute_s;
        const double layer_merkle0 = rep.merkle_s;
        const uint64_t layer_regen_misses0 = rep.regen_misses;
        const uint64_t layer_regen_hits0 = rep.regen_hits;
        const uint64_t layer_regen_bytes0 = rep.regen_bytes;
        const uint64_t layer_extract_tiles0 = rep.extract_tiles;
        const uint32_t layer_checked_merkle_openings0 = rep.checked_merkle_openings;
        const uint64_t layer_checked_merkle_hashes0 = rep.checked_merkle_hashes;
        for (const TilePlanBench& pl : TilePositionsBench(base_seed, li, lp.m, lp.n)) {
            std::array<int8_t, rc::kRCMxBlockLen> eo{};
            if (lp.kind == rc::RCGkrLayerKind::GemmPhase1SV) {
                const auto& qkt = prov[lp.a.src_idx];
                const uint32_t d_head = p.d_head;
                const uint32_t n_ctx = lp.k;
                rep.recompute_macs += static_cast<uint64_t>(n_ctx) * d_head;
                rep.recompute_macs += static_cast<uint64_t>(n_ctx) * rc::kRCMxBlockLen;
                const std::vector<int8_t>& Q = regen_leaf(qkt.a.seed, p.n_q, d_head);
                const std::vector<int8_t>& K = regen_leaf(qkt.b.seed, n_ctx, d_head);
                const std::vector<int8_t>& V = regen_leaf(lp.b.seed, n_ctx, d_head);
                const auto t_rc_sv = std::chrono::steady_clock::now();
                std::vector<int8_t> S_row(n_ctx);
                std::array<int64_t, rc::kRCMxBlockLen> blk{};
                for (uint32_t bt = 0; bt < n_ctx / rc::kRCMxBlockLen; ++bt) {
                    for (uint32_t c = 0; c < rc::kRCMxBlockLen; ++c) {
                        const uint32_t t = bt * rc::kRCMxBlockLen + c;
                        int64_t acc = 0;
                        for (uint32_t d = 0; d < d_head; ++d) {
                            acc += static_cast<int64_t>(Q[static_cast<size_t>(pl.row) * d_head + d]) *
                                   static_cast<int64_t>(K[static_cast<size_t>(t) * d_head + d]);
                        }
                        blk[c] = acc;
                    }
                    const auto so = ExtractBlockBench(qkt.extract_prf, pl.row, bt, blk.data());
                    for (uint32_t c = 0; c < rc::kRCMxBlockLen; ++c)
                        S_row[bt * rc::kRCMxBlockLen + c] = so[c];
                }
                std::array<int64_t, rc::kRCMxBlockLen> yblk{};
                const uint32_t out_col0 = pl.bcol * rc::kRCMxBlockLen;
                rc::RCDenseRowBlockExactI8(S_row.data(), V.data(), n_ctx, d_head, out_col0,
                                           yblk.data());
                eo = ExtractBlockBench(lp.extract_prf, pl.row, pl.bcol, yblk.data());
                rep.recompute_s += elapsed(t_rc_sv);
            } else if (lp.kind == rc::RCGkrLayerKind::GemmPhase2Fwd) {
                const auto& up = prov[lp.a.src_idx];
                const uint32_t d_model = lp.n;
                const uint32_t d_ff = lp.k;
                rep.recompute_macs += static_cast<uint64_t>(d_model) * d_ff;
                rep.recompute_macs += static_cast<uint64_t>(d_ff) * rc::kRCMxBlockLen;
                std::vector<int8_t> X_row(d_model);
                const auto& xprov = up.a;
                if (xprov.is_leaf) {
                    if (xprov.x0_row_blocks) {
                        const uint32_t block = pl.row / rc::kRCX0RowBlockRows;
                        const uint32_t rel = pl.row % rc::kRCX0RowBlockRows;
                        const std::vector<int8_t>& X0 =
                            regen_leaf(rc::DeriveX0RowBlockSeed(xprov.seed, block),
                                       rc::kRCX0RowBlockRows, d_model);
                        std::copy_n(X0.data() + static_cast<size_t>(rel) * d_model, d_model,
                                    X_row.data());
                    } else {
                        const std::vector<int8_t>& X0 = regen_leaf(xprov.seed, p.b_seq, d_model);
                        std::copy_n(X0.data() + static_cast<size_t>(pl.row) * d_model, d_model,
                                    X_row.data());
                    }
                } else {
                    // In the real carrier this row is copied from a T_leaf
                    // committed activation leaf. Its values do not affect
                    // verifier cost; the copy shape is the load-bearing part.
                    for (uint32_t d = 0; d < d_model; ++d) {
                        X_row[d] = static_cast<int8_t>((pl.row + d + lp.layer) & 0x7f);
                    }
                }
                const std::vector<int8_t>& W_up = regen_leaf(up.b.seed, d_model, d_ff);
                const std::vector<int8_t>& W_down = regen_leaf(lp.b.seed, d_ff, d_model);
                const auto t_rc_dn = std::chrono::steady_clock::now();
                const std::vector<int8_t>& W_up_t = transpose_w_up(up.b.seed, W_up, d_model, d_ff);
                const std::vector<int8_t>& W_down_t =
                    transpose_w_up(lp.b.seed, W_down, d_ff, d_model);
                std::vector<int8_t> H_row(d_ff);
                std::array<int64_t, rc::kRCMxBlockLen> blk{};
                for (uint32_t bj = 0; bj < d_ff / rc::kRCMxBlockLen; ++bj) {
                    const uint32_t col0 = bj * rc::kRCMxBlockLen;
                    if (use_packed_i8mm) {
                        rc::RCDenseRowBlockPackedI8mmExactI8(X_row.data(), W_up_t.data(), d_model,
                                                             d_ff, col0, blk.data());
                    } else {
                        rc::RCDenseRowBlockTransposedExactI8(X_row.data(), W_up_t.data(), d_model,
                                                             d_ff, col0, blk.data());
                    }
                    const auto ho = ExtractBlockBench(up.extract_prf, pl.row, bj, blk.data());
                    for (uint32_t c = 0; c < rc::kRCMxBlockLen; ++c)
                        H_row[bj * rc::kRCMxBlockLen + c] = ho[c];
                }
                std::array<int64_t, rc::kRCMxBlockLen> yblk{};
                const uint32_t out_col0 = pl.bcol * rc::kRCMxBlockLen;
                if (use_packed_i8mm) {
                    rc::RCDenseRowBlockPackedI8mmExactI8(H_row.data(), W_down_t.data(), d_ff,
                                                         d_model, out_col0, yblk.data());
                } else {
                    rc::RCDenseRowBlockExactI8(H_row.data(), W_down.data(), d_ff, d_model, out_col0,
                                               yblk.data());
                }
                for (uint32_t c = 0; c < rc::kRCMxBlockLen; ++c) {
                    yblk[c] += static_cast<int64_t>(X_row[out_col0 + c]);
                }
                eo = ExtractBlockBench(lp.extract_prf, pl.row, pl.bcol, yblk.data());
                rep.recompute_s += elapsed(t_rc_dn);
            }
            const auto t_mk = std::chrono::steady_clock::now();
            if (lp.kind == rc::RCGkrLayerKind::GemmPhase2Fwd && lp.layer > 0) {
                BOOST_REQUIRE(SimulateMerkleOpenBench(dummy_leaf, /*leaf_index=*/0, dummy_proof));
                ++rep.checked_merkle_openings;
                rep.checked_merkle_hashes += rep.tree_depth;
            }
            BOOST_REQUIRE(SimulateMerkleOpenBench(dummy_leaf, /*leaf_index=*/0, dummy_proof));
            ++rep.checked_merkle_openings;
            rep.checked_merkle_hashes += rep.tree_depth;
            rep.merkle_s += elapsed(t_mk);
            for (int8_t v : eo) rep.checksum = rep.checksum * 131u + static_cast<unsigned char>(v);
            ++rep.extract_tiles;
        }
        if (rep.layers_checked == 0) {
            rep.first_layer_total_s = elapsed(t0) - layer_t0;
            rep.first_layer_regen_s = rep.regen_s - layer_regen0;
            rep.first_layer_recompute_s = rep.recompute_s - layer_recompute0;
            rep.first_layer_merkle_s = rep.merkle_s - layer_merkle0;
            rep.first_layer_regen_misses = rep.regen_misses - layer_regen_misses0;
            rep.first_layer_regen_hits = rep.regen_hits - layer_regen_hits0;
            rep.first_layer_regen_bytes = rep.regen_bytes - layer_regen_bytes0;
            rep.first_layer_extract_tiles = rep.extract_tiles - layer_extract_tiles0;
            rep.first_layer_checked_merkle_openings =
                rep.checked_merkle_openings - layer_checked_merkle_openings0;
            rep.first_layer_checked_merkle_hashes =
                rep.checked_merkle_hashes - layer_checked_merkle_hashes0;
        }
        ++rep.layers_checked;
        if (rep.layers_checked == 1) {
            rep.first_layer_total_s = elapsed(t_layer);
            rep.first_layer_regen_s = rep.regen_s - regen_s_before;
            rep.first_layer_recompute_s = rep.recompute_s - recompute_s_before;
            rep.first_layer_merkle_s = rep.merkle_s - merkle_s_before;
            rep.first_layer_regen_misses = rep.regen_misses - regen_misses_before;
            rep.first_layer_regen_hits = rep.regen_hits - regen_hits_before;
            rep.first_layer_regen_bytes = rep.regen_bytes - regen_bytes_before;
            rep.first_layer_extract_tiles = rep.extract_tiles - extract_tiles_before;
        }
        rep.total_s = elapsed(t0);
        if (!full && rep.total_s > 0.900) {
            rep.stopped_at_budget = true;
            break;
        }
    }
    rep.total_s = elapsed(t0);
    return rep;
}
} // namespace

// Off-CI production-shape verifier compute benchmark. This deliberately remains
// opt-in because it executes production-dimension PRF/GEMM/Extract verifier work.
// Normal test runs only prove the benchmark is compiled and available.
BOOST_AUTO_TEST_CASE(rc_dc_production_carrier_verify_compute_benchmark)
{
    if (std::getenv("BTX_RC_PROD_CARRIER_VERIFY_BENCH") == nullptr) {
        BOOST_TEST_MESSAGE("production carrier verify compute benchmark skipped; set BTX_RC_PROD_CARRIER_VERIFY_BENCH=1");
        BOOST_CHECK(true);
        return;
    }

    const auto rep = RunProductionCarrierVerifierComputeBench();
    BOOST_TEST_MESSAGE("production carrier verify compute benchmark: total_ms="
                       << (rep.total_s * 1000.0)
                       << " regen_s=" << rep.regen_s
                       << " recompute_s=" << rep.recompute_s
                       << " merkle_s=" << rep.merkle_s
                       << " threads=" << rep.threads
                       << " prewarm_s=" << rep.regen_s
                       << " unitcheck_s=" << rep.recompute_s
                       << " reduce_s=0"
                       << " first_layer_total_s=" << rep.first_layer_total_s
                       << " first_layer_regen_s=" << rep.first_layer_regen_s
                       << " first_layer_recompute_s=" << rep.first_layer_recompute_s
                       << " first_layer_merkle_s=" << rep.first_layer_merkle_s
                       << " budget_ms=900"
                       << " stopped_at_budget=" << (rep.stopped_at_budget ? 1 : 0)
                       << " units_total=" << rep.units_total
                       << " sampled_total=" << rep.sampled_total
                       << " first_layer_index=" << rep.first_layer_index
                       << " first_layer_kind=" << rep.first_layer_kind
                       << " first_m=" << rep.first_m
                       << " first_n=" << rep.first_n
                       << " first_k=" << rep.first_k
                       << " first_layer_ms=" << (rep.first_layer_total_s * 1000.0)
                       << " first_layer_regen_ms=" << (rep.first_layer_regen_s * 1000.0)
                       << " first_layer_recompute_ms=" << (rep.first_layer_recompute_s * 1000.0)
                       << " first_layer_merkle_ms=" << (rep.first_layer_merkle_s * 1000.0)
                       << " first_layer_regen_misses=" << rep.first_layer_regen_misses
                       << " first_layer_regen_hits=" << rep.first_layer_regen_hits
                       << " first_layer_regen_bytes=" << rep.first_layer_regen_bytes
                       << " first_layer_extract_tiles=" << rep.first_layer_extract_tiles
                       << " layers_checked=" << rep.layers_checked
                       << " extract_tiles=" << rep.extract_tiles
                       << " carrier_bytes=" << rep.carrier_bytes
                       << " tree_depth=" << rep.tree_depth
                       << " merkle_openings=" << rep.merkle_openings
                       << " merkle_hashes=" << rep.merkle_hashes
                       << " checked_merkle_openings=" << rep.checked_merkle_openings
                       << " checked_merkle_hashes=" << rep.checked_merkle_hashes
                       << " first_layer_extract_tiles=" << rep.first_layer_extract_tiles
                       << " first_layer_checked_merkle_openings=" << rep.first_layer_checked_merkle_openings
                       << " first_layer_checked_merkle_hashes=" << rep.first_layer_checked_merkle_hashes
                       << " regen_misses=" << rep.regen_misses
                       << " regen_hits=" << rep.regen_hits
                       << " regen_bytes=" << rep.regen_bytes
                       << " regen_GiB_s=" << (rep.regen_s > 0.0 ? (static_cast<double>(rep.regen_bytes) / (1024.0 * 1024.0 * 1024.0)) / rep.regen_s : 0.0)
                       << " recompute_macs=" << rep.recompute_macs
                       << " recompute_Gmac_s=" << (rep.recompute_s > 0.0 ? (static_cast<double>(rep.recompute_macs) / 1.0e9) / rep.recompute_s : 0.0)
                       << " first_layer_regen_misses=" << rep.first_layer_regen_misses
                       << " first_layer_regen_hits=" << rep.first_layer_regen_hits
                       << " first_layer_regen_bytes=" << rep.first_layer_regen_bytes
                       << " recompute_vectorized=" << (rep.recompute_vectorized ? 1 : 0)
                       << " planned_full_regen_misses=" << rep.planned_regen_misses_full
                       << " planned_full_regen_bytes=" << rep.planned_regen_bytes_full
                       << " checksum=" << rep.checksum);

    BOOST_CHECK_LE(rep.carrier_bytes, rc::kRCFreivaldsCarrierMaxSerializedBytes);
    BOOST_CHECK_MESSAGE(!rep.stopped_at_budget && rep.total_s <= 0.900,
                        "production carrier verify compute exceeds 0.9s budget; see metric line");
}

// (c''') REGRESSION: d_ff is a consensus/relay shape field. A carrier with a
//       cheaper fused-FFN inner width must not authenticate for a profile-2
//       block, even if every other carrier byte came from an honest proof.
BOOST_AUTO_TEST_CASE(rc_dc_authority_profile2_rejects_d_ff_mismatch)
{
    Consensus::Params p = MakeRCActiveParams(/*profile=*/2);
    constexpr int32_t kHeight = 10;
    BOOST_REQUIRE(p.IsMatMulRCActive(kHeight));

    CBlockHeader header = MakeDcRCHeader(0xdff0);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();
    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);
    header.matmul_digest = rc::MineRCEpisode(header, params_rc, kHeight);
    BOOST_REQUIRE(!header.matmul_digest.IsNull());
    const auto target = DeriveTarget(header.nBits, p.powLimit);
    BOOST_REQUIRE(target.has_value());

    rc::RCFreivaldsSampledCarrier carrier;
    BOOST_REQUIRE(BuildToyCarrier(header, params_rc, kHeight, *target, carrier));
    BOOST_REQUIRE_EQUAL(carrier.episode.d_ff, params_rc.d_ff);

    rc::RCFreivaldsSampledCarrier bad = carrier;
    bad.episode.d_ff += rc::kRCMxBlockLen; // keep mod-32 shape-valid, but consensus-wrong
    BOOST_REQUIRE(rc::ValidateRCEpisodeParams(bad.episode));

    // Consensus authority rejects before the sampled carrier can stand in for a
    // cheaper episode shape.
    rc::RCFreivaldsCarrierStoreClear();
    rc::RCFreivaldsCarrierStorePut(header.GetHash(), bad);
    bool carrier_missing = true;
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(header, p, kHeight, &carrier_missing));
    BOOST_CHECK(!carrier_missing); // present-but-wrong is permanent, not transient

    // The relay/carrier semantic gate also rejects the mutated shape: d_ff is
    // bound into the FS seed / layer provenance and cannot be changed under an
    // otherwise honest carrier.
    std::string why;
    BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(bad, header, kHeight, *target, &why));
    BOOST_CHECK_MESSAGE(why.rfind("v7fs:", 0) == 0,
                        "d_ff mismatch should die inside the v7fs carrier gate, got: " << why);
    rc::RCFreivaldsCarrierStoreClear();
}

// (c'''') REGRESSION: the sampled output tile is not self-authenticating relay
//         data. The verifier must recompute X[l+1] =
//         Extract(Extract(X·W_up)·W_down + X) from anchored inputs and reject a
//         forged committed output tile before it can pass via tile-tree tautology.
BOOST_AUTO_TEST_CASE(rc_dc_authority_profile2_forged_output_recompute_rejects)
{
    Consensus::Params p = MakeRCActiveParams(/*profile=*/2);
    constexpr int32_t kHeight = 10;
    BOOST_REQUIRE(p.IsMatMulRCActive(kHeight));

    CBlockHeader header = MakeDcRCHeader(0xf09d);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();
    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);
    header.matmul_digest = rc::MineRCEpisode(header, params_rc, kHeight);
    BOOST_REQUIRE(!header.matmul_digest.IsNull());
    const auto target = DeriveTarget(header.nBits, p.powLimit);
    BOOST_REQUIRE(target.has_value());

    rc::RCFreivaldsSampledCarrier carrier;
    BOOST_REQUIRE(BuildToyCarrier(header, params_rc, kHeight, *target, carrier));
    std::string why;
    BOOST_REQUIRE_MESSAGE(
        rc::VerifyEpisodeFreivaldsSampledCarrier(carrier, header, kHeight, *target, &why),
        "honest carrier must verify: " << why);

    rc::RCFreivaldsSampledCarrier forged = carrier;
    bool flipped = false;
    for (auto& e : forged.sampled) {
        if (e.kind != rc::RCGkrLayerKind::GemmPhase2Fwd) continue;
        for (auto& t : e.tiles) {
            if (!t.extract_out.empty()) {
                t.extract_out[0] ^= 0x1;
                flipped = true;
                break;
            }
        }
        if (flipped) break;
    }
    BOOST_REQUIRE(flipped);

    why.clear();
    BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(forged, header, kHeight, *target, &why));
    BOOST_CHECK_EQUAL(why, "v7fs:recompute_mismatch");

    rc::RCFreivaldsCarrierStoreClear();
    rc::RCFreivaldsCarrierStorePut(header.GetHash(), forged);
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(header, p, kHeight));
    rc::RCFreivaldsCarrierStoreClear();
}

// (f) Carrier serialization round-trips BYTE-EXACT, and the bounded deserializer
//     rejects oversize / truncated / trailing-data / wrong-version input.
BOOST_AUTO_TEST_CASE(rc_dc_carrier_serialize_roundtrip_and_bounds)
{
    Consensus::Params p = MakeRCActiveParams(/*profile=*/2);
    constexpr int32_t kHeight = 10;
    CBlockHeader header = MakeDcRCHeader(0x5151);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();
    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);
    header.matmul_digest = rc::MineRCEpisode(header, params_rc, kHeight);
    BOOST_REQUIRE(!header.matmul_digest.IsNull());
    const auto target = DeriveTarget(header.nBits, p.powLimit);
    BOOST_REQUIRE(target.has_value());

    rc::RCFreivaldsSampledCarrier carrier;
    BOOST_REQUIRE(BuildToyCarrier(header, params_rc, kHeight, *target, carrier));
    BOOST_REQUIRE(!carrier.sampled.empty());   // toy episode has sampleable layers

    std::vector<unsigned char> wire;
    rc::SerializeRCFreivaldsCarrier(carrier, wire);
    BOOST_CHECK(!wire.empty());
    BOOST_CHECK(wire.size() <= rc::kRCFreivaldsCarrierMaxSerializedBytes);

    // Round-trip and re-serialize: byte-exact iff the two wire forms are identical.
    rc::RCFreivaldsSampledCarrier back;
    std::string why;
    BOOST_REQUIRE_MESSAGE(rc::DeserializeRCFreivaldsCarrierBounded(wire, back, &why),
                          "round-trip deserialize failed: " << why);
    std::vector<unsigned char> wire2;
    rc::SerializeRCFreivaldsCarrier(back, wire2);
    BOOST_CHECK(wire == wire2);                       // byte-exact round trip
    // And the recovered carrier still authenticates.
    BOOST_CHECK(rc::VerifyEpisodeFreivaldsSampledCarrier(back, header, kHeight, *target, &why));

    // Oversize input: a frame larger than the ceiling is rejected before parse.
    {
        std::vector<unsigned char> oversize(rc::kRCFreivaldsCarrierMaxSerializedBytes + 1, 0);
        rc::RCFreivaldsSampledCarrier tmp;
        BOOST_CHECK(!rc::DeserializeRCFreivaldsCarrierBounded(oversize, tmp, &why));
    }
    // Truncated input: every prefix short of the full frame must be rejected
    // (never a partial/UB read), and none may spuriously succeed.
    for (size_t cut : {size_t{0}, wire.size() / 3, wire.size() / 2, wire.size() - 1}) {
        rc::RCFreivaldsSampledCarrier tmp;
        Span<const unsigned char> prefix{wire.data(), cut};
        BOOST_CHECK(!rc::DeserializeRCFreivaldsCarrierBounded(prefix, tmp, &why));
    }
    // Trailing data: a well-formed frame with extra bytes appended is rejected.
    {
        std::vector<unsigned char> trailing = wire;
        trailing.push_back(0x00);
        rc::RCFreivaldsSampledCarrier tmp;
        BOOST_CHECK(!rc::DeserializeRCFreivaldsCarrierBounded(trailing, tmp, &why));
    }
    // Wrong version byte: rejected.
    {
        std::vector<unsigned char> badver = wire;
        badver[0] = static_cast<unsigned char>(badver[0] + 1);
        rc::RCFreivaldsSampledCarrier tmp;
        BOOST_CHECK(!rc::DeserializeRCFreivaldsCarrierBounded(badver, tmp, &why));
    }
}

// (g) HALT CLOSURE: a profile-2 node WITHOUT the carrier fail-closed REJECTS a
//     valid block; once the RELAYED carrier (round-tripped through the wire form,
//     as net_processing stores it) is populated, the SAME block ACCEPTS.
BOOST_AUTO_TEST_CASE(rc_dc_carrier_relay_closes_halt)
{
    Consensus::Params p = MakeRCActiveParams(/*profile=*/2);
    constexpr int32_t kHeight = 10;
    CBlockHeader header = MakeDcRCHeader(0x6262);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();
    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);
    header.matmul_digest = rc::MineRCEpisode(header, params_rc, kHeight);
    BOOST_REQUIRE(!header.matmul_digest.IsNull());
    const auto target = DeriveTarget(header.nBits, p.powLimit);
    BOOST_REQUIRE(target.has_value());

    // Non-mining node: no carrier yet → the described halt (fail-closed reject).
    rc::RCFreivaldsCarrierStoreClear();
    rc::RCGkrProofV7StoreClear();
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(header, p, kHeight));

    // Miner builds the carrier; it travels over the wire (serialize → bounded
    // deserialize) exactly as the RCCARRIER relay carries it; the receiver stores
    // the deserialized object.
    rc::RCFreivaldsSampledCarrier carrier;
    BOOST_REQUIRE(BuildToyCarrier(header, params_rc, kHeight, *target, carrier));
    std::vector<unsigned char> wire;
    rc::SerializeRCFreivaldsCarrier(carrier, wire);
    rc::RCFreivaldsSampledCarrier received;
    std::string why;
    BOOST_REQUIRE(rc::DeserializeRCFreivaldsCarrierBounded(wire, received, &why));
    rc::RCFreivaldsCarrierStorePut(header.GetHash(), received);

    // With the relayed carrier populated BEFORE validation, the block ACCEPTS.
    BOOST_CHECK(CheckMatMulProofOfWork_RC(header, p, kHeight));

    // Evicting the carrier reverts to fail-closed reject (proves the store, not
    // some other path, is load-bearing).
    rc::RCFreivaldsCarrierStoreClear();
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(header, p, kHeight));
}

// (h) DoS / soundness of the store gate: a carrier for a DIFFERENT header does
//     not authenticate for this block (so a mis-keyed or spoofed carrier can
//     never make an unrelated block accept), and a tampered carrier is rejected.
BOOST_AUTO_TEST_CASE(rc_dc_carrier_rejects_irrelevant_and_tampered)
{
    Consensus::Params p = MakeRCActiveParams(/*profile=*/2);
    constexpr int32_t kHeight = 10;
    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);
    const auto target_of = [&](const CBlockHeader& h) { return DeriveTarget(h.nBits, p.powLimit); };

    CBlockHeader header_a = MakeDcRCHeader(0x7001);
    header_a.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header_a.nBits = UintToArith256(p.powLimit).GetCompact();
    header_a.matmul_digest = rc::MineRCEpisode(header_a, params_rc, kHeight);
    CBlockHeader header_b = MakeDcRCHeader(0x7002);
    header_b.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header_b.nBits = UintToArith256(p.powLimit).GetCompact();
    header_b.matmul_digest = rc::MineRCEpisode(header_b, params_rc, kHeight);
    BOOST_REQUIRE(header_a.GetHash() != header_b.GetHash());
    const auto ta = target_of(header_a);
    BOOST_REQUIRE(ta.has_value());

    rc::RCFreivaldsSampledCarrier carrier_a;
    BOOST_REQUIRE(BuildToyCarrier(header_a, params_rc, kHeight, *ta, carrier_a));

    // IRRELEVANT: A's carrier stored under B's hash must NOT let B accept — the
    // carrier is header-bound, so its verify fails against B. (This is exactly the
    // consensus check the net-layer 'interested + authenticate' gate mirrors.)
    rc::RCFreivaldsCarrierStoreClear();
    rc::RCFreivaldsCarrierStorePut(header_b.GetHash(), carrier_a);
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(header_b, p, kHeight));

    // TAMPERED: flip a sampled output tile; the carrier no longer authenticates.
    rc::RCFreivaldsSampledCarrier tampered = carrier_a;
    bool flipped = false;
    for (auto& e : tampered.sampled) {
        for (auto& t : e.tiles) {
            if (!t.extract_out.empty()) { t.extract_out[0] ^= 0x1; flipped = true; break; }
        }
        if (flipped) break;
    }
    BOOST_REQUIRE(flipped);
    std::string why;
    BOOST_CHECK(!rc::VerifyEpisodeFreivaldsSampledCarrier(tampered, header_a, kHeight, *ta, &why));
    rc::RCFreivaldsCarrierStoreClear();
    rc::RCFreivaldsCarrierStorePut(header_a.GetHash(), tampered);
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(header_a, p, kHeight));
    rc::RCFreivaldsCarrierStoreClear();
}

// (d) Profile 1: ExactReplay remains the authority, needs NO proof, and accepts
//     an honest episode exactly as before the datacenter cutover.
BOOST_AUTO_TEST_CASE(rc_dc_authority_profile1_exactreplay_unchanged)
{
    Consensus::Params p = MakeRCActiveParams(/*profile=*/1);
    constexpr int32_t kHeight = 10;
    BOOST_REQUIRE(p.IsMatMulRCActive(kHeight));

    CBlockHeader header = MakeDcRCHeader(7);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();
    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);   // toy dims
    header.matmul_digest = rc::MineRCEpisode(header, params_rc, kHeight);
    BOOST_REQUIRE(!header.matmul_digest.IsNull());

    // No proof in the store — profile 1 does not consult it; ExactReplay accepts.
    rc::RCGkrProofV7StoreClear();
    BOOST_CHECK(CheckMatMulProofOfWork_RC(header, p, kHeight));

    // Wrong digest still rejects via ExactReplay.
    CBlockHeader bad = header;
    bad.matmul_digest = uint256::ONE;
    BOOST_CHECK(!CheckMatMulProofOfWork_RC(bad, p, kHeight));
}

// (e) The updated construction invariant ACCEPTS the aggressive datacenter config
//     (profile 2 default + finite regtest height + coupled 16× ASERT) — building
//     the chainparams would abort on a bad invariant, so a clean construct is the
//     positive assertion. Profile ∉ {1,2} is rejected by an assert() at
//     construction (an abort, not catchable here); documented, not exercised.
BOOST_AUTO_TEST_CASE(rc_dc_authority_invariant_accepts_aggressive_config)
{
    ArgsManager args;
    args.ForceSetArg("-regtestrcprofile", "2");
    args.ForceSetArg("-regtestrcheight", "150");
    const auto reg = CreateChainParams(args, ChainType::REGTEST)->GetConsensus();
    BOOST_CHECK_EQUAL(reg.nMatMulRCProfile, 2u);
    BOOST_CHECK_EQUAL(reg.nMatMulRCHeight, 150);
    BOOST_CHECK_EQUAL(reg.nMatMulRCAsertRescaleNum, 16422);
    BOOST_CHECK_EQUAL(reg.nMatMulRCAsertRescaleDen, 1027);

    // Mainnet also constructs with the datacenter default (profile 2) while
    // staying gated (INT32_MAX height, ASERT 1/1).
    const auto main = CreateChainParams(ArgsManager{}, ChainType::MAIN)->GetConsensus();
    BOOST_CHECK_EQUAL(main.nMatMulRCProfile, 2u);
    BOOST_CHECK_EQUAL(main.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(main.nMatMulRCAsertRescaleNum, 1);
    BOOST_CHECK_EQUAL(main.nMatMulRCAsertRescaleDen, 1);
}

// ---------------------------------------------------------------------------
// SEGMENT CARRIER: the datacenter relay-ceiling FIT + WIDTH UNPIN + the coupled
// λ=512 / raised-T_leaf / compute-hash-margin params. The current FULL-operand
// carrier blows the 12 MiB ceiling at production dims (a single Fwd Y is 1 GiB
// int64); the segment carrier's per-layer relay is bounded by the segment
// footprint, independent of m,n,k.
// ---------------------------------------------------------------------------

// (i) At PRODUCTION datacenter dims the segment carrier serializes UNDER the
//     12 MiB ceiling — the size that blows the full-operand carrier.
BOOST_AUTO_TEST_CASE(rc_dc_segment_carrier_fits_production_ceiling)
{
    const rc::RCEpisodeParams dc = rc::MakeDatacenterRCEpisodeParams();

    // The size that BLOWS the ceiling: a single Fwd layer's full operands.
    // Y (int64 b_seq×d_model) alone is ~2.87 GiB — far over the 12 MiB ceiling.
    const uint64_t fwd_Y_bytes = static_cast<uint64_t>(dc.b_seq) * dc.d_model * 8ull;
    BOOST_CHECK_EQUAL(fwd_Y_bytes, 2868903936ull);                 // ~2.87 GiB
    BOOST_CHECK_GT(fwd_Y_bytes, rc::kRCFreivaldsCarrierMaxSerializedBytes);
    // The full-operand carrier carried Y+extract_in+extract_out+A+B for EVERY one
    // of λ sampled layers — utterly over the ceiling. The segment carrier does not.

    // The segment carrier's per-sampled-layer bound is bounded and small.
    const size_t per_layer = rc::RCFreivaldsSegLayerByteBound(dc);
    BOOST_TEST_MESSAGE("segment per-layer relay bound (bytes): " << per_layer);
    // λ=512 sampled layers + the fixed header (round roots/seeds, digests) still
    // fits under the 12 MiB ceiling.
    const size_t fixed = 4 + 8 * 4 + 4 + 3 * 32 + 2 * (dc.rounds * 32u + 4) + 8;
    const size_t total_bound = static_cast<size_t>(rc::kRCFreivaldsSampleCount) * per_layer + fixed;
    BOOST_TEST_MESSAGE("segment carrier upper-bound at DC dims, λ=512 (bytes): " << total_bound);
    BOOST_CHECK_LT(total_bound, rc::kRCFreivaldsCarrierMaxSerializedBytes);
    // And it is a large reduction vs even ONE full Fwd Y.
    BOOST_CHECK_LT(total_bound, fwd_Y_bytes / 50);
}

// (j) WIDTH UNPIN: the per-layer relay bound is INDEPENDENT of d_model (and n_ctx),
//     so a d_model > 4096 episode's carrier still fits — width is no longer pinned
//     by the ~32 MB relay budget of full-operand opening.
BOOST_AUTO_TEST_CASE(rc_dc_segment_carrier_width_unpin)
{
    const rc::RCEpisodeParams dc = rc::MakeDatacenterRCEpisodeParams();
    const size_t bound_4096 = rc::RCFreivaldsSegLayerByteBound(dc);

    // Frontier-ward widths (GPT-3-175B / GPT-4 class contraction). Hold n_ctx
    // (hash-bound guardrail) and depth; only widen d_model. The int32 Extract
    // accumulator invariant d_model·48² < 2^31 still holds to 12288+.
    for (uint32_t dmw : {8192u, 12288u, 16384u}) {
        rc::RCEpisodeParams wide = dc;
        wide.d_model = dmw;
        wide.n_q = 512;                    // keep n_q = 4·d_head (independent of d_model)
        BOOST_REQUIRE(rc::ValidateRCEpisodeParams(wide));
        // The per-layer relay bound is byte-identical — it depends only on the
        // segment granularity + T_leaf, NOT on d_model. This IS the width unpin.
        BOOST_CHECK_EQUAL(rc::RCFreivaldsSegLayerByteBound(wide), bound_4096);
        // A full d_model=dmw episode carrier at λ=512 still fits the ceiling.
        const size_t total = static_cast<size_t>(rc::kRCFreivaldsSampleCount) *
                                 rc::RCFreivaldsSegLayerByteBound(wide) + 4096;
        BOOST_CHECK_LT(total, rc::kRCFreivaldsCarrierMaxSerializedBytes);
        // Whereas the full-operand Fwd Y at this width is even more absurd.
        const uint64_t full_Y = static_cast<uint64_t>(wide.b_seq) * dmw * 8ull;
        BOOST_CHECK_GT(full_Y, 20ull * rc::kRCFreivaldsCarrierMaxSerializedBytes);
    }
}

// (k) The coupled params: λ=512, raised datacenter T_leaf, and the compute/hash
//     margin moved OFF the ~1× knee. Quantify the ratio and assert it improves.
BOOST_AUTO_TEST_CASE(rc_dc_segment_lambda512_tleaf_compute_hash_margin)
{
    // (a) λ raised 256→512 (halves the deterrence residual ρ* ≈ ln κ/λ).
    BOOST_CHECK_EQUAL(rc::kRCFreivaldsSampleCount, 512u);
    // ρ*(κ=2) ≈ ln(2)/λ : 0.271% at λ=256 → 0.135% at λ=512 (halved).
    const double rho_256 = std::log(2.0) / 256.0;
    const double rho_512 = std::log(2.0) / 512.0;
    BOOST_CHECK_CLOSE(rho_256, 0.002707, 1.0);
    BOOST_CHECK_CLOSE(rho_512, 0.001354, 1.0);
    BOOST_CHECK_CLOSE(rho_256 / rho_512, 2.0, 1e-6);

    // (b) datacenter T_leaf raised 1024→4096.
    const rc::RCEpisodeParams dc = rc::MakeDatacenterRCEpisodeParams();
    const rc::RCEpisodeParams base = rc::DefaultConsensusRCEpisodeParams();
    BOOST_CHECK_EQUAL(dc.T_leaf, 4096u);
    BOOST_CHECK_GT(dc.T_leaf, base.T_leaf);

    // (c) compute/hash ratio. Fused FFN commits one output byte per layer but
    // performs up+down work = 2·d_ff MAC per committed byte; the SHA tile-tree
    // processes (1 + 64/T_leaf) bytes per committed byte (leaf content + 64-byte
    // internal nodes). Normalize by a balanced-node knee ≈6400 MAC/SHA-byte.
    auto hash_overhead = [](uint32_t t_leaf) { return 1.0 + 64.0 / t_leaf; };
    auto ratio = [&](const rc::RCEpisodeParams& p) {
        return 2.0 * p.d_ff / hash_overhead(p.T_leaf);
    };
    const double knee = 6400.0;
    const double r_epoch0 = ratio(base);   // d_ff=16384, T_leaf=1024
    const double r_dc = ratio(dc);         // d_ff=16384, T_leaf=4096
    const double margin_epoch0 = r_epoch0 / knee;
    const double margin_dc = r_dc / knee;
    BOOST_TEST_MESSAGE("compute/hash margin epoch-0 (T_leaf=1024): " << margin_epoch0);
    BOOST_TEST_MESSAGE("compute/hash margin datacenter (T_leaf=4096): " << margin_dc);
    BOOST_TEST_MESSAGE("improvement factor: " << (r_dc / r_epoch0));
    // The raise moves the margin OFF the ~0.90 knee upward by the overhead ratio.
    BOOST_CHECK_GT(r_dc, r_epoch0);                       // strictly improved
    BOOST_CHECK_CLOSE(r_dc / r_epoch0,
                      hash_overhead(1024) / hash_overhead(4096), 1e-6); // ≈1.046
    BOOST_CHECK_GT(margin_dc, 5.0);                       // ≈5.04× the knee
    BOOST_CHECK_LT(margin_epoch0, margin_dc);
    const double max_possible = 2.0 * dc.d_ff / 1.0 / knee; // T_leaf → ∞
    BOOST_CHECK_LT(margin_dc, max_possible);
    BOOST_CHECK_GT(max_possible, 5.1);
}

// (h) ASYNC-WORKER MEMO INTEGRITY: the ENC-DR verdict memo's invariant is that a
//     verdict is a PURE FUNCTION OF THE HEADER. A profile-2 false verdict caused
//     solely by a not-yet-arrived carrier is environment-dependent, so the worker
//     must NOT memoize it — otherwise the later carrier-present resubmit would
//     replay the stale false and PERMANENTLY reject a valid block. Once the
//     carrier is present, the (now header-pure) true verdict IS memoized.
BOOST_AUTO_TEST_CASE(rc_dc_worker_does_not_memoize_missing_carrier_verdict)
{
    const Consensus::Params p = MakeRCActiveParams(/*profile=*/2);
    constexpr int32_t kHeight = 10;
    BOOST_REQUIRE(p.IsMatMulRCActive(kHeight));

    // Fresh, unique header/hash so the process-global verdict memo cannot carry a
    // colliding entry from another test/run.
    CBlockHeader header = MakeDcRCHeader(0xD1CED1CEull);
    header.matmul_dim = static_cast<uint16_t>(p.nMatMulV4Dimension);
    header.nBits = UintToArith256(p.powLimit).GetCompact();
    const auto params_rc = rc::ResolveRCEpisodeParams(p, kHeight);
    header.matmul_digest = rc::MineRCEpisode(header, params_rc, kHeight);
    BOOST_REQUIRE(!header.matmul_digest.IsNull());
    const auto target = DeriveTarget(header.nBits, p.powLimit);
    BOOST_REQUIRE(target.has_value());

    auto block = std::make_shared<CBlock>();
    static_cast<CBlockHeader&>(*block) = header;
    const uint256 hash = block->GetHash();

    rc::RCFreivaldsCarrierStoreClear();
    BOOST_REQUIRE(!LookupMatMulEncDrVerdict(hash).has_value());

    const auto wait_completion = [](std::atomic<int>& done) {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{20};
        while (done.load() == 0) {
            if (std::chrono::steady_clock::now() > deadline) break;
            std::this_thread::sleep_for(std::chrono::milliseconds{2});
        }
    };

    // Real predicate (no override), single worker thread.
    node::MatMulVerifyWorker worker{p, /*max_threads=*/1};

    // (1) No carrier: the worker's verdict is false, and it MUST NOT be memoized.
    {
        std::atomic<int> done{0};
        std::atomic<bool> verdict{true};
        node::MatMulVerifyWorker::Job job{block, kHeight, /*parent_mtp=*/std::nullopt,
                                          [&](bool ok) { verdict = ok; done = 1; }};
        BOOST_REQUIRE(worker.Enqueue(job));
        wait_completion(done);
        BOOST_REQUIRE_EQUAL(done.load(), 1);
        BOOST_CHECK(!verdict.load());                                  // fail-closed
        BOOST_CHECK(!LookupMatMulEncDrVerdict(hash).has_value());      // NOT poisoned
    }

    // (2) Carrier present: verdict is true and now (header-pure) IS memoized.
    {
        const auto pr = rc::ProveWinnerEpisodeV7(header, params_rc, kHeight, *target,
                                                 header.matmul_digest);
        BOOST_REQUIRE(pr.timing.ok);
        rc::RCFreivaldsSampledCarrier carrier;
        std::string why;
        BOOST_REQUIRE(rc::BuildFreivaldsSampledCarrier(pr.proof, header, kHeight, *target,
                                                       carrier, &why));
        rc::RCFreivaldsCarrierStorePut(hash, carrier);

        std::atomic<int> done{0};
        std::atomic<bool> verdict{false};
        node::MatMulVerifyWorker::Job job{block, kHeight, /*parent_mtp=*/std::nullopt,
                                          [&](bool ok) { verdict = ok; done = 1; }};
        BOOST_REQUIRE(worker.Enqueue(job));
        wait_completion(done);
        BOOST_REQUIRE_EQUAL(done.load(), 1);
        BOOST_CHECK(verdict.load());                                   // accepts with carrier
        const auto memo = LookupMatMulEncDrVerdict(hash);
        BOOST_REQUIRE(memo.has_value());
        BOOST_CHECK(*memo);
    }

    worker.Stop();
    rc::RCFreivaldsCarrierStoreClear();
}

BOOST_AUTO_TEST_SUITE_END()
