// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <cuda/matmul_v4_rc_episode_context.h>
#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_rc_batch.h>
#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_datacenter.h>

#include <consensus/params.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <limits>
#include <set>
#include <string>
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

} // namespace

BOOST_AUTO_TEST_CASE(rc_dc_heights_remain_int32_max)
{
    Consensus::Params consensus;
    BOOST_CHECK_EQUAL(consensus.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK_EQUAL(consensus.nMatMulRCCoupledHeight, std::numeric_limits<int32_t>::max());
}

BOOST_AUTO_TEST_CASE(rc_dc_consensus_flags_default_off)
{
    BOOST_CHECK(!dc::kRCCoupFullBankScheduleEnabled);
    BOOST_CHECK(!dc::kRCCoupMaterialExchangeEnabled);
    BOOST_CHECK(!dc::kRCThreeAxisScheduleWireEnabled);
    BOOST_CHECK_EQUAL(dc::kRCCoupPagesPerBarrierLobe, 12u);
    BOOST_CHECK_EQUAL(dc::kRCCoupExchangeRowsDefault, 128u);
    BOOST_CHECK_EQUAL(dc::kRCMinerBatchQDefault, 32u);
    BOOST_CHECK_EQUAL(dc::kRCMinerBatchQMax, 256u);
    BOOST_CHECK_EQUAL(dc::kRCPackedBankTargetGiBCount, 4u);
    BOOST_CHECK_CLOSE(dc::kRCMxPackedBytesPerElem, 0.53125, 1e-12);
}

BOOST_AUTO_TEST_CASE(rc_dc_probe_status_smoke)
{
    const dc::RCDcStatus st = dc::ProbeRCDcStatus();
    BOOST_CHECK(!st.full_bank_schedule);
    BOOST_CHECK(!st.material_exchange);
    BOOST_CHECK(!st.three_axis_wire);
    BOOST_CHECK(st.miner_batch_q_default_on);
    BOOST_CHECK_EQUAL(st.miner_batch_q, dc::kRCMinerBatchQDefault);
    BOOST_CHECK(!st.gkr_arbiter);
    BOOST_CHECK(!st.deficit.empty());
    // Without CUDA experimental, episode TU is the honesty stub.
    BOOST_CHECK_EQUAL(st.cuda_episode_compiled, matmul_v4::cuda::IsRcEpisodeCudaCompiled());
    BOOST_CHECK(!st.cuda_episode_ready);
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

BOOST_AUTO_TEST_CASE(rc_dc_full_schedule_flag_off_keeps_legacy_digest)
{
    const auto params = rc::MakeToyRCCoupParams();
    const auto header = MakeCoupHeader(99);
    rc::RCCoupOptions opts;
    opts.full_bank_schedule = false;
    const uint256 d0 = rc::RecomputeCoupledPuzzleReference(header, 0, params, opts);
    const uint256 d1 = rc::MineRCCoupledEpisode(header, 0, params);
    BOOST_CHECK(d0 == d1);

    // Explicit full_schedule override changes the digest (research path).
    opts.full_bank_schedule = true;
    const uint256 d_full = rc::RecomputeCoupledPuzzleReference(header, 0, params, opts);
    BOOST_CHECK(d_full != d0);
}

BOOST_AUTO_TEST_CASE(rc_dc_getenv_cannot_flip_consensus_digest)
{
    // P0: BTX_RC_COUP_FULL_BANK_SCHEDULE / MATERIAL_EXCHANGE must not change digests.
    const auto params = rc::MakeToyRCCoupParams();
    const auto header = MakeCoupHeader(12345);
    rc::RCCoupOptions opts; // full_bank_schedule defaults false

    ::setenv("BTX_RC_COUP_FULL_BANK_SCHEDULE", "1", /*overwrite=*/1);
    ::setenv("BTX_RC_COUP_MATERIAL_EXCHANGE", "1", /*overwrite=*/1);
    BOOST_CHECK(!dc::RCCoupFullBankScheduleActive());
    BOOST_CHECK(!dc::RCCoupMaterialExchangeActive());
    const uint256 with_env = rc::RecomputeCoupledPuzzleReference(header, 0, params, opts);

    ::unsetenv("BTX_RC_COUP_FULL_BANK_SCHEDULE");
    ::unsetenv("BTX_RC_COUP_MATERIAL_EXCHANGE");
    const uint256 without_env = rc::RecomputeCoupledPuzzleReference(header, 0, params, opts);
    BOOST_CHECK(with_env == without_env);
    BOOST_CHECK(with_env == rc::MineRCCoupledEpisode(header, 0, params));
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

BOOST_AUTO_TEST_CASE(rc_dc_cuda_episode_context_stub)
{
    matmul_v4::cuda::RCCudaEpisodeContext ctx;
    std::string err;
    BOOST_CHECK(ctx.Init(rc::MakeToyRCCoupParams(), /*batch_q=*/dc::kRCMinerBatchQDefault, &err));
    BOOST_CHECK(ctx.Ready());
    const auto pages = rc::DeriveCoupledBankPages(MakeCoupHeader(1), 0, rc::MakeToyRCCoupParams());
    BOOST_CHECK(ctx.LoadBank(pages, &err));
    BOOST_CHECK(!ctx.RunBarrierGraph(&err));
    BOOST_CHECK(err.find("graph_unavailable") != std::string::npos);
    BOOST_CHECK(err.find("not_wired") != std::string::npos);
    ctx.Destroy();
    BOOST_CHECK(!ctx.Ready());
}

BOOST_AUTO_TEST_SUITE_END()
