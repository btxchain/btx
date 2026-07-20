// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4.h>
#include <matmul/matmul_v4_lt.h>
#include <matmul/matmul_v4_rc_coupled.h>

#include <consensus/params.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <limits>
#include <vector>

namespace rc = matmul::v4::rc;
namespace lt = matmul::v4::lt;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_coupled_tests, BasicTestingSetup)

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

bool WrongGemmS8S8(const std::vector<int8_t>& /*L*/, const std::vector<int8_t>& /*R*/,
                   uint32_t rows, uint32_t /*inner*/, uint32_t cols, std::vector<int32_t>& out)
{
    out.assign(static_cast<size_t>(rows) * cols, 123456789);
    return true;
}

bool WrongGemmS32S8(const std::vector<int32_t>& /*L*/, const std::vector<int8_t>& /*R*/,
                    uint32_t rows, uint32_t /*inner*/, uint32_t cols, std::vector<int32_t>& out)
{
    out.assign(static_cast<size_t>(rows) * cols, -999);
    return true;
}

} // namespace

BOOST_AUTO_TEST_CASE(rc_coup_inactive_and_constants)
{
    Consensus::Params consensus;
    BOOST_CHECK_EQUAL(consensus.nMatMulRCHeight, std::numeric_limits<int32_t>::max());
    BOOST_CHECK(!consensus.IsMatMulRCActive(0));
    BOOST_CHECK_EQUAL(rc::kRCCoupRounds, 4u);
    BOOST_CHECK_EQUAL(rc::kRCCoupLobes, 4u);
    BOOST_CHECK_EQUAL(rc::kRCCoupLobeWidth, 32u);
    BOOST_CHECK_EQUAL(rc::kRCCoupStateBytes, 128u);
    BOOST_CHECK_EQUAL(rc::kRCCoupBankPages, 8u);
    BOOST_CHECK_EQUAL(rc::kRCCoupLobeWidth % 32, 0u);
    BOOST_CHECK_EQUAL(rc::kRCCoupStateBytes % 32, 0u);

    const auto toy = rc::MakeToyRCCoupParams();
    BOOST_CHECK(rc::ValidateRCCoupParams(toy));
    BOOST_CHECK_EQUAL(toy.barriers, rc::kRCCoupRounds);
    BOOST_CHECK_EQUAL(toy.lobes, rc::kRCCoupLobes);
    BOOST_CHECK_EQUAL(toy.lobe_width, rc::kRCCoupLobeWidth);
    BOOST_CHECK_EQUAL(toy.bank_pages, rc::kRCCoupBankPages);
    BOOST_CHECK_EQUAL(toy.StateBytes(), rc::kRCCoupStateBytes);

    const auto med = rc::MakeMediumRCCoupParams();
    BOOST_CHECK(rc::ValidateRCCoupParams(med));
    BOOST_CHECK_EQUAL(med.barriers, 8u);
    BOOST_CHECK_EQUAL(med.lobes, 8u);
    BOOST_CHECK_EQUAL(med.lobe_width, 64u);
    BOOST_CHECK_EQUAL(med.bank_pages, 32u);
    BOOST_CHECK_EQUAL(med.StateBytes(), 512u);
    BOOST_CHECK_EQUAL(med.lobe_width % 32, 0u);
    BOOST_CHECK_EQUAL(med.StateBytes() % 32, 0u);
    BOOST_CHECK_EQUAL(med.StateBytes() & (med.StateBytes() - 1), 0u);
}

BOOST_AUTO_TEST_CASE(rc_coup_golden_digest_stable)
{
    // FREEZE toy golden for MakeCoupHeader(42) @ height 0.
    // If the coupled algorithm changes, update this hex deliberately (no silent replace).
    const auto header = MakeCoupHeader(42);
    const uint256 d1 = rc::RecomputeCoupledPuzzleReference(header, /*height=*/0);
    const uint256 d2 = rc::RecomputeCoupledPuzzleReference(header, /*height=*/0);
    BOOST_CHECK(!d1.IsNull());
    BOOST_CHECK(d1 == d2);
    BOOST_CHECK_EQUAL(d1.GetHex(),
                      "c9ac99d002ba26105ef259bfc09fbc0e2ad57bae14b9558d68b82719fa811363");

    // Toy params overload must stay byte-identical to the no-params path.
    const uint256 d_params =
        rc::RecomputeCoupledPuzzleReference(header, 0, rc::MakeToyRCCoupParams());
    BOOST_CHECK(d1 == d_params);
}

BOOST_AUTO_TEST_CASE(rc_coup_medium_golden_digest_stable)
{
    // FREEZE medium golden for MakeCoupHeader(42) + MakeMediumRCCoupParams() @ height 0.
    const auto header = MakeCoupHeader(42);
    const auto params = rc::MakeMediumRCCoupParams();
    const uint256 d1 = rc::RecomputeCoupledPuzzleReference(header, 0, params);
    const uint256 d2 = rc::RecomputeCoupledPuzzleReference(header, 0, params);
    BOOST_CHECK(!d1.IsNull());
    BOOST_CHECK(d1 == d2);
    // Placeholder — replaced after first honest run below if mismatched.
    BOOST_CHECK_EQUAL(d1.GetHex(),
                      "2f731ec6a6909ce895758312bcd9d6aa016bfe5a501513765d345dcba1ff9eb2");
}

BOOST_AUTO_TEST_CASE(rc_coup_mode_equivalence_all_four)
{
    const auto header = MakeCoupHeader(7);
    const rc::RCCoupExecMode modes[] = {
        rc::RCCoupExecMode::SequentialLobes,
        rc::RCCoupExecMode::Checkpointed,
        rc::RCCoupExecMode::Streamed,
        rc::RCCoupExecMode::Resident,
    };

    // Toy
    uint256 toy_ref;
    for (size_t i = 0; i < 4; ++i) {
        rc::RCCoupOptions opt;
        opt.mode = modes[i];
        const uint256 d = rc::RecomputeCoupledPuzzleReference(header, 0, opt);
        if (i == 0) toy_ref = d;
        else BOOST_CHECK(d == toy_ref);
    }

    // Medium
    const auto med = rc::MakeMediumRCCoupParams();
    uint256 med_ref;
    for (size_t i = 0; i < 4; ++i) {
        rc::RCCoupOptions opt;
        opt.mode = modes[i];
        const uint256 d = rc::RecomputeCoupledPuzzleReference(header, 0, med, opt);
        if (i == 0) med_ref = d;
        else BOOST_CHECK(d == med_ref);
    }
    BOOST_CHECK(toy_ref != med_ref);
}

BOOST_AUTO_TEST_CASE(rc_coup_shortcut_skip_barrier_changes_digest)
{
    const auto header = MakeCoupHeader(9);
    const uint256 honest = rc::RecomputeCoupledPuzzleReference(header, 0);
    rc::RCCoupOptions bad;
    bad.skip_barrier = true;
    bad.skip_barrier_index = 2;
    const uint256 cheated = rc::RecomputeCoupledPuzzleReference(header, 0, bad);
    BOOST_CHECK(honest != cheated);
}

BOOST_AUTO_TEST_CASE(rc_coup_shortcut_skip_page_changes_digest)
{
    const auto header = MakeCoupHeader(11);
    const uint256 honest = rc::RecomputeCoupledPuzzleReference(header, 0);
    rc::RCCoupOptions bad;
    bad.skip_bank_page = true;
    bad.skip_page_index = 3;
    const uint256 cheated = rc::RecomputeCoupledPuzzleReference(header, 0, bad);
    BOOST_CHECK(honest != cheated);

    // Streamed skip_page must also diverge.
    rc::RCCoupOptions bad_stream = bad;
    bad_stream.mode = rc::RCCoupExecMode::Streamed;
    const uint256 cheated_stream = rc::RecomputeCoupledPuzzleReference(header, 0, bad_stream);
    BOOST_CHECK(honest != cheated_stream);
}

BOOST_AUTO_TEST_CASE(rc_coup_medium_invariants_and_shortcuts)
{
    // Cross-gap: medium %32 / power-of-two already asserted in constants case;
    // additionally prove shortcut hooks change the medium digest.
    const auto header = MakeCoupHeader(13);
    const auto med = rc::MakeMediumRCCoupParams();
    BOOST_REQUIRE(rc::ValidateRCCoupParams(med));
    BOOST_CHECK_EQUAL(med.lobe_width % 32, 0u);
    BOOST_CHECK_EQUAL(med.StateBytes() % 32, 0u);
    BOOST_CHECK_EQUAL(med.StateBytes() & (med.StateBytes() - 1), 0u);

    const uint256 honest = rc::RecomputeCoupledPuzzleReference(header, 0, med);

    rc::RCCoupOptions skip_b;
    skip_b.skip_barrier = true;
    skip_b.skip_barrier_index = 3;
    BOOST_CHECK(honest != rc::RecomputeCoupledPuzzleReference(header, 0, med, skip_b));

    rc::RCCoupOptions skip_p;
    skip_p.skip_bank_page = true;
    skip_p.skip_page_index = 7;
    BOOST_CHECK(honest != rc::RecomputeCoupledPuzzleReference(header, 0, med, skip_p));
}

BOOST_AUTO_TEST_CASE(rc_coup_device_probe_skip_without_gpu)
{
    // Skip-friendly: without an admitted device backend after RC self-qual,
    // ProbeRCCoupledDevice reports backend_resolved=false and does not claim
    // native MX. With a GPU that passes self-qual, require CPU match.
    const auto probe = rc::ProbeRCCoupledDevice();
    BOOST_CHECK(!probe.detail.empty());
    if (!probe.backend_resolved) {
        BOOST_CHECK_EQUAL(probe.provider, "cpu");
        BOOST_TEST_MESSAGE("RC coupled ExactGemm device path skipped: " << probe.detail);
        return;
    }
    BOOST_REQUIRE(probe.device_gemm_returned);
    BOOST_CHECK(probe.matched_cpu_exactgemm);
    BOOST_TEST_MESSAGE("RC coupled ExactGemm device path provider=" << probe.provider);
}

BOOST_AUTO_TEST_CASE(rc_coup_balanced_perm_hits_every_index_once)
{
    const auto header = MakeCoupHeader(42);
    const uint256 sigma = matmul::v4::DeriveSigma(header);
    for (uint32_t b = 0; b < rc::kRCCoupRounds; ++b) {
        const auto pi = rc::DeriveCoupledBalancedPermutation(sigma, b);
        BOOST_CHECK(rc::IsBalancedPermutation(pi));
        // Explicit: every output index appears exactly once.
        std::array<int, rc::kRCCoupStateBytes> hits{};
        for (uint32_t i = 0; i < rc::kRCCoupStateBytes; ++i) {
            BOOST_REQUIRE(pi[i] < rc::kRCCoupStateBytes);
            hits[pi[i]] += 1;
        }
        for (uint32_t j = 0; j < rc::kRCCoupStateBytes; ++j) {
            BOOST_CHECK_EQUAL(hits[j], 1);
        }
    }
}

BOOST_AUTO_TEST_CASE(rc_coup_nonce_fresh_digest_differs)
{
    const auto h0 = MakeCoupHeader(100);
    const auto h1 = MakeCoupHeader(101);
    const uint256 d0 = rc::RecomputeCoupledPuzzleReference(h0, 0);
    const uint256 d1 = rc::RecomputeCoupledPuzzleReference(h1, 0);
    BOOST_CHECK(d0 != d1);
}

BOOST_AUTO_TEST_CASE(rc_coup_exact_gemm_inject)
{
    const auto header = MakeCoupHeader(42);
    const auto params = rc::MakeToyRCCoupParams();
    const uint256 cpu = rc::RecomputeCoupledPuzzleReference(header, 0, params);

    // Honest wrapping backend must match CPU (device replaces CPU with identical output).
    lt::ExactGemmBackend good;
    good.gemm_s8s8 = +[](const std::vector<int8_t>& L, const std::vector<int8_t>& R,
                         uint32_t rows, uint32_t inner, uint32_t cols,
                         std::vector<int32_t>& out) -> bool {
        out = lt::ExactGemmS8S8(L, R, rows, inner, cols);
        return true;
    };
    good.gemm_s32s8 = +[](const std::vector<int32_t>& L, const std::vector<int8_t>& R,
                          uint32_t rows, uint32_t inner, uint32_t cols,
                          std::vector<int32_t>& out) -> bool {
        out = lt::ExactGemmS32S8(L, R, rows, inner, cols);
        return true;
    };
    const uint256 with_good = rc::MineCoupledPuzzle(header, 0, params, good);
    BOOST_CHECK(cpu == with_good);

    // Wrong-but-successful backend diverges — no silent CPU rescue.
    lt::ExactGemmBackend bad;
    bad.gemm_s8s8 = &WrongGemmS8S8;
    bad.gemm_s32s8 = &WrongGemmS32S8;
    const uint256 with_bad = rc::MineCoupledPuzzle(header, 0, params, bad);
    BOOST_CHECK(cpu != with_bad);
}

BOOST_AUTO_TEST_SUITE_END()
