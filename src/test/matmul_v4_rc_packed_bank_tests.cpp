// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_rc_coupled.h>
#include <matmul/matmul_v4_rc_datacenter.h>
#include <matmul/matmul_v4_rc_packed_bank.h>
#include <matmul/matmul_v4_rc_peak_ready.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(matmul_v4_rc_packed_bank_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(rc_packed_size_v2_768_and_v3_1536)
{
    namespace rc = matmul::v4::rc;
    namespace dc = matmul::v4::rc::dc;
    constexpr uint32_t W = 8192;
    // 768 × 8192² × 17/32 = 25.5 GiB exactly when expressed in double GiB.
    const uint64_t p768 = rc::PackedBytesForBank(768, W);
    const uint64_t e768 = rc::ExpandedBytesForBank(768, W);
    BOOST_CHECK_EQUAL(e768, 768ull * 8192ull * 8192ull);
    BOOST_CHECK_EQUAL(p768, (e768 * 17ull) / 32ull);
    BOOST_CHECK_CLOSE(static_cast<double>(p768) / (1024.0 * 1024.0 * 1024.0), 25.5, 1e-9);
    BOOST_CHECK_CLOSE(static_cast<double>(e768) / (1024.0 * 1024.0 * 1024.0), 48.0, 1e-9);

    const uint64_t p1536 = rc::PackedBytesForBank(1536, W);
    const uint64_t e1536 = rc::ExpandedBytesForBank(1536, W);
    BOOST_CHECK_EQUAL(e1536, 2 * e768);
    BOOST_CHECK_EQUAL(p1536, 2 * p768);
    BOOST_CHECK_CLOSE(static_cast<double>(p1536) / (1024.0 * 1024.0 * 1024.0), 51.0, 1e-9);
    BOOST_CHECK_CLOSE(static_cast<double>(e1536) / (1024.0 * 1024.0 * 1024.0), 96.0, 1e-9);

    BOOST_CHECK_EQUAL(dc::kRCPackedBankV2GiB, 25.5);
    BOOST_CHECK_EQUAL(dc::kRCExpandedBankV2GiB, 48.0);
    BOOST_CHECK_EQUAL(dc::kRCPackedBankPrimaryGiB, 51.0);

    const auto v3 = rc::MakeProductionV3RCCoupParams();
    BOOST_CHECK_EQUAL(v3.bank_pages, 1536u);
    BOOST_CHECK_EQUAL(v3.rows_per_lobe, 128u);
    BOOST_CHECK_EQUAL(v3.pages_per_barrier_lobe, 24u);
    BOOST_CHECK_EQUAL(rc::TotalRCCoupPackedBytes(v3), p1536);
    BOOST_CHECK_EQUAL(rc::TotalRCCoupExpandedBytes(v3), e1536);
    // 12 TiMAC = 12 << 40
    BOOST_CHECK_EQUAL(rc::TotalRCCoupMacs(v3), 12ull << 40);
}

BOOST_AUTO_TEST_CASE(rc_packed_roundtrip_small)
{
    namespace rc = matmul::v4::rc;
    constexpr uint32_t W = 32;
    std::vector<int8_t> page(static_cast<size_t>(W) * W);
    for (size_t i = 0; i < page.size(); ++i) {
        page[i] = static_cast<int8_t>((static_cast<int>(i) % 15) - 7);
    }
    std::vector<uint8_t> packed;
    std::string err;
    BOOST_REQUIRE(rc::PackExpandedPageToCanonical(page.data(), W, packed, &err));
    BOOST_CHECK_EQUAL(packed.size(), rc::PackedBytesForPage(W));
    std::vector<int8_t> back;
    BOOST_REQUIRE(rc::UnpackCanonicalPageToExpanded(packed.data(), packed.size(), W, back, &err));
    BOOST_CHECK(back == page);
}

BOOST_AUTO_TEST_CASE(rc_peak_ready_never_manual_true)
{
    namespace rc = matmul::v4::rc;
    rc::RCPeakReadyInputs empty{};
    const auto st = rc::DeriveRCPeakReady(empty);
    BOOST_CHECK(!st.peak_ready);
    BOOST_CHECK(!st.production_qualified);
    BOOST_CHECK(!st.deficit.empty());
}

BOOST_AUTO_TEST_SUITE_END()
