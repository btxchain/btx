// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_v4_lt.h>
#include <matmul/accel_v4.h>

#include <primitives/block.h>
#include <span.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <string_view>
#include <vector>

namespace lt = matmul::v4::lt;

BOOST_FIXTURE_TEST_SUITE(matmul_v4_lt_tests, BasicTestingSetup)

namespace {

constexpr uint32_t kTestDim = 64;

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

CBlockHeader MakeLTHeader(uint64_t nonce, uint32_t n)
{
    CBlockHeader header;
    header.nVersion = 0x20000004;
    header.hashPrevBlock = ParseUint256("5151515151515151515151515151515151515151515151515151515151515151");
    header.hashMerkleRoot = ParseUint256("a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3a3");
    header.nTime = 1'770'000'000;
    header.nBits = 0x207fffff;
    header.nNonce64 = nonce;
    header.nNonce = static_cast<uint32_t>(nonce);
    header.matmul_dim = static_cast<uint16_t>(n);
    header.seed_a = ParseUint256("1111111111111111111111111111111111111111111111111111111111111111");
    header.seed_b = ParseUint256("2222222222222222222222222222222222222222222222222222222222222222");
    return header;
}

} // namespace

BOOST_AUTO_TEST_CASE(fold_int32_to_emax48_range)
{
    // Legacy linear fold — non-normative; retained for differential tests.
    for (int32_t y = -5000; y <= 5000; y += 97) {
        const int32_t v = lt::FoldInt32ToEmax48(y);
        BOOST_CHECK(v >= -48 && v <= 48);
    }
    BOOST_CHECK_EQUAL(lt::FoldInt32ToEmax48(0), -48);
    BOOST_CHECK_EQUAL(lt::FoldInt32ToEmax48(48), 0);
    BOOST_CHECK_EQUAL(lt::FoldInt32ToEmax48(96), 48);
}

BOOST_AUTO_TEST_CASE(matexpand_extract_range_and_determinism)
{
    constexpr uint64_t salt = 0xC0FFEEULL;
    for (int32_t raw = -2000; raw <= 2000; raw += 17) {
        const int8_t a = lt::ExtractDequantMatExpand(raw, 3, 5, salt);
        const int8_t b = lt::ExtractDequantMatExpand(raw, 3, 5, salt);
        BOOST_CHECK_EQUAL(a, b);
        BOOST_CHECK(a >= -48 && a <= 48);
    }
}

BOOST_AUTO_TEST_CASE(matexpand_not_affine_in_raw)
{
    // Linear fold satisfies f(x+d)-f(x) period structure; Mix+M11 Extract must not
    // coincide with Fold on a dense sample (non-collapse witness).
    constexpr uint64_t salt = 0xA5A5A5A5ULL;
    int disagreements = 0;
    for (int32_t y = -500; y <= 500; ++y) {
        if (lt::ExtractDequantMatExpand(y, 0, 0, salt) !=
            static_cast<int8_t>(lt::FoldInt32ToEmax48(y))) {
            ++disagreements;
        }
    }
    BOOST_CHECK(disagreements > 100);

    // Homogeneity collapse f(2x)=2f(x) must fail for a non-zero sample point.
    bool homogeneity_broken = false;
    for (int32_t x = 1; x <= 200; ++x) {
        const int8_t fx = lt::ExtractDequantMatExpand(x, 1, 2, salt);
        const int8_t f2x = lt::ExtractDequantMatExpand(2 * x, 1, 2, salt);
        if (fx != 0 && f2x != static_cast<int8_t>(2 * fx)) {
            homogeneity_broken = true;
            break;
        }
    }
    BOOST_CHECK(homogeneity_broken);
}

BOOST_AUTO_TEST_CASE(matexpand_position_salt_differential)
{
    constexpr uint64_t salt = 0x1234567890ABCDEFULL;
    const int32_t raw = 42;
    BOOST_CHECK(lt::ExtractDequantMatExpand(raw, 0, 0, salt) !=
                    lt::ExtractDequantMatExpand(raw, 1, 0, salt) ||
                lt::MixMatExpandEntry(raw, 0, 0, salt) !=
                    lt::MixMatExpandEntry(raw, 1, 0, salt));
    BOOST_CHECK(lt::MixMatExpandEntry(raw, 0, 0, salt) !=
                lt::MixMatExpandEntry(raw, 0, 1, salt));
    BOOST_CHECK(lt::MixMatExpandEntry(raw, 0, 0, salt) !=
                lt::MixMatExpandEntry(raw, 0, 0, salt ^ 1));
}

BOOST_AUTO_TEST_CASE(plan_lt_accel_known_classes)
{
    const auto b200 = lt::PlanLTAccel("b200");
    BOOST_CHECK(b200.projection == matmul::v4::bmx4::ProjectionLane::ScalePartitionedMxfp4);
    const auto cpu = lt::PlanLTAccel("cpu");
    BOOST_CHECK(cpu.projection == matmul::v4::bmx4::ProjectionLane::CanonicalInt8);
}

BOOST_AUTO_TEST_CASE(accel_dispatch_matches_reference)
{
    auto header = MakeLTHeader(21, kTestDim);
    std::vector<CBlockHeader> headers{header};
    std::vector<uint256> digests;
    std::vector<std::vector<unsigned char>> payloads;
    BOOST_REQUIRE(matmul_v4::accel::ComputeDigestsBMX4CLTDispatched(
        headers, kTestDim, /*rounds=*/2, uint256::ONE, digests, payloads));
    BOOST_REQUIRE_EQUAL(digests.size(), 1U);
    BOOST_REQUIRE_EQUAL(payloads.size(), 1U);
    uint256 ref;
    std::vector<unsigned char> ref_payload;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, ref, ref_payload));
    BOOST_CHECK(digests[0] == ref);
    BOOST_CHECK(payloads[0] == ref_payload);
}

BOOST_AUTO_TEST_CASE(qstar_128_seal_distinct)
{
    BOOST_CHECK(lt::IsValidConsensusQStar(128));
    std::vector<uint256> digests(128);
    for (size_t i = 0; i < digests.size(); ++i) {
        unsigned char b[32]{};
        b[0] = static_cast<unsigned char>(i);
        b[1] = static_cast<unsigned char>(i >> 8);
        digests[i] = uint256{Span<const unsigned char>{b, sizeof(b)}};
    }
    const uint256 root = lt::ComputeWindowMerkleRoot(digests);
    const uint256 sigma = ParseUint256(
        "3333333333333333333333333333333333333333333333333333333333333333");
    BOOST_CHECK(lt::SealWindowCommit(sigma, root, 128) !=
                lt::SealWindowCommit(sigma, root, 64));
}

BOOST_AUTO_TEST_CASE(matexpand_a_template_invariant_b_nonce_fresh)
{
    auto h0 = MakeLTHeader(1, kTestDim);
    auto h1 = MakeLTHeader(2, kTestDim);
    BOOST_CHECK(lt::ExpandOperandAMatExpand(h0, kTestDim) ==
                lt::ExpandOperandAMatExpand(h1, kTestDim));
    BOOST_CHECK(lt::ExpandOperandBMatExpand(h0, kTestDim) !=
                lt::ExpandOperandBMatExpand(h1, kTestDim));
}

BOOST_AUTO_TEST_CASE(digest_determinism_and_nonce_sensitivity)
{
    auto header = MakeLTHeader(7, kTestDim);
    uint256 d1, d2;
    std::vector<unsigned char> p1, p2;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, d1, p1));
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, d2, p2));
    BOOST_CHECK(d1 == d2);
    BOOST_CHECK(p1 == p2);

    header.nNonce64 = 8;
    header.nNonce = 8;
    uint256 d3;
    std::vector<unsigned char> p3;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, d3, p3));
    BOOST_CHECK(d1 != d3);
}

BOOST_AUTO_TEST_CASE(verify_accepts_compute_digest)
{
    auto header = MakeLTHeader(9, kTestDim);
    uint256 digest;
    std::vector<unsigned char> payload;
    BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(header, kTestDim, digest, payload));
    header.matmul_digest = digest;
    uint256 vout;
    BOOST_CHECK(lt::VerifySketchBMX4CLT(header, kTestDim, 2, payload, vout));
    BOOST_CHECK(vout == digest);
}

BOOST_AUTO_TEST_CASE(window_merkle_and_seal)
{
    std::vector<uint256> digests;
    for (int i = 0; i < 4; ++i) {
        char hex[65];
        for (int j = 0; j < 64; ++j) hex[j] = "0123456789abcdef"[(i + j) % 16];
        hex[64] = 0;
        digests.push_back(ParseUint256(hex));
    }
    const uint256 root = lt::ComputeWindowMerkleRoot(digests);
    BOOST_CHECK(!root.IsNull());
    const uint256 sigma = ParseUint256(
        "3333333333333333333333333333333333333333333333333333333333333333");
    BOOST_CHECK(lt::SealWindowCommit(sigma, root, 64) !=
                lt::SealWindowCommit(sigma, root, 128));
    BOOST_CHECK(lt::IsValidConsensusQStar(64));
    BOOST_CHECK(!lt::IsValidConsensusQStar(32));
}

BOOST_AUTO_TEST_CASE(window_miner_matches_reference)
{
    auto tmpl = MakeLTHeader(0, kTestDim);
    lt::WindowSketchMinerLT miner{tmpl, kTestDim};
    BOOST_REQUIRE(miner.Valid());
    const std::vector<uint64_t> nonces{11, 12, 13};
    std::vector<lt::DigestOnlyResultLT> results;
    BOOST_REQUIRE(miner.Mine(nonces, uint256::ONE, results, nullptr));
    BOOST_REQUIRE_EQUAL(results.size(), nonces.size());
    for (size_t i = 0; i < nonces.size(); ++i) {
        auto h = tmpl;
        h.nNonce64 = nonces[i];
        h.nNonce = static_cast<uint32_t>(nonces[i]);
        uint256 ref;
        std::vector<unsigned char> payload;
        BOOST_REQUIRE(lt::ComputeDigestBMX4CLT(h, kTestDim, ref, payload));
        BOOST_CHECK(results[i].digest == ref);
    }
}

BOOST_AUTO_TEST_SUITE_END()
