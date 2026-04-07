// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <matmul/matmul_pow.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <serialize.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>
#include <cstdint>
#include <string_view>

namespace {

uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

CBlockHeader MakeHeader()
{
    CBlockHeader header;
    header.nVersion = 2;
    header.hashPrevBlock = ParseUint256("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    header.hashMerkleRoot = ParseUint256("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
    header.nTime = 1'700'000'000U;
    header.nBits = 0x1e00ffffU;
    header.nNonce64 = 0x0123456789abcdefULL;
    header.matmul_digest = ParseUint256("1111111111111111111111111111111111111111111111111111111111111111");
    header.matmul_dim = 512;
    header.seed_a = ParseUint256("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    header.seed_b = ParseUint256("fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210");
    return header;
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_header_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(header_serialize_roundtrip)
{
    const CBlockHeader header = MakeHeader();

    DataStream ss{};
    ss << header;

    CBlockHeader decoded;
    ss >> decoded;

    BOOST_CHECK_EQUAL(decoded.nVersion, header.nVersion);
    BOOST_CHECK_EQUAL(decoded.hashPrevBlock, header.hashPrevBlock);
    BOOST_CHECK_EQUAL(decoded.hashMerkleRoot, header.hashMerkleRoot);
    BOOST_CHECK_EQUAL(decoded.nTime, header.nTime);
    BOOST_CHECK_EQUAL(decoded.nBits, header.nBits);
    BOOST_CHECK_EQUAL(decoded.nNonce64, header.nNonce64);
    BOOST_CHECK_EQUAL(decoded.matmul_digest, header.matmul_digest);
    BOOST_CHECK_EQUAL(decoded.matmul_dim, header.matmul_dim);
    BOOST_CHECK_EQUAL(decoded.seed_a, header.seed_a);
    BOOST_CHECK_EQUAL(decoded.seed_b, header.seed_b);
}

BOOST_AUTO_TEST_CASE(header_size_is_182_bytes)
{
    const CBlockHeader header = MakeHeader();
    BOOST_CHECK_EQUAL(GetSerializeSize(header), 182U);
}

// TEST: header_setNull_clears_all
BOOST_AUTO_TEST_CASE(header_setnull_clears_all)
{
    CBlockHeader header = MakeHeader();
    header.SetNull();

    BOOST_CHECK(header.matmul_digest.IsNull());
    BOOST_CHECK_EQUAL(header.matmul_dim, 0U);
    BOOST_CHECK(header.seed_a.IsNull());
    BOOST_CHECK(header.seed_b.IsNull());
    BOOST_CHECK_EQUAL(header.nNonce64, 0U);
}

BOOST_AUTO_TEST_CASE(header_hash_excludes_digest)
{
    CBlockHeader a = MakeHeader();
    CBlockHeader b = a;
    b.matmul_digest = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");

    BOOST_CHECK_EQUAL(matmul::ComputeMatMulHeaderHash(a), matmul::ComputeMatMulHeaderHash(b));
    BOOST_CHECK_EQUAL(matmul::DeriveSigma(a), matmul::DeriveSigma(b));
}

BOOST_AUTO_TEST_CASE(header_block_hash_includes_digest)
{
    CBlockHeader a = MakeHeader();
    CBlockHeader b = a;
    b.matmul_digest = ParseUint256("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");

    BOOST_CHECK_NE(a.GetHash(), b.GetHash());
}

// TEST: seed_reconstruction_matches
BOOST_AUTO_TEST_CASE(seed_derivation_exact_bytes)
{
    const CBlockHeader header = MakeHeader();

    const uint256 expected_header_hash = ParseUint256("bfee30c86915bff25c65f33fb69d83475a44289a23f1b8331e8ec29677182461");
    const uint256 expected_sigma = ParseUint256("76586be52cd0af32c79d35da4e702e42ddf2bcf631f1859c5edf4cedaa802a2e");

    BOOST_CHECK_EQUAL(matmul::ComputeMatMulHeaderHash(header), expected_header_hash);
    BOOST_CHECK_EQUAL(matmul::DeriveSigma(header), expected_sigma);
}

// TEST: seed_changes_with_matrix_seed
BOOST_AUTO_TEST_CASE(seed_changes_with_nonce_and_seed)
{
    const CBlockHeader header = MakeHeader();
    const uint256 sigma = matmul::DeriveSigma(header);

    CBlockHeader nonce_changed = header;
    ++nonce_changed.nNonce64;
    BOOST_CHECK_NE(matmul::DeriveSigma(nonce_changed), sigma);

    CBlockHeader seed_changed = header;
    seed_changed.seed_a = ParseUint256("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    BOOST_CHECK_NE(matmul::DeriveSigma(seed_changed), sigma);
}

BOOST_AUTO_TEST_CASE(block_v2_payload_roundtrip)
{
    CBlock block;
    static_cast<CBlockHeader&>(block) = MakeHeader();
    CMutableTransaction coinbase_tx;
    coinbase_tx.vin.resize(1);
    coinbase_tx.vout.resize(1);
    coinbase_tx.vout[0].nValue = 1;
    block.vtx.push_back(MakeTransactionRef(coinbase_tx));
    block.matrix_a_data = {1, 2, 3, 4};
    block.matrix_b_data = {5, 6, 7, 8};

    DataStream ss{};
    ParamsStream ssw{ss, TX_WITH_WITNESS};
    ssw << block;

    CBlock decoded;
    ParamsStream ssr{ss, TX_WITH_WITNESS};
    ssr >> decoded;

    BOOST_REQUIRE_EQUAL(decoded.matrix_a_data.size(), 4U);
    BOOST_REQUIRE_EQUAL(decoded.matrix_b_data.size(), 4U);
    BOOST_CHECK_EQUAL(decoded.matrix_a_data[0], 1U);
    BOOST_CHECK_EQUAL(decoded.matrix_b_data[3], 8U);
}

BOOST_AUTO_TEST_CASE(block_without_payload_roundtrip)
{
    CBlock block;
    static_cast<CBlockHeader&>(block) = MakeHeader();

    DataStream ss{};
    ParamsStream ssw{ss, TX_WITH_WITNESS};
    ssw << block;

    CBlock decoded;
    ParamsStream ssr{ss, TX_WITH_WITNESS};
    ssr >> decoded;

    BOOST_CHECK(decoded.matrix_a_data.empty());
    BOOST_CHECK(decoded.matrix_b_data.empty());
}

BOOST_AUTO_TEST_CASE(block_legacy_encoding_without_payload_is_accepted)
{
    CBlock block;
    static_cast<CBlockHeader&>(block) = MakeHeader();

    DataStream ss{};
    ParamsStream ssw{ss, TX_WITH_WITNESS};
    ssw << static_cast<const CBlockHeader&>(block);
    ssw << block.vtx;

    CBlock decoded;
    ParamsStream ssr{ss, TX_WITH_WITNESS};
    ssr >> decoded;

    BOOST_CHECK_EQUAL(decoded.nVersion, block.nVersion);
    BOOST_CHECK_EQUAL(decoded.hashPrevBlock, block.hashPrevBlock);
    BOOST_CHECK_EQUAL(decoded.hashMerkleRoot, block.hashMerkleRoot);
    BOOST_CHECK(decoded.matrix_a_data.empty());
    BOOST_CHECK(decoded.matrix_b_data.empty());
}

BOOST_AUTO_TEST_SUITE_END()
