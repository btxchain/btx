// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <arith_uint256.h>
#include <chainparams.h>
#include <crypto/ethash/helpers.hpp>
#include <crypto/ethash/include/ethash/progpow.hpp>
#include <crypto/kawpow.h>
#include <pow.h>
#include <primitives/block.h>
#include <test/util/setup_common.h>
#include <util/chaintype.h>
#include <util/time.h>

#include <array>
#include <atomic>
#include <cstdlib>
#include <boost/test/unit_test.hpp>
#include <thread>
#include <vector>

namespace {
class ScopedHeaderTimeRefreshEnv
{
public:
    explicit ScopedHeaderTimeRefreshEnv(const char* value)
    {
#if defined(WIN32)
        _putenv_s("BTX_MINER_HEADER_TIME_REFRESH_ATTEMPTS", value != nullptr ? value : "");
#else
        if (value != nullptr) {
            setenv("BTX_MINER_HEADER_TIME_REFRESH_ATTEMPTS", value, 1);
        } else {
            unsetenv("BTX_MINER_HEADER_TIME_REFRESH_ATTEMPTS");
        }
#endif
    }

    ~ScopedHeaderTimeRefreshEnv()
    {
#if defined(WIN32)
        _putenv_s("BTX_MINER_HEADER_TIME_REFRESH_ATTEMPTS", "");
#else
        unsetenv("BTX_MINER_HEADER_TIME_REFRESH_ATTEMPTS");
#endif
    }
};

class ScopedNodeMockTime
{
public:
    explicit ScopedNodeMockTime(int64_t seconds)
    {
        SetMockTime(seconds);
    }

    ~ScopedNodeMockTime()
    {
        SetMockTime(0);
    }
};
} // namespace

BOOST_FIXTURE_TEST_SUITE(kawpow_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(kawpow_hash_30000_vector)
{
    constexpr int block_number{30000};
    const auto header = to_hash256("ffeeddccbbaa9988776655443322110000112233445566778899aabbccddeeff");
    constexpr uint64_t nonce{0x123456789abcdef0};

    const auto context = ethash::create_epoch_context(ethash::get_epoch_number(block_number));
    BOOST_REQUIRE(context);

    const auto result = progpow::hash(*context, block_number, header, nonce);
    BOOST_CHECK_EQUAL(to_hex(result.mix_hash), "177b565752a375501e11b6d9d3679c2df6197b2cab3a1ba2d6b10b8c71a3d459");
    BOOST_CHECK_EQUAL(to_hex(result.final_hash), "c824bee0418e3cfb7fae56e0d5b3b8b14ba895777feea81c70c0ba947146da69");
}

BOOST_AUTO_TEST_CASE(kawpow_wrapper_matches_progpow)
{
    constexpr uint32_t block_height{30000};
    CBlockHeader block;
    block.nVersion = 1;
    block.hashPrevBlock = *uint256::FromHex("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef");
    block.hashMerkleRoot = *uint256::FromHex("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789");
    block.nTime = 1700000000;
    block.nBits = 0x207fffff;
    block.nNonce = 7;
    block.nNonce64 = 0x123456789abcdef0ULL;

    const auto wrapped = kawpow::Hash(block, block_height);
    BOOST_REQUIRE(wrapped.has_value());

    const auto context = ethash::create_epoch_context(ethash::get_epoch_number(static_cast<int>(block_height)));
    BOOST_REQUIRE(context);

    const auto header_hash = to_hash256(kawpow::GetHeaderHash(block, block_height).GetHex());
    const auto direct = progpow::hash(*context, static_cast<int>(block_height), header_hash, block.nNonce64);

    BOOST_CHECK_EQUAL(wrapped->mix_hash.GetHex(), to_hex(direct.mix_hash));
    BOOST_CHECK_EQUAL(wrapped->final_hash.GetHex(), to_hex(direct.final_hash));
}

BOOST_AUTO_TEST_CASE(kawpow_pow_mix_validation)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();

    CBlockHeader block;
    block.nVersion = 1;
    block.hashPrevBlock = *uint256::FromHex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
    block.hashMerkleRoot = *uint256::FromHex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100");
    block.nTime = 1700000100;
    block.nBits = UintToArith256(consensus.powLimit).GetCompact();
    block.nNonce = 0;

    const auto target = DeriveTarget(block.nBits, consensus.powLimit);
    BOOST_REQUIRE(target.has_value());

    constexpr uint32_t block_height{18000};
    std::optional<kawpow::Result> mined;
    for (uint64_t nonce = 0; nonce < 1000; ++nonce) {
        block.nNonce64 = nonce;
        mined = kawpow::Hash(block, block_height);
        BOOST_REQUIRE(mined.has_value());
        if (UintToArith256(mined->final_hash) <= *target) break;
    }

    BOOST_REQUIRE(mined.has_value());
    BOOST_REQUIRE(UintToArith256(mined->final_hash) <= *target);

    block.mix_hash = mined->mix_hash;
    BOOST_CHECK(CheckKAWPOWProofOfWork(block, block_height, consensus));

    block.mix_hash = uint256{1};
    BOOST_CHECK(!CheckKAWPOWProofOfWork(block, block_height, consensus));
}

BOOST_AUTO_TEST_CASE(kawpow_solver_finds_solution)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();

    CBlockHeader block;
    block.nVersion = 1;
    block.hashPrevBlock = *uint256::FromHex("111122223333444455556666777788889999aaaabbbbccccddddeeeeffff0000");
    block.hashMerkleRoot = *uint256::FromHex("0000ffffeeeeddddccccbbbbaaaa999988887777666655554444333322221111");
    block.nTime = 1700000200;
    block.nBits = UintToArith256(consensus.powLimit).GetCompact();

    uint64_t max_tries{2000};
    constexpr uint32_t block_height{18000};
    const bool solved = SolveKAWPOW(block, block_height, consensus, max_tries);
    BOOST_REQUIRE(solved);
    BOOST_CHECK(max_tries < 2000);
    BOOST_CHECK(block.mix_hash != uint256{});
    BOOST_CHECK(CheckKAWPOWProofOfWork(block, block_height, consensus));
}

BOOST_AUTO_TEST_CASE(kawpow_solver_respects_zero_maxtries)
{
    const auto consensus = CreateChainParams(*m_node.args, ChainType::REGTEST)->GetConsensus();

    CBlockHeader block;
    block.nVersion = 1;
    block.hashPrevBlock = *uint256::FromHex("99990000aaaabbbbccccddddeeeeffff11112222333344445555666677778888");
    block.hashMerkleRoot = *uint256::FromHex("88887777666655554444333322221111ffffeeeeddddccccbbbbaaaa00009999");
    block.nTime = 1700000300;
    block.nBits = UintToArith256(consensus.powLimit).GetCompact();
    block.nNonce64 = 42;
    block.mix_hash = uint256{1};

    uint64_t max_tries{0};
    constexpr uint32_t block_height{18000};
    const bool solved = SolveKAWPOW(block, block_height, consensus, max_tries);
    BOOST_CHECK(!solved);
    BOOST_CHECK_EQUAL(block.nNonce64, 42);
    BOOST_CHECK_EQUAL(block.mix_hash, uint256{1});
}

BOOST_AUTO_TEST_CASE(kawpow_solver_refreshes_header_time_when_configured_interval_elapses)
{
    ScopedHeaderTimeRefreshEnv header_refresh_env("1");
    const auto consensus = CreateChainParams(*m_node.args, ChainType::MAIN)->GetConsensus();

    CBlockHeader block;
    block.nVersion = 1;
    block.hashPrevBlock = *uint256::FromHex("aaaa0000aaaabbbbccccddddeeeeffff11112222333344445555666677778888");
    block.hashMerkleRoot = *uint256::FromHex("bbbb7777666655554444333322221111ffffeeeeddddccccbbbbaaaa00009999");
    block.nTime = 1'700'000'300U;
    block.nBits = arith_uint256{1}.GetCompact();
    block.nNonce64 = 0;
    block.mix_hash.SetNull();

    const uint32_t refreshed_time{1'700'000'999U};
    ScopedNodeMockTime mock_time{refreshed_time};

    uint64_t max_tries{1};
    constexpr uint32_t block_height{18000};
    const bool solved = SolveKAWPOW(block, block_height, consensus, max_tries);
    BOOST_CHECK(!solved);
    BOOST_CHECK_EQUAL(max_tries, 0U);
    BOOST_CHECK_EQUAL(block.nTime, refreshed_time);
}

BOOST_AUTO_TEST_CASE(kawpow_solver_skips_header_time_refresh_on_min_difficulty_networks)
{
    ScopedHeaderTimeRefreshEnv header_refresh_env("1");
    auto consensus = CreateChainParams(*m_node.args, ChainType::TESTNET)->GetConsensus();
    consensus.fPowAllowMinDifficultyBlocks = true;

    CBlockHeader block;
    block.nVersion = 1;
    block.hashPrevBlock = *uint256::FromHex("cccc0000aaaabbbbccccddddeeeeffff11112222333344445555666677778888");
    block.hashMerkleRoot = *uint256::FromHex("dddd7777666655554444333322221111ffffeeeeddddccccbbbbaaaa00009999");
    block.nTime = 1'700'000'400U;
    block.nBits = arith_uint256{1}.GetCompact();
    block.nNonce64 = 0;
    block.mix_hash.SetNull();

    const uint32_t original_time{block.nTime};
    ScopedNodeMockTime mock_time{1'700'000'999U};

    uint64_t max_tries{1};
    constexpr uint32_t block_height{18000};
    const bool solved = SolveKAWPOW(block, block_height, consensus, max_tries);
    BOOST_CHECK(!solved);
    BOOST_CHECK_EQUAL(max_tries, 0U);
    BOOST_CHECK_EQUAL(block.nTime, original_time);
}

BOOST_AUTO_TEST_CASE(kawpow_hash_epoch_switch_deterministic)
{
    CBlockHeader block;
    block.nVersion = 1;
    block.hashPrevBlock = *uint256::FromHex("1234123412341234123412341234123412341234123412341234123412341234");
    block.hashMerkleRoot = *uint256::FromHex("4321432143214321432143214321432143214321432143214321432143214321");
    block.nTime = 1700000400;
    block.nBits = 0x207fffff;
    block.nNonce = 0;

    const std::array<uint32_t, 3> heights{29999, 30000, 60000};
    const std::array<uint64_t, 3> nonces{
        0x0102030405060708ULL,
        0x1112131415161718ULL,
        0x2122232425262728ULL,
    };

    std::array<uint256, 3> expected_mix{};
    std::array<uint256, 3> expected_final{};
    for (size_t i = 0; i < heights.size(); ++i) {
        block.nNonce64 = nonces[i];
        const auto baseline = kawpow::Hash(block, heights[i]);
        BOOST_REQUIRE(baseline.has_value());
        expected_mix[i] = baseline->mix_hash;
        expected_final[i] = baseline->final_hash;
    }

    for (int round = 0; round < 6; ++round) {
        for (size_t i = 0; i < heights.size(); ++i) {
            const size_t idx = (static_cast<size_t>(round) + i) % heights.size();
            block.nNonce64 = nonces[idx];
            const auto result = kawpow::Hash(block, heights[idx]);
            BOOST_REQUIRE(result.has_value());
            BOOST_CHECK_EQUAL(result->mix_hash, expected_mix[idx]);
            BOOST_CHECK_EQUAL(result->final_hash, expected_final[idx]);
        }
    }
}

BOOST_AUTO_TEST_CASE(kawpow_hash_epoch_switch_multithreaded)
{
    CBlockHeader block_template;
    block_template.nVersion = 1;
    block_template.hashPrevBlock = *uint256::FromHex("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef");
    block_template.hashMerkleRoot = *uint256::FromHex("beefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdead");
    block_template.nTime = 1700000500;
    block_template.nBits = 0x207fffff;
    block_template.nNonce = 0;

    const std::array<uint32_t, 4> heights{0, 29999, 30000, 60000};
    const std::array<uint64_t, 4> nonces{
        0x0000000000000001ULL,
        0x00000000000000f1ULL,
        0x0000000000000f01ULL,
        0x000000000000f001ULL,
    };

    std::array<uint256, 4> expected_mix{};
    std::array<uint256, 4> expected_final{};
    for (size_t i = 0; i < heights.size(); ++i) {
        CBlockHeader block{block_template};
        block.nNonce64 = nonces[i];
        const auto baseline = kawpow::Hash(block, heights[i]);
        BOOST_REQUIRE(baseline.has_value());
        expected_mix[i] = baseline->mix_hash;
        expected_final[i] = baseline->final_hash;
    }

    std::atomic<bool> ok{true};
    std::vector<std::thread> workers;
    workers.reserve(4);
    for (int worker = 0; worker < 4; ++worker) {
        workers.emplace_back([&, worker] {
            CBlockHeader block{block_template};
            for (int iteration = 0; iteration < 6; ++iteration) {
                if (!ok.load()) return;
                const size_t idx = (static_cast<size_t>(worker + iteration)) % heights.size();
                block.nNonce64 = nonces[idx];
                const auto result = kawpow::Hash(block, heights[idx]);
                if (!result || result->mix_hash != expected_mix[idx] ||
                    result->final_hash != expected_final[idx]) {
                    ok.store(false);
                    return;
                }
            }
        });
    }

    for (auto& worker : workers) {
        worker.join();
    }

    BOOST_CHECK(ok.load());
}

BOOST_AUTO_TEST_SUITE_END()
