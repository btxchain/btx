// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <consensus/params.h>
#include <headerssync.h>
#include <pow.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <util/time.h>
#include <validation.h>
#include <list>
#include <span>
#include <vector>

#include <boost/test/unit_test.hpp>
#include <limits>

struct HeadersGeneratorSetup : public RegTestingSetup {
    /** Search for a nonce to meet (regtest) proof of work */
    void FindProofOfWork(CBlockHeader& starting_header, uint32_t block_height);
    /**
     * Generate headers in a chain that build off a given starting hash, using
     * the given nVersion, advancing time by 1 second from the starting
     * prev_time, and with a fixed merkle root hash.
     */
    void GenerateHeaders(std::vector<CBlockHeader>& headers, size_t count,
            const uint256& starting_hash, const int nVersion, int prev_time,
            const uint256& merkle_root, const uint32_t nBits, uint32_t starting_height = 0);
};

void HeadersGeneratorSetup::FindProofOfWork(CBlockHeader& starting_header, uint32_t block_height)
{
    BOOST_REQUIRE(MineHeaderForConsensus(starting_header, block_height, Params().GetConsensus()));
}

void HeadersGeneratorSetup::GenerateHeaders(std::vector<CBlockHeader>& headers,
        size_t count, const uint256& starting_hash, const int nVersion, int prev_time,
        const uint256& merkle_root, const uint32_t nBits, uint32_t starting_height)
{
    uint256 prev_hash = starting_hash;

    while (headers.size() < count) {
        headers.emplace_back();
        CBlockHeader& next_header = headers.back();;
        next_header.nVersion = nVersion;
        next_header.hashPrevBlock = prev_hash;
        next_header.hashMerkleRoot = merkle_root;
        next_header.nTime = prev_time+1;
        next_header.nBits = nBits;

        const uint32_t next_height{starting_height + static_cast<uint32_t>(headers.size())};
        FindProofOfWork(next_header, next_height);
        prev_hash = next_header.GetHash();
        prev_time = next_header.nTime;
    }
    return;
}

BOOST_FIXTURE_TEST_SUITE(headers_sync_chainwork_tests, HeadersGeneratorSetup)

// In this test, we construct two sets of headers from genesis, one with
// sufficient proof of work and one without.
// 1. We deliver the first set of headers and verify that the headers sync state
//    updates to the REDOWNLOAD phase successfully.
// 2. Then we deliver the second set of headers and verify that they fail
//    processing (presumably due to commitments not matching).
// 3. Finally, we verify that repeating with the first set of headers in both
//    phases is successful.
BOOST_AUTO_TEST_CASE(headers_sync_state)
{
    std::vector<CBlockHeader> first_chain;
    std::vector<CBlockHeader> second_chain;

    std::unique_ptr<HeadersSyncState> hss;

    const int target_blocks = 15000;
    arith_uint256 chain_work = target_blocks*2;

    // Generate headers for two different chains (using differing merkle roots
    // to ensure the headers are different).
    GenerateHeaders(first_chain, target_blocks-1, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(0), Params().GenesisBlock().nBits);

    GenerateHeaders(second_chain, target_blocks-2, Params().GenesisBlock().GetHash(),
            Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
            ArithToUint256(1), Params().GenesisBlock().nBits);

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    std::vector<CBlockHeader> headers_batch;

    // Feed the first chain to HeadersSyncState, by delivering 1 header
    // initially and then the rest.
    headers_batch.insert(headers_batch.end(), std::next(first_chain.begin()), first_chain.end());

    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders({first_chain.front()}, true);
    // Pretend the first header is still "full", so we don't abort.
    auto result = hss->ProcessNextHeaders(headers_batch, true);

    // This chain should look valid, and we should have met the proof-of-work
    // requirement.
    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    // Try to sneakily feed back the second chain.
    result = hss->ProcessNextHeaders(second_chain, true);
    BOOST_CHECK(!result.success); // foiled!
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Now try again, this time feeding the first chain twice.
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    (void)hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::REDOWNLOAD);

    result = hss->ProcessNextHeaders(first_chain, true);
    BOOST_CHECK(result.success);
    BOOST_CHECK(!result.request_more);
    // All headers should be ready for acceptance:
    BOOST_CHECK(result.pow_validated_headers.size() == first_chain.size());
    // Nothing left for the sync logic to do:
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);

    // Finally, verify that just trying to process the second chain would not
    // succeed (too little work)
    hss.reset(new HeadersSyncState(0, Params().GetConsensus(), chain_start, chain_work));
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);
     // Pretend just the first message is "full", so we don't abort.
    (void)hss->ProcessNextHeaders({second_chain.front()}, true);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::PRESYNC);

    headers_batch.clear();
    headers_batch.insert(headers_batch.end(), std::next(second_chain.begin(), 1), second_chain.end());
    // Tell the sync logic that the headers message was not full, implying no
    // more headers can be requested. For a low-work-chain, this should causes
    // the sync to end with no headers for acceptance.
    result = hss->ProcessNextHeaders(headers_batch, false);
    BOOST_CHECK(hss->GetState() == HeadersSyncState::State::FINAL);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(!result.request_more);
    // Nevertheless, no validation errors should have been detected with the
    // chain:
    BOOST_CHECK(result.success);
}

BOOST_AUTO_TEST_CASE(headers_sync_state_zero_minimum_work_handles_short_tip_message)
{
    std::vector<CBlockHeader> chain;

    GenerateHeaders(chain, /*count=*/8, Params().GenesisBlock().GetHash(),
                    Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
                    ArithToUint256(0x42), Params().GenesisBlock().nBits);

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    BOOST_REQUIRE(chain_start != nullptr);

    HeadersSyncState hss(/*id=*/0, Params().GetConsensus(), chain_start, /*minimum_required_work=*/arith_uint256{});

    // With minimum work at zero, PRESYNC should transition immediately.
    auto result = hss.ProcessNextHeaders(chain, /*full_headers_message=*/true);
    BOOST_REQUIRE(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(hss.GetState() == HeadersSyncState::State::REDOWNLOAD);

    // A non-full message at tip in REDOWNLOAD should complete cleanly instead
    // of aborting as an incomplete PRESYNC batch.
    result = hss.ProcessNextHeaders(chain, /*full_headers_message=*/false);
    BOOST_REQUIRE(result.success);
    BOOST_CHECK(!result.request_more);
    BOOST_CHECK(!result.pow_validated_headers.empty());
    BOOST_CHECK(hss.GetState() == HeadersSyncState::State::FINAL);
}

BOOST_AUTO_TEST_CASE(compressed_header_roundtrip_preserves_serialized_header_fields)
{
    CBlockHeader header;
    header.nVersion = 7;
    header.hashPrevBlock = uint256{1};
    header.hashMerkleRoot = uint256{2};
    header.nTime = 1'738'800'123;
    header.nBits = 0x20147ae1U;
    header.nNonce = 0xabcdef01U;
    header.nNonce64 = 0x1234567890abcdefULL;
    header.matmul_digest = uint256{3};
    header.matmul_dim = 512;
    header.seed_a = uint256{4};
    header.seed_b = uint256{5};

    const CompressedHeader compressed{header};
    const CBlockHeader reconstructed{compressed.GetFullHeader(header.hashPrevBlock)};

    BOOST_CHECK_EQUAL(reconstructed.nVersion, header.nVersion);
    BOOST_CHECK_EQUAL(reconstructed.hashPrevBlock, header.hashPrevBlock);
    BOOST_CHECK_EQUAL(reconstructed.hashMerkleRoot, header.hashMerkleRoot);
    BOOST_CHECK_EQUAL(reconstructed.nTime, header.nTime);
    BOOST_CHECK_EQUAL(reconstructed.nBits, header.nBits);
    BOOST_CHECK_EQUAL(reconstructed.nNonce, header.nNonce);
    BOOST_CHECK_EQUAL(reconstructed.nNonce64, header.nNonce64);
    BOOST_CHECK_EQUAL(reconstructed.matmul_digest, header.matmul_digest);
    BOOST_CHECK_EQUAL(reconstructed.matmul_dim, header.matmul_dim);
    BOOST_CHECK_EQUAL(reconstructed.seed_a, header.seed_a);
    BOOST_CHECK_EQUAL(reconstructed.seed_b, header.seed_b);
    BOOST_CHECK_EQUAL(reconstructed.GetHash(), header.GetHash());
}

BOOST_AUTO_TEST_CASE(calculate_claimed_work_rejects_invalid_matmul_schedule_nbits)
{
    if (!Params().GetConsensus().fMatMulPOW) return;

    std::vector<CBlockHeader> headers;
    GenerateHeaders(headers, /*count=*/4, Params().GenesisBlock().GetHash(),
                    Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
                    ArithToUint256(0), Params().GenesisBlock().nBits);

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    BOOST_REQUIRE(chain_start != nullptr);

    const auto valid_work = CalculateClaimedHeadersWork(*chain_start, headers, Params().GetConsensus());
    BOOST_REQUIRE(valid_work.has_value());
    BOOST_CHECK(*valid_work > 0);

    headers[1].nBits = UintToArith256(Params().GetConsensus().powLimit).GetCompact();
    const auto invalid_work = CalculateClaimedHeadersWork(*chain_start, headers, Params().GetConsensus());
    BOOST_CHECK(!invalid_work.has_value());
}

BOOST_AUTO_TEST_CASE(calculate_claimed_work_accepts_long_matmul_batch_with_nonzero_asert_anchor)
{
    if (!Params().GetConsensus().fMatMulPOW) return;

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    BOOST_REQUIRE(chain_start != nullptr);

    Consensus::Params consensus = Params().GetConsensus();
    consensus.fPowNoRetargeting = false;
    consensus.fPowAllowMinDifficultyBlocks = false;
    consensus.nFastMineHeight = 50;
    consensus.nMatMulAsertHeight = 50;
    consensus.nMatMulAsertRetuneHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulAsertRetune2Height = std::numeric_limits<int32_t>::max();

    static constexpr size_t LONG_BATCH_COUNT{260};
    std::vector<CBlockHeader> headers;
    headers.reserve(LONG_BATCH_COUNT);
    std::list<CBlockIndex> synthetic_indices;

    const CBlockHeader genesis_header{Params().GenesisBlock()};
    const uint256 merkle_root{ArithToUint256(0x12345)};
    CBlockIndex* previous_index = const_cast<CBlockIndex*>(chain_start);
    uint256 prev_hash = chain_start->GetBlockHash();
    uint32_t prev_time = chain_start->GetBlockTime();
    int32_t next_height = chain_start->nHeight + 1;

    for (size_t i = 0; i < LONG_BATCH_COUNT; ++i) {
        CBlockHeader header;
        header.nVersion = genesis_header.nVersion;
        header.hashPrevBlock = prev_hash;
        header.hashMerkleRoot = merkle_root;
        header.nTime = prev_time + 1;
        header.nBits = GetNextWorkRequired(previous_index, &header, consensus);
        header.nNonce = static_cast<uint32_t>(i + 1);
        header.nNonce64 = static_cast<uint64_t>(i + 1);
        header.matmul_digest = genesis_header.matmul_digest;
        header.matmul_dim = genesis_header.matmul_dim;
        header.seed_a = genesis_header.seed_a;
        header.seed_b = genesis_header.seed_b;

        headers.push_back(header);
        prev_hash = header.GetHash();
        prev_time = header.nTime;

        synthetic_indices.emplace_back(header);
        CBlockIndex& synthesized = synthetic_indices.back();
        synthesized.nHeight = next_height;
        synthesized.pprev = previous_index;
        previous_index = &synthesized;
        ++next_height;
    }

    const auto claimed_work = CalculateClaimedHeadersWork(*chain_start, headers, consensus);
    BOOST_REQUIRE(claimed_work.has_value());
    BOOST_CHECK(*claimed_work > 0);
}

BOOST_AUTO_TEST_CASE(headers_sync_state_accepts_long_matmul_batch_with_nonzero_asert_anchor)
{
    if (!Params().GetConsensus().fMatMulPOW) return;

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    BOOST_REQUIRE(chain_start != nullptr);

    Consensus::Params consensus = Params().GetConsensus();
    consensus.fPowNoRetargeting = false;
    consensus.fPowAllowMinDifficultyBlocks = false;
    consensus.nFastMineHeight = 50;
    consensus.nMatMulAsertHeight = 50;
    consensus.nMatMulAsertRetuneHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulAsertRetune2Height = std::numeric_limits<int32_t>::max();

    static constexpr size_t LONG_BATCH_COUNT{260};
    std::vector<CBlockHeader> headers;
    headers.reserve(LONG_BATCH_COUNT);
    std::list<CBlockIndex> synthetic_indices;

    const CBlockHeader genesis_header{Params().GenesisBlock()};
    const uint256 merkle_root{ArithToUint256(0x23456)};
    CBlockIndex* previous_index = const_cast<CBlockIndex*>(chain_start);
    uint256 prev_hash = chain_start->GetBlockHash();
    uint32_t prev_time = chain_start->GetBlockTime();
    int32_t next_height = chain_start->nHeight + 1;

    for (size_t i = 0; i < LONG_BATCH_COUNT; ++i) {
        CBlockHeader header;
        header.nVersion = genesis_header.nVersion;
        header.hashPrevBlock = prev_hash;
        header.hashMerkleRoot = merkle_root;
        header.nTime = prev_time + 1;
        header.nBits = GetNextWorkRequired(previous_index, &header, consensus);
        header.nNonce = static_cast<uint32_t>(i + 1);
        header.nNonce64 = static_cast<uint64_t>(i + 1);
        header.matmul_digest = genesis_header.matmul_digest;
        header.matmul_dim = genesis_header.matmul_dim;
        header.seed_a = genesis_header.seed_a;
        header.seed_b = genesis_header.seed_b;

        headers.push_back(header);
        prev_hash = header.GetHash();
        prev_time = header.nTime;

        synthetic_indices.emplace_back(header);
        CBlockIndex& synthesized = synthetic_indices.back();
        synthesized.nHeight = next_height;
        synthesized.pprev = previous_index;
        previous_index = &synthesized;
        ++next_height;
    }

    const arith_uint256 unreachable_work{~arith_uint256{}};
    HeadersSyncState hss(/*id=*/0, consensus, chain_start, unreachable_work);
    const auto result = hss.ProcessNextHeaders(headers, /*full_headers_message=*/true);

    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(hss.GetState() == HeadersSyncState::State::PRESYNC);
    BOOST_CHECK_EQUAL(hss.GetPresyncHeight(), static_cast<int64_t>(LONG_BATCH_COUNT));
}

BOOST_AUTO_TEST_CASE(headers_sync_state_presync_survives_mainnet_anchor_plus_window)
{
    if (!Params().GetConsensus().fMatMulPOW) return;

    const CBlockHeader genesis_header{Params().GenesisBlock()};
    CBlockIndex synthetic_chain_start{genesis_header};
    const uint256 synthetic_chain_start_hash{genesis_header.GetHash()};
    synthetic_chain_start.phashBlock = &synthetic_chain_start_hash;
    synthetic_chain_start.nChainWork = arith_uint256{};
    synthetic_chain_start.nHeight = 50'000;

    Consensus::Params consensus = Params().GetConsensus();
    consensus.fPowNoRetargeting = false;
    consensus.fPowAllowMinDifficultyBlocks = false;
    consensus.nFastMineHeight = 50'000;
    consensus.nMatMulAsertHeight = 50'000;
    consensus.nMatMulAsertRetuneHeight = std::numeric_limits<int32_t>::max();
    consensus.nMatMulAsertRetune2Height = std::numeric_limits<int32_t>::max();

    // Regression target for the historical failure at height 50'181:
    // 50'000 + synthetic window (180) + 1.
    static constexpr size_t HEADER_COUNT{220};
    std::vector<CBlockHeader> headers;
    headers.reserve(HEADER_COUNT);
    std::list<CBlockIndex> synthetic_indices;

    CBlockIndex* previous_index = &synthetic_chain_start;
    uint256 prev_hash = synthetic_chain_start_hash;
    uint32_t prev_time = synthetic_chain_start.GetBlockTime();
    int32_t next_height = synthetic_chain_start.nHeight + 1;
    for (size_t i = 0; i < HEADER_COUNT; ++i) {
        CBlockHeader header;
        header.nVersion = genesis_header.nVersion;
        header.hashPrevBlock = prev_hash;
        header.hashMerkleRoot = ArithToUint256(0x34567);
        header.nTime = prev_time + 1;
        header.nBits = GetNextWorkRequired(previous_index, &header, consensus);
        header.nNonce = static_cast<uint32_t>(i + 1);
        header.nNonce64 = static_cast<uint64_t>(i + 1);
        header.matmul_digest = genesis_header.matmul_digest;
        header.matmul_dim = genesis_header.matmul_dim;
        header.seed_a = genesis_header.seed_a;
        header.seed_b = genesis_header.seed_b;

        headers.push_back(header);
        prev_hash = header.GetHash();
        prev_time = header.nTime;

        synthetic_indices.emplace_back(header);
        CBlockIndex& synthesized = synthetic_indices.back();
        synthesized.nHeight = next_height;
        synthesized.pprev = previous_index;
        previous_index = &synthesized;
        ++next_height;
    }

    const arith_uint256 unreachable_work{~arith_uint256{}};
    HeadersSyncState hss(/*id=*/0, consensus, &synthetic_chain_start, unreachable_work);
    const auto result = hss.ProcessNextHeaders(headers, /*full_headers_message=*/true);

    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(hss.GetState() == HeadersSyncState::State::PRESYNC);
    BOOST_CHECK_EQUAL(
        hss.GetPresyncHeight(),
        static_cast<int64_t>(synthetic_chain_start.nHeight + static_cast<int>(HEADER_COUNT)));
}

BOOST_AUTO_TEST_CASE(headers_sync_state_presync_survives_anchor_retune_rollovers)
{
    if (!Params().GetConsensus().fMatMulPOW) return;

    const CBlockHeader genesis_header{Params().GenesisBlock()};
    CBlockIndex synthetic_chain_start{genesis_header};
    const uint256 synthetic_chain_start_hash{genesis_header.GetHash()};
    synthetic_chain_start.phashBlock = &synthetic_chain_start_hash;
    synthetic_chain_start.nChainWork = arith_uint256{};
    synthetic_chain_start.nHeight = 50'000;

    Consensus::Params consensus = Params().GetConsensus();
    consensus.fPowNoRetargeting = false;
    consensus.fPowAllowMinDifficultyBlocks = false;
    consensus.nFastMineHeight = 50'000;
    consensus.nMatMulAsertHeight = 50'000;
    consensus.nMatMulAsertRetuneHeight = 50'040;
    consensus.nMatMulAsertRetune2Height = 50'080;

    // Cross both retune anchors and continue more than a synthetic window past
    // the second retune anchor.
    static constexpr size_t HEADER_COUNT{260};
    std::vector<CBlockHeader> headers;
    headers.reserve(HEADER_COUNT);
    std::list<CBlockIndex> synthetic_indices;

    CBlockIndex* previous_index = &synthetic_chain_start;
    uint256 prev_hash = synthetic_chain_start_hash;
    uint32_t prev_time = synthetic_chain_start.GetBlockTime();
    int32_t next_height = synthetic_chain_start.nHeight + 1;
    for (size_t i = 0; i < HEADER_COUNT; ++i) {
        CBlockHeader header;
        header.nVersion = genesis_header.nVersion;
        header.hashPrevBlock = prev_hash;
        header.hashMerkleRoot = ArithToUint256(0x45678);
        header.nTime = prev_time + 1;
        header.nBits = GetNextWorkRequired(previous_index, &header, consensus);
        header.nNonce = static_cast<uint32_t>(i + 100);
        header.nNonce64 = static_cast<uint64_t>(i + 100);
        header.matmul_digest = genesis_header.matmul_digest;
        header.matmul_dim = genesis_header.matmul_dim;
        header.seed_a = genesis_header.seed_a;
        header.seed_b = genesis_header.seed_b;

        headers.push_back(header);
        prev_hash = header.GetHash();
        prev_time = header.nTime;

        synthetic_indices.emplace_back(header);
        CBlockIndex& synthesized = synthetic_indices.back();
        synthesized.nHeight = next_height;
        synthesized.pprev = previous_index;
        previous_index = &synthesized;
        ++next_height;
    }

    const arith_uint256 unreachable_work{~arith_uint256{}};
    HeadersSyncState hss(/*id=*/0, consensus, &synthetic_chain_start, unreachable_work);
    const auto result = hss.ProcessNextHeaders(headers, /*full_headers_message=*/true);

    BOOST_CHECK(result.success);
    BOOST_CHECK(result.request_more);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(hss.GetState() == HeadersSyncState::State::PRESYNC);
    BOOST_CHECK_EQUAL(
        hss.GetPresyncHeight(),
        static_cast<int64_t>(synthetic_chain_start.nHeight + static_cast<int>(HEADER_COUNT)));
}

BOOST_AUTO_TEST_CASE(headers_sync_state_rejects_invalid_matmul_schedule_nbits)
{
    if (!Params().GetConsensus().fMatMulPOW) return;

    std::vector<CBlockHeader> headers;
    GenerateHeaders(headers, /*count=*/10, Params().GenesisBlock().GetHash(),
                    Params().GenesisBlock().nVersion, Params().GenesisBlock().nTime,
                    ArithToUint256(0), Params().GenesisBlock().nBits);

    headers[3].nBits = UintToArith256(Params().GetConsensus().powLimit).GetCompact();

    const CBlockIndex* chain_start = WITH_LOCK(::cs_main, return m_node.chainman->m_blockman.LookupBlockIndex(Params().GenesisBlock().GetHash()));
    BOOST_REQUIRE(chain_start != nullptr);

    const arith_uint256 min_work = chain_start->nChainWork + 1;
    HeadersSyncState hss(/*id=*/0, Params().GetConsensus(), chain_start, min_work);
    const auto result = hss.ProcessNextHeaders(headers, /*full_headers_message=*/true);
    BOOST_CHECK(!result.success);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(hss.GetState() == HeadersSyncState::State::FINAL);
}

BOOST_AUTO_TEST_CASE(headers_sync_state_clamps_negative_time_window_for_commitment_bound)
{
    const auto previous_mock_time = GetMockTime();
    // Set a pre-genesis mock time. Mock time value 0 disables mocking.
    SetMockTime(1);

    const CBlockHeader genesis_header{Params().GenesisBlock()};
    CBlockIndex synthetic_chain_start{genesis_header};
    const uint256 synthetic_chain_start_hash{genesis_header.GetHash()};
    synthetic_chain_start.phashBlock = &synthetic_chain_start_hash;
    synthetic_chain_start.nChainWork = arith_uint256{};

    arith_uint256 unreachable_work{~arith_uint256{}};
    HeadersSyncState hss(/*id=*/0, Params().GetConsensus(), &synthetic_chain_start, unreachable_work);

    static constexpr size_t HEADERS_TO_EXCEED_MIN_BOUND{43'400};
    std::vector<CBlockHeader> headers;
    headers.reserve(HEADERS_TO_EXCEED_MIN_BOUND);

    uint256 prev_hash{synthetic_chain_start_hash};
    for (size_t i = 0; i < HEADERS_TO_EXCEED_MIN_BOUND; ++i) {
        CBlockHeader header;
        header.nVersion = genesis_header.nVersion;
        header.hashPrevBlock = prev_hash;
        header.hashMerkleRoot = genesis_header.hashMerkleRoot;
        header.nTime = genesis_header.nTime + static_cast<uint32_t>(i + 1);
        header.nBits = genesis_header.nBits;
        header.nNonce = static_cast<uint32_t>(i + 1);
        header.nNonce64 = static_cast<uint64_t>(i + 1);
        header.matmul_digest = genesis_header.matmul_digest;
        header.matmul_dim = genesis_header.matmul_dim;
        header.seed_a = genesis_header.seed_a;
        header.seed_b = genesis_header.seed_b;

        prev_hash = header.GetHash();
        headers.push_back(std::move(header));
    }

    const auto result = hss.ProcessNextHeaders(headers, /*full_headers_message=*/true);
    BOOST_CHECK(!result.success);
    BOOST_CHECK(!result.request_more);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(hss.GetState() == HeadersSyncState::State::FINAL);

    SetMockTime(previous_mock_time);
}

BOOST_AUTO_TEST_CASE(headers_sync_state_rejects_block_height_overflow)
{
    const CBlockHeader genesis_header{Params().GenesisBlock()};
    CBlockIndex synthetic_chain_start{genesis_header};
    const uint256 synthetic_chain_start_hash{genesis_header.GetHash()};
    synthetic_chain_start.phashBlock = &synthetic_chain_start_hash;
    synthetic_chain_start.nChainWork = arith_uint256{};
    synthetic_chain_start.nHeight = std::numeric_limits<int>::max();

    const arith_uint256 min_work = synthetic_chain_start.nChainWork + 1;
    HeadersSyncState hss(/*id=*/0, Params().GetConsensus(), &synthetic_chain_start, min_work);

    CBlockHeader header;
    header.nVersion = genesis_header.nVersion;
    header.hashPrevBlock = synthetic_chain_start_hash;
    header.hashMerkleRoot = genesis_header.hashMerkleRoot;
    header.nTime = genesis_header.nTime + 1;
    header.nBits = genesis_header.nBits;
    header.nNonce = 1;
    header.nNonce64 = 1;
    header.matmul_digest = genesis_header.matmul_digest;
    header.matmul_dim = genesis_header.matmul_dim;
    header.seed_a = genesis_header.seed_a;
    header.seed_b = genesis_header.seed_b;

    const auto result = hss.ProcessNextHeaders({header}, /*full_headers_message=*/true);
    BOOST_CHECK(!result.success);
    BOOST_CHECK(!result.request_more);
    BOOST_CHECK(result.pow_validated_headers.empty());
    BOOST_CHECK(hss.GetState() == HeadersSyncState::State::FINAL);
}

BOOST_AUTO_TEST_CASE(calculate_claimed_work_rejects_block_height_overflow)
{
    const CBlockHeader genesis_header{Params().GenesisBlock()};
    CBlockIndex synthetic_chain_start{genesis_header};
    const uint256 synthetic_chain_start_hash{genesis_header.GetHash()};
    synthetic_chain_start.phashBlock = &synthetic_chain_start_hash;
    synthetic_chain_start.nChainWork = arith_uint256{};
    synthetic_chain_start.nHeight = std::numeric_limits<int>::max();

    CBlockHeader header;
    header.nVersion = genesis_header.nVersion;
    header.hashPrevBlock = synthetic_chain_start_hash;
    header.hashMerkleRoot = genesis_header.hashMerkleRoot;
    header.nTime = genesis_header.nTime + 1;
    header.nBits = genesis_header.nBits;
    header.nNonce = 2;
    header.nNonce64 = 2;
    header.matmul_digest = genesis_header.matmul_digest;
    header.matmul_dim = genesis_header.matmul_dim;
    header.seed_a = genesis_header.seed_a;
    header.seed_b = genesis_header.seed_b;

    const auto claimed_work = CalculateClaimedHeadersWork(
        synthetic_chain_start,
        std::span<const CBlockHeader>{&header, 1},
        Params().GetConsensus());
    BOOST_CHECK(!claimed_work.has_value());
}

BOOST_AUTO_TEST_SUITE_END()
