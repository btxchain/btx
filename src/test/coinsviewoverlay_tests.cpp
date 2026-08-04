// Copyright (c) The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <coins.h>
#include <kernel/chainstatemanager_opts.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <txdb.h>
#include <uint256.h>
#include <util/hasher.h>
#include <util/threadpool.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <memory>
#include <ranges>
#include <unordered_set>
#include <vector>

namespace {

std::shared_ptr<ThreadPool> MakeStartedThreadPool()
{
    auto pool{std::make_shared<ThreadPool>("fetch_test")};
    pool->Start(DEFAULT_PREVOUTFETCH_THREADS);
    return pool;
}

CBlock CreateBlock() noexcept
{
    static constexpr int NUM_TXS{100};
    CBlock block;
    CMutableTransaction coinbase;
    coinbase.vin.emplace_back();
    block.vtx.push_back(MakeTransactionRef(coinbase));

    Txid prevhash{Txid::FromUint256(uint256{1})};
    for (const int i : std::views::iota(1, NUM_TXS)) {
        CMutableTransaction tx;
        const Txid txid{i % 20 == 0 ? prevhash : Txid::FromUint256(uint256{static_cast<uint8_t>(i)})};
        tx.vin.emplace_back(txid, 0);
        prevhash = tx.GetHash();
        block.vtx.push_back(MakeTransactionRef(tx));
    }
    return block;
}

void PopulateView(const CBlock& block, CCoinsView& view, bool spent = false)
{
    CCoinsViewCache cache{&view};
    cache.SetBestBlock(uint256::ONE);
    std::unordered_set<Txid, SaltedCoinsCacheHasher> txids;
    txids.reserve(block.vtx.size() - 1);
    for (const auto& tx : block.vtx | std::views::drop(1)) {
        for (const auto& input : tx->vin) {
            if (txids.contains(input.prevout.hash)) continue;
            Coin coin{};
            if (!spent) coin.out.nValue = 1;
            cache.EmplaceCoinInternalDANGER(COutPoint{input.prevout}, std::move(coin));
        }
        txids.emplace(tx->GetHash());
    }
    BOOST_REQUIRE(cache.Flush());
}

void CheckCache(const CBlock& block, const CCoinsViewCache& cache)
{
    uint32_t counter{0};
    std::unordered_set<Txid, SaltedCoinsCacheHasher> txids;
    txids.reserve(block.vtx.size() - 1);
    for (const auto& tx : block.vtx) {
        if (tx->IsCoinBase()) {
            BOOST_CHECK(!cache.HaveCoinInCache(tx->vin[0].prevout));
        } else {
            for (const auto& input : tx->vin) {
                const auto& first{cache.AccessCoin(input.prevout)};
                const auto& second{cache.AccessCoin(input.prevout)};
                BOOST_CHECK_EQUAL(&first, &second);
                const bool have{cache.HaveCoinInCache(input.prevout)};
                BOOST_CHECK_NE(txids.contains(input.prevout.hash), have);
                counter += have;
            }
            txids.emplace(tx->GetHash());
        }
    }
    BOOST_CHECK_EQUAL(cache.GetCacheSize(), counter);
}

} // namespace

BOOST_AUTO_TEST_SUITE(coinsviewoverlay_tests)

BOOST_AUTO_TEST_CASE(fetch_inputs_without_mutating_parent_cache)
{
    const auto block{CreateBlock()};
    CCoinsViewDB db{{.path = "", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    PopulateView(block, db);
    CCoinsViewCache main_cache{&db};
    CoinsViewOverlay view{&main_cache, MakeStartedThreadPool()};
    const auto reset_guard{view.StartFetching(block)};

    CheckCache(block, view);
    for (const auto& tx : block.vtx) {
        for (const auto& input : tx->vin) {
            BOOST_CHECK(!main_cache.HaveCoinInCache(input.prevout));
        }
    }

    const auto& outpoint{block.vtx[1]->vin[0].prevout};
    view.SetBestBlock(uint256::ONE);
    BOOST_CHECK(view.SpendCoin(outpoint));
    BOOST_CHECK(view.Flush());
    BOOST_CHECK(!main_cache.PeekCoin(outpoint));
}

BOOST_AUTO_TEST_CASE(fetch_respects_spent_parent_cache_entries)
{
    const auto block{CreateBlock()};
    CCoinsViewDB db{{.path = "", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    PopulateView(block, db);
    CCoinsViewCache main_cache{&db};
    PopulateView(block, main_cache, /*spent=*/true);
    CoinsViewOverlay view{&main_cache, MakeStartedThreadPool()};
    const auto reset_guard{view.StartFetching(block)};

    for (const auto& tx : block.vtx) {
        for (const auto& input : tx->vin) {
            BOOST_CHECK(view.AccessCoin(input.prevout).IsSpent());
        }
    }
    BOOST_CHECK_EQUAL(view.GetCacheSize(), 0U);
}

BOOST_AUTO_TEST_CASE(fetch_state_reusable_after_reset_and_flush)
{
    const auto block{CreateBlock()};
    CCoinsViewDB db{{.path = "", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache main_cache{&db};
    PopulateView(block, main_cache);
    CoinsViewOverlay view{&main_cache, MakeStartedThreadPool()};

    for (const bool flush : {false, true, false}) {
        {
            const auto reset_guard{view.StartFetching(block)};
            CheckCache(block, view);
            BOOST_CHECK_GT(view.GetCacheSize(), 0U);
            if (flush) {
                view.SetBestBlock(uint256::ONE);
                BOOST_CHECK(view.Flush());
            }
        }
        BOOST_CHECK_EQUAL(view.GetCacheSize(), 0U);
    }
}

BOOST_AUTO_TEST_CASE(disabled_and_interrupted_pools_fall_back_to_serial_reads)
{
    const auto block{CreateBlock()};
    CCoinsViewDB db{{.path = "", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache main_cache{&db};
    PopulateView(block, main_cache);

    for (const bool interrupted : {false, true}) {
        auto pool{std::make_shared<ThreadPool>("fetch_fallback")};
        if (interrupted) {
            pool->Start(2);
            pool->Interrupt();
        }
        CoinsViewOverlay view{&main_cache, pool};
        const auto reset_guard{view.StartFetching(block)};
        CheckCache(block, view);
    }
}

BOOST_AUTO_TEST_CASE(coinbase_txid_is_filtered_from_fetch_queue)
{
    CBlock block;
    CMutableTransaction coinbase;
    coinbase.vin.emplace_back();
    coinbase.vout.emplace_back(10, CScript{});
    block.vtx.push_back(MakeTransactionRef(coinbase));

    CMutableTransaction same_block_spend;
    same_block_spend.vin.emplace_back(block.vtx[0]->GetHash(), 0);
    block.vtx.push_back(MakeTransactionRef(same_block_spend));

    const COutPoint external{Txid::FromUint256(uint256{42}), 0};
    CMutableTransaction external_spend;
    external_spend.vin.emplace_back(external);
    block.vtx.push_back(MakeTransactionRef(external_spend));

    CCoinsViewDB db{{.path = "", .cache_bytes = 1 << 20, .memory_only = true}, {}};
    CCoinsViewCache main_cache{&db};
    main_cache.EmplaceCoinInternalDANGER(COutPoint{external}, Coin{CTxOut{5, CScript{}}, 1, false});
    main_cache.SetBestBlock(uint256::ONE);

    CoinsViewOverlay view{&main_cache, MakeStartedThreadPool()};
    const auto reset_guard{view.StartFetching(block)};
    view.AddCoin(COutPoint{block.vtx[0]->GetHash(), 0}, Coin{CTxOut{10, CScript{}}, 1, true}, false);
    BOOST_CHECK(!view.AccessCoin(same_block_spend.vin[0].prevout).IsSpent());
    BOOST_CHECK(!view.AccessCoin(external).IsSpent());
    BOOST_CHECK(view.AllInputsConsumed());
}

BOOST_AUTO_TEST_SUITE_END()
