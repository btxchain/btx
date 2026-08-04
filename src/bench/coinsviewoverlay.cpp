// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bench/bench.h>
#include <coins.h>
#include <primitives/block.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <util/threadpool.h>

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <ranges>
#include <thread>

namespace {

constexpr uint32_t NUM_INPUTS{256};

class LatencyCoinsView final : public CCoinsView
{
private:
    const std::chrono::microseconds m_delay;

public:
    explicit LatencyCoinsView(std::chrono::microseconds delay) : m_delay{delay} {}

    std::optional<Coin> PeekCoin(const COutPoint&) const override
    {
        if (m_delay.count() > 0) std::this_thread::sleep_for(m_delay);
        return Coin{CTxOut{1, CScript{}}, 1, false};
    }
};

CBlock CreatePrevoutBlock()
{
    CBlock block;
    CMutableTransaction coinbase;
    coinbase.vin.emplace_back();
    block.vtx.push_back(MakeTransactionRef(coinbase));

    const Txid prevhash{Txid::FromUint256(uint256{1})};
    for (const uint32_t i : std::views::iota(uint32_t{0}, NUM_INPUTS)) {
        CMutableTransaction tx;
        tx.vin.emplace_back(prevhash, i);
        block.vtx.push_back(MakeTransactionRef(tx));
    }
    return block;
}

void ConsumeInputs(const CBlock& block, CoinsViewOverlay& view)
{
    const auto reset_guard{view.StartFetching(block)};
    for (const auto& tx : block.vtx | std::views::drop(1)) {
        for (const auto& input : tx->vin) {
            ankerl::nanobench::doNotOptimizeAway(view.AccessCoin(input.prevout));
        }
    }
}

void BenchPrevoutFetching(benchmark::Bench& bench, uint32_t workers, std::chrono::microseconds delay)
{
    const CBlock block{CreatePrevoutBlock()};
    LatencyCoinsView base{delay};
    auto pool{std::make_shared<ThreadPool>("fetch_bench")};
    if (workers > 0) pool->Start(workers);
    CoinsViewOverlay view{&base, std::move(pool)};

    bench.batch(NUM_INPUTS).unit("prevout").run([&] { ConsumeInputs(block, view); });
}

void CoinsViewOverlaySerialWarm(benchmark::Bench& bench)
{
    BenchPrevoutFetching(bench, /*workers=*/0, std::chrono::microseconds{0});
}

void CoinsViewOverlayParallelWarm8(benchmark::Bench& bench)
{
    BenchPrevoutFetching(bench, /*workers=*/8, std::chrono::microseconds{0});
}

void CoinsViewOverlaySerialLatency(benchmark::Bench& bench)
{
    BenchPrevoutFetching(bench, /*workers=*/0, std::chrono::microseconds{50});
}

void CoinsViewOverlayParallelLatency8(benchmark::Bench& bench)
{
    BenchPrevoutFetching(bench, /*workers=*/8, std::chrono::microseconds{50});
}

void CoinsViewOverlayParallelLatency2(benchmark::Bench& bench)
{
    BenchPrevoutFetching(bench, /*workers=*/2, std::chrono::microseconds{50});
}

void CoinsViewOverlayParallelLatency4(benchmark::Bench& bench)
{
    BenchPrevoutFetching(bench, /*workers=*/4, std::chrono::microseconds{50});
}

void CoinsViewOverlayParallelLatency16(benchmark::Bench& bench)
{
    BenchPrevoutFetching(bench, /*workers=*/16, std::chrono::microseconds{50});
}

} // namespace

BENCHMARK(CoinsViewOverlaySerialWarm, benchmark::PriorityLevel::HIGH);
BENCHMARK(CoinsViewOverlayParallelWarm8, benchmark::PriorityLevel::HIGH);
BENCHMARK(CoinsViewOverlaySerialLatency, benchmark::PriorityLevel::HIGH);
BENCHMARK(CoinsViewOverlayParallelLatency8, benchmark::PriorityLevel::HIGH);
BENCHMARK(CoinsViewOverlayParallelLatency2, benchmark::PriorityLevel::HIGH);
BENCHMARK(CoinsViewOverlayParallelLatency4, benchmark::PriorityLevel::HIGH);
BENCHMARK(CoinsViewOverlayParallelLatency16, benchmark::PriorityLevel::HIGH);
