// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <consensus/amount.h>
#include <shielded/turnstile.h>

static void ShieldedTurnstileApply(benchmark::Bench& bench)
{
    ShieldedPoolBalance pool;
    bench.run([&] {
        (void)pool.ApplyValueBalance(-1 * COIN);
        (void)pool.ApplyValueBalance(1 * COIN);
    });
}

BENCHMARK(ShieldedTurnstileApply, benchmark::PriorityLevel::HIGH);
