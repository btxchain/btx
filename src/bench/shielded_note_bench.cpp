// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <random.h>
#include <shielded/note.h>

#include <vector>

static void NoteCommitment(benchmark::Bench& bench)
{
    ShieldedNote note;
    note.value = 50 * COIN;
    note.recipient_pk_hash = GetRandHash();
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    bench.minEpochIterations(10000).run([&] {
        ankerl::nanobench::doNotOptimizeAway(note.GetCommitment());
    });
}

static void NullifierDerivation(benchmark::Bench& bench)
{
    ShieldedNote note;
    note.value = 50 * COIN;
    note.recipient_pk_hash = GetRandHash();
    note.rho = GetRandHash();
    note.rcm = GetRandHash();
    std::vector<unsigned char> sk(32, 0x42);

    bench.minEpochIterations(10000).run([&] {
        ankerl::nanobench::doNotOptimizeAway(note.GetNullifier(sk));
    });
}

BENCHMARK(NoteCommitment, benchmark::PriorityLevel::HIGH);
BENCHMARK(NullifierDerivation, benchmark::PriorityLevel::HIGH);
