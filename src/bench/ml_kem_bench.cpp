// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/bench.h>
#include <crypto/ml_kem.h>
#include <random.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>

#include <cassert>

static void MLKEMKeyGenBench(benchmark::Bench& bench)
{
    bench.minEpochIterations(200).run([&] {
        auto kp = mlkem::KeyGen();
        ankerl::nanobench::doNotOptimizeAway(kp.pk);
    });
}

static void MLKEMEncapsBench(benchmark::Bench& bench)
{
    const auto kp = mlkem::KeyGen();
    bench.minEpochIterations(1000).run([&] {
        auto enc = mlkem::Encaps(kp.pk);
        ankerl::nanobench::doNotOptimizeAway(enc.ct);
    });
}

static void MLKEMDecapsBench(benchmark::Bench& bench)
{
    const auto kp = mlkem::KeyGen();
    const auto enc = mlkem::Encaps(kp.pk);
    bench.minEpochIterations(1000).run([&] {
        auto ss = mlkem::Decaps(enc.ct, kp.sk);
        ankerl::nanobench::doNotOptimizeAway(ss);
    });
}

static void NoteEncryptBench(benchmark::Bench& bench)
{
    const auto kp = mlkem::KeyGen();

    ShieldedNote note;
    note.value = 5 * COIN;
    note.recipient_pk_hash = GetRandHash();
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    bench.minEpochIterations(1000).run([&] {
        auto enc = shielded::NoteEncryption::Encrypt(note, kp.pk);
        ankerl::nanobench::doNotOptimizeAway(enc.view_tag);
    });
}

static void NoteDecryptBench(benchmark::Bench& bench)
{
    const auto kp = mlkem::KeyGen();

    ShieldedNote note;
    note.value = 5 * COIN;
    note.recipient_pk_hash = GetRandHash();
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    const auto enc = shielded::NoteEncryption::Encrypt(note, kp.pk);
    bench.minEpochIterations(1000).run([&] {
        auto dec = shielded::NoteEncryption::TryDecrypt(enc, kp.pk, kp.sk);
        assert(dec.has_value());
    });
}

BENCHMARK(MLKEMKeyGenBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLKEMEncapsBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(MLKEMDecapsBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(NoteEncryptBench, benchmark::PriorityLevel::HIGH);
BENCHMARK(NoteDecryptBench, benchmark::PriorityLevel::HIGH);
