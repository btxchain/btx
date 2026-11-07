// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_TEST_UTIL_MATMUL_FIXTURE_H
#define BITCOIN_TEST_UTIL_MATMUL_FIXTURE_H

struct TestOpts;

/** Defer costly regtest v4/BMX4C/DRLT/RC activations for fixtures whose subject
 *  is not the activation itself. Preserve explicit activation overrides and
 *  keep MatMul mining and validation enabled. */
TestOpts WithCheapMatMulFixtureDefaults(TestOpts opts);

#endif // BITCOIN_TEST_UTIL_MATMUL_FIXTURE_H
