// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_CONSENSUS_CONSENSUS_H
#define BITCOIN_CONSENSUS_CONSENSUS_H

#include <cstdlib>
#include <stdint.h>

/** The maximum allowed size for a serialized block, in bytes (network rule).
 * Raised from 12MB to 24MB for SMILE v2 lattice proofs which achieve
 * ~25KB per 2-in-2-out transaction (vs ~300KB MatRiCT), enabling higher
 * throughput within the same verification budget. */
static const unsigned int MAX_BLOCK_SERIALIZED_SIZE = 24000000;
/** The maximum allowed weight for a block (network rule).
 * With WITNESS_SCALE_FACTOR=1, weight equals serialized size. */
static const unsigned int MAX_BLOCK_WEIGHT = 24000000;
/** The maximum allowed number of signature check operations in a block (network rule).
 * Raised from 240k to 480k to accommodate PQ (ML-DSA-44) multisig transactions
 * whose sigop cost is higher than ECDSA/Schnorr equivalents. */
static const int64_t MAX_BLOCK_SIGOPS_COST = 480000;
/** Coinbase transaction outputs can only be spent after this number of new blocks (network rule) */
static const int COINBASE_MATURITY = 100;

/** Witness scale factor: 1x (no discount).
 * BTX uses lattice-based SMILE proofs where all data is equally
 * critical for verification — no distinction between witness and
 * non-witness bytes. */
static const int WITNESS_SCALE_FACTOR = 1;

static const size_t MIN_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 60; // 60 is the lower bound for the size of a valid serialized CTransaction
static const size_t MIN_SERIALIZABLE_TRANSACTION_WEIGHT = WITNESS_SCALE_FACTOR * 10; // 10 is the lower bound for the size of a serialized CTransaction

/** Flags for nSequence and nLockTime locks */
/** Interpret sequence numbers as relative lock-time constraints. */
static constexpr unsigned int LOCKTIME_VERIFY_SEQUENCE = (1 << 0);

/**
 * Maximum number of seconds that the timestamp of the first
 * block of a difficulty adjustment period is allowed to
 * be earlier than the last block of the previous period (BIP94).
 */
static constexpr int64_t MAX_TIMEWARP = 600;

#endif // BITCOIN_CONSENSUS_CONSENSUS_H
