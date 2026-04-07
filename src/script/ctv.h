// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_CTV_H
#define BITCOIN_SCRIPT_CTV_H

#include <uint256.h>

#include <cstdint>

struct CMutableTransaction;
class CTransaction;
struct PrecomputedTransactionData;

uint256 ComputeCTVHash(const CTransaction& tx, uint32_t nIn, const PrecomputedTransactionData& txdata);
uint256 ComputeCTVHash(const CMutableTransaction& tx, uint32_t nIn, const PrecomputedTransactionData& txdata);

#endif // BITCOIN_SCRIPT_CTV_H
