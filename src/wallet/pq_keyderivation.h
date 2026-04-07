// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_WALLET_PQ_KEYDERIVATION_H
#define BITCOIN_WALLET_PQ_KEYDERIVATION_H

// Thin wrapper — canonical implementation lives in pq/pq_keyderivation.h
#include <crypto/ml_kem.h>
#include <pq/pq_keyderivation.h>

namespace wallet {

inline std::array<unsigned char, 32> DerivePQSeedFromBIP39(
    Span<const unsigned char> master_seed,
    PQAlgorithm algo,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index)
{
    return pq::DerivePQSeedFromBIP39(master_seed, algo, coin_type, account, change, index);
}

inline std::optional<CPQKey> DerivePQKeyFromBIP39(
    Span<const unsigned char> master_seed,
    PQAlgorithm algo,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index)
{
    return pq::DerivePQKeyFromBIP39(master_seed, algo, coin_type, account, change, index);
}


/** Derive deterministic ML-KEM keygen seed material from wallet master seed. */
std::array<unsigned char, mlkem::KEYGEN_SEEDBYTES> DeriveMLKEMSeedFromBIP39(
    Span<const unsigned char> master_seed,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index);

/** Derive deterministic ML-KEM keypair from wallet master seed. */
mlkem::KeyPair DeriveMLKEMKeyFromBIP39(
    Span<const unsigned char> master_seed,
    uint32_t coin_type,
    uint32_t account,
    uint32_t change,
    uint32_t index);

} // namespace wallet

#endif // BITCOIN_WALLET_PQ_KEYDERIVATION_H
