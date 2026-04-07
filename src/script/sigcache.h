// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_SIGCACHE_H
#define BITCOIN_SCRIPT_SIGCACHE_H

#include <consensus/amount.h>
#include <crypto/sha256.h>
#include <cuckoocache.h>
#include <script/interpreter.h>
#include <span.h>
#include <uint256.h>
#include <util/hasher.h>

#include <cstddef>
#include <shared_mutex>
#include <vector>

class CPubKey;
class CTransaction;
class XOnlyPubKey;

// Default validation cache size. Raised from 32 MiB to 128 MiB to accommodate
// PQ signatures (ML-DSA-44: 2420 bytes vs ECDSA: ~72 bytes) which need ~33x
// more cache space per entry.
static constexpr size_t DEFAULT_VALIDATION_CACHE_BYTES{128 << 20};
static constexpr size_t DEFAULT_SIGNATURE_CACHE_BYTES{DEFAULT_VALIDATION_CACHE_BYTES / 2};
static constexpr size_t DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES{DEFAULT_VALIDATION_CACHE_BYTES / 2};
static_assert(DEFAULT_VALIDATION_CACHE_BYTES == DEFAULT_SIGNATURE_CACHE_BYTES + DEFAULT_SCRIPT_EXECUTION_CACHE_BYTES);

/**
 * Valid signature cache, to avoid doing expensive ECDSA signature checking
 * twice for every transaction (once when accepted into memory pool, and
 * again when accepted into the block chain)
 */
class SignatureCache
{
private:
    //! Entries are SHA256(nonce || 'E', 'S', or 'P' || 31 zero bytes || signature hash || public key || signature):
    CSHA256 m_salted_hasher_ecdsa;
    CSHA256 m_salted_hasher_schnorr;
    CSHA256 m_salted_hasher_pq;
    typedef CuckooCache::cache<uint256, SignatureCacheHasher> map_type;
    map_type setValid;
    std::shared_mutex cs_sigcache;

public:
    SignatureCache(size_t max_size_bytes);

    SignatureCache(const SignatureCache&) = delete;
    SignatureCache& operator=(const SignatureCache&) = delete;

    void ComputeEntryECDSA(uint256& entry, const uint256 &hash, const std::vector<unsigned char>& vchSig, const CPubKey& pubkey) const;

    void ComputeEntrySchnorr(uint256& entry, const uint256 &hash, Span<const unsigned char> sig, const XOnlyPubKey& pubkey) const;

    void ComputeEntryPQ(uint256& entry, const uint256& hash, Span<const unsigned char> sig, Span<const unsigned char> pubkey, PQAlgorithm algo) const;

    bool Get(const uint256& entry, const bool erase);

    void Set(const uint256& entry);
};

class CachingTransactionSignatureChecker : public TransactionSignatureChecker
{
private:
    bool store;
    SignatureCache& m_signature_cache;

public:
    CachingTransactionSignatureChecker(const CTransaction* txToIn, unsigned int nInIn, const CAmount& amountIn, bool storeIn, SignatureCache& signature_cache, PrecomputedTransactionData& txdataIn) : TransactionSignatureChecker(txToIn, nInIn, amountIn, txdataIn, MissingDataBehavior::ASSERT_FAIL), store(storeIn), m_signature_cache(signature_cache)  {}

    bool VerifyECDSASignature(const std::vector<unsigned char>& vchSig, const CPubKey& vchPubKey, const uint256& sighash) const override;
    bool VerifySchnorrSignature(Span<const unsigned char> sig, const XOnlyPubKey& pubkey, const uint256& sighash) const override;
    bool VerifyPQSignature(Span<const unsigned char> sig, Span<const unsigned char> pubkey, PQAlgorithm algo, const uint256& sighash) const override;
};

#endif // BITCOIN_SCRIPT_SIGCACHE_H
