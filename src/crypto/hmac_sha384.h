// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_CRYPTO_HMAC_SHA384_H
#define BITCOIN_CRYPTO_HMAC_SHA384_H

#include <crypto/sha384.h>

#include <cstdlib>
#include <stdint.h>

/** A hasher class for HMAC-SHA-384 (SHA-512 family, 128-byte block, 48-byte tag). */
class CHMAC_SHA384
{
private:
    CSHA384 outer;
    CSHA384 inner;

public:
    static constexpr size_t OUTPUT_SIZE = 48;

    CHMAC_SHA384(const unsigned char* key, size_t keylen);
    CHMAC_SHA384& Write(const unsigned char* data, size_t len)
    {
        inner.Write(data, len);
        return *this;
    }
    void Finalize(unsigned char hash[OUTPUT_SIZE]);
};

#endif // BITCOIN_CRYPTO_HMAC_SHA384_H
