// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/hmac_sha384.h>

#include <support/cleanse.h>

#include <algorithm>
#include <string.h>

CHMAC_SHA384::CHMAC_SHA384(const unsigned char* key, size_t keylen)
{
    unsigned char rkey[128];
    if (keylen <= 128) {
        std::copy(key, key + keylen, rkey);
        memset(rkey + keylen, 0, 128 - keylen);
    } else {
        CSHA384().Write(key, keylen).Finalize(rkey);
        memset(rkey + CSHA384::OUTPUT_SIZE, 0, 128 - CSHA384::OUTPUT_SIZE);
    }

    for (int n = 0; n < 128; n++)
        rkey[n] ^= 0x5c;
    outer.Write(rkey, 128);

    for (int n = 0; n < 128; n++)
        rkey[n] ^= 0x5c ^ 0x36;
    inner.Write(rkey, 128);

    memory_cleanse(rkey, sizeof(rkey));
}

void CHMAC_SHA384::Finalize(unsigned char hash[OUTPUT_SIZE])
{
    unsigned char temp[CSHA384::OUTPUT_SIZE];
    inner.Finalize(temp);
    outer.Write(temp, CSHA384::OUTPUT_SIZE).Finalize(hash);
    memory_cleanse(temp, sizeof(temp));
}
