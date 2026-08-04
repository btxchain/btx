// Copyright (c) 2015-2019 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
//
// C++ wrapper around ctaes, a constant-time AES implementation

#ifndef BITCOIN_CRYPTO_AES_H
#define BITCOIN_CRYPTO_AES_H

#include <support/allocators/secure.h>

extern "C" {
#include <crypto/ctaes/ctaes.h>
}

static const int AES_BLOCKSIZE = 16;
static const int AES256_KEYSIZE = 32;

/** An encryption class for AES-256. */
class AES256Encrypt
{
private:
    secure_allocator<AES256_ctx> allocator;
    AES256_ctx* ctx;

public:
    explicit AES256Encrypt(const unsigned char key[32]);
    ~AES256Encrypt();
    AES256Encrypt(const AES256Encrypt&) = delete;
    AES256Encrypt& operator=(const AES256Encrypt&) = delete;
    void Encrypt(unsigned char ciphertext[16], const unsigned char plaintext[16]) const;
};

/** A decryption class for AES-256. */
class AES256Decrypt
{
private:
    secure_allocator<AES256_ctx> allocator;
    AES256_ctx* ctx;

public:
    explicit AES256Decrypt(const unsigned char key[32]);
    ~AES256Decrypt();
    AES256Decrypt(const AES256Decrypt&) = delete;
    AES256Decrypt& operator=(const AES256Decrypt&) = delete;
    void Decrypt(unsigned char plaintext[16], const unsigned char ciphertext[16]) const;
};

class AES256CBCEncrypt
{
public:
    AES256CBCEncrypt(const unsigned char key[AES256_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn);
    ~AES256CBCEncrypt();
    AES256CBCEncrypt(const AES256CBCEncrypt&) = delete;
    AES256CBCEncrypt& operator=(const AES256CBCEncrypt&) = delete;
    int Encrypt(const unsigned char* data, int size, unsigned char* out) const;

private:
    secure_allocator<unsigned char> allocator;
    const AES256Encrypt enc;
    const bool pad;
    unsigned char* iv;
};

class AES256CBCDecrypt
{
public:
    AES256CBCDecrypt(const unsigned char key[AES256_KEYSIZE], const unsigned char ivIn[AES_BLOCKSIZE], bool padIn);
    ~AES256CBCDecrypt();
    AES256CBCDecrypt(const AES256CBCDecrypt&) = delete;
    AES256CBCDecrypt& operator=(const AES256CBCDecrypt&) = delete;
    int Decrypt(const unsigned char* data, int size, unsigned char* out) const;

private:
    secure_allocator<unsigned char> allocator;
    const AES256Decrypt dec;
    const bool pad;
    unsigned char* iv;
};

#endif // BITCOIN_CRYPTO_AES_H
