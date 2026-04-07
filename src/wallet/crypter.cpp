// Copyright (c) 2009-2021 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <wallet/crypter.h>

#include <common/system.h>
#include <crypto/aes.h>
#include <crypto/ct_utils.h>
#include <crypto/hkdf_sha256_32.h>
#include <crypto/hmac_sha256.h>
#include <crypto/sha512.h>
#include <support/cleanse.h>

#include <array>
#include <cstring>
#include <string>
#include <type_traits>
#include <vector>

namespace wallet {
namespace {

constexpr std::array<unsigned char, 8> WALLET_AUTHENTICATED_SECRET_MAGIC{
    {'B', 'T', 'X', 'A', 'U', 'T', 'H', '1'}};
constexpr size_t WALLET_AUTHENTICATED_SECRET_TAG_SIZE{CHMAC_SHA256::OUTPUT_SIZE};
constexpr const char* WALLET_AUTHENTICATED_SECRET_SALT{"BTX-Wallet-Secret-MAC-V1"};

[[nodiscard]] bool IsAuthenticatedSecretPayload(std::span<const unsigned char> ciphertext)
{
    return ciphertext.size() >= WALLET_AUTHENTICATED_SECRET_MAGIC.size() +
                                    WALLET_AUTHENTICATED_SECRET_TAG_SIZE &&
        std::memcmp(ciphertext.data(),
                    WALLET_AUTHENTICATED_SECRET_MAGIC.data(),
                    WALLET_AUTHENTICATED_SECRET_MAGIC.size()) == 0;
}

[[nodiscard]] bool ComputeAuthenticatedSecretTag(const CKeyingMaterial& master_key,
                                                 std::string_view purpose,
                                                 const uint256& iv,
                                                 std::span<const unsigned char> raw_ciphertext,
                                                 std::array<unsigned char, WALLET_AUTHENTICATED_SECRET_TAG_SIZE>& tag_out)
{
    if (master_key.size() != WALLET_CRYPTO_KEY_SIZE) return false;

    unsigned char mac_key[WALLET_CRYPTO_KEY_SIZE];
    CHKDF_HMAC_SHA256_L32 hkdf(master_key.data(), master_key.size(), WALLET_AUTHENTICATED_SECRET_SALT);
    hkdf.Expand32(std::string{"wallet-secret-mac:"} + std::string{purpose}, mac_key);

    CHMAC_SHA256 hmac(mac_key, sizeof(mac_key));
    hmac.Write(WALLET_AUTHENTICATED_SECRET_MAGIC.data(), WALLET_AUTHENTICATED_SECRET_MAGIC.size());
    hmac.Write(reinterpret_cast<const unsigned char*>(purpose.data()), purpose.size());
    hmac.Write(iv.begin(), iv.size());
    hmac.Write(raw_ciphertext.data(), raw_ciphertext.size());
    hmac.Finalize(tag_out.data());

    memory_cleanse(mac_key, sizeof(mac_key));
    return true;
}

} // namespace

int CCrypter::BytesToKeySHA512AES(const std::span<const unsigned char> salt, const SecureString& key_data, int count, unsigned char* key, unsigned char* iv) const
{
    // This mimics the behavior of openssl's EVP_BytesToKey with an aes256cbc
    // cipher and sha512 message digest. Because sha512's output size (64b) is
    // greater than the aes256 block size (16b) + aes256 key size (32b),
    // there's no need to process more than once (D_0).

    if(!count || !key || !iv)
        return 0;

    unsigned char buf[CSHA512::OUTPUT_SIZE];
    CSHA512 di;

    di.Write(UCharCast(key_data.data()), key_data.size());
    di.Write(salt.data(), salt.size());
    di.Finalize(buf);

    for(int i = 0; i != count - 1; i++)
        di.Reset().Write(buf, sizeof(buf)).Finalize(buf);

    memcpy(key, buf, WALLET_CRYPTO_KEY_SIZE);
    memcpy(iv, buf + WALLET_CRYPTO_KEY_SIZE, WALLET_CRYPTO_IV_SIZE);
    memory_cleanse(buf, sizeof(buf));
    return WALLET_CRYPTO_KEY_SIZE;
}

bool CCrypter::SetKeyFromPassphrase(const SecureString& key_data, const std::span<const unsigned char> salt, const unsigned int rounds, const unsigned int derivation_method)
{
    if (rounds < 1 || salt.size() != WALLET_CRYPTO_SALT_SIZE) {
        return false;
    }

    int i = 0;
    if (derivation_method == 0) {
        i = BytesToKeySHA512AES(salt, key_data, rounds, vchKey.data(), vchIV.data());
    }

    if (i != (int)WALLET_CRYPTO_KEY_SIZE)
    {
        memory_cleanse(vchKey.data(), vchKey.size());
        memory_cleanse(vchIV.data(), vchIV.size());
        return false;
    }

    fKeySet = true;
    return true;
}

bool CCrypter::SetKey(const CKeyingMaterial& new_key, const std::span<const unsigned char> new_iv)
{
    if (new_key.size() != WALLET_CRYPTO_KEY_SIZE || new_iv.size() != WALLET_CRYPTO_IV_SIZE) {
        return false;
    }

    memcpy(vchKey.data(), new_key.data(), new_key.size());
    memcpy(vchIV.data(), new_iv.data(), new_iv.size());

    fKeySet = true;
    return true;
}

bool CCrypter::Encrypt(const CKeyingMaterial& vchPlaintext, std::vector<unsigned char> &vchCiphertext) const
{
    if (!fKeySet)
        return false;

    // max ciphertext len for a n bytes of plaintext is
    // n + AES_BLOCKSIZE bytes
    vchCiphertext.resize(vchPlaintext.size() + AES_BLOCKSIZE);

    AES256CBCEncrypt enc(vchKey.data(), vchIV.data(), true);
    size_t nLen = enc.Encrypt(vchPlaintext.data(), vchPlaintext.size(), vchCiphertext.data());
    if(nLen < vchPlaintext.size())
        return false;
    vchCiphertext.resize(nLen);

    return true;
}

bool CCrypter::Decrypt(const std::span<const unsigned char> ciphertext, CKeyingMaterial& plaintext) const
{
    if (!fKeySet)
        return false;

    // plaintext will always be equal to or lesser than length of ciphertext
    plaintext.resize(ciphertext.size());

    AES256CBCDecrypt dec(vchKey.data(), vchIV.data(), true);
    int len = dec.Decrypt(ciphertext.data(), ciphertext.size(), plaintext.data());
    if (len == 0) {
        return false;
    }
    plaintext.resize(len);
    return true;
}

bool EncryptSecret(const CKeyingMaterial& vMasterKey, const CKeyingMaterial &vchPlaintext, const uint256& nIV, std::vector<unsigned char> &vchCiphertext)
{
    CCrypter cKeyCrypter;
    std::vector<unsigned char> chIV(WALLET_CRYPTO_IV_SIZE);
    memcpy(chIV.data(), &nIV, WALLET_CRYPTO_IV_SIZE);
    if(!cKeyCrypter.SetKey(vMasterKey, chIV))
        return false;
    return cKeyCrypter.Encrypt(vchPlaintext, vchCiphertext);
}

bool DecryptSecret(const CKeyingMaterial& master_key, const std::span<const unsigned char> ciphertext, const uint256& iv, CKeyingMaterial& plaintext)
{
    CCrypter key_crypter;
    static_assert(WALLET_CRYPTO_IV_SIZE <= std::remove_reference_t<decltype(iv)>::size());
    const std::span iv_prefix{iv.data(), WALLET_CRYPTO_IV_SIZE};
    if (!key_crypter.SetKey(master_key, iv_prefix)) {
        return false;
    }
    return key_crypter.Decrypt(ciphertext, plaintext);
}

bool EncryptAuthenticatedSecret(const CKeyingMaterial& master_key,
                                const std::span<const unsigned char> plaintext,
                                const uint256& iv,
                                std::vector<unsigned char>& ciphertext,
                                const std::string_view purpose)
{
    if (master_key.size() != WALLET_CRYPTO_KEY_SIZE) return false;

    std::array<unsigned char, AES_BLOCKSIZE> iv_bytes;
    static_assert(WALLET_CRYPTO_IV_SIZE == AES_BLOCKSIZE);
    std::memcpy(iv_bytes.data(), iv.begin(), AES_BLOCKSIZE);

    AES256CBCEncrypt enc(master_key.data(), iv_bytes.data(), /*padIn=*/true);
    std::vector<unsigned char> raw_ciphertext(plaintext.size() + AES_BLOCKSIZE);
    const int cipher_len = enc.Encrypt(plaintext.data(), plaintext.size(), raw_ciphertext.data());
    if (cipher_len < static_cast<int>(plaintext.size())) return false;
    raw_ciphertext.resize(cipher_len);

    std::array<unsigned char, WALLET_AUTHENTICATED_SECRET_TAG_SIZE> tag;
    if (!ComputeAuthenticatedSecretTag(master_key, purpose, iv, raw_ciphertext, tag)) {
        return false;
    }

    ciphertext.resize(WALLET_AUTHENTICATED_SECRET_MAGIC.size() + tag.size() + raw_ciphertext.size());
    auto out_it = std::copy(WALLET_AUTHENTICATED_SECRET_MAGIC.begin(),
                            WALLET_AUTHENTICATED_SECRET_MAGIC.end(),
                            ciphertext.begin());
    out_it = std::copy(tag.begin(), tag.end(), out_it);
    std::copy(raw_ciphertext.begin(), raw_ciphertext.end(), out_it);
    return true;
}

bool DecryptAuthenticatedSecret(const CKeyingMaterial& master_key,
                                const std::span<const unsigned char> ciphertext,
                                const uint256& iv,
                                std::vector<unsigned char>& plaintext,
                                const std::string_view purpose,
                                bool* was_authenticated)
{
    if (was_authenticated != nullptr) {
        *was_authenticated = false;
    }
    if (master_key.size() != WALLET_CRYPTO_KEY_SIZE) return false;

    std::span<const unsigned char> raw_ciphertext{ciphertext};
    if (IsAuthenticatedSecretPayload(ciphertext)) {
        if (was_authenticated != nullptr) {
            *was_authenticated = true;
        }

        const std::span<const unsigned char> stored_tag{
            ciphertext.data() + WALLET_AUTHENTICATED_SECRET_MAGIC.size(),
            WALLET_AUTHENTICATED_SECRET_TAG_SIZE};
        raw_ciphertext = ciphertext.subspan(
            WALLET_AUTHENTICATED_SECRET_MAGIC.size() + WALLET_AUTHENTICATED_SECRET_TAG_SIZE);

        std::array<unsigned char, WALLET_AUTHENTICATED_SECRET_TAG_SIZE> expected_tag;
        if (!ComputeAuthenticatedSecretTag(master_key, purpose, iv, raw_ciphertext, expected_tag)) {
            return false;
        }
        const bool tags_match =
            ct_memcmp(expected_tag.data(), stored_tag.data(), expected_tag.size()) == 0;
        memory_cleanse(expected_tag.data(), expected_tag.size());
        if (!tags_match) return false;
    }

    std::array<unsigned char, AES_BLOCKSIZE> iv_bytes;
    static_assert(WALLET_CRYPTO_IV_SIZE == AES_BLOCKSIZE);
    std::memcpy(iv_bytes.data(), iv.begin(), AES_BLOCKSIZE);

    AES256CBCDecrypt dec(master_key.data(), iv_bytes.data(), /*padIn=*/true);
    plaintext.resize(raw_ciphertext.size());
    const int plain_len = dec.Decrypt(raw_ciphertext.data(), raw_ciphertext.size(), plaintext.data());
    if (plain_len == 0) return false;
    plaintext.resize(plain_len);
    return true;
}

bool DecryptKey(const CKeyingMaterial& master_key, const std::span<const unsigned char> crypted_secret, const CPubKey& pub_key, CKey& key)
{
    CKeyingMaterial secret;
    if (!DecryptSecret(master_key, crypted_secret, pub_key.GetHash(), secret)) {
        return false;
    }

    if (secret.size() != 32) {
        return false;
    }

    key.Set(secret.begin(), secret.end(), pub_key.IsCompressed());
    return key.VerifyPubKey(pub_key);
}
} // namespace wallet
