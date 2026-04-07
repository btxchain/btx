// Copyright (c) 2014-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>
#include <wallet/crypter.h>

#include <vector>

#include <boost/test/unit_test.hpp>

using namespace util::hex_literals;

namespace wallet {
BOOST_FIXTURE_TEST_SUITE(wallet_crypto_tests, BasicTestingSetup)

class TestCrypter
{
public:
static void TestPassphraseSingle(const std::span<const unsigned char> salt, const SecureString& passphrase, uint32_t rounds,
                                 const std::span<const unsigned char> correct_key = {},
                                 const std::span<const unsigned char> correct_iv = {})
{
    CCrypter crypt;
    crypt.SetKeyFromPassphrase(passphrase, salt, rounds, 0);

    if (!correct_key.empty()) {
        BOOST_CHECK_MESSAGE(memcmp(crypt.vchKey.data(), correct_key.data(), crypt.vchKey.size()) == 0,
            HexStr(crypt.vchKey) + std::string(" != ") + HexStr(correct_key));
    }
    if (!correct_iv.empty()) {
        BOOST_CHECK_MESSAGE(memcmp(crypt.vchIV.data(), correct_iv.data(), crypt.vchIV.size()) == 0,
            HexStr(crypt.vchIV) + std::string(" != ") + HexStr(correct_iv));
    }
}

static void TestPassphrase(const std::span<const unsigned char> salt, const SecureString& passphrase, uint32_t rounds,
                           const std::span<const unsigned char> correct_key = {},
                           const std::span<const unsigned char> correct_iv = {})
{
    TestPassphraseSingle(salt, passphrase, rounds, correct_key, correct_iv);
    for (SecureString::const_iterator it{passphrase.begin()}; it != passphrase.end(); ++it) {
        TestPassphraseSingle(salt, SecureString{it, passphrase.end()}, rounds);
    }
}

static void TestDecrypt(const CCrypter& crypt, const std::span<const unsigned char> ciphertext,
                        const std::span<const unsigned char> correct_plaintext = {})
{
    CKeyingMaterial decrypted;
    crypt.Decrypt(ciphertext, decrypted);
    if (!correct_plaintext.empty()) {
        BOOST_CHECK_EQUAL_COLLECTIONS(decrypted.begin(), decrypted.end(), correct_plaintext.begin(), correct_plaintext.end());
    }
}

static void TestEncryptSingle(const CCrypter& crypt, const CKeyingMaterial& plaintext,
                              const std::span<const unsigned char> correct_ciphertext = {})
{
    std::vector<unsigned char> ciphertext;
    crypt.Encrypt(plaintext, ciphertext);

    if (!correct_ciphertext.empty()) {
        BOOST_CHECK_EQUAL_COLLECTIONS(ciphertext.begin(), ciphertext.end(), correct_ciphertext.begin(), correct_ciphertext.end());
    }

    TestDecrypt(crypt, ciphertext, /*correct_plaintext=*/plaintext);
}

static void TestEncrypt(const CCrypter& crypt, const std::span<const unsigned char> plaintext,
                        const std::span<const unsigned char> correct_ciphertext = {})
{
    TestEncryptSingle(crypt, CKeyingMaterial{plaintext.begin(), plaintext.end()}, correct_ciphertext);
    for (auto it{plaintext.begin()}; it != plaintext.end(); ++it) {
        TestEncryptSingle(crypt, CKeyingMaterial{it, plaintext.end()});
    }
}

};

BOOST_AUTO_TEST_CASE(passphrase) {
    // These are expensive.

    TestCrypter::TestPassphrase("0000deadbeef0000"_hex_u8, "test", 25000,
                                "fc7aba077ad5f4c3a0988d8daa4810d0d4a0e3bcb53af662998898f33df0556a"_hex_u8,
                                "cf2f2691526dd1aa220896fb8bf7c369"_hex_u8);

    std::string hash(GetRandHash().ToString());
    std::vector<unsigned char> vchSalt(8);
    GetRandBytes(vchSalt);
    uint32_t rounds = m_rng.rand32();
    if (rounds > 30000)
        rounds = 30000;
    TestCrypter::TestPassphrase(vchSalt, SecureString(hash.begin(), hash.end()), rounds);
}

BOOST_AUTO_TEST_CASE(encrypt) {
    constexpr std::array<uint8_t, WALLET_CRYPTO_SALT_SIZE> salt{"0000deadbeef0000"_hex_u8};
    CCrypter crypt;
    crypt.SetKeyFromPassphrase("passphrase", salt, 25000, 0);
    TestCrypter::TestEncrypt(crypt, "22bcade09ac03ff6386914359cfe885cfeb5f77ff0d670f102f619687453b29d"_hex_u8);

    for (int i = 0; i != 100; i++)
    {
        uint256 hash(GetRandHash());
        TestCrypter::TestEncrypt(crypt, std::span<unsigned char>{hash.begin(), hash.end()});
    }

}

BOOST_AUTO_TEST_CASE(decrypt) {
    constexpr std::array<uint8_t, WALLET_CRYPTO_SALT_SIZE> salt{"0000deadbeef0000"_hex_u8};
    CCrypter crypt;
    crypt.SetKeyFromPassphrase("passphrase", salt, 25000, 0);

    // Some corner cases the came up while testing
    TestCrypter::TestDecrypt(crypt,"795643ce39d736088367822cdc50535ec6f103715e3e48f4f3b1a60a08ef59ca"_hex_u8);
    TestCrypter::TestDecrypt(crypt,"de096f4a8f9bd97db012aa9d90d74de8cdea779c3ee8bc7633d8b5d6da703486"_hex_u8);
    TestCrypter::TestDecrypt(crypt,"32d0a8974e3afd9c6c3ebf4d66aa4e6419f8c173de25947f98cf8b7ace49449c"_hex_u8);
    TestCrypter::TestDecrypt(crypt,"e7c055cca2faa78cb9ac22c9357a90b4778ded9b2cc220a14cea49f931e596ea"_hex_u8);
    TestCrypter::TestDecrypt(crypt,"b88efddd668a6801d19516d6830da4ae9811988ccbaf40df8fbb72f3f4d335fd"_hex_u8);
    TestCrypter::TestDecrypt(crypt,"8cae76aa6a43694e961ebcb28c8ca8f8540b84153d72865e8561ddd93fa7bfa9"_hex_u8);

    for (int i = 0; i != 100; i++)
    {
        uint256 hash(GetRandHash());
        TestCrypter::TestDecrypt(crypt, std::vector<unsigned char>(hash.begin(), hash.end()));
    }
}

BOOST_AUTO_TEST_CASE(authenticated_secret_roundtrip_and_tamper_detection)
{
    const auto master_key_bytes =
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"_hex_u8;
    const CKeyingMaterial master_key(master_key_bytes.begin(), master_key_bytes.end());
    const auto plaintext =
        "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"_hex_u8;
    const uint256 iv{"f69f2445df4f9b17ad2b417be66c371000000000000000000000000000000000"};

    std::vector<unsigned char> ciphertext;
    BOOST_REQUIRE(EncryptAuthenticatedSecret(master_key, plaintext, iv, ciphertext, "shieldedstate"));
    BOOST_REQUIRE_GT(ciphertext.size(), plaintext.size());

    std::vector<unsigned char> decrypted;
    bool was_authenticated{false};
    BOOST_REQUIRE(DecryptAuthenticatedSecret(master_key,
                                            ciphertext,
                                            iv,
                                            decrypted,
                                            "shieldedstate",
                                            &was_authenticated));
    BOOST_CHECK(was_authenticated);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        decrypted.begin(), decrypted.end(), plaintext.begin(), plaintext.end());

    auto tampered = ciphertext;
    tampered.back() ^= 0x01;
    BOOST_CHECK(!DecryptAuthenticatedSecret(master_key,
                                           tampered,
                                           iv,
                                           decrypted,
                                           "shieldedstate"));
    BOOST_CHECK(!DecryptAuthenticatedSecret(master_key,
                                           ciphertext,
                                           iv,
                                           decrypted,
                                           "pqmasterseed"));
}

BOOST_AUTO_TEST_CASE(authenticated_secret_accepts_legacy_ciphertext_for_migration)
{
    const auto master_key_bytes =
        "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4"_hex_u8;
    const CKeyingMaterial master_key(master_key_bytes.begin(), master_key_bytes.end());
    const auto plaintext =
        "ae2d8a571e03ac9c9eb76fac45af8e516bc1bee22e409f96e93d7e117393172a"_hex_u8;
    const CKeyingMaterial plaintext_secure(plaintext.begin(), plaintext.end());
    const uint256 iv{"000102030405060708090a0b0c0d0e0f00000000000000000000000000000000"};

    std::vector<unsigned char> legacy_ciphertext;
    BOOST_REQUIRE(EncryptSecret(master_key, plaintext_secure, iv, legacy_ciphertext));

    std::vector<unsigned char> decrypted;
    bool was_authenticated{true};
    BOOST_REQUIRE(DecryptAuthenticatedSecret(master_key,
                                            legacy_ciphertext,
                                            iv,
                                            decrypted,
                                            "pqmasterseed",
                                            &was_authenticated));
    BOOST_CHECK(!was_authenticated);
    BOOST_CHECK_EQUAL_COLLECTIONS(
        decrypted.begin(), decrypted.end(), plaintext.begin(), plaintext.end());
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
