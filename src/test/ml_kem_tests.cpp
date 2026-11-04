// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/ml_kem.h>
#include <test/util/setup_common.h>

extern "C" {
#include <crypto/ml-kem-768/fips202.h>
#include <crypto/ml-kem-768/params.h>
}

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>

BOOST_FIXTURE_TEST_SUITE(ml_kem_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(keygen_produces_correct_sizes)
{
    const auto kp = mlkem::KeyGen();
    BOOST_CHECK_EQUAL(kp.pk.size(), mlkem::PUBLICKEYBYTES);
    BOOST_CHECK_EQUAL(kp.sk.size(), mlkem::SECRETKEYBYTES);
}

BOOST_AUTO_TEST_CASE(keygen_produces_different_keys_each_call)
{
    const auto kp1 = mlkem::KeyGen();
    const auto kp2 = mlkem::KeyGen();
    BOOST_CHECK(kp1.pk != kp2.pk);
}

BOOST_AUTO_TEST_CASE(deterministic_keygen_from_seed)
{
    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> seed;
    seed.fill(0x42);
    const auto kp1 = mlkem::KeyGenDerand(seed);
    const auto kp2 = mlkem::KeyGenDerand(seed);

    BOOST_CHECK(kp1.pk == kp2.pk);
    BOOST_CHECK(kp1.sk == kp2.sk);
}

BOOST_AUTO_TEST_CASE(encapsulation_key_check_preserves_generated_keys)
{
    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> seed{};
    for (const uint8_t value : {uint8_t{0}, uint8_t{0x42}, uint8_t{0xff}}) {
        seed.fill(value);
        const auto kp = mlkem::KeyGenDerand(seed);
        BOOST_CHECK(mlkem::IsValidEncapsulationKey(kp.pk));
        const auto enc = mlkem::Encaps(kp.pk);
        BOOST_CHECK(mlkem::Decaps(enc.ct, kp.sk) == enc.ss);
    }
}

BOOST_AUTO_TEST_CASE(encapsulation_key_check_does_not_restrict_seed)
{
    mlkem::PublicKey pk{};
    BOOST_CHECK(mlkem::IsValidEncapsulationKey(pk));
    std::fill(pk.end() - 32, pk.end(), uint8_t{0xff});
    BOOST_CHECK(mlkem::IsValidEncapsulationKey(pk));
}

BOOST_AUTO_TEST_CASE(encapsulation_key_check_range_and_position)
{
    for (size_t offset = 0; offset < mlkem::PUBLICKEYBYTES - 32; offset += 3) {
        for (const uint16_t value : {uint16_t{0}, uint16_t{3328}, uint16_t{3329}, uint16_t{4095}}) {
            for (const bool second : {false, true}) {
                mlkem::PublicKey pk{};
                const uint16_t a = second ? 0 : value;
                const uint16_t b = second ? value : 0;
                pk[offset] = a & 0xff;
                pk[offset + 1] = (a >> 8) | ((b & 0x0f) << 4);
                pk[offset + 2] = b >> 4;
                BOOST_CHECK_EQUAL(mlkem::IsValidEncapsulationKey(pk), value < 3329);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(encaps_decaps_roundtrip)
{
    const auto kp = mlkem::KeyGen();
    const auto enc = mlkem::Encaps(kp.pk);
    const auto ss = mlkem::Decaps(enc.ct, kp.sk);
    BOOST_CHECK(enc.ss == ss);
}

BOOST_AUTO_TEST_CASE(decaps_with_wrong_sk_produces_different_secret)
{
    const auto kp_a = mlkem::KeyGen();
    const auto kp_b = mlkem::KeyGen();
    const auto enc = mlkem::Encaps(kp_a.pk);
    const auto ss_wrong = mlkem::Decaps(enc.ct, kp_b.sk);
    BOOST_CHECK(enc.ss != ss_wrong);
}

BOOST_AUTO_TEST_CASE(fips203_sk_contains_pk_and_hash)
{
    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> seed;
    seed.fill(0xA5);
    const auto kp = mlkem::KeyGenDerand(seed);

    BOOST_CHECK_EQUAL(kp.sk.size(), mlkem::SECRETKEYBYTES);
    BOOST_CHECK_EQUAL(kp.pk.size(), mlkem::PUBLICKEYBYTES);

    const size_t pk_offset = KYBER_INDCPA_SECRETKEYBYTES;
    BOOST_REQUIRE(pk_offset + mlkem::PUBLICKEYBYTES + 32 <= kp.sk.size());

    BOOST_CHECK(std::equal(kp.sk.begin() + pk_offset,
                           kp.sk.begin() + pk_offset + mlkem::PUBLICKEYBYTES,
                           kp.pk.begin()));

    uint8_t expected_pk_hash[32];
    sha3_256(expected_pk_hash, kp.pk.data(), kp.pk.size());
    BOOST_CHECK(std::equal(kp.sk.begin() + pk_offset + mlkem::PUBLICKEYBYTES,
                           kp.sk.begin() + pk_offset + mlkem::PUBLICKEYBYTES + 32,
                           expected_pk_hash));
}

BOOST_AUTO_TEST_SUITE_END()
