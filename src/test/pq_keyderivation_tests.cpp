// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <crypto/hkdf_sha256_32.h>
#include <pq/pq_keyderivation.h>
#include <wallet/pq_keyderivation.h>
#include <pqkey.h>
#include <test/util/setup_common.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <algorithm>
#include <new>
#include <type_traits>

BOOST_AUTO_TEST_SUITE(pq_keyderivation_tests)

static std::array<unsigned char, 32> MakeSeed(uint8_t fill)
{
    std::array<unsigned char, 32> seed{};
    std::fill(seed.begin(), seed.end(), fill);
    return seed;
}

BOOST_AUTO_TEST_CASE(determinism)
{
    // Same inputs must produce identical output every time
    auto seed = MakeSeed(0x42);
    auto a = pq::DerivePQSeedFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 0);
    auto b = pq::DerivePQSeedFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 0);
    BOOST_CHECK(a == b);

    // And for full key derivation
    auto key_a = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 0);
    auto key_b = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 0);
    BOOST_CHECK(key_a.has_value());
    BOOST_CHECK(key_b.has_value());
    BOOST_CHECK(key_a->GetPubKey() == key_b->GetPubKey());
}

BOOST_AUTO_TEST_CASE(path_components_affect_output)
{
    auto seed = MakeSeed(0x01);
    auto base = pq::DerivePQSeedFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 0);

    // Different coin_type
    auto diff_coin = pq::DerivePQSeedFromBIP39(seed, PQAlgorithm::ML_DSA_44, 1, 0, 0, 0);
    BOOST_CHECK(base != diff_coin);

    // Different account
    auto diff_acct = pq::DerivePQSeedFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 1, 0, 0);
    BOOST_CHECK(base != diff_acct);

    // Different change
    auto diff_change = pq::DerivePQSeedFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 1, 0);
    BOOST_CHECK(base != diff_change);

    // Different index
    auto diff_idx = pq::DerivePQSeedFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 1);
    BOOST_CHECK(base != diff_idx);
}

BOOST_AUTO_TEST_CASE(algo_affects_output)
{
    auto seed = MakeSeed(0x02);
    auto ml = pq::DerivePQSeedFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 0);
    auto slh = pq::DerivePQSeedFromBIP39(seed, PQAlgorithm::SLH_DSA_128S, 0, 0, 0, 0);
    BOOST_CHECK(ml != slh);
}

BOOST_AUTO_TEST_CASE(empty_seed_returns_zero)
{
    std::array<unsigned char, 32> empty{};
    Span<const unsigned char> empty_span{};
    auto result = pq::DerivePQSeedFromBIP39(empty_span, PQAlgorithm::ML_DSA_44, 0, 0, 0, 0);
    BOOST_CHECK(result == empty);
}

BOOST_AUTO_TEST_CASE(key_derivation_produces_valid_keys)
{
    auto seed = MakeSeed(0xAA);
    auto ml_key = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 0);
    BOOST_CHECK(ml_key.has_value());
    BOOST_CHECK(!ml_key->GetPubKey().empty());

    auto slh_key = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::SLH_DSA_128S, 0, 0, 0, 0);
    BOOST_CHECK(slh_key.has_value());
    BOOST_CHECK(!slh_key->GetPubKey().empty());

    // Different algos produce different pubkeys
    BOOST_CHECK(ml_key->GetPubKey() != slh_key->GetPubKey());
}

BOOST_AUTO_TEST_CASE(wallet_namespace_forwarding)
{
    // Verify the wallet:: namespace wrapper produces identical results to pq::
    auto seed = MakeSeed(0x55);
    auto pq_result = pq::DerivePQSeedFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 5);
    auto wallet_result = wallet::DerivePQSeedFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 5);
    BOOST_CHECK(pq_result == wallet_result);
}

BOOST_AUTO_TEST_CASE(hkdf_intermediate_state_is_cleansed_on_destruct)
{
    static_assert(sizeof(CHKDF_HMAC_SHA256_L32) == 32);
    static_assert(std::is_standard_layout_v<CHKDF_HMAC_SHA256_L32>);

    const auto seed = MakeSeed(0x33);
    alignas(CHKDF_HMAC_SHA256_L32) std::array<unsigned char, sizeof(CHKDF_HMAC_SHA256_L32)> storage{};

    auto* hkdf = new (storage.data()) CHKDF_HMAC_SHA256_L32(seed.data(), seed.size(), "BTX-Test-HKDF");
    BOOST_CHECK(std::any_of(storage.begin(), storage.end(), [](unsigned char byte) { return byte != 0; }));

    hkdf->~CHKDF_HMAC_SHA256_L32();
    BOOST_CHECK(std::all_of(storage.begin(), storage.end(), [](unsigned char byte) { return byte == 0; }));
}

extern "C" {
void btx_mldsa_randombytes(unsigned char* out, size_t outlen);
void btx_spx_randombytes(unsigned char* out, unsigned long long outlen);
}

BOOST_AUTO_TEST_CASE(randombytes_names_do_not_alias_libsodium)
{
    // Linking these symbols fails if the PQ cores still export randombytes
    // and the linker resolves that name to libsodium. Key equality is the
    // behavior the wallet depends on: the same seed must restore the same key.
    unsigned char mldsa_byte{0};
    unsigned char slh_byte{0};
    btx_mldsa_randombytes(&mldsa_byte, 1);
    btx_spx_randombytes(&slh_byte, 1);

    const auto seed = MakeSeed(0x42);
    const auto ml_first = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 0);
    const auto slh_first = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::SLH_DSA_128S, 0, 0, 0, 0);
    const auto ml_second = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 0);
    const auto slh_second = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::SLH_DSA_128S, 0, 0, 0, 0);
    BOOST_REQUIRE(ml_first.has_value());
    BOOST_REQUIRE(slh_first.has_value());
    BOOST_REQUIRE(ml_second.has_value());
    BOOST_REQUIRE(slh_second.has_value());
    BOOST_CHECK(ml_first->GetPubKey() == ml_second->GetPubKey());
    BOOST_CHECK(slh_first->GetPubKey() == slh_second->GetPubKey());

    const auto ml_other_path = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 1);
    const auto slh_other_seed = pq::DerivePQKeyFromBIP39(MakeSeed(0x43), PQAlgorithm::SLH_DSA_128S, 0, 0, 0, 0);
    BOOST_REQUIRE(ml_other_path.has_value());
    BOOST_REQUIRE(slh_other_seed.has_value());
    BOOST_CHECK(ml_first->GetPubKey() != ml_other_path->GetPubKey());
    BOOST_CHECK(slh_first->GetPubKey() != slh_other_seed->GetPubKey());

    const auto ml_after_slh = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::ML_DSA_44, 0, 0, 0, 0);
    const auto slh_after_ml = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::SLH_DSA_128S, 0, 0, 0, 0);
    BOOST_REQUIRE(ml_after_slh.has_value());
    BOOST_REQUIRE(slh_after_ml.has_value());
    BOOST_CHECK(ml_first->GetPubKey() == ml_after_slh->GetPubKey());
    BOOST_CHECK(slh_first->GetPubKey() == slh_after_ml->GetPubKey());
}

BOOST_AUTO_TEST_SUITE_END()
