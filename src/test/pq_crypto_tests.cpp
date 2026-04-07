// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pqkey.h>

#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>
#include <cassert>
#include <string_view>
#include <vector>

namespace {
uint256 ParseUint256(std::string_view hex)
{
    const auto parsed = uint256::FromHex(hex);
    assert(parsed.has_value());
    return *parsed;
}

const uint256 MESSAGE_A{ParseUint256("0102030405060708090a0b0c0d0e0f1000000000000000000000000000000000")};
const uint256 MESSAGE_B{ParseUint256("ffffffffffffffffffffffffffffffff00000000000000000000000000000000")};
} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_crypto_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(mldsa44_keygen_produces_valid_sizes)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    BOOST_CHECK_EQUAL(key.GetPubKeySize(), MLDSA44_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(key.GetPubKey().size(), MLDSA44_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(key.GetSigSize(), MLDSA44_SIGNATURE_SIZE);
}

BOOST_AUTO_TEST_CASE(mldsa44_sign_verify_roundtrip)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(MESSAGE_A, sig));
    BOOST_CHECK_EQUAL(sig.size(), MLDSA44_SIGNATURE_SIZE);

    const CPQPubKey pubkey{PQAlgorithm::ML_DSA_44, key.GetPubKey()};
    BOOST_CHECK(pubkey.Verify(MESSAGE_A, sig));
}

BOOST_AUTO_TEST_CASE(mldsa44_hedged_signing_varies_signature)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    std::vector<unsigned char> sig_a;
    std::vector<unsigned char> sig_b;
    BOOST_REQUIRE(key.Sign(MESSAGE_A, sig_a));
    BOOST_REQUIRE(key.Sign(MESSAGE_A, sig_b));
    BOOST_CHECK_EQUAL(sig_a.size(), MLDSA44_SIGNATURE_SIZE);
    BOOST_CHECK_EQUAL(sig_b.size(), MLDSA44_SIGNATURE_SIZE);
    BOOST_CHECK(sig_a != sig_b);

    const CPQPubKey pubkey{PQAlgorithm::ML_DSA_44, key.GetPubKey()};
    BOOST_CHECK(pubkey.Verify(MESSAGE_A, sig_a));
    BOOST_CHECK(pubkey.Verify(MESSAGE_A, sig_b));
}

BOOST_AUTO_TEST_CASE(mldsa44_verify_rejects_wrong_message)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(MESSAGE_A, sig));

    const CPQPubKey pubkey{PQAlgorithm::ML_DSA_44, key.GetPubKey()};
    BOOST_CHECK(!pubkey.Verify(MESSAGE_B, sig));
}

BOOST_AUTO_TEST_CASE(mldsa44_verify_rejects_wrong_key)
{
    CPQKey signer;
    signer.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(signer.IsValid());
    CPQKey wrong;
    wrong.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(wrong.IsValid());

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(signer.Sign(MESSAGE_A, sig));

    const CPQPubKey wrong_pubkey{PQAlgorithm::ML_DSA_44, wrong.GetPubKey()};
    BOOST_CHECK(!wrong_pubkey.Verify(MESSAGE_A, sig));
}

BOOST_AUTO_TEST_CASE(slhdsa128s_keygen_produces_valid_sizes)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key.IsValid());
    BOOST_CHECK_EQUAL(key.GetPubKeySize(), SLHDSA128S_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(key.GetPubKey().size(), SLHDSA128S_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(key.GetSigSize(), SLHDSA128S_SIGNATURE_SIZE);
}

BOOST_AUTO_TEST_CASE(slhdsa128s_sign_verify_roundtrip)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key.IsValid());

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(MESSAGE_A, sig));
    BOOST_CHECK_EQUAL(sig.size(), SLHDSA128S_SIGNATURE_SIZE);

    const CPQPubKey pubkey{PQAlgorithm::SLH_DSA_128S, key.GetPubKey()};
    BOOST_CHECK(pubkey.Verify(MESSAGE_A, sig));
}

BOOST_AUTO_TEST_CASE(slhdsa128s_hedged_signing_varies_signature)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key.IsValid());

    std::vector<unsigned char> sig_a;
    std::vector<unsigned char> sig_b;
    BOOST_REQUIRE(key.Sign(MESSAGE_A, sig_a));
    BOOST_REQUIRE(key.Sign(MESSAGE_A, sig_b));
    BOOST_CHECK_EQUAL(sig_a.size(), SLHDSA128S_SIGNATURE_SIZE);
    BOOST_CHECK_EQUAL(sig_b.size(), SLHDSA128S_SIGNATURE_SIZE);
    BOOST_CHECK(sig_a != sig_b);

    const CPQPubKey pubkey{PQAlgorithm::SLH_DSA_128S, key.GetPubKey()};
    BOOST_CHECK(pubkey.Verify(MESSAGE_A, sig_a));
    BOOST_CHECK(pubkey.Verify(MESSAGE_A, sig_b));
}

BOOST_AUTO_TEST_CASE(slhdsa128s_verify_rejects_wrong_message)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key.IsValid());

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(MESSAGE_A, sig));

    const CPQPubKey pubkey{PQAlgorithm::SLH_DSA_128S, key.GetPubKey()};
    BOOST_CHECK(!pubkey.Verify(MESSAGE_B, sig));
}

BOOST_AUTO_TEST_CASE(pq_key_zeroization)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());

    key.ClearKeyData();
    BOOST_CHECK(!key.IsValid());
    BOOST_CHECK(key.GetPubKey().empty());

    std::vector<unsigned char> sig;
    BOOST_CHECK(!key.Sign(MESSAGE_A, sig));
}

BOOST_AUTO_TEST_SUITE_END()
