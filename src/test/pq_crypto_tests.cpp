// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pqkey.h>

#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>
#include <libbitcoinpqc/bitcoinpqc.h>
#include <test/data/fips205_slhdsa_kat.h>
#include <util/strencodings.h>
#include <algorithm>
#include <cassert>
#include <string>
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

// FIPS-205 CONFORMANCE (#24): BTX verifies the OFFICIAL NIST ACVP FIPS-205
// SLH-DSA-SHAKE-128s vectors when run in FIPS-205 mode (slhdsa_fips205=1), which
// applies the finalized base_2b FORS index derivation. Cross-checked against
// @noble/post-quantum (which verifies both vectors as VALID). The fix was a single
// signing-path change (FORS index bit-order), gated on the flag so legacy round-3
// signatures still verify in legacy mode.
//
// External/pure interface: M' = 0x00 || 0x00 || M (empty context) + base_2b.
BOOST_AUTO_TEST_CASE(slhdsa128s_fips205_official_acvp_kat)
{
    const std::vector<unsigned char> pk = ParseHex(std::string(fips205_kat::KAT_PK_HEX));
    const std::vector<unsigned char> msg = ParseHex(std::string(fips205_kat::KAT_MSG_HEX));
    const std::vector<unsigned char> sig = ParseHex(std::string(fips205_kat::KAT_SIG_HEX));
    BOOST_REQUIRE_EQUAL(pk.size(), SLHDSA128S_PUBKEY_SIZE);
    BOOST_REQUIRE_EQUAL(sig.size(), SLHDSA128S_SIGNATURE_SIZE);
    BOOST_REQUIRE(!msg.empty());

    // FIPS-205 pure mode, empty context: M' = 0x00 || 0x00 || M.
    std::vector<unsigned char> wrapped;
    wrapped.reserve(2 + msg.size());
    wrapped.push_back(0x00);
    wrapped.push_back(0x00);
    wrapped.insert(wrapped.end(), msg.begin(), msg.end());

    // FIPS-205 mode ACCEPTS the official signature.
    BOOST_CHECK_EQUAL(
        bitcoin_pqc_verify(BITCOIN_PQC_SLH_DSA_SHAKE_128S, pk.data(), pk.size(),
                           wrapped.data(), wrapped.size(), sig.data(), sig.size(),
                           /*slhdsa_fips205=*/1),
        BITCOIN_PQC_OK);
    // Legacy round-3 mode (wrong FORS bit-order) REJECTS it -> the gating works.
    BOOST_CHECK(
        bitcoin_pqc_verify(BITCOIN_PQC_SLH_DSA_SHAKE_128S, pk.data(), pk.size(),
                           wrapped.data(), wrapped.size(), sig.data(), sig.size(),
                           /*slhdsa_fips205=*/0)
        != BITCOIN_PQC_OK);
}

// Internal interface (bare message) + base_2b: isolates the core from the message
// wrapper. FIPS-205 mode verifies the official internal-interface vector.
BOOST_AUTO_TEST_CASE(slhdsa128s_fips205_internal_core_kat)
{
    const std::vector<unsigned char> pk = ParseHex(std::string(fips205_kat::KAT_INT_PK_HEX));
    const std::vector<unsigned char> msg = ParseHex(std::string(fips205_kat::KAT_INT_MSG_HEX));
    const std::vector<unsigned char> sig = ParseHex(std::string(fips205_kat::KAT_INT_SIG_HEX));
    BOOST_REQUIRE_EQUAL(pk.size(), SLHDSA128S_PUBKEY_SIZE);
    BOOST_REQUIRE_EQUAL(sig.size(), SLHDSA128S_SIGNATURE_SIZE);
    // FIPS-205 mode (base_2b) ACCEPTS; legacy round-3 (LSB-first) REJECTS.
    BOOST_CHECK_EQUAL(
        bitcoin_pqc_verify(BITCOIN_PQC_SLH_DSA_SHAKE_128S, pk.data(), pk.size(),
                           msg.data(), msg.size(), sig.data(), sig.size(),
                           /*slhdsa_fips205=*/1),
        BITCOIN_PQC_OK);
    BOOST_CHECK(
        bitcoin_pqc_verify(BITCOIN_PQC_SLH_DSA_SHAKE_128S, pk.data(), pk.size(),
                           msg.data(), msg.size(), sig.data(), sig.size(),
                           /*slhdsa_fips205=*/0)
        != BITCOIN_PQC_OK);
}

// Diagnostic (FIPS-205 #24): isolate WHERE BTX's SLH-DSA core diverges from
// FIPS-205 -- keygen (tweakable hashes F/H/T/PRF) or signing (H_msg). Feed BTX's
// keygen the official ACVP deterministic seed (first 48 bytes of the ACVP sk =
// SK.seed||SK.prf||PK.seed) and compare the derived public key to the official pk
// (last 32 bytes of the sk). @noble reproduces the ACVP pk from this exact seed,
// so a MATCH here means BTX's tweakable hashes are FIPS-205-conformant and the
// divergence is confined to the message/H_msg path; a MISMATCH means the core's
// hash construction itself diverges (a full core swap is required).
BOOST_AUTO_TEST_CASE(slhdsa128s_fips205_keygen_locus_diagnostic)
{
    const std::vector<unsigned char> sk = ParseHex(std::string(fips205_kat::KAT_INT_SK_HEX));
    BOOST_REQUIRE_EQUAL(sk.size(), SLHDSA128S_SECRET_KEY_SIZE);
    std::array<unsigned char, 128> entropy{};
    std::copy(sk.begin(), sk.begin() + 48, entropy.begin()); // SK.seed||SK.prf||PK.seed

    bitcoin_pqc_keypair_t kp{};
    BOOST_REQUIRE_EQUAL(
        bitcoin_pqc_keygen(BITCOIN_PQC_SLH_DSA_SHAKE_128S, &kp, entropy.data(), entropy.size()),
        BITCOIN_PQC_OK);
    const std::vector<unsigned char> derived_pk(
        static_cast<const unsigned char*>(kp.public_key),
        static_cast<const unsigned char*>(kp.public_key) + kp.public_key_size);
    bitcoin_pqc_keypair_free(&kp);

    const std::vector<unsigned char> expected_pk(sk.end() - 32, sk.end());
    const bool keygen_conformant = (derived_pk == expected_pk);
    BOOST_TEST_MESSAGE("BTX SLH-DSA keygen(ACVP seed) == FIPS-205 pk : " << keygen_conformant
        << "  (true => tweakable hashes conformant, divergence is signing-only;"
        << " false => core hash construction diverges)");
    BOOST_REQUIRE_EQUAL(derived_pk.size(), SLHDSA128S_PUBKEY_SIZE);
}

// FIPS-205 SLH-DSA: the pure-mode empty-context wrapper is exactly
// 0x00 || 0x00 || M (M = the 32-byte hash).
BOOST_AUTO_TEST_CASE(fips205_pure_context_wrapper_bytes)
{
    const std::vector<unsigned char> wrapped = Fips205PureContextMessage(MESSAGE_A);
    BOOST_REQUIRE_EQUAL(wrapped.size(), 2u + 32u);
    BOOST_CHECK_EQUAL(wrapped[0], 0x00); // pure-mode domain separator
    BOOST_CHECK_EQUAL(wrapped[1], 0x00); // |ctx| = 0
    BOOST_CHECK(std::equal(MESSAGE_A.begin(), MESSAGE_A.end(), wrapped.begin() + 2));
}

// SLH-DSA signed in FIPS-205 mode verifies in FIPS-205 mode.
BOOST_AUTO_TEST_CASE(slhdsa128s_fips205_sign_verify_roundtrip)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key.IsValid());
    CPQPubKey pub(PQAlgorithm::SLH_DSA_128S, key.GetPubKey());

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(MESSAGE_A, sig, /*slhdsa_fips205=*/true));
    BOOST_CHECK(pub.Verify(MESSAGE_A, sig, /*slhdsa_fips205=*/true));
}

// FIPS-205 and legacy round-3 are distinct message preconditionings: a signature
// made in one mode must NOT verify in the other (prevents silent acceptance of a
// stale-format signature across the activation boundary).
BOOST_AUTO_TEST_CASE(slhdsa128s_fips205_mode_separation)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::SLH_DSA_128S);
    BOOST_REQUIRE(key.IsValid());
    CPQPubKey pub(PQAlgorithm::SLH_DSA_128S, key.GetPubKey());

    std::vector<unsigned char> sig_fips;
    BOOST_REQUIRE(key.Sign(MESSAGE_A, sig_fips, /*slhdsa_fips205=*/true));
    BOOST_CHECK(!pub.Verify(MESSAGE_A, sig_fips, /*slhdsa_fips205=*/false));

    std::vector<unsigned char> sig_legacy;
    BOOST_REQUIRE(key.Sign(MESSAGE_A, sig_legacy, /*slhdsa_fips205=*/false));
    BOOST_CHECK(!pub.Verify(MESSAGE_A, sig_legacy, /*slhdsa_fips205=*/true));
}

// The FIPS-205 flag is SLH-DSA-only: it must not change ML-DSA (FIPS-204), so a
// signature made with either flag value verifies under either flag value.
BOOST_AUTO_TEST_CASE(mldsa44_fips205_flag_is_noop)
{
    CPQKey key;
    key.MakeNewKey(PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(key.IsValid());
    CPQPubKey pub(PQAlgorithm::ML_DSA_44, key.GetPubKey());

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(key.Sign(MESSAGE_A, sig, /*slhdsa_fips205=*/true));
    BOOST_CHECK(pub.Verify(MESSAGE_A, sig, /*slhdsa_fips205=*/true));
    BOOST_CHECK(pub.Verify(MESSAGE_A, sig, /*slhdsa_fips205=*/false));
}

BOOST_AUTO_TEST_SUITE_END()
