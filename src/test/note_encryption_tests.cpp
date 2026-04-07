// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <crypto/ml_kem.h>
#include <random.h>
#include <shielded/note.h>
#include <shielded/note_encryption.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <uint256.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(note_encryption_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(encrypt_decrypt_roundtrip)
{
    const auto recipient = mlkem::KeyGen();

    ShieldedNote note;
    note.value = 7 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();
    note.memo = {0x01, 0x02, 0x03, 0x04};

    const auto enc = shielded::NoteEncryption::Encrypt(note, recipient.pk);
    const auto dec = shielded::NoteEncryption::TryDecrypt(enc, recipient.pk, recipient.sk);

    BOOST_REQUIRE(dec.has_value());
    BOOST_CHECK_EQUAL(dec->value, note.value);
    BOOST_CHECK(dec->recipient_pk_hash == note.recipient_pk_hash);
    BOOST_CHECK(dec->rho == note.rho);
    BOOST_CHECK(dec->rcm == note.rcm);
    BOOST_CHECK(dec->memo == note.memo);
}

BOOST_AUTO_TEST_CASE(decrypt_with_wrong_key_returns_nullopt)
{
    const auto recipient = mlkem::KeyGen();
    const auto wrong = mlkem::KeyGen();

    ShieldedNote note;
    note.value = 3 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    const auto enc = shielded::NoteEncryption::Encrypt(note, recipient.pk);
    const auto dec = shielded::NoteEncryption::TryDecrypt(enc, wrong.pk, wrong.sk);
    BOOST_CHECK(!dec.has_value());
}

BOOST_AUTO_TEST_CASE(view_tag_statistical_rejection)
{
    const auto recipient = mlkem::KeyGen();

    ShieldedNote note;
    note.value = COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    const auto enc = shielded::NoteEncryption::Encrypt(note, recipient.pk);

    int accidental_matches{0};
    constexpr int kTrials{1024};
    for (int i = 0; i < kTrials; ++i) {
        const auto other = mlkem::KeyGen();
        if (shielded::NoteEncryption::ComputeViewTag(enc.kem_ciphertext, other.pk) == enc.view_tag) {
            ++accidental_matches;
        }
    }
    BOOST_CHECK(accidental_matches < 20);
}

BOOST_AUTO_TEST_CASE(encrypted_note_serialization_roundtrip)
{
    const auto recipient = mlkem::KeyGen();

    ShieldedNote note;
    note.value = 11 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();
    note.memo = {0xDE, 0xAD, 0xBE, 0xEF};

    const auto enc = shielded::NoteEncryption::Encrypt(note, recipient.pk);
    const auto serialized = enc.Serialize();
    const auto decoded = shielded::EncryptedNote::Deserialize(serialized);
    BOOST_REQUIRE(decoded.has_value());

    const auto dec = shielded::NoteEncryption::TryDecrypt(*decoded, recipient.pk, recipient.sk);
    BOOST_REQUIRE(dec.has_value());
    BOOST_CHECK_EQUAL(dec->value, note.value);
    BOOST_CHECK(dec->memo == note.memo);
}

BOOST_AUTO_TEST_CASE(deterministic_encryption_same_inputs_same_output)
{
    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> key_seed;
    key_seed.fill(0x33);
    const auto recipient = mlkem::KeyGenDerand(key_seed);

    ShieldedNote note;
    note.value = 13 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();
    note.memo = {0xAA, 0xBB, 0xCC};

    std::array<uint8_t, mlkem::ENCAPS_SEEDBYTES> kem_seed;
    kem_seed.fill(0x5A);
    std::array<uint8_t, 12> nonce;
    nonce.fill(0xC3);

    const auto enc1 = shielded::NoteEncryption::EncryptDeterministic(note, recipient.pk, kem_seed, nonce);
    const auto enc2 = shielded::NoteEncryption::EncryptDeterministic(note, recipient.pk, kem_seed, nonce);
    BOOST_CHECK(enc1.Serialize() == enc2.Serialize());
}

BOOST_AUTO_TEST_CASE(bound_note_transport_roundtrip_and_bucketed_padding)
{
    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> key_seed;
    key_seed.fill(0x24);
    const auto recipient = mlkem::KeyGenDerand(key_seed);

    ShieldedNote short_note_template;
    short_note_template.value = 9 * COIN;
    short_note_template.recipient_pk_hash = uint256{0x91};
    short_note_template.memo = {0x0A, 0x0B, 0x0C, 0x0D};

    ShieldedNote long_note_template = short_note_template;
    long_note_template.memo.resize(96, 0x5C);

    ShieldedNote same_bucket_note_template = short_note_template;
    same_bucket_note_template.memo.resize(24, 0x6D);

    std::array<uint8_t, mlkem::ENCAPS_SEEDBYTES> kem_seed;
    kem_seed.fill(0x73);
    std::array<uint8_t, 12> nonce;
    nonce.fill(0x84);

    const auto bound = shielded::NoteEncryption::EncryptBoundNoteDeterministic(
        short_note_template,
        recipient.pk,
        kem_seed,
        nonce);
    auto same_bucket_nonce = nonce;
    same_bucket_nonce[0] ^= 0x22;
    const auto padded_same_bucket = shielded::NoteEncryption::EncryptBoundNoteDeterministic(
        same_bucket_note_template,
        recipient.pk,
        kem_seed,
        same_bucket_nonce);
    auto long_nonce = nonce;
    long_nonce[0] ^= 0x11;
    const auto padded_long = shielded::NoteEncryption::EncryptBoundNoteDeterministic(
        long_note_template,
        recipient.pk,
        kem_seed,
        long_nonce);
    const auto dec = shielded::NoteEncryption::TryDecrypt(bound.encrypted_note, recipient.pk, recipient.sk);
    const auto long_dec =
        shielded::NoteEncryption::TryDecrypt(padded_long.encrypted_note, recipient.pk, recipient.sk);
    BOOST_REQUIRE(dec.has_value());
    BOOST_REQUIRE(long_dec.has_value());
    const auto same_bucket_dec =
        shielded::NoteEncryption::TryDecrypt(padded_same_bucket.encrypted_note, recipient.pk, recipient.sk);
    BOOST_REQUIRE(same_bucket_dec.has_value());
    BOOST_CHECK_EQUAL(dec->value, bound.note.value);
    BOOST_CHECK(dec->recipient_pk_hash == bound.note.recipient_pk_hash);
    BOOST_CHECK(dec->rho == bound.note.rho);
    BOOST_CHECK(dec->rcm == bound.note.rcm);
    BOOST_CHECK(dec->memo == bound.note.memo);
    BOOST_CHECK(same_bucket_dec->memo == padded_same_bucket.note.memo);
    BOOST_CHECK(long_dec->memo == padded_long.note.memo);

    const auto legacy = shielded::NoteEncryption::EncryptDeterministic(bound.note, recipient.pk, kem_seed, nonce);
    const auto legacy_long = shielded::NoteEncryption::EncryptDeterministic(
        padded_long.note,
        recipient.pk,
        kem_seed,
        long_nonce);
    BOOST_CHECK_EQUAL(bound.encrypted_note.Serialize().size(),
                      padded_same_bucket.encrypted_note.Serialize().size());
    BOOST_CHECK_LT(bound.encrypted_note.Serialize().size(),
                   padded_long.encrypted_note.Serialize().size());
    BOOST_CHECK_LT(legacy.Serialize().size(), legacy_long.Serialize().size());
}

BOOST_AUTO_TEST_CASE(encrypted_note_deserialize_rejects_oversized_ciphertext_payload)
{
    const auto recipient = mlkem::KeyGen();

    ShieldedNote note;
    note.value = 2 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    const auto enc = shielded::NoteEncryption::Encrypt(note, recipient.pk);

    DataStream malformed{};
    malformed << enc.kem_ciphertext;
    WriteCompactSize(malformed, static_cast<uint64_t>(shielded::EncryptedNote::MAX_AEAD_CIPHERTEXT_SIZE + 1));

    const auto bytes = MakeUCharSpan(malformed);
    const auto decoded = shielded::EncryptedNote::Deserialize(bytes);
    BOOST_CHECK(!decoded.has_value());
}

BOOST_AUTO_TEST_CASE(trydecrypt_rejects_oversized_runtime_ciphertext_payload)
{
    const auto recipient = mlkem::KeyGen();

    ShieldedNote note;
    note.value = 2 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    auto enc = shielded::NoteEncryption::Encrypt(note, recipient.pk);
    enc.aead_ciphertext.resize(shielded::EncryptedNote::MAX_AEAD_CIPHERTEXT_SIZE + 1, 0xAA);

    const auto dec = shielded::NoteEncryption::TryDecrypt(enc, recipient.pk, recipient.sk);
    BOOST_CHECK(!dec.has_value());
}

BOOST_AUTO_TEST_CASE(trydecrypt_rejects_undersized_runtime_ciphertext_payload)
{
    const auto recipient = mlkem::KeyGen();

    ShieldedNote note;
    note.value = 2 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    note.rho = GetRandHash();
    note.rcm = GetRandHash();

    auto enc = shielded::NoteEncryption::Encrypt(note, recipient.pk);
    enc.aead_ciphertext.resize(15);

    const auto dec = shielded::NoteEncryption::TryDecrypt(enc, recipient.pk, recipient.sk);
    BOOST_CHECK(!dec.has_value());
}

// R6-318: Fully deterministic note encryption KAT with pinned ciphertext hash.
BOOST_AUTO_TEST_CASE(note_encryption_deterministic_kat_frozen)
{
    // All inputs are deterministic — no GetRandHash().
    std::array<uint8_t, mlkem::KEYGEN_SEEDBYTES> key_seed;
    key_seed.fill(0x33);
    const auto recipient = mlkem::KeyGenDerand(key_seed);

    ShieldedNote note;
    note.value = 13 * COIN;
    note.recipient_pk_hash = uint256::ONE;
    // Deterministic rho and rcm
    note.rho = uint256{0xAA};
    note.rcm = uint256{0xBB};
    note.memo = {0xAA, 0xBB, 0xCC};

    std::array<uint8_t, mlkem::ENCAPS_SEEDBYTES> kem_seed;
    kem_seed.fill(0x5A);
    std::array<uint8_t, 12> nonce;
    nonce.fill(0xC3);

    const auto enc = shielded::NoteEncryption::EncryptDeterministic(note, recipient.pk, kem_seed, nonce);
    const auto serialized = enc.Serialize();

    // Hash the serialized ciphertext for regression pinning
    CSHA256 hasher;
    hasher.Write(serialized.data(), serialized.size());
    unsigned char digest[32];
    hasher.Finalize(digest);
    uint256 ct_hash;
    std::memcpy(ct_hash.begin(), digest, 32);

    // R6-318: Frozen — detects silent changes to encryption scheme or key derivation.
    BOOST_CHECK_EQUAL(ct_hash.GetHex(),
                      "f83ab17ce55012ffa0f30116da763483aff178ea5ffd1076d3f5f660007fccd9");

    // Verify determinism: second encryption produces identical result
    const auto enc2 = shielded::NoteEncryption::EncryptDeterministic(note, recipient.pk, kem_seed, nonce);
    BOOST_CHECK(enc.Serialize() == enc2.Serialize());

    // Verify decryption roundtrip
    const auto dec = shielded::NoteEncryption::TryDecrypt(enc, recipient.pk, recipient.sk);
    BOOST_CHECK(dec.has_value());
    if (dec) {
        BOOST_CHECK_EQUAL(dec->value, note.value);
    }
}

BOOST_AUTO_TEST_SUITE_END()
