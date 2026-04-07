// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SHIELDED_NOTE_ENCRYPTION_H
#define BITCOIN_SHIELDED_NOTE_ENCRYPTION_H

#include <crypto/ml_kem.h>
#include <shielded/note.h>

#include <serialize.h>

#include <array>
#include <cstdint>
#include <ios>
#include <optional>
#include <vector>

namespace shielded {

/** Encrypted wire representation of a shielded note. */
struct EncryptedNote {
    static constexpr size_t MAX_AEAD_CIPHERTEXT_SIZE{2048};

    mlkem::Ciphertext kem_ciphertext{};
    std::array<uint8_t, 12> aead_nonce{};
    std::vector<uint8_t> aead_ciphertext;
    uint8_t view_tag{0};

    [[nodiscard]] std::vector<uint8_t> Serialize() const;
    [[nodiscard]] static std::optional<EncryptedNote> Deserialize(Span<const uint8_t> data);

    // The reset-chain wire format derives the AEAD nonce from the ML-KEM
    // shared secret and recomputes the view tag when needed, so neither value
    // needs to ride on-chain.
    static constexpr size_t OVERHEAD{mlkem::CIPHERTEXTBYTES + 16};

    SERIALIZE_METHODS(EncryptedNote, obj)
    {
        READWRITE(obj.kem_ciphertext);
        if constexpr (ser_action.ForRead()) {
            uint64_t ct_size{0};
            ::Unserialize(s, COMPACTSIZE(ct_size));
            if (ct_size > MAX_AEAD_CIPHERTEXT_SIZE) {
                throw std::ios_base::failure("EncryptedNote::Unserialize oversized aead_ciphertext");
            }
            obj.aead_ciphertext.resize(ct_size);
            if (ct_size > 0) {
                s.read(AsWritableBytes(Span<uint8_t>{obj.aead_ciphertext.data(), obj.aead_ciphertext.size()}));
            }
        } else {
            const uint64_t ct_size = obj.aead_ciphertext.size();
            if (ct_size > MAX_AEAD_CIPHERTEXT_SIZE) {
                throw std::ios_base::failure("EncryptedNote::Serialize oversized aead_ciphertext");
            }
            ::Serialize(s, COMPACTSIZE(ct_size));
            if (ct_size > 0) {
                s.write(AsBytes(Span<const uint8_t>{obj.aead_ciphertext.data(), obj.aead_ciphertext.size()}));
            }
        }
    }
};

struct BoundEncryptedNoteResult {
    ShieldedNote note;
    EncryptedNote encrypted_note;
};

/** Note encryption/decryption using ML-KEM + HKDF + ChaCha20-Poly1305. */
class NoteEncryption
{
public:
    /** Encrypt a note for a recipient public key. */
    [[nodiscard]] static EncryptedNote Encrypt(const ShieldedNote& note,
                                               const mlkem::PublicKey& recipient_pk);

    /** Encrypt a note while deriving rho/rcm from the KEM shared secret.
     *  This compact transport keeps the final note semantics intact while
     *  removing explicit rho/rcm transport from user-facing ciphertexts. */
    [[nodiscard]] static BoundEncryptedNoteResult EncryptBoundNote(
        const ShieldedNote& note_template,
        const mlkem::PublicKey& recipient_pk);

    /** Deterministic encryption for test vectors. */
    [[nodiscard]] static EncryptedNote EncryptDeterministic(const ShieldedNote& note,
                                                            const mlkem::PublicKey& recipient_pk,
                                                            Span<const uint8_t> kem_seed,
                                                            Span<const uint8_t> nonce);

    /** Deterministic bound-note encryption for transport/size tests. */
    [[nodiscard]] static BoundEncryptedNoteResult EncryptBoundNoteDeterministic(
        const ShieldedNote& note_template,
        const mlkem::PublicKey& recipient_pk,
        Span<const uint8_t> kem_seed,
        Span<const uint8_t> nonce);

    /** Attempt decryption; returns nullopt on failure.
     *  SideChannel F2 fix: constant_time_scan defaults to true to prevent
     *  timing side-channels from view-tag early exit that could allow
     *  network observers to statistically determine which notes belong
     *  to a wallet based on trial-decryption latency differences. */
    [[nodiscard]] static std::optional<ShieldedNote> TryDecrypt(const EncryptedNote& enc_note,
                                                                const mlkem::PublicKey& kem_pk,
                                                                const mlkem::SecretKey& kem_sk,
                                                                bool constant_time_scan = true);

    /** Compute 1-byte view tag from public data. */
    [[nodiscard]] static uint8_t ComputeViewTag(const mlkem::Ciphertext& kem_ct,
                                                const mlkem::PublicKey& pk);

private:
    /** HKDF-SHA256(shared_secret, salt, info) -> 32-byte AEAD key. */
    [[nodiscard]] static std::vector<uint8_t, secure_allocator<uint8_t>> DeriveAeadKey(
        Span<const uint8_t> shared_secret);

    /** HKDF-SHA256(shared_secret, salt, info) -> 96-bit AEAD nonce. */
    [[nodiscard]] static std::array<uint8_t, 12> DeriveAeadNonce(
        Span<const uint8_t> shared_secret);
};

} // namespace shielded

#endif // BITCOIN_SHIELDED_NOTE_ENCRYPTION_H
