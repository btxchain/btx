// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <shielded/note_encryption.h>

#include <crypto/chacha20poly1305.h>
#include <crypto/common.h>
#include <crypto/hkdf_sha256_32.h>
#include <random.h>
#include <streams.h>
#include <support/cleanse.h>
#include <util/check.h>

extern "C" {
#include <crypto/ml-kem-768/fips202.h>
}

#include <cstring>
#include <algorithm>
#include <exception>
#include <string_view>
#include <stdexcept>

namespace shielded {

namespace {
constexpr const char* KDF_SALT{"BTX-ShieldedPool"};
constexpr const char* KDF_INFO_KEY{"BTX-Note-Encryption-Key-V2"};
constexpr const char* KDF_INFO_NONCE{"BTX-Note-Encryption-Nonce-V2"};
constexpr const char* KDF_INFO_BOUND_RHO{"BTX-Note-Bound-Rho-V1"};
constexpr const char* KDF_INFO_BOUND_RCM{"BTX-Note-Bound-Rcm-V1"};
constexpr const char* KDF_INFO_BOUND_RHO_V2{"BTX-Note-Bound-Rho-V2"};
constexpr const char* KDF_INFO_BOUND_RCM_V2{"BTX-Note-Bound-Rcm-V2"};
constexpr std::array<uint8_t, 4> COMPACT_NOTE_MAGIC{{'B', 'N', 'O', '1'}};
constexpr std::array<uint8_t, 4> PADDED_BOUND_NOTE_MAGIC{{'B', 'N', 'O', '2'}};
constexpr std::array<uint8_t, 4> BUCKETED_BOUND_NOTE_MAGIC{{'B', 'N', 'O', '3'}};

enum class BoundMemoBucket : uint8_t {
    SMALL_32 = 0,
    MEDIUM_128 = 1,
    LARGE_512 = 2,
};

[[nodiscard]] bool IsValidBoundMemoBucket(BoundMemoBucket bucket)
{
    switch (bucket) {
    case BoundMemoBucket::SMALL_32:
    case BoundMemoBucket::MEDIUM_128:
    case BoundMemoBucket::LARGE_512:
        return true;
    }
    return false;
}

[[nodiscard]] size_t GetBoundMemoBucketSize(BoundMemoBucket bucket)
{
    switch (bucket) {
    case BoundMemoBucket::SMALL_32:
        return 32;
    case BoundMemoBucket::MEDIUM_128:
        return 128;
    case BoundMemoBucket::LARGE_512:
        return MAX_SHIELDED_MEMO_SIZE;
    }
    return MAX_SHIELDED_MEMO_SIZE;
}

[[nodiscard]] BoundMemoBucket SelectBoundMemoBucket(size_t memo_size)
{
    if (memo_size <= GetBoundMemoBucketSize(BoundMemoBucket::SMALL_32)) {
        return BoundMemoBucket::SMALL_32;
    }
    if (memo_size <= GetBoundMemoBucketSize(BoundMemoBucket::MEDIUM_128)) {
        return BoundMemoBucket::MEDIUM_128;
    }
    return BoundMemoBucket::LARGE_512;
}

template <typename ByteVector>
class SecureByteVectorWriter
{
public:
    SecureByteVectorWriter(ByteVector& data, size_t pos) : m_data{data}, m_pos{pos}
    {
        if (m_pos > m_data.size()) m_data.resize(m_pos);
    }

    void write(Span<const std::byte> src)
    {
        const size_t overwrite = std::min(src.size(), m_data.size() - m_pos);
        if (overwrite > 0) {
            std::memcpy(m_data.data() + m_pos, src.data(), overwrite);
        }
        if (overwrite < src.size()) {
            const size_t append = src.size() - overwrite;
            const size_t old_size = m_data.size();
            m_data.resize(old_size + append);
            std::memcpy(m_data.data() + old_size, src.data() + overwrite, append);
        }
        m_pos += src.size();
    }

    template <typename T>
    SecureByteVectorWriter& operator<<(const T& obj)
    {
        ::Serialize(*this, obj);
        return *this;
    }

private:
    ByteVector& m_data;
    size_t m_pos;
};

template <typename T>
std::vector<uint8_t, secure_allocator<uint8_t>> SerializeToSecureBytes(const T& obj)
{
    std::vector<uint8_t, secure_allocator<uint8_t>> bytes;
    SecureByteVectorWriter writer{bytes, 0};
    writer << obj;
    return bytes;
}

struct CompactBoundNotePlaintext {
    CAmount value{0};
    uint256 recipient_pk_hash;
    std::vector<unsigned char> memo;

    SERIALIZE_METHODS(CompactBoundNotePlaintext, obj)
    {
        if constexpr (ser_action.ForRead()) {
            std::array<uint8_t, COMPACT_NOTE_MAGIC.size()> magic{};
            s.read(AsWritableBytes(Span<uint8_t>{magic.data(), magic.size()}));
            if (magic != COMPACT_NOTE_MAGIC) {
                throw std::ios_base::failure("CompactBoundNotePlaintext::Unserialize invalid magic");
            }
        } else {
            s.write(AsBytes(Span<const uint8_t>{COMPACT_NOTE_MAGIC.data(), COMPACT_NOTE_MAGIC.size()}));
        }

        READWRITE(obj.value, obj.recipient_pk_hash);
        if constexpr (ser_action.ForRead()) {
            uint64_t memo_size{0};
            ::Unserialize(s, COMPACTSIZE(memo_size));
            if (memo_size > MAX_SHIELDED_MEMO_SIZE) {
                throw std::ios_base::failure("CompactBoundNotePlaintext::Unserialize oversized memo");
            }
            obj.memo.resize(memo_size);
            if (memo_size > 0) {
                s.read(AsWritableBytes(Span<unsigned char>{obj.memo.data(), obj.memo.size()}));
            }
        } else {
            const uint64_t memo_size = obj.memo.size();
            if (memo_size > MAX_SHIELDED_MEMO_SIZE) {
                throw std::ios_base::failure("CompactBoundNotePlaintext::Serialize oversized memo");
            }
            ::Serialize(s, COMPACTSIZE(memo_size));
            if (memo_size > 0) {
                s.write(AsBytes(Span<const unsigned char>{obj.memo.data(), obj.memo.size()}));
            }
        }
    }
};

struct PaddedBoundNotePlaintext {
    CAmount value{0};
    uint256 recipient_pk_hash;
    uint16_t memo_size{0};
    std::array<unsigned char, MAX_SHIELDED_MEMO_SIZE> memo_bytes{};
    uint8_t flags{0};
    std::array<uint8_t, 15> reserved{};

    SERIALIZE_METHODS(PaddedBoundNotePlaintext, obj)
    {
        if constexpr (ser_action.ForRead()) {
            std::array<uint8_t, PADDED_BOUND_NOTE_MAGIC.size()> magic{};
            s.read(AsWritableBytes(Span<uint8_t>{magic.data(), magic.size()}));
            if (magic != PADDED_BOUND_NOTE_MAGIC) {
                throw std::ios_base::failure("PaddedBoundNotePlaintext::Unserialize invalid magic");
            }
        } else {
            s.write(AsBytes(Span<const uint8_t>{PADDED_BOUND_NOTE_MAGIC.data(), PADDED_BOUND_NOTE_MAGIC.size()}));
        }

        READWRITE(obj.value, obj.recipient_pk_hash, obj.memo_size);
        if (obj.memo_size > MAX_SHIELDED_MEMO_SIZE) {
            throw std::ios_base::failure("PaddedBoundNotePlaintext::Serialize invalid memo size");
        }
        READWRITE(obj.memo_bytes, obj.flags, obj.reserved);
    }
};

struct BucketedBoundNotePlaintext {
    CAmount value{0};
    uint256 recipient_pk_hash;
    uint16_t memo_size{0};
    BoundMemoBucket memo_bucket{BoundMemoBucket::SMALL_32};
    uint8_t flags{0};
    std::array<uint8_t, 6> reserved{};
    std::array<unsigned char, MAX_SHIELDED_MEMO_SIZE> memo_bytes{};

    SERIALIZE_METHODS(BucketedBoundNotePlaintext, obj)
    {
        if constexpr (ser_action.ForRead()) {
            std::array<uint8_t, BUCKETED_BOUND_NOTE_MAGIC.size()> magic{};
            s.read(AsWritableBytes(Span<uint8_t>{magic.data(), magic.size()}));
            if (magic != BUCKETED_BOUND_NOTE_MAGIC) {
                throw std::ios_base::failure("BucketedBoundNotePlaintext::Unserialize invalid magic");
            }
        } else {
            s.write(AsBytes(Span<const uint8_t>{BUCKETED_BOUND_NOTE_MAGIC.data(),
                                                BUCKETED_BOUND_NOTE_MAGIC.size()}));
        }

        READWRITE(obj.value, obj.recipient_pk_hash, obj.memo_size);
        uint8_t memo_bucket_byte = static_cast<uint8_t>(obj.memo_bucket);
        READWRITE(memo_bucket_byte);
        if constexpr (ser_action.ForRead()) {
            obj.memo_bucket = static_cast<BoundMemoBucket>(memo_bucket_byte);
            if (!IsValidBoundMemoBucket(obj.memo_bucket)) {
                throw std::ios_base::failure(
                    "BucketedBoundNotePlaintext::Unserialize invalid memo_bucket");
            }
        }
        READWRITE(obj.flags, obj.reserved);

        const size_t bucket_size = GetBoundMemoBucketSize(obj.memo_bucket);
        if (obj.memo_size > bucket_size || obj.memo_size > MAX_SHIELDED_MEMO_SIZE) {
            throw std::ios_base::failure("BucketedBoundNotePlaintext::Serialize invalid memo size");
        }

        if constexpr (ser_action.ForRead()) {
            std::fill(obj.memo_bytes.begin(), obj.memo_bytes.end(), 0);
            s.read(AsWritableBytes(Span<unsigned char>{obj.memo_bytes.data(), bucket_size}));
        } else {
            s.write(AsBytes(Span<const unsigned char>{obj.memo_bytes.data(), bucket_size}));
        }
    }
};

bool IsBoundNoteTemplateValid(const ShieldedNote& note)
{
    return MoneyRange(note.value) &&
           !note.recipient_pk_hash.IsNull() &&
           note.memo.size() <= MAX_SHIELDED_MEMO_SIZE;
}

uint256 DeriveBoundNoteHash(Span<const uint8_t> shared_secret,
                            std::string_view info,
                            const uint256& recipient_pk_hash)
{
    CHKDF_HMAC_SHA256_L32 hkdf(shared_secret.data(), shared_secret.size(), KDF_SALT);
    std::array<uint8_t, 32> expanded{};
    hkdf.Expand32(info.data(), expanded.data());
    CSHA256 hasher;
    hasher.Write(expanded.data(), expanded.size());
    hasher.Write(recipient_pk_hash.begin(), recipient_pk_hash.size());
    uint256 out;
    hasher.Finalize(out.begin());
    memory_cleanse(expanded.data(), expanded.size());
    return out;
}

ShieldedNote BuildBoundNote(const ShieldedNote& note_template, Span<const uint8_t> shared_secret)
{
    ShieldedNote note = note_template;
    note.rho = DeriveBoundNoteHash(shared_secret, KDF_INFO_BOUND_RHO, note.recipient_pk_hash);
    note.rcm = DeriveBoundNoteHash(shared_secret, KDF_INFO_BOUND_RCM, note.recipient_pk_hash);
    return note;
}

ShieldedNote BuildBoundNoteV2(const ShieldedNote& note_template, Span<const uint8_t> shared_secret)
{
    ShieldedNote note = note_template;
    note.rho = DeriveBoundNoteHash(shared_secret, KDF_INFO_BOUND_RHO_V2, note.recipient_pk_hash);
    note.rcm = DeriveBoundNoteHash(shared_secret, KDF_INFO_BOUND_RCM_V2, note.recipient_pk_hash);
    MarkShieldedNoteForModernDerivation(note);
    return note;
}

template <typename PlaintextBytes>
EncryptedNote EncryptPlaintext(const mlkem::EncapsResult& kem,
                               const mlkem::PublicKey& recipient_pk,
                               PlaintextBytes&& plaintext)
{
    std::vector<uint8_t, secure_allocator<uint8_t>> aead_key(32, 0);
    CHKDF_HMAC_SHA256_L32 hkdf_key(kem.ss.data(), kem.ss.size(), KDF_SALT);
    hkdf_key.Expand32(KDF_INFO_KEY, aead_key.data());
    std::array<uint8_t, 12> aead_nonce{};
    std::array<uint8_t, 32> expanded_nonce{};
    CHKDF_HMAC_SHA256_L32 hkdf_nonce(kem.ss.data(), kem.ss.size(), KDF_SALT);
    hkdf_nonce.Expand32(KDF_INFO_NONCE, expanded_nonce.data());
    std::copy_n(expanded_nonce.begin(), aead_nonce.size(), aead_nonce.begin());
    memory_cleanse(expanded_nonce.data(), expanded_nonce.size());

    EncryptedNote result;
    result.kem_ciphertext = kem.ct;
    result.aead_nonce = aead_nonce;
    result.aead_ciphertext.resize(plaintext.size() + AEADChaCha20Poly1305::EXPANSION);

    {
        AEADChaCha20Poly1305 aead(MakeByteSpan(aead_key));
        const uint32_t nonce_prefix = ReadLE32(aead_nonce.data());
        const uint64_t nonce_suffix = ReadLE64(aead_nonce.data() + 4);
        const AEADChaCha20Poly1305::Nonce96 nonce96{nonce_prefix, nonce_suffix};
        aead.Encrypt(MakeByteSpan(plaintext),
                     MakeByteSpan(result.kem_ciphertext),
                     nonce96,
                     MakeWritableByteSpan(result.aead_ciphertext));
    }

    result.view_tag = NoteEncryption::ComputeViewTag(result.kem_ciphertext, recipient_pk);

    if (!plaintext.empty()) {
        memory_cleanse(plaintext.data(), plaintext.size());
    }
    memory_cleanse(aead_key.data(), aead_key.size());
    return result;
}

BoundEncryptedNoteResult EncryptBoundNoteInternal(const ShieldedNote& note_template,
                                                  const mlkem::PublicKey& recipient_pk,
                                                  Span<const uint8_t> kem_seed)
{
    if (!IsBoundNoteTemplateValid(note_template)) {
        throw std::invalid_argument("EncryptBoundNote: invalid note template");
    }
    if (kem_seed.size() != mlkem::ENCAPS_SEEDBYTES) {
        throw std::invalid_argument("EncryptBoundNote: kem_seed size mismatch");
    }

    mlkem::EncapsResult kem = mlkem::EncapsDerand(recipient_pk, kem_seed);
    ShieldedNote note = BuildBoundNoteV2(note_template, kem.ss);
    if (!note.IsValid()) {
        throw std::invalid_argument("EncryptBoundNote: derived note invalid");
    }

    BucketedBoundNotePlaintext compact;
    compact.value = note.value;
    compact.recipient_pk_hash = note.recipient_pk_hash;
    compact.memo_size = static_cast<uint16_t>(note.memo.size());
    compact.memo_bucket = SelectBoundMemoBucket(note.memo.size());
    std::copy(note.memo.begin(), note.memo.end(), compact.memo_bytes.begin());
    auto plaintext = SerializeToSecureBytes(compact);

    BoundEncryptedNoteResult out;
    out.note = std::move(note);
    out.encrypted_note = EncryptPlaintext(kem, recipient_pk, plaintext);
    memory_cleanse(kem.ss.data(), kem.ss.size());
    return out;
}

std::optional<ShieldedNote> TryDecryptCompactBoundNote(const std::vector<uint8_t, secure_allocator<uint8_t>>& plaintext,
                                                       Span<const uint8_t> shared_secret)
{
    try {
        SpanReader note_stream{Span<const unsigned char>{plaintext.data(), plaintext.size()}};
        CompactBoundNotePlaintext compact;
        note_stream >> compact;
        if (!note_stream.empty()) {
            return std::nullopt;
        }
        ShieldedNote note;
        note.value = compact.value;
        note.recipient_pk_hash = compact.recipient_pk_hash;
        note.memo = std::move(compact.memo);
        note = BuildBoundNote(note, shared_secret);
        if (!note.IsValid()) {
            return std::nullopt;
        }
        return note;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<ShieldedNote> TryDecryptPaddedBoundNote(const std::vector<uint8_t, secure_allocator<uint8_t>>& plaintext,
                                                      Span<const uint8_t> shared_secret)
{
    try {
        SpanReader note_stream{Span<const unsigned char>{plaintext.data(), plaintext.size()}};
        PaddedBoundNotePlaintext compact;
        note_stream >> compact;
        if (!note_stream.empty()) {
            return std::nullopt;
        }
        ShieldedNote note;
        note.value = compact.value;
        note.recipient_pk_hash = compact.recipient_pk_hash;
        note.memo.assign(compact.memo_bytes.begin(), compact.memo_bytes.begin() + compact.memo_size);
        note = BuildBoundNoteV2(note, shared_secret);
        memory_cleanse(compact.memo_bytes.data(), compact.memo_bytes.size());
        memory_cleanse(compact.reserved.data(), compact.reserved.size());
        if (!note.IsValid() || !UsesModernShieldedNoteDerivation(note)) {
            return std::nullopt;
        }
        return note;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

std::optional<ShieldedNote> TryDecryptBucketedBoundNote(
    const std::vector<uint8_t, secure_allocator<uint8_t>>& plaintext,
    Span<const uint8_t> shared_secret)
{
    try {
        SpanReader note_stream{Span<const unsigned char>{plaintext.data(), plaintext.size()}};
        BucketedBoundNotePlaintext compact;
        note_stream >> compact;
        if (!note_stream.empty()) {
            return std::nullopt;
        }
        const size_t bucket_size = GetBoundMemoBucketSize(compact.memo_bucket);
        if (compact.memo_size > bucket_size || compact.memo_size > MAX_SHIELDED_MEMO_SIZE) {
            return std::nullopt;
        }
        ShieldedNote note;
        note.value = compact.value;
        note.recipient_pk_hash = compact.recipient_pk_hash;
        note.memo.assign(compact.memo_bytes.begin(), compact.memo_bytes.begin() + compact.memo_size);
        note = BuildBoundNoteV2(note, shared_secret);
        memory_cleanse(compact.memo_bytes.data(), compact.memo_bytes.size());
        memory_cleanse(compact.reserved.data(), compact.reserved.size());
        if (!note.IsValid() || !UsesModernShieldedNoteDerivation(note)) {
            return std::nullopt;
        }
        return note;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}
} // namespace

std::vector<uint8_t> EncryptedNote::Serialize() const
{
    DataStream ss{};
    ss << kem_ciphertext << aead_ciphertext;
    const auto bytes = MakeUCharSpan(ss);
    return {bytes.begin(), bytes.end()};
}

std::optional<EncryptedNote> EncryptedNote::Deserialize(Span<const uint8_t> data)
{
    EncryptedNote out;
    try {
        DataStream ss{data};
        ss >> out.kem_ciphertext >> out.aead_ciphertext;
        if (!ss.empty()) return std::nullopt;
        return out;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

EncryptedNote NoteEncryption::Encrypt(const ShieldedNote& note, const mlkem::PublicKey& recipient_pk)
{
    std::array<uint8_t, mlkem::ENCAPS_SEEDBYTES> kem_seed;
    GetStrongRandBytes(MakeUCharSpan(kem_seed));
    const std::array<uint8_t, 12> ignored_nonce{};
    auto result = EncryptDeterministic(note, recipient_pk, kem_seed, ignored_nonce);
    memory_cleanse(kem_seed.data(), kem_seed.size());
    return result;
}

BoundEncryptedNoteResult NoteEncryption::EncryptBoundNote(const ShieldedNote& note_template,
                                                          const mlkem::PublicKey& recipient_pk)
{
    std::array<uint8_t, mlkem::ENCAPS_SEEDBYTES> kem_seed;
    GetStrongRandBytes(MakeUCharSpan(kem_seed));
    auto result = EncryptBoundNoteInternal(note_template, recipient_pk, kem_seed);
    memory_cleanse(kem_seed.data(), kem_seed.size());
    return result;
}

EncryptedNote NoteEncryption::EncryptDeterministic(const ShieldedNote& note,
                                                   const mlkem::PublicKey& recipient_pk,
                                                   Span<const uint8_t> kem_seed,
                                                   Span<const uint8_t> nonce)
{
    // R6-413 / Finding 8 fix: Validate inputs defensively and throw on invalid
    // input rather than silently returning an empty EncryptedNote that could be
    // serialized into a malformed transaction.
    if (kem_seed.size() != mlkem::ENCAPS_SEEDBYTES) {
        throw std::invalid_argument("EncryptDeterministic: kem_seed size mismatch");
    }
    if (!note.IsValid()) {
        throw std::invalid_argument("EncryptDeterministic: invalid note");
    }
    if (nonce.size() != 12) {
        throw std::invalid_argument("EncryptDeterministic: nonce must be 12 bytes");
    }

    mlkem::EncapsResult kem = mlkem::EncapsDerand(recipient_pk, kem_seed);
    auto aead_key = DeriveAeadKey(kem.ss);
    const auto aead_nonce = DeriveAeadNonce(kem.ss);

    // Serialize directly into the secure buffer to avoid transient plaintext
    // copies in the zero-after-free DataStream backing store.
    auto plaintext = SerializeToSecureBytes(note);

    EncryptedNote result;
    result.kem_ciphertext = kem.ct;
    result.aead_nonce = aead_nonce;
    result.aead_ciphertext.resize(plaintext.size() + AEADChaCha20Poly1305::EXPANSION);

    {
        AEADChaCha20Poly1305 aead(MakeByteSpan(aead_key));
        const uint32_t nonce_prefix = ReadLE32(aead_nonce.data());
        const uint64_t nonce_suffix = ReadLE64(aead_nonce.data() + 4);
        const AEADChaCha20Poly1305::Nonce96 nonce96{nonce_prefix, nonce_suffix};
        aead.Encrypt(MakeByteSpan(plaintext),
                     MakeByteSpan(result.kem_ciphertext),
                     nonce96,
                     MakeWritableByteSpan(result.aead_ciphertext));
    }

    result.view_tag = ComputeViewTag(result.kem_ciphertext, recipient_pk);

    if (!plaintext.empty()) {
        memory_cleanse(plaintext.data(), plaintext.size());
    }
    memory_cleanse(aead_key.data(), aead_key.size());
    memory_cleanse(kem.ss.data(), kem.ss.size());
    return result;
}

BoundEncryptedNoteResult NoteEncryption::EncryptBoundNoteDeterministic(
    const ShieldedNote& note_template,
    const mlkem::PublicKey& recipient_pk,
    Span<const uint8_t> kem_seed,
    Span<const uint8_t> nonce)
{
    if (nonce.size() != 12) {
        throw std::invalid_argument("EncryptBoundNoteDeterministic: nonce must be 12 bytes");
    }
    return EncryptBoundNoteInternal(note_template, recipient_pk, kem_seed);
}

std::optional<ShieldedNote> NoteEncryption::TryDecrypt(const EncryptedNote& enc_note,
                                                       const mlkem::PublicKey& kem_pk,
                                                       const mlkem::SecretKey& kem_sk,
                                                       bool constant_time_scan)
{
    if (enc_note.aead_ciphertext.size() > EncryptedNote::MAX_AEAD_CIPHERTEXT_SIZE) {
        return std::nullopt;
    }
    if (enc_note.aead_ciphertext.size() < AEADChaCha20Poly1305::EXPANSION) {
        return std::nullopt;
    }
    const bool view_tag_present = enc_note.view_tag != 0;
    const uint8_t expected_view_tag = ComputeViewTag(enc_note.kem_ciphertext, kem_pk);
    const bool view_tag_match = !view_tag_present || enc_note.view_tag == expected_view_tag;
    if (!constant_time_scan && view_tag_present && !view_tag_match) {
        return std::nullopt;
    }

    mlkem::SharedSecret ss = mlkem::Decaps(enc_note.kem_ciphertext, kem_sk);
    auto aead_key = DeriveAeadKey(ss);
    const auto aead_nonce = DeriveAeadNonce(ss);

    // R6-404: Use secure_allocator to prevent decrypted note data from being paged to swap.
    std::vector<uint8_t, secure_allocator<uint8_t>> plaintext(enc_note.aead_ciphertext.size() - AEADChaCha20Poly1305::EXPANSION);
    bool ok{false};
    {
        AEADChaCha20Poly1305 aead(MakeByteSpan(aead_key));
        const uint32_t nonce_prefix = ReadLE32(aead_nonce.data());
        const uint64_t nonce_suffix = ReadLE64(aead_nonce.data() + 4);
        const AEADChaCha20Poly1305::Nonce96 nonce96{nonce_prefix, nonce_suffix};
        ok = aead.Decrypt(MakeByteSpan(enc_note.aead_ciphertext),
                          MakeByteSpan(enc_note.kem_ciphertext),
                          nonce96,
                          MakeWritableByteSpan(plaintext));
    }
    memory_cleanse(aead_key.data(), aead_key.size());

    if (!ok || !view_tag_match) {
        memory_cleanse(ss.data(), ss.size());
        memory_cleanse(plaintext.data(), plaintext.size());
        return std::nullopt;
    }

    try {
        if (auto bucketed_note = TryDecryptBucketedBoundNote(plaintext, ss); bucketed_note.has_value()) {
            memory_cleanse(ss.data(), ss.size());
            memory_cleanse(plaintext.data(), plaintext.size());
            return bucketed_note;
        }

        if (auto padded_note = TryDecryptPaddedBoundNote(plaintext, ss); padded_note.has_value()) {
            memory_cleanse(ss.data(), ss.size());
            memory_cleanse(plaintext.data(), plaintext.size());
            return padded_note;
        }

        if (auto compact_note = TryDecryptCompactBoundNote(plaintext, ss); compact_note.has_value()) {
            memory_cleanse(ss.data(), ss.size());
            memory_cleanse(plaintext.data(), plaintext.size());
            return compact_note;
        }

        SpanReader note_stream{Span<const unsigned char>{plaintext.data(), plaintext.size()}};
        ShieldedNote note;
        note_stream >> note;
        if (!note_stream.empty()) {
            memory_cleanse(ss.data(), ss.size());
            memory_cleanse(plaintext.data(), plaintext.size());
            return std::nullopt;
        }
        if (!note.IsValid()) {
            memory_cleanse(ss.data(), ss.size());
            memory_cleanse(plaintext.data(), plaintext.size());
            return std::nullopt;
        }
        memory_cleanse(ss.data(), ss.size());
        memory_cleanse(plaintext.data(), plaintext.size());
        return note;
    } catch (const std::exception&) {
        memory_cleanse(ss.data(), ss.size());
        memory_cleanse(plaintext.data(), plaintext.size());
        return std::nullopt;
    }
}

uint8_t NoteEncryption::ComputeViewTag(const mlkem::Ciphertext& kem_ct, const mlkem::PublicKey& pk)
{
    std::array<uint8_t, mlkem::CIPHERTEXTBYTES + mlkem::PUBLICKEYBYTES> input;
    std::memcpy(input.data(), kem_ct.data(), kem_ct.size());
    std::memcpy(input.data() + kem_ct.size(), pk.data(), pk.size());

    uint8_t digest[32];
    sha3_256(digest, input.data(), input.size());
    return digest[0];
}

std::vector<uint8_t, secure_allocator<uint8_t>> NoteEncryption::DeriveAeadKey(
    Span<const uint8_t> shared_secret)
{
    std::vector<uint8_t, secure_allocator<uint8_t>> key(32, 0);
    CHKDF_HMAC_SHA256_L32 hkdf(shared_secret.data(), shared_secret.size(), KDF_SALT);
    hkdf.Expand32(KDF_INFO_KEY, key.data());
    return key;
}

std::array<uint8_t, 12> NoteEncryption::DeriveAeadNonce(Span<const uint8_t> shared_secret)
{
    std::array<uint8_t, 12> nonce{};
    std::array<uint8_t, 32> expanded{};
    CHKDF_HMAC_SHA256_L32 hkdf(shared_secret.data(), shared_secret.size(), KDF_SALT);
    hkdf.Expand32(KDF_INFO_NONCE, expanded.data());
    std::copy_n(expanded.begin(), nonce.size(), nonce.begin());
    memory_cleanse(expanded.data(), expanded.size());
    return nonce;
}

} // namespace shielded
