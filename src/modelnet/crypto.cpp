// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/crypto.h>

#include <crypto/chacha20poly1305.h>
#include <crypto/common.h>
#include <crypto/hmac_sha384.h>
#include <crypto/sha256.h>
#include <crypto/sha384.h>
#include <random.h>
#include <support/cleanse.h>

#include <algorithm>
#include <bit>
#include <cstring>
#include <stdexcept>

namespace modelnet {
namespace {

#define MODELNET_QUARTERROUND(a, b, c, d) \
    a += b; d = std::rotl(d ^ a, 16); \
    c += d; b = std::rotl(b ^ c, 12); \
    a += b; d = std::rotl(d ^ a, 8); \
    c += d; b = std::rotl(b ^ c, 7);

void HChaCha20(unsigned char out[32], const unsigned char key[32], const unsigned char nonce16[16])
{
    uint32_t x0 = 0x61707865u;
    uint32_t x1 = 0x3320646eu;
    uint32_t x2 = 0x79622d32u;
    uint32_t x3 = 0x6b206574u;
    uint32_t x4 = ReadLE32(key + 0);
    uint32_t x5 = ReadLE32(key + 4);
    uint32_t x6 = ReadLE32(key + 8);
    uint32_t x7 = ReadLE32(key + 12);
    uint32_t x8 = ReadLE32(key + 16);
    uint32_t x9 = ReadLE32(key + 20);
    uint32_t x10 = ReadLE32(key + 24);
    uint32_t x11 = ReadLE32(key + 28);
    uint32_t x12 = ReadLE32(nonce16 + 0);
    uint32_t x13 = ReadLE32(nonce16 + 4);
    uint32_t x14 = ReadLE32(nonce16 + 8);
    uint32_t x15 = ReadLE32(nonce16 + 12);
    for (int i = 0; i < 10; ++i) {
        MODELNET_QUARTERROUND(x0, x4, x8, x12);
        MODELNET_QUARTERROUND(x1, x5, x9, x13);
        MODELNET_QUARTERROUND(x2, x6, x10, x14);
        MODELNET_QUARTERROUND(x3, x7, x11, x15);
        MODELNET_QUARTERROUND(x0, x5, x10, x15);
        MODELNET_QUARTERROUND(x1, x6, x11, x12);
        MODELNET_QUARTERROUND(x2, x7, x8, x13);
        MODELNET_QUARTERROUND(x3, x4, x9, x14);
    }
    WriteLE32(out + 0, x0);
    WriteLE32(out + 4, x1);
    WriteLE32(out + 8, x2);
    WriteLE32(out + 12, x3);
    WriteLE32(out + 16, x12);
    WriteLE32(out + 20, x13);
    WriteLE32(out + 24, x14);
    WriteLE32(out + 28, x15);
}

#undef MODELNET_QUARTERROUND

} // namespace

Digest48 DomainHash(const std::string& domain, Span<const unsigned char> body)
{
    if (domain.empty() || domain.size() > 255) {
        throw std::runtime_error("invalid hash domain");
    }
    for (unsigned char c : domain) {
        if (c > 127) throw std::runtime_error("invalid hash domain");
    }
    unsigned char len16[2];
    WriteLE16(len16, static_cast<uint16_t>(domain.size()));
    unsigned char len64[8];
    WriteLE64(len64, static_cast<uint64_t>(body.size()));
    Digest48 out;
    CSHA384 hasher;
    hasher.Write(len16, 2);
    hasher.Write(reinterpret_cast<const unsigned char*>(domain.data()), domain.size());
    hasher.Write(len64, 8);
    if (!body.empty()) hasher.Write(body.data(), body.size());
    hasher.Finalize(out.data.data());
    return out;
}

std::vector<unsigned char> HkdfSha384(Span<const unsigned char> ikm,
                                       Span<const unsigned char> salt,
                                       Span<const unsigned char> info,
                                       size_t length)
{
    if (length == 0 || length > 48 * 255) {
        throw std::runtime_error("HKDF-SHA384 length");
    }
    unsigned char prk[CHMAC_SHA384::OUTPUT_SIZE];
    {
        const unsigned char empty = 0;
        const unsigned char* saltp = salt.empty() ? &empty : salt.data();
        CHMAC_SHA384 extract(saltp, salt.size());
        if (!ikm.empty()) extract.Write(ikm.data(), ikm.size());
        extract.Finalize(prk);
    }
    std::vector<unsigned char> okm;
    okm.reserve(length);
    unsigned char t[CHMAC_SHA384::OUTPUT_SIZE];
    size_t tlen = 0;
    unsigned char counter = 1;
    while (okm.size() < length) {
        CHMAC_SHA384 expand(prk, sizeof(prk));
        if (tlen) expand.Write(t, tlen);
        if (!info.empty()) expand.Write(info.data(), info.size());
        expand.Write(&counter, 1);
        expand.Finalize(t);
        tlen = sizeof(t);
        const size_t take = std::min(length - okm.size(), sizeof(t));
        okm.insert(okm.end(), t, t + take);
        ++counter;
    }
    memory_cleanse(prk, sizeof(prk));
    memory_cleanse(t, sizeof(t));
    return okm;
}

bool XChaCha20Poly1305Encrypt(Span<const unsigned char> key,
                              Span<const unsigned char> nonce24,
                              Span<const unsigned char> aad,
                              Span<const unsigned char> plaintext,
                              std::vector<unsigned char>& ciphertext_and_tag)
{
    if (key.size() != 32 || nonce24.size() != 24) return false;
    unsigned char subkey[32];
    HChaCha20(subkey, key.data(), nonce24.data());
    AEADChaCha20Poly1305 aead{AsBytes(Span<const unsigned char>{subkey, 32})};
    ciphertext_and_tag.resize(plaintext.size() + AEADChaCha20Poly1305::EXPANSION);
    const AEADChaCha20Poly1305::Nonce96 nonce{
        0, ReadLE64(nonce24.data() + 16)};
    aead.Encrypt(AsBytes(plaintext), AsBytes(aad), nonce, AsWritableBytes(Span<unsigned char>{ciphertext_and_tag.data(), ciphertext_and_tag.size()}));
    memory_cleanse(subkey, sizeof(subkey));
    return true;
}

bool XChaCha20Poly1305Decrypt(Span<const unsigned char> key,
                              Span<const unsigned char> nonce24,
                              Span<const unsigned char> aad,
                              Span<const unsigned char> ciphertext_and_tag,
                              std::vector<unsigned char>& plaintext)
{
    if (key.size() != 32 || nonce24.size() != 24) return false;
    if (ciphertext_and_tag.size() < AEADChaCha20Poly1305::EXPANSION) return false;
    unsigned char subkey[32];
    HChaCha20(subkey, key.data(), nonce24.data());
    AEADChaCha20Poly1305 aead{AsBytes(Span<const unsigned char>{subkey, 32})};
    plaintext.resize(ciphertext_and_tag.size() - AEADChaCha20Poly1305::EXPANSION);
    const AEADChaCha20Poly1305::Nonce96 nonce{
        0, ReadLE64(nonce24.data() + 16)};
    const bool ok = aead.Decrypt(AsBytes(ciphertext_and_tag), AsBytes(aad), nonce, AsWritableBytes(Span<unsigned char>{plaintext.data(), plaintext.size()}));
    memory_cleanse(subkey, sizeof(subkey));
    if (!ok) plaintext.clear();
    return ok;
}

Hash32 Sha256(Span<const unsigned char> data)
{
    Hash32 out;
    CSHA256 hasher;
    if (!data.empty()) hasher.Write(data.data(), data.size());
    hasher.Finalize(out.data.data());
    return out;
}

bool LooksLikeBtxEnc2(Span<const unsigned char> bytes)
{
    static const unsigned char magic[8] = {'B', 'T', 'X', 'E', 'N', 'C', '2', 0};
    return bytes.size() >= 8 + 24 + 16 && std::memcmp(bytes.data(), magic, 8) == 0;
}

namespace {
bool ReleaseCipherKey(Span<const unsigned char> secret32, unsigned char key[32], std::string& err)
{
    if (secret32.size() != 32) {
        err = "secret must be 32 bytes";
        return false;
    }
    static const unsigned char info[] = "BTX/ReleaseCipher/v1";
    const auto okm = HkdfSha384(secret32, Span<const unsigned char>{},
                                 Span<const unsigned char>{info, sizeof(info) - 1}, 32);
    if (okm.size() != 32) {
        err = "hkdf";
        return false;
    }
    std::memcpy(key, okm.data(), 32);
    return true;
}
} // namespace

bool WrapBtxEnc2(Span<const unsigned char> secret32, Span<const unsigned char> plaintext,
                 std::vector<unsigned char>& wrapped, std::string& err)
{
    unsigned char key[32];
    if (!ReleaseCipherKey(secret32, key, err)) return false;
    unsigned char nonce[24];
    GetStrongRandBytes(Span<unsigned char>{nonce, 24});
    std::vector<unsigned char> ct;
    if (!XChaCha20Poly1305Encrypt(Span<const unsigned char>{key, 32},
                                  Span<const unsigned char>{nonce, 24}, {}, plaintext, ct)) {
        memory_cleanse(key, sizeof(key));
        err = "encrypt";
        return false;
    }
    wrapped.clear();
    wrapped.insert(wrapped.end(), {'B', 'T', 'X', 'E', 'N', 'C', '2', 0});
    wrapped.insert(wrapped.end(), nonce, nonce + 24);
    wrapped.insert(wrapped.end(), ct.begin(), ct.end());
    memory_cleanse(key, sizeof(key));
    return true;
}

bool UnwrapBtxEnc2(Span<const unsigned char> secret32, Span<const unsigned char> wrapped,
                    std::vector<unsigned char>& plaintext, std::string& err)
{
    if (!LooksLikeBtxEnc2(wrapped)) {
        err = "not BTXENC2";
        return false;
    }
    unsigned char key[32];
    if (!ReleaseCipherKey(secret32, key, err)) return false;
    const auto nonce = Span<const unsigned char>{wrapped.data() + 8, 24};
    const auto ct = Span<const unsigned char>{wrapped.data() + 32, wrapped.size() - 32};
    const bool ok = XChaCha20Poly1305Decrypt(Span<const unsigned char>{key, 32}, nonce, {}, ct, plaintext);
    memory_cleanse(key, sizeof(key));
    if (!ok) {
        err = "decrypt failed (wrong secret or corrupt ciphertext)";
        plaintext.clear();
    }
    return ok;
}

} // namespace modelnet
