// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_CRYPTO_H
#define BITCOIN_MODELNET_CRYPTO_H

#include <modelnet/types.h>

#include <span.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Domain-separated SHA-384: SHA384(le16(len(name)) || name || le64(len(body)) || body). */
Digest48 DomainHash(const std::string& domain, Span<const unsigned char> body);

std::vector<unsigned char> HkdfSha384(Span<const unsigned char> ikm,
                                       Span<const unsigned char> salt,
                                       Span<const unsigned char> info,
                                       size_t length);

/** IETF XChaCha20-Poly1305 (24-byte nonce, 16-byte tag appended). */
bool XChaCha20Poly1305Encrypt(Span<const unsigned char> key,
                              Span<const unsigned char> nonce24,
                              Span<const unsigned char> aad,
                              Span<const unsigned char> plaintext,
                              std::vector<unsigned char>& ciphertext_and_tag);

bool XChaCha20Poly1305Decrypt(Span<const unsigned char> key,
                              Span<const unsigned char> nonce24,
                              Span<const unsigned char> aad,
                              Span<const unsigned char> ciphertext_and_tag,
                              std::vector<unsigned char>& plaintext);

Hash32 Sha256(Span<const unsigned char> data);

/** BTXENC2 envelope: magic "BTXENC2\\0" || nonce24 || XChaCha20-Poly1305(ct||tag).
 *  Key is HKDF-SHA384(secret32, info="BTX/ReleaseCipher/v1")[:32]. Never stores the secret. */
bool LooksLikeBtxEnc2(Span<const unsigned char> bytes);
bool WrapBtxEnc2(Span<const unsigned char> secret32, Span<const unsigned char> plaintext,
                 std::vector<unsigned char>& wrapped, std::string& err);
bool UnwrapBtxEnc2(Span<const unsigned char> secret32, Span<const unsigned char> wrapped,
                    std::vector<unsigned char>& plaintext, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_CRYPTO_H
