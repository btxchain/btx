// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RESOURCE_URI_H
#define BITCOIN_MODELNET_RESOURCE_URI_H

#include <modelnet/types.h>

#include <optional>
#include <string>
#include <string_view>

namespace modelnet {

struct Resource {
    ResourceKind kind{ResourceKind::MODEL};
    Digest48 digest{};
    std::string Uri() const;
};

/** Canonical encode: btx:// + 85-char Bech32m token. */
bool EncodeResource(ResourceKind kind, const Digest48& digest, std::string& uri, std::string& err);

/** Decode canonical btx://, convenience btx:, or a bare 85-char token. */
bool DecodeResource(std::string_view text, Resource& out, std::string& err);

/** Low-level helper used by negative tests (does not check kind registry). */
bool RawToken(uint8_t version, uint8_t kind, const Digest48& digest, std::string& token, std::string& err);

bool BridgePath(const std::string& uri, const std::string& origin, std::string& out, std::string& err);
bool SplitBridgeHost(const std::string& uri, const std::string& suffix, std::string& out, std::string& err);

/** Truncated display (`btx://abcdefgh...last8`). Not decodable. Empty if `text` is not a URI. */
std::string ShortDisplayUri(std::string_view text);
/** Canonical full URI for clipboard/copy. Empty if `text` is not a URI. Never returns the short form. */
std::string CopyUri(std::string_view text);

} // namespace modelnet

#endif // BITCOIN_MODELNET_RESOURCE_URI_H
