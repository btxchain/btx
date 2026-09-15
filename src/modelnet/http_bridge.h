// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_HTTP_BRIDGE_H
#define BITCOIN_MODELNET_HTTP_BRIDGE_H

#include <modelnet/resource_uri.h>

#include <span.h>

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

struct BrowserBridgeResponse {
    bool ok{false};
    int http_status{404};
    std::string content_type;
    std::string body;
    std::string canonical_btx;
    std::vector<std::pair<std::string, std::string>> headers;
};

/**
 * Optional v1.1 D09 / §12.1 disclosed-weaker browser edge.
 *
 * Native PQ1 stays strict inside btx-modeld. This decoder is for a *separate*
 * loopback process (contrib/modelbridge). It is not a native trust root, not a
 * wallet proxy, and not permission to restore classical TLS in the helper.
 *
 * GET /health, GET /open?uri=, optional read-only GET /api/v1/ (decode-only
 * unless BTX_BRIDGE_RPC_SOCKET points at btx-modeld unix RPC; never wallet),
 * and a bare btx:// token path. Every JSON body discloses pq_end_to_end=false,
 * btx:// token path. Every JSON body discloses pq_end_to_end=false,
 * native_fallback=false, wallet=false.
 *
 * Range query/header values are ignored: this edge never emits model bytes
 * (no application/octet-stream). headers is optional request-header text
 * (e.g. "Range: bytes=0-100") for tests; production decode is path-only.
 */
bool HandleBridgeGet(const std::string& path, BrowserBridgeResponse& out,
                     const std::string& headers = {});

/**
 * Method-aware dispatch used by the contrib loopback server (and unit tests).
 *
 * GET/HEAD → HandleBridgeGet. Mutating methods on wallet-like paths
 * (/wallet, /sign, /dump, or a POST body that names a wallet RPC) return 405.
 * GET on those paths returns 403. Never BanMan, never spend, never secrets.
 * Never fetch/upstream download. headers is forwarded and ignored for Range.
 */
bool HandleBridgeRequest(const std::string& method, const std::string& path,
                         const std::string& body, BrowserBridgeResponse& out,
                         const std::string& headers = {});

/**
 * BRIDGE-06: max DNS-wildcard depth this edge will treat as identity.
 *
 * Always 0: native-style, no wildcard certificate identity at the browser
 * edge. Operators who terminate TLS elsewhere are out of band.
 */
int BridgeTlsMaxWildcardDepth();

/**
 * BRIDGE-05: DNS 42/43 split of an 85-char Bech32m token.
 *
 * A single 85-char label exceeds the 63-char DNS limit. On success, left is
 * 42 chars, right is 43, and left+right reconstructs the token payload.
 * token may be a bare 85-char token or a canonical btx:// URI.
 * Join with DnsSplitJoin as {left}.{right}.{zone}.
 */
bool DnsSplit42_43(const std::string& token, std::string& left, std::string& right);

/** Join DnsSplit42_43 labels as {left}.{right}.{zone}. Empty on bad sizes or empty zone. */
std::string DnsSplitJoin(const std::string& left, const std::string& right, const std::string& zone);

/**
 * BRIDGE-10: map an inclusive byte range onto piece indices.
 *
 * piece_size is PIECE_SIZE from types.h (4 MiB). Rejects last_byte < first_byte
 * and piece_size == 0. Exposed for tests; HandleBridgeGet does not apply this
 * mapping to HTTP bodies (JSON-only).
 */
bool BridgeRangeToPieces(uint64_t first_byte, uint64_t last_byte, uint64_t piece_size,
                         uint32_t& first_piece, uint32_t& piece_count);

/**
 * BRIDGE-11: cache-key material for a canonical token + file index.
 *
 * Includes the full canonical URI (not a 42-char DNS split). Two different
 * tokens must not collide. HandleBridgeGet remains stateless: no disk cache of
 * model bytes.
 */
std::string BridgeCacheKey(const std::string& canonical_uri, uint32_t file_index);

/**
 * BRIDGE-07: PUBLIC_DOWNLOAD operator gate.
 *
 * Default false. True only when env BTX_BRIDGE_PUBLIC_DOWNLOAD=1.
 * HandleBridgeGet never fetches. Byte emission is HandleBridgePublicFile.
 */
bool BridgePublicDownloadEnabled();

/**
 * BRIDGE-10: emit verified file bytes only when PUBLIC_DOWNLOAD=1 and the
 * caller already holds verified bytes. Never fetches. Range maps to a slice
 * of those verified bytes. Unverified/empty input is 409, not a byte serve.
 */
bool HandleBridgePublicFile(const std::string& path, const std::string& headers,
                            Span<const unsigned char> verified,
                            BrowserBridgeResponse& out);

} // namespace modelnet

#endif // BITCOIN_MODELNET_HTTP_BRIDGE_H
