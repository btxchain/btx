// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_CLOUD_LAYOUT_H
#define BITCOIN_MODELNET_CLOUD_LAYOUT_H

#include <cstdint>
#include <string>
#include <string_view>

namespace modelnet {

enum class CloudProvider : uint8_t {
    AUTO = 0,
    GENERIC_S3 = 1,
    AWS_S3 = 2,
    CLOUDFLARE_R2 = 3,
    MINIO = 4,
};

enum class CloudObjectLayout : uint8_t {
    AUTO = 0,
    SOURCE_FILES = 1,
    PIECE_OBJECTS = 2,
};

enum class CloudReadStrategy : uint8_t {
    AUTO = 0,
    STREAM_FILE = 1,
    PIECE_GET = 2,
};

/** R2 PIECE_OBJECTS above this projected object count is "material" request amplification. */
constexpr uint64_t kR2HeavyPieceObjectThreshold = 64;

const char* CloudProviderName(CloudProvider p);
const char* CloudObjectLayoutName(CloudObjectLayout l);
const char* CloudReadStrategyName(CloudReadStrategy s);

bool CloudProviderFromName(std::string_view name, CloudProvider& out);
bool CloudObjectLayoutFromName(std::string_view name, CloudObjectLayout& out);
bool CloudReadStrategyFromName(std::string_view name, CloudReadStrategy& out);

/**
 * True only for the standard R2 object hostname `*.r2.cloudflarestorage.com`
 * (optional apex `r2.cloudflarestorage.com`). Custom domains are never inferred.
 */
bool EndpointLooksLikeCloudflareR2(std::string_view endpoint);

/** Explicit CLOUDFLARE_R2, or AUTO plus a standard R2 hostname. */
bool CloudProviderIsR2(CloudProvider provider, std::string_view endpoint);

/**
 * R2 (explicit or auto-detected standard hostname) + AUTO layout → SOURCE_FILES + STREAM_FILE.
 * R2 + PIECE_OBJECTS + material projected_piece_objects + !allow_request_heavy → reject.
 * Always fills out_layout / out_strategy. On reject, they describe the refused plan.
 */
bool ResolveCloudLayout(CloudProvider provider,
                        std::string_view endpoint,
                        CloudObjectLayout explicit_layout,
                        bool allow_request_heavy,
                        uint64_t projected_piece_objects,
                        CloudObjectLayout& out_layout,
                        CloudReadStrategy& out_strategy,
                        std::string& reject_reason);

/** SOURCE_FILES / AUTO → n_files; PIECE_OBJECTS → n_pieces. */
uint64_t EstimatedGetsPerColdRetrieval(CloudObjectLayout layout, uint64_t n_files, uint64_t n_pieces);

/** `<prefix>/artifacts/<artifact_hex>/files/<file_index>` */
std::string ObjectKeySourceFile(std::string_view prefix, std::string_view artifact_hex, uint32_t file_index);
/** `<prefix>/artifacts/<artifact_hex>/<file_index>/<piece_index>.piece` */
std::string ObjectKeyPiece(std::string_view prefix, std::string_view artifact_hex, uint32_t file_index, uint32_t piece_index);

bool NormalizeCloudKeyPrefix(std::string_view prefix, std::string& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_CLOUD_LAYOUT_H
