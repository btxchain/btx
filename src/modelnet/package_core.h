// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PACKAGE_CORE_H
#define BITCOIN_MODELNET_PACKAGE_CORE_H

#include <modelnet/package_bundle.h>
#include <modelnet/capability_types.h>
#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

inline constexpr uint64_t BTX_PACKAGE_MAX_PAYLOAD = 4ull * 1024 * 1024;
inline constexpr const char* PACKAGE_CORE_V1_DOMAIN = "BTX/PackageCore/v1";
inline constexpr const char* PACKAGE_CORE_V2_DOMAIN = "BTX/PackageCore/v2";
inline constexpr const char* AGENT_HANDOFF_V1 = "AGENT_HANDOFF_V1";
inline constexpr const char* BTXPKG_CORE_V2 = "BTXPKG_CORE_V2";

enum class PackageCoreVersion : int { V1 = 1, V2 = 2, V3 = 3 };

struct DecodedBtxPackage {
    uint32_t flags{0};
    uint64_t payload_len{0};
    Digest48 frame_sha384{};
    UniValue payload;
    UniValue core;
    int core_version{0};
    Digest48 package_core_id{};
    std::string err_code;
};

bool PackageCoreId(const UniValue& core, Digest48& out, std::string& err);
/**
 * Canonical BTX-PJSON1 body under the shared BTXPKG_MAGIC 68-byte header.
 * EncodeBtxBundle/DecodeBtxBundle (package_bundle.h) use the same magic and
 * header with a UniValue::write() JSON body; the two bodies do not decode
 * across. New callers should use this pair.
 */
bool EncodeBtxPackage(const UniValue& payload, std::vector<unsigned char>& out, std::string& err);
bool DecodeBtxPackage(Span<const unsigned char> data, DecodedBtxPackage& out, std::string& err);
/** Strict Core v2 + AGENT_HANDOFF_V1. Unknown fields fail closed. */
bool ValidateAgentPackageCore(const UniValue& core, std::string& err_code, std::string& err);
/** Strict Core v3 + CAPABILITY_HANDOFF_V1. Domain BTX/PackageCore/v3. */
bool ValidateCapabilityPackageCore(const UniValue& core, std::string& err_code, std::string& err);
bool ValidateAgentHandoff(const UniValue& core, std::string& err_code, std::string& err);
bool ValidatePackagePayload(const UniValue& payload, std::string& err_code, std::string& err);
/** Verify PACKAGE_CORE / ML-DSA-44 over the 48-byte core id. Trust is separate. */
bool VerifyPackageCoreSignature(const Digest48& core_id, const UniValue& signature, std::string& err_code,
                               std::string& err);
bool ParseAgentPackageFile(Span<const unsigned char> data, DecodedBtxPackage& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PACKAGE_CORE_H
