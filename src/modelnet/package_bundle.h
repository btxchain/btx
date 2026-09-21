// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PACKAGE_BUNDLE_H
#define BITCOIN_MODELNET_PACKAGE_BUNDLE_H

#include <span.h>
#include <univalue.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/** Binary .btxbundle framing. exportmodellink remains the JSON magnet analog. */
inline constexpr unsigned char BTXPKG_MAGIC[8] = {'B', 'T', 'X', 'P', 'K', 'G', 0x00, 0x01};

/**
 * Shared 68-byte header with EncodeBtxPackage/DecodeBtxPackage (package_core.h):
 * magic[8] | flags LE32 | len LE64 | SHA-384 of body[48]. Magic stays BTXPKG1
 * so LooksLikeBtxBundle (package_export) still sniffs these frames. Bodies are
 * not interchangeable: this pair writes UniValue::write() JSON, package_core
 * writes canonical BTX-PJSON1.
 *
 * flags is the discriminator. package_core emits 0 (BTXPKG_CORE_FLAGS). This
 * pair emits BTXPKG_BUNDLE_FLAGS. flags=0 is not a valid bundle discriminator
 * when a PJSON1 package body is also present: DecodeBtxBundle rejects that
 * conflicting dual body instead of silently winning as JSON.
 */
inline constexpr uint32_t BTXPKG_CORE_FLAGS = 0;
inline constexpr uint32_t BTXPKG_BUNDLE_FLAGS = 0x4a01;

static_assert(BTXPKG_BUNDLE_FLAGS != BTXPKG_CORE_FLAGS,
              "bundle JSON and PJSON1 package bodies must not share flags=0");

bool EncodeBtxBundle(const UniValue& value, std::vector<unsigned char>& out, std::string& err);
bool DecodeBtxBundle(Span<const unsigned char> data, UniValue& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PACKAGE_BUNDLE_H
