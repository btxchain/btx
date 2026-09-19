// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PACKAGE_EXPORT_H
#define BITCOIN_MODELNET_PACKAGE_EXPORT_H

#include <span.h>
#include <univalue.h>

#include <string>
#include <vector>

namespace modelnet {

/**
 * Public package helpers.
 * .btx JSON magnet analog (exportmodellink) is distinct from binary .btxbundle
 * (EncodeBtxBundle). This module does not replace either framing path.
 */
enum class PackageExportKind {
    MAGNET_ANALOG = 0,
    BINARY_BUNDLE = 1,
};

bool PublicExportKeyForbidden(const std::string& key);
bool PublicExportObjectAllowed(const UniValue& value, std::string& err);

/** True if uri query contains dn= (display names belong on copy_text only). */
bool UriQueryHasDn(const std::string& uri);

bool LooksLikeBtxBundle(Span<const unsigned char> data);
bool IsMagnetAnalogObject(const UniValue& value);

/**
 * Thin .btx JSON magnet analog: schema_version/kind/uri/copy_text plus optional
 * public metadata. Refuses secret-bearing keys. Does not emit BTXPKG bytes.
 */
bool EncodeMagnetAnalog(const UniValue& fields, UniValue& out, std::string& err);
bool ParseMagnetAnalog(const UniValue& json, UniValue& out, std::string& err);

/** Secret-scan, then existing EncodeBtxBundle / DecodeBtxBundle. No framing rewrite. */
bool EncodePublicBtxBundle(const UniValue& value, std::vector<unsigned char>& out, std::string& err);
bool DecodePublicBtxBundle(Span<const unsigned char> data, UniValue& out, std::string& err);
/**
 * Labeled legacy acquisition-only export: drops agent_handoff and encodes the
 * remaining object with EncodePublicBtxBundle. Distinct from Core v2 handoff.
 */
bool EncodeLegacyAcquisitionExport(const UniValue& value, std::vector<unsigned char>& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PACKAGE_EXPORT_H
