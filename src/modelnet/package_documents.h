// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PACKAGE_DOCUMENTS_H
#define BITCOIN_MODELNET_PACKAGE_DOCUMENTS_H

#include <univalue.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

inline constexpr size_t DOC_MAX_COUNT = 32;
inline constexpr size_t DOC_MAX_BYTES = 65536;
inline constexpr size_t DOC_AGENTS_MAX_BYTES = 24576;
inline constexpr size_t DOC_AGGREGATE_MAX_BYTES = 262144;

struct PackageDocument {
    std::string path;
    std::string media_type;
    std::string encoding{"utf-8"};
    std::string text;
    uint64_t size_bytes{0};
    std::string sha384_hex;
};

bool DocumentPathAllowed(const std::string& path, std::string& err);
bool ValidatePackageDocuments(const UniValue& documents, std::string& err_code, std::string& err);
bool GetPackageDocument(const UniValue& core, const std::string& path, PackageDocument& out, std::string& err);
/** Escape C0/C1 and ANSI for terminal; never write project AGENTS.md. */
std::string EscapeForTerminal(const std::string& text);
bool GenerateAgentsMarkdown(const UniValue& core, std::string& out, std::string& err);
bool LintAgentsContradictions(const UniValue& core, const std::string& agents_text, std::vector<std::string>& flags);
/**
 * Exclusive no-follow extract into dest_dir. dest must be an existing empty
 * directory that is not a symlink. Overwrite and symlink targets fail closed.
 * extract_agents=false never writes AGENTS.md even into dest.
 */
bool ExtractPackageDocuments(const UniValue& core, const std::string& dest_dir, bool extract_agents,
                             std::string& err_code, std::string& err);
/**
 * Readable JSON/Markdown sidecar is never package-core authority. Matching
 * package_core_id + retrieval_mode is still nonauthoritative preview; mismatch
 * is SIDECAR_MISMATCH and must not drive install/model/economics.
 */
bool SidecarPreviewMatchesCore(const UniValue& sidecar, const UniValue& core, std::string& err_code,
                               std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PACKAGE_DOCUMENTS_H
