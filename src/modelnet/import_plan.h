// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_IMPORT_PLAN_H
#define BITCOIN_MODELNET_IMPORT_PLAN_H

#include <modelnet/byte_source.h>
#include <univalue.h>

#include <string>
#include <vector>

namespace modelnet {

enum class ImportSourceKind {
    LOCAL = 0,
    HUGGINGFACE = 1,
    TORRENT = 2,
    MAGNET = 3,
    BTX = 4,
    S3 = 5,
};

struct ImportFileSpec {
    std::string source_path;
    std::string destination_path;
    uint64_t size_bytes{0};
};

/** Immutable once ParseImportPlan succeeds. */
struct ImportPlan {
    std::string plan_id;
    ImportSourceKind kind{ImportSourceKind::LOCAL};
    std::string locator;
    std::string snapshot_token;
    std::string resolved_revision;
    std::string expected_btx_manifest;
    std::vector<ImportFileSpec> files;
    std::string provenance_note; // source integrity; not authorship
};

bool ParseImportPlan(const UniValue& json, ImportPlan& out, std::string& err);
UniValue ImportPlanJson(const ImportPlan& plan);
bool ImportSourceKindFromName(const std::string& name, ImportSourceKind& out);

} // namespace modelnet

#endif // BITCOIN_MODELNET_IMPORT_PLAN_H
