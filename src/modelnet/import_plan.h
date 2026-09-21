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
    HTTP = 6,
    MODELSCOPE = 7,
    WISEMODEL = 8,
    OPENXLAB = 9,
    MODELERS = 10,
    GITCODE = 11,
    GITEE = 12,
    OPENI = 13,
    HF_MIRROR = 14,
    OCI = 15,
};

struct ImportFileSpec {
    std::string source_path;
    std::string destination_path;
    uint64_t size_bytes{0};
    std::string sha384_hex; // optional; failover never keys on display name. Whole-file only.
    std::vector<std::string> piece_sha384_hex; // ChunkLeaf hex; enables per-piece origin mix
};

/** One replaceable origin for the same verified artifact. Type is a resolver id, not identity. */
struct ImportOrigin {
    std::string type;
    std::string locator;
    std::string snapshot_token;
    std::string integrity;
    int priority{0};
};

/** Additional provenance slots. Native BTX publisher signatures stay first-class. */
struct ProvenanceEvidence {
    std::string kind; // btx_publisher | openssf_oms | sigstore | cosign | oci_attestation | vendor_attestation | unsigned
    std::string locator;
    std::string note;
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
    std::vector<ImportOrigin> origins;
    std::vector<ProvenanceEvidence> provenance_evidence;
    bool live_wan{false};
    bool wallet_required{false}; // fetch never requires a wallet; monetary plane is separate
    int min_independent_origins{1}; // observation target; does not fail a single-origin fetch
};

bool ParseImportPlan(const UniValue& json, ImportPlan& out, std::string& err);
UniValue ImportPlanJson(const ImportPlan& plan);
bool ImportSourceKindFromName(const std::string& name, ImportSourceKind& out);
const char* ImportSourceKindName(ImportSourceKind k);
const char* ImportOriginTypeName(ImportSourceKind k);
bool ImportOriginTypeFromName(const std::string& name, std::string& canonical);
bool ImportKindIsRegistry(ImportSourceKind k);
void SynthesizeOriginsFromV1(ImportPlan& plan);

} // namespace modelnet

#endif // BITCOIN_MODELNET_IMPORT_PLAN_H
