// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_IMPORT_COORDINATOR_H
#define BITCOIN_MODELNET_IMPORT_COORDINATOR_H

#include <modelnet/byte_source.h>
#include <modelnet/import_plan.h>
#include <modelnet/verified_manifest.h>
#include <univalue.h>
#include <util/fs.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace modelnet {

enum class ImportPhase {
    UNPREPARED = 0,
    STAGING = 1,
    PUBLISH_READY = 2,
    FAILED = 3,
};

/**
 * Owns import identity construction. Bytes stage under a local UUID.
 * A final model_id exists only after a VerifiedManifest is accepted.
 * Source integrity (HF snapshot, torrent infohash, Xet CAS) is not authorship.
 */
class ImportCoordinator {
    const ImportPlan m_plan;
    const fs::path m_stage_root;
    const std::string m_staging_uuid;
    ImportPhase m_phase{ImportPhase::UNPREPARED};
    std::vector<ImportFileSpec> m_accepted;
    std::optional<VerifiedManifest> m_verified;
    std::string m_fail_reason;

public:
    ImportCoordinator(ImportPlan plan, fs::path stage_root);
    const ImportPlan& Plan() const { return m_plan; }
    const std::string& StagingUuid() const { return m_staging_uuid; }
    fs::path StagingDir() const;
    ImportPhase Phase() const { return m_phase; }
    const std::vector<ImportFileSpec>& AcceptedFiles() const { return m_accepted; }

    bool PrepareStaging(std::string& err);
    bool StageFromSource(ByteSource& src, const ImportFileSpec& spec, uint64_t budget_bytes, std::string& err);
    bool AcceptVerifiedManifest(const VerifiedManifest& vm, std::string& err);

    bool HasFinalModelId() const { return m_verified.has_value(); }
    Digest48 FinalModelId() const;
    Digest48 FinalArtifactId() const;
    UniValue StatusJson() const;
};

/** True for pickle / .pt / executable-like relative paths. Never execute those files. */
bool ImportRelPathUnsafe(const std::string& rel);

std::unique_ptr<ByteSource> MakePlanByteSource(const ImportPlan& plan, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_IMPORT_COORDINATOR_H
