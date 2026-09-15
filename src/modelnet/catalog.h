// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_CATALOG_H
#define BITCOIN_MODELNET_CATALOG_H

#include <modelnet/cores.h>
#include <modelnet/piece_ranges.h>
#include <modelnet/policy.h>
#include <modelnet/qualification.h>
#include <modelnet/resource_uri.h>
#include <modelnet/store.h>
#include <span.h>
#include <univalue.h>
#include <util/fs.h>

#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

struct CatalogEntry {
    Digest48 model_id;
    Digest48 artifact_id;
    std::string label;
    bool seeded{false};
    bool pinned{false};
    AdmissionLevel admission{AdmissionLevel::DISCOVERED};
    int observed_sources{0};
    bool bytes_verified{false};
    ModelCore core;
    ArtifactCore artifact;
    std::string source_path;
    int64_t imported_at{0};
    int64_t completed_at{0};
    int64_t last_access_at{0};
    int64_t last_served_at{0};
    int64_t useful_bytes_served{0};
    int64_t useful_bytes_received{0};
    int64_t seeding_started_at{0};
    bool incomplete{false};
};

class ModelCatalog {
    fs::path m_dir;
    ModelStore m_store;
    mutable std::mutex m_mu;
    std::vector<CatalogEntry> m_models;
    std::vector<std::string> m_peers;
    PreservationPolicy m_policy;
    std::set<Digest48> m_active_artifacts;

    /** Merkle cache for GetVerifiedPiece. rows[0] is the power-of-two padded leaves.
     *  Keyed by (artifact, file_index); the stored pieces_root must match or the slot is ignored. */
    struct CachedPieceTree {
        Digest48 pieces_root;
        uint64_t file_size{0};
        std::vector<Digest48> leaves;
        std::vector<std::vector<Digest48>> rows;
    };
    using PieceTreeKey = std::pair<Digest48, uint32_t>;
    mutable std::mutex m_piece_tree_mu;
    mutable std::map<PieceTreeKey, CachedPieceTree> m_piece_trees;
    void DropPieceTreeCache(const Digest48& artifact) const;
    void DropPieceTreeCache(const Digest48& artifact, uint32_t file_index) const;

    bool PersistLocked(std::string& err);
    bool LoadLocked(std::string& err);
    void DemandSeedLocked(CatalogEntry& e);

public:
    ModelCatalog(fs::path dir, uint64_t quota_bytes);
    ModelStore& Store() { return m_store; }
    const ModelStore& Store() const { return m_store; }

    void SetPolicy(PreservationPolicy p);
    PreservationPolicy Policy() const;
    bool ApplyDemandSeed(const Digest48& model_id, std::string& err);
    bool EnforceQuota(uint64_t need_bytes, std::string& err);
    bool PinModel(const Digest48& model_id, bool on, std::string& err);
    void SetQuotaBytes(uint64_t bytes);
    void BeginTransfer(const Digest48& artifact);
    void EndTransfer(const Digest48& artifact);
    UniValue FileAvailabilityJson(const Digest48& artifact, const ModelCore& core) const;
    uint64_t PinnedBytes() const;
    uint64_t ReclaimableBytes() const;

    bool ImportPath(const std::string& path, bool pin, CatalogEntry& out, std::string& err);
    bool Seed(const Digest48& model_id, bool on, std::string& err);
    bool List(UniValue& out) const;
    bool GetManifest(const Digest48& id, UniValue& out, std::string& err) const;
    bool Find(const Digest48& model_or_artifact, CatalogEntry& out) const;
    /** Typed lookup: MODEL matches model_id only, ARTIFACT matches artifact_id only. */
    bool FindExact(ResourceKind kind, const Digest48& digest, CatalogEntry& out) const;
    bool InstallFromManifest(const UniValue& manifest, std::string& err, bool complete = true);
    bool VerifyFileDigest(const Digest48& artifact, uint32_t file_index, const Digest48& expected, std::string& err);
    bool GetVerifiedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                           std::vector<unsigned char>& bytes, std::vector<Digest48>& proof,
                           uint64_t& file_size, std::string& err) const;
    bool PutFetchedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                          Span<const unsigned char> bytes, const std::vector<Digest48>& proof,
                          uint64_t file_size, const Digest48& pieces_root, std::string& err);
    void AddPeer(const std::string& endpoint);
    std::vector<std::string> Peers() const;
    uint64_t QuotaBytes() const { return m_store.QuotaBytes(); }
    uint64_t UsedBytes() const { return m_store.UsedBytes(); }
};

bool GuessFileRole(const std::string& relpath, FileRole& role);
bool ImportRegularFile(ModelStore& store, const Digest48& staging_artifact, uint32_t file_index,
                       const fs::path& src, const std::string& relpath, CoreFile& out,
                       QualReport* qual, std::string& err);

UniValue CapabilitiesObject();

} // namespace modelnet

#endif // BITCOIN_MODELNET_CATALOG_H
