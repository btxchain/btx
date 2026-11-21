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

#include <crypto/sha384.h>

#include <atomic>
#include <istream>
#include <streambuf>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {

struct VerifiedManifest;

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
    /** Search label. Empty on catalogs written before EXL3 detection; not part of the core hash. */
    std::string weight_format;
};

class ModelCatalog {
    fs::path m_dir;
    ModelStore m_store;
    mutable std::mutex m_mu;
    std::vector<CatalogEntry> m_models;
    std::vector<std::string> m_peers;
    //! catalog.json was there but could not be opened or parsed when it was
    //! loaded; the catalog then refuses to save over it.
    bool m_unreadable{false};
    PreservationPolicy m_policy;
    //! Running transfers per artifact. Several catalog entries can share one
    //! artifact, so more than one transfer can protect it at a time.
    std::map<Digest48, uint32_t> m_active_artifacts;

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

    bool EnforceQuotaLocked(uint64_t need_bytes, std::string& err);
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
    /** Admit a verified download, crediting proof-verified pieces only while
     *  its artifact is active and protected from quota eviction. */
    bool EnforceDownloadQuota(const VerifiedManifest& manifest, std::string& err,
                              const std::atomic<bool>* stop = nullptr);
    bool PinModel(const Digest48& model_id, bool on, std::string& err);
    /** True while this model's artifact is marked active (fetch or serve). */
    bool TransferActive(const Digest48& model_id) const;
    /** Delete a local model: its catalog entry and, unless another entry shares
     *  it, its artifact directory. Refuses while the artifact is active and does
     *  not unpin or unseed on that refusal. */
    bool RemoveModel(const Digest48& model_id, Digest48& artifact_out, std::string& err);
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
    /** Mark FETCHING so getmodel will TryHydrateFromCloud. Does not rewrite identity. */
    bool MarkIncomplete(const Digest48& model_or_artifact, bool incomplete, std::string& err);
    bool NoteUsefulBytes(const Digest48& model_or_artifact, int64_t served_delta, int64_t received_delta, std::string& err);
    bool InstallFromManifest(const UniValue& manifest, std::string& err, bool complete = true);
    bool VerifyFileDigest(const Digest48& artifact, uint32_t file_index, const Digest48& expected, std::string& err);
    /**
     * Rebuild the original directory tree from verified pieces into dest.
     * Refuses incomplete replicas. dest is the usable runtime root (HF/GGUF files),
     * not the piece store. Does not start a runtime.
     */
    bool MaterializeCheckout(const Digest48& model_or_artifact, const fs::path& dest, std::string& err);
    bool GetVerifiedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                           std::vector<unsigned char>& bytes, std::vector<Digest48>& proof,
                           uint64_t& file_size, std::string& err) const;
    bool PutFetchedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                          Span<const unsigned char> bytes, const std::vector<Digest48>& proof,
                          uint64_t file_size, const Digest48& pieces_root, std::string& err);
    /** Operator / -modelpeer contacts only. Unauthenticated PEX must not call this. */
    bool AddPeer(const std::string& endpoint, std::string* save_error = nullptr);
    std::vector<std::string> Peers() const;
    uint64_t QuotaBytes() const { return m_store.QuotaBytes(); }
    uint64_t UsedBytes() const { return m_store.UsedBytes(); }
};

/** Sequential upload source bound to an imported file, never its external path.
 * Retains one PIECE_SIZE piece; proof verification uses bounded piece scratch.
 * A failed final digest
 * withholds the final piece, so an exact-length uploader cannot commit it.
 * The caller protects the artifact with BeginTransfer/EndTransfer.
 */
class CatalogFileStream final : public std::istream {
    class Buffer final : public std::streambuf {
        const ModelCatalog& m_catalog;
        Digest48 m_artifact;
        uint32_t m_file_index;
        CoreFile m_file;
        uint64_t m_read{0};
        uint32_t m_next_piece{0};
        CSHA384 m_hash;
        std::vector<unsigned char> m_bytes;
        std::string m_error;
        size_t m_max_buffer{0};

        int_type underflow() override;

    public:
        Buffer(const ModelCatalog& catalog, const Digest48& artifact,
               uint32_t file_index, const CoreFile& file);
        const std::string& Error() const { return m_error; }
        size_t MaxBufferBytes() const { return m_max_buffer; }
    } m_buffer;

public:
    CatalogFileStream(const ModelCatalog& catalog, const Digest48& artifact,
                      uint32_t file_index, const CoreFile& file);
    const std::string& Error() const { return m_buffer.Error(); }
    size_t MaxBufferBytes() const { return m_buffer.MaxBufferBytes(); }
};

bool GuessFileRole(const std::string& relpath, FileRole& role);
bool ImportRegularFile(ModelStore& store, const Digest48& staging_artifact, uint32_t file_index,
                       const fs::path& src, const std::string& relpath, CoreFile& out,
                       QualReport* qual, std::string& err);

UniValue CapabilitiesObject();
void SetAdvertisedCloudCaps(bool cloud_attached, bool direct_cloud_seed);

} // namespace modelnet

#endif // BITCOIN_MODELNET_CATALOG_H
