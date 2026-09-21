// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PIECE_STORE_H
#define BITCOIN_MODELNET_PIECE_STORE_H

#include <modelnet/store.h>
#include <span.h>
#include <util/fs.h>

#include <cstdint>
#include <iosfwd>
#include <map>
#include <memory>
#include <string>
#include <tuple>
#include <vector>

namespace modelnet {

/** Where a verified piece currently lives. Never encodes credentials. */
enum class PieceResidency {
    LOCAL = 0,
    CLOUD = 1,
    BOTH = 2,
    ABSENT = 3,
};

const char* PieceResidencyName(PieceResidency residency);

struct PieceStoreHealth {
    bool ok{false};
    std::string backend;
    std::string error;
    uint64_t local_bytes{0};
    uint64_t cloud_objects{0};
};

/**
 * Object-key backend (S3/R2/MinIO). Lane C implements this.
 *
 * GetObject is a byte fetch. It does not verify ChunkLeaf / pieces_root / SHA-384
 * and must not be trusted via ETag. PieceStore::PutVerifiedPiece still requires
 * expected_leaf. Random-piece Get of SOURCE_FILES is not this type's job.
 */
class CloudObjectStore
{
public:
    virtual ~CloudObjectStore() = default;

    /** If len == 0, return [offset, end). */
    virtual bool GetObject(const std::string& key, uint64_t offset, uint64_t len,
                           std::vector<unsigned char>& out, std::string& err) = 0;
    /** content_length == 0 means read body until EOF. */
    virtual bool PutObject(const std::string& key, std::istream& body, uint64_t content_length,
                            std::string& err) = 0;
    virtual bool HeadObject(const std::string& key, uint64_t& size, std::string& err) const = 0;
    virtual bool DeleteObject(const std::string& key, std::string& err) = 0;
    virtual PieceStoreHealth Health() const = 0;
};

/** Lane C: `class S3PieceStore : public CloudObjectStore` in s3_store.cpp. */
class S3PieceStore;

/** PIECE_OBJECTS key: `<prefix>/artifacts/<hex>/<file>/<piece>.piece`. */
std::string PieceObjectKey(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                            const std::string& prefix = {});

/**
 * Verified piece access. Catalog / delivery stay above this: they still run
 * ChunkLeaf / pieces_root / file SHA-384. Never treat a cloud ETag as a leaf.
 */
class PieceStore
{
public:
    virtual ~PieceStore() = default;

    virtual bool HasPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const = 0;
    virtual bool GetPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                           std::vector<unsigned char>& out, std::string& err) = 0;
    virtual bool PutVerifiedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                    Span<const unsigned char> bytes, const Digest48& expected_leaf,
                                    std::string& err) = 0;
    virtual bool DeletePiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                              std::string& err) = 0;
    virtual bool RemoveArtifact(const Digest48& artifact, std::string& err) = 0;
    virtual bool EnumerateCommittedPieces(const Digest48& artifact, uint32_t file_index,
                                         std::vector<uint32_t>& out) const = 0;
    virtual PieceStoreHealth Health() const = 0;
    virtual PieceResidency Residency(const Digest48& artifact, uint32_t file_index,
                                     uint32_t piece_index) const = 0;
};

/** Filesystem adapter. Does not change ModelStore's on-disk layout. */
class LocalPieceStore : public PieceStore
{
    friend class TieredPieceStore;

    ModelStore m_store;
    struct ResidencyEntry {
        PieceResidency residency{PieceResidency::ABSENT};
        Digest48 leaf{};
        bool has_leaf{false};
    };
    std::map<std::tuple<Digest48, uint32_t, uint32_t>, ResidencyEntry> m_residencies;

    fs::path ResidencyPath() const;
    bool LoadResidency();
    bool SaveResidency() const;
    void NoteResidency(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                          PieceResidency residency, const Digest48& leaf);
    void EraseResidency(const Digest48& artifact, uint32_t file_index, uint32_t piece_index);
    void EraseArtifactResidency(const Digest48& artifact);
    bool LookupLeaf(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                     Digest48& leaf) const;
    bool MappedCloud(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const;
    uint64_t CountCloudObjects() const;

public:
    explicit LocalPieceStore(fs::path root, uint64_t quota_bytes);

    ModelStore& Store() { return m_store; }
    const ModelStore& Store() const { return m_store; }
    const fs::path& Root() const { return m_store.Root(); }

    bool HasPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const override;
    bool GetPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                   std::vector<unsigned char>& out, std::string& err) override;
    bool PutVerifiedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                            Span<const unsigned char> bytes, const Digest48& expected_leaf,
                            std::string& err) override;
    bool DeletePiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                      std::string& err) override;
    bool RemoveArtifact(const Digest48& artifact, std::string& err) override;
    bool EnumerateCommittedPieces(const Digest48& artifact, uint32_t file_index,
                                     std::vector<uint32_t>& out) const override;
    PieceStoreHealth Health() const override;
    PieceResidency Residency(const Digest48& artifact, uint32_t file_index,
                               uint32_t piece_index) const override;
};

struct TieredPieceStorePolicy {
    bool write_local{true};
    bool write_cloud{true};
    bool cache_cloud_hits_locally{true};
    std::string cloud_key_prefix;
};

/**
 * Local then cloud. Cloud Get of SOURCE_FILES (whole file object) is not
 * required here; this path only fetches PIECE_OBJECTS keys.
 */
class TieredPieceStore : public PieceStore
{
    std::unique_ptr<LocalPieceStore> m_local;
    std::unique_ptr<CloudObjectStore> m_cloud;
    TieredPieceStorePolicy m_policy;

    std::string ObjectKey(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const;
    bool WantLocal() const { return m_policy.write_local && m_local; }
    bool WantCloud() const { return m_policy.write_cloud && m_cloud; }

public:
    explicit TieredPieceStore(std::unique_ptr<LocalPieceStore> local,
                              std::unique_ptr<CloudObjectStore> cloud = nullptr,
                              TieredPieceStorePolicy policy = {});

    LocalPieceStore& Local() { return *m_local; }
    const LocalPieceStore& Local() const { return *m_local; }
    CloudObjectStore* Cloud() { return m_cloud.get(); }
    const CloudObjectStore* Cloud() const { return m_cloud.get(); }

    bool HasPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const override;
    bool GetPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                   std::vector<unsigned char>& out, std::string& err) override;
    bool PutVerifiedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                            Span<const unsigned char> bytes, const Digest48& expected_leaf,
                            std::string& err) override;
    bool DeletePiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                      std::string& err) override;
    bool RemoveArtifact(const Digest48& artifact, std::string& err) override;
    bool EnumerateCommittedPieces(const Digest48& artifact, uint32_t file_index,
                                     std::vector<uint32_t>& out) const override;
    PieceStoreHealth Health() const override;
    PieceResidency Residency(const Digest48& artifact, uint32_t file_index,
                               uint32_t piece_index) const override;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_PIECE_STORE_H
