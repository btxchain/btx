// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_STORE_H
#define BITCOIN_MODELNET_STORE_H

#include <modelnet/types.h>
#include <span.h>
#include <util/fs.h>

#include <optional>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

constexpr uint64_t MAX_FILE_BYTES = uint64_t{4} << 40;

bool IsPortableRelPath(const std::string& path, std::string& err);

Digest48 ChunkLeaf(uint64_t index, Span<const unsigned char> piece);
Digest48 ChunkPad(uint64_t index);
Digest48 ChunkNode(const Digest48& left, const Digest48& right);
Digest48 EmptyFileRoot();

std::vector<std::vector<Digest48>> BuildChunkTree(Span<const unsigned char> file);
bool VerifyPiece(const Digest48& root, uint64_t file_size, uint64_t index,
                  Span<const unsigned char> piece,
                  const std::vector<Digest48>& siblings);
std::vector<Digest48> PieceProof(const std::vector<std::vector<Digest48>>& rows, uint64_t index);

struct FileEntry {
    std::string path;
    FileRole role{FileRole::WEIGHTS};
    uint64_t size{0};
    Digest48 sha384;
    Digest48 pieces_root;
};

struct StoreQuota {
    uint64_t max_bytes{0};
    uint64_t used_bytes{0};
};

struct PieceIndex {
    uint64_t file_size{0};
    Digest48 pieces_root;
    std::vector<Digest48> leaves; // power-of-two padded width
};

std::vector<std::vector<Digest48>> BuildChunkTreeFromLeaves(const std::vector<Digest48>& padded_leaves);

/** Filesystem model store. Never under wallet/chainstate/blocks. */
class ModelStore {
    fs::path m_root;
    StoreQuota m_quota;
    std::set<std::string> m_pinned;

public:
    explicit ModelStore(fs::path root, uint64_t quota_bytes);
    const fs::path& Root() const { return m_root; }
    uint64_t QuotaBytes() const { return m_quota.max_bytes; }
    bool PutVerifiedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                           Span<const unsigned char> bytes, const Digest48& expected_leaf, std::string& err);
    bool GetPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                  std::vector<unsigned char>& out, std::string& err) const;
    bool HasPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const;
    bool SavePieceIndex(const Digest48& artifact, uint32_t file_index, const PieceIndex& idx, std::string& err);
    bool LoadPieceIndex(const Digest48& artifact, uint32_t file_index, PieceIndex& idx, std::string& err) const;
    bool SavePieceProof(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                         uint64_t file_size, const Digest48& pieces_root,
                         const std::vector<Digest48>& siblings, std::string& err);
    bool LoadPieceProof(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                         uint64_t& file_size, Digest48& pieces_root,
                         std::vector<Digest48>& siblings, std::string& err) const;
    bool RenameArtifact(const Digest48& from, const Digest48& to, std::string& err);
    bool Pin(const Digest48& model_id, std::string& err);
    bool Unpin(const Digest48& model_id);
    bool IsPinned(const Digest48& model_id) const;
    uint64_t UsedBytes() const { return m_quota.used_bytes; }
    void SetQuotaBytes(uint64_t bytes);
    void RecountUsed();
    bool RemoveArtifact(const Digest48& artifact, std::string& err);
    void EvictUnpinned();
    bool ListCommittedPieces(const Digest48& artifact, uint32_t file_index, std::vector<uint32_t>& out) const;
    int64_t PieceMtime(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_STORE_H
