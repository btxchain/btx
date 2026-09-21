// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/piece_store.h>

#include <univalue.h>
#include <util/fs.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <limits>
#include <sstream>
#include <system_error>
#include <utility>

namespace modelnet {
namespace {

PieceResidency CombineResidency(bool local, bool cloud)
{
    if (local && cloud) return PieceResidency::BOTH;
    if (local) return PieceResidency::LOCAL;
    if (cloud) return PieceResidency::CLOUD;
    return PieceResidency::ABSENT;
}

bool ParseResidencyName(const std::string& name, PieceResidency& out)
{
    if (name == "LOCAL") {
        out = PieceResidency::LOCAL;
        return true;
    }
    if (name == "CLOUD") {
        out = PieceResidency::CLOUD;
        return true;
    }
    if (name == "BOTH") {
        out = PieceResidency::BOTH;
        return true;
    }
    return false;
}

fs::path PiecePath(const fs::path& root, const Digest48& artifact, uint32_t file_index, uint32_t piece_index)
{
    return root / "artifacts" / artifact.Hex().c_str() / std::to_string(file_index).c_str() /
           (std::to_string(piece_index) + ".piece").c_str();
}

bool LeafMatches(uint32_t piece_index, Span<const unsigned char> bytes, const Digest48& expected_leaf)
{
    return ChunkLeaf(piece_index, bytes) == expected_leaf;
}

bool PutObjectFromSpan(CloudObjectStore& cloud, const std::string& key, Span<const unsigned char> bytes,
                         std::string& err)
{
    const std::string raw(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    std::istringstream in(raw);
    return cloud.PutObject(key, in, bytes.size(), err);
}

} // namespace

const char* PieceResidencyName(PieceResidency residency)
{
    switch (residency) {
    case PieceResidency::LOCAL: return "LOCAL";
    case PieceResidency::CLOUD: return "CLOUD";
    case PieceResidency::BOTH: return "BOTH";
    case PieceResidency::ABSENT: return "ABSENT";
    }
    return "ABSENT";
}

std::string PieceObjectKey(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                            const std::string& prefix)
{
    std::string key = "artifacts/" + artifact.Hex() + "/" + std::to_string(file_index) + "/" +
                       std::to_string(piece_index) + ".piece";
    if (prefix.empty()) return key;
    if (prefix.back() == '/') return prefix + key;
    return prefix + "/" + key;
}

LocalPieceStore::LocalPieceStore(fs::path root, uint64_t quota_bytes)
    : m_store(std::move(root), quota_bytes)
{
    LoadResidency();
}

fs::path LocalPieceStore::ResidencyPath() const
{
    return m_store.Root() / "residency.json";
}

bool LocalPieceStore::LoadResidency()
{
    m_residencies.clear();
    const fs::path path = ResidencyPath();
    std::ifstream in(path);
    if (!in) return true;
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue obj;
    if (!obj.read(raw) || !obj.isObject() || !obj.exists("pieces") || !obj["pieces"].isArray()) {
        return false;
    }
    for (const auto& e : obj["pieces"].getValues()) {
        if (!e.isObject() || !e.exists("artifact") || !e["artifact"].isStr() ||
            !e.exists("file") || !e["file"].isNum() || !e.exists("piece") || !e["piece"].isNum() ||
            !e.exists("residency") || !e["residency"].isStr()) {
            continue;
        }
        const int64_t file64 = e["file"].getInt<int64_t>();
        const int64_t piece64 = e["piece"].getInt<int64_t>();
        if (file64 < 0 || piece64 < 0 ||
            file64 > static_cast<int64_t>(std::numeric_limits<uint32_t>::max()) ||
            piece64 > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
            continue;
        }
        PieceResidency residency;
        if (!ParseResidencyName(e["residency"].get_str(), residency) ||
            residency == PieceResidency::ABSENT) {
            continue;
        }
        Digest48 artifact;
        std::string hex_err;
        if (!Digest48::FromHex(e["artifact"].get_str(), artifact, hex_err)) continue;
        ResidencyEntry entry;
        entry.residency = residency;
        if (e.exists("leaf") && e["leaf"].isStr()) {
            if (!Digest48::FromHex(e["leaf"].get_str(), entry.leaf, hex_err)) continue;
            entry.has_leaf = true;
        }
        m_residencies.emplace(std::make_tuple(artifact, static_cast<uint32_t>(file64),
                                               static_cast<uint32_t>(piece64)),
                              entry);
    }
    return true;
}

bool LocalPieceStore::SaveResidency() const
{
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("version", 1);
    UniValue pieces(UniValue::VARR);
    for (const auto& item : m_residencies) {
        const auto& key = item.first;
        const auto& entry = item.second;
        if (entry.residency == PieceResidency::ABSENT) continue;
        UniValue e(UniValue::VOBJ);
        e.pushKV("artifact", std::get<0>(key).Hex());
        e.pushKV("file", static_cast<int64_t>(std::get<1>(key)));
        e.pushKV("piece", static_cast<int64_t>(std::get<2>(key)));
        e.pushKV("residency", PieceResidencyName(entry.residency));
        if (entry.has_leaf) e.pushKV("leaf", entry.leaf.Hex());
        pieces.push_back(e);
    }
    obj.pushKV("pieces", pieces);

    fs::create_directories(m_store.Root() / "tmp");
    const fs::path tmp = m_store.Root() / "tmp" / "residency.json.tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) return false;
        out << obj.write(2, 0) << "\n";
        out.flush();
        if (!out) return false;
    }
    std::error_code ec;
    fs::rename(tmp, ResidencyPath(), ec);
    return !ec;
}

void LocalPieceStore::NoteResidency(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                      PieceResidency residency, const Digest48& leaf)
{
    if (residency == PieceResidency::ABSENT) {
        EraseResidency(artifact, file_index, piece_index);
        return;
    }
    ResidencyEntry entry;
    entry.residency = residency;
    entry.leaf = leaf;
    entry.has_leaf = true;
    m_residencies[std::make_tuple(artifact, file_index, piece_index)] = entry;
    SaveResidency();
}

void LocalPieceStore::EraseResidency(const Digest48& artifact, uint32_t file_index, uint32_t piece_index)
{
    m_residencies.erase(std::make_tuple(artifact, file_index, piece_index));
    SaveResidency();
}

void LocalPieceStore::EraseArtifactResidency(const Digest48& artifact)
{
    for (auto it = m_residencies.begin(); it != m_residencies.end();) {
        if (std::get<0>(it->first) == artifact) it = m_residencies.erase(it);
        else ++it;
    }
    SaveResidency();
}

bool LocalPieceStore::LookupLeaf(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                   Digest48& leaf) const
{
    const auto it = m_residencies.find(std::make_tuple(artifact, file_index, piece_index));
    if (it == m_residencies.end() || !it->second.has_leaf) return false;
    leaf = it->second.leaf;
    return true;
}

bool LocalPieceStore::MappedCloud(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const
{
    const auto it = m_residencies.find(std::make_tuple(artifact, file_index, piece_index));
    if (it == m_residencies.end()) return false;
    return it->second.residency == PieceResidency::CLOUD || it->second.residency == PieceResidency::BOTH;
}

uint64_t LocalPieceStore::CountCloudObjects() const
{
    uint64_t n = 0;
    for (const auto& item : m_residencies) {
        if (item.second.residency == PieceResidency::CLOUD || item.second.residency == PieceResidency::BOTH) {
            ++n;
        }
    }
    return n;
}

bool LocalPieceStore::HasPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const
{
    return m_store.HasPiece(artifact, file_index, piece_index);
}

bool LocalPieceStore::GetPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                 std::vector<unsigned char>& out, std::string& err)
{
    if (!m_store.GetPiece(artifact, file_index, piece_index, out, err)) return false;
    Digest48 leaf;
    if (LookupLeaf(artifact, file_index, piece_index, leaf) &&
        !LeafMatches(piece_index, Span<const unsigned char>{out.data(), out.size()}, leaf)) {
        out.clear();
        err = "corrupt chunk";
        return false;
    }
    return true;
}

bool LocalPieceStore::PutVerifiedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                        Span<const unsigned char> bytes, const Digest48& expected_leaf,
                                        std::string& err)
{
    if (!LeafMatches(piece_index, bytes, expected_leaf)) {
        err = "corrupt chunk";
        return false;
    }
    if (!m_store.PutVerifiedPiece(artifact, file_index, piece_index, bytes, expected_leaf, err)) {
        return false;
    }
    const auto it = m_residencies.find(std::make_tuple(artifact, file_index, piece_index));
    const PieceResidency next =
        (it != m_residencies.end() &&
         (it->second.residency == PieceResidency::CLOUD || it->second.residency == PieceResidency::BOTH))
            ? PieceResidency::BOTH
            : PieceResidency::LOCAL;
    NoteResidency(artifact, file_index, piece_index, next, expected_leaf);
    return true;
}

bool LocalPieceStore::DeletePiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                    std::string& err)
{
    (void)err;
    const fs::path path = PiecePath(m_store.Root(), artifact, file_index, piece_index);
    std::error_code ec;
    std::filesystem::remove(path, ec);
    m_store.RecountUsed();
    EraseResidency(artifact, file_index, piece_index);
    return true;
}

bool LocalPieceStore::RemoveArtifact(const Digest48& artifact, std::string& err)
{
    if (!m_store.RemoveArtifact(artifact, err)) return false;
    EraseArtifactResidency(artifact);
    return true;
}

bool LocalPieceStore::EnumerateCommittedPieces(const Digest48& artifact, uint32_t file_index,
                                                 std::vector<uint32_t>& out) const
{
    return m_store.ListCommittedPieces(artifact, file_index, out);
}

PieceStoreHealth LocalPieceStore::Health() const
{
    PieceStoreHealth h;
    h.backend = "local";
    h.local_bytes = m_store.UsedBytes();
    h.cloud_objects = CountCloudObjects();
    if (!fs::exists(m_store.Root())) {
        h.ok = false;
        h.error = "store root missing";
        return h;
    }
    h.ok = true;
    return h;
}

PieceResidency LocalPieceStore::Residency(const Digest48& artifact, uint32_t file_index,
                                             uint32_t piece_index) const
{
    return CombineResidency(HasPiece(artifact, file_index, piece_index),
                             MappedCloud(artifact, file_index, piece_index));
}

TieredPieceStore::TieredPieceStore(std::unique_ptr<LocalPieceStore> local,
                                     std::unique_ptr<CloudObjectStore> cloud,
                                     TieredPieceStorePolicy policy)
    : m_local(std::move(local)), m_cloud(std::move(cloud)), m_policy(std::move(policy))
{
}

std::string TieredPieceStore::ObjectKey(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const
{
    return PieceObjectKey(artifact, file_index, piece_index, m_policy.cloud_key_prefix);
}

bool TieredPieceStore::HasPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const
{
    if (m_local && m_local->HasPiece(artifact, file_index, piece_index)) return true;
    if (m_local && m_local->MappedCloud(artifact, file_index, piece_index)) return true;
    if (!m_cloud) return false;
    uint64_t size = 0;
    std::string err;
    return m_cloud->HeadObject(ObjectKey(artifact, file_index, piece_index), size, err) && size > 0;
}

bool TieredPieceStore::GetPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                  std::vector<unsigned char>& out, std::string& err)
{
    if (m_local && m_local->HasPiece(artifact, file_index, piece_index)) {
        return m_local->GetPiece(artifact, file_index, piece_index, out, err);
    }
    if (!m_cloud) {
        err = "missing piece";
        return false;
    }
    std::vector<unsigned char> remote;
    if (!m_cloud->GetObject(ObjectKey(artifact, file_index, piece_index), 0, 0, remote, err)) {
        return false;
    }
    if (remote.empty() || remote.size() > PIECE_SIZE) {
        err = "invalid cloud piece";
        return false;
    }
    Digest48 expected_leaf;
    if (!m_local || !m_local->LookupLeaf(artifact, file_index, piece_index, expected_leaf)) {
        err = "unverified cloud piece";
        return false;
    }
    if (!LeafMatches(piece_index, Span<const unsigned char>{remote.data(), remote.size()}, expected_leaf)) {
        err = "corrupt chunk";
        return false;
    }
    PieceIndex idx;
    std::string index_err;
    if (m_local && m_local->Store().LoadPieceIndex(artifact, file_index, idx, index_err)) {
        if (piece_index >= idx.leaves.size() || idx.leaves[piece_index] != expected_leaf) {
            err = "corrupt chunk";
            return false;
        }
    }
    if (m_policy.cache_cloud_hits_locally && m_local) {
        std::string cache_err;
        (void)m_local->PutVerifiedPiece(artifact, file_index, piece_index,
                                          Span<const unsigned char>{remote.data(), remote.size()},
                                          expected_leaf, cache_err);
        if (m_local->HasPiece(artifact, file_index, piece_index)) {
            m_local->NoteResidency(artifact, file_index, piece_index, PieceResidency::BOTH, expected_leaf);
        }
    }
    out = std::move(remote);
    return true;
}

bool TieredPieceStore::PutVerifiedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                         Span<const unsigned char> bytes, const Digest48& expected_leaf,
                                         std::string& err)
{
    if (!LeafMatches(piece_index, bytes, expected_leaf)) {
        err = "corrupt chunk";
        return false;
    }
    const bool want_local = WantLocal();
    const bool want_cloud = WantCloud();
    if (!want_local && !want_cloud) {
        err = "no storage destination";
        return false;
    }
    bool local_ok = !want_local;
    bool cloud_ok = !want_cloud;
    if (want_local) {
        local_ok = m_local->PutVerifiedPiece(artifact, file_index, piece_index, bytes, expected_leaf, err);
        if (!local_ok) return false;
    }
    if (want_cloud) {
        std::string cloud_err;
        cloud_ok = PutObjectFromSpan(*m_cloud, ObjectKey(artifact, file_index, piece_index), bytes, cloud_err);
        if (!cloud_ok) {
            err = cloud_err.empty() ? "cloud put failed" : cloud_err;
            if (local_ok && m_local) {
                m_local->NoteResidency(artifact, file_index, piece_index, PieceResidency::LOCAL, expected_leaf);
            }
            return false;
        }
    }
    if (!m_local) return true;
    const PieceResidency next = CombineResidency(want_local && local_ok, want_cloud && cloud_ok);
    m_local->NoteResidency(artifact, file_index, piece_index, next, expected_leaf);
    return true;
}

bool TieredPieceStore::DeletePiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                     std::string& err)
{
    bool ok = true;
    if (m_cloud) {
        std::string cloud_err;
        if (!m_cloud->DeleteObject(ObjectKey(artifact, file_index, piece_index), cloud_err)) {
            err = cloud_err.empty() ? "cloud delete failed" : cloud_err;
            ok = false;
        }
    }
    if (m_local && !m_local->DeletePiece(artifact, file_index, piece_index, err)) ok = false;
    return ok;
}

bool TieredPieceStore::RemoveArtifact(const Digest48& artifact, std::string& err)
{
    if (m_cloud && m_local) {
        std::vector<std::tuple<uint32_t, uint32_t>> cloud_pieces;
        for (const auto& item : m_local->m_residencies) {
            if (std::get<0>(item.first) != artifact) continue;
            if (item.second.residency == PieceResidency::CLOUD || item.second.residency == PieceResidency::BOTH) {
                cloud_pieces.emplace_back(std::get<1>(item.first), std::get<2>(item.first));
            }
        }
        for (const auto& fp : cloud_pieces) {
            std::string cloud_err;
            (void)m_cloud->DeleteObject(ObjectKey(artifact, std::get<0>(fp), std::get<1>(fp)), cloud_err);
        }
    }
    if (m_local) return m_local->RemoveArtifact(artifact, err);
    err = "no local store";
    return false;
}

bool TieredPieceStore::EnumerateCommittedPieces(const Digest48& artifact, uint32_t file_index,
                                                  std::vector<uint32_t>& out) const
{
    out.clear();
    if (m_local) {
        if (!m_local->EnumerateCommittedPieces(artifact, file_index, out)) return false;
        for (const auto& item : m_local->m_residencies) {
            if (std::get<0>(item.first) != artifact || std::get<1>(item.first) != file_index) continue;
            if (item.second.residency == PieceResidency::CLOUD || item.second.residency == PieceResidency::BOTH) {
                out.push_back(std::get<2>(item.first));
            }
        }
        std::sort(out.begin(), out.end());
        out.erase(std::unique(out.begin(), out.end()), out.end());
    }
    return true;
}

PieceStoreHealth TieredPieceStore::Health() const
{
    PieceStoreHealth h;
    h.backend = m_cloud ? "tiered" : "local";
    if (!m_local) {
        h.ok = false;
        h.error = "no local store";
        return h;
    }
    h = m_local->Health();
    h.backend = m_cloud ? "tiered" : h.backend;
    if (m_cloud) {
        const PieceStoreHealth cloud = m_cloud->Health();
        if (cloud.backend.size()) {
            h.backend = std::string("tiered+") + cloud.backend;
        }
        if (cloud.cloud_objects) h.cloud_objects = cloud.cloud_objects;
        if (!cloud.ok) {
            h.ok = false;
            if (h.error.empty()) h.error = cloud.error.empty() ? "cloud unhealthy" : cloud.error;
        }
    }
    return h;
}

PieceResidency TieredPieceStore::Residency(const Digest48& artifact, uint32_t file_index,
                                               uint32_t piece_index) const
{
    if (!m_local) return PieceResidency::ABSENT;
    return m_local->Residency(artifact, file_index, piece_index);
}

} // namespace modelnet
