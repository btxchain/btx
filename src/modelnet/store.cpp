// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/store.h>

#include <modelnet/crypto.h>
#include <crypto/common.h>
#include <crypto/sha384.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <regex>
#include <limits>
#include <system_error>
#include <chrono>

namespace modelnet {
namespace {

fs::path ArtifactDir(const fs::path& root, const Digest48& artifact)
{
    return root / "artifacts" / artifact.Hex().c_str();
}

/** Read a committed piece after checking file_size. Never reads more than PIECE_SIZE. */
bool ReadBoundedPiece(const fs::path& path, std::vector<unsigned char>& out, std::string& err)
{
    std::error_code ec;
    const auto sz = std::filesystem::file_size(path, ec);
    if (ec) {
        err = "missing piece";
        return false;
    }
    if (sz == 0 || sz > PIECE_SIZE) {
        err = "invalid piece size";
        return false;
    }
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        err = "missing piece";
        return false;
    }
    out.resize(static_cast<size_t>(sz));
    in.read(reinterpret_cast<char*>(out.data()), static_cast<std::streamsize>(sz));
    if (static_cast<uint64_t>(in.gcount()) != sz) {
        out.clear();
        err = "piece read failed";
        return false;
    }
    return true;
}

} // namespace

bool IsPortableRelPath(const std::string& path, std::string& err)
{
    static const std::regex re{R"(^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$)"};
    if (!std::regex_match(path, re) || path.size() > 240) {
        err = "unsafe path";
        return false;
    }
    static const std::set<std::string> reserved{"CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"};
    size_t start = 0;
    while (start < path.size()) {
        const size_t slash = path.find('/', start);
        const std::string part = path.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
        if (part == "." || part == ".." || (!part.empty() && part.back() == '.')) {
            err = "unsafe path";
            return false;
        }
        std::string stem = part;
        const auto dot = stem.find('.');
        if (dot != std::string::npos) stem = stem.substr(0, dot);
        for (char& c : stem) {
            if (c >= 'a' && c <= 'z') c = static_cast<char>(c - 'a' + 'A');
        }
        if (reserved.count(stem)) {
            err = "unsafe path";
            return false;
        }
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    return true;
}

Digest48 ChunkLeaf(uint64_t index, Span<const unsigned char> piece)
{
    std::vector<unsigned char> body(8 + 4 + piece.size());
    WriteLE64(body.data(), index);
    WriteLE32(body.data() + 8, static_cast<uint32_t>(piece.size()));
    if (!piece.empty()) memcpy(body.data() + 12, piece.data(), piece.size());
    return DomainHash("BTX/ModelChunk/v2", body);
}

Digest48 ChunkPad(uint64_t index)
{
    unsigned char buf[8];
    WriteLE64(buf, index);
    return DomainHash("BTX/ModelChunkPad/v2", Span<const unsigned char>{buf, 8});
}

Digest48 ChunkNode(const Digest48& left, const Digest48& right)
{
    unsigned char body[96];
    memcpy(body, left.data.data(), 48);
    memcpy(body + 48, right.data.data(), 48);
    return DomainHash("BTX/ModelChunkNode/v2", Span<const unsigned char>{body, 96});
}

Digest48 EmptyFileRoot()
{
    return DomainHash("BTX/ModelEmpty/v2", Span<const unsigned char>{});
}

std::vector<std::vector<Digest48>> BuildChunkTree(Span<const unsigned char> file)
{
    if (file.empty()) return {{EmptyFileRoot()}};
    const size_t n = (file.size() + PIECE_SIZE - 1) / PIECE_SIZE;
    size_t width = 1;
    while (width < n) width <<= 1;
    std::vector<Digest48> leaves;
    leaves.reserve(width);
    for (size_t i = 0; i < n; ++i) {
        const size_t off = i * PIECE_SIZE;
        const size_t len = std::min(PIECE_SIZE, file.size() - off);
        leaves.push_back(ChunkLeaf(i, Span<const unsigned char>{file.data() + off, len}));
    }
    for (size_t i = n; i < width; ++i) leaves.push_back(ChunkPad(i));
    std::vector<std::vector<Digest48>> rows;
    rows.push_back(std::move(leaves));
    while (rows.back().size() > 1) {
        const auto& r = rows.back();
        std::vector<Digest48> next;
        next.reserve(r.size() / 2);
        for (size_t i = 0; i < r.size(); i += 2) {
            next.push_back(ChunkNode(r[i], r[i + 1]));
        }
        rows.push_back(std::move(next));
    }
    return rows;
}

std::vector<std::vector<Digest48>> BuildChunkTreeFromLeaves(const std::vector<Digest48>& padded_leaves)
{
    if (padded_leaves.empty()) return {{EmptyFileRoot()}};
    std::vector<std::vector<Digest48>> rows;
    rows.push_back(padded_leaves);
    while (rows.back().size() > 1) {
        const auto& r = rows.back();
        if (r.size() % 2 != 0) {
            return {};
        }
        std::vector<Digest48> next;
        next.reserve(r.size() / 2);
        for (size_t i = 0; i < r.size(); i += 2) {
            next.push_back(ChunkNode(r[i], r[i + 1]));
        }
        rows.push_back(std::move(next));
    }
    return rows;
}

std::vector<Digest48> PieceProof(const std::vector<std::vector<Digest48>>& rows, uint64_t index)
{
    std::vector<Digest48> result;
    uint64_t i = index;
    for (size_t level = 0; level + 1 < rows.size(); ++level) {
        result.push_back(rows[level][i ^ 1]);
        i /= 2;
    }
    return result;
}

bool VerifyPiece(const Digest48& root, uint64_t file_size, uint64_t index,
                  Span<const unsigned char> piece,
                  const std::vector<Digest48>& siblings)
{
    if (file_size == 0 || file_size > MAX_FILE_BYTES) return false;
    const uint64_t n = (file_size + PIECE_SIZE - 1) / PIECE_SIZE;
    if (index >= n) return false;
    const uint64_t expected_len = std::min<uint64_t>(PIECE_SIZE, file_size - index * PIECE_SIZE);
    if (piece.size() != expected_len) return false;
    size_t width_bits = 0;
    uint64_t tmp = n - 1;
    while (tmp) {
        ++width_bits;
        tmp >>= 1;
    }
    if (siblings.size() != width_bits) return false;
    Digest48 v = ChunkLeaf(index, piece);
    for (size_t level = 0; level < siblings.size(); ++level) {
        if ((index >> level) & 1) {
            v = ChunkNode(siblings[level], v);
        } else {
            v = ChunkNode(v, siblings[level]);
        }
    }
    return v == root;
}

ModelStore::ModelStore(fs::path root, uint64_t quota_bytes) : m_root(std::move(root))
{
    m_quota.max_bytes = quota_bytes;
    fs::create_directories(m_root / "artifacts");
    fs::create_directories(m_root / "tmp");
    RecountUsed();
}

void ModelStore::RecountUsed()
{
    m_quota.used_bytes = 0;
    const fs::path arts = m_root / "artifacts";
    if (!fs::exists(arts)) return;
    std::error_code ec;
    for (auto it = std::filesystem::recursive_directory_iterator(arts, ec),
         end = std::filesystem::recursive_directory_iterator();
         it != end && !ec; it.increment(ec)) {
        if (!it->is_regular_file(ec) || ec) continue;
        const std::string name = fs::PathToString(it->path().filename());
        if (name.size() >= 6 && name.compare(name.size() - 6, 6, ".piece") == 0) {
            const auto sz = std::filesystem::file_size(it->path(), ec);
            if (!ec) m_quota.used_bytes += sz;
        }
    }
}

bool ModelStore::RemoveArtifact(const Digest48& artifact, std::string& err)
{
    const fs::path dir = ArtifactDir(m_root, artifact);
    if (!fs::exists(dir)) return true;
    std::error_code ec;
    uint64_t drop = 0;
    for (auto it = std::filesystem::recursive_directory_iterator(dir, ec),
         end = std::filesystem::recursive_directory_iterator();
         it != end && !ec; it.increment(ec)) {
        if (!it->is_regular_file(ec) || ec) continue;
        const std::string name = fs::PathToString(it->path().filename());
        if (name.size() >= 6 && name.compare(name.size() - 6, 6, ".piece") == 0) {
            const auto sz = std::filesystem::file_size(it->path(), ec);
            if (!ec) drop += sz;
        }
    }
    std::filesystem::remove_all(dir, ec);
    if (ec) {
        err = "artifact remove failed";
        return false;
    }
    if (m_quota.used_bytes >= drop) m_quota.used_bytes -= drop;
    else m_quota.used_bytes = 0;
    return true;
}

bool ModelStore::PutVerifiedPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                     Span<const unsigned char> bytes, const Digest48& expected_leaf, std::string& err)
{
    if (ChunkLeaf(piece_index, bytes) != expected_leaf) {
        err = "corrupt chunk";
        return false;
    }
    const fs::path dir = ArtifactDir(m_root, artifact) / std::to_string(file_index).c_str();
    fs::create_directories(dir);
    const fs::path final_path = dir / (std::to_string(piece_index) + ".piece").c_str();
    if (fs::exists(final_path)) {
        std::vector<unsigned char> existing;
        if (!ReadBoundedPiece(final_path, existing, err)) {
            return false;
        }
        if (existing.size() != bytes.size() || ChunkLeaf(piece_index, existing) != expected_leaf) {
            err = "existing piece mismatch";
            return false;
        }
        return true;
    }
    if (!m_quota.max_bytes) {
        err = "payload storage is 0 until -modelstorage / -modelcache allocates a quota";
        return false;
    }
    if (m_quota.used_bytes + bytes.size() > m_quota.max_bytes) {
        err = "disk quota";
        return false;
    }
    fs::create_directories(m_root / "tmp");
    const fs::path tmp = m_root / "tmp" / (artifact.Hex() + "-" + std::to_string(file_index) + "-" + std::to_string(piece_index) + ".tmp").c_str();
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "tmp write failed";
            return false;
        }
        if (!bytes.empty()) out.write(reinterpret_cast<const char*>(bytes.data()), bytes.size());
        out.flush();
        if (!out) {
            err = "tmp write failed";
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, final_path, ec);
    if (ec) {
        err = "atomic rename failed";
        return false;
    }
    m_quota.used_bytes += bytes.size();
    return true;
}

bool ModelStore::GetPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                            std::vector<unsigned char>& out, std::string& err) const
{
    const fs::path path = ArtifactDir(m_root, artifact) / std::to_string(file_index).c_str() /
                           (std::to_string(piece_index) + ".piece").c_str();
    return ReadBoundedPiece(path, out, err);
}

bool ModelStore::HasPiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const
{
    const fs::path path = ArtifactDir(m_root, artifact) / std::to_string(file_index).c_str() /
                           (std::to_string(piece_index) + ".piece").c_str();
    std::error_code ec;
    const auto sz = std::filesystem::file_size(path, ec);
    return !ec && sz > 0;
}

bool ModelStore::DeletePiece(const Digest48& artifact, uint32_t file_index, uint32_t piece_index, std::string& err)
{
    const fs::path dir = ArtifactDir(m_root, artifact) / std::to_string(file_index).c_str();
    const fs::path path = dir / (std::to_string(piece_index) + ".piece").c_str();
    std::error_code ec;
    if (!std::filesystem::exists(path, ec) || ec) return true;
    const auto sz = std::filesystem::file_size(path, ec);
    const uint64_t drop = (!ec && sz > 0) ? static_cast<uint64_t>(sz) : 0;
    std::filesystem::remove(path, ec);
    if (ec) {
        err = "piece remove failed";
        return false;
    }
    if (drop > 0) {
        if (m_quota.used_bytes >= drop) m_quota.used_bytes -= drop;
        else m_quota.used_bytes = 0;
    }
    const fs::path proof = dir / (std::to_string(piece_index) + ".proof.json").c_str();
    std::filesystem::remove(proof, ec);
    return true;
}

bool ModelStore::Pin(const Digest48& model_id, std::string& err)
{
    (void)err;
    m_pinned.insert(model_id.Hex());
    return true;
}

bool ModelStore::Unpin(const Digest48& model_id)
{
    return m_pinned.erase(model_id.Hex()) > 0;
}

bool ModelStore::IsPinned(const Digest48& model_id) const
{
    return m_pinned.count(model_id.Hex()) > 0;
}

void ModelStore::SetQuotaBytes(uint64_t bytes)
{
    m_quota.max_bytes = bytes;
}

void ModelStore::EvictUnpinned()
{
    std::error_code ec;
    const auto now = std::chrono::file_clock::now();
    const fs::path tmp = m_root / "tmp";
    if (fs::exists(tmp)) {
        for (auto it = std::filesystem::directory_iterator(tmp, ec), end = std::filesystem::directory_iterator();
             it != end && !ec; it.increment(ec)) {
            if (!it->is_regular_file(ec) || ec) continue;
            const auto ftime = std::filesystem::last_write_time(it->path(), ec);
            if (ec) continue;
            const auto age = std::chrono::duration_cast<std::chrono::hours>(now - ftime);
            if (age.count() >= 24) {
                std::filesystem::remove(it->path(), ec);
            }
        }
    }
    const fs::path arts = m_root / "artifacts";
    if (fs::exists(arts)) {
        for (auto it = std::filesystem::directory_iterator(arts, ec), end = std::filesystem::directory_iterator();
             it != end && !ec; it.increment(ec)) {
            if (!it->is_directory(ec) || ec) continue;
            const std::string hex = fs::PathToString(it->path().filename());
            if (m_pinned.count(hex)) continue;
            const auto ftime = std::filesystem::last_write_time(it->path(), ec);
            if (ec) continue;
            const auto age = std::chrono::duration_cast<std::chrono::hours>(now - ftime);
            if (age.count() < 24) continue;
            bool any_piece = false;
            std::error_code rec_ec;
            for (auto rit = std::filesystem::recursive_directory_iterator(it->path(), rec_ec),
                 rend = std::filesystem::recursive_directory_iterator();
                 rit != rend && !rec_ec; rit.increment(rec_ec)) {
                if (!rit->is_regular_file(rec_ec) || rec_ec) continue;
                const std::string name = fs::PathToString(rit->path().filename());
                if (name.size() >= 6 && name.compare(name.size() - 6, 6, ".piece") == 0) {
                    any_piece = true;
                    break;
                }
            }
            if (!any_piece) {
                std::filesystem::remove_all(it->path(), ec);
            }
        }
    }
    RecountUsed();
}

bool ModelStore::ListCommittedPieces(const Digest48& artifact, uint32_t file_index, std::vector<uint32_t>& out) const
{
    out.clear();
    const fs::path dir = ArtifactDir(m_root, artifact) / std::to_string(file_index).c_str();
    if (!fs::exists(dir)) return true;
    std::error_code ec;
    for (auto it = std::filesystem::directory_iterator(dir, ec), end = std::filesystem::directory_iterator();
         it != end && !ec; it.increment(ec)) {
        if (!it->is_regular_file(ec) || ec) continue;
        const std::string name = fs::PathToString(it->path().filename());
        if (name.size() < 7 || name.compare(name.size() - 6, 6, ".piece") != 0) continue;
        const std::string num = name.substr(0, name.size() - 6);
        try {
            const unsigned long v = std::stoul(num);
            if (v <= std::numeric_limits<uint32_t>::max()) out.push_back(static_cast<uint32_t>(v));
        } catch (...) {
            continue;
        }
    }
    std::sort(out.begin(), out.end());
    out.erase(std::unique(out.begin(), out.end()), out.end());
    return true;
}

int64_t ModelStore::PieceMtime(const Digest48& artifact, uint32_t file_index, uint32_t piece_index) const
{
    const fs::path path = ArtifactDir(m_root, artifact) / std::to_string(file_index).c_str() /
                           (std::to_string(piece_index) + ".piece").c_str();
    std::error_code ec;
    const auto ftime = std::filesystem::last_write_time(path, ec);
    if (ec) return 0;
    const auto secs = std::chrono::duration_cast<std::chrono::seconds>(ftime.time_since_epoch());
    return static_cast<int64_t>(secs.count());
}

bool ModelStore::SavePieceIndex(const Digest48& artifact, uint32_t file_index, const PieceIndex& idx, std::string& err)
{
    if (idx.leaves.empty()) {
        err = "empty leaf index";
        return false;
    }
    const fs::path dir = ArtifactDir(m_root, artifact) / std::to_string(file_index).c_str();
    fs::create_directories(dir);
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("file_size", idx.file_size);
    obj.pushKV("pieces_root", idx.pieces_root.Hex());
    UniValue leaves(UniValue::VARR);
    for (const auto& leaf : idx.leaves) leaves.push_back(leaf.Hex());
    obj.pushKV("leaves", leaves);
    const fs::path final_path = dir / "index.json";
    const fs::path tmp = m_root / "tmp" / (artifact.Hex() + "-" + std::to_string(file_index) + "-index.tmp").c_str();
    fs::create_directories(tmp.parent_path());
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            err = "index tmp write failed";
            return false;
        }
        out << obj.write(2, 0) << "\n";
        out.flush();
        if (!out) {
            err = "index tmp write failed";
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, final_path, ec);
    if (ec) {
        err = "index rename failed";
        return false;
    }
    return true;
}

bool ModelStore::LoadPieceIndex(const Digest48& artifact, uint32_t file_index, PieceIndex& idx, std::string& err) const
{
    idx = {};
    const fs::path path = ArtifactDir(m_root, artifact) / std::to_string(file_index).c_str() / "index.json";
    std::ifstream in(path);
    if (!in) {
        err = "missing piece index";
        return false;
    }
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue obj;
    if (!obj.read(raw) || !obj.isObject()) {
        err = "piece index json";
        return false;
    }
    idx.file_size = obj["file_size"].getInt<uint64_t>();
    if (!Digest48::FromHex(obj["pieces_root"].get_str(), idx.pieces_root, err)) return false;
    for (const auto& leaf : obj["leaves"].getValues()) {
        Digest48 d;
        if (!Digest48::FromHex(leaf.get_str(), d, err)) return false;
        idx.leaves.push_back(d);
    }
    return true;
}

bool ModelStore::SavePieceProof(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                 uint64_t file_size, const Digest48& pieces_root,
                                 const std::vector<Digest48>& siblings, std::string& err)
{
    const fs::path dir = ArtifactDir(m_root, artifact) / std::to_string(file_index).c_str();
    fs::create_directories(dir);
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("file_size", file_size);
    obj.pushKV("pieces_root", pieces_root.Hex());
    UniValue sibs(UniValue::VARR);
    for (const auto& d : siblings) sibs.push_back(d.Hex());
    obj.pushKV("siblings", sibs);
    const fs::path final_path = dir / (std::to_string(piece_index) + ".proof.json").c_str();
    const fs::path tmp = m_root / "tmp" / (artifact.Hex() + "-" + std::to_string(file_index) + "-" +
                                            std::to_string(piece_index) + "-proof.tmp").c_str();
    fs::create_directories(tmp.parent_path());
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            err = "proof tmp write failed";
            return false;
        }
        out << obj.write() << "\n";
        out.flush();
        if (!out) {
            err = "proof tmp write failed";
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, final_path, ec);
    if (ec) {
        err = "proof rename failed";
        return false;
    }
    return true;
}

bool ModelStore::LoadPieceProof(const Digest48& artifact, uint32_t file_index, uint32_t piece_index,
                                 uint64_t& file_size, Digest48& pieces_root,
                                 std::vector<Digest48>& siblings, std::string& err) const
{
    siblings.clear();
    const fs::path path = ArtifactDir(m_root, artifact) / std::to_string(file_index).c_str() /
                           (std::to_string(piece_index) + ".proof.json").c_str();
    std::ifstream in(path);
    if (!in) {
        err = "missing piece proof";
        return false;
    }
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue obj;
    if (!obj.read(raw) || !obj.isObject()) {
        err = "piece proof json";
        return false;
    }
    file_size = obj["file_size"].getInt<uint64_t>();
    if (!Digest48::FromHex(obj["pieces_root"].get_str(), pieces_root, err)) return false;
    if (obj.exists("siblings") && obj["siblings"].isArray()) {
        for (const auto& s : obj["siblings"].getValues()) {
            Digest48 d;
            if (!Digest48::FromHex(s.get_str(), d, err)) return false;
            siblings.push_back(d);
        }
    }
    return true;
}

bool ModelStore::RenameArtifact(const Digest48& from, const Digest48& to, std::string& err)
{
    if (from == to) return true;
    const fs::path src = ArtifactDir(m_root, from);
    const fs::path dst = ArtifactDir(m_root, to);
    std::error_code ec;
    if (!fs::exists(src)) {
        err = "staging artifact missing";
        return false;
    }
    if (fs::exists(dst)) {
        err = "destination artifact exists";
        return false;
    }
    fs::create_directories(dst.parent_path());
    fs::rename(src, dst, ec);
    if (ec) {
        err = "artifact rename failed";
        return false;
    }
    return true;
}

} // namespace modelnet
