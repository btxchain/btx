// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/git_snapshot.h>

#include <modelnet/crypto.h>
#include <crypto/sha384.h>

#include <cctype>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

bool FailPath(std::string& err)
{
    err = "BTX035_PATH_UNSAFE";
    return false;
}

bool EqualsIgnoreCase(std::string_view left, std::string_view right)
{
    if (left.size() != right.size()) return false;
    for (size_t i = 0; i < left.size(); ++i) {
        const unsigned char a = static_cast<unsigned char>(left[i]);
        const unsigned char b = static_cast<unsigned char>(right[i]);
        if (std::tolower(a) != std::tolower(b)) return false;
    }
    return true;
}

bool IsReservedDevice(std::string_view stem)
{
    if (EqualsIgnoreCase(stem, "con") || EqualsIgnoreCase(stem, "prn") ||
        EqualsIgnoreCase(stem, "aux") || EqualsIgnoreCase(stem, "nul")) {
        return true;
    }
    if (stem.size() != 4) return false;
    const bool com = EqualsIgnoreCase(stem.substr(0, 3), "com");
    const bool lpt = EqualsIgnoreCase(stem.substr(0, 3), "lpt");
    const unsigned char n = static_cast<unsigned char>(stem[3]);
    return (com || lpt) && n >= '1' && n <= '9';
}

bool SegmentUnsafe(std::string_view seg)
{
    if (seg.empty() || seg == "." || seg == "..") return true;
    const unsigned char tail = static_cast<unsigned char>(seg.back());
    if (tail == ' ' || tail == '.') return true;
    if (EqualsIgnoreCase(seg, ".git")) return true;
    const size_t dot = seg.find('.');
    const std::string_view stem = dot == std::string_view::npos ? seg : seg.substr(0, dot);
    return IsReservedDevice(stem);
}

void AppendLe32(std::vector<unsigned char>& out, uint32_t value)
{
    out.push_back(static_cast<unsigned char>(value));
    out.push_back(static_cast<unsigned char>(value >> 8));
    out.push_back(static_cast<unsigned char>(value >> 16));
    out.push_back(static_cast<unsigned char>(value >> 24));
}

void AppendLe64(std::vector<unsigned char>& out, uint64_t value)
{
    for (int shift = 0; shift < 64; shift += 8) {
        out.push_back(static_cast<unsigned char>(value >> shift));
    }
}

bool EncodeTips(const std::map<std::string, GitRefTip>& tips, std::vector<unsigned char>& body, std::string& err)
{
    body.clear();
    for (const auto& [name, tip] : tips) {
        AppendLe32(body, static_cast<uint32_t>(name.size()));
        body.insert(body.end(), name.begin(), name.end());
        AppendLe64(body, tip.sequence);
        Digest48 id;
        if (!Digest48::FromHex(tip.record_id, id, err)) {
            err = "BTX035_ID_MISMATCH";
            return false;
        }
        body.insert(body.end(), id.data.begin(), id.data.end());
    }
    err.clear();
    return true;
}

bool Admit(std::map<std::string, GitRefTip>& view, const GitRefUpdate& update, std::string& err)
{
    const auto it = view.find(update.refname);
    if (it == view.end()) {
        if (update.sequence == 0 && update.previous_update_id.empty()) {
            view.emplace(update.refname, GitRefTip{update.sequence, update.record_id});
            return true;
        }
        err = "BTX035_GAP";
        return false;
    }
    const GitRefTip& current = it->second;
    if (update.sequence == current.sequence) {
        err = update.record_id == current.record_id ? "BTX035_DUPLICATE" : "BTX035_EQUIVOCATION";
        return false;
    }
    if (update.sequence < current.sequence) {
        err = "BTX035_ROLLBACK";
        return false;
    }
    if (update.sequence != current.sequence + 1 || update.previous_update_id != current.record_id) {
        err = "BTX035_GAP";
        return false;
    }
    it->second = GitRefTip{update.sequence, update.record_id};
    return true;
}

bool WellFormed(const GitRefUpdate& update, std::string& err)
{
    if (!SafeGitPath(update.refname, err)) return false;
    if (!IsStrongGitDigest(update.record_id)) {
        err = "BTX035_ID_MISMATCH";
        return false;
    }
    if (!update.previous_update_id.empty() && !IsStrongGitDigest(update.previous_update_id)) {
        err = "BTX035_ID_MISMATCH";
        return false;
    }
    return true;
}

} // namespace

bool IsStrongGitDigest(std::string_view hex)
{
    if (hex.size() != 96) return false;
    for (unsigned char c : hex) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

bool GitObjectDigest(std::string_view kind, Span<const unsigned char> content, std::string& digest_hex, std::string& err)
{
    if (kind != "blob" && kind != "tree" && kind != "commit" && kind != "tag" && kind != "research" && kind != "train" &&
        kind != "lineage" && kind != "model" && kind != "piece" && kind != "replay") {
        err = "BTX035_GIT_TYPE";
        return false;
    }
    const std::string length = std::to_string(content.size());
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(kind.data()), kind.size());
    const unsigned char space = ' ';
    hasher.Write(&space, 1);
    hasher.Write(reinterpret_cast<const unsigned char*>(length.data()), length.size());
    const unsigned char nul = 0;
    hasher.Write(&nul, 1);
    if (!content.empty()) hasher.Write(content.data(), content.size());
    Digest48 dig;
    hasher.Finalize(dig.data.data());
    digest_hex = dig.Hex();
    err.clear();
    return true;
}

bool SafeGitPath(std::string_view path, std::string& err)
{
    if (path.empty()) return FailPath(err);
    if (path.find('\0') != std::string_view::npos) return FailPath(err);
    if (path.find('\\') != std::string_view::npos) return FailPath(err);
    if (path.find(':') != std::string_view::npos) return FailPath(err);
    if (path.front() == '/') return FailPath(err);

    size_t begin = 0;
    while (begin <= path.size()) {
        const size_t slash = path.find('/', begin);
        const std::string_view seg = path.substr(begin, slash == std::string_view::npos ? std::string_view::npos : slash - begin);
        if (SegmentUnsafe(seg)) return FailPath(err);
        if (slash == std::string_view::npos) break;
        begin = slash + 1;
    }
    err.clear();
    return true;
}

bool RefJournal::AuthorizeAndStage(const std::vector<GitRefUpdate>& updates, std::string& err)
{
    if (updates.empty() || m_staged) {
        err = "BTX035_PUSH_STAGE";
        return false;
    }
    for (const GitRefUpdate& update : updates) {
        if (!WellFormed(update, err)) return false;
    }
    m_pending = updates;
    m_staged = true;
    err.clear();
    return true;
}

bool RefJournal::Publish(std::string& err)
{
    if (!m_staged) {
        err = "BTX035_PUSH_STAGE";
        return false;
    }
    std::map<std::string, GitRefTip> next = m_committed;
    for (const GitRefUpdate& update : m_pending) {
        if (!Admit(next, update, err)) {
            m_pending.clear();
            m_staged = false;
            return false;
        }
    }
    std::vector<unsigned char> encoded;
    if (!EncodeTips(next, encoded, err)) {
        m_pending.clear();
        m_staged = false;
        return false;
    }
    const Digest48 commitment = DomainHash("BTX/035/Journal/v1", encoded);
    m_committed.swap(next);
    m_pending.clear();
    m_staged = false;
    m_commitment = commitment;
    err.clear();
    return true;
}

void RefJournal::AbandonStaged()
{
    m_pending.clear();
    m_staged = false;
}

} // namespace modelnet
