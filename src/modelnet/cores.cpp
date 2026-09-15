// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/cores.h>

#include <modelnet/crypto.h>
#include <modelnet/store.h>
#include <crypto/common.h>
#include <span.h>

#include <algorithm>
#include <cstring>
#include <regex>
#include <set>

namespace modelnet {
namespace {

bool CompactSize(uint64_t n, std::vector<unsigned char>& out, std::string& err)
{
    if (n < 253) {
        out.push_back(static_cast<unsigned char>(n));
        return true;
    }
    if (n <= 65535) {
        out.push_back(0xfd);
        unsigned char b[2];
        WriteLE16(b, static_cast<uint16_t>(n));
        out.insert(out.end(), b, b + 2);
        return true;
    }
    if (n <= 0xffffffffULL) {
        out.push_back(0xfe);
        unsigned char b[4];
        WriteLE32(b, static_cast<uint32_t>(n));
        out.insert(out.end(), b, b + 4);
        return true;
    }
    out.push_back(0xff);
    unsigned char b[8];
    WriteLE64(b, n);
    out.insert(out.end(), b, b + 8);
    (void)err;
    return true;
}

bool EncodeString(const std::string& s, size_t limit, std::vector<unsigned char>& out, std::string& err)
{
    if (s.empty() || s.size() > limit) {
        err = "string length";
        return false;
    }
    for (unsigned char c : s) {
        if (c > 127) {
            err = "non-ascii string";
            return false;
        }
    }
    if (!CompactSize(s.size(), out, err)) return false;
    out.insert(out.end(), s.begin(), s.end());
    return true;
}

bool EncodeFileEntry(const CoreFile& f, std::vector<unsigned char>& out, std::string& err)
{
    if (!IsPortableRelPath(f.path, err)) return false;
    const uint8_t role = static_cast<uint8_t>(f.role);
    if (role < 1 || role > 5) {
        err = "file role";
        return false;
    }
    if (f.size > MAX_FILE_BYTES) {
        err = "file size";
        return false;
    }
    if (!EncodeString(f.path, 240, out, err)) return false;
    out.push_back(role);
    unsigned char sz[8];
    WriteLE64(sz, f.size);
    out.insert(out.end(), sz, sz + 8);
    out.insert(out.end(), f.sha384.data.begin(), f.sha384.data.end());
    out.insert(out.end(), f.pieces_root.data.begin(), f.pieces_root.data.end());
    return true;
}

bool EncodeFiles(const std::vector<CoreFile>& files, std::vector<unsigned char>& out, std::string& err)
{
    if (files.empty() || files.size() > 1024) {
        err = "file count";
        return false;
    }
    std::vector<std::string> paths;
    paths.reserve(files.size());
    uint64_t total = 0;
    for (const auto& f : files) {
        paths.push_back(f.path);
        if (total > MAX_FILE_BYTES - f.size) {
            err = "artifact too large";
            return false;
        }
        total += f.size;
    }
    auto sorted = paths;
    std::sort(sorted.begin(), sorted.end());
    if (sorted != paths) {
        err = "path ordering";
        return false;
    }
    std::set<std::string> lower;
    for (const auto& p : paths) {
        std::string l = p;
        for (char& c : l) {
            if (c >= 'A' && c <= 'Z') c = static_cast<char>(c - 'A' + 'a');
        }
        if (!lower.insert(l).second) {
            err = "duplicate path";
            return false;
        }
    }
    if (!CompactSize(files.size(), out, err)) return false;
    for (const auto& f : files) {
        if (!EncodeFileEntry(f, out, err)) return false;
    }
    return true;
}

} // namespace

bool EncodeCompactSizeModel(uint64_t n, std::vector<unsigned char>& out, std::string& err)
{
    return CompactSize(n, out, err);
}

bool EncodeModelCore(const ModelCore& core, std::vector<unsigned char>& out, std::string& err)
{
    out.clear();
    if (core.version != 2) {
        err = "version2 required";
        return false;
    }
    if (core.format_profile != 1 && core.format_profile != 2) {
        err = "profile";
        return false;
    }
    if (core.execution_profile > 1) {
        err = "profile";
        return false;
    }
    if (core.base_models.size() > 8) {
        err = "bases order";
        return false;
    }
    auto bases = core.base_models;
    auto uniq = bases;
    std::sort(uniq.begin(), uniq.end());
    uniq.erase(std::unique(uniq.begin(), uniq.end()), uniq.end());
    if (uniq != bases) {
        err = "bases order";
        return false;
    }
    unsigned char u16[2];
    WriteLE16(u16, core.version);
    out.insert(out.end(), u16, u16 + 2);
    WriteLE16(u16, core.format_profile);
    out.insert(out.end(), u16, u16 + 2);
    WriteLE16(u16, core.execution_profile);
    out.insert(out.end(), u16, u16 + 2);
    out.insert(out.end(), core.config_sha384.data.begin(), core.config_sha384.data.end());
    out.insert(out.end(), core.tokenizer_sha384.data.begin(), core.tokenizer_sha384.data.end());
    if (!CompactSize(core.base_models.size(), out, err)) return false;
    for (const auto& b : core.base_models) {
        out.insert(out.end(), b.data.begin(), b.data.end());
    }
    return EncodeFiles(core.files, out, err);
}

bool EncodeArtifactCore(const ArtifactCore& core, std::vector<unsigned char>& out, std::string& err)
{
    out.clear();
    if (core.version != 2) {
        err = "version2 required";
        return false;
    }
    if (core.codec != 1 && core.codec != 2) {
        err = "codec";
        return false;
    }
    if (core.codec == 1) {
        for (unsigned char c : core.encryption_context) {
            if (c != 0) {
                err = "plain context must be zero";
                return false;
            }
        }
    }
    unsigned char u16[2];
    WriteLE16(u16, core.version);
    out.insert(out.end(), u16, u16 + 2);
    out.push_back(core.codec);
    out.insert(out.end(), core.model_id.data.begin(), core.model_id.data.end());
    out.insert(out.end(), core.encryption_context.begin(), core.encryption_context.end());
    return EncodeFiles(core.files, out, err);
}

Digest48 ModelCoreId(const std::vector<unsigned char>& canonical)
{
    return DomainHash("BTX/ModelCore/v2", Span<const unsigned char>{canonical.data(), canonical.size()});
}

Digest48 ArtifactCoreId(const std::vector<unsigned char>& canonical)
{
    return DomainHash("BTX/Artifact/v2", Span<const unsigned char>{canonical.data(), canonical.size()});
}

bool ValidateCollectionEntries(const std::vector<CollectionEntry>& entries, std::string& err)
{
    if (entries.empty() || entries.size() > MAX_COLLECTION_ENTRIES) {
        err = "collection size";
        return false;
    }
    for (size_t i = 0; i < entries.size(); ++i) {
        const auto& e = entries[i];
        if (e.priority < 1 || e.priority > 5 || e.retention_days > 3650) {
            err = "entry policy";
            return false;
        }
        if (i > 0) {
            if (!(entries[i - 1].model_id < e.model_id)) {
                err = "collection order";
                return false;
            }
        }
    }
    return true;
}

bool CanonicalizeCollectionEntries(std::vector<CollectionEntry>& entries, std::string& err)
{
    std::sort(entries.begin(), entries.end(), [](const CollectionEntry& a, const CollectionEntry& b) {
        return a.model_id < b.model_id;
    });
    auto last = std::unique(entries.begin(), entries.end(), [](const CollectionEntry& a, const CollectionEntry& b) {
        return a.model_id == b.model_id;
    });
    entries.erase(last, entries.end());
    return ValidateCollectionEntries(entries, err);
}

bool CollectionGrantsQualification(const std::vector<CollectionEntry>& entries, const std::string& filename)
{
    (void)entries;
    (void)filename;
    return false;
}

bool CollectionLoadsCode()
{
    return false;
}

bool CollectionFollowRaisesQuota()
{
    return false;
}

bool CircleHasOnChainMembership()
{
    return false;
}

Digest48 AliasKey(const Digest48& signer_id, const std::string& slug, std::string& err)
{
    static const std::regex slug_re{R"(^[a-z0-9][a-z0-9-]{0,31}$)"};
    if (!std::regex_match(slug, slug_re)) {
        err = "alias slug";
        return {};
    }
    std::vector<unsigned char> body(signer_id.data.begin(), signer_id.data.end());
    if (!EncodeCompactSizeModel(slug.size(), body, err)) return {};
    body.insert(body.end(), slug.begin(), slug.end());
    return DomainHash("BTX/ModelAliasKey/v1.1", body);
}

AliasApply AliasIndex::Apply(const Digest48& alias_key,
                              uint64_t sequence,
                              const Digest48& record_id,
                              ResourceKind target_kind,
                              const Digest48& target_id,
                              std::string& err)
{
    if (target_kind == ResourceKind::ALIAS) {
        err = "alias cannot chain";
        return AliasApply::REJECTED_CHAIN;
    }
    if (target_kind != ResourceKind::MODEL && target_kind != ResourceKind::COLLECTION &&
        target_kind != ResourceKind::RELEASE && target_kind != ResourceKind::POLICY_BUNDLE &&
        target_kind != ResourceKind::CIRCLE) {
        err = "alias target";
        return AliasApply::REJECTED;
    }
    auto it = m_by_key.find(alias_key);
    if (it == m_by_key.end()) {
        m_by_key[alias_key] = Mapping{sequence, record_id, target_kind, target_id, false};
        return AliasApply::ACCEPTED;
    }
    Mapping& cur = it->second;
    if (cur.frozen) {
        err = "equivocation freeze";
        return AliasApply::FROZEN_EQUIVOCATION;
    }
    if (sequence == cur.sequence && record_id != cur.record_id) {
        cur.frozen = true;
        err = "equivocation freeze";
        return AliasApply::FROZEN_EQUIVOCATION;
    }
    if (sequence > cur.sequence) {
        cur = Mapping{sequence, record_id, target_kind, target_id, false};
        return AliasApply::ACCEPTED;
    }
    if (sequence == cur.sequence && record_id == cur.record_id) {
        return AliasApply::ACCEPTED;
    }
    err = "stale alias";
    return AliasApply::REJECTED;
}

bool AliasIndex::Frozen(const Digest48& alias_key) const
{
    const auto it = m_by_key.find(alias_key);
    return it != m_by_key.end() && it->second.frozen;
}

bool AliasIndex::HoldsPrior(const Digest48& alias_key, const Digest48& target_id) const
{
    const auto it = m_by_key.find(alias_key);
    return it != m_by_key.end() && it->second.target_id == target_id;
}

} // namespace modelnet
