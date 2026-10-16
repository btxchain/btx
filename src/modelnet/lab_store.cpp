// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_store.h>

#include <crypto/sha384.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>

#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

constexpr char kMagic[8] = {'B', 'T', 'X', '0', '3', '5', 'L', 'S'};
constexpr uint32_t kVersion = 1;
constexpr uint64_t kHardMaxRows = 100000;
constexpr uint64_t kHardMaxBytes = 32ull * 1024ull * 1024ull;
constexpr uint32_t kMaxString = 1024u * 1024u;

bool Fail(std::string& err, const char* code)
{
    err = code;
    return false;
}

// State token preimage (REV-014 lab encoding):
//   ASCII("BTX/035/StateToken/v1.1") || 0x00 || Canonical(fields)
// Canonical is a tiny deterministic encoding, not the chapter-4 tagged tree.
// Keys are written in ascending ASCII order. Each key and each value is a
// uint32 little-endian byte length followed by the raw bytes. A null value_id
// is a zero-length value. Order: generation, owner_scope, policy_epoch,
// realm_id, target_key, target_kind, value_id.
void AppendLp(std::vector<unsigned char>& out, std::string_view bytes)
{
    const uint32_t n = static_cast<uint32_t>(bytes.size());
    out.push_back(static_cast<unsigned char>(n));
    out.push_back(static_cast<unsigned char>(n >> 8));
    out.push_back(static_cast<unsigned char>(n >> 16));
    out.push_back(static_cast<unsigned char>(n >> 24));
    out.insert(out.end(), bytes.begin(), bytes.end());
}

void AppendCanon(std::vector<unsigned char>& out, const LabStateFields& fields)
{
    AppendLp(out, "generation");
    AppendLp(out, fields.generation);
    AppendLp(out, "owner_scope");
    AppendLp(out, fields.owner_scope);
    AppendLp(out, "policy_epoch");
    AppendLp(out, fields.policy_epoch);
    AppendLp(out, "realm_id");
    AppendLp(out, fields.realm_id);
    AppendLp(out, "target_key");
    AppendLp(out, fields.target_key);
    AppendLp(out, "target_kind");
    AppendLp(out, fields.target_kind);
    AppendLp(out, "value_id");
    const std::string value_id = fields.value_id.value_or(std::string{});
    AppendLp(out, value_id);
}

bool AddBytes(uint64_t& acc, size_t n)
{
    if (n > std::numeric_limits<uint64_t>::max() - acc) return false;
    acc += static_cast<uint64_t>(n);
    return true;
}

bool AddStr(uint64_t& acc, const std::string& s)
{
    return AddBytes(acc, s.size());
}

class Writer {
public:
    void U8(uint8_t v) { m_bytes.push_back(v); }
    void U32(uint32_t v)
    {
        U8(static_cast<uint8_t>(v));
        U8(static_cast<uint8_t>(v >> 8));
        U8(static_cast<uint8_t>(v >> 16));
        U8(static_cast<uint8_t>(v >> 24));
    }
    void U64(uint64_t v)
    {
        U32(static_cast<uint32_t>(v));
        U32(static_cast<uint32_t>(v >> 32));
    }
    bool Str(std::string_view s)
    {
        if (s.size() > kMaxString) return false;
        U32(static_cast<uint32_t>(s.size()));
        m_bytes.insert(m_bytes.end(), s.begin(), s.end());
        return true;
    }
    const std::vector<unsigned char>& Bytes() const { return m_bytes; }

private:
    std::vector<unsigned char> m_bytes;
};

class Reader {
public:
    explicit Reader(std::vector<unsigned char> bytes) : m_bytes(std::move(bytes)) {}

    bool U8(uint8_t& v)
    {
        if (m_off >= m_bytes.size()) return false;
        v = m_bytes[m_off++];
        return true;
    }
    bool U32(uint32_t& v)
    {
        uint8_t a = 0, b = 0, c = 0, d = 0;
        if (!U8(a) || !U8(b) || !U8(c) || !U8(d)) return false;
        v = static_cast<uint32_t>(a) | (static_cast<uint32_t>(b) << 8) | (static_cast<uint32_t>(c) << 16) |
            (static_cast<uint32_t>(d) << 24);
        return true;
    }
    bool U64(uint64_t& v)
    {
        uint32_t lo = 0, hi = 0;
        if (!U32(lo) || !U32(hi)) return false;
        v = static_cast<uint64_t>(lo) | (static_cast<uint64_t>(hi) << 32);
        return true;
    }
    bool Str(std::string& s)
    {
        uint32_t n = 0;
        if (!U32(n) || n > kMaxString || m_off + n > m_bytes.size()) return false;
        s.assign(reinterpret_cast<const char*>(m_bytes.data() + m_off), n);
        m_off += n;
        return true;
    }
    bool Bool(bool& v)
    {
        uint8_t b = 0;
        if (!U8(b) || (b != 0 && b != 1)) return false;
        v = b == 1;
        return true;
    }
    bool Done() const { return m_off == m_bytes.size(); }

private:
    std::vector<unsigned char> m_bytes;
    size_t m_off{0};
};

bool WriteStr(Writer& w, std::string_view s)
{
    return w.Str(s);
}

bool SameRecord(const LabRecord& a, const LabRecord& b)
{
    return a.type == b.type && a.principal == b.principal && a.realm == b.realm && a.bytes_ref == b.bytes_ref &&
           a.accepted_at == b.accepted_at && a.auth_state == b.auth_state && a.is_private == b.is_private;
}

bool SameRef(const LabRef& a, const LabRef& b)
{
    return a.update_id == b.update_id && a.target == b.target && a.is_private == b.is_private;
}

bool SameEpoch(const LabIdentityEpoch& a, const LabIdentityEpoch& b)
{
    return a.transition == b.transition && a.key == b.key && a.status == b.status && a.is_private == b.is_private;
}

bool SameRevocation(const LabRevocation& a, const LabRevocation& b)
{
    return a.is_private == b.is_private;
}

bool EmptyKey(const LabIdempotency& scope)
{
    return scope.caller.empty() || scope.realm.empty() || scope.method.empty() || scope.key.empty();
}

bool EmptyStateKey(const LabStateKey& key)
{
    return key.realm_id.empty() || key.owner_scope.empty() || key.target_kind.empty() || key.target_key.empty();
}

bool EmptyStateFields(const LabStateFields& fields)
{
    return fields.realm_id.empty() || fields.owner_scope.empty() || fields.target_kind.empty() || fields.target_key.empty();
}

} // namespace

uint64_t LabStore::EffectiveRows(const Snapshot& snap)
{
    return snap.max_records < kHardMaxRows ? snap.max_records : kHardMaxRows;
}

uint64_t LabStore::EffectiveBytes(const Snapshot& snap)
{
    return snap.max_bytes < kHardMaxBytes ? snap.max_bytes : kHardMaxBytes;
}

LabStore::RefKey LabStore::RefOf(const LabRef& row)
{
    return {row.repository, row.name_space, row.name, row.sequence};
}

LabStore::EpochKey LabStore::EpochOf(const LabIdentityEpoch& row)
{
    return {row.root, row.epoch};
}

LabStore::RevKey LabStore::RevOf(const LabRevocation& row)
{
    return {row.issuer, row.epoch, row.target};
}

LabStore::IdemKey LabStore::IdemOf(const LabIdempotency& scope)
{
    return {scope.caller, scope.realm, scope.method, scope.key};
}

LabStore::StateMapKey LabStore::StateOf(const LabStateKey& key)
{
    return {key.realm_id, key.owner_scope, key.target_kind, key.target_key};
}

LabStore::StateMapKey LabStore::StateOf(const LabStateFields& fields)
{
    return {fields.realm_id, fields.owner_scope, fields.target_kind, fields.target_key};
}

bool LabStore::PayloadBytes(const Snapshot& snap, uint64_t& out)
{
    uint64_t acc = 0;
    for (const auto& item : snap.records) {
        const LabRecord& row = item.second;
        if (!AddStr(acc, row.record_id) || !AddStr(acc, row.type) || !AddStr(acc, row.principal) || !AddStr(acc, row.realm) ||
            !AddStr(acc, row.bytes_ref) || !AddStr(acc, row.accepted_at) || !AddStr(acc, row.auth_state)) {
            return false;
        }
    }
    for (const auto& item : snap.refs) {
        const LabRef& row = item.second;
        if (!AddStr(acc, row.repository) || !AddStr(acc, row.name_space) || !AddStr(acc, row.name) || !AddStr(acc, row.sequence) ||
            !AddStr(acc, row.update_id) || !AddStr(acc, row.target)) {
            return false;
        }
    }
    for (const auto& item : snap.epochs) {
        const LabIdentityEpoch& row = item.second;
        if (!AddStr(acc, row.root) || !AddStr(acc, row.epoch) || !AddStr(acc, row.transition) || !AddStr(acc, row.key) ||
            !AddStr(acc, row.status)) {
            return false;
        }
    }
    for (const auto& item : snap.revocations) {
        const LabRevocation& row = item.second;
        if (!AddStr(acc, row.issuer) || !AddStr(acc, row.epoch) || !AddStr(acc, row.target)) return false;
    }
    for (const auto& item : snap.idempotency) {
        const LabStore::IdemRow& row = item.second;
        if (!AddStr(acc, std::get<0>(item.first)) || !AddStr(acc, std::get<1>(item.first)) || !AddStr(acc, std::get<2>(item.first)) ||
            !AddStr(acc, std::get<3>(item.first)) || !AddStr(acc, row.canonical_request) || !AddStr(acc, row.expected_state) ||
            !AddStr(acc, row.target.realm_id) || !AddStr(acc, row.target.owner_scope) || !AddStr(acc, row.target.target_kind) ||
            !AddStr(acc, row.target.target_key) || !AddStr(acc, row.result)) {
            return false;
        }
    }
    for (const auto& item : snap.states) {
        const LabStateFields& row = item.second;
        if (!AddStr(acc, row.realm_id) || !AddStr(acc, row.owner_scope) || !AddStr(acc, row.target_kind) || !AddStr(acc, row.target_key) ||
            !AddStr(acc, row.generation) || !AddStr(acc, row.policy_epoch)) {
            return false;
        }
        if (row.value_id && !AddStr(acc, *row.value_id)) return false;
    }
    out = acc;
    return true;
}

uint64_t LabStore::RowCount(const Snapshot& snap)
{
    const size_t n = snap.records.size() + snap.refs.size() + snap.epochs.size() + snap.revocations.size() + snap.idempotency.size() +
                     snap.states.size();
    return static_cast<uint64_t>(n);
}

bool LabStore::WithinLimits(const Snapshot& snap, std::string& err)
{
    uint64_t bytes = 0;
    if (!PayloadBytes(snap, bytes) || RowCount(snap) > EffectiveRows(snap) || bytes > EffectiveBytes(snap)) {
        return Fail(err, "BTX035_LIMIT_EXCEEDED");
    }
    return true;
}

bool LabStore::Encode(const Snapshot& snap, std::vector<unsigned char>& out, std::string& err)
{
    if (!snap.signature_required) return Fail(err, "BTX035_RECOVERY_REQUIRED");
    if (snap.backend_ready && snap.records.empty() && snap.refs.empty() && snap.epochs.empty() && snap.revocations.empty()) {
        return Fail(err, "BTX035_RECOVERY_REQUIRED");
    }
    Writer w;
    for (char c : kMagic) w.U8(static_cast<uint8_t>(c));
    w.U32(kVersion);
    w.U8(1);
    w.U8(snap.backend_ready ? 1 : 0);
    w.U64(snap.max_records);
    w.U64(snap.max_bytes);
    w.U32(static_cast<uint32_t>(snap.records.size()));
    for (const auto& item : snap.records) {
        const LabRecord& row = item.second;
        if (!WriteStr(w, row.record_id) || !WriteStr(w, row.type) || !WriteStr(w, row.principal) || !WriteStr(w, row.realm) ||
            !WriteStr(w, row.bytes_ref) || !WriteStr(w, row.accepted_at) || !WriteStr(w, row.auth_state)) {
            return Fail(err, "BTX035_LIMIT_EXCEEDED");
        }
        w.U8(row.is_private ? 1 : 0);
    }
    w.U32(static_cast<uint32_t>(snap.refs.size()));
    for (const auto& item : snap.refs) {
        const LabRef& row = item.second;
        if (!WriteStr(w, row.repository) || !WriteStr(w, row.name_space) || !WriteStr(w, row.name) || !WriteStr(w, row.sequence) ||
            !WriteStr(w, row.update_id) || !WriteStr(w, row.target)) {
            return Fail(err, "BTX035_LIMIT_EXCEEDED");
        }
        w.U8(row.is_private ? 1 : 0);
    }
    w.U32(static_cast<uint32_t>(snap.epochs.size()));
    for (const auto& item : snap.epochs) {
        const LabIdentityEpoch& row = item.second;
        if (!WriteStr(w, row.root) || !WriteStr(w, row.epoch) || !WriteStr(w, row.transition) || !WriteStr(w, row.key) ||
            !WriteStr(w, row.status)) {
            return Fail(err, "BTX035_LIMIT_EXCEEDED");
        }
        w.U8(row.is_private ? 1 : 0);
    }
    w.U32(static_cast<uint32_t>(snap.revocations.size()));
    for (const auto& item : snap.revocations) {
        const LabRevocation& row = item.second;
        if (!WriteStr(w, row.issuer) || !WriteStr(w, row.epoch) || !WriteStr(w, row.target)) return Fail(err, "BTX035_LIMIT_EXCEEDED");
        w.U8(row.is_private ? 1 : 0);
    }
    w.U32(static_cast<uint32_t>(snap.idempotency.size()));
    for (const auto& item : snap.idempotency) {
        const LabStore::IdemRow& row = item.second;
        unsigned char hash[CSHA384::OUTPUT_SIZE];
        CSHA384 hasher;
        hasher.Write(reinterpret_cast<const unsigned char*>(row.canonical_request.data()), row.canonical_request.size());
        hasher.Finalize(hash);
        if (!WriteStr(w, std::get<0>(item.first)) || !WriteStr(w, std::get<1>(item.first)) || !WriteStr(w, std::get<2>(item.first)) ||
            !WriteStr(w, std::get<3>(item.first)) || !WriteStr(w, row.canonical_request) || !w.Str(std::string_view(reinterpret_cast<const char*>(hash), CSHA384::OUTPUT_SIZE)) ||
            !WriteStr(w, row.expected_state) || !WriteStr(w, row.target.realm_id) || !WriteStr(w, row.target.owner_scope) ||
            !WriteStr(w, row.target.target_kind) || !WriteStr(w, row.target.target_key) || !WriteStr(w, row.result)) {
            return Fail(err, "BTX035_LIMIT_EXCEEDED");
        }
        w.U8(row.committed ? 2 : 1);
    }
    w.U32(static_cast<uint32_t>(snap.states.size()));
    for (const auto& item : snap.states) {
        const LabStateFields& row = item.second;
        if (!WriteStr(w, row.realm_id) || !WriteStr(w, row.owner_scope) || !WriteStr(w, row.target_kind) || !WriteStr(w, row.target_key) ||
            !WriteStr(w, row.generation) || !WriteStr(w, row.policy_epoch)) {
            return Fail(err, "BTX035_LIMIT_EXCEEDED");
        }
        w.U8(row.value_id ? 1 : 0);
        if (!WriteStr(w, row.value_id.value_or(""))) return Fail(err, "BTX035_LIMIT_EXCEEDED");
    }
    out = w.Bytes();
    return true;
}

bool LabStore::Decode(const std::vector<unsigned char>& bytes, Snapshot& snap)
{
    Reader r(bytes);
    uint8_t magic[8];
    for (uint8_t& b : magic) {
        if (!r.U8(b)) return false;
    }
    for (size_t i = 0; i < 8; ++i) {
        if (magic[i] != static_cast<uint8_t>(kMagic[i])) return false;
    }
    uint32_t version = 0;
    if (!r.U32(version) || version != kVersion) return false;
    uint8_t sig = 0;
    if (!r.U8(sig) || sig != 1) return false;
    snap.signature_required = true;
    if (!r.Bool(snap.backend_ready)) return false;
    if (!r.U64(snap.max_records) || !r.U64(snap.max_bytes)) return false;
    uint32_t n = 0;
    if (!r.U32(n) || n > kHardMaxRows) return false;
    for (uint32_t i = 0; i < n; ++i) {
        LabRecord row;
        if (!r.Str(row.record_id) || !r.Str(row.type) || !r.Str(row.principal) || !r.Str(row.realm) || !r.Str(row.bytes_ref) ||
            !r.Str(row.accepted_at) || !r.Str(row.auth_state) || !r.Bool(row.is_private) || row.record_id.empty()) {
            return false;
        }
        if (!snap.records.emplace(row.record_id, row).second) return false;
    }
    if (!r.U32(n) || n > kHardMaxRows) return false;
    for (uint32_t i = 0; i < n; ++i) {
        LabRef row;
        if (!r.Str(row.repository) || !r.Str(row.name_space) || !r.Str(row.name) || !r.Str(row.sequence) || !r.Str(row.update_id) ||
            !r.Str(row.target) || !r.Bool(row.is_private) || row.repository.empty() || row.name.empty()) {
            return false;
        }
        if (!snap.refs.emplace(RefOf(row), row).second) return false;
    }
    if (!r.U32(n) || n > kHardMaxRows) return false;
    for (uint32_t i = 0; i < n; ++i) {
        LabIdentityEpoch row;
        if (!r.Str(row.root) || !r.Str(row.epoch) || !r.Str(row.transition) || !r.Str(row.key) || !r.Str(row.status) ||
            !r.Bool(row.is_private) || row.root.empty()) {
            return false;
        }
        if (!snap.epochs.emplace(EpochOf(row), row).second) return false;
    }
    if (!r.U32(n) || n > kHardMaxRows) return false;
    for (uint32_t i = 0; i < n; ++i) {
        LabRevocation row;
        if (!r.Str(row.issuer) || !r.Str(row.epoch) || !r.Str(row.target) || !r.Bool(row.is_private) || row.issuer.empty() ||
            row.target.empty()) {
            return false;
        }
        if (!snap.revocations.emplace(RevOf(row), row).second) return false;
    }
    if (!r.U32(n) || n > kHardMaxRows) return false;
    for (uint32_t i = 0; i < n; ++i) {
        LabIdempotency scope;
        LabStore::IdemRow row;
        std::string hash;
        uint8_t phase = 0;
        if (!r.Str(scope.caller) || !r.Str(scope.realm) || !r.Str(scope.method) || !r.Str(scope.key) || !r.Str(row.canonical_request) ||
            !r.Str(hash) || !r.Str(row.expected_state) || !r.Str(row.target.realm_id) || !r.Str(row.target.owner_scope) ||
            !r.Str(row.target.target_kind) || !r.Str(row.target.target_key) || !r.Str(row.result) || !r.U8(phase)) {
            return false;
        }
        if (phase != 1 && phase != 2) return false;
        if (hash.size() != CSHA384::OUTPUT_SIZE) return false;
        unsigned char expect[CSHA384::OUTPUT_SIZE];
        CSHA384 hasher;
        hasher.Write(reinterpret_cast<const unsigned char*>(row.canonical_request.data()), row.canonical_request.size());
        hasher.Finalize(expect);
        if (hash != std::string(reinterpret_cast<const char*>(expect), CSHA384::OUTPUT_SIZE)) return false;
        row.committed = phase == 2;
        if (EmptyKey(scope) || EmptyStateKey(row.target)) return false;
        if (!snap.idempotency.emplace(IdemOf(scope), row).second) return false;
    }
    if (!r.U32(n) || n > kHardMaxRows) return false;
    for (uint32_t i = 0; i < n; ++i) {
        LabStateFields row;
        uint8_t has_value = 0;
        std::string value;
        if (!r.Str(row.realm_id) || !r.Str(row.owner_scope) || !r.Str(row.target_kind) || !r.Str(row.target_key) || !r.Str(row.generation) ||
            !r.Str(row.policy_epoch) || !r.U8(has_value) || !r.Str(value)) {
            return false;
        }
        if (has_value == 1) row.value_id = value;
        else if (has_value == 0) {
            if (!value.empty()) return false;
            row.value_id.reset();
        } else {
            return false;
        }
        if (EmptyStateFields(row)) return false;
        if (!snap.states.emplace(StateOf(row), row).second) return false;
    }
    if (snap.backend_ready && snap.records.empty() && snap.refs.empty() && snap.epochs.empty() && snap.revocations.empty()) return false;
    return r.Done();
}

namespace {

bool ReadAll(const fs::path& path, std::vector<unsigned char>& out)
{
    FILE* file = fsbridge::fopen(path, "rb");
    if (!file) return false;
    if (fseek(file, 0, SEEK_END) != 0) {
        fclose(file);
        return false;
    }
    const long sz = ftell(file);
    if (sz < 0 || static_cast<uint64_t>(sz) > kHardMaxBytes + (1024ull * 1024ull)) {
        fclose(file);
        return false;
    }
    if (fseek(file, 0, SEEK_SET) != 0) {
        fclose(file);
        return false;
    }
    out.resize(static_cast<size_t>(sz));
    const size_t n = sz == 0 ? 0 : fread(out.data(), 1, out.size(), file);
    const int closed = fclose(file);
    return closed == 0 && n == out.size();
}

bool AtomicWrite(const fs::path& dir, const std::vector<unsigned char>& bytes, std::string& err)
{
    const fs::path dest = dir / "lab.store";
    const fs::path tmp = dir / "lab.store.tmp";
    FILE* file = fsbridge::fopen(tmp, "wb");
    if (!file) return Fail(err, "BTX035_RECOVERY_REQUIRED");
    const size_t n = fwrite(bytes.data(), 1, bytes.size(), file);
    const bool committed = n == bytes.size() && FileCommit(file);
    const int closed = fclose(file);
    if (!committed || closed != 0 || !RenameOver(tmp, dest)) {
        std::error_code ec;
        fs::remove(tmp, ec);
        return Fail(err, "BTX035_RECOVERY_REQUIRED");
    }
    DirectoryCommit(dir);
    return true;
}

std::string ExportJoin(std::string_view kind, const std::vector<std::string>& fields)
{
    std::string line(kind);
    for (const std::string& field : fields) {
        line.push_back('|');
        line += field;
    }
    line.push_back('\n');
    return line;
}

} // namespace

bool LabStore::Save(const fs::path& dir, const Snapshot& snap, std::string& err)
{
    std::vector<unsigned char> bytes;
    if (!Encode(snap, bytes, err)) return false;
    if (bytes.size() > kHardMaxBytes + (1024ull * 1024ull)) return Fail(err, "BTX035_LIMIT_EXCEEDED");
    return AtomicWrite(dir, bytes, err);
}

std::string StateToken(const LabStateFields& fields)
{
    static constexpr char kDomain[] = "BTX/035/StateToken/v1.1";
    std::vector<unsigned char> canon;
    AppendCanon(canon, fields);
    CSHA384 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(kDomain), sizeof(kDomain) - 1);
    const unsigned char nul = 0;
    hasher.Write(&nul, 1);
    if (!canon.empty()) hasher.Write(canon.data(), canon.size());
    unsigned char out[CSHA384::OUTPUT_SIZE];
    hasher.Finalize(out);
    return HexStr(out);
}

LabStore::LabStore(fs::path directory) : m_dir(std::move(directory)) {}

bool LabStore::EnsureOpen(std::string& err) const
{
    if (!m_open) return Fail(err, "BTX035_RECOVERY_REQUIRED");
    return true;
}

bool LabStore::Persist(Snapshot next, std::string& err)
{
    if (!m_open) return Fail(err, "BTX035_RECOVERY_REQUIRED");
    if (!next.signature_required) return Fail(err, "BTX035_RECOVERY_REQUIRED");
    if (!Save(m_dir, next, err)) return false;
    m_snap = std::move(next);
    err.clear();
    return true;
}

bool LabStore::Open(std::string& err)
{
    m_open = false;
    try {
        if (std::filesystem::exists(m_dir)) {
            if (!std::filesystem::is_directory(m_dir)) return Fail(err, "BTX035_RECOVERY_REQUIRED");
        } else if (!fs::create_directories(m_dir)) {
            return Fail(err, "BTX035_RECOVERY_REQUIRED");
        }
    } catch (const std::filesystem::filesystem_error&) {
        return Fail(err, "BTX035_RECOVERY_REQUIRED");
    }
    const fs::path file = m_dir / "lab.store";
    bool have_file = false;
    try {
        have_file = fs::exists(file);
    } catch (const std::filesystem::filesystem_error&) {
        return Fail(err, "BTX035_RECOVERY_REQUIRED");
    }
    if (!have_file) {
        Snapshot fresh;
        fresh.signature_required = true;
        fresh.backend_ready = false;
        m_open = true;
        if (!Save(m_dir, fresh, err)) {
            m_open = false;
            return false;
        }
        m_snap = std::move(fresh);
        err.clear();
        return true;
    }
    std::vector<unsigned char> bytes;
    if (!ReadAll(file, bytes)) return Fail(err, "BTX035_RECOVERY_REQUIRED");
    Snapshot loaded;
    if (!Decode(bytes, loaded)) return Fail(err, "BTX035_RECOVERY_REQUIRED");
    m_snap = std::move(loaded);
    m_open = true;
    err.clear();
    return true;
}

bool LabStore::SetLimits(uint64_t max_records, uint64_t max_bytes, std::string& err)
{
    if (!EnsureOpen(err)) return false;
    Snapshot next = m_snap;
    next.max_records = max_records;
    next.max_bytes = max_bytes;
    next.signature_required = m_snap.signature_required;
    next.backend_ready = m_snap.backend_ready;
    return Persist(std::move(next), err);
}

bool LabStore::MarkBackendReady(std::string& err)
{
    if (!EnsureOpen(err)) return false;
    const bool empty = m_snap.records.empty() && m_snap.refs.empty() && m_snap.epochs.empty() && m_snap.revocations.empty();
    if (empty || !m_snap.signature_required) return Fail(err, "BTX035_RECOVERY_REQUIRED");
    Snapshot next = m_snap;
    next.backend_ready = true;
    next.signature_required = true;
    return Persist(std::move(next), err);
}

std::string LabStore::TokenFor(const LabStateKey& key) const
{
    const auto it = m_snap.states.find(StateOf(key));
    if (it == m_snap.states.end()) return {};
    return StateToken(it->second);
}

bool LabStore::StateMatches(const LabStateKey& key, const std::string& expected_state, std::string& err) const
{
    if (expected_state != TokenFor(key)) return Fail(err, "BTX035_STATE");
    return true;
}

bool LabStore::InsertRecord(const LabRecord& row, std::string& err)
{
    if (!EnsureOpen(err)) return false;
    if (row.record_id.empty()) return Fail(err, "BTX035_SCHEMA");
    const auto it = m_snap.records.find(row.record_id);
    if (it != m_snap.records.end()) {
        if (!SameRecord(it->second, row)) return Fail(err, "BTX035_CONFLICT");
        err.clear();
        return true;
    }
    Snapshot next = m_snap;
    next.records.emplace(row.record_id, row);
    if (!WithinLimits(next, err)) return false;
    return Persist(std::move(next), err);
}

bool LabStore::InsertRef(const LabRef& row, std::string& err)
{
    if (!EnsureOpen(err)) return false;
    if (row.repository.empty() || row.name.empty()) return Fail(err, "BTX035_SCHEMA");
    const RefKey key = RefOf(row);
    const auto it = m_snap.refs.find(key);
    if (it != m_snap.refs.end()) {
        if (!SameRef(it->second, row)) return Fail(err, "BTX035_CONFLICT");
        err.clear();
        return true;
    }
    Snapshot next = m_snap;
    next.refs.emplace(key, row);
    if (!WithinLimits(next, err)) return false;
    return Persist(std::move(next), err);
}

bool LabStore::InsertIdentityEpoch(const LabIdentityEpoch& row, std::string& err)
{
    if (!EnsureOpen(err)) return false;
    if (row.root.empty()) return Fail(err, "BTX035_SCHEMA");
    const EpochKey key = EpochOf(row);
    const auto it = m_snap.epochs.find(key);
    if (it != m_snap.epochs.end()) {
        if (!SameEpoch(it->second, row)) return Fail(err, "BTX035_CONFLICT");
        err.clear();
        return true;
    }
    Snapshot next = m_snap;
    next.epochs.emplace(key, row);
    if (!WithinLimits(next, err)) return false;
    return Persist(std::move(next), err);
}

bool LabStore::InsertRevocation(const LabRevocation& row, std::string& err)
{
    if (!EnsureOpen(err)) return false;
    if (row.issuer.empty() || row.target.empty()) return Fail(err, "BTX035_SCHEMA");
    const RevKey key = RevOf(row);
    const auto it = m_snap.revocations.find(key);
    if (it != m_snap.revocations.end()) {
        if (!SameRevocation(it->second, row)) return Fail(err, "BTX035_CONFLICT");
        err.clear();
        return true;
    }
    Snapshot next = m_snap;
    next.revocations.emplace(key, row);
    if (!WithinLimits(next, err)) return false;
    return Persist(std::move(next), err);
}

bool LabStore::GetRecord(const std::string& record_id, LabRecord& out, std::string& err) const
{
    if (!EnsureOpen(err)) return false;
    const auto it = m_snap.records.find(record_id);
    if (it == m_snap.records.end()) return Fail(err, "BTX035_NOT_FOUND");
    out = it->second;
    err.clear();
    return true;
}

bool LabStore::GetRef(const std::string& repository, const std::string& name_space, const std::string& name,
                      const std::string& sequence, LabRef& out, std::string& err) const
{
    if (!EnsureOpen(err)) return false;
    const auto it = m_snap.refs.find(RefKey{repository, name_space, name, sequence});
    if (it == m_snap.refs.end()) return Fail(err, "BTX035_NOT_FOUND");
    out = it->second;
    err.clear();
    return true;
}

bool LabStore::GetIdentityEpoch(const std::string& root, const std::string& epoch, LabIdentityEpoch& out, std::string& err) const
{
    if (!EnsureOpen(err)) return false;
    const auto it = m_snap.epochs.find(EpochKey{root, epoch});
    if (it == m_snap.epochs.end()) return Fail(err, "BTX035_NOT_FOUND");
    out = it->second;
    err.clear();
    return true;
}

bool LabStore::GetRevocation(const std::string& issuer, const std::string& epoch, const std::string& target, LabRevocation& out,
                             std::string& err) const
{
    if (!EnsureOpen(err)) return false;
    const auto it = m_snap.revocations.find(RevKey{issuer, epoch, target});
    if (it == m_snap.revocations.end()) return Fail(err, "BTX035_NOT_FOUND");
    out = it->second;
    err.clear();
    return true;
}

bool LabStore::PutState(const LabStateFields& fields, std::string& err)
{
    if (!EnsureOpen(err)) return false;
    if (EmptyStateFields(fields)) return Fail(err, "BTX035_SCHEMA");
    Snapshot next = m_snap;
    next.states.insert_or_assign(StateOf(fields), fields);
    if (!WithinLimits(next, err)) return false;
    return Persist(std::move(next), err);
}

bool LabStore::StateGet(const LabStateKey& key, LabStateView& out, std::string& err) const
{
    if (!EnsureOpen(err)) return false;
    if (EmptyStateKey(key)) return Fail(err, "BTX035_SCHEMA");
    LabStateView view;
    const auto it = m_snap.states.find(StateOf(key));
    if (it == m_snap.states.end()) {
        view.exists = false;
        view.generation = "0";
        view.value_id.reset();
        view.policy_epoch = "0";
        view.state_token.reset();
    } else {
        view.exists = true;
        view.generation = it->second.generation;
        view.value_id = it->second.value_id;
        view.policy_epoch = it->second.policy_epoch;
        view.state_token = StateToken(it->second);
    }
    out = std::move(view);
    err.clear();
    return true;
}

bool LabStore::Reserve(const LabIdempotency& scope, const std::string& canonical_request, const std::string& expected_state,
                       const LabStateKey& target, bool& replayed, std::string& response, std::string& err)
{
    replayed = false;
    response.clear();
    if (!EnsureOpen(err)) return false;
    if (EmptyKey(scope) || EmptyStateKey(target)) return Fail(err, "BTX035_SCHEMA");
    const auto it = m_snap.idempotency.find(IdemOf(scope));
    if (it != m_snap.idempotency.end()) {
        if (it->second.canonical_request != canonical_request) return Fail(err, "BTX035_IDEMPOTENCY");
        if (it->second.committed) {
            replayed = true;
            response = it->second.result;
            err.clear();
            return true;
        }
        if (it->second.expected_state != expected_state || it->second.target.realm_id != target.realm_id ||
            it->second.target.owner_scope != target.owner_scope || it->second.target.target_kind != target.target_kind ||
            it->second.target.target_key != target.target_key) {
            return Fail(err, "BTX035_STATE");
        }
        if (!StateMatches(target, expected_state, err)) return false;
        err.clear();
        return true;
    }
    if (!StateMatches(target, expected_state, err)) return false;
    Snapshot next = m_snap;
    IdemRow row;
    row.canonical_request = canonical_request;
    row.expected_state = expected_state;
    row.target = target;
    row.committed = false;
    next.idempotency.emplace(IdemOf(scope), row);
    if (!WithinLimits(next, err)) return false;
    return Persist(std::move(next), err);
}

bool LabStore::Commit(const LabIdempotency& scope, const std::string& canonical_request, const std::string& response_body,
                      std::string& err)
{
    if (!EnsureOpen(err)) return false;
    if (EmptyKey(scope)) return Fail(err, "BTX035_SCHEMA");
    const auto it = m_snap.idempotency.find(IdemOf(scope));
    if (it == m_snap.idempotency.end()) return Fail(err, "BTX035_IDEMPOTENCY");
    if (it->second.canonical_request != canonical_request) return Fail(err, "BTX035_IDEMPOTENCY");
    if (it->second.committed) {
        if (it->second.result != response_body) return Fail(err, "BTX035_IDEMPOTENCY");
        err.clear();
        return true;
    }
    if (!StateMatches(it->second.target, it->second.expected_state, err)) return false;
    Snapshot next = m_snap;
    IdemRow& row = next.idempotency.at(IdemOf(scope));
    row.result = response_body;
    row.committed = true;
    if (!WithinLimits(next, err)) return false;
    return Persist(std::move(next), err);
}

bool LabStore::PublicExport(std::string& out, std::string& err) const
{
    if (!EnsureOpen(err)) return false;
    std::string text;
    for (const auto& item : m_snap.records) {
        const LabRecord& row = item.second;
        if (row.is_private) continue;
        text += ExportJoin("record", {row.record_id, row.type, row.principal, row.realm, row.bytes_ref, row.accepted_at, row.auth_state});
    }
    for (const auto& item : m_snap.refs) {
        const LabRef& row = item.second;
        if (row.is_private) continue;
        text += ExportJoin("ref", {row.repository, row.name_space, row.name, row.sequence, row.update_id, row.target});
    }
    for (const auto& item : m_snap.epochs) {
        const LabIdentityEpoch& row = item.second;
        if (row.is_private) continue;
        text += ExportJoin("identity_epoch", {row.root, row.epoch, row.transition, row.key, row.status});
    }
    for (const auto& item : m_snap.revocations) {
        const LabRevocation& row = item.second;
        if (row.is_private) continue;
        text += ExportJoin("revocation", {row.issuer, row.epoch, row.target});
    }
    out = std::move(text);
    err.clear();
    return true;
}

} // namespace modelnet
