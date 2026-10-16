// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/realm_channel.h>

#include <crypto/hex_base.h>
#include <crypto/sha384.h>
#include <span.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <limits>
#include <system_error>
#include <utility>

namespace modelnet {
namespace {

bool AcceptedObservation(const std::string& state)
{
    return state == "HEALTHY" || state == "UNHEALTHY" || state == "UNKNOWN";
}

bool SingleLine(const std::string& text)
{
    return text.find('\n') == std::string::npos && text.find('\r') == std::string::npos;
}

bool ParseU64(const std::string& text, uint64_t& out)
{
    if (text.empty() || (text.size() > 1 && text[0] == '0')) return false;
    uint64_t value = 0;
    for (const unsigned char c : text) {
        if (c < '0' || c > '9') return false;
        const uint64_t digit = static_cast<uint64_t>(c - '0');
        if (value > (std::numeric_limits<uint64_t>::max() - digit) / 10ull) return false;
        value = value * 10ull + digit;
    }
    out = value;
    return true;
}

bool KeyValue(const std::string& line, const char* key, std::string& value)
{
    const std::string prefix = std::string(key) + "=";
    if (line.compare(0, prefix.size(), prefix) != 0) return false;
    value = line.substr(prefix.size());
    return true;
}

bool NextLine(const std::vector<std::string>& lines, std::size_t& index, std::string& line)
{
    if (index >= lines.size()) return false;
    line = lines[index++];
    return true;
}

struct OfflineText {
    std::string realm;
    int threshold{0};
    std::set<std::string> pinned;
    std::set<std::string> revoked;
    bool has_channel{false};
    int64_t channel_sequence{0};
    std::string body_hash;
    /** Set when the live channel key is realm + newline + this name. */
    std::string channel_name;
};

bool ReadIdList(const std::vector<std::string>& lines, std::size_t& index, const char* key, std::set<std::string>& ids)
{
    std::string line;
    std::string value;
    if (!NextLine(lines, index, line) || !KeyValue(line, key, value)) return false;
    uint64_t count = 0;
    if (!ParseU64(value, count)) return false;
    if (count > static_cast<uint64_t>(lines.size() - index)) return false;
    for (uint64_t n = 0; n < count; ++n) {
        if (!NextLine(lines, index, line) || line.empty() || !ids.insert(line).second) return false;
    }
    return true;
}

bool ParseOfflineText(const std::vector<std::string>& lines, OfflineText& out)
{
    std::size_t index = 0;
    std::string line;
    std::string value;
    if (!NextLine(lines, index, line) || line != "BTX035-OFFLINE-1") return false;
    if (!NextLine(lines, index, line) || !KeyValue(line, "realm", value) || value.empty() || !SingleLine(value)) return false;
    out.realm = std::move(value);
    if (!NextLine(lines, index, line) || !KeyValue(line, "threshold", value)) return false;
    uint64_t threshold = 0;
    if (!ParseU64(value, threshold) || threshold < 1 || threshold > static_cast<uint64_t>(std::numeric_limits<int>::max())) return false;
    out.threshold = static_cast<int>(threshold);
    if (!ReadIdList(lines, index, "pinned", out.pinned)) return false;
    if (!ReadIdList(lines, index, "revoked", out.revoked)) return false;
    if (!NextLine(lines, index, line) || !KeyValue(line, "channel", value)) return false;
    if (value == "-1") {
        out.has_channel = false;
        out.channel_sequence = 0;
    } else {
        uint64_t sequence = 0;
        if (!ParseU64(value, sequence) || sequence > static_cast<uint64_t>(std::numeric_limits<int64_t>::max())) return false;
        out.has_channel = true;
        out.channel_sequence = static_cast<int64_t>(sequence);
    }
    if (!NextLine(lines, index, line) || !KeyValue(line, "body", out.body_hash)) return false;
    if (!out.has_channel && !out.body_hash.empty()) return false;
    if (index < lines.size()) {
        if (!NextLine(lines, index, line) || !KeyValue(line, "name", out.channel_name) || out.channel_name.empty() ||
            !SingleLine(out.channel_name)) {
            return false;
        }
    }
    return index == lines.size();
}

bool EndpointLifecycleState(const std::string& state)
{
    return state == "DISCOVERED" || state == "FETCHING" || state == "STAGED" || state == "VERIFIED" ||
           state == "CANARY" || state == "ACTIVE" || state == "PAUSED" || state == "FAILED" ||
           state == "ROLLED_BACK" || state == "UNKNOWN";
}

bool TransportCompletionState(const std::string& state)
{
    return state == "FETCHING" || state == "STAGED";
}

std::string Sha384Hex(const std::string& text)
{
    CSHA384 hasher;
    if (!text.empty()) {
        hasher.Write(reinterpret_cast<const unsigned char*>(text.data()), text.size());
    }
    unsigned char out[CSHA384::OUTPUT_SIZE];
    hasher.Finalize(out);
    return HexStr(Span<const unsigned char>(out, CSHA384::OUTPUT_SIZE));
}

std::string TargetRoot(const std::set<std::string>& ids)
{
    std::string lines;
    for (const std::string& id : ids) {
        if (!lines.empty()) lines.push_back('\n');
        lines += id;
    }
    return Sha384Hex(lines);
}

bool GenerationNameOk(const std::string& name, std::string& err)
{
    if (name.empty() || !SingleLine(name)) {
        err = "BTX035_POLICY";
        return false;
    }
    if (name.front() == '/') {
        err = "BTX035_PATH_UNSAFE";
        return false;
    }
    std::size_t start = 0;
    while (start <= name.size()) {
        const std::size_t slash = name.find('/', start);
        const std::size_t end = slash == std::string::npos ? name.size() : slash;
        const std::string comp = name.substr(start, end - start);
        if (comp.empty() || comp == "." || comp == "..") {
            err = "BTX035_PATH_UNSAFE";
            return false;
        }
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    return true;
}

bool PortableRelative(const std::string& path)
{
    if (path.empty() || path.front() == '/') return false;
    std::size_t start = 0;
    while (start <= path.size()) {
        const std::size_t slash = path.find('/', start);
        const std::size_t end = slash == std::string::npos ? path.size() : slash;
        const std::string comp = path.substr(start, end - start);
        if (comp.empty() || comp == "." || comp == "..") return false;
        if (slash == std::string::npos) break;
        start = slash + 1;
    }
    return true;
}

uint64_t LookupCounter(const std::map<std::string, uint64_t>& table, const std::string& key)
{
    const auto it = table.find(key);
    return it == table.end() ? 0 : it->second;
}

bool SumFits(uint64_t current, uint64_t add, uint64_t cap, uint64_t& next)
{
    if (add > std::numeric_limits<uint64_t>::max() - current) return false;
    next = current + add;
    return next <= cap;
}

constexpr std::size_t kTarBlock = 512;
constexpr uint64_t kMaxUstarSize = 077777777777ull;

bool AllZero(const char* data, std::size_t width)
{
    for (std::size_t i = 0; i < width; ++i) {
        if (data[i] != 0) return false;
    }
    return true;
}

void WriteOctal(char* dest, std::size_t width, uint64_t value)
{
    for (std::size_t i = 0; i < width; ++i) dest[i] = '\0';
    if (width == 0) return;
    for (std::size_t i = width - 1; i-- > 0;) {
        dest[i] = static_cast<char>('0' + static_cast<unsigned>(value & 7u));
        value >>= 3;
    }
}

bool OctalFits(uint64_t value, std::size_t width)
{
    if (width < 2) return false;
    uint64_t max = 0;
    for (std::size_t i = 0; i + 1 < width; ++i) {
        if (max > (std::numeric_limits<uint64_t>::max() - 7) / 8) return true;
        max = max * 8 + 7;
    }
    return value <= max;
}

unsigned HeaderChecksum(const char* header)
{
    unsigned sum = 0;
    for (std::size_t i = 0; i < kTarBlock; ++i) {
        const unsigned char byte = (i >= 148 && i < 156) ? static_cast<unsigned char>(' ') : static_cast<unsigned char>(header[i]);
        sum += byte;
    }
    return sum;
}

void WriteChecksum(char* header)
{
    for (int i = 148; i < 156; ++i) header[i] = ' ';
    unsigned sum = HeaderChecksum(header);
    for (int i = 5; i >= 0; --i) {
        header[148 + i] = static_cast<char>('0' + (sum & 7u));
        sum >>= 3;
    }
    header[154] = '\0';
    header[155] = ' ';
}

bool ParseOctal(const char* data, std::size_t width, uint64_t& value)
{
    value = 0;
    bool digits = false;
    for (std::size_t i = 0; i < width; ++i) {
        const unsigned char c = static_cast<unsigned char>(data[i]);
        if (c == '\0' || c == ' ') {
            if (digits) break;
            continue;
        }
        if (c < '0' || c > '7') return false;
        digits = true;
        if (value > (std::numeric_limits<uint64_t>::max() >> 3)) return false;
        value = (value << 3) + static_cast<uint64_t>(c - '0');
    }
    return true;
}

std::string TarField(const char* data, std::size_t width)
{
    std::size_t n = 0;
    while (n < width && data[n] != '\0') ++n;
    return std::string(data, n);
}

bool SplitTarName(const std::string& tar_name, std::string& name, std::string& prefix)
{
    if (tar_name.size() <= 100) {
        name = tar_name;
        prefix.clear();
        return true;
    }
    if (tar_name.size() > 256) return false;
    std::size_t split = std::string::npos;
    for (std::size_t i = 0; i < tar_name.size(); ++i) {
        if (tar_name[i] != '/') continue;
        const std::size_t name_len = tar_name.size() - i - 1;
        if (name_len >= 1 && name_len <= 100 && i <= 155) split = i;
    }
    if (split == std::string::npos) return false;
    prefix = tar_name.substr(0, split);
    name = tar_name.substr(split + 1);
    return true;
}

struct ArchiveItem {
    std::string rel;
    std::filesystem::path source;
    bool directory{false};
    uint64_t size{0};
    std::string bytes;
    bool synthetic{false};

    std::string TarName() const
    {
        return directory ? rel + "/" : rel;
    }
};

bool SingleComponent(const std::string& name)
{
    return !name.empty() && name != "." && name != ".." && name.find('/') == std::string::npos && name.front() != '/';
}

bool CollectArchive(const std::filesystem::path& dir, const std::string& prefix, std::vector<ArchiveItem>& items, std::string& err)
{
    std::error_code ec;
    std::filesystem::directory_iterator it(dir, ec);
    if (ec) {
        err = "BTX035_BUNDLE";
        return false;
    }
    while (it != std::filesystem::directory_iterator()) {
        const std::filesystem::directory_entry entry = *it;
        it.increment(ec);
        if (ec) {
            err = "BTX035_BUNDLE";
            return false;
        }
        const std::string name = entry.path().filename().string();
        if (!SingleComponent(name)) {
            err = "BTX035_PATH_UNSAFE";
            return false;
        }
        const std::string rel = prefix.empty() ? name : prefix + "/" + name;
        if (!PortableRelative(rel) || rel == "manifest") {
            err = "BTX035_PATH_UNSAFE";
            return false;
        }
        const std::filesystem::file_status st = entry.symlink_status(ec);
        if (ec) {
            err = "BTX035_BUNDLE";
            return false;
        }
        if (std::filesystem::is_symlink(st)) {
            err = "BTX035_PATH_UNSAFE";
            return false;
        }
        if (std::filesystem::is_directory(st)) {
            ArchiveItem item;
            item.rel = rel;
            item.source = entry.path();
            item.directory = true;
            items.push_back(std::move(item));
            if (!CollectArchive(entry.path(), rel, items, err)) return false;
        } else if (std::filesystem::is_regular_file(st)) {
            const auto sz = std::filesystem::file_size(entry.path(), ec);
            if (ec) {
                err = "BTX035_BUNDLE";
                return false;
            }
            if (static_cast<uint64_t>(sz) > kMaxUstarSize) {
                err = "BTX035_LIMIT_EXCEEDED";
                return false;
            }
            ArchiveItem item;
            item.rel = rel;
            item.source = entry.path();
            item.size = static_cast<uint64_t>(sz);
            items.push_back(std::move(item));
        } else {
            err = "BTX035_PATH_UNSAFE";
            return false;
        }
    }
    return true;
}

bool WriteHeader(std::ostream& out, const std::string& tar_name, char typeflag, uint64_t size)
{
    std::string name;
    std::string prefix;
    if (!SplitTarName(tar_name, name, prefix)) return false;
    std::array<char, kTarBlock> header{};
    std::memcpy(header.data(), name.data(), name.size());
    WriteOctal(header.data() + 100, 8, typeflag == '5' ? 0755u : 0644u);
    WriteOctal(header.data() + 108, 8, 0);
    WriteOctal(header.data() + 116, 8, 0);
    WriteOctal(header.data() + 124, 12, size);
    WriteOctal(header.data() + 136, 12, 0);
    header[156] = typeflag;
    std::memcpy(header.data() + 257, "ustar", 5);
    header[262] = '\0';
    header[263] = '0';
    header[264] = '0';
    WriteOctal(header.data() + 329, 8, 0);
    WriteOctal(header.data() + 337, 8, 0);
    if (!prefix.empty()) std::memcpy(header.data() + 345, prefix.data(), prefix.size());
    WriteChecksum(header.data());
    out.write(header.data(), static_cast<std::streamsize>(header.size()));
    return static_cast<bool>(out);
}

bool WritePadding(std::ostream& out, uint64_t size)
{
    const uint64_t pad = (kTarBlock - (size % kTarBlock)) % kTarBlock;
    if (pad == 0) return true;
    std::array<char, kTarBlock> zeros{};
    out.write(zeros.data(), static_cast<std::streamsize>(pad));
    return static_cast<bool>(out);
}

bool WriteItemBytes(std::ostream& out, const ArchiveItem& item)
{
    if (item.directory || item.size == 0) return true;
    if (item.synthetic) {
        out.write(item.bytes.data(), static_cast<std::streamsize>(item.bytes.size()));
        return static_cast<bool>(out);
    }
    std::ifstream in(item.source, std::ios::binary);
    if (!in) return false;
    std::array<char, 8192> buf{};
    uint64_t left = item.size;
    while (left > 0) {
        const std::size_t chunk = static_cast<std::size_t>(std::min<uint64_t>(left, buf.size()));
        in.read(buf.data(), static_cast<std::streamsize>(chunk));
        if (static_cast<std::size_t>(in.gcount()) != chunk) return false;
        out.write(buf.data(), static_cast<std::streamsize>(chunk));
        if (!out) return false;
        left -= chunk;
    }
    return true;
}

std::string LogicalTarPath(std::string full)
{
    while (!full.empty() && full.back() == '/') full.pop_back();
    return full;
}

bool SplitManifest(const std::string& text, std::vector<std::string>& lines, std::string& err)
{
    lines.clear();
    std::size_t start = 0;
    while (start < text.size()) {
        const std::size_t nl = text.find('\n', start);
        const bool last = nl == std::string::npos;
        const std::size_t end = last ? text.size() : nl;
        std::string line = text.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) {
            if (last || nl + 1 == text.size()) break;
            err = "BTX035_BUNDLE";
            return false;
        }
        lines.push_back(std::move(line));
        if (last) break;
        start = nl + 1;
    }
    return true;
}

bool ReadBlock(std::istream& in, char* dest, std::string& err)
{
    in.read(dest, static_cast<std::streamsize>(kTarBlock));
    if (in.gcount() == 0 && in.eof()) {
        err = "BTX035_BUNDLE";
        return false;
    }
    if (static_cast<std::size_t>(in.gcount()) != kTarBlock) {
        err = "BTX035_BUNDLE";
        return false;
    }
    return true;
}

} // namespace

bool RealmRollout::SetPolicy(const std::string& realm, int threshold, const std::vector<std::string>& pinned_ids, std::string& err)
{
    if (threshold < 1) {
        err = "BTX035_THRESHOLD";
        return false;
    }
    if (realm.empty()) {
        err = "BTX035_REALM";
        return false;
    }
    std::set<std::string> pins;
    for (const std::string& id : pinned_ids) {
        if (id.empty()) {
            err = "BTX035_POLICY";
            return false;
        }
        pins.insert(id);
    }
    const auto existing = m_realms.find(realm);
    if (existing != m_realms.end() && existing->second.policy_set) {
        if (existing->second.threshold != threshold) {
            err = "BTX035_THRESHOLD";
            return false;
        }
        if (existing->second.pinned != pins) {
            err = "BTX035_POLICY";
            return false;
        }
        err.clear();
        return true;
    }
    RealmState& st = m_realms[realm];
    st.policy_set = true;
    st.threshold = threshold;
    st.pinned = std::move(pins);
    err.clear();
    return true;
}

bool RealmRollout::RevokeAttestor(const std::string& realm, const std::string& id, std::string& err)
{
    const auto it = m_realms.find(realm);
    if (it == m_realms.end() || !it->second.policy_set) {
        err = "BTX035_REALM";
        return false;
    }
    if (id.empty()) {
        err = "BTX035_POLICY";
        return false;
    }
    it->second.revoked.insert(id);
    err.clear();
    return true;
}

bool RealmRollout::Quorum(const std::string& realm, const std::vector<std::string>& signer_ids) const
{
    const auto it = m_realms.find(realm);
    if (it == m_realms.end() || !it->second.policy_set) return false;
    const RealmState& st = it->second;
    std::set<std::string> eligible;
    for (const std::string& id : signer_ids) {
        if (st.pinned.count(id) == 0) continue;
        if (st.revoked.count(id) != 0) continue;
        eligible.insert(id);
    }
    return eligible.size() >= static_cast<std::size_t>(st.threshold);
}

int RealmRollout::Threshold(const std::string& realm) const
{
    const auto it = m_realms.find(realm);
    if (it == m_realms.end() || !it->second.policy_set) return 0;
    return it->second.threshold;
}

bool RealmRollout::Attest(const std::string& realm, const std::string& /*signer*/, const std::string& claimed_realm, std::string& err)
{
    if (realm.empty() || claimed_realm != realm) {
        err = "BTX035_REALM";
        return false;
    }
    err.clear();
    return true;
}

bool RealmRollout::PublishChannel(const std::string& realm, int64_t sequence, const std::string& body_hash, std::string& err)
{
    if (realm.empty()) {
        err = "BTX035_REALM";
        return false;
    }
    const auto it = m_realms.find(realm);
    const bool has_channel = it != m_realms.end() && it->second.has_channel;
    const int64_t last = has_channel ? it->second.channel_sequence : 0;
    if (!has_channel) {
        if (sequence < 0) {
            err = "BTX035_ROLLBACK";
            return false;
        }
        if (sequence > 0) {
            err = "BTX035_GAP";
            return false;
        }
    } else {
        if (sequence < last) {
            err = "BTX035_ROLLBACK";
            return false;
        }
        if (sequence == last) {
            err = "BTX035_STALE";
            return false;
        }
        if (last == std::numeric_limits<int64_t>::max() || sequence != last + 1) {
            err = "BTX035_GAP";
            return false;
        }
    }
    RealmState& st = m_realms[realm];
    st.has_channel = true;
    st.channel_sequence = sequence;
    st.body_hash = body_hash;
    err.clear();
    return true;
}

int64_t RealmRollout::ChannelSequence(const std::string& realm) const
{
    const auto it = m_realms.find(realm);
    if (it == m_realms.end() || !it->second.has_channel) return -1;
    return it->second.channel_sequence;
}

std::string RealmRollout::ChannelBody(const std::string& realm) const
{
    const auto it = m_realms.find(realm);
    if (it == m_realms.end() || !it->second.has_channel) return {};
    return it->second.body_hash;
}

bool RealmRollout::Observe(const std::string& endpoint, const std::string& state, std::string& err)
{
    if (endpoint.empty() || !AcceptedObservation(state)) {
        err = "BTX035_OBSERVE";
        return false;
    }
    m_observed[endpoint] = state;
    err.clear();
    return true;
}

FleetCounts RealmRollout::FleetStatus() const
{
    FleetCounts counts;
    for (const auto& item : m_observed) {
        const std::string& state = item.second;
        if (state == "HEALTHY") {
            ++counts.healthy;
        } else if (state == "UNHEALTHY") {
            ++counts.unhealthy;
        } else if (state == "UNKNOWN") {
            ++counts.unknown;
        }
    }
    return counts;
}

bool RealmRollout::AdvanceRing(const std::string& realm,
                               const std::string& frozen_policy_hash,
                               const std::string& current_policy_hash,
                               int unhealthy,
                               std::string& err)
{
    if (realm.empty()) {
        err = "BTX035_REALM";
        return false;
    }
    if (frozen_policy_hash.empty() || current_policy_hash.empty() || frozen_policy_hash != current_policy_hash) {
        err = "BTX035_POLICY";
        return false;
    }
    if (unhealthy != 0) {
        err = "BTX035_HEALTH";
        return false;
    }
    int64_t& generation = m_ring[realm];
    if (generation == std::numeric_limits<int64_t>::max()) {
        err = "BTX035_GAP";
        return false;
    }
    ++generation;
    err.clear();
    return true;
}

int64_t RealmRollout::RingGeneration(const std::string& realm) const
{
    const auto it = m_ring.find(realm);
    if (it == m_ring.end()) return 0;
    return it->second;
}

bool RealmRollout::ActivateOffline(int64_t bundle_generation, int64_t channel_sequence, std::string& err)
{
    m_offline = true;
    m_offline_bundle = bundle_generation;
    m_offline_channel = channel_sequence;
    err.clear();
    return true;
}

int64_t RealmRollout::OfflineBundleGeneration() const
{
    return m_offline_bundle;
}

int64_t RealmRollout::OfflineChannelSequence() const
{
    return m_offline_channel;
}

bool RealmRollout::OfflineRecorded() const
{
    return m_offline;
}

bool RealmRollout::AdvanceRingFromOffline(std::string& err) const
{
    err = "BTX035_OFFLINE";
    return false;
}

std::vector<RealmRollout::SavedRealm> RealmRollout::SavedRealms() const
{
    std::vector<SavedRealm> out;
    out.reserve(m_realms.size());
    for (const auto& item : m_realms) {
        SavedRealm row;
        row.key = item.first;
        row.policy = item.second.policy_set;
        row.threshold = item.second.threshold;
        row.pins.assign(item.second.pinned.begin(), item.second.pinned.end());
        row.revoked.assign(item.second.revoked.begin(), item.second.revoked.end());
        row.has_channel = item.second.has_channel;
        row.sequence = item.second.has_channel ? item.second.channel_sequence : static_cast<int64_t>(-1);
        row.body = item.second.has_channel ? item.second.body_hash : std::string();
        out.push_back(std::move(row));
    }
    return out;
}

bool RealmRollout::RestoreRealm(const SavedRealm& saved, std::string& err)
{
    if (saved.key.empty()) {
        err = "BTX035_REALM";
        return false;
    }
    if (saved.policy && saved.threshold < 1) {
        err = "BTX035_THRESHOLD";
        return false;
    }
    if (saved.has_channel && saved.sequence < 0) {
        err = "BTX035_ROLLBACK";
        return false;
    }
    RealmState& st = m_realms[saved.key];
    if (saved.policy) {
        st.policy_set = true;
        st.threshold = saved.threshold;
        st.pinned.clear();
        for (const std::string& id : saved.pins) {
            if (id.empty()) {
                err = "BTX035_POLICY";
                return false;
            }
            st.pinned.insert(id);
        }
        st.revoked.clear();
        for (const std::string& id : saved.revoked) {
            if (id.empty()) {
                err = "BTX035_POLICY";
                return false;
            }
            st.revoked.insert(id);
        }
    }
    if (saved.has_channel) {
        st.has_channel = true;
        st.channel_sequence = saved.sequence;
        st.body_hash = saved.body;
    }
    err.clear();
    return true;
}

std::vector<std::pair<std::string, std::string>> RealmRollout::SavedFleet() const
{
    return {m_observed.begin(), m_observed.end()};
}

std::vector<std::pair<std::string, std::string>> RealmRollout::SavedEndpoints() const
{
    return {m_endpoint_state.begin(), m_endpoint_state.end()};
}

std::vector<std::string> RealmRollout::StagedGenerations() const
{
    std::vector<std::pair<int64_t, std::string>> ordered;
    ordered.reserve(m_generations.size());
    for (const auto& item : m_generations) ordered.emplace_back(item.second.order, item.first);
    std::sort(ordered.begin(), ordered.end());
    std::vector<std::string> names;
    names.reserve(ordered.size());
    for (const auto& item : ordered) names.push_back(item.second);
    return names;
}

bool RealmRollout::RestoreGenerations(const std::vector<std::string>& ordered, const std::string& active, const std::string& previous, std::string& err)
{
    for (const std::string& name : ordered) {
        if (!StageGeneration(name, {}, err)) return false;
    }
    if (!active.empty() && m_generations.find(active) == m_generations.end()) {
        err = "BTX035_POLICY";
        return false;
    }
    if (!previous.empty() && m_generations.find(previous) == m_generations.end()) {
        err = "BTX035_POLICY";
        return false;
    }
    m_active_generation = active;
    m_previous_generation = previous;
    err.clear();
    return true;
}

bool RealmRollout::WriteOfflineBundle(const std::filesystem::path& path, const std::string& realm, std::string& err) const
{
    const auto it = m_realms.find(realm);
    if (realm.empty() || it == m_realms.end() || !it->second.policy_set || !SingleLine(realm)) {
        err = "BTX035_REALM";
        return false;
    }
    const RealmState& st = it->second;
    if (path.empty() || !SingleLine(st.body_hash)) {
        err = "BTX035_BUNDLE";
        return false;
    }
    for (const std::string& id : st.pinned) {
        if (id.empty() || !SingleLine(id)) {
            err = "BTX035_BUNDLE";
            return false;
        }
    }
    for (const std::string& id : st.revoked) {
        if (id.empty() || !SingleLine(id)) {
            err = "BTX035_BUNDLE";
            return false;
        }
    }

    int64_t sequence = st.has_channel ? st.channel_sequence : static_cast<int64_t>(-1);
    std::string body = st.has_channel ? st.body_hash : std::string();
    std::string channel_name;
    if (!st.has_channel) {
        const std::string prefix = realm + "\n";
        for (const auto& item : m_realms) {
            if (item.first.rfind(prefix, 0) != 0 || !item.second.has_channel) continue;
            if (!channel_name.empty()) {
                err = "BTX035_BUNDLE";
                return false;
            }
            channel_name = item.first.substr(prefix.size());
            sequence = item.second.channel_sequence;
            body = item.second.body_hash;
        }
    }
    if (!SingleLine(body) || !SingleLine(channel_name)) {
        err = "BTX035_BUNDLE";
        return false;
    }
    std::string text = "BTX035-OFFLINE-1\n";
    text += "realm=" + realm + "\n";
    text += "threshold=" + std::to_string(st.threshold) + "\n";
    text += "pinned=" + std::to_string(st.pinned.size()) + "\n";
    for (const std::string& id : st.pinned) text += id + "\n";
    text += "revoked=" + std::to_string(st.revoked.size()) + "\n";
    for (const std::string& id : st.revoked) text += id + "\n";
    text += "channel=" + std::to_string(sequence) + "\n";
    text += "body=" + body + "\n";
    if (!channel_name.empty()) text += "name=" + channel_name + "\n";

    std::ofstream out(path, std::ios::out | std::ios::trunc);
    if (!out) {
        err = "BTX035_BUNDLE";
        return false;
    }
    out << text;
    out.flush();
    if (!out) {
        err = "BTX035_BUNDLE";
        return false;
    }
    err.clear();
    return true;
}

bool RealmRollout::ReadOfflineBundle(const std::filesystem::path& path, const std::string& expected_realm, std::string& err)
{
    std::ifstream in(path, std::ios::in);
    if (!in) {
        err = "BTX035_BUNDLE";
        return false;
    }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        lines.push_back(std::move(line));
    }
    if (in.bad()) {
        err = "BTX035_BUNDLE";
        return false;
    }
    OfflineText parsed;
    if (!ParseOfflineText(lines, parsed)) {
        err = "BTX035_BUNDLE";
        return false;
    }
    if (expected_realm.empty() || parsed.realm != expected_realm) {
        err = "BTX035_REALM";
        return false;
    }

    RealmState st;
    st.policy_set = true;
    st.threshold = parsed.threshold;
    st.pinned = std::move(parsed.pinned);
    st.revoked = std::move(parsed.revoked);
    st.has_channel = parsed.has_channel && parsed.channel_name.empty();
    st.channel_sequence = st.has_channel ? parsed.channel_sequence : 0;
    st.body_hash = st.has_channel ? parsed.body_hash : std::string();
    m_realms[parsed.realm] = std::move(st);
    if (parsed.has_channel && !parsed.channel_name.empty()) {
        RealmState channel;
        channel.has_channel = true;
        channel.channel_sequence = parsed.channel_sequence;
        channel.body_hash = parsed.body_hash;
        m_realms[parsed.realm + "\n" + parsed.channel_name] = std::move(channel);
    }
    err.clear();
    return true;
}

bool RealmRollout::RestoreBackup(int64_t backup_sequence, int64_t current_sequence, std::string& err)
{
    if (!m_has_sequence) {
        m_current_sequence = current_sequence;
        m_has_sequence = true;
    } else if (current_sequence < m_current_sequence) {
        err = "BTX035_ROLLBACK";
        return false;
    }
    if (backup_sequence < current_sequence || backup_sequence < m_current_sequence) {
        err = "BTX035_ROLLBACK";
        return false;
    }
    m_current_sequence = backup_sequence;
    err.clear();
    return true;
}

int64_t RealmRollout::CurrentSequence() const
{
    return m_current_sequence;
}

bool RealmRollout::RecordPromotion(const std::string& source_exporter, const std::string& destination_approver, std::string& err)
{
    m_source_exporter = source_exporter;
    m_destination_approver = destination_approver;
    err.clear();
    return true;
}

bool RealmRollout::ApprovePromotion(std::string& err) const
{
    if (m_source_exporter.empty() || m_destination_approver.empty() || m_source_exporter == m_destination_approver) {
        err = "BTX035_AUTHORITY";
        return false;
    }
    err.clear();
    return true;
}

std::string RealmRollout::SourceExporter() const
{
    return m_source_exporter;
}

std::string RealmRollout::DestinationApprover() const
{
    return m_destination_approver;
}

bool RealmRollout::ObserveEndpoint(const std::string& endpoint, const std::string& state, std::string& err)
{
    if (endpoint.empty() || !EndpointLifecycleState(state)) {
        err = "BTX035_OBSERVE";
        return false;
    }
    m_endpoint_state[endpoint] = state;
    err.clear();
    return true;
}

std::string RealmRollout::EndpointState(const std::string& endpoint) const
{
    const auto it = m_endpoint_state.find(endpoint);
    if (it == m_endpoint_state.end()) return {};
    return it->second;
}

bool RealmRollout::MarkTransportComplete(const std::string& endpoint, const std::string& state, std::string& err)
{
    if (endpoint.empty() || !TransportCompletionState(state)) {
        err = "BTX035_OBSERVE";
        return false;
    }
    m_endpoint_state[endpoint] = state;
    err.clear();
    return true;
}

bool RealmRollout::MarkVerified(const std::string& endpoint, std::string& err)
{
    const auto it = m_endpoint_state.find(endpoint);
    if (endpoint.empty() || it == m_endpoint_state.end()) {
        err = "BTX035_OBSERVE";
        return false;
    }
    it->second = "VERIFIED";
    err.clear();
    return true;
}

bool RealmRollout::MarkActive(const std::string& endpoint, std::string& err)
{
    const auto it = m_endpoint_state.find(endpoint);
    if (it == m_endpoint_state.end() || (it->second != "VERIFIED" && it->second != "CANARY")) {
        err = "BTX035_HEALTH";
        return false;
    }
    it->second = "ACTIVE";
    err.clear();
    return true;
}

bool RealmRollout::StageGeneration(const std::string& directory_name, const std::filesystem::path& path, std::string& err)
{
    if (!GenerationNameOk(directory_name, err)) return false;
    const bool fresh = m_generations.find(directory_name) == m_generations.end();
    if (fresh && m_next_generation_order == std::numeric_limits<int64_t>::max()) {
        err = "BTX035_GAP";
        return false;
    }
    if (!path.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(path, ec);
        if (ec) {
            err = "BTX035_BUNDLE";
            return false;
        }
    }
    if (fresh) {
        GenerationState st;
        st.order = m_next_generation_order++;
        m_generations.emplace(directory_name, st);
    }
    err.clear();
    return true;
}

bool RealmRollout::ActivateGeneration(const std::string& directory_name, bool admission_ok, bool abi_ok, std::string& err)
{
    const auto next = m_generations.find(directory_name);
    if (directory_name.empty() || next == m_generations.end()) {
        err = "BTX035_POLICY";
        return false;
    }
    if (!m_active_generation.empty()) {
        const auto current = m_generations.find(m_active_generation);
        if (current != m_generations.end() && next->second.order < current->second.order) {
            err = "BTX035_ROLLBACK";
            return false;
        }
    }
    if (!admission_ok || !abi_ok) {
        err = "BTX035_HEALTH";
        return false;
    }
    if (directory_name != m_active_generation) {
        m_previous_generation = m_active_generation;
        m_active_generation = directory_name;
    }
    err.clear();
    return true;
}

bool RealmRollout::GenerationStaged(const std::string& directory_name) const
{
    return m_generations.find(directory_name) != m_generations.end();
}

std::string RealmRollout::ActiveGeneration() const
{
    return m_active_generation;
}

std::string RealmRollout::PreviousGeneration() const
{
    return m_previous_generation;
}

bool RealmRollout::RetainReader(const std::string& reader, const std::string& directory_name, std::string& err)
{
    if (reader.empty() || m_generations.find(directory_name) == m_generations.end()) {
        err = "BTX035_POLICY";
        return false;
    }
    for (auto& item : m_generation_readers) item.second.erase(reader);
    m_generation_readers[directory_name].insert(reader);
    err.clear();
    return true;
}

std::vector<std::string> RealmRollout::ReadersOf(const std::string& directory_name) const
{
    std::vector<std::string> out;
    const auto it = m_generation_readers.find(directory_name);
    if (it == m_generation_readers.end()) return out;
    out.assign(it->second.begin(), it->second.end());
    return out;
}

bool RealmRollout::ReplaceLocalSnapshot(const std::string& realm, int64_t snapshot_sequence, const std::string& body_hash, std::string& err)
{
    if (realm.empty()) {
        err = "BTX035_REALM";
        return false;
    }
    if (snapshot_sequence < 0) {
        err = "BTX035_ROLLBACK";
        return false;
    }
    const auto it = m_realms.find(realm);
    if (it != m_realms.end() && it->second.has_channel && snapshot_sequence < it->second.channel_sequence) {
        err = "BTX035_ROLLBACK";
        return false;
    }
    RealmState& st = m_realms[realm];
    st.has_channel = true;
    st.channel_sequence = snapshot_sequence;
    st.body_hash = body_hash;
    err.clear();
    return true;
}

std::string RealmRollout::FreezeTargetSet(const std::vector<std::string>& device_ids, std::string& err)
{
    std::set<std::string> ids;
    for (const std::string& id : device_ids) {
        if (id.empty() || !SingleLine(id)) {
            err = "BTX035_POLICY";
            return {};
        }
        ids.insert(id);
    }
    if (m_targets_frozen) {
        if (ids != m_frozen_targets) {
            err = "BTX035_POLICY";
            return {};
        }
        err.clear();
        return m_status_root;
    }
    m_frozen_targets = std::move(ids);
    m_status_root = TargetRoot(m_frozen_targets);
    m_targets_frozen = true;
    err.clear();
    return m_status_root;
}

std::string RealmRollout::StatusRoot() const
{
    return m_status_root;
}

bool RealmRollout::AddDevice(const std::string& device_id, std::string& err)
{
    if (!m_targets_frozen || device_id.empty() || !SingleLine(device_id)) {
        err = "BTX035_POLICY";
        return false;
    }
    if (m_frozen_targets.count(device_id) == 0) m_late_enrollment.insert(device_id);
    err.clear();
    return true;
}

std::vector<std::string> RealmRollout::LateEnrollment() const
{
    return std::vector<std::string>(m_late_enrollment.begin(), m_late_enrollment.end());
}

bool RealmRollout::FrozenTarget(const std::string& device_id) const
{
    return m_frozen_targets.count(device_id) != 0;
}

bool RealmRollout::WritePortableArchive(const std::filesystem::path& directory, const std::filesystem::path& destination, std::string& err) const
{
    std::error_code ec;
    const std::filesystem::file_status root = std::filesystem::symlink_status(directory, ec);
    if (ec) {
        err = "BTX035_BUNDLE";
        return false;
    }
    if (std::filesystem::is_symlink(root)) {
        err = "BTX035_PATH_UNSAFE";
        return false;
    }
    if (!std::filesystem::is_directory(root)) {
        err = "BTX035_BUNDLE";
        return false;
    }

    std::vector<ArchiveItem> items;
    if (!CollectArchive(directory, "", items, err)) return false;
    std::sort(items.begin(), items.end(), [](const ArchiveItem& a, const ArchiveItem& b) {
        return a.TarName() < b.TarName();
    });

    std::string manifest;
    uint64_t total = 0;
    for (const ArchiveItem& item : items) {
        if (!PortableRelative(item.rel) || !OctalFits(item.size, 12)) {
            err = item.size > kMaxUstarSize ? "BTX035_LIMIT_EXCEEDED" : "BTX035_PATH_UNSAFE";
            return false;
        }
        if (total > std::numeric_limits<uint64_t>::max() - item.size) {
            err = "BTX035_LIMIT_EXCEEDED";
            return false;
        }
        total += item.size;
        if (!manifest.empty()) manifest.push_back('\n');
        manifest += item.rel;
    }
    if (!items.empty()) manifest.push_back('\n');
    if (total > std::numeric_limits<uint64_t>::max() - manifest.size() || total + manifest.size() > kPortableArchiveBudget) {
        err = "BTX035_LIMIT_EXCEEDED";
        return false;
    }

    ArchiveItem manifest_item;
    manifest_item.rel = "manifest";
    manifest_item.bytes = manifest;
    manifest_item.size = manifest.size();
    manifest_item.synthetic = true;
    items.push_back(std::move(manifest_item));
    std::sort(items.begin(), items.end(), [](const ArchiveItem& a, const ArchiveItem& b) {
        return a.TarName() < b.TarName();
    });
    for (const ArchiveItem& item : items) {
        std::string tar_name;
        std::string tar_prefix;
        if (!SplitTarName(item.TarName(), tar_name, tar_prefix)) {
            err = "BTX035_BUNDLE";
            return false;
        }
        const std::string rebuilt = tar_prefix.empty() ? tar_name : tar_prefix + "/" + tar_name;
        if (rebuilt != item.TarName()) {
            err = "BTX035_BUNDLE";
            return false;
        }
    }

    std::ofstream out(destination, std::ios::binary | std::ios::trunc);
    if (!out) {
        err = "BTX035_BUNDLE";
        return false;
    }
    auto fail = [&](const char* code) {
        out.close();
        std::error_code ignore;
        std::filesystem::remove(destination, ignore);
        err = code;
        return false;
    };
    for (const ArchiveItem& item : items) {
        const char typeflag = item.directory ? '5' : '0';
        if (!WriteHeader(out, item.TarName(), typeflag, item.size) || !WriteItemBytes(out, item) || !WritePadding(out, item.size)) {
            return fail("BTX035_BUNDLE");
        }
    }
    std::array<char, kTarBlock * 2> zeros{};
    out.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
    out.flush();
    if (!out) return fail("BTX035_BUNDLE");
    err.clear();
    return true;
}

bool RealmRollout::ReadPortableArchive(const std::filesystem::path& archive, std::vector<std::string>& relative_paths, std::string& err) const
{
    relative_paths.clear();
    std::ifstream in(archive, std::ios::binary);
    if (!in) {
        err = "BTX035_BUNDLE";
        return false;
    }

    std::vector<std::string> payload;
    std::string manifest;
    bool saw_manifest = false;
    bool have_previous = false;
    std::string previous_name;
    uint64_t remaining = kPortableArchiveBudget;
    int zero_blocks = 0;

    while (zero_blocks < 2) {
        char header[kTarBlock];
        if (!ReadBlock(in, header, err)) return false;
        if (AllZero(header, kTarBlock)) {
            ++zero_blocks;
            continue;
        }
        if (zero_blocks != 0) {
            err = "BTX035_BUNDLE";
            return false;
        }

        uint64_t stored_sum = 0;
        if (!ParseOctal(header + 148, 8, stored_sum) || stored_sum != HeaderChecksum(header)) {
            err = "BTX035_BUNDLE";
            return false;
        }
        const char typeflag = header[156];
        if (typeflag != '0' && typeflag != '\0' && typeflag != '5') {
            err = "BTX035_PATH_UNSAFE";
            return false;
        }
        const std::string prefix = TarField(header + 345, 155);
        const std::string name = TarField(header, 100);
        const std::string full = prefix.empty() ? name : prefix + "/" + name;
        const std::string logical = LogicalTarPath(full);
        if (!PortableRelative(logical)) {
            err = "BTX035_PATH_UNSAFE";
            return false;
        }
        if (have_previous && full < previous_name) {
            err = "BTX035_BUNDLE";
            return false;
        }
        previous_name = full;
        have_previous = true;

        uint64_t size = 0;
        if (!ParseOctal(header + 124, 12, size)) {
            err = "BTX035_BUNDLE";
            return false;
        }
        if (typeflag == '5' && size != 0) {
            err = "BTX035_BUNDLE";
            return false;
        }
        if (size > remaining) {
            err = "BTX035_LIMIT_EXCEEDED";
            return false;
        }
        remaining -= size;

        const bool duplicate = logical == "manifest" ? saw_manifest : std::find(payload.begin(), payload.end(), logical) != payload.end();
        if (duplicate) {
            err = "BTX035_PATH_UNSAFE";
            return false;
        }

        std::string body;
        body.reserve(static_cast<std::size_t>(size));
        uint64_t left = size;
        while (left > 0) {
            char buf[8192];
            const std::size_t chunk = static_cast<std::size_t>(std::min<uint64_t>(left, sizeof(buf)));
            in.read(buf, static_cast<std::streamsize>(chunk));
            if (static_cast<std::size_t>(in.gcount()) != chunk) {
                err = "BTX035_BUNDLE";
                return false;
            }
            body.append(buf, chunk);
            left -= chunk;
        }
        const uint64_t pad = (kTarBlock - (size % kTarBlock)) % kTarBlock;
        if (pad != 0) {
            char junk[kTarBlock];
            in.read(junk, static_cast<std::streamsize>(pad));
            if (static_cast<std::size_t>(in.gcount()) != pad) {
                err = "BTX035_BUNDLE";
                return false;
            }
        }
        if (logical == "manifest") {
            if (typeflag == '5') {
                err = "BTX035_BUNDLE";
                return false;
            }
            manifest = std::move(body);
            saw_manifest = true;
        } else {
            payload.push_back(logical);
        }
    }

    if (!saw_manifest) {
        err = "BTX035_BUNDLE";
        return false;
    }
    std::vector<std::string> lines;
    if (!SplitManifest(manifest, lines, err)) return false;
    for (const std::string& line : lines) {
        if (!PortableRelative(line)) {
            err = "BTX035_PATH_UNSAFE";
            return false;
        }
    }
    if (lines != payload) {
        err = "BTX035_BUNDLE";
        return false;
    }
    relative_paths = std::move(payload);
    err.clear();
    return true;
}

bool BandwidthBudget::SetCaps(uint64_t global_bytes, uint64_t per_site_bytes, uint64_t per_device_bytes, std::string& err)
{
    m_global_cap = global_bytes;
    m_site_cap = per_site_bytes;
    m_device_cap = per_device_bytes;
    m_caps_set = true;
    err.clear();
    return true;
}

bool BandwidthBudget::SetDeploymentPaused(bool paused, std::string& err)
{
    m_paused = paused;
    err.clear();
    return true;
}

bool BandwidthBudget::WindowPaused() const
{
    return m_paused;
}

bool BandwidthBudget::AdmitFetch(const std::string& site, const std::string& device, uint64_t bytes, std::string& err)
{
    if (m_paused) {
        err = "BTX035_PAUSED";
        return false;
    }
    if (!m_caps_set) {
        err = "BTX035_LIMIT_EXCEEDED";
        return false;
    }
    uint64_t global_next = 0;
    uint64_t site_next = 0;
    uint64_t device_next = 0;
    const uint64_t site_current = LookupCounter(m_site, site);
    const uint64_t device_current = LookupCounter(m_device, device);
    if (!SumFits(m_global, bytes, m_global_cap, global_next) ||
        !SumFits(site_current, bytes, m_site_cap, site_next) ||
        !SumFits(device_current, bytes, m_device_cap, device_next)) {
        err = "BTX035_LIMIT_EXCEEDED";
        return false;
    }
    m_global = global_next;
    m_site[site] = site_next;
    m_device[device] = device_next;
    err.clear();
    return true;
}

uint64_t BandwidthBudget::AdmittedGlobal() const
{
    return m_global;
}

uint64_t BandwidthBudget::AdmittedSite(const std::string& site) const
{
    return LookupCounter(m_site, site);
}

uint64_t BandwidthBudget::AdmittedDevice(const std::string& device) const
{
    return LookupCounter(m_device, device);
}

} // namespace modelnet
