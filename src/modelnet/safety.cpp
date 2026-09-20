// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/safety.h>

#include <modelnet/types.h>
#include <util/strencodings.h>

#include <fstream>
#include <sstream>

namespace modelnet {
namespace {

bool Hex96(const std::string& s)
{
    if (s.size() != 96) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return false;
    }
    return true;
}

bool ReadJson(const fs::path& path, UniValue& out)
{
    std::ifstream in(path);
    if (!in) {
        out = UniValue(UniValue::VOBJ);
        return true;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    if (!out.read(ss.str()) || (!out.isObject() && !out.isArray())) {
        out = UniValue(UniValue::VOBJ);
        return false;
    }
    return true;
}

bool WriteJsonAtomic(const fs::path& path, const UniValue& obj, std::string& err)
{
    fs::create_directories(path.parent_path());
    const fs::path tmp = fs::PathFromString(fs::PathToString(path) + ".tmp");
    {
        std::ofstream out(tmp);
        if (!out) {
            err = "write safety";
            return false;
        }
        out << obj.write() << "\n";
        if (!out) {
            err = "write safety";
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        err = "rename safety";
        return false;
    }
    return true;
}

bool EndsUnsafe(const std::string& lower)
{
    static const char* ext[] = {
        ".pt", ".pth", ".pkl", ".py", ".so", ".bin", ".exe", ".dll", ".ipynb", ".cu", ".sig",
        ".bat", ".cmd", ".ps1", ".sh", ".dylib", ".wasm", ".class", ".jar", ".com", ".scr",
        ".msi", ".apk", ".dex", ".app", ".dmg", ".pkg", ".rpm", ".elf", ".ko",
    };
    for (const char* e : ext) {
        if (lower.ends_with(e)) return true;
    }
    return false;
}

bool InnerUnsafe(const std::string& lower)
{
    static const char* inner[] = {
        ".exe.", ".dll.", ".so.", ".dylib.", ".bat.", ".cmd.", ".ps1.", ".scr.", ".com.",
        ".msi.", ".apk.", ".jar.", ".wasm.", ".class.", ".elf.",
    };
    for (const char* e : inner) {
        if (lower.find(e) != std::string::npos) return true;
    }
    return false;
}

UniValue AdvisoryToJson(const SafetyRegistry::Advisory& a)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("publisher_id", a.publisher_id);
    o.pushKV("record_id", a.record_id);
    o.pushKV("target_id", a.target_id);
    o.pushKV("target_kind", a.target_kind);
    o.pushKV("severity", a.severity);
    o.pushKV("reason_code", a.reason_code);
    o.pushKV("content_sha384", a.content_sha384);
    o.pushKV("note", a.note);
    o.pushKV("expires_at", a.expires_at);
    o.pushKV("local", a.local);
    return o;
}

} // namespace

bool RelPathLooksUnsafe(const std::string& rel)
{
    const auto lower = ToLower(rel);
    if (lower.empty() || lower.starts_with(".") || lower.find("/.") != std::string::npos) return true;
    if (lower.find('\0') != std::string::npos) return true;
    if (lower.find("..") != std::string::npos || lower.find('\\') != std::string::npos) return true;
    if (EndsUnsafe(lower) || InnerUnsafe(lower)) return true;
    return false;
}

void SafetyRegistry::RebuildLocked(int64_t now)
{
    m_deny.clear();
    m_quarantine.clear();
    auto apply = [&](const Advisory& a) {
        if (a.expires_at && now > 0 && a.expires_at < now) return;
        m_deny.insert(a.target_id);
        m_quarantine.insert(a.target_id);
        if (Hex96(a.content_sha384) && a.content_sha384 != std::string(96, '0')) {
            m_deny.insert(a.content_sha384);
            m_quarantine.insert(a.content_sha384);
        }
    };
    for (const auto& a : m_advisories) apply(a);
}

void SafetyRegistry::LoadLocked()
{
    m_publishers.clear();
    m_advisories.clear();
    m_warnings.clear();
    m_deny.clear();
    m_quarantine.clear();
    if (m_dir.empty()) return;
    UniValue pubs;
    if (!ReadJson(m_dir / "safety_publishers.json", pubs)) {
        // Corrupt pin list: fail-closed (no remote auto-apply).
        pubs = UniValue(UniValue::VOBJ);
    }
    if (pubs.isObject() && pubs.exists("publishers") && pubs["publishers"].isArray()) {
        for (const auto& p : pubs["publishers"].getValues()) {
            if (!p.isObject() || !p.exists("id") || !p["id"].isStr()) continue;
            const std::string id = ToLower(p["id"].get_str());
            if (!Hex96(id)) continue;
            std::string label;
            if (p.exists("label") && p["label"].isStr()) label = p["label"].get_str();
            if (m_publishers.size() >= MAX_SAFETY_PUBLISHERS) break;
            m_publishers.emplace(id, label);
        }
    }
    UniValue ads;
    if (!ReadJson(m_dir / "safety_advisories.json", ads)) {
        ads = UniValue(UniValue::VOBJ);
    }
    auto load_list = [&](const char* key, std::vector<Advisory>& dest, size_t cap) {
        if (!ads.isObject() || !ads.exists(key) || !ads[key].isArray()) return;
        for (const auto& x : ads[key].getValues()) {
            if (!x.isObject() || dest.size() >= cap) break;
            if (!x.exists("target_id") || !x["target_id"].isStr()) continue;
            Advisory a;
            a.publisher_id = x.exists("publisher_id") && x["publisher_id"].isStr() ? ToLower(x["publisher_id"].get_str()) : "";
            a.record_id = x.exists("record_id") && x["record_id"].isStr() ? x["record_id"].get_str() : "";
            a.target_id = ToLower(x["target_id"].get_str());
            if (!Hex96(a.target_id)) continue;
            a.target_kind = x.exists("target_kind") ? static_cast<uint8_t>(x["target_kind"].getInt<int>()) : SAFETY_TARGET_MODEL;
            a.severity = x.exists("severity") ? static_cast<uint8_t>(x["severity"].getInt<int>()) : SAFETY_MALWARE;
            a.reason_code = x.exists("reason_code") ? static_cast<uint16_t>(x["reason_code"].getInt<int>()) : 0;
            a.content_sha384 = x.exists("content_sha384") && x["content_sha384"].isStr() ? ToLower(x["content_sha384"].get_str()) : std::string(96, '0');
            a.note = x.exists("note") && x["note"].isStr() ? x["note"].get_str() : "";
            a.expires_at = x.exists("expires_at") ? x["expires_at"].getInt<int64_t>() : 0;
            a.local = x.exists("local") && x["local"].isTrue();
            dest.push_back(std::move(a));
        }
    };
    load_list("advisories", m_advisories, MAX_SAFETY_ADVISORIES);
    load_list("warnings", m_warnings, MAX_SAFETY_WARNINGS);
    RebuildLocked(0);
}

bool SafetyRegistry::PersistLocked(std::string& err) const
{
    if (m_dir.empty()) return true;
    UniValue pubs(UniValue::VOBJ);
    UniValue parr(UniValue::VARR);
    for (const auto& [id, label] : m_publishers) {
        UniValue o(UniValue::VOBJ);
        o.pushKV("id", id);
        o.pushKV("label", label);
        parr.push_back(o);
    }
    pubs.pushKV("schema_version", 2);
    pubs.pushKV("automatic_spend_atoms", 0);
    pubs.pushKV("consensus", false);
    pubs.pushKV("publishers", parr);
    if (!WriteJsonAtomic(m_dir / "safety_publishers.json", pubs, err)) return false;
    UniValue ads(UniValue::VOBJ);
    UniValue aarr(UniValue::VARR);
    UniValue warr(UniValue::VARR);
    for (const auto& a : m_advisories) aarr.push_back(AdvisoryToJson(a));
    for (const auto& a : m_warnings) warr.push_back(AdvisoryToJson(a));
    ads.pushKV("schema_version", 2);
    ads.pushKV("advisories", aarr);
    ads.pushKV("warnings", warr);
    return WriteJsonAtomic(m_dir / "safety_advisories.json", ads, err);
}

void SafetyRegistry::Bind(const fs::path& helper_dir)
{
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_dir == helper_dir && !m_dir.empty()) return;
    m_dir = helper_dir;
    LoadLocked();
}

void SafetyRegistry::ResetForTests()
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_dir.clear();
    m_publishers.clear();
    m_advisories.clear();
    m_warnings.clear();
    m_deny.clear();
    m_quarantine.clear();
}

bool SafetyRegistry::PinPublisher(const std::string& publisher_id_hex, const std::string& label, std::string& err)
{
    const std::string id = ToLower(publisher_id_hex);
    if (!Hex96(id)) {
        err = "publisher_id";
        return false;
    }
    std::lock_guard<std::mutex> lock(m_mu);
    if (!m_publishers.count(id) && m_publishers.size() >= MAX_SAFETY_PUBLISHERS) {
        err = "too many safety publishers";
        return false;
    }
    m_publishers[id] = label.substr(0, 96);
    RebuildLocked(0);
    return PersistLocked(err);
}

bool SafetyRegistry::UnpinPublisher(const std::string& publisher_id_hex)
{
    const std::string id = ToLower(publisher_id_hex);
    std::lock_guard<std::mutex> lock(m_mu);
    const bool erased = m_publishers.erase(id) > 0;
    RebuildLocked(0);
    std::string err;
    (void)PersistLocked(err);
    return erased;
}

bool SafetyRegistry::PublisherPinned(const std::string& publisher_id_hex) const
{
    const std::string id = ToLower(publisher_id_hex);
    std::lock_guard<std::mutex> lock(m_mu);
    return m_publishers.count(id) > 0;
}

bool SafetyRegistry::LocalReport(const std::string& target_hex, uint8_t target_kind, uint8_t severity,
                                 const std::string& note, int64_t now, std::string& err)
{
    const std::string tid = ToLower(target_hex);
    if (!Hex96(tid)) {
        err = "target_id";
        return false;
    }
    if (target_kind != SAFETY_TARGET_MODEL && target_kind != SAFETY_TARGET_ARTIFACT &&
        target_kind != SAFETY_TARGET_DIGEST) {
        err = "target_kind";
        return false;
    }
    if (severity < SAFETY_MALWARE || severity > SAFETY_GARBAGE) {
        err = "severity";
        return false;
    }
    Advisory a;
    a.publisher_id = "local-operator";
    a.record_id = tid;
    a.target_id = tid;
    a.target_kind = target_kind;
    a.severity = severity;
    a.note = note.substr(0, 192);
    a.expires_at = now > 0 ? now + 30 * DAY_SECONDS : 0;
    a.local = true;
    a.content_sha384 = std::string(96, '0');
    std::lock_guard<std::mutex> lock(m_mu);
    for (auto& ex : m_advisories) {
        if (ex.local && ex.target_id == tid) {
            ex = a;
            RebuildLocked(now);
            return PersistLocked(err);
        }
    }
    if (m_advisories.size() >= MAX_SAFETY_ADVISORIES) {
        err = "advisory cap";
        return false;
    }
    m_advisories.push_back(std::move(a));
    RebuildLocked(now);
    return PersistLocked(err);
}

bool SafetyRegistry::IngestSigned(const UniValue& body, const std::string& signer_id, const std::string& record_id,
                                  int64_t now, bool& applied, std::string& err)
{
    applied = false;
    if (!body.isObject() || !body.exists("target_id") || !body["target_id"].isStr()) {
        err = "advisory shape";
        return false;
    }
    const std::string sid = ToLower(signer_id);
    if (sid == "local-operator") {
        err = "reserved signer";
        return false;
    }
    Advisory a;
    a.publisher_id = sid;
    a.record_id = record_id;
    a.target_id = ToLower(body["target_id"].get_str());
    if (!Hex96(a.target_id)) {
        err = "target_id";
        return false;
    }
    a.target_kind = body.exists("target_kind") ? static_cast<uint8_t>(body["target_kind"].getInt<int>()) : SAFETY_TARGET_MODEL;
    a.severity = body.exists("severity") ? static_cast<uint8_t>(body["severity"].getInt<int>()) : SAFETY_MALWARE;
    a.reason_code = body.exists("reason_code") ? static_cast<uint16_t>(body["reason_code"].getInt<int>()) : 0;
    a.content_sha384 = body.exists("content_sha384") && body["content_sha384"].isStr()
                           ? ToLower(body["content_sha384"].get_str())
                           : std::string(96, '0');
    a.note = body.exists("note") && body["note"].isStr() ? body["note"].get_str().substr(0, 192) : "";
    a.expires_at = body.exists("expires_at") ? body["expires_at"].getInt<int64_t>() : 0;
    a.local = false;
    std::lock_guard<std::mutex> lock(m_mu);
    const bool pinned = m_publishers.count(sid) > 0;
    auto& dest = pinned ? m_advisories : m_warnings;
    const size_t cap = pinned ? MAX_SAFETY_ADVISORIES : MAX_SAFETY_WARNINGS;
    for (const auto& ex : dest) {
        if (!record_id.empty() && ex.record_id == record_id) {
            applied = pinned;
            return true;
        }
    }
    if (dest.size() >= cap) dest.erase(dest.begin());
    dest.push_back(std::move(a));
    if (pinned) {
        RebuildLocked(now);
        applied = true;
    }
    return PersistLocked(err);
}

bool SafetyRegistry::SubjectBlocked(const std::string& hex_id) const
{
    const std::string id = ToLower(hex_id);
    std::lock_guard<std::mutex> lock(m_mu);
    return m_deny.count(id) > 0;
}

bool SafetyRegistry::SubjectQuarantined(const std::string& hex_id) const
{
    const std::string id = ToLower(hex_id);
    std::lock_guard<std::mutex> lock(m_mu);
    return m_quarantine.count(id) > 0;
}

UniValue SafetyRegistry::PublishersJson() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("consensus", false);
    UniValue arr(UniValue::VARR);
    for (const auto& [id, label] : m_publishers) {
        UniValue p(UniValue::VOBJ);
        p.pushKV("id", id);
        p.pushKV("label", label);
        arr.push_back(p);
    }
    o.pushKV("publishers", arr);
    o.pushKV("note", "operator-pinned safety publishers; unsigned gossip is stored as warnings only");
    return o;
}

UniValue SafetyRegistry::AdvisoriesJson(int64_t now) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    UniValue arr(UniValue::VARR);
    for (const auto& a : m_advisories) {
        if (a.expires_at && now > 0 && a.expires_at < now) continue;
        arr.push_back(AdvisoryToJson(a));
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("advisories", arr);
    return o;
}

UniValue SafetyRegistry::WarningsJson(int64_t now) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    UniValue arr(UniValue::VARR);
    for (const auto& a : m_warnings) {
        if (a.expires_at && now > 0 && a.expires_at < now) continue;
        arr.push_back(AdvisoryToJson(a));
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("warnings", arr);
    o.pushKV("automatic_deny", false);
    return o;
}

SafetyRegistry& GlobalSafety()
{
    static SafetyRegistry g;
    return g;
}

void EnsureSafetyBound(const fs::path& helper_dir)
{
    GlobalSafety().Bind(helper_dir);
}

} // namespace modelnet
