// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/package_install.h>

#include <modelnet/package_core.h>
#include <modelnet/package_pjson.h>
#include <crypto/common.h>
#include <crypto/hex_base.h>
#include <crypto/sha384.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <set>
#include <string>
#include <vector>

namespace modelnet {
namespace {

bool Fail(InstallPlan& out, std::string& err_code, std::string& err, const char* code, const std::string& msg,
          bool trust_required = true)
{
    out = {};
    out.trust_required = trust_required;
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

bool DigestOf(const char* domain, const UniValue& obj, Digest48& out, std::string& err)
{
    std::vector<unsigned char> c;
    if (!EncodePjson1(obj, c, err)) return false;
    std::vector<unsigned char> pre;
    pre.insert(pre.end(), domain, domain + std::strlen(domain));
    pre.push_back(0);
    unsigned char lenle[8];
    WriteLE64(lenle, c.size());
    pre.insert(pre.end(), lenle, lenle + 8);
    pre.insert(pre.end(), c.begin(), c.end());
    CSHA384 hasher;
    hasher.Write(pre.data(), pre.size());
    hasher.Finalize(out.data.data());
    return true;
}

const UniValue& UnwrapCore(const UniValue& in)
{
    if (in.isObject() && in.exists("core") && in["core"].isObject() && !in.exists("agent_handoff")) {
        return in["core"];
    }
    return in;
}

bool ValidToken(const std::string& s, size_t max_len)
{
    if (s.empty() || s.size() > max_len) return false;
    const auto first = static_cast<unsigned char>(s[0]);
    if (!std::isalnum(first)) return false;
    return std::all_of(s.begin() + 1, s.end(), [](char ch) {
        const auto c = static_cast<unsigned char>(ch);
        return std::isalnum(c) || c == '_' || c == '.' || c == '-';
    });
}

bool ValidDecStr(const std::string& s)
{
    if (s.empty() || s.size() > 20) return false;
    if (s == "0") return true;
    if (s[0] == '0') return false;
    return std::all_of(s.begin(), s.end(), [](char ch) { return ch >= '0' && ch <= '9'; });
}

bool ValidHex96(const std::string& s)
{
    Digest48 tmp;
    std::string hex_err;
    return Digest48::FromHex(s, tmp, hex_err);
}

bool GetStr(const UniValue& o, const char* key, std::string& out)
{
    if (!o.isObject() || !o.exists(key)) return false;
    if (o[key].isStr()) {
        out = o[key].get_str();
        return true;
    }
    if (o[key].isNum()) {
        out = o[key].getValStr();
        return true;
    }
    return false;
}

std::string Sha384Hex(const std::string& bytes)
{
    CSHA384 h;
    h.Write(reinterpret_cast<const unsigned char*>(bytes.data()), bytes.size());
    unsigned char d[48];
    h.Finalize(d);
    return HexStr(Span<const unsigned char>{d, 48});
}

bool CatalogueEmpty(const UniValue& cat)
{
    if (cat.isNull()) return true;
    if (cat.isArray()) return cat.empty();
    if (!cat.isObject()) return true;
    if (cat.exists("releases")) {
        return !cat["releases"].isArray() || cat["releases"].empty();
    }
    if (cat.exists("entries")) {
        return !cat["entries"].isArray() || cat["entries"].empty();
    }
    if (cat.exists("artifact_sha384") || cat.exists("capabilities") || cat.exists("release_version") ||
        cat.exists("independent_trust_ref")) {
        return false;
    }
    return cat.empty();
}

void CollectReleases(const UniValue& cat, const UniValue*& parent, std::vector<const UniValue*>& releases)
{
    parent = nullptr;
    releases.clear();
    if (cat.isArray()) {
        for (const auto& r : cat.getValues()) {
            if (r.isObject()) releases.push_back(&r);
        }
        return;
    }
    if (!cat.isObject()) return;
    parent = &cat;
    const UniValue* arr = nullptr;
    if (cat.exists("releases") && cat["releases"].isArray()) arr = &cat["releases"];
    else if (cat.exists("entries") && cat["entries"].isArray()) arr = &cat["entries"];
    if (arr) {
        for (const auto& r : arr->getValues()) {
            if (r.isObject()) releases.push_back(&r);
        }
        return;
    }
    releases.push_back(&cat);
}

bool CopyDownloadHosts(const UniValue& src, UniValue& out_hosts)
{
    out_hosts = UniValue(UniValue::VARR);
    if (!src.isArray() || src.empty() || src.size() > 8) return false;
    for (const auto& h : src.getValues()) {
        if (!h.isStr()) return false;
        const std::string& s = h.get_str();
        if (s.empty() || s.size() > 253) return false;
        out_hosts.push_back(s);
    }
    return !out_hosts.empty();
}

bool HasRequiredCapabilities(const UniValue& release, const std::vector<std::string>& required)
{
    const UniValue* caps = nullptr;
    if (release.exists("capabilities") && release["capabilities"].isArray()) {
        caps = &release["capabilities"];
    } else if (release.exists("required_capabilities") && release["required_capabilities"].isArray()) {
        caps = &release["required_capabilities"];
    }
    if (!caps) return false;
    std::set<std::string> have;
    for (const auto& c : caps->getValues()) {
        if (c.isStr()) have.insert(c.get_str());
    }
    for (const auto& need : required) {
        if (!have.count(need)) return false;
    }
    return true;
}

bool ParseDottedVersion(const std::string& s, std::vector<int>& parts)
{
    parts.clear();
    if (s.empty()) return false;
    size_t i = 0;
    while (i < s.size()) {
        if (s[i] < '0' || s[i] > '9') return false;
        int n = 0;
        while (i < s.size() && s[i] >= '0' && s[i] <= '9') {
            n = n * 10 + (s[i] - '0');
            ++i;
        }
        parts.push_back(n);
        if (i >= s.size()) break;
        if (s[i] == '.') {
            ++i;
            continue;
        }
        break;
    }
    return !parts.empty();
}

int CompareDottedVersion(const std::string& a, const std::string& b)
{
    std::vector<int> pa, pb;
    if (!ParseDottedVersion(a, pa) || !ParseDottedVersion(b, pb)) return 0;
    const size_t n = std::max(pa.size(), pb.size());
    pa.resize(n, 0);
    pb.resize(n, 0);
    if (pa < pb) return -1;
    if (pa > pb) return 1;
    return 0;
}

bool SystemInstallPath(const std::string& p)
{
    if (p.find("btxd.real") != std::string::npos) return true;
    if (p == "/usr" || p == "/bin" || p == "/sbin" || p == "/etc" || p == "/opt") return true;
    static const char* prefixes[] = {"/usr/", "/bin/", "/sbin/", "/etc/", "/lib/", "/lib64/"};
    for (const char* pre : prefixes) {
        if (p.rfind(pre, 0) == 0) return true;
    }
    return false;
}

} // namespace

bool PlanBtxClientInstall(const UniValue& core, const UniValue& trusted_catalogue, const UniValue& user_policy,
                          InstallPlan& out, std::string& err_code, std::string& err)
{
    out = {};
    out.trust_required = true;
    err_code.clear();
    err.clear();

    const UniValue& core_obj = UnwrapCore(core);
    if (!core_obj.isObject()) {
        return Fail(out, err_code, err, "NONCANONICAL_PAYLOAD", "core object");
    }

    // Spec §8.1–8.2: a package cannot appoint its own installer key. A binary
    // URL+hash carried only in the same descriptor is not independent trust.
    // Those package fields are never read as a catalogue.
    if (user_policy.isObject() && user_policy.exists("trust_package_hashes") &&
        user_policy["trust_package_hashes"].isTrue()) {
        return Fail(out, err_code, err, "CLIENT_TRUST_REQUIRED", "TRUST_REQUIRED", true);
    }
    if (CatalogueEmpty(trusted_catalogue)) {
        return Fail(out, err_code, err, "CLIENT_TRUST_REQUIRED", "TRUST_REQUIRED", true);
    }
    // Passing the package core (or any object that names an installer key /
    // software_trust_root / agent_handoff) as the "trusted catalogue" is the
    // AHP appoint-own-key path. Independent catalogue only.
    if (trusted_catalogue.isObject() &&
        (trusted_catalogue.exists("agent_handoff") || trusted_catalogue.exists("software_trust_root") ||
         trusted_catalogue.exists("installer_key") || trusted_catalogue.exists("installer_url") ||
         trusted_catalogue.exists("installer_sha384"))) {
        return Fail(out, err_code, err, "CLIENT_TRUST_REQUIRED", "TRUST_REQUIRED", true);
    }

    if (!core_obj.exists("agent_handoff") || !core_obj["agent_handoff"].isObject()) {
        return Fail(out, err_code, err, "CLIENT_TARGET_UNSUPPORTED", "agent_handoff", false);
    }
    const UniValue& handoff = core_obj["agent_handoff"];
    if (!handoff.exists("client_requirements") || !handoff["client_requirements"].isObject()) {
        return Fail(out, err_code, err, "CLIENT_TARGET_UNSUPPORTED", "client_requirements", false);
    }
    const UniValue& req = handoff["client_requirements"];

    std::string distribution_id;
    if (!GetStr(req, "distribution_id", distribution_id) || !ValidToken(distribution_id, 64)) {
        return Fail(out, err_code, err, "CLIENT_TARGET_UNSUPPORTED", "distribution_id", false);
    }
    if (!req.exists("required_capabilities") || !req["required_capabilities"].isArray() ||
        req["required_capabilities"].empty()) {
        return Fail(out, err_code, err, "CLIENT_TARGET_UNSUPPORTED", "required_capabilities", false);
    }
    std::vector<std::string> required_caps;
    for (const auto& c : req["required_capabilities"].getValues()) {
        if (!c.isStr() || !ValidToken(c.get_str(), 64)) {
            return Fail(out, err_code, err, "CLIENT_TARGET_UNSUPPORTED", "capability", false);
        }
        required_caps.push_back(c.get_str());
    }
    std::string min_version;
    GetStr(req, "minimum_client_version", min_version);

    std::string network;
    if (!GetStr(core_obj, "network", network) ||
        (network != "MAINNET" && network != "TESTNET" && network != "REGTEST")) {
        return Fail(out, err_code, err, "NONCANONICAL_PAYLOAD", "network");
    }
    if (!PackageCoreId(core_obj, out.package_core_id, err)) {
        err_code = "UNSUPPORTED_CORE_VERSION";
        out.trust_required = true;
        return false;
    }

    std::string want_platform;
    GetStr(user_policy, "platform", want_platform);

    const UniValue* cat_parent = nullptr;
    std::vector<const UniValue*> releases;
    CollectReleases(trusted_catalogue, cat_parent, releases);

    std::string cat_distro, cat_trust;
    if (cat_parent) {
        GetStr(*cat_parent, "distribution_id", cat_distro);
        GetStr(*cat_parent, "independent_trust_ref", cat_trust);
    }

    const UniValue* chosen = nullptr;
    bool saw_trusted_metadata = false;
    for (const UniValue* rel : releases) {
        std::string dist = cat_distro;
        GetStr(*rel, "distribution_id", dist);
        if (dist != distribution_id) continue;

        std::string plat;
        GetStr(*rel, "platform", plat);
        if (!plat.empty() && !want_platform.empty() && plat != want_platform) continue;

        std::string art, sz, ver, trust, meta_id;
        GetStr(*rel, "artifact_sha384", art);
        GetStr(*rel, "artifact_size_bytes", sz);
        GetStr(*rel, "release_version", ver);
        trust = cat_trust;
        GetStr(*rel, "independent_trust_ref", trust);
        GetStr(*rel, "verified_release_metadata_id", meta_id);
        UniValue hosts(UniValue::VARR);
        const bool hosts_ok =
            rel->exists("download_hosts") ? CopyDownloadHosts((*rel)["download_hosts"], hosts) :
            (cat_parent && cat_parent->exists("download_hosts") && CopyDownloadHosts((*cat_parent)["download_hosts"], hosts));
        if (!ValidHex96(art) || !ValidDecStr(sz) || ver.empty() || trust.empty() || !ValidHex96(meta_id) || !hosts_ok) {
            continue;
        }
        saw_trusted_metadata = true;

        // Capabilities — not version strings — decide feature support (§7, §8).
        if (!HasRequiredCapabilities(*rel, required_caps)) continue;
        if (!min_version.empty() && CompareDottedVersion(ver, min_version) < 0) continue;
        if (want_platform.empty() && plat.empty()) continue;
        if (!want_platform.empty() && plat.empty()) continue;

        chosen = rel;
        break;
    }

    if (!chosen) {
        if (!saw_trusted_metadata) {
            return Fail(out, err_code, err, "CLIENT_TRUST_REQUIRED", "TRUST_REQUIRED", true);
        }
        return Fail(out, err_code, err, "CLIENT_TARGET_UNSUPPORTED", "no capable trusted release", false);
    }

    std::string release_version, platform, artifact, size_bytes, trust_ref, meta_id;
    GetStr(*chosen, "release_version", release_version);
    GetStr(*chosen, "platform", platform);
    GetStr(*chosen, "artifact_sha384", artifact);
    GetStr(*chosen, "artifact_size_bytes", size_bytes);
    trust_ref = cat_trust;
    GetStr(*chosen, "independent_trust_ref", trust_ref);
    GetStr(*chosen, "verified_release_metadata_id", meta_id);
    if (platform.empty()) platform = want_platform;

    std::string candidate_hash, candidate_size;
    if (user_policy.isObject()) {
        GetStr(user_policy, "candidate_artifact_sha384", candidate_hash);
        if (candidate_hash.empty()) GetStr(user_policy, "offered_artifact_sha384", candidate_hash);
        GetStr(user_policy, "candidate_artifact_size_bytes", candidate_size);
        if (candidate_size.empty()) GetStr(user_policy, "offered_artifact_size_bytes", candidate_size);
        if (user_policy.exists("served_bytes") && user_policy["served_bytes"].isStr()) {
            const std::string& bytes = user_policy["served_bytes"].get_str();
            candidate_hash = Sha384Hex(bytes);
            candidate_size = std::to_string(bytes.size());
        }
    }
    if (!candidate_hash.empty() && candidate_hash != artifact) {
        return Fail(out, err_code, err, "ARTIFACT_DIGEST_MISMATCH", "served digest != trusted metadata", true);
    }
    if (!candidate_size.empty() && candidate_size != size_bytes) {
        return Fail(out, err_code, err, "ARTIFACT_DIGEST_MISMATCH", "served size != trusted metadata", true);
    }

    std::string privileges{"USER_ONLY"};
    GetStr(user_policy, "privileges", privileges);
    if (privileges.empty()) privileges = "USER_ONLY";
    if (privileges != "USER_ONLY") {
        return Fail(out, err_code, err, "INSTALL_APPROVAL_REQUIRED", "default plan is USER_ONLY", true);
    }

    std::string install_dir;
    GetStr(user_policy, "installation_directory", install_dir);
    if (install_dir.empty()) install_dir = "user-local/btx-model-tools";
    if (install_dir.size() > 4096 || SystemInstallPath(install_dir)) {
        return Fail(out, err_code, err, "INSTALL_APPROVAL_REQUIRED", "refusing system/production path", true);
    }

    std::string expires;
    GetStr(user_policy, "expires_at_ms", expires);
    if (expires.empty() && cat_parent) GetStr(*cat_parent, "expires_at_ms", expires);
    if (expires.empty()) GetStr(*chosen, "expires_at_ms", expires);
    if (!ValidDecStr(expires)) {
        return Fail(out, err_code, err, "INVALID_INSTALL_POLICY", "expires_at_ms", true);
    }

    std::string floor;
    GetStr(user_policy, "local_floor_version", floor);
    if (!floor.empty() && CompareDottedVersion(release_version, floor) < 0) {
        const bool recovery = user_policy.exists("authorized_recovery") && user_policy["authorized_recovery"].isTrue();
        if (!recovery) {
            return Fail(out, err_code, err, "INSTALL_ROLLBACK_FORBIDDEN", "release below local floor", true);
        }
    }
    std::string now_ms;
    GetStr(user_policy, "now_ms", now_ms);
    if (!now_ms.empty() && ValidDecStr(now_ms)) {
        const int cmp = (expires.size() != now_ms.size()) ? (expires.size() < now_ms.size() ? -1 : 1) :
                         (expires < now_ms ? -1 : (expires > now_ms ? 1 : 0));
        if (cmp < 0) {
            return Fail(out, err_code, err, "INSTALL_METADATA_EXPIRED", "release metadata expired", true);
        }
    }

    bool reused = false;
    if (user_policy.exists("installed_client") && user_policy["installed_client"].isObject()) {
        const UniValue& inst = user_policy["installed_client"];
        std::string inst_dist, inst_hash, inst_ver;
        GetStr(inst, "distribution_id", inst_dist);
        GetStr(inst, "artifact_sha384", inst_hash);
        GetStr(inst, "release_version", inst_ver);
        if (inst_hash == artifact && (inst_dist.empty() || inst_dist == distribution_id) &&
            (inst_ver.empty() || min_version.empty() || CompareDottedVersion(inst_ver, min_version) >= 0)) {
            reused = true;
        }
    }
    bool offline = false;
    if (user_policy.exists("offline_cache")) {
        std::string cached;
        if (user_policy["offline_cache"].isObject()) {
            GetStr(user_policy["offline_cache"], "artifact_sha384", cached);
            if (cached.empty()) GetStr(user_policy["offline_cache"], "cached_artifact_sha384", cached);
        }
        GetStr(user_policy, "cached_artifact_sha384", cached);
        if (user_policy["offline_cache"].isTrue() || cached == artifact) {
            if (cached.empty() || cached == artifact) offline = true;
        }
    }

    UniValue hosts(UniValue::VARR);
    if (chosen->exists("download_hosts")) {
        CopyDownloadHosts((*chosen)["download_hosts"], hosts);
    } else if (cat_parent && cat_parent->exists("download_hosts")) {
        CopyDownloadHosts((*cat_parent)["download_hosts"], hosts);
    }

    UniValue body(UniValue::VOBJ);
    body.pushKV("schema_version", 1);
    body.pushKV("package_core_id", out.package_core_id.Hex());
    body.pushKV("network", network);
    body.pushKV("expires_at_ms", expires);
    body.pushKV("distribution_id", distribution_id);
    body.pushKV("release_version", release_version);
    body.pushKV("platform", platform);
    body.pushKV("artifact_sha384", artifact);
    body.pushKV("artifact_size_bytes", size_bytes);
    body.pushKV("independent_trust_ref", trust_ref);
    body.pushKV("verified_release_metadata_id", meta_id);
    body.pushKV("download_hosts", (reused || offline) ? UniValue(UniValue::VARR) : hosts);
    body.pushKV("installation_directory", install_dir);
    body.pushKV("privileges", "USER_ONLY");
    body.pushKV("reused_installed", reused);
    body.pushKV("network_required", !reused && !offline);
    if (offline) body.pushKV("offline_cache", true);

    Digest48 plan_id;
    if (!DigestOf("BTX/InstallPlan/v1", body, plan_id, err)) {
        err_code = "NONCANONICAL_PAYLOAD";
        return false;
    }

    out.plan_id_hex = plan_id.Hex();
    out.distribution_id = distribution_id;
    out.release_version = release_version;
    out.platform = platform;
    out.artifact_sha384_hex = artifact;
    out.trust_required = false;
    body.pushKV("plan_id", out.plan_id_hex);
    out.json = std::move(body);
    err_code.clear();
    err.clear();
    return true;
}

bool InstallArchiveEntryAllowed(const std::string& rel_path, bool is_symlink, bool is_duplicate_name, std::string& err)
{
    err.clear();
    if (is_symlink) {
        err = "symlink refused";
        return false;
    }
    if (is_duplicate_name) {
        err = "duplicate executable";
        return false;
    }
    if (rel_path.empty() || rel_path.size() > 256) {
        err = "path";
        return false;
    }
    if (rel_path.find("..") != std::string::npos || rel_path.find('\\') != std::string::npos ||
        rel_path.find('\0') != std::string::npos || rel_path.front() == '/' || rel_path.find("//") != std::string::npos) {
        err = "traversal";
        return false;
    }
    return true;
}

bool InstallStagingResumeOrPurge(const std::string& phase, bool stage_verified, bool& resume, bool& purge,
                                  std::string& err_code)
{
    resume = false;
    purge = false;
    err_code.clear();
    if (phase == "download" || phase == "promote") {
        if (!stage_verified) {
            purge = true;
            err_code = "STAGING_PURGED";
            return true;
        }
        resume = true;
        return true;
    }
    if (phase == "verify") {
        if (!stage_verified) {
            purge = true;
            err_code = "STAGING_PURGED";
            return true;
        }
        resume = true;
        return true;
    }
    err_code = "INVALID_INSTALL_POLICY";
    return false;
}

} // namespace modelnet
