// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/compute_economy.h>

#include <modelnet/bounty.h>
#include <modelnet/canonical_codec.h>
#include <modelnet/catalog.h>
#include <modelnet/identity.h>
#include <crypto/sha256.h>
#include <crypto/sha384.h>
#include <matmul/compute_passport.h>
#include <matmul/compute_profile.h>
#include <matmul/compute_qualification.h>
#include <univalue.h>
#include <util/fs_helpers.h>
#include <util/strencodings.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <fstream>
#include <limits>
#include <map>
#include <mutex>
#include <set>

namespace modelnet {
namespace {

std::string g_chain;
std::string g_qual_path;

int64_t WallMs()
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg;
    return false;
}

bool U64Field(const UniValue& o, const char* key, uint64_t& out, std::string& err)
{
    if (!o.exists(key) || !o[key].isNum()) {
        err = key;
        return false;
    }
    try {
        out = o[key].getInt<uint64_t>();
    } catch (...) {
        err = key;
        return false;
    }
    return true;
}

bool I64Field(const UniValue& o, const char* key, int64_t& out, std::string& err)
{
    if (!o.exists(key) || !o[key].isNum()) {
        err = key;
        return false;
    }
    out = o[key].getInt<int64_t>();
    if (out < 0) {
        err = key;
        return false;
    }
    return true;
}

const UniValue& Arg0(const UniValue& params)
{
    static const UniValue empty{UniValue::VOBJ};
    if (params.isArray() && !params.empty() && params[0].isObject()) return params[0];
    if (params.isObject()) return params;
    return empty;
}

/** A string field, or empty when it is absent or not a string. Stored records
 *  are iterated on every settlement, so a wrong type must not throw. */
std::string StrOf(const UniValue& o, const char* key)
{
    if (!o.isObject() || !o.exists(key) || !o[key].isStr()) return {};
    return o[key].get_str();
}

/** One stored record, as written and as listed, stays well under the 256 KiB
 *  helper reply cap so get/list of any record can always be answered. */
constexpr size_t kMaxRecordJsonBytes = 128 * 1024;

bool LowerHex(const std::string& s, size_t len)
{
    if (s.size() != len) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

bool HexKey(const std::string& hex)
{
    if (hex.size() != MLDSA44_PK * 2) return false;
    return ParseHex(hex).size() == MLDSA44_PK;
}

bool AddU64(uint64_t& acc, uint64_t v)
{
    if (acc > std::numeric_limits<uint64_t>::max() - v) return false;
    acc += v;
    return true;
}

bool CeilMulDiv(uint64_t a, uint64_t b, uint64_t d, uint64_t& out, std::string& err)
{
    if (d == 0) {
        err = "COMPUTE_RECORD_INVALID";
        return false;
    }
    const unsigned __int128 prod = static_cast<unsigned __int128>(a) * b;
    if (a != 0 && prod / a != b) {
        err = "COMPUTE_CREDIT_OVERFLOW";
        return false;
    }
    const unsigned __int128 q = (prod + static_cast<unsigned __int128>(d) - 1) / d;
    if (q > std::numeric_limits<uint64_t>::max()) {
        err = "COMPUTE_CREDIT_OVERFLOW";
        return false;
    }
    out = static_cast<uint64_t>(q);
    return true;
}

bool KnownJobClass(const std::string& c, bool regtest)
{
    static const char* k[] = {
        "INFERENCE_BATCH", "EMBEDDING_BATCH", "EVALUATION", "SYNTHETIC_DATA",
        "DISTILLATION", "FINE_TUNE_BATCH", "QUANTIZATION", "DATA_TRANSFORM", "OTHER",
    };
    for (const char* n : k) {
        if (c == n) return true;
    }
    return regtest && c == "REGTEST_DETERMINISTIC";
}

bool ProfileOk(const std::string& profile_id, const std::string& chain, std::string& err_code)
{
    std::string code;
    const pwc::WorkProfile* profile = pwc::FindWorkProfile(profile_id, chain == "regtest", code);
    if (!profile) {
        err_code = code.empty() ? "COMPUTE_PROFILE_UNKNOWN" : code;
        return false;
    }
    if (profile->test_only && chain != "regtest") {
        err_code = "COMPUTE_TEST_PROFILE_DISABLED";
        return false;
    }
    return true;
}

bool PolicyClosed(const UniValue& policy, std::string& err_code)
{
    if (!policy.isObject()) {
        err_code = "COMPUTE_RECORD_INVALID";
        return false;
    }
    for (const char* k : {"transferable", "cash_redeemable", "cross_agreement_credit", "carryover"}) {
        if (!policy.exists(k) || !policy[k].isBool() || policy[k].get_bool()) {
            err_code = "COMPUTE_RECORD_INVALID";
            return false;
        }
    }
    return true;
}

std::string DirName(const std::string& type)
{
    if (type == "ComputeOffer") return "offers";
    if (type == "ComputeAgreement") return "agreements";
    if (type == "ComputeJob") return "jobs";
    if (type == "ComputeJobResult") return "results";
    if (type == "ComputeReceipt") return "receipts";
    if (type == "ComputeAccessGrant") return "grants";
    return {};
}

class ComputeStore {
public:
    void Bind(const fs::path& dir, const std::string& chain)
    {
        if (m_ident_dir == dir && m_chain == chain && m_loaded && !m_corrupt) return;
        m_offers.clear();
        m_agreements.clear();
        m_jobs.clear();
        m_results.clear();
        m_receipts.clear();
        m_grants.clear();
        m_cancelled.clear();
        m_loaded = false;
        m_corrupt = false;
        m_dir = dir / "compute";
        m_ident_dir = dir;
        m_chain = chain;
        m_network = PwcNetworkId(chain);
        std::string err;
        Load(err);
    }

    bool Dispatch(const std::string& method, const UniValue& params, UniValue& result, std::string& err_code, std::string& err);

private:
    fs::path m_dir;
    fs::path m_ident_dir;
    std::string m_chain;
    NetworkId m_network{};
    std::map<std::string, SignedEnvelope> m_offers;
    std::map<std::string, SignedEnvelope> m_agreements;
    std::map<std::string, SignedEnvelope> m_jobs;
    std::map<std::string, SignedEnvelope> m_results;
    std::map<std::string, SignedEnvelope> m_receipts;
    std::map<std::string, SignedEnvelope> m_grants;
    std::set<std::string> m_cancelled;
    bool m_loaded{false};
    bool m_corrupt{false};

    std::map<std::string, SignedEnvelope>& MapFor(const std::string& type)
    {
        if (type == "ComputeOffer") return m_offers;
        if (type == "ComputeAgreement") return m_agreements;
        if (type == "ComputeJob") return m_jobs;
        if (type == "ComputeJobResult") return m_results;
        if (type == "ComputeReceipt") return m_receipts;
        return m_grants;
    }

    bool Load(std::string& err);
    bool WriteEnvelope(const SignedEnvelope& env, std::string& err);
    bool LoadIdentity(std::vector<unsigned char>& pk, std::vector<unsigned char>& sk, std::string& err) const;
    bool Sign(const std::string& type, const UniValue& payload, SignedEnvelope& env, std::string& err_code, std::string& err);
    bool Import(const UniValue& obj, const std::string& expect_type, SignedEnvelope& env, std::string& err_code, std::string& err);
    bool BalanceOf(const std::string& agreement_id, int64_t now_ms, UniValue& out, std::string& err_code, std::string& err);
};

ComputeStore& Store()
{
    static ComputeStore s;
    return s;
}

bool ComputeStore::LoadIdentity(std::vector<unsigned char>& pk, std::vector<unsigned char>& sk, std::string& err) const
{
    std::ifstream in(m_ident_dir / "research_identity.json");
    if (!in) {
        err = "COMPUTE_SIGNING_IDENTITY_REQUIRED";
        return false;
    }
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue store;
    if (!store.read(raw) || !store.exists("pk_hex") || !store.exists("sk_hex")) {
        err = "COMPUTE_SIGNING_IDENTITY_REQUIRED";
        return false;
    }
    pk = ParseHex(store["pk_hex"].get_str());
    sk = ParseHex(store["sk_hex"].get_str());
    if (pk.size() != MLDSA44_PK || sk.size() != MLDSA44_SK) {
        err = "COMPUTE_SIGNING_IDENTITY_REQUIRED";
        return false;
    }
    return true;
}

bool ComputeStore::WriteEnvelope(const SignedEnvelope& env, std::string& err)
{
    const std::string type = env.body["record_type"].get_str();
    const fs::path dir = m_dir / fs::PathFromString(DirName(type));
    fs::create_directories(dir);
    const fs::path dest = dir / fs::PathFromString(env.record_id.Hex() + ".json");
    const std::string bytes = EnvelopeToJson(env).write();
    if (bytes.size() > kMaxRecordJsonBytes) {
        err = "COMPUTE_RECORD_INVALID";
        return false;
    }
    if (fs::exists(dest)) {
        std::ifstream in(dest);
        std::string prev((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        UniValue old_json;
        SignedEnvelope old_env;
        std::string perr;
        std::vector<unsigned char> left, right;
        if (!old_json.read(prev) || !EnvelopeFromJson(old_json, old_env, perr) ||
            old_env.signature != env.signature ||
            !CanonicalEncode(old_env.body, left, perr) || !CanonicalEncode(env.body, right, perr) || left != right) {
            err = "COMPUTE_DUPLICATE_RECEIPT";
            return false;
        }
        return true;
    }
    const fs::path tmp = dir / fs::PathFromString(env.record_id.Hex() + ".json.tmp");
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            err = "COMPUTE_RECORD_INVALID";
            return false;
        }
        out << bytes << "\n";
    }
    if (!RenameOver(tmp, dest)) {
        err = "COMPUTE_RECORD_INVALID";
        return false;
    }
    return true;
}

bool ComputeStore::Load(std::string& err)
{
    if (m_loaded) return !m_corrupt;
    m_loaded = true;
    if (!fs::exists(m_dir)) return true;
    const char* types[] = {"ComputeOffer", "ComputeAgreement", "ComputeJob", "ComputeJobResult", "ComputeReceipt", "ComputeAccessGrant"};
    for (const char* type : types) {
        const fs::path dir = m_dir / fs::PathFromString(DirName(type));
        if (!fs::exists(dir)) continue;
        for (const auto& ent : fs::directory_iterator(dir)) {
            if (!ent.is_regular_file()) continue;
            if (ent.path().extension() != ".json") continue;
            std::ifstream in(ent.path());
            std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            UniValue obj;
            SignedEnvelope env;
            std::string verr;
            if (!obj.read(raw) || !EnvelopeFromJson(obj, env, verr) || !VerifySignedEnvelope(env, m_network, verr)) {
                m_corrupt = true;
                err = "COMPUTE_RECORD_INVALID";
                return false;
            }
            auto& map = MapFor(type);
            auto it = map.find(env.record_id.Hex());
            if (it != map.end() && EnvelopeToJson(it->second).write() != EnvelopeToJson(env).write()) {
                m_corrupt = true;
                err = "COMPUTE_DUPLICATE_RECEIPT";
                return false;
            }
            map[env.record_id.Hex()] = env;
        }
    }
    const fs::path cancel = m_dir / "cancelled.txt";
    if (fs::exists(cancel)) {
        std::ifstream in(cancel);
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty()) m_cancelled.insert(line);
        }
    }
    return true;
}

bool ComputeStore::Sign(const std::string& type, const UniValue& payload, SignedEnvelope& env, std::string& err_code, std::string& err)
{
    if (m_chain.empty()) return Fail(err_code, err, "COMPUTE_NETWORK_MISMATCH", "chain");
    if (m_corrupt) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "store");
    std::vector<unsigned char> pk, sk;
    if (!LoadIdentity(pk, sk, err)) return Fail(err_code, err, "COMPUTE_SIGNING_IDENTITY_REQUIRED", err);
    UniValue body = payload;
    if (body.exists("network_id") && body["network_id"].isStr() && body["network_id"].get_str() != m_network.Hex()) {
        return Fail(err_code, err, "COMPUTE_NETWORK_MISMATCH", "network");
    }
    if (!body.exists("network_id")) body.pushKV("network_id", m_network.Hex());
    if (body.exists("issuer_pubkey")) {
        if (!body["issuer_pubkey"].isStr() || body["issuer_pubkey"].get_str() != HexStr(pk)) {
            return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "issuer");
        }
    } else {
        body.pushKV("issuer_pubkey", HexStr(pk));
    }
    if (!BuildSignedEnvelope(type, m_network, pk, sk, body, UniValue(UniValue::VNULL), env, err)) {
        return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
    }
    return true;
}

bool ComputeStore::Import(const UniValue& obj, const std::string& expect_type, SignedEnvelope& env, std::string& err_code, std::string& err)
{
    if (m_corrupt) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "store");
    const UniValue rec = obj.exists("envelope") ? obj["envelope"] : obj;
    if (!EnvelopeFromJson(rec, env, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
    if (!VerifySignedEnvelope(env, m_network, err)) {
        if (err.find("network") != std::string::npos) return Fail(err_code, err, "COMPUTE_NETWORK_MISMATCH", err);
        return Fail(err_code, err, "COMPUTE_SIGNATURE_INVALID", err);
    }
    if (env.body["record_type"].get_str() != expect_type) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "type");
    const std::string id = env.record_id.Hex();
    auto& map = MapFor(expect_type);
    auto it = map.find(id);
    if (it != map.end()) {
        std::vector<unsigned char> left, right;
        std::string canon_err;
        if (it->second.signature != env.signature ||
            !CanonicalEncode(it->second.body, left, canon_err) ||
            !CanonicalEncode(env.body, right, canon_err) || left != right) {
            return Fail(err_code, err, "COMPUTE_DUPLICATE_RECEIPT", "bytes differ");
        }
        return true;
    }
    if (!WriteEnvelope(env, err)) return Fail(err_code, err, err.c_str(), err);
    map[id] = env;
    return true;
}

bool ValidOffer(const UniValue& p, const std::string& chain, std::string& err_code, std::string& err)
{
    uint64_t required = 0;
    if (!p.exists("settlement") || !p["settlement"].isObject()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "settlement");
    const UniValue& s = p["settlement"];
    if (!s.exists("profile_id") || !s["profile_id"].isStr()) return Fail(err_code, err, "COMPUTE_PROFILE_UNKNOWN", "profile");
    if (!ProfileOk(s["profile_id"].get_str(), chain, err_code)) return Fail(err_code, err, err_code.c_str(), "profile");
    if (!U64Field(s, "required_p1e_microunits", required, err) || required == 0) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "required");
    if (!s.exists("schedule") || (s["schedule"].get_str() != "PREPAID" && s["schedule"].get_str() != "PRO_RATA")) {
        return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "schedule");
    }
    if (!s.exists("allowed_settlement_modes") || !s["allowed_settlement_modes"].isArray() || s["allowed_settlement_modes"].empty()) {
        return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "modes");
    }
    for (const auto& m : s["allowed_settlement_modes"].getValues()) {
        if (!m.isStr() || (m.get_str() != "USEFUL_JOB_RECEIPTS" && m.get_str() != "DIRECT_COMPUTE")) {
            return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "mode");
        }
    }
    if (s.exists("allowed_job_classes")) {
        for (const auto& c : s["allowed_job_classes"].getValues()) {
            if (!c.isStr() || !KnownJobClass(c.get_str(), chain == "regtest")) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "job class");
        }
    }
    if (!p.exists("policy") || !PolicyClosed(p["policy"], err_code)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "policy");
    if (!p.exists("access") || !p["access"].isObject()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "access");
    int64_t period = 0;
    if (!I64Field(p["access"], "period_ms", period, err) || period <= 0) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "period");
    int64_t exp = 0;
    if (!I64Field(p, "expires_at_ms", exp, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "expiry");
    if (!p.exists("resource_ref") || !p["resource_ref"].isStr() || p["resource_ref"].get_str().empty()) {
        return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "resource");
    }
    return true;
}

const UniValue& PayloadOf(const SignedEnvelope& env)
{
    return env.body["payload"];
}

bool ComputeStore::BalanceOf(const std::string& agreement_id, int64_t now_ms, UniValue& out, std::string& err_code, std::string& err)
{
    auto ait = m_agreements.find(agreement_id);
    if (ait == m_agreements.end()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "agreement");
    const UniValue& p = PayloadOf(ait->second);
    const UniValue& s = p["settlement"];
    const uint64_t required = s["required_p1e_microunits"].getInt<uint64_t>();
    uint64_t credited = 0;
    std::vector<std::string> ids;
    std::set<std::string> settled_jobs;
    for (const auto& kv : m_receipts) {
        const UniValue& rp = PayloadOf(kv.second);
        // A field of the wrong type must skip this record. get_str() would throw
        // and stop the balance of every agreement on the node.
        if (StrOf(rp, "agreement_id") != agreement_id) continue;
        uint64_t credit = 0;
        if (!U64Field(rp, "credited_p1e_microunits", credit, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "credit");
        if (!AddU64(credited, credit)) return Fail(err_code, err, "COMPUTE_CREDIT_OVERFLOW", "sum");
        ids.push_back(kv.first);
        if (rp.exists("job_id") && rp["job_id"].isStr() && !rp["job_id"].get_str().empty()) settled_jobs.insert(rp["job_id"].get_str());
    }
    std::sort(ids.begin(), ids.end());
    std::string joined;
    for (const auto& id : ids) joined += id;
    unsigned char dig[48];
    CSHA384 h;
    const std::string tag = "BTX/ComputeReceiptSet/v1";
    h.Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size());
    h.Write(reinterpret_cast<const unsigned char*>(joined.data()), joined.size());
    h.Finalize(dig);
    uint64_t reserved = 0;
    for (const auto& kv : m_jobs) {
        const UniValue& jp = PayloadOf(kv.second);
        if (StrOf(jp, "agreement_id") != agreement_id) continue;
        if (settled_jobs.count(kv.first)) continue;
        int64_t exp = 0;
        if (!I64Field(jp, "expires_at_ms", exp, err)) continue;
        if (exp < now_ms) continue;
        uint64_t credit = 0;
        if (!U64Field(jp, "credit_p1e_microunits", credit, err)) continue;
        if (!AddU64(reserved, credit)) return Fail(err_code, err, "COMPUTE_CREDIT_OVERFLOW", "reserved");
    }
    const std::string schedule = s["schedule"].get_str();
    const int64_t start = p["period_start_ms"].getInt<int64_t>();
    const int64_t end = p["period_end_ms"].getInt<int64_t>();
    uint64_t due = 0;
    if (schedule == "PREPAID") {
        due = required;
    } else {
        const int64_t span = end - start;
        int64_t elapsed = now_ms - start;
        if (elapsed < 0) elapsed = 0;
        if (elapsed > span) elapsed = span;
        if (span > 0 && !CeilMulDiv(required, static_cast<uint64_t>(elapsed), static_cast<uint64_t>(span), due, err)) {
            return Fail(err_code, err, "COMPUTE_CREDIT_OVERFLOW", err);
        }
    }
    std::string status = "OPEN";
    if (m_cancelled.count(agreement_id)) status = "CANCELLED";
    else if (now_ms > end) status = "EXPIRED";
    else if (credited >= required) status = "SATISFIED";
    // due is 0 before the period starts; that is not standing, or repeated
    // 24h pro-rata grants would cover the time before the agreement begins.
    else if (schedule == "PRO_RATA" && now_ms >= start && credited >= due) status = "IN_GOOD_STANDING";
    UniValue o(UniValue::VOBJ);
    o.pushKV("agreement_id", agreement_id);
    o.pushKV("required_p1e_microunits", required);
    o.pushKV("credited_p1e_microunits", credited);
    o.pushKV("remaining_p1e_microunits", credited >= required ? 0 : required - credited);
    o.pushKV("excess_p1e_microunits", credited > required ? credited - required : 0);
    o.pushKV("due_now_p1e_microunits", due);
    o.pushKV("outstanding_reserved_p1e_microunits", reserved);
    o.pushKV("valid_receipt_count", static_cast<uint64_t>(ids.size()));
    o.pushKV("receipt_set_digest", HexStr(std::vector<unsigned char>(dig, dig + 48)));
    o.pushKV("status", status);
    o.pushKV("automatic_spend_atoms", 0);
    out = std::move(o);
    return true;
}

std::string SubjectDigestHex(const std::string& pubkey_hex)
{
    const auto pk = ParseHex(pubkey_hex);
    CSHA256 hasher;
    hasher.Write(pk.data(), pk.size());
    unsigned char out[32];
    hasher.Finalize(out);
    return HexStr(std::vector<unsigned char>(out, out + 32));
}

std::string SignerOf(const SignedEnvelope& env)
{
    if (!env.body.exists("public_key_hex") || !env.body["public_key_hex"].isStr()) return {};
    return env.body["public_key_hex"].get_str();
}

bool ConfirmRedeemedQualification(const UniValue& qual, const UniValue& settlement, const std::string& subject_pubkey,
                                  int64_t now_ms, uint32_t& episodes, std::string& err_code, std::string& err)
{
    episodes = 0;
    if (!qual.isObject() || !qual.exists("challenge_id") || !qual["challenge_id"].isStr()) {
        return Fail(err_code, err, "COMPUTE_QUALIFICATION_REQUIRED", "qualification");
    }
    if (g_qual_path.empty()) return Fail(err_code, err, "COMPUTE_QUALIFICATION_REQUIRED", "registry");
    pwc::QualificationRegistry reg;
    std::string open_err;
    if (!reg.Open(fs::PathFromString(g_qual_path), open_err)) {
        return Fail(err_code, err, "COMPUTE_CHALLENGE_INVALID", open_err);
    }
    UniValue st;
    if (!reg.Status(qual["challenge_id"].get_str(), now_ms, st, err_code, err)) return false;
    if (!st.exists("status") || st["status"].get_str() != "redeemed") {
        return Fail(err_code, err, "COMPUTE_QUALIFICATION_REQUIRED", "not redeemed");
    }
    if (!st.exists("profile_id") || st["profile_id"].get_str() != settlement["profile_id"].get_str()) {
        return Fail(err_code, err, "COMPUTE_PROFILE_MISMATCH", "qualification");
    }
    if (!st.exists("subject_digest") || st["subject_digest"].get_str() != SubjectDigestHex(subject_pubkey)) {
        return Fail(err_code, err, "COMPUTE_SUBJECT_MISMATCH", "qualification");
    }
    if (settlement.exists("max_qualification_age_ms")) {
        uint64_t max_age = 0;
        if (!U64Field(settlement, "max_qualification_age_ms", max_age, err)) {
            return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
        }
        const int64_t redeemed_at = st["redeemed_at_ms"].getInt<int64_t>();
        if (now_ms < redeemed_at || static_cast<uint64_t>(now_ms - redeemed_at) > max_age) {
            return Fail(err_code, err, "COMPUTE_QUALIFICATION_REQUIRED", "age");
        }
    }
    if (settlement.exists("optional_min_rate_p1e_microunits_per_hour")) {
        uint64_t min_rate = 0;
        if (!U64Field(settlement, "optional_min_rate_p1e_microunits_per_hour", min_rate, err)) {
            return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
        }
        const uint64_t rate = st["conservative_rate_p1e_microunits_per_hour"].getInt<uint64_t>();
        if (rate < min_rate) return Fail(err_code, err, "COMPUTE_RATE_TOO_LOW", "qualification");
    }
    episodes = static_cast<uint32_t>(st["episode_count"].getInt<int64_t>());
    return episodes > 0 || Fail(err_code, err, "COMPUTE_QUALIFICATION_REQUIRED", "episodes");
}

bool ContainsKey(const UniValue& arr, const std::string& key)
{
    if (!arr.isArray()) return false;
    for (const auto& v : arr.getValues()) {
        if (v.isStr() && v.get_str() == key) return true;
    }
    return false;
}

bool ComputeStore::Dispatch(const std::string& method, const UniValue& params, UniValue& result, std::string& err_code, std::string& err)
{
    if (m_chain.empty()) return Fail(err_code, err, "COMPUTE_NETWORK_MISMATCH", "chain");
    std::string lerr;
    if (!Load(lerr)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", lerr);
    const UniValue& a = Arg0(params);
    int64_t now_ms = WallMs();
    if (a.exists("now_ms")) {
        if (m_chain != "regtest") return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "now_ms");
        if (!I64Field(a, "now_ms", now_ms, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
    }

    if (method == "getcomputesigningidentity") {
        std::vector<unsigned char> pk, sk;
        if (!LoadIdentity(pk, sk, err)) return Fail(err_code, err, "COMPUTE_SIGNING_IDENTITY_REQUIRED", err);
        result = UniValue(UniValue::VOBJ);
        result.pushKV("public_key_hex", HexStr(pk));
        result.pushKV("signer_id", ResearchIdentityId(pk).Hex());
        result.pushKV("network_id", m_network.Hex());
        result.pushKV("chain", m_chain);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }

    if (method == "createcomputeoffer") {
        UniValue payload = a.exists("offer") ? a["offer"] : a;
        if (!ValidOffer(payload, m_chain, err_code, err)) return false;
        int64_t exp = payload["expires_at_ms"].getInt<int64_t>();
        if (exp <= now_ms) return Fail(err_code, err, "COMPUTE_OFFER_EXPIRED", "offer");
        SignedEnvelope env;
        if (!Sign("ComputeOffer", payload, env, err_code, err)) return false;
        if (!WriteEnvelope(env, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
        m_offers[env.record_id.Hex()] = env;
        result = EnvelopeToJson(env);
        result.pushKV("offer_id", env.record_id.Hex());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "importcomputeoffer") {
        // Validate before Import() writes the record, so a rejected offer is not stored.
        SignedEnvelope parsed;
        if (!EnvelopeFromJson(a.exists("envelope") ? a["envelope"] : a, parsed, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
        if (!ValidOffer(PayloadOf(parsed), m_chain, err_code, err)) return false;
        // The payload names its issuer. It must be the key that signed it, or a
        // listing shows another provider's name on this offer.
        if (StrOf(PayloadOf(parsed), "issuer_pubkey").empty() || StrOf(PayloadOf(parsed), "issuer_pubkey") != SignerOf(parsed)) {
            return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "issuer");
        }
        SignedEnvelope env;
        if (!Import(a, "ComputeOffer", env, err_code, err)) return false;
        result = EnvelopeToJson(env);
        result.pushKV("offer_id", env.record_id.Hex());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getcomputeoffer" || method == "getcomputeagreement" || method == "getcomputejob" ||
        method == "getcomputejobresult" || method == "getcomputereceipt" || method == "getcomputeaccessgrant") {
        const std::string id = (a.exists("id") && a["id"].isStr()) ? a["id"].get_str() : "";
        const std::map<std::string, SignedEnvelope>* map = &m_offers;
        if (method.find("agreement") != std::string::npos) map = &m_agreements;
        else if (method.find("jobresult") != std::string::npos) map = &m_results;
        else if (method.find("job") != std::string::npos) map = &m_jobs;
        else if (method.find("receipt") != std::string::npos) map = &m_receipts;
        else if (method.find("grant") != std::string::npos) map = &m_grants;
        auto it = map->find(id);
        if (it == map->end()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "missing");
        result = EnvelopeToJson(it->second);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    // btxd reads at most 256 KiB (MAX_RPC_BODY) of a helper reply and one signed
    // record is ~14 KB, so listings page by size from "start" and report next_start.
    auto list_page = [&](const std::map<std::string, SignedEnvelope>& map, const std::string* resource_ref) {
        uint64_t start = 0;
        if (a.exists("start") && !U64Field(a, "start", start, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "start");
        constexpr size_t kPageBytes = 192 * 1024;
        UniValue arr(UniValue::VARR);
        size_t used = 0;
        uint64_t index = 0;
        bool more = false;
        for (const auto& kv : map) {
            if (resource_ref && StrOf(PayloadOf(kv.second), "resource_ref") != *resource_ref) continue;
            if (index++ < start) continue;
            UniValue row = EnvelopeToJson(kv.second);
            if (!resource_ref) row.pushKV("id", kv.first);
            const size_t bytes = row.write().size();
            if (!arr.empty() && used + bytes > kPageBytes) {
                more = true;
                break;
            }
            used += bytes;
            arr.push_back(row);
        }
        result = UniValue(UniValue::VOBJ);
        result.pushKV("records", arr);
        if (more) result.pushKV("next_start", start + arr.size());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    };
    if (method == "listcomputeoffers" || method == "listcomputeagreements" || method == "listcomputejobs" || method == "listcomputereceipts") {
        const std::map<std::string, SignedEnvelope>* map = &m_offers;
        if (method.find("agreement") != std::string::npos) map = &m_agreements;
        else if (method.find("job") != std::string::npos) map = &m_jobs;
        else if (method.find("receipt") != std::string::npos) map = &m_receipts;
        return list_page(*map, nullptr);
    }
    if (method == "getcomputeoffersforresource") {
        if (a.exists("resource_ref") && !a["resource_ref"].isStr()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "resource");
        const std::string ref = a.exists("resource_ref") ? a["resource_ref"].get_str() : "";
        return list_page(m_offers, &ref);
    }
    if (method == "quotecomputeaccess") {
        UniValue offer_copy;
        if (a.exists("offer") && a["offer"].isObject()) {
            offer_copy = a["offer"];
        } else if (a.exists("offer_id")) {
            auto it = m_offers.find(a["offer_id"].get_str());
            if (it == m_offers.end()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "offer");
            offer_copy = PayloadOf(it->second);
        } else {
            offer_copy = a;
        }
        const UniValue& offer = offer_copy;
        const UniValue& settlement = offer.exists("settlement") ? offer["settlement"] : offer;
        const UniValue passport = a["passport"];
        if (!passport.isObject() || !passport.exists("profile_id") || !settlement.exists("profile_id")) {
            return Fail(err_code, err, "COMPUTE_PROFILE_MISMATCH", "profile");
        }
        result = UniValue(UniValue::VOBJ);
        result.pushKV("estimate_only", true);
        result.pushKV("settlement_requires_receipts", true);
        result.pushKV("automatic_spend_atoms", 0);
        if (passport["profile_id"].get_str() != settlement["profile_id"].get_str()) {
            result.pushKV("profile_match", false);
            result.pushKV("error", "COMPUTE_PROFILE_MISMATCH");
            return true;
        }
        uint64_t required = 0, rate = 0;
        if (!U64Field(settlement, "required_p1e_microunits", required, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
        if (!U64Field(passport, "p1e_microunits_per_hour", rate, err) || rate == 0) return Fail(err_code, err, "COMPUTE_RATE_TOO_LOW", "rate");
        uint64_t duty = 10000;
        if (a.exists("duty_cycle_bps")) {
            if (!U64Field(a, "duty_cycle_bps", duty, err) || duty == 0 || duty > 10000) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "duty");
        }
        uint64_t full_ms = 0, calendar = 0;
        if (!CeilMulDiv(required, 3600000ull, rate, full_ms, err)) return Fail(err_code, err, "COMPUTE_CREDIT_OVERFLOW", err);
        if (!CeilMulDiv(full_ms, 10000ull, duty, calendar, err)) return Fail(err_code, err, "COMPUTE_CREDIT_OVERFLOW", err);
        uint64_t min_rate = 0;
        if (settlement.exists("optional_min_rate_p1e_microunits_per_hour")) {
            U64Field(settlement, "optional_min_rate_p1e_microunits_per_hour", min_rate, err);
        }
        uint64_t min_samples = 0;
        if (settlement.exists("minimum_passport_samples")) U64Field(settlement, "minimum_passport_samples", min_samples, err);
        uint64_t samples = passport.exists("sample_count") ? passport["sample_count"].getInt<uint64_t>() : 0;
        result.pushKV("profile_match", true);
        result.pushKV("required_p1e_microunits", required);
        result.pushKV("passport_rate_p1e_microunits_per_hour", rate);
        result.pushKV("estimated_full_duty_elapsed_ms", full_ms);
        result.pushKV("requested_duty_cycle_bps", duty);
        result.pushKV("estimated_calendar_elapsed_ms", calendar);
        result.pushKV("minimum_rate_required", min_rate);
        result.pushKV("rate_requirement_met", rate >= min_rate && samples >= min_samples);
        return true;
    }
    if (method == "issuecomputeagreement") {
        const std::string offer_id = a["offer_id"].get_str();
        auto it = m_offers.find(offer_id);
        if (it == m_offers.end()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "offer");
        const UniValue& op = PayloadOf(it->second);
        if (op["expires_at_ms"].getInt<int64_t>() <= now_ms) return Fail(err_code, err, "COMPUTE_OFFER_EXPIRED", "offer");
        if (!HexKey(a["subject_pubkey"].get_str())) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "subject");
        {
            // An agreement freezes this node's own offer. An imported offer carries
            // someone else's scheduler and receipt-issuer lists; signing it here
            // would let those keys earn this node's access grant.
            std::vector<unsigned char> own_pk, own_sk;
            if (!LoadIdentity(own_pk, own_sk, err)) return Fail(err_code, err, "COMPUTE_SIGNING_IDENTITY_REQUIRED", err);
            if (SignerOf(it->second) != HexStr(own_pk)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "offer issuer");
        }
        int64_t period_start = 0, period_end = 0;
        if (!I64Field(a, "period_start_ms", period_start, err) || !I64Field(a, "period_end_ms", period_end, err) ||
            period_end <= period_start) {
            return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "period");
        }
        UniValue payload(UniValue::VOBJ);
        payload.pushKV("record_type", "compute_agreement_v1");
        payload.pushKV("schema_version", 1);
        payload.pushKV("offer_id", offer_id);
        payload.pushKV("subject_pubkey", a["subject_pubkey"].get_str());
        payload.pushKV("resource_ref", op["resource_ref"]);
        payload.pushKV("period_start_ms", period_start);
        payload.pushKV("period_end_ms", period_end);
        payload.pushKV("settlement", op["settlement"]);
        payload.pushKV("access", op["access"]);
        payload.pushKV("policy", op["policy"]);
        const bool qual_required = op["settlement"].exists("qualification_required") && op["settlement"]["qualification_required"].isTrue();
        if (qual_required) {
            if (!a.exists("qualification")) return Fail(err_code, err, "COMPUTE_QUALIFICATION_REQUIRED", "qualification");
            uint32_t episodes = 0;
            if (!ConfirmRedeemedQualification(a["qualification"], op["settlement"], a["subject_pubkey"].get_str(), now_ms, episodes, err_code, err)) {
                return false;
            }
            payload.pushKV("qualification", a["qualification"]);
        } else if (a.exists("qualification")) {
            payload.pushKV("qualification", a["qualification"]);
        }
        payload.pushKV("issued_at_ms", now_ms);
        payload.pushKV("nonce", a.exists("nonce") ? a["nonce"].get_str() : HexStr(std::vector<unsigned char>(16, 1)));
        SignedEnvelope env;
        if (!Sign("ComputeAgreement", payload, env, err_code, err)) return false;
        if (!WriteEnvelope(env, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
        m_agreements[env.record_id.Hex()] = env;
        result = EnvelopeToJson(env);
        result.pushKV("agreement_id", env.record_id.Hex());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "importcomputeagreement") {
        SignedEnvelope env;
        if (!Import(a, "ComputeAgreement", env, err_code, err)) return false;
        const UniValue& ap = PayloadOf(env);
        if (!ap.exists("subject_pubkey") || !ap["subject_pubkey"].isStr() || !HexKey(ap["subject_pubkey"].get_str())) {
            return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "subject");
        }
        if (!ap.exists("settlement") || !ap["settlement"].isObject() || !ap["settlement"].exists("profile_id") || !ap["settlement"]["profile_id"].isStr()) {
            return Fail(err_code, err, "COMPUTE_PROFILE_UNKNOWN", "profile");
        }
        if (!ProfileOk(ap["settlement"]["profile_id"].get_str(), m_chain, err_code)) {
            return Fail(err_code, err, err_code.c_str(), "profile");
        }
        if (ap.exists("policy") && !PolicyClosed(ap["policy"], err_code)) return false;
        int64_t start = 0, end = 0;
        if (!I64Field(ap, "period_start_ms", start, err) || !I64Field(ap, "period_end_ms", end, err) || end <= start) {
            return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "period");
        }
        if (ap.exists("qualification") && ap["qualification"].isObject() && ap["qualification"].exists("profile_id") &&
            ap["qualification"]["profile_id"].get_str() != ap["settlement"]["profile_id"].get_str()) {
            return Fail(err_code, err, "COMPUTE_PROFILE_MISMATCH", "qualification");
        }
        auto offer = m_offers.find(ap["offer_id"].get_str());
        if (offer != m_offers.end()) {
            const UniValue& op = PayloadOf(offer->second);
            if (SignerOf(env) != SignerOf(offer->second)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "issuer");
            if (op["resource_ref"].get_str() != ap["resource_ref"].get_str()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "resource");
            if (op["settlement"]["profile_id"].get_str() != ap["settlement"]["profile_id"].get_str()) {
                return Fail(err_code, err, "COMPUTE_PROFILE_MISMATCH", "profile");
            }
        }
        result = EnvelopeToJson(env);
        result.pushKV("agreement_id", env.record_id.Hex());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "createcomputejob") {
        auto it = m_agreements.find(a["agreement_id"].get_str());
        if (it == m_agreements.end()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "agreement");
        const UniValue& ap = PayloadOf(it->second);
        if (m_cancelled.count(a["agreement_id"].get_str())) return Fail(err_code, err, "COMPUTE_AGREEMENT_CANCELLED", "cancelled");
        if (ap["period_end_ms"].getInt<int64_t>() <= now_ms) return Fail(err_code, err, "COMPUTE_AGREEMENT_EXPIRED", "expired");
        std::vector<unsigned char> pk, sk;
        if (!LoadIdentity(pk, sk, err)) return Fail(err_code, err, "COMPUTE_SIGNING_IDENTITY_REQUIRED", err);
        const std::string me = HexStr(pk);
        const UniValue& sched = ap["settlement"]["authorized_job_scheduler_pubkeys"];
        if (!ContainsKey(sched, me)) return Fail(err_code, err, "COMPUTE_UNAUTHORIZED_SCHEDULER", "scheduler");
        if (a["subject_pubkey"].get_str() != ap["subject_pubkey"].get_str()) return Fail(err_code, err, "COMPUTE_SUBJECT_MISMATCH", "subject");
        if (!KnownJobClass(a["job_class"].get_str(), m_chain == "regtest")) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "class");
        if (ap["settlement"].exists("allowed_job_classes") && !ContainsKey(ap["settlement"]["allowed_job_classes"], a["job_class"].get_str())) {
            return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "class");
        }
        uint64_t credit = 0;
        if (!U64Field(a, "credit_p1e_microunits", credit, err) || credit == 0) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "credit");
        // A job whose expiry is not an integer is never counted as reserved and
        // can never be settled; refuse it like importcomputejob does.
        int64_t job_expires = 0;
        if (!I64Field(a, "expires_at_ms", job_expires, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "expiry");
        if (job_expires <= now_ms) return Fail(err_code, err, "COMPUTE_JOB_EXPIRED", "job");
        UniValue bal;
        if (!BalanceOf(a["agreement_id"].get_str(), now_ms, bal, err_code, err)) return false;
        const uint64_t reserved = bal["outstanding_reserved_p1e_microunits"].getInt<uint64_t>();
        const uint64_t required = bal["required_p1e_microunits"].getInt<uint64_t>();
        const uint64_t credited = bal["credited_p1e_microunits"].getInt<uint64_t>();
        const uint64_t remaining = credited >= required ? 0 : required - credited;
        if (remaining == 0 || reserved > remaining || credit > remaining - reserved) {
            return Fail(err_code, err, "COMPUTE_CREDIT_OVERFLOW", "reservation");
        }
        uint64_t outstanding = 0;
        for (const auto& kv : m_jobs) {
            const UniValue& jp = PayloadOf(kv.second);
            if (StrOf(jp, "agreement_id") != a["agreement_id"].get_str()) continue;
            bool settled = false;
            for (const auto& rec : m_receipts) {
                const UniValue& rp = PayloadOf(rec.second);
                if (rp.exists("job_id") && rp["job_id"].isStr() && rp["job_id"].get_str() == kv.first) settled = true;
            }
            int64_t exp = 0;
            if (settled || !I64Field(jp, "expires_at_ms", exp, err) || exp < now_ms) continue;
            ++outstanding;
        }
        if (outstanding >= 64) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "too many jobs");
        const std::string job_method = a.exists("verification_method") && a["verification_method"].isStr()
                                           ? a["verification_method"].get_str()
                                           : "ISSUER_ACCEPTANCE";
        if (job_method != "ISSUER_ACCEPTANCE" ||
            !ContainsKey(ap["settlement"]["allowed_settlement_modes"], "USEFUL_JOB_RECEIPTS")) {
            return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "method");
        }
        UniValue payload(UniValue::VOBJ);
        payload.pushKV("record_type", "compute_job_v1");
        payload.pushKV("schema_version", 1);
        payload.pushKV("agreement_id", a["agreement_id"]);
        payload.pushKV("subject_pubkey", a["subject_pubkey"]);
        payload.pushKV("beneficiary_ref", a.exists("beneficiary_ref") ? a["beneficiary_ref"] : "");
        payload.pushKV("job_class", a["job_class"]);
        payload.pushKV("credit_p1e_microunits", credit);
        payload.pushKV("profile_id", ap["settlement"]["profile_id"]);
        payload.pushKV("input_commitment", a["input_commitment"]);
        payload.pushKV("executor_spec_commitment", a["executor_spec_commitment"]);
        payload.pushKV("result_schema_commitment", a.exists("result_schema_commitment") ? a["result_schema_commitment"] : a["input_commitment"]);
        payload.pushKV("verification_method", job_method);
        payload.pushKV("issued_at_ms", now_ms);
        payload.pushKV("expires_at_ms", job_expires);
        payload.pushKV("nonce", a.exists("nonce") ? a["nonce"].get_str() : HexStr(std::vector<unsigned char>(16, 2)));
        SignedEnvelope env;
        if (!Sign("ComputeJob", payload, env, err_code, err)) return false;
        if (!WriteEnvelope(env, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
        m_jobs[env.record_id.Hex()] = env;
        result = EnvelopeToJson(env);
        result.pushKV("job_id", env.record_id.Hex());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "importcomputejob") {
        SignedEnvelope env;
        const UniValue rec = a.exists("envelope") ? a["envelope"] : a;
        if (!EnvelopeFromJson(rec, env, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
        if (!VerifySignedEnvelope(env, m_network, err)) {
            if (err.find("network") != std::string::npos) return Fail(err_code, err, "COMPUTE_NETWORK_MISMATCH", err);
            return Fail(err_code, err, "COMPUTE_SIGNATURE_INVALID", err);
        }
        const UniValue& jp = PayloadOf(env);
        if (m_jobs.count(env.record_id.Hex()) == 0) {
            auto it = m_agreements.find(jp["agreement_id"].get_str());
            if (it == m_agreements.end()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "agreement");
            const UniValue& ap = PayloadOf(it->second);
            if (m_cancelled.count(jp["agreement_id"].get_str())) return Fail(err_code, err, "COMPUTE_AGREEMENT_CANCELLED", "cancelled");
            if (ap["period_end_ms"].getInt<int64_t>() <= now_ms) return Fail(err_code, err, "COMPUTE_AGREEMENT_EXPIRED", "expired");
            if (jp["expires_at_ms"].getInt<int64_t>() <= now_ms) return Fail(err_code, err, "COMPUTE_JOB_EXPIRED", "job");
            if (!ContainsKey(ap["settlement"]["authorized_job_scheduler_pubkeys"], SignerOf(env))) {
                return Fail(err_code, err, "COMPUTE_UNAUTHORIZED_SCHEDULER", "scheduler");
            }
            if (jp["subject_pubkey"].get_str() != ap["subject_pubkey"].get_str()) return Fail(err_code, err, "COMPUTE_SUBJECT_MISMATCH", "subject");
            if (jp["profile_id"].get_str() != ap["settlement"]["profile_id"].get_str()) return Fail(err_code, err, "COMPUTE_PROFILE_MISMATCH", "profile");
            if (!KnownJobClass(jp["job_class"].get_str(), m_chain == "regtest")) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "class");
            const std::string job_method = jp.exists("verification_method") && jp["verification_method"].isStr()
                                               ? jp["verification_method"].get_str()
                                               : "";
            if (job_method != "ISSUER_ACCEPTANCE" ||
                !ContainsKey(ap["settlement"]["allowed_settlement_modes"], "USEFUL_JOB_RECEIPTS")) {
                return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "method");
            }
            if (ap["settlement"].exists("allowed_job_classes") && !ContainsKey(ap["settlement"]["allowed_job_classes"], jp["job_class"].get_str())) {
                return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "class");
            }
            uint64_t credit = 0;
            if (!U64Field(jp, "credit_p1e_microunits", credit, err) || credit == 0) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "credit");
            UniValue bal;
            if (!BalanceOf(jp["agreement_id"].get_str(), now_ms, bal, err_code, err)) return false;
            const uint64_t reserved = bal["outstanding_reserved_p1e_microunits"].getInt<uint64_t>();
            const uint64_t required = bal["required_p1e_microunits"].getInt<uint64_t>();
            const uint64_t credited = bal["credited_p1e_microunits"].getInt<uint64_t>();
            const uint64_t remaining = credited >= required ? 0 : required - credited;
            if (remaining == 0 || reserved > remaining || credit > remaining - reserved) {
                return Fail(err_code, err, "COMPUTE_CREDIT_OVERFLOW", "reservation");
            }
        }
        if (!Import(a, "ComputeJob", env, err_code, err)) return false;
        result = EnvelopeToJson(env);
        result.pushKV("job_id", env.record_id.Hex());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "submitcomputejobresult") {
        auto it = m_jobs.find(a["job_id"].get_str());
        if (it == m_jobs.end()) return Fail(err_code, err, "COMPUTE_RESULT_INVALID", "job");
        const UniValue& jp = PayloadOf(it->second);
        if (jp["expires_at_ms"].getInt<int64_t>() <= now_ms) return Fail(err_code, err, "COMPUTE_JOB_EXPIRED", "job");
        std::vector<unsigned char> pk, sk;
        if (!LoadIdentity(pk, sk, err)) return Fail(err_code, err, "COMPUTE_SIGNING_IDENTITY_REQUIRED", err);
        if (HexStr(pk) != jp["subject_pubkey"].get_str()) return Fail(err_code, err, "COMPUTE_SUBJECT_MISMATCH", "subject");
        UniValue payload(UniValue::VOBJ);
        payload.pushKV("record_type", "compute_job_result_v1");
        payload.pushKV("schema_version", 1);
        payload.pushKV("job_id", a["job_id"]);
        payload.pushKV("agreement_id", jp["agreement_id"]);
        payload.pushKV("subject_pubkey", jp["subject_pubkey"]);
        payload.pushKV("output_commitment", a["output_commitment"]);
        if (a.exists("evidence_commitment")) payload.pushKV("evidence_commitment", a["evidence_commitment"]);
        payload.pushKV("completed_at_ms", now_ms);
        payload.pushKV("nonce", a.exists("nonce") ? a["nonce"].get_str() : HexStr(std::vector<unsigned char>(16, 3)));
        SignedEnvelope env;
        if (!Sign("ComputeJobResult", payload, env, err_code, err)) return false;
        if (!WriteEnvelope(env, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
        m_results[env.record_id.Hex()] = env;
        result = EnvelopeToJson(env);
        result.pushKV("result_id", env.record_id.Hex());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "importcomputejobresult") {
        SignedEnvelope env;
        const UniValue rec = a.exists("envelope") ? a["envelope"] : a;
        if (!EnvelopeFromJson(rec, env, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
        if (!VerifySignedEnvelope(env, m_network, err)) {
            if (err.find("network") != std::string::npos) return Fail(err_code, err, "COMPUTE_NETWORK_MISMATCH", err);
            return Fail(err_code, err, "COMPUTE_SIGNATURE_INVALID", err);
        }
        const UniValue& rp = PayloadOf(env);
        auto jit = m_jobs.find(rp["job_id"].get_str());
        if (jit == m_jobs.end()) return Fail(err_code, err, "COMPUTE_RESULT_INVALID", "job");
        const UniValue& jp = PayloadOf(jit->second);
        if (jp["expires_at_ms"].getInt<int64_t>() <= now_ms) return Fail(err_code, err, "COMPUTE_JOB_EXPIRED", "job");
        if (SignerOf(env) != jp["subject_pubkey"].get_str() || rp["subject_pubkey"].get_str() != jp["subject_pubkey"].get_str()) {
            return Fail(err_code, err, "COMPUTE_SUBJECT_MISMATCH", "subject");
        }
        if (rp["agreement_id"].get_str() != jp["agreement_id"].get_str()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "agreement");
        if (!rp.exists("output_commitment") || !rp["output_commitment"].isStr() || rp["output_commitment"].get_str().empty()) {
            return Fail(err_code, err, "COMPUTE_RESULT_INVALID", "output");
        }
        if (!Import(a, "ComputeJobResult", env, err_code, err)) return false;
        result = EnvelopeToJson(env);
        result.pushKV("result_id", env.record_id.Hex());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "acceptcomputejobresult" || method == "issuecomputereceipt") {
        std::vector<unsigned char> pk, sk;
        if (!LoadIdentity(pk, sk, err)) return Fail(err_code, err, "COMPUTE_SIGNING_IDENTITY_REQUIRED", err);
        const std::string me = HexStr(pk);
        std::string agreement_id;
        std::string job_id;
        std::string result_id;
        uint64_t credit = 0;
        std::string profile_id;
        std::string beneficiary;
        std::string subject;
        std::string method_name = "ISSUER_ACCEPTANCE";
        std::string evidence;
        if (method == "acceptcomputejobresult") {
            auto rit = m_results.find(a["result_id"].get_str());
            if (rit == m_results.end()) return Fail(err_code, err, "COMPUTE_RESULT_INVALID", "result");
            const UniValue& rp = PayloadOf(rit->second);
            auto jit = m_jobs.find(rp["job_id"].get_str());
            if (jit == m_jobs.end()) return Fail(err_code, err, "COMPUTE_RESULT_INVALID", "job");
            const UniValue& jp = PayloadOf(jit->second);
            if (rp["subject_pubkey"].get_str() != jp["subject_pubkey"].get_str() || SignerOf(rit->second) != jp["subject_pubkey"].get_str()) {
                return Fail(err_code, err, "COMPUTE_SUBJECT_MISMATCH", "subject");
            }
            if (a.exists("expected_output_commitment") && a["expected_output_commitment"].get_str() != rp["output_commitment"].get_str()) {
                return Fail(err_code, err, "COMPUTE_RESULT_INVALID", "output");
            }
            agreement_id = jp["agreement_id"].get_str();
            job_id = rp["job_id"].get_str();
            result_id = rit->first;
            credit = jp["credit_p1e_microunits"].getInt<uint64_t>();
            profile_id = jp["profile_id"].get_str();
            beneficiary = jp["beneficiary_ref"].get_str();
            subject = jp["subject_pubkey"].get_str();
            method_name = jp["verification_method"].get_str();
            if (method_name == "DIRECT_COMPUTE") return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "method");
            evidence = rp["output_commitment"].get_str();
            for (const auto& kv : m_receipts) {
                const UniValue& rec = PayloadOf(kv.second);
                if (StrOf(rec, "job_id") == job_id) return Fail(err_code, err, "COMPUTE_JOB_ALREADY_SETTLED", "job");
            }
        } else {
            agreement_id = a["agreement_id"].get_str();
            if (!U64Field(a, "credited_p1e_microunits", credit, err) || credit == 0) return Fail(err_code, err, "COMPUTE_RECEIPT_CREDIT_MISMATCH", "credit");
            if (a.exists("job_id") && a["job_id"].isStr() && !a["job_id"].get_str().empty()) {
                auto jit = m_jobs.find(a["job_id"].get_str());
                if (jit == m_jobs.end()) return Fail(err_code, err, "COMPUTE_RESULT_INVALID", "job");
                if (PayloadOf(jit->second)["credit_p1e_microunits"].getInt<uint64_t>() != credit) {
                    return Fail(err_code, err, "COMPUTE_RECEIPT_CREDIT_MISMATCH", "credit");
                }
                job_id = a["job_id"].get_str();
                for (const auto& kv : m_receipts) {
                    if (StrOf(PayloadOf(kv.second), "job_id") == job_id) {
                        return Fail(err_code, err, "COMPUTE_JOB_ALREADY_SETTLED", "job");
                    }
                }
            }
            profile_id = a["profile_id"].get_str();
            subject = a["subject_pubkey"].get_str();
            beneficiary = a.exists("beneficiary_ref") ? a["beneficiary_ref"].get_str() : "";
            method_name = a.exists("verification_method") ? a["verification_method"].get_str() : "DIRECT_COMPUTE";
            evidence = a.exists("evidence_commitment") ? a["evidence_commitment"].get_str() : "";
            if (a.exists("result_id")) result_id = a["result_id"].get_str();
            if (!job_id.empty()) {
                const UniValue& jp = PayloadOf(m_jobs.at(job_id));
                if (StrOf(jp, "agreement_id") != agreement_id) {
                    return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "agreement");
                }
                if (method_name == "DIRECT_COMPUTE") return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "method");
            } else if (method_name != "DIRECT_COMPUTE") {
                return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "method");
            }
            if (method_name == "DIRECT_COMPUTE") {
                auto ait_pre = m_agreements.find(agreement_id);
                if (ait_pre == m_agreements.end()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "agreement");
                if (!ContainsKey(PayloadOf(ait_pre->second)["settlement"]["authorized_receipt_issuer_pubkeys"], me)) {
                    return Fail(err_code, err, "COMPUTE_UNAUTHORIZED_RECEIPT_ISSUER", "issuer");
                }
                if (!ContainsKey(PayloadOf(ait_pre->second)["settlement"]["allowed_settlement_modes"], "DIRECT_COMPUTE")) {
                    return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "mode");
                }
                UniValue qual(UniValue::VOBJ);
                qual.pushKV("challenge_id", evidence);
                uint32_t episodes = 0;
                if (!ConfirmRedeemedQualification(qual, PayloadOf(ait_pre->second)["settlement"], subject, now_ms, episodes, err_code, err)) {
                    return false;
                }
                const uint64_t expected = static_cast<uint64_t>(episodes) * 1000000ull;
                if (credit != expected) return Fail(err_code, err, "COMPUTE_RECEIPT_CREDIT_MISMATCH", "qualification");
                // One redeemed challenge backs one direct-compute receipt, on any agreement.
                for (const auto& kv : m_receipts) {
                    const UniValue& prior = PayloadOf(kv.second);
                    if (prior.exists("verification_method") && prior["verification_method"].isStr() &&
                        prior["verification_method"].get_str() == "DIRECT_COMPUTE" && prior.exists("evidence_commitment") &&
                        prior["evidence_commitment"].isStr() && prior["evidence_commitment"].get_str() == evidence) {
                        return Fail(err_code, err, "COMPUTE_CHALLENGE_REDEEMED", "direct receipt");
                    }
                }
            }
        }
        auto ait = m_agreements.find(agreement_id);
        if (ait == m_agreements.end()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "agreement");
        const UniValue& ap = PayloadOf(ait->second);
        if (m_cancelled.count(agreement_id)) return Fail(err_code, err, "COMPUTE_AGREEMENT_CANCELLED", "cancelled");
        if (ap["period_end_ms"].getInt<int64_t>() <= now_ms) return Fail(err_code, err, "COMPUTE_AGREEMENT_EXPIRED", "expired");
        if (subject != ap["subject_pubkey"].get_str()) return Fail(err_code, err, "COMPUTE_SUBJECT_MISMATCH", "subject");
        if (profile_id != ap["settlement"]["profile_id"].get_str()) return Fail(err_code, err, "COMPUTE_PROFILE_MISMATCH", "profile");
        const char* need_mode = job_id.empty() ? "DIRECT_COMPUTE" : "USEFUL_JOB_RECEIPTS";
        if (!ContainsKey(ap["settlement"]["allowed_settlement_modes"], need_mode)) {
            return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "mode");
        }
        if (!ContainsKey(ap["settlement"]["authorized_receipt_issuer_pubkeys"], me)) {
            return Fail(err_code, err, "COMPUTE_UNAUTHORIZED_RECEIPT_ISSUER", "issuer");
        }
        UniValue payload(UniValue::VOBJ);
        payload.pushKV("record_type", "compute_receipt_v1");
        payload.pushKV("schema_version", 1);
        payload.pushKV("agreement_id", agreement_id);
        if (!job_id.empty()) payload.pushKV("job_id", job_id);
        if (!result_id.empty()) payload.pushKV("result_id", result_id);
        payload.pushKV("subject_pubkey", subject);
        if (!beneficiary.empty()) payload.pushKV("beneficiary_ref", beneficiary);
        payload.pushKV("profile_id", profile_id);
        payload.pushKV("credited_p1e_microunits", credit);
        payload.pushKV("verification_method", method_name);
        payload.pushKV("evidence_commitment", evidence);
        payload.pushKV("accepted_at_ms", now_ms);
        payload.pushKV("nonce", a.exists("nonce") ? a["nonce"].get_str() : HexStr(std::vector<unsigned char>(16, 4)));
        SignedEnvelope env;
        if (!Sign("ComputeReceipt", payload, env, err_code, err)) return false;
        if (!WriteEnvelope(env, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
        m_receipts[env.record_id.Hex()] = env;
        result = EnvelopeToJson(env);
        result.pushKV("receipt_id", env.record_id.Hex());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "importcomputereceipt") {
        SignedEnvelope env;
        const UniValue rec = a.exists("envelope") ? a["envelope"] : a;
        if (!EnvelopeFromJson(rec, env, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
        if (!VerifySignedEnvelope(env, m_network, err)) {
            if (err.find("network") != std::string::npos) return Fail(err_code, err, "COMPUTE_NETWORK_MISMATCH", err);
            return Fail(err_code, err, "COMPUTE_SIGNATURE_INVALID", err);
        }
        const UniValue& rp = PayloadOf(env);
        auto ait = m_agreements.find(rp["agreement_id"].get_str());
        if (ait == m_agreements.end()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "agreement");
        const UniValue& ap = PayloadOf(ait->second);
        if (rp["profile_id"].get_str() != ap["settlement"]["profile_id"].get_str()) return Fail(err_code, err, "COMPUTE_PROFILE_MISMATCH", "profile");
        if (rp["subject_pubkey"].get_str() != ap["subject_pubkey"].get_str()) return Fail(err_code, err, "COMPUTE_SUBJECT_MISMATCH", "subject");
        const std::string issuer = env.body["public_key_hex"].get_str();
        if (!ContainsKey(ap["settlement"]["authorized_receipt_issuer_pubkeys"], issuer)) {
            return Fail(err_code, err, "COMPUTE_UNAUTHORIZED_RECEIPT_ISSUER", "issuer");
        }
        // Every stored receipt is re-read on each settlement and balance call.
        // A field of the wrong type must be refused here, not thrown on later.
        uint64_t imported_credit = 0;
        if (!U64Field(rp, "credited_p1e_microunits", imported_credit, err) || imported_credit == 0) {
            return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "credit");
        }
        for (const char* k : {"job_id", "result_id", "verification_method", "evidence_commitment", "beneficiary_ref"}) {
            if (rp.exists(k) && !rp[k].isStr()) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", k);
        }
        if (rp.exists("job_id") && rp["job_id"].isStr() && !rp["job_id"].get_str().empty()) {
            for (const auto& kv : m_receipts) {
                if (kv.first == env.record_id.Hex()) continue;
                const UniValue& other = PayloadOf(kv.second);
                if (StrOf(other, "job_id") == rp["job_id"].get_str()) {
                    return Fail(err_code, err, "COMPUTE_JOB_ALREADY_SETTLED", "job");
                }
            }
            auto jit = m_jobs.find(rp["job_id"].get_str());
            if (jit == m_jobs.end()) return Fail(err_code, err, "COMPUTE_RESULT_INVALID", "job");
            const std::string method = rp.exists("verification_method") && rp["verification_method"].isStr()
                ? rp["verification_method"].get_str() : "";
            if (method == "DIRECT_COMPUTE") return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "method");
            const UniValue& jp = PayloadOf(jit->second);
            if (jp["agreement_id"].get_str() != rp["agreement_id"].get_str()) {
                return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "agreement");
            }
            if (jp["credit_p1e_microunits"].getInt<uint64_t>() != rp["credited_p1e_microunits"].getInt<uint64_t>()) {
                return Fail(err_code, err, "COMPUTE_RECEIPT_CREDIT_MISMATCH", "credit");
            }
            if (!ContainsKey(ap["settlement"]["allowed_settlement_modes"], "USEFUL_JOB_RECEIPTS")) {
                return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "mode");
            }
        } else {
            const std::string method = rp.exists("verification_method") && rp["verification_method"].isStr()
                ? rp["verification_method"].get_str() : "";
            if (method != "DIRECT_COMPUTE" || !ContainsKey(ap["settlement"]["allowed_settlement_modes"], "DIRECT_COMPUTE")) {
                return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "method");
            }
            const std::string evidence = StrOf(rp, "evidence_commitment");
            // A direct-compute receipt names one redeemed challenge (48-byte id,
            // lower-case hex as issued) and credits whole episodes of it. Without
            // this an empty or invented evidence string skips the one-challenge,
            // one-receipt rule and can carry any credit.
            if (!LowerHex(evidence, 96)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "evidence");
            if (imported_credit % pwc::P1E_MICROUNITS != 0 || imported_credit / pwc::P1E_MICROUNITS > pwc::kQualEpisodeMax) {
                return Fail(err_code, err, "COMPUTE_RECEIPT_CREDIT_MISMATCH", "direct credit");
            }
            for (const auto& kv : m_receipts) {
                if (kv.first == env.record_id.Hex()) continue;
                const UniValue& prior = PayloadOf(kv.second);
                if (StrOf(prior, "verification_method") == "DIRECT_COMPUTE" && StrOf(prior, "evidence_commitment") == evidence) {
                    return Fail(err_code, err, "COMPUTE_CHALLENGE_REDEEMED", "direct receipt");
                }
            }
            // When the challenge was issued by this node's btxd, hold the receipt
            // to what was actually redeemed. A challenge from another issuer is
            // not visible here and rests on the listed receipt issuer.
            if (!g_qual_path.empty()) {
                pwc::QualificationRegistry reg;
                std::string open_err;
                UniValue st;
                std::string st_code, st_err;
                if (reg.Open(fs::PathFromString(g_qual_path), open_err) && reg.Status(evidence, now_ms, st, st_code, st_err) &&
                    StrOf(st, "status") != "unknown") {
                    if (StrOf(st, "status") != "redeemed") return Fail(err_code, err, "COMPUTE_QUALIFICATION_REQUIRED", "not redeemed");
                    if (StrOf(st, "subject_digest") != SubjectDigestHex(ap["subject_pubkey"].get_str())) {
                        return Fail(err_code, err, "COMPUTE_SUBJECT_MISMATCH", "qualification");
                    }
                    if (StrOf(st, "profile_id") != ap["settlement"]["profile_id"].get_str()) {
                        return Fail(err_code, err, "COMPUTE_PROFILE_MISMATCH", "qualification");
                    }
                    if (!st["episode_count"].isNum() ||
                        imported_credit != static_cast<uint64_t>(st["episode_count"].getInt<int64_t>()) * pwc::P1E_MICROUNITS) {
                        return Fail(err_code, err, "COMPUTE_RECEIPT_CREDIT_MISMATCH", "qualification");
                    }
                }
            }
        }
        if (!Import(a, "ComputeReceipt", env, err_code, err)) return false;
        result = EnvelopeToJson(env);
        result.pushKV("receipt_id", env.record_id.Hex());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getcomputebalance") {
        return BalanceOf(a["agreement_id"].get_str(), now_ms, result, err_code, err);
    }
    if (method == "issuecomputeaccessgrant") {
        const std::string agreement_id = a["agreement_id"].get_str();
        UniValue bal;
        if (!BalanceOf(agreement_id, now_ms, bal, err_code, err)) return false;
        // Imported agreements carry their own issuer and receipt-issuer list.
        // Only the identity that issued the agreement may grant access under it.
        std::vector<unsigned char> pk, sk;
        if (!LoadIdentity(pk, sk, err)) return Fail(err_code, err, "COMPUTE_SIGNING_IDENTITY_REQUIRED", err);
        if (m_agreements.at(agreement_id).body["public_key_hex"].get_str() != HexStr(pk)) {
            return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "agreement issuer");
        }
        const std::string status = bal["status"].get_str();
        const UniValue& ap = PayloadOf(m_agreements.at(agreement_id));
        const std::string schedule = ap["settlement"]["schedule"].get_str();
        const bool ok = status == "SATISFIED" || (schedule == "PRO_RATA" && status == "IN_GOOD_STANDING");
        if (!ok) {
            return Fail(err_code, err, status == "OPEN" ? "COMPUTE_NOT_SATISFIED" : "COMPUTE_NOT_IN_GOOD_STANDING", status);
        }
        // A grant covers only time inside the agreement. A pro-rata grant is
        // refused before the period starts, even when the units are already
        // credited; a prepaid grant issued early starts at period_start_ms.
        const int64_t period_start = ap["period_start_ms"].getInt<int64_t>();
        if (schedule == "PRO_RATA" && now_ms < period_start) {
            return Fail(err_code, err, "COMPUTE_NOT_SATISFIED", "period not started");
        }
        const int64_t valid_from = std::max(now_ms, period_start);
        int64_t until = ap["period_end_ms"].getInt<int64_t>();
        if (schedule == "PRO_RATA") {
            const int64_t cap = now_ms + 24LL * 60 * 60 * 1000;
            if (cap < until) until = cap;
        }
        if (until < valid_from) return Fail(err_code, err, "COMPUTE_NOT_IN_GOOD_STANDING", "window");
        UniValue payload(UniValue::VOBJ);
        payload.pushKV("record_type", "compute_access_grant_v1");
        payload.pushKV("schema_version", 1);
        payload.pushKV("agreement_id", agreement_id);
        payload.pushKV("offer_id", ap["offer_id"]);
        payload.pushKV("subject_pubkey", ap["subject_pubkey"]);
        payload.pushKV("resource_ref", ap["resource_ref"]);
        payload.pushKV("rights", ap["access"]["rights"]);
        payload.pushKV("profile_id", ap["settlement"]["profile_id"]);
        payload.pushKV("required_p1e_microunits", bal["required_p1e_microunits"]);
        payload.pushKV("credited_p1e_microunits", bal["credited_p1e_microunits"]);
        payload.pushKV("receipt_set_digest", bal["receipt_set_digest"]);
        payload.pushKV("issued_at_ms", now_ms);
        payload.pushKV("valid_from_ms", valid_from);
        payload.pushKV("valid_until_ms", until);
        payload.pushKV("nonce", a.exists("nonce") ? a["nonce"].get_str() : HexStr(std::vector<unsigned char>(16, 5)));
        SignedEnvelope env;
        if (!Sign("ComputeAccessGrant", payload, env, err_code, err)) return false;
        if (!WriteEnvelope(env, err)) return Fail(err_code, err, "COMPUTE_RECORD_INVALID", err);
        m_grants[env.record_id.Hex()] = env;
        result = EnvelopeToJson(env);
        result.pushKV("grant_id", env.record_id.Hex());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "importcomputeaccessgrant") {
        SignedEnvelope env;
        const UniValue rec = a.exists("envelope") ? a["envelope"] : a;
        if (!EnvelopeFromJson(rec, env, err)) return Fail(err_code, err, "COMPUTE_GRANT_INVALID", err);
        if (!VerifySignedEnvelope(env, m_network, err)) return Fail(err_code, err, "COMPUTE_SIGNATURE_INVALID", err);
        const UniValue& gp = PayloadOf(env);
        auto ait = m_agreements.find(gp["agreement_id"].get_str());
        if (ait == m_agreements.end()) return Fail(err_code, err, "COMPUTE_GRANT_INVALID", "agreement");
        const UniValue& ap = PayloadOf(ait->second);
        if (SignerOf(env) != SignerOf(ait->second)) return Fail(err_code, err, "COMPUTE_GRANT_INVALID", "issuer");
        if (gp["subject_pubkey"].get_str() != ap["subject_pubkey"].get_str()) return Fail(err_code, err, "COMPUTE_GRANT_INVALID", "subject");
        if (gp["resource_ref"].get_str() != ap["resource_ref"].get_str()) return Fail(err_code, err, "COMPUTE_GRANT_INVALID", "resource");
        if (gp["valid_until_ms"].getInt<int64_t>() < gp["valid_from_ms"].getInt<int64_t>()) {
            return Fail(err_code, err, "COMPUTE_GRANT_INVALID", "window");
        }
        if (!Import(a, "ComputeAccessGrant", env, err_code, err)) return false;
        result = EnvelopeToJson(env);
        result.pushKV("grant_id", env.record_id.Hex());
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "verifycomputeaccessgrant") {
        SignedEnvelope env;
        const UniValue rec = a.exists("envelope") ? a["envelope"] : a;
        UniValue parsed = rec;
        if (!rec.exists("body")) {
            if (!a.exists("grant_id") || !m_grants.count(a["grant_id"].get_str())) return Fail(err_code, err, "COMPUTE_GRANT_INVALID", "missing");
            parsed = EnvelopeToJson(m_grants.at(a["grant_id"].get_str()));
        }
        if (!EnvelopeFromJson(parsed, env, err)) {
            return Fail(err_code, err, "COMPUTE_GRANT_INVALID", err);
        }
        if (!VerifySignedEnvelope(env, m_network, err)) return Fail(err_code, err, "COMPUTE_SIGNATURE_INVALID", err);
        const UniValue& gp = PayloadOf(env);
        // Only a ComputeAccessGrant is a grant. The trusted issuer also signs
        // offers, agreements and receipts; none of them may pass as access.
        if (StrOf(env.body, "record_type") != "ComputeAccessGrant" || StrOf(gp, "record_type") != "compute_access_grant_v1" ||
            !gp.exists("valid_from_ms") || !gp["valid_from_ms"].isNum() || !gp.exists("valid_until_ms") || !gp["valid_until_ms"].isNum() ||
            StrOf(gp, "subject_pubkey").empty() || StrOf(gp, "resource_ref").empty() || StrOf(gp, "agreement_id").empty()) {
            return Fail(err_code, err, "COMPUTE_GRANT_INVALID", "record type");
        }
        if (!a.exists("trusted_issuer_pubkey") || !a["trusted_issuer_pubkey"].isStr() ||
            a["trusted_issuer_pubkey"].get_str() != SignerOf(env)) {
            return Fail(err_code, err, "COMPUTE_GRANT_INVALID", "trusted issuer");
        }
        if (a.exists("subject_pubkey") && a["subject_pubkey"].get_str() != gp["subject_pubkey"].get_str()) {
            return Fail(err_code, err, "COMPUTE_GRANT_INVALID", "subject");
        }
        if (a.exists("resource_ref") && a["resource_ref"].get_str() != gp["resource_ref"].get_str()) {
            return Fail(err_code, err, "COMPUTE_GRANT_INVALID", "resource");
        }
        if (now_ms > gp["valid_until_ms"].getInt<int64_t>() || now_ms < gp["valid_from_ms"].getInt<int64_t>()) {
            return Fail(err_code, err, "COMPUTE_GRANT_EXPIRED", "window");
        }
        result = UniValue(UniValue::VOBJ);
        result.pushKV("valid", true);
        result.pushKV("grant_id", env.record_id.Hex());
        result.pushKV("subject_pubkey", gp["subject_pubkey"]);
        result.pushKV("resource_ref", gp["resource_ref"]);
        result.pushKV("rights", gp["rights"]);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    return Fail(err_code, err, "COMPUTE_RECORD_INVALID", "method");
}

const std::set<std::string>& Methods()
{
    static const std::set<std::string> k = {
        "createcomputeoffer", "importcomputeoffer", "getcomputeoffer", "listcomputeoffers", "getcomputeoffersforresource",
        "quotecomputeaccess", "issuecomputeagreement", "importcomputeagreement", "getcomputeagreement", "listcomputeagreements",
        "createcomputejob", "importcomputejob", "getcomputejob", "listcomputejobs",
        "submitcomputejobresult", "importcomputejobresult", "getcomputejobresult",
        "acceptcomputejobresult", "issuecomputereceipt", "importcomputereceipt", "getcomputereceipt", "listcomputereceipts",
        "getcomputebalance", "issuecomputeaccessgrant", "importcomputeaccessgrant", "getcomputeaccessgrant", "verifycomputeaccessgrant",
        "getcomputesigningidentity",
    };
    return k;
}

bool DispatchBound(const fs::path& dir, const std::string& chain, const std::string& method, const UniValue& params,
                   UniValue& result, std::string& err_code, std::string& err)
{
    // btx-modeld answers unix RPC on several worker threads. The store's maps
    // and its check-then-write settlement (one receipt per job) must not interleave.
    static std::mutex mu;
    std::lock_guard<std::mutex> lock(mu);
    auto& st = Store();
    st.Bind(dir, chain);
    return st.Dispatch(method, params, result, err_code, err);
}

} // namespace

void SetPwcChain(const std::string& chain) { g_chain = chain; }
void SetPwcQualificationRegistryPath(const std::string& path) { g_qual_path = path; }
std::string PwcChain() { return g_chain; }

NetworkId PwcNetworkId(const std::string& chain)
{
    CSHA256 hasher;
    const std::string tag = "BTX/PWC/network/v1";
    hasher.Write(reinterpret_cast<const unsigned char*>(tag.data()), tag.size());
    hasher.Write(reinterpret_cast<const unsigned char*>(chain.data()), chain.size());
    unsigned char out[32];
    hasher.Finalize(out);
    NetworkId id;
    std::memcpy(id.data.data(), out, 32);
    return id;
}

bool IsComputeHelperMethod(const std::string& method)
{
    return Methods().count(method) > 0;
}

bool DispatchComputeHelperRpc(ModelCatalog& cat, const std::string& method, const UniValue& params, UniValue& result,
                              std::string& err_code, std::string& err)
{
    if (!IsComputeHelperMethod(method)) return false;
    const std::string chain = g_chain.empty() ? std::string{} : g_chain;
    return DispatchBound(cat.Store().Root().parent_path(), chain, method, params, result, err_code, err);
}

bool ComputeEconomySelfTestHook(const fs::path& dir, const std::string& chain, const std::string& method,
                                 const UniValue& params, UniValue& result, std::string& err_code, std::string& err)
{
    return DispatchBound(dir, chain, method, params, result, err_code, err);
}

} // namespace modelnet
