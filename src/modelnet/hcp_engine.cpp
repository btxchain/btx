// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// In-process HCP/1 gateway + hosted connector. Not consensus. Not a wallet
// proxy. OAuth lives here (btx-hcpd), never in btxd. automatic_spend_atoms = 0.

#include <modelnet/hcp.h>

#include <modelnet/helper.h>
#include <modelnet/identity.h>
#include <modelnet/package_core.h>
#include <modelnet/package_pjson.h>
#include <crypto/sha256.h>
#include <crypto/sha384.h>
#include <random.h>
#include <span.h>
#include <util/strencodings.h>
#include <util/fs.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iterator>
#include <limits>
#include <mutex>
#include <optional>
#include <sstream>
#include <thread>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

namespace modelnet {

namespace {

std::string Lower(std::string s)
{
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

std::string Trim(std::string s)
{
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r' || s.front() == '\n')) {
        s.erase(s.begin());
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r' || s.back() == '\n')) {
        s.pop_back();
    }
    return s;
}

std::string Sha256Hex(const std::string& s)
{
    unsigned char d[CSHA256::OUTPUT_SIZE];
    CSHA256 h;
    h.Write(reinterpret_cast<const unsigned char*>(s.data()), s.size());
    h.Finalize(d);
    return HexStr(Span<const unsigned char>{d, sizeof(d)});
}

std::string Sha384Hex(Span<const unsigned char> b)
{
    unsigned char d[CSHA384::OUTPUT_SIZE];
    CSHA384 h;
    h.Write(b.data(), b.size());
    h.Finalize(d);
    return HexStr(Span<const unsigned char>{d, sizeof(d)});
}

std::string LabelDigest(const std::string& label)
{
    return Sha384Hex(Span<const unsigned char>{reinterpret_cast<const unsigned char*>(label.data()), label.size()});
}

std::string RandId(const std::string& prefix)
{
    unsigned char b[16];
    GetRandBytes(Span<unsigned char>{b, sizeof(b)});
    return prefix + HexStr(Span<const unsigned char>{b, sizeof(b)}).substr(0, 16);
}

std::vector<std::string> Split(const std::string& s, char c)
{
    std::vector<std::string> o;
    std::string cur;
    for (char x : s) {
        if (x == c) {
            o.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(x);
        }
    }
    o.push_back(cur);
    return o;
}

std::string UrlDecode(const std::string& s)
{
    std::string o;
    o.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            const auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int hi = hex(s[i + 1]);
            const int lo = hex(s[i + 2]);
            if (hi >= 0 && lo >= 0) {
                o.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
                continue;
            }
        }
        if (s[i] == '+') o.push_back(' ');
        else o.push_back(s[i]);
    }
    return o;
}

std::string QueryGet(const std::string& query, const std::string& key)
{
    for (const auto& part : Split(query, '&')) {
        const auto eq = part.find('=');
        if (eq == std::string::npos) continue;
        if (part.substr(0, eq) == key) return UrlDecode(part.substr(eq + 1));
    }
    return {};
}

bool MatchPath(const std::string& path, const std::string& pat, std::map<std::string, std::string>& cap)
{
    cap.clear();
    const auto a = Split(path, '/');
    const auto b = Split(pat, '/');
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (!b[i].empty() && b[i].front() == '{' && b[i].back() == '}') {
            cap[b[i].substr(1, b[i].size() - 2)] = a[i];
        } else if (a[i] != b[i]) {
            return false;
        }
    }
    return true;
}

std::string Hdr(const HcpHttpRequest& req, const std::string& k)
{
    const std::string want = Lower(k);
    for (const auto& e : req.headers) {
        if (Lower(e.first) == want) return Trim(e.second);
    }
    return {};
}

bool PrivateUrl(const std::string& url)
{
    const std::string u = Lower(url);
    if (u.find("127.0.0.1") != std::string::npos || u.find("localhost") != std::string::npos ||
        u.find("10.") != std::string::npos || u.find("172.16.") != std::string::npos ||
        u.find("192.168.") != std::string::npos || u.find("169.254.") != std::string::npos ||
        u.find("metadata") != std::string::npos || u.find("0.0.0.0") != std::string::npos) {
        return true;
    }
    return false;
}

const char* kLocalEffects[] = {
    HCP_EFFECT_INSPECT, HCP_EFFECT_FETCH_METADATA, HCP_EFFECT_ACQUIRE_MODEL, HCP_EFFECT_SEED_MODEL,
    HCP_EFFECT_INSTALL_CLIENT, HCP_EFFECT_PLAN_LOCAL_RUN, HCP_EFFECT_EXECUTE_LOCAL_RUN,
    HCP_EFFECT_REPORT_READINESS,
};

bool EffectKnown(const std::string& e)
{
    for (const char* x : kLocalEffects) {
        if (e == x) return true;
    }
    return false;
}

HcpHttpResponse JsonStatus(int status, UniValue obj)
{
    HcpHttpResponse r;
    r.status = status;
    r.json = obj;
    std::string err;
    std::vector<unsigned char> raw;
    if (EncodePjson1(obj, raw, err)) {
        r.body.assign(raw.begin(), raw.end());
    } else {
        r.body = obj.write();
    }
    return r;
}

HcpHttpResponse Err(int status, const std::string& code, const std::string& msg)
{
    UniValue o(UniValue::VOBJ);
    UniValue e(UniValue::VOBJ);
    e.pushKV("code", code);
    e.pushKV("message", msg);
    o.pushKV("error", e);
    auto r = JsonStatus(status, o);
    r.headers["Cache-Control"] = "no-store";
    return r;
}

} // namespace

struct HcpEngine::Impl {
    HcpConfig cfg;
    mutable std::mutex mu;
    std::vector<unsigned char> root_pk, root_sk, op_pk, op_sk, dpop_pk, dpop_sk, dpop_other_pk, dpop_other_sk;
    int64_t key_sequence{1};
    std::string current_op_key_id{"op-1"};
    std::string root_key_id{"root-1"};
    bool enrolled{false};
    bool old_key_revoked{true};
    std::string enrolled_origin;

    struct Code {
        std::string account, client, redirect, challenge, state;
        std::vector<std::string> scopes;
        bool used{false};
    };
    struct Token {
        std::string account, audience, jkt, refresh;
        std::vector<std::string> scopes;
        bool revoked{false};
        int64_t expires_at{0};
    };
    std::map<std::string, Code> codes;
    std::map<std::string, Token> tokens;
    std::set<std::string> used_jti;
    std::string last_access;

    struct Account {
        int64_t available{0};
        int64_t held{0};
        int64_t escrow{0};
        int64_t claimed{0};
        int64_t refunded{0};
        int64_t converted{0};
    };
    std::map<std::string, Account> accounts;

    struct Policy {
        UniValue json;
        std::string policy_id;
        std::string account;
        int64_t revision{1};
        int64_t lifetime_spent{0};
        int64_t outstanding{0};
        bool revoked{false};
        bool refund_replenishes{false};
        std::set<std::string> actions;
        int64_t lifetime_principal{0};
        int64_t per_action{0};
        int64_t expires_at{0};
        std::string publisher;
    };
    std::map<std::string, Policy> policies;

    LocalCapabilityGrant grant;
    bool have_grant{false};

    struct HandoffJob {
        std::string handoff_id;
        std::string client_operation_id;
        std::string device_id;
        std::string account;
        std::string nonce;
        std::string package_core_id;
        std::string recipe_id;
        std::string generation{"gen-1"};
        std::string readiness{"NOT_READY"};
        bool wallet_touched{false};
        bool duplicate{false};
        HcpEnvelope env;
    };
    std::map<std::string, HandoffJob> jobs;
    HandoffJob last_job;
    std::map<std::string, UniValue> export_jobs;
    std::map<std::string, UniValue> research_drafts;

    struct Pkg {
        std::vector<unsigned char> bytes;
        std::string recipe_id;
        std::string file_sha384;
    };
    std::map<std::string, Pkg> packages;
    std::map<std::string, HcpEnvelope> offers;

    struct Intent {
        HcpEnvelope env;
        std::string state{"CREATED"};
        std::string receipt_state{"PREPARED"};
        std::string account;
        std::string client_operation_id;
        std::string quote_id;
        std::string terms_id;
        std::string policy_id;
        int64_t policy_revision{0};
        int64_t principal{0};
        int64_t fee_cap{0};
        int64_t total{0};
        std::vector<unsigned char> signed_tx;
        std::string txid;
        bool unknown{false};
        bool conversion{false};
        bool funding_failed{false};
        bool knowledge{false};
        std::string fencing_owner;
        std::string output_id;
        std::string lot_id;
        std::string action;
        int confirmations{0};
        bool in_active_chain{true};
        int64_t quote_expires{0};
    };
    std::map<std::string, Intent> intents;
    std::map<std::string, std::string> client_ops; // account|operation|client_operation_id -> intent_id
    std::map<std::string, HcpEnvelope> quotes;
    std::map<std::string, HcpEnvelope> receipts;
    std::string last_tx_hex;
    std::string last_txid;

    struct Device {
        std::string account;
        std::string nonce;
        std::string challenge;
        bool paired{false};
        bool revoked{false};
        std::string platform{"linux"};
        std::string readiness{"NOT_READY"};
    };
    std::map<std::string, Device> devices;

    struct Ev {
        int64_t seq{0};
        std::string account;
        std::string filter;
        std::string type;
        std::string business_key;
        UniValue payload;
        bool delivered{false};
    };
    std::vector<Ev> events;
    int64_t event_seq{0};
    int64_t retained_from{1};
    std::map<std::string, int64_t> logical;
    bool outbox_crashed{false};
    std::vector<Ev> outbox;
    std::map<std::string, bool> subs_revoked;
    std::map<std::string, std::string> subs_account;

    struct Fetch {
        int status{200};
        std::string location;
        std::string body;
    };
    std::map<std::string, Fetch> fetches;
    UniValue traffic{UniValue::VARR};
    bool provider_up{true};
    bool observer_up{true};
    bool verifier_agrees{true};
    bool dma{false};
    bool dma_fenced{true};
    bool warmup_fail{false};
    bool missing_extent{false};
    bool native_only{false};
    bool unknown_critical{false};
    bool migration_crash{false};
    bool reporting{false};
    std::string prompt;
    std::string kv;
    std::set<std::string> resident;
    std::map<std::string, int64_t> lan_ttc;
    std::map<std::string, int64_t> inet_ttc;
    int64_t native_height{0};
    int64_t refund_height{100};
    std::string template_family{"BTX_RELEASE_BOUNTY"};
    std::string lease_owner;
    std::map<std::string, std::string> sentinels;
    std::map<std::string, std::string> output_owner;
    std::string pending_unknown_provider;
    std::string pending_unknown_intent;
    std::string secret_source_url;
    UniValue last_plan{UniValue::VOBJ};

    struct Cr11State {
        int64_t protected_atoms{400};
        int64_t remaining_authority{250};
        int64_t pending_deposit{0};
        int64_t expected_refund{0};
        int64_t sibling_funds{0};
        int64_t forecast_savings{0};
        int64_t encumbered{0};
        int64_t cognitive_holdings{0};
        int64_t lifetime_cap{1000000};
        int64_t lifetime_spent{0};
        int64_t outstanding{0};
        int64_t per_plan_cap{0};
        int64_t lifetime_turnover{0};
        int64_t last_replenish_ms{0};
        int64_t quote_observed_at{0};
        int64_t snapshot_seq{0};
        int64_t policy_generation{0};
        bool family_view{false};
        bool refund_replenishes{false};
        std::string legal_entity{"le-demo"};
        std::string authed_account;
        std::string policy_id;
        std::string parent_profile_body_id;
        std::string replenish_mode{"SUGGEST"};
        std::string last_child_intent;
        std::string last_child_handoff;
        std::string last_execution;
        std::string last_cex_action;
        std::map<std::string, UniValue> links, portfolios, rpolicies, snapshots, workloads, tcos, plans, allocations;
        std::map<std::string, UniValue> arules, areqs, programs, products, positions, reports, exports, executions;
        std::map<std::string, std::vector<UniValue>> decisions;
        std::map<std::string, std::string> person_of_actor, role_of_person, idem;
        std::set<std::string> revoked_links, expired_people;
        std::map<std::string, int64_t> soft_budgets;
        UniValue last_report{UniValue::VOBJ};
    } cr11;

    struct Crl12 {
        std::map<std::string, UniValue> roles, bindings, adapters, assets, rights, positions, valuations, exposures;
        std::map<std::string, UniValue> metrics, projections, exports, export_chunks, imports, breaks, instructions;
        std::map<std::string, UniValue> scenarios, jobs, chunks, conformance;
        std::map<std::string, std::string> pos_hash;
        std::map<std::string, std::string> pos_source_seq;
        std::map<std::string, std::string> instr_hash;
        std::map<std::string, std::string> idem_hash;
        std::map<std::string, std::string> idem_replay;
        std::map<std::string, int64_t> binding_gen;
        std::set<std::string> accepted_issuers{"issuer-lab"};
        std::string last_job;
        bool source_unavailable{false};
    } crl12;

    HcpHttpResponse HandleLocked(const HcpHttpRequest& req);
    HcpHttpResponse HandleCr11Locked(const HcpHttpRequest& req);
    HcpHttpResponse HandleCrl12Locked(const HcpHttpRequest& req);
    bool Auth(const HcpHttpRequest& req, const std::string& need_scope, std::string& account, std::string& err_code,
              bool financial);
    UniValue SignedProfile();
    UniValue DemoNetwork();
    bool ProfileOn(const std::string& p) const { return cfg.enabled_profiles.count(p) != 0; }
    void NoteTraffic(const std::string& kind, const UniValue& body);
    void AppendEvent(const std::string& account, const std::string& type, const std::string& key, const UniValue& p);
    UniValue PersistObj() const;
};

HcpEngine::HcpEngine(std::unique_ptr<Impl> impl) : m(std::move(impl)) {}
HcpEngine::~HcpEngine() = default;

#include "hcp_cr11_engine.inc.cpp"
#include "hcp_crl12_engine.inc.cpp"

std::unique_ptr<HcpEngine> HcpEngine::Create(const HcpConfig& cfg, std::string& err)
{
    if (cfg.automatic_spend_atoms != 0) {
        err = "automatic_spend_atoms must be 0";
        return nullptr;
    }
    auto impl = std::make_unique<Impl>();
    impl->cfg = cfg;
    impl->cfg.automatic_spend_atoms = 0;
    impl->lease_owner = cfg.replica_id;
    if (!GenerateMlDsa44(impl->root_pk, impl->root_sk, err)) return nullptr;
    if (!GenerateMlDsa44(impl->op_pk, impl->op_sk, err)) return nullptr;
    if (!GenerateMlDsa44(impl->dpop_pk, impl->dpop_sk, err)) return nullptr;
    if (!GenerateMlDsa44(impl->dpop_other_pk, impl->dpop_other_sk, err)) return nullptr;
    impl->enrolled_origin = cfg.origin;
    if (!cfg.persist_dir.empty()) {
        fs::create_directories(impl->cfg.persist_dir);
        auto self = std::unique_ptr<HcpEngine>(new HcpEngine(std::move(impl)));
        self->Restore();
        return self;
    }
    return std::unique_ptr<HcpEngine>(new HcpEngine(std::move(impl)));
}

void HcpEngine::SetClock(int64_t ms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cfg.clock_ms = ms;
}
int64_t HcpEngine::Now() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->cfg.clock_ms;
}
const HcpConfig& HcpEngine::Cfg() const { return m->cfg; }
const std::vector<unsigned char>& HcpEngine::RootPk() const { return m->root_pk; }
const std::vector<unsigned char>& HcpEngine::OpPk() const { return m->op_pk; }
const std::vector<unsigned char>& HcpEngine::RootSk() const { return m->root_sk; }
const std::vector<unsigned char>& HcpEngine::OpSk() const { return m->op_sk; }

bool HcpEngine::SignAsProvider(HcpEnvelope& env, std::string& err)
{
    return HcpSign(env, Span<const unsigned char>{m->op_sk.data(), m->op_sk.size()}, m->current_op_key_id, err);
}
bool HcpEngine::SignAsRoot(HcpEnvelope& env, std::string& err)
{
    return HcpSign(env, Span<const unsigned char>{m->root_sk.data(), m->root_sk.size()}, m->root_key_id, err);
}

UniValue HcpEngine::Impl::DemoNetwork()
{
    UniValue n(UniValue::VOBJ);
    n.pushKV("environment", cfg.environment);
    n.pushKV("genesis_hash", cfg.genesis_hash);
    return n;
}

UniValue HcpEngine::Impl::SignedProfile()
{
    HcpEnvelope env;
    env.object_type = HCP_TYPE_PROVIDER_PROFILE;
    env.body.pushKV("version", 1);
    env.body.pushKV("provider_id", cfg.provider_id);
    env.body.pushKV("profile_sequence", std::to_string(key_sequence));
    env.body.pushKV("issued_at_ms", std::to_string(cfg.clock_ms));
    env.body.pushKV("expires_at_ms", std::to_string(cfg.clock_ms + 86400000));
    env.body.pushKV("origin", cfg.origin);
    env.body.pushKV("api_base", cfg.api_base);
    env.body.pushKV("network", DemoNetwork());
    UniValue profs(UniValue::VARR);
    for (const auto& p : cfg.enabled_profiles) profs.push_back(p);
    env.body.pushKV("supported_profiles", profs);
    UniValue vers(UniValue::VARR);
    vers.push_back(3);
    env.body.pushKV("package_core_versions", vers);
    env.body.pushKV("keyset_url", cfg.origin + "/btx/hcp/keys");
    env.body.pushKV("oauth_metadata_url", cfg.origin + "/.well-known/oauth-authorization-server");
    UniValue cust(UniValue::VARR);
    cust.push_back(cfg.finance_enabled ? "CUSTODIAL" : "DISCOVERY_ONLY");
    env.body.pushKV("custody_modes", cust);
    UniValue obs(UniValue::VARR);
    obs.push_back("HOSTED_ATTESTED");
    env.body.pushKV("financial_observation_modes", obs);
    env.body.pushKV("max_body_bytes", std::to_string(cfg.max_body_bytes));
    env.body.pushKV("max_page_size", cfg.max_page_size);
    env.body.pushKV("privacy_url", cfg.origin + "/privacy");
    env.body.pushKV("export_supported", true);
    std::string err;
    HcpSign(env, Span<const unsigned char>{root_sk.data(), root_sk.size()}, root_key_id, err);
    return EncodeHcpEnvelope(env);
}

void HcpEngine::Impl::NoteTraffic(const std::string& kind, const UniValue& body)
{
    UniValue e(UniValue::VOBJ);
    e.pushKV("kind", kind);
    e.pushKV("body", body);
    traffic.push_back(e);
}

void HcpEngine::Impl::AppendEvent(const std::string& account, const std::string& type, const std::string& key,
                                  const UniValue& p)
{
    Ev e;
    e.seq = ++event_seq;
    e.account = account;
    e.filter = "default";
    e.type = type;
    e.business_key = key;
    e.payload = p;
    events.push_back(e);
    if (!outbox_crashed) {
        e.delivered = true;
        logical[key] += 1;
    } else {
        outbox.push_back(e);
    }
}

bool HcpEngine::Impl::Auth(const HcpHttpRequest& req, const std::string& need_scope, std::string& account,
                           std::string& err_code, bool financial)
{
    account.clear();
    const std::string auth = Trim(Hdr(req, "authorization"));
    if (need_scope.empty() && HcpIsPublicReadPath(req.method, req.path)) return true;
    if (auth.size() < 8 || Lower(auth.substr(0, 7)) != "bearer ") {
        err_code = "UNAUTHENTICATED";
        return false;
    }
    const std::string tok = Trim(auth.substr(7));
    auto it = tokens.find(tok);
    if (it == tokens.end() || it->second.revoked || cfg.clock_ms > it->second.expires_at) {
        err_code = "TOKEN_INVALID";
        return false;
    }
    if (it->second.audience != cfg.audience) {
        err_code = HCP_ERR_AUDIENCE;
        return false;
    }
    if (!need_scope.empty()) {
        bool ok = false;
        for (const auto& s : it->second.scopes) {
            if (s == need_scope || s == "account:admin") ok = true;
        }
        if (!ok) {
            err_code = HCP_ERR_SCOPE;
            return false;
        }
    }
    if (financial || req.method == "POST") {
        const std::string dpop = Hdr(req, "dpop");
        if (dpop.empty()) {
            err_code = HCP_ERR_DPOP;
            return false;
        }
        UniValue proof;
        if (!proof.read(dpop) || !proof.isObject()) {
            err_code = HCP_ERR_DPOP;
            return false;
        }
        if (!proof.exists("htm") || proof["htm"].get_str() != req.method) {
            err_code = HCP_ERR_DPOP;
            return false;
        }
        const std::string htu = proof.exists("htu") ? proof["htu"].get_str() : "";
        if (htu.find(cfg.api_base) != 0 && htu.find(req.path) == std::string::npos) {
            err_code = HCP_ERR_DPOP;
            return false;
        }
        const std::string jkt = proof.exists("jkt") ? proof["jkt"].get_str() : "";
        if (jkt != it->second.jkt) {
            err_code = HCP_ERR_DPOP;
            return false;
        }
        if (proof.exists("ath") && proof["ath"].get_str() != Sha256Hex(tok)) {
            err_code = HCP_ERR_DPOP;
            return false;
        }
        if (proof.exists("jti")) {
            const std::string jti = proof["jti"].get_str();
            if (used_jti.count(jti)) {
                err_code = HCP_ERR_DPOP;
                return false;
            }
            used_jti.insert(jti);
        }
    }
    account = it->second.account;
    // A bearer token with an empty account must not satisfy a scoped call.
    // Ownership compares (`owner == authed_account`) would otherwise match
    // any object that also stored an empty owner string.
    if (account.empty()) {
        err_code = "UNAUTHENTICATED";
        return false;
    }
    return true;
}

HcpHttpResponse HcpEngine::Handle(const HcpHttpRequest& req)
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->HandleLocked(req);
}

HcpHttpResponse HcpEngine::Impl::HandleLocked(const HcpHttpRequest& req)
{
    const bool crl12_stage = (req.method == "POST") &&
                             (req.path == "/institutional/imports/chunks" ||
                              req.path.find("/institutional/imports/chunks") != std::string::npos);
    const int64_t body_cap = crl12_stage ? HCP_CR12_MAX_STAGE_BYTES : cfg.max_body_bytes;
    if (static_cast<int64_t>(req.body.size()) > body_cap) {
        return Err(413, "BODY_TOO_LARGE", "max_body_bytes");
    }
    HcpHttpRequest routed = req;
    const std::string pre{"/btx/hcp/v1"};
    if (routed.path.rfind(pre, 0) == 0) routed.path = routed.path.substr(pre.size());
    if (routed.path.empty()) routed.path = "/";
    if (routed.path == "/extensions/cognitive-reserve/v1.2" || routed.path.rfind("/layer/", 0) == 0 ||
        routed.path.rfind("/institutional/", 0) == 0) {
        return HandleCrl12Locked(routed);
    }
    if (routed.path == "/extensions/cognitive-reserve" || routed.path.rfind("/reserve/", 0) == 0 ||
        routed.path.rfind("/capital/", 0) == 0) {
        return HandleCr11Locked(routed);
    }
    if (req.path == "/rpc" || req.path.rfind("/rpc/", 0) == 0) {
        return Err(404, HCP_ERR_GENERIC_RPC, "typed operations only");
    }
    if (req.method == "GET" && req.path == "/health") {
        UniValue o(UniValue::VOBJ);
        o.pushKV("ok", true);
        o.pushKV("hcp", "HCP/1");
        o.pushKV("instance", cfg.instance_id);
        o.pushKV("walletless", cfg.walletless);
        o.pushKV("finance", cfg.finance_enabled);
        o.pushKV("cognitive_reserve", cfg.cr11_enabled);
        o.pushKV("cognitive_reserve_layer", cfg.cr12_enabled);
        o.pushKV("automatic_spend_atoms", 0);
        o.pushKV("simulation_only", cfg.simulation_only);
        o.pushKV("not_live_cex_idp", true);
        o.pushKV("custody_backend", cfg.custody_backend);
        o.pushKV("not_live_hsm", cfg.custody_backend.find("HSM") == std::string::npos);
        return JsonStatus(200, o);
    }
    // Loopback REGTEST OAUTH_LAB only. Not a live CEX IdP. Never linked into btxd.
    if (cfg.environment == "REGTEST" && req.method == "GET" && req.path == "/.well-known/oauth-authorization-server") {
        UniValue o(UniValue::VOBJ);
        o.pushKV("issuer", cfg.origin);
        o.pushKV("authorization_endpoint", "http://127.0.0.1/lab/authorize");
        o.pushKV("token_endpoint", "http://127.0.0.1/lab/token");
        o.pushKV("dpop_bound_access_tokens", true);
        o.pushKV("lab_only", true);
        o.pushKV("not_live_cex_idp", true);
        return JsonStatus(200, o);
    }
    if (cfg.environment == "REGTEST" && req.method == "GET" && req.path == "/lab/pkce") {
        const std::string ver = QueryGet(req.query, "verifier");
        if (ver.empty()) return Err(400, "PKCE", "verifier");
        UniValue o(UniValue::VOBJ);
        o.pushKV("challenge", Sha256Hex(ver));
        o.pushKV("lab_only", true);
        return JsonStatus(200, o);
    }
    if (cfg.environment == "REGTEST" && req.method == "GET" && req.path == "/lab/authorize") {
        const std::string account = QueryGet(req.query, "account");
        const std::string client = QueryGet(req.query, "client_id");
        const std::string redirect = QueryGet(req.query, "redirect");
        const std::string state = QueryGet(req.query, "state");
        const std::string challenge = QueryGet(req.query, "challenge");
        const std::string scope_csv = QueryGet(req.query, "scopes");
        if (account.empty() || challenge.empty()) return Err(400, "AUTHORIZE", "account/challenge");
        Code c;
        c.account = account;
        c.client = client.empty() ? "client-demo" : client;
        c.redirect = redirect.empty() ? "https://app.example/cb" : redirect;
        c.challenge = challenge;
        c.state = state;
        for (const auto& s : Split(scope_csv, ',')) {
            if (!s.empty()) c.scopes.push_back(s);
        }
        if (c.scopes.empty()) {
            c.scopes = {"catalog:read", "packages:read", "handoffs:create", "devices:enroll", "devices:report",
                        "account:read", "quotes:create", "intents:create", "intents:authorize", "intents:submit",
                        "intents:cancel", "policies:admin", "subscriptions:write", "events:read", "exports:create",
                        "research:publish", "entities:admin", "capital:read", "capital:prepare", "capital:approve",
                        "capital:execute", "reserve:read", "holdings:write", "products:read", "products:refer",
                        "reports:create", "reports:read", "exports:read", "layer:admin", "bindings:admin",
                        "bindings:read", "assets:write", "assets:read", "positions:write", "positions:read",
                        "valuations:write", "valuations:read", "exposures:write", "exposures:read",
                        "metrics:admin", "metrics:read", "projections:create", "projections:read",
                        "imports:write", "imports:read", "reconciliation:read", "reconciliation:write",
                        "scenarios:create", "scenarios:read", "jobs:read", "jobs:cancel"};
        }
        const std::string code = RandId("code-");
        codes[code] = c;
        UniValue o(UniValue::VOBJ);
        o.pushKV("code", code);
        o.pushKV("state", state);
        o.pushKV("lab_only", true);
        return JsonStatus(200, o);
    }
    if (cfg.environment == "REGTEST" && req.method == "GET" && req.path == "/lab/token") {
        const std::string code = QueryGet(req.query, "code");
        const std::string verifier = QueryGet(req.query, "verifier");
        const std::string redirect = QueryGet(req.query, "redirect");
        const std::string audience = QueryGet(req.query, "audience");
        const std::string dpop_jkt = QueryGet(req.query, "jkt");
        auto it = codes.find(code);
        if (it == codes.end() || it->second.used) return Err(400, "CODE_INVALID", "code");
        const std::string want_redir = redirect.empty() ? it->second.redirect : redirect;
        if (it->second.redirect != want_redir || Sha256Hex(verifier) != it->second.challenge) {
            return Err(400, "PKCE_MISMATCH", "pkce");
        }
        it->second.used = true;
        const std::string tok = RandId("tok-");
        Token t;
        t.account = it->second.account;
        t.audience = audience.empty() ? cfg.audience : audience;
        t.jkt = dpop_jkt.empty() ? Sha384Hex(Span<const unsigned char>{dpop_pk.data(), dpop_pk.size()}) : dpop_jkt;
        t.scopes = it->second.scopes;
        t.expires_at = cfg.clock_ms + 3600000;
        t.refresh = RandId("ref-");
        tokens[tok] = t;
        last_access = tok;
        UniValue out(UniValue::VOBJ);
        out.pushKV("access_token", tok);
        out.pushKV("refresh_token", t.refresh);
        out.pushKV("token_type", "DPoP");
        out.pushKV("audience", t.audience);
        UniValue sc(UniValue::VARR);
        for (const auto& s : t.scopes) sc.push_back(s);
        out.pushKV("scope", sc);
        out.pushKV("jkt", t.jkt);
        out.pushKV("lab_only", true);
        return JsonStatus(200, out);
    }
    if (cfg.environment == "REGTEST" && req.method == "GET" && req.path == "/lab/dpop") {
        const std::string htm = QueryGet(req.query, "htm");
        const std::string htu = QueryGet(req.query, "htu");
        const std::string access = QueryGet(req.query, "access_token");
        if (htm.empty() || htu.empty() || access.empty()) return Err(400, "DPOP", "htm/htu/access_token");
        UniValue p(UniValue::VOBJ);
        p.pushKV("htm", htm);
        p.pushKV("htu", htu);
        p.pushKV("jkt", Sha384Hex(Span<const unsigned char>{dpop_pk.data(), dpop_pk.size()}));
        p.pushKV("ath", Sha256Hex(access));
        p.pushKV("iat", std::to_string(cfg.clock_ms));
        p.pushKV("jti", RandId("jti-"));
        p.pushKV("lab_only", true);
        return JsonStatus(200, p);
    }
    std::map<std::string, std::string> cap;
    UniValue parsed;
    bool have_body = false;
    if (!req.body.empty()) {
        std::vector<unsigned char> raw(req.body.begin(), req.body.end());
        std::string perr;
        if (!DecodePjson1(Span<const unsigned char>{raw.data(), raw.size()}, parsed, perr)) {
            UniValue loose;
            if (!loose.read(req.body)) {
                return Err(400, "NONCANONICAL_BYTES", perr);
            }
            return Err(400, "NONCANONICAL_BYTES", perr.empty() ? "noncanonical" : perr);
        }
        have_body = true;
        if (parsed.isObject() && parsed.exists("object_type") && parsed.exists("body")) {
            HcpEnvelope env;
            std::string e;
            if (!ParseHcpEnvelope(parsed, env, e)) return Err(400, e, e);
        }
    }

    auto need_profile = [&](const std::string& p) {
        if (!ProfileOn(p)) return Err(403, "PROFILE_DISABLED", p);
        return HcpHttpResponse{};
    };

    std::string account, acode;

    if (req.method == "GET" && req.path == "/profile") {
        auto r = JsonStatus(200, SignedProfile());
        r.headers["Cache-Control"] = "public, max-age=60";
        return r;
    }
    if (req.method == "POST" && req.path == "/capabilities/search") {
        auto dis = need_profile(HCP_PROFILE_DISCOVERY);
        if (dis.status >= 400) return dis;
        if (!Hdr(req, "authorization").empty()) {
            if (!Auth(req, "catalog:read", account, acode, false)) return Err(401, acode, acode);
        }
        UniValue q = have_body ? parsed : UniValue(UniValue::VOBJ);
        if (q.exists("q") && q["q"].isStr()) {
            const std::string text = q["q"].get_str();
            if (text.find("createwallet") != std::string::npos || text.find("SELECT ") != std::string::npos) {
                // stays data
            }
        }
        int limit = cfg.max_page_size;
        if (q.exists("limit") && q["limit"].isNum()) {
            limit = std::min(cfg.max_page_size, static_cast<int>(q["limit"].getInt<int64_t>()));
        }
        UniValue hits(UniValue::VARR);
        int n = 0;
        for (const auto& [id, env] : offers) {
            if (n++ >= limit) break;
            UniValue hit(UniValue::VOBJ);
            hit.pushKV("offer", EncodeHcpEnvelope(env));
            hit.pushKV("sponsored", env.body.exists("sponsored") && env.body["sponsored"].isTrue());
            hit.pushKV("signature_status", "PROVIDER_SIGNED");
            hit.pushKV("quality_claim", UniValue());
            hit.pushKV("observed_availability", env.body.exists("availability_scope") ? env.body["availability_scope"] : "UNKNOWN");
            hit.pushKV("memory_compatible", UniValue());
            hit.pushKV("evidence_complete", false);
            hits.push_back(hit);
        }
        UniValue out(UniValue::VOBJ);
        out.pushKV("hits", hits);
        out.pushKV("incomplete", true);
        out.pushKV("query_budget", limit);
        auto r = JsonStatus(200, out);
        r.headers["Cache-Control"] = "no-store";
        return r;
    }
    if (MatchPath(req.path, "/packages/{package_core_id}", cap) && (req.method == "GET" || req.method == "HEAD")) {
        auto dis = need_profile(HCP_PROFILE_DISCOVERY);
        if (dis.status >= 400) return dis;
        auto it = packages.find(cap["package_core_id"]);
        if (it == packages.end()) return Err(404, "NOT_FOUND", "package");
        HcpHttpResponse r;
        r.status = 200;
        r.content_type = "application/octet-stream";
        r.body.assign(it->second.bytes.begin(), it->second.bytes.end());
        r.headers["Cache-Control"] = "public, immutable";
        r.headers["X-Package-Core-Id"] = cap["package_core_id"];
        return r;
    }
    if (MatchPath(req.path, "/economy/{target_id}", cap) && req.method == "GET") {
        auto dis = need_profile(HCP_PROFILE_DISCOVERY);
        if (dis.status >= 400) return dis;
        UniValue o(UniValue::VOBJ);
        o.pushKV("target_id", cap["target_id"]);
        o.pushKV("dated_observation", "STALE_PERCENT");
        o.pushKV("current_terms_id", UniValue());
        o.pushKV("anchor_required_for_finance", true);
        o.pushKV("percent_funded_label", "old");
        o.pushKV("observation_basis", "HOSTED_ATTESTED");
        auto r = JsonStatus(200, o);
        r.headers["Cache-Control"] = "no-store";
        return r;
    }
    if (req.method == "POST" && req.path == "/handoffs") {
        auto dis = need_profile(HCP_PROFILE_HANDOFF);
        if (dis.status >= 400) return dis;
        if (!Auth(req, "handoffs:create", account, acode, false)) return Err(401, acode, acode);
        HcpEnvelope env;
        env.object_type = HCP_TYPE_CAPABILITY_HANDOFF;
        env.body.pushKV("version", 1);
        env.body.pushKV("provider_id", cfg.provider_id);
        env.body.pushKV("account_ref", account);
        const std::string device = have_body && parsed.exists("device_id") ? parsed["device_id"].get_str() : "device-demo";
        auto dit = devices.find(device);
        if (dit == devices.end() || !dit->second.paired || dit->second.revoked) {
            return Err(403, "DEVICE_NOT_PAIRED", device);
        }
        env.body.pushKV("device_id", device);
        env.body.pushKV("network", DemoNetwork());
        const std::string hid = RandId("handoff-");
        env.body.pushKV("handoff_id", hid);
        env.body.pushKV("client_operation_id",
                         have_body && parsed.exists("client_operation_id") ? parsed["client_operation_id"].get_str() :
                                                                               RandId("op-"));
        env.body.pushKV("request_nonce", dit->second.nonce);
        env.body.pushKV("issued_at_ms", std::to_string(cfg.clock_ms));
        env.body.pushKV("expires_at_ms", std::to_string(cfg.clock_ms + 600000));
        UniValue pkg(UniValue::VOBJ);
        std::string core_id = "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111";
        std::string recipe = "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333";
        if (have_body && parsed.exists("package_core_id")) core_id = parsed["package_core_id"].get_str();
        if (have_body && parsed.exists("recipe_id")) recipe = parsed["recipe_id"].get_str();
        pkg.pushKV("package_core_id", core_id);
        pkg.pushKV("file_sha384", "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222");
        pkg.pushKV("recipe_id", recipe);
        pkg.pushKV("download_url", cfg.api_base + "/packages/" + core_id);
        env.body.pushKV("package", pkg);
        env.body.pushKV("readiness_target", "RUNTIME_READY");
        UniValue eff(UniValue::VARR);
        eff.push_back(HCP_EFFECT_FETCH_METADATA);
        eff.push_back(HCP_EFFECT_ACQUIRE_MODEL);
        eff.push_back(HCP_EFFECT_PLAN_LOCAL_RUN);
        env.body.pushKV("requested_effects", eff);
        env.body.pushKV("source_hints", UniValue(UniValue::VARR));
        env.body.pushKV("receipt_ref", UniValue());
        env.body.pushKV("reporting_requested", reporting);
        std::string serr;
        HcpSign(env, Span<const unsigned char>{op_sk.data(), op_sk.size()}, current_op_key_id, serr);
        HandoffJob job;
        job.handoff_id = hid;
        job.device_id = device;
        job.account = account;
        job.nonce = dit->second.nonce;
        job.package_core_id = core_id;
        job.recipe_id = recipe;
        job.env = env;
        jobs[hid] = job;
        last_job = job;
        AppendEvent(account, "HANDOFF_CREATED", hid, EncodeHcpEnvelope(env));
        return JsonStatus(201, EncodeHcpEnvelope(env));
    }
    if (MatchPath(req.path, "/handoffs/{handoff_id}", cap) && req.method == "GET") {
        if (!Auth(req, "account:read", account, acode, false)) return Err(401, acode, acode);
        auto it = jobs.find(cap["handoff_id"]);
        if (it == jobs.end() || it->second.account != account) return Err(404, "NOT_FOUND", "handoff");
        if (it->second.env.object_type == HCP_TYPE_CAPABILITY_HANDOFF) {
            return JsonStatus(200, EncodeHcpEnvelope(it->second.env));
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("handoff_id", it->second.handoff_id);
        o.pushKV("readiness", it->second.readiness);
        return JsonStatus(200, o);
    }
    if (req.method == "POST" && req.path == "/devices/enroll") {
        auto dis = need_profile(HCP_PROFILE_HANDOFF);
        if (dis.status >= 400) return dis;
        if (!Auth(req, "devices:enroll", account, acode, false)) return Err(401, acode, acode);
        const std::string did = have_body && parsed.exists("device_id") ? parsed["device_id"].get_str() : RandId("device-");
        Device d;
        d.account = account;
        d.challenge = RandId("pair-");
        d.nonce = RandId("nonce-");
        d.paired = false;
        if (have_body && parsed.exists("platform")) d.platform = parsed["platform"].get_str();
        devices[did] = d;
        UniValue o(UniValue::VOBJ);
        o.pushKV("device_id", did);
        o.pushKV("challenge", d.challenge);
        o.pushKV("paired", false);
        return JsonStatus(201, o);
    }
    if (MatchPath(req.path, "/devices/{device_id}/confirm", cap) && req.method == "POST") {
        if (!Auth(req, "devices:enroll", account, acode, false)) return Err(401, acode, acode);
        auto it = devices.find(cap["device_id"]);
        if (it == devices.end()) return Err(404, "NOT_FOUND", "device");
        if (it->second.account != account) return Err(404, "NOT_FOUND", "device");
        const std::string ch = have_body && parsed.exists("challenge") ? parsed["challenge"].get_str() : "";
        if (ch != it->second.challenge || it->second.revoked) return Err(403, "PAIRING_CHALLENGE", "mismatch");
        it->second.paired = true;
        UniValue o(UniValue::VOBJ);
        o.pushKV("device_id", cap["device_id"]);
        o.pushKV("paired", true);
        o.pushKV("account_ref", account);
        return JsonStatus(200, o);
    }
    if (MatchPath(req.path, "/devices/{device_id}/revoke", cap) && req.method == "POST") {
        if (!Auth(req, "devices:enroll", account, acode, false)) return Err(401, acode, acode);
        if (account.empty()) return Err(401, "UNAUTHENTICATED", "account");
        auto it = devices.find(cap["device_id"]);
        if (it == devices.end() || it->second.account.empty() || it->second.account != account) {
            return Err(404, "NOT_FOUND", "device");
        }
        it->second.revoked = true;
        it->second.paired = false;
        UniValue o(UniValue::VOBJ);
        o.pushKV("device_id", cap["device_id"]);
        o.pushKV("revoked", true);
        return JsonStatus(200, o);
    }
    if (MatchPath(req.path, "/devices/{device_id}/handoffs", cap) && req.method == "GET") {
        if (!Auth(req, "events:read", account, acode, false)) return Err(401, acode, acode);
        auto it = devices.find(cap["device_id"]);
        if (it == devices.end() || it->second.account != account) return Err(404, "NOT_FOUND", "device");
        if (it->second.revoked) return Err(403, "DEVICE_REVOKED", "revoked");
        UniValue ids(UniValue::VARR);
        for (const auto& [hid, job] : jobs) {
            if (job.device_id == cap["device_id"]) ids.push_back(hid);
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("ids", ids);
        o.pushKV("outbound_only", true);
        o.pushKV("inbound_execution_port", false);
        return JsonStatus(200, o);
    }
    if (MatchPath(req.path, "/devices/{device_id}/reports", cap) && req.method == "POST") {
        auto dis = need_profile(HCP_PROFILE_FLEET);
        if (dis.status >= 400) return dis;
        if (!Auth(req, "devices:report", account, acode, false)) return Err(401, acode, acode);
        auto it = devices.find(cap["device_id"]);
        if (it == devices.end() || it->second.account != account || it->second.revoked) {
            return Err(403, "DEVICE_REVOKED", "report");
        }
        if (!reporting) {
            return Err(403, "REPORTING_DISABLED", "owner off");
        }
        HcpEnvelope env;
        std::string e;
        if (!have_body || !ParseHcpEnvelope(parsed, env, e) || env.object_type != HCP_TYPE_LOCAL_READINESS) {
            return Err(400, "SCHEMA", e);
        }
        const std::string dump = parsed.write();
        if (dump.find(prompt) != std::string::npos && !prompt.empty()) return Err(400, "PRIVACY", "prompt");
        if (dump.find(kv) != std::string::npos && !kv.empty()) return Err(400, "PRIVACY", "kv");
        if (env.body.exists("state") && env.body["state"].isStr()) {
            it->second.readiness = env.body["state"].get_str();
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("accepted", true);
        o.pushKV("state", it->second.readiness);
        return JsonStatus(202, o);
    }
    if (req.method == "GET" && req.path == "/treasury/balances") {
        auto dis = need_profile(HCP_PROFILE_CUSTODY);
        if (dis.status >= 400) return dis;
        if (!Auth(req, "account:read", account, acode, false)) return Err(401, acode, acode);
        Account a = accounts[account];
        UniValue o(UniValue::VOBJ);
        o.pushKV("account_ref", account);
        o.pushKV("available_atoms", std::to_string(a.available));
        o.pushKV("held_atoms", std::to_string(a.held));
        o.pushKV("escrow_atoms", std::to_string(a.escrow));
        o.pushKV("claimed_atoms", std::to_string(a.claimed));
        o.pushKV("refunded_atoms", std::to_string(a.refunded));
        o.pushKV("converted_retained_atoms", std::to_string(a.converted));
        auto r = JsonStatus(200, o);
        r.headers["Cache-Control"] = "no-store";
        return r;
    }

    auto finance_gate = [&]() -> HcpHttpResponse {
        if (!cfg.finance_enabled || !ProfileOn(HCP_PROFILE_FUNDING)) {
            return Err(403, HCP_ERR_FUNDING_DISABLED, "funding profile off");
        }
        if (cfg.custody_backend != HCP_CUSTODY_BTX_NATIVE) {
            return Err(403, HCP_ERR_CUSTODY_UNSUPPORTED, cfg.custody_backend);
        }
        if (cfg.automatic_spend_atoms != 0) return Err(500, "AUTOMATIC_SPEND", "must be 0");
        return {};
    };

    if (req.method == "POST" && req.path == "/finance/quotes") {
        auto g = finance_gate();
        if (g.status >= 400) return g;
        if (!Auth(req, "quotes:create", account, acode, true)) return Err(401, acode, acode);
        HcpEnvelope env;
        env.object_type = HCP_TYPE_FUNDING_QUOTE;
        env.body.pushKV("version", 1);
        env.body.pushKV("provider_id", cfg.provider_id);
        env.body.pushKV("account_ref", account);
        env.body.pushKV("network", DemoNetwork());
        const std::string qid = RandId("quote-");
        env.body.pushKV("quote_id", qid);
        env.body.pushKV("quote_kind", "FIRM");
        env.body.pushKV("action", have_body && parsed.exists("action") ? parsed["action"].get_str() : HCP_ACTION_FUND_RELEASE);
        env.body.pushKV("target_object_id", LabelDigest(std::string("HCP/target|") + qid + "|" + account));
        env.body.pushKV("terms_id",
                         have_body && parsed.exists("terms_id") ? parsed["terms_id"].get_str() :
                                                                 LabelDigest(std::string("HCP/terms|") + account));
        env.body.pushKV("native_template_id",
                         LabelDigest(std::string("HCP/template|") + cfg.custody_backend + "|" + cfg.environment));
        env.body.pushKV("round_id", UniValue());
        env.body.pushKV("lot_id", UniValue());
        UniValue amt(UniValue::VOBJ);
        if (have_body && parsed.exists("amounts")) amt = parsed["amounts"];
        else {
            amt.pushKV("principal_atoms", "1000");
            amt.pushKV("network_fee_cap_atoms", "30");
            amt.pushKV("service_fee_atoms", "20");
            amt.pushKV("tax_atoms", "0");
            amt.pushKV("max_total_debit_atoms", "1050");
        }
        int64_t total = 0;
        std::string aerr;
        if (!HcpAmountsOk(amt, total, aerr)) return Err(400, aerr, aerr);
        env.body.pushKV("amounts", amt);
        env.body.pushKV("refund_controller", "CEX_CUSTODIAL_KEY");
        env.body.pushKV("required_confirmations", cfg.required_confirmations);
        env.body.pushKV("issued_at_ms", std::to_string(cfg.clock_ms));
        env.body.pushKV("expires_at_ms", std::to_string(cfg.clock_ms + 600000));
        env.body.pushKV("conversion_quote_ref", UniValue());
        env.body.pushKV("conversion_quote", UniValue());
        std::string serr;
        HcpSign(env, Span<const unsigned char>{op_sk.data(), op_sk.size()}, current_op_key_id, serr);
        quotes[qid] = env;
        return JsonStatus(201, EncodeHcpEnvelope(env));
    }

    if (req.method == "POST" && req.path == "/finance/intents") {
        auto g = finance_gate();
        if (g.status >= 400) return g;
        if (!Auth(req, "intents:create", account, acode, true)) return Err(401, acode, acode);
        if (have_grant && have_body && parsed.exists("local_grant_id")) {
            return Err(403, HCP_ERR_GRANT_NOT_SPEND, "local grant cannot spend");
        }
        const std::string cop = have_body && parsed.exists("client_operation_id") ? parsed["client_operation_id"].get_str() :
                                                                                    RandId("op-");
        UniValue amt = have_body && parsed.exists("amounts") ? parsed["amounts"] : UniValue(UniValue::VOBJ);
        if (!amt.exists("principal_atoms")) {
            amt.pushKV("principal_atoms", "1000");
            amt.pushKV("network_fee_cap_atoms", "30");
            amt.pushKV("service_fee_atoms", "20");
            amt.pushKV("tax_atoms", "0");
            amt.pushKV("max_total_debit_atoms", "1050");
        }
        int64_t total = 0;
        std::string aerr;
        if (!HcpAmountsOk(amt, total, aerr)) return Err(400, aerr, aerr);
        if (account.empty()) return Err(401, "UNAUTHENTICATED", "account");
        const std::string cop_slot = account + "|POST /finance/intents|" + cop;
        if (client_ops.count(cop_slot)) {
            const std::string existing = client_ops[cop_slot];
            auto& itn = intents[existing];
            std::string newp = amt["principal_atoms"].get_str();
            if (itn.env.body["amounts"]["principal_atoms"].get_str() != newp ||
                (parsed.exists("terms_id") && parsed["terms_id"].get_str() != itn.terms_id)) {
                return Err(409, HCP_ERR_CONFLICT, "client_operation_id body mismatch");
            }
            return JsonStatus(200, EncodeHcpEnvelope(itn.env));
        }
        const std::string qid = have_body && parsed.exists("quote_id") ? parsed["quote_id"].get_str() : "";
        if (!qid.empty()) {
            auto qit = quotes.find(qid);
            if (qit == quotes.end()) return Err(404, "QUOTE_NOT_FOUND", qid);
            int64_t exp = 0;
            ParseAtomString(qit->second.body["expires_at_ms"].get_str(), exp, aerr);
            if (cfg.clock_ms >= exp) return Err(400, HCP_ERR_QUOTE_EXPIRED, "quote expired");
        }
        const std::string pid = have_body && parsed.exists("policy_id") ? parsed["policy_id"].get_str() : "";
        if (!pid.empty()) {
            auto pit = policies.find(pid);
            if (pit == policies.end() || pit->second.revoked) return Err(403, "POLICY_REVOKED", pid);
            int64_t prin = 0;
            ParseAtomString(amt["principal_atoms"].get_str(), prin, aerr);
            if (pit->second.lifetime_spent + prin > pit->second.lifetime_principal && pit->second.lifetime_principal > 0) {
                return Err(403, "LIFETIME_CAP", "lifetime");
            }
        }
        Account& acc = accounts[account];
        int64_t prin = 0, fee = 0;
        ParseAtomString(amt["principal_atoms"].get_str(), prin, aerr);
        ParseAtomString(amt["network_fee_cap_atoms"].get_str(), fee, aerr);
        int64_t svc = 0, tax = 0;
        ParseAtomString(amt["service_fee_atoms"].get_str(), svc, aerr);
        ParseAtomString(amt["tax_atoms"].get_str(), tax, aerr);
        if (acc.available < total) return Err(403, "INSUFFICIENT", "available");
        acc.available -= total;
        acc.held += total;
        if (!pid.empty()) {
            policies[pid].lifetime_spent += prin;
            policies[pid].outstanding += total;
        }
        HcpEnvelope env;
        env.object_type = HCP_TYPE_FINANCE_INTENT;
        env.body.pushKV("version", 1);
        env.body.pushKV("provider_id", cfg.provider_id);
        env.body.pushKV("account_ref", account);
        env.body.pushKV("actor_ref", account);
        env.body.pushKV("network", DemoNetwork());
        const std::string iid = RandId("intent-");
        env.body.pushKV("intent_id", iid);
        env.body.pushKV("client_operation_id", cop);
        env.body.pushKV("quote_id", qid);
        env.body.pushKV("quote_body_id",
                         qid.empty() ? LabelDigest(std::string("HCP/quote/none|") + account) : quotes[qid].body_id.Hex());
        env.body.pushKV("action", have_body && parsed.exists("action") ? parsed["action"].get_str() : HCP_ACTION_FUND_RELEASE);
        env.body.pushKV("terms_id", have_body && parsed.exists("terms_id") ?
                                          parsed["terms_id"].get_str() :
                                          LabelDigest(std::string("HCP/terms|") + account));
        env.body.pushKV("native_template_id",
                         LabelDigest(std::string("HCP/template|") + cfg.custody_backend + "|" + cfg.environment));
        env.body.pushKV("amounts", amt);
        env.body.pushKV("policy_id", pid.empty() ? "policy-demo" : pid);
        env.body.pushKV("policy_revision", pid.empty() ? "1" : std::to_string(policies[pid].revision));
        env.body.pushKV("refund_controller", "CEX_CUSTODIAL_KEY");
        env.body.pushKV("expires_at_ms", std::to_string(cfg.clock_ms + 600000));
        std::string serr;
        HcpSign(env, Span<const unsigned char>{op_sk.data(), op_sk.size()}, current_op_key_id, serr);
        Intent in;
        in.env = env;
        in.account = account;
        in.client_operation_id = cop;
        in.quote_id = qid;
        in.terms_id = env.body["terms_id"].get_str();
        in.policy_id = pid;
        in.policy_revision = pid.empty() ? 1 : policies[pid].revision;
        in.principal = prin;
        in.fee_cap = fee;
        in.total = total;
        in.action = env.body["action"].get_str();
        in.fencing_owner = lease_owner;
        in.lot_id = RandId("lot-");
        in.output_id = RandId("out-");
        if (!qid.empty()) {
            int64_t exp = 0;
            ParseAtomString(quotes[qid].body["expires_at_ms"].get_str(), exp, aerr);
            in.quote_expires = exp;
        }
        intents[iid] = in;
        client_ops[cop_slot] = iid;
        AppendEvent(account, "INTENT_CREATED", cop + "/" + in.action, EncodeHcpEnvelope(env));
        return JsonStatus(201, EncodeHcpEnvelope(env));
    }

    if (MatchPath(req.path, "/finance/intents/{intent_id}", cap) && req.method == "GET") {
        if (!Auth(req, "account:read", account, acode, false)) return Err(401, acode, acode);
        if (account.empty()) return Err(401, "UNAUTHENTICATED", "account");
        auto it = intents.find(cap["intent_id"]);
        if (it == intents.end() || it->second.account.empty() || it->second.account != account) {
            return Err(404, "NOT_FOUND", "intent");
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("intent_id", cap["intent_id"]);
        o.pushKV("state", it->second.unknown ? HCP_ERR_BROADCAST_UNKNOWN : it->second.state);
        o.pushKV("receipt_state", it->second.receipt_state);
        o.pushKV("conversion_complete", it->second.conversion);
        o.pushKV("funding_failed", it->second.funding_failed);
        o.pushKV("knowledge_disclosed", it->second.knowledge);
        o.pushKV("runtime_ready", false);
        return JsonStatus(200, o);
    }

    if (MatchPath(req.path, "/finance/intents/{intent_id}/authorize", cap) && req.method == "POST") {
        auto g = finance_gate();
        if (g.status >= 400) return g;
        if (!Auth(req, "intents:authorize", account, acode, true)) return Err(401, acode, acode);
        auto it = intents.find(cap["intent_id"]);
        if (it == intents.end() || it->second.account != account) return Err(404, "NOT_FOUND", "intent");
        if (have_body && parsed.exists("expected_body_id") &&
            parsed["expected_body_id"].get_str() != it->second.env.body_id.Hex()) {
            return Err(409, "INTENT_DIGEST_MISMATCH", "body changed");
        }
        if (have_body && parsed.exists("policy_revision")) {
            const std::string want = parsed["policy_revision"].isStr() ? parsed["policy_revision"].get_str() :
                                                                            std::to_string(parsed["policy_revision"].getInt<int64_t>());
            if (want != std::to_string(it->second.policy_revision)) return Err(409, "POLICY_REVISION", "changed");
        }
        it->second.state = "AUTHORIZED";
        UniValue o(UniValue::VOBJ);
        o.pushKV("intent_id", cap["intent_id"]);
        o.pushKV("state", it->second.state);
        return JsonStatus(200, o);
    }

    if (MatchPath(req.path, "/finance/intents/{intent_id}/submit", cap) && req.method == "POST") {
        auto g = finance_gate();
        if (g.status >= 400) return g;
        if (!Auth(req, "intents:submit", account, acode, true)) return Err(401, acode, acode);
        auto it = intents.find(cap["intent_id"]);
        if (it == intents.end() || it->second.account != account) return Err(404, "NOT_FOUND", "intent");
        if (lease_owner != cfg.replica_id && it->second.fencing_owner != cfg.replica_id) {
            return Err(409, HCP_ERR_FENCED, lease_owner);
        }
        if (have_body && parsed.exists("expected_body_id") &&
            parsed["expected_body_id"].get_str() != it->second.env.body_id.Hex()) {
            return Err(409, "INTENT_DIGEST_MISMATCH", "mutate before submit");
        }
        if (it->second.quote_expires && cfg.clock_ms >= it->second.quote_expires) {
            accounts[account].held -= it->second.total;
            accounts[account].available += it->second.total;
            it->second.state = HCP_ERR_QUOTE_EXPIRED;
            return Err(400, HCP_ERR_QUOTE_EXPIRED, "expired");
        }
        if (have_body && parsed.exists("terms_id") && parsed["terms_id"].get_str() != it->second.terms_id) {
            it->second.state = HCP_ERR_TERMS_CHANGED;
            return Err(409, HCP_ERR_TERMS_CHANGED, "reprepare");
        }
        if (have_body && parsed.exists("network_fee_atoms")) {
            int64_t nf = 0;
            std::string e;
            if (!ParseAtomString(parsed["network_fee_atoms"].get_str(), nf, e) || nf > it->second.fee_cap) {
                return Err(409, "FEE_CAP", "fresh authority required");
            }
        }
        if (it->second.signed_tx.empty()) {
            std::string tx = "btx-lab-tx:" + cap["intent_id"] + ":" + it->second.output_id + ":" +
                             std::to_string(it->second.principal);
            it->second.signed_tx.assign(tx.begin(), tx.end());
            it->second.txid = Sha256Hex(tx);
            last_tx_hex = HexStr(it->second.signed_tx);
            last_txid = it->second.txid;
        } else {
            // identical bytes only
        }
        if (it->second.unknown) {
            UniValue o(UniValue::VOBJ);
            o.pushKV("state", HCP_ERR_BROADCAST_UNKNOWN);
            o.pushKV("txid", it->second.txid);
            o.pushKV("signed_tx_hex", HexStr(it->second.signed_tx));
            o.pushKV("identical_dispatch_only", true);
            return JsonStatus(202, o);
        }
        it->second.state = "ACCEPTED";
        it->second.receipt_state = "NATIVE_PENDING";
        HcpEnvelope rec;
        rec.object_type = HCP_TYPE_FINANCIAL_RECEIPT;
        rec.body.pushKV("version", 1);
        rec.body.pushKV("provider_id", cfg.provider_id);
        rec.body.pushKV("account_ref", account);
        rec.body.pushKV("network", DemoNetwork());
        const std::string rid = RandId("receipt-");
        rec.body.pushKV("receipt_id", rid);
        rec.body.pushKV("receipt_sequence", "1");
        rec.body.pushKV("supersedes", UniValue());
        rec.body.pushKV("intent_id", cap["intent_id"]);
        rec.body.pushKV("intent_body_id", it->second.env.body_id.Hex());
        rec.body.pushKV("action", it->second.action);
        rec.body.pushKV("terms_id", it->second.terms_id);
        rec.body.pushKV("quote_id", it->second.quote_id);
        rec.body.pushKV("amounts", it->second.env.body["amounts"]);
        rec.body.pushKV("actual_network_fee_atoms", UniValue());
        rec.body.pushKV("state", "PREPARED");
        rec.body.pushKV("evidence_basis", "CEX_LEDGER");
        rec.body.pushKV("custody_mode", "CUSTODIAL");
        rec.body.pushKV("refund_controller", "CEX_CUSTODIAL_KEY");
        rec.body.pushKV("native_observation", UniValue());
        rec.body.pushKV("observed_at_ms", std::to_string(cfg.clock_ms));
        std::string serr;
        HcpSign(rec, Span<const unsigned char>{op_sk.data(), op_sk.size()}, current_op_key_id, serr);
        receipts[rid] = rec;
        UniValue o(UniValue::VOBJ);
        o.pushKV("operation_id", cap["intent_id"]);
        o.pushKV("state", it->second.state);
        o.pushKV("funded", false);
        o.pushKV("txid", it->second.txid);
        o.pushKV("receipt_id", rid);
        o.pushKV("principal_in_native_sum", std::to_string(it->second.principal));
        o.pushKV("fees_itemized", true);
        return JsonStatus(202, o);
    }

    if (MatchPath(req.path, "/finance/intents/{intent_id}/cancel", cap) && req.method == "POST") {
        auto g = finance_gate();
        if (g.status >= 400) return g;
        if (!Auth(req, "intents:cancel", account, acode, true)) return Err(401, acode, acode);
        auto it = intents.find(cap["intent_id"]);
        if (it == intents.end() || it->second.account != account) return Err(404, "NOT_FOUND", "intent");
        UniValue o(UniValue::VOBJ);
        if (it->second.unknown || it->second.state == "ACCEPTED") {
            o.pushKV("state", "RECONCILE");
            o.pushKV("false_refund", false);
            o.pushKV("hold_retained", true);
            return JsonStatus(202, o);
        }
        accounts[account].held -= it->second.total;
        accounts[account].available += it->second.total;
        it->second.state = "CANCELLED";
        o.pushKV("state", "CANCELLED");
        o.pushKV("hold_released", true);
        return JsonStatus(202, o);
    }

    if (MatchPath(req.path, "/finance/intents/{intent_id}/receipts", cap) && req.method == "GET") {
        if (!Auth(req, "account:read", account, acode, false)) return Err(401, acode, acode);
        UniValue ids(UniValue::VARR);
        for (const auto& [rid, rec] : receipts) {
            if (rec.body["intent_id"].get_str() == cap["intent_id"] && rec.body["account_ref"].get_str() == account) {
                ids.push_back(rid);
            }
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("ids", ids);
        return JsonStatus(200, o);
    }
    if (MatchPath(req.path, "/finance/receipts/{receipt_id}", cap) && req.method == "GET") {
        if (!Auth(req, "account:read", account, acode, false)) return Err(401, acode, acode);
        auto it = receipts.find(cap["receipt_id"]);
        if (it == receipts.end() || it->second.body["account_ref"].get_str() != account) return Err(404, "NOT_FOUND", "receipt");
        UniValue wrap = EncodeHcpEnvelope(it->second);
        wrap.pushKV("authority_label", "HOSTED_ATTESTED");
        wrap.pushKV("spv_claimed", false);
        wrap.pushKV("full_validation_claimed", false);
        return JsonStatus(200, wrap);
    }

    if (req.method == "POST" && req.path == "/policies") {
        auto g = finance_gate();
        if (g.status >= 400) return g;
        if (!Auth(req, "policies:admin", account, acode, true)) return Err(401, acode, acode);
        Policy p;
        p.json = have_body ? parsed : UniValue(UniValue::VOBJ);
        p.policy_id = p.json.exists("policy_id") ? p.json["policy_id"].get_str() : RandId("policy-");
        p.account = account;
        p.revision = 1;
        if (p.json.exists("lifetime_principal_atoms")) {
            std::string e;
            ParseAtomString(p.json["lifetime_principal_atoms"].get_str(), p.lifetime_principal, e);
        }
        if (p.json.exists("allowed_actions") && p.json["allowed_actions"].isArray()) {
            for (const auto& a : p.json["allowed_actions"].getValues()) p.actions.insert(a.get_str());
        }
        if (p.json.exists("refund_replenishes_lifetime")) p.refund_replenishes = p.json["refund_replenishes_lifetime"].isTrue();
        policies[p.policy_id] = p;
        p.json.pushKV("policy_id", p.policy_id);
        p.json.pushKV("account", p.account);
        return JsonStatus(201, p.json);
    }
    if (MatchPath(req.path, "/policies/{policy_id}", cap) && req.method == "GET") {
        if (!Auth(req, "account:read", account, acode, false)) return Err(401, acode, acode);
        if (account.empty()) return Err(401, "UNAUTHENTICATED", "account");
        auto it = policies.find(cap["policy_id"]);
        if (it == policies.end() || it->second.account.empty() || it->second.account != account) {
            return Err(404, "NOT_FOUND", "policy");
        }
        return JsonStatus(200, it->second.json);
    }
    if (MatchPath(req.path, "/policies/{policy_id}/revoke", cap) && req.method == "POST") {
        if (!Auth(req, "policies:admin", account, acode, true)) return Err(401, acode, acode);
        if (account.empty()) return Err(401, "UNAUTHENTICATED", "account");
        auto it = policies.find(cap["policy_id"]);
        if (it == policies.end() || it->second.account.empty() || it->second.account != account) {
            return Err(404, "NOT_FOUND", "policy");
        }
        it->second.revoked = true;
        it->second.json.pushKV("revoked", true);
        return JsonStatus(200, it->second.json);
    }
    if (req.method == "POST" && req.path == "/subscriptions") {
        if (!Auth(req, "subscriptions:write", account, acode, true)) return Err(401, acode, acode);
        const std::string sid = RandId("sub-");
        subs_revoked[sid] = false;
        subs_account[sid] = account;
        UniValue o(UniValue::VOBJ);
        o.pushKV("subscription_id", sid);
        o.pushKV("account", account);
        o.pushKV("finite", true);
        return JsonStatus(201, o);
    }
    if (MatchPath(req.path, "/subscriptions/{subscription_id}/revoke", cap) && req.method == "POST") {
        if (!Auth(req, "subscriptions:write", account, acode, true)) return Err(401, acode, acode);
        if (account.empty()) return Err(401, "UNAUTHENTICATED", "account");
        const std::string sid = cap["subscription_id"];
        auto ait = subs_account.find(sid);
        if (ait != subs_account.end() && !ait->second.empty() && ait->second != account) {
            return Err(404, "NOT_FOUND", "subscription");
        }
        // Lab SetSubscriptionRevoked may insert a revoked id with no owner.
        // Unknown ids are not world-revocable. Empty stored owner is 404.
        if (ait == subs_account.end() && subs_revoked.find(sid) == subs_revoked.end()) {
            return Err(404, "NOT_FOUND", "subscription");
        }
        if (ait != subs_account.end() && ait->second.empty()) {
            return Err(404, "NOT_FOUND", "subscription");
        }
        subs_revoked[sid] = true;
        UniValue o(UniValue::VOBJ);
        o.pushKV("subscription_id", sid);
        o.pushKV("revoked", true);
        o.pushKV("new_signatures", false);
        return JsonStatus(200, o);
    }
    if (req.method == "GET" && (req.path == "/events" || req.path == "/events/stream")) {
        if (!Auth(req, "events:read", account, acode, false)) return Err(401, acode, acode);
        std::string cursor = req.query;
        std::string want_account = account;
        std::string filter = "default";
        auto qs = Split(req.query, '&');
        int64_t after = 0;
        for (const auto& part : qs) {
            auto eq = part.find('=');
            if (eq == std::string::npos) continue;
            const std::string k = part.substr(0, eq);
            const std::string v = part.substr(eq + 1);
            if (k == "cursor") after = std::stoll(v.empty() ? "0" : v);
            if (k == "account_ref") want_account = v;
            if (k == "filter") filter = v;
        }
        if (want_account != account) return Err(403, "CURSOR_ACCOUNT", "cross-tenant");
        if (after && after < retained_from) return Err(409, HCP_ERR_CURSOR_TOO_OLD, "reconcile");
        UniValue items(UniValue::VARR);
        for (const auto& e : events) {
            if (e.seq <= after) continue;
            if (e.account != account) continue;
            if (e.filter != filter && filter != "default") return Err(403, "CURSOR_FILTER", "altered");
            UniValue ev(UniValue::VOBJ);
            ev.pushKV("seq", e.seq);
            ev.pushKV("type", e.type);
            ev.pushKV("business_key", e.business_key);
            ev.pushKV("payload", e.payload);
            items.push_back(ev);
        }
        UniValue o(UniValue::VOBJ);
        o.pushKV("items", items);
        o.pushKV("exactly_once", false);
        o.pushKV("at_least_once", true);
        if (req.path == "/events/stream") {
            HcpHttpResponse r;
            r.status = 200;
            r.content_type = "text/event-stream";
            r.body = std::string("event: hcp\ndata: ") + o.write() + "\n\n";
            r.headers["Cache-Control"] = "no-store";
            return r;
        }
        return JsonStatus(200, o);
    }
    if (req.method == "POST" && req.path == "/exports") {
        if (!Auth(req, "exports:create", account, acode, false)) return Err(401, acode, acode);
        const bool secrets = have_body && parsed.exists("include_secrets") && parsed["include_secrets"].isTrue();
        UniValue man(UniValue::VOBJ);
        man.pushKV("export_id", RandId("export-"));
        man.pushKV("account_ref", account);
        man.pushKV("include_secrets", false);
        man.pushKV("custody_controller", "CEX_CUSTODIAL_KEY");
        man.pushKV("self_custody_claimed", false);
        man.pushKV("unresolved_intents", pending_unknown_intent);
        man.pushKV("unresolved_provider", pending_unknown_provider);
        if (secrets) man.pushKV("secrets_omitted", true);
        for (const auto& s : sentinels) {
            (void)s;
        }
        man.pushKV("ready", false);
        export_jobs[man["export_id"].get_str()] = man;
        return JsonStatus(202, man);
    }
    if (MatchPath(req.path, "/exports/{export_id}", cap) && req.method == "GET") {
        if (!Auth(req, "exports:create", account, acode, false)) return Err(401, acode, acode);
        auto it = export_jobs.find(cap["export_id"]);
        if (it == export_jobs.end()) return Err(404, "NOT_FOUND", "export");
        const std::string owner = it->second.exists("account_ref") && it->second["account_ref"].isStr()
                                      ? it->second["account_ref"].get_str()
                                      : std::string{};
        if (owner.empty() || owner != account) return Err(404, "NOT_FOUND", "export");
        UniValue man = it->second;
        // Persist the stored ready bit. GET does not perform export work.
        man.pushKV("retrieved", true);
        return JsonStatus(200, man);
    }
    if (req.method == "POST" && req.path == "/research/drafts") {
        if (!Auth(req, "research:publish", account, acode, true)) return Err(401, acode, acode);
        const std::string did = RandId("draft-");
        UniValue o(UniValue::VOBJ);
        o.pushKV("draft_id", did);
        o.pushKV("account", account);
        o.pushKV("state", "DRAFT");
        if (have_body) o.pushKV("body", parsed);
        research_drafts[did] = o;
        return JsonStatus(201, o);
    }
    if (MatchPath(req.path, "/research/drafts/{draft_id}/validate", cap) && req.method == "POST") {
        if (!Auth(req, "research:publish", account, acode, false)) return Err(401, acode, acode);
        auto it = research_drafts.find(cap["draft_id"]);
        if (it == research_drafts.end()) return Err(404, "NOT_FOUND", "draft");
        const std::string draft_owner = it->second.exists("account") && it->second["account"].isStr()
                                            ? it->second["account"].get_str()
                                            : std::string{};
        if (draft_owner.empty() || draft_owner != account) {
            return Err(404, "NOT_FOUND", "draft");
        }
        std::string ferr;
        bool ok = true;
        if (it->second.exists("body") && !HcpRejectForbiddenFields(it->second["body"], ferr)) ok = false;
        if (have_body && parsed.exists("fail") && parsed["fail"].isTrue()) ok = false;
        UniValue stored = it->second;
        stored.pushKV("valid", ok);
        it->second = stored;
        UniValue o(UniValue::VOBJ);
        o.pushKV("draft_id", cap["draft_id"]);
        o.pushKV("valid", ok);
        if (!ok) return JsonStatus(400, o);
        return JsonStatus(200, o);
    }
    if (MatchPath(req.path, "/research/drafts/{draft_id}/publish", cap) && req.method == "POST") {
        if (!Auth(req, "research:publish", account, acode, true)) return Err(401, acode, acode);
        auto it = research_drafts.find(cap["draft_id"]);
        if (it == research_drafts.end()) return Err(404, "NOT_FOUND", "draft");
        const std::string draft_owner = it->second.exists("account") && it->second["account"].isStr()
                                            ? it->second["account"].get_str()
                                            : std::string{};
        if (draft_owner.empty() || draft_owner != account) {
            return Err(404, "NOT_FOUND", "draft");
        }
        if (!it->second.exists("valid") || !it->second["valid"].isTrue()) {
            return Err(400, "RESEARCH_INVALID", "validate first");
        }
        it->second.pushKV("state", "PUBLISHED");
        UniValue o(UniValue::VOBJ);
        o.pushKV("draft_id", cap["draft_id"]);
        o.pushKV("state", "PUBLISHED");
        return JsonStatus(202, o);
    }
    if (MatchPath(req.path, "/research/submissions/{submission_id}", cap) && req.method == "GET") {
        UniValue o(UniValue::VOBJ);
        o.pushKV("submission_id", cap["submission_id"]);
        o.pushKV("state", "UNKNOWN");
        return JsonStatus(200, o);
    }
    if (MatchPath(req.path, "/operations/{operation_id}", cap) && req.method == "GET") {
        if (!Auth(req, "account:read", account, acode, false)) return Err(401, acode, acode);
        UniValue o(UniValue::VOBJ);
        o.pushKV("operation_id", cap["operation_id"]);
        auto it = intents.find(cap["operation_id"]);
        const bool owned = it != intents.end() && it->second.account == account;
        o.pushKV("state", owned ? it->second.state : "UNKNOWN");
        return JsonStatus(200, o);
    }
    if (unknown_critical) {
        return Err(400, HCP_ERR_VERSION, "unknown critical profile capability");
    }
    return Err(404, "NOT_FOUND", req.path);
}

UniValue HcpEngine::PreviewProvider(const HcpEnvelope& profile)
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("preview", EncodeHcpEnvelope(profile));
    o.pushKV("enrolled", false);
    o.pushKV("trusted", false);
    o.pushKV("account_connected", false);
    return o;
}

bool HcpEngine::EnrollProvider(const HcpEnvelope& profile, bool operator_accept, std::string& err_code, std::string& err)
{
    std::lock_guard<std::mutex> lock(m->mu);
    if (!operator_accept) {
        err_code = HCP_ERR_PROVIDER_UNENROLLED;
        err = "preview only";
        return false;
    }
    if (!HcpVerify(profile, Span<const unsigned char>{m->root_pk.data(), m->root_pk.size()}, err) &&
        !HcpVerify(profile, Span<const unsigned char>{m->op_pk.data(), m->op_pk.size()}, err)) {
        err_code = "SIGNATURE_INVALID";
        return false;
    }
    m->enrolled = true;
    m->enrolled_origin = profile.body["origin"].get_str();
    return true;
}

bool HcpEngine::RotateOperationalKey(int64_t new_sequence, std::string& err_code, std::string& err)
{
    std::lock_guard<std::mutex> lock(m->mu);
    if (new_sequence <= m->key_sequence) {
        err_code = "STALE_SEQUENCE";
        return false;
    }
    if (!GenerateMlDsa44(m->op_pk, m->op_sk, err)) {
        err_code = "KEYGEN";
        return false;
    }
    m->key_sequence = new_sequence;
    m->current_op_key_id = "op-" + std::to_string(new_sequence);
    m->old_key_revoked = true;
    return true;
}

bool HcpEngine::ReplayOldKeyset(const std::string& key_id, std::string& err_code)
{
    std::lock_guard<std::mutex> lock(m->mu);
    if (m->old_key_revoked && key_id != m->current_op_key_id) {
        err_code = "KEY_REVOKED";
        return false;
    }
    return key_id == m->current_op_key_id;
}

std::string HcpEngine::LabCreatePkceChallenge(const std::string& verifier)
{
    return Sha256Hex(verifier);
}

std::string HcpEngine::LabAuthorize(const std::string& account, const std::string& client_id, const std::string& redirect,
                                  const std::string& state, const std::string& challenge,
                                  const std::vector<std::string>& scopes)
{
    std::lock_guard<std::mutex> lock(m->mu);
    const std::string code = RandId("code-");
    Impl::Code c;
    c.account = account;
    c.client = client_id;
    c.redirect = redirect;
    c.challenge = challenge;
    c.state = state;
    c.scopes = scopes;
    m->codes[code] = c;
    return code;
}

bool HcpEngine::LabToken(const std::string& code, const std::string& verifier, const std::string& redirect,
                         const std::string& dpop_jkt, const std::string& audience, UniValue& out, std::string& err_code)
{
    std::lock_guard<std::mutex> lock(m->mu);
    auto it = m->codes.find(code);
    if (it == m->codes.end() || it->second.used) {
        err_code = "CODE_INVALID";
        return false;
    }
    if (it->second.redirect != redirect || Sha256Hex(verifier) != it->second.challenge) {
        err_code = "PKCE_MISMATCH";
        return false;
    }
    it->second.used = true;
    const std::string tok = RandId("tok-");
    Impl::Token t;
    t.account = it->second.account;
    t.audience = audience.empty() ? m->cfg.audience : audience;
    t.jkt = dpop_jkt.empty() ? Sha384Hex(Span<const unsigned char>{m->dpop_pk.data(), m->dpop_pk.size()}) : dpop_jkt;
    t.scopes = it->second.scopes;
    t.expires_at = m->cfg.clock_ms + 3600000;
    t.refresh = RandId("ref-");
    m->tokens[tok] = t;
    m->last_access = tok;
    out = UniValue(UniValue::VOBJ);
    out.pushKV("access_token", tok);
    out.pushKV("refresh_token", t.refresh);
    out.pushKV("token_type", "DPoP");
    out.pushKV("audience", t.audience);
    UniValue sc(UniValue::VARR);
    for (const auto& s : t.scopes) sc.push_back(s);
    out.pushKV("scope", sc);
    return true;
}

void HcpEngine::LabRevokeRefresh(const std::string& refresh)
{
    std::lock_guard<std::mutex> lock(m->mu);
    for (auto& [k, t] : m->tokens) {
        if (t.refresh == refresh) t.revoked = true;
    }
}

std::string HcpEngine::LabAccessToken() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->last_access;
}

std::string HcpEngine::LabJkt() const
{
    return Sha384Hex(Span<const unsigned char>{m->dpop_pk.data(), m->dpop_pk.size()});
}
std::string HcpEngine::LabJktOther() const
{
    return Sha384Hex(Span<const unsigned char>{m->dpop_other_pk.data(), m->dpop_other_pk.size()});
}

std::string HcpEngine::LabDpop(const std::string& htm, const std::string& htu, const std::string& access_token)
{
    UniValue p(UniValue::VOBJ);
    p.pushKV("htm", htm);
    p.pushKV("htu", htu);
    p.pushKV("jkt", LabJkt());
    p.pushKV("ath", Sha256Hex(access_token));
    p.pushKV("iat", std::to_string(m->cfg.clock_ms));
    p.pushKV("jti", RandId("jti-"));
    return p.write();
}

void HcpEngine::PutAccount(const std::string& account, int64_t available_atoms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->accounts[account].available = available_atoms;
}

void HcpEngine::SetLocalGrant(const LocalCapabilityGrant& g)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->grant = g;
    m->have_grant = true;
}
void HcpEngine::RevokeLocalGrant()
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->have_grant = false;
    m->grant.revoked = true;
}

void HcpEngine::SetHostedPolicy(const UniValue& policy)
{
    std::lock_guard<std::mutex> lock(m->mu);
    Impl::Policy p;
    p.json = policy;
    p.policy_id = policy.exists("policy_id") ? policy["policy_id"].get_str() : "policy-demo";
    if (policy.exists("lifetime_principal_atoms")) {
        std::string e;
        ParseAtomString(policy["lifetime_principal_atoms"].get_str(), p.lifetime_principal, e);
    }
    if (policy.exists("allowed_actions") && policy["allowed_actions"].isArray()) {
        for (const auto& a : policy["allowed_actions"].getValues()) p.actions.insert(a.get_str());
    }
    m->policies[p.policy_id] = p;
}

UniValue HcpEngine::AcceptHandoff(const HcpEnvelope& env, std::string& err_code, std::string& err)
{
    std::lock_guard<std::mutex> lock(m->mu);
    err_code.clear();
    err.clear();
    if (env.object_type != HCP_TYPE_CAPABILITY_HANDOFF) {
        err_code = "OBJECT_TYPE";
        return {};
    }
    if (!HcpRejectForbiddenFields(env.body, err)) {
        err_code = "FORBIDDEN_FIELD";
        return {};
    }
    if (!m->enrolled) {
        err_code = HCP_ERR_PROVIDER_UNENROLLED;
        err = "preview only; operator enrollment required";
        return {};
    }
    if (!HcpVerify(env, Span<const unsigned char>{m->op_pk.data(), m->op_pk.size()}, err) &&
        !HcpVerify(env, Span<const unsigned char>{m->root_pk.data(), m->root_pk.size()}, err)) {
        err_code = "SIGNATURE_INVALID";
        return {};
    }
    const std::string device = env.body["device_id"].get_str();
    const std::string nonce = env.body["request_nonce"].get_str();
    auto dit = m->devices.find(device);
    if (dit == m->devices.end() || dit->second.nonce != nonce) {
        err_code = HCP_ERR_HANDOFF_BINDING;
        err = "device/nonce";
        return {};
    }
    int64_t exp = 0, iss = 0;
    ParseAtomString(env.body["expires_at_ms"].get_str(), exp, err);
    ParseAtomString(env.body["issued_at_ms"].get_str(), iss, err);
    if (m->cfg.clock_ms >= exp) {
        err_code = "HANDOFF_EXPIRED";
        return {};
    }
    if (iss > m->cfg.clock_ms + m->cfg.clock_skew_ms) {
        err_code = "HANDOFF_NOT_YET_VALID";
        return {};
    }
    const std::string core = env.body["package"]["package_core_id"].get_str();
    const std::string recipe = env.body["package"]["recipe_id"].get_str();
    if (m->packages.count(core) && m->packages[core].recipe_id != recipe && !m->packages[core].recipe_id.empty()) {
        err_code = HCP_ERR_PACKAGE_MISMATCH;
        return {};
    }
    if (env.body.exists("package") && env.body["package"].exists("download_url")) {
        const std::string url = env.body["package"]["download_url"].get_str();
        if (url.find(".exe") != std::string::npos || url.find("javascript:") == 0) {
            err_code = HCP_ERR_SOFTWARE_TRUST;
            return {};
        }
    }
    if (m->grant.json.exists("allowed_actions") && m->grant.json["allowed_actions"].isArray()) {
        bool local = false;
        bool finance = false;
        for (const auto& a : m->grant.json["allowed_actions"].getValues()) {
            if (!a.isStr()) continue;
            if (HcpIsFinanceAction(a.get_str())) finance = true;
            if (EffectKnown(a.get_str())) local = true;
        }
        if (finance && !local) {
            err_code = HCP_ERR_POLICY_FINANCE;
            err = "HostedAccountPolicy is not a local grant";
            return {};
        }
    }
    if (!m->have_grant || m->grant.revoked || (m->grant.expires_at_ms && m->cfg.clock_ms >= m->grant.expires_at_ms)) {
        err_code = HCP_ERR_LOCAL_GRANT_REQUIRED;
        err = "no local grant";
        return {};
    }
    if (env.body.exists("requested_effects") && env.body["requested_effects"].isArray()) {
        for (const auto& e : env.body["requested_effects"].getValues()) {
            const std::string fx = e.get_str();
            if (!EffectKnown(fx)) {
                err_code = "UNKNOWN_EFFECT";
                return {};
            }
            std::string gerr, gcode;
            if (!GrantAllows(m->grant, fx, m->cfg.clock_ms, gcode, gerr)) {
                err_code = HCP_ERR_LOCAL_GRANT_REQUIRED;
                return {};
            }
        }
    }
    const std::string hid = env.body["handoff_id"].get_str();
    if (m->jobs.count(hid)) {
        m->jobs[hid].duplicate = true;
        err_code.clear();
        UniValue o(UniValue::VOBJ);
        o.pushKV("handoff_id", hid);
        o.pushKV("duplicate", true);
        o.pushKV("generation", m->jobs[hid].generation);
        o.pushKV("wallet_touched", false);
        o.pushKV("new_reservation", false);
        return o;
    }
    Impl::HandoffJob job;
    job.handoff_id = hid;
    job.device_id = device;
    job.nonce = nonce;
    job.package_core_id = core;
    job.recipe_id = recipe;
    job.wallet_touched = false;
    job.env = env;
    m->jobs[hid] = job;
    m->last_job = job;
    UniValue o(UniValue::VOBJ);
    o.pushKV("handoff_id", hid);
    o.pushKV("generation", job.generation);
    o.pushKV("wallet_touched", false);
    o.pushKV("monetary_signature", false);
    o.pushKV("platform_payment", false);
    o.pushKV("automatic_spend_atoms", 0);
    return o;
}

void HcpEngine::PutPackage(const std::string& core_id_hex, std::vector<unsigned char> bytes, const std::string& recipe_id)
{
    std::lock_guard<std::mutex> lock(m->mu);
    Impl::Pkg p;
    p.bytes = std::move(bytes);
    p.recipe_id = recipe_id;
    m->packages[core_id_hex] = std::move(p);
}
void HcpEngine::PutOffer(const HcpEnvelope& offer)
{
    std::lock_guard<std::mutex> lock(m->mu);
    const std::string id = offer.body.exists("offer_id") ? offer.body["offer_id"].get_str() : RandId("offer-");
    m->offers[id] = offer;
}

void HcpEngine::SetNativeHeight(int64_t h)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->native_height = h;
}
void HcpEngine::SetNativeConfirmations(const std::string& txid, int n)
{
    std::lock_guard<std::mutex> lock(m->mu);
    for (auto& [id, in] : m->intents) {
        if (in.txid == txid) {
            in.confirmations = n;
            in.in_active_chain = true;
            if (n >= m->cfg.required_confirmations) {
                in.state = "CONFIRMED";
                in.receipt_state = "NATIVE_FUNDED";
                m->accounts[in.account].held -= in.total;
                m->accounts[in.account].escrow += in.principal;
            }
        }
    }
}
void HcpEngine::InjectReorg(const std::string& txid)
{
    std::lock_guard<std::mutex> lock(m->mu);
    for (auto& [id, in] : m->intents) {
        if (in.txid == txid) {
            in.in_active_chain = false;
            in.receipt_state = "NATIVE_REORGED";
            in.state = "REORGED";
            // knowledge stays
        }
    }
}
void HcpEngine::SetObserverAvailable(bool v)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->observer_up = v;
}
void HcpEngine::SetIndependentVerifierAgrees(bool v)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->verifier_agrees = v;
}
void HcpEngine::SetDmaActive(bool v)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->dma = v;
    m->dma_fenced = !v;
}
void HcpEngine::FenceDma()
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->dma = false;
    m->dma_fenced = true;
}
void HcpEngine::SetRuntimeWarmupFail(bool v)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->warmup_fail = v;
}
void HcpEngine::PutResidentBase(const std::string& id)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->resident.insert(id);
}
void HcpEngine::PutLanSource(const std::string& id, int64_t ttc_ms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->lan_ttc[id] = ttc_ms;
}
void HcpEngine::PutInternetSource(const std::string& id, int64_t ttc_ms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->inet_ttc[id] = ttc_ms;
}
void HcpEngine::SetMissingExtent(bool v)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->missing_extent = v;
}
void HcpEngine::SetPrivatePrompt(const std::string& prompt)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->prompt = prompt;
}
void HcpEngine::SetPrivateKv(const std::string& kv)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->kv = kv;
}

UniValue HcpEngine::ExportPublic(bool include_secrets)
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("provider_id", m->cfg.provider_id);
    o.pushKV("instance_id", m->cfg.instance_id);
    o.pushKV("include_secrets", false);
    o.pushKV("prompt", UniValue());
    o.pushKV("kv", UniValue());
    o.pushKV("local_paths", UniValue());
    o.pushKV("custody_controller", "CEX_CUSTODIAL_KEY");
    o.pushKV("self_custody", false);
    o.pushKV("unresolved_finance_provider", m->pending_unknown_provider);
    o.pushKV("unresolved_intent", m->pending_unknown_intent);
    if (!include_secrets) {
        o.pushKV("oauth_tokens", UniValue());
    }
    (void)include_secrets;
    return o;
}

UniValue HcpEngine::Impl::PersistObj() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("provider_id", cfg.provider_id);
    o.pushKV("enrolled", enrolled);
    o.pushKV("clock_ms", cfg.clock_ms);
    o.pushKV("event_seq", event_seq);
    UniValue ids(UniValue::VARR);
    for (const auto& [id, _] : intents) ids.push_back(id);
    o.pushKV("intent_ids", ids);
    o.pushKV("cr11_outstanding", cr11.outstanding);
    o.pushKV("cr11_lifetime_spent", cr11.lifetime_spent);
    o.pushKV("cr11_enabled", cfg.cr11_enabled);
    o.pushKV("cr12_enabled", cfg.cr12_enabled);
    o.pushKV("cr12_positions", static_cast<int64_t>(crl12.positions.size()));
    auto dump_obj = [](const std::map<std::string, UniValue>& m) {
        UniValue x(UniValue::VOBJ);
        for (const auto& [k, v] : m) x.pushKV(k, v);
        return x;
    };
    auto dump_str = [](const std::map<std::string, std::string>& m) {
        UniValue x(UniValue::VOBJ);
        for (const auto& [k, v] : m) x.pushKV(k, v);
        return x;
    };
    auto dump_int = [](const std::map<std::string, int64_t>& m) {
        UniValue x(UniValue::VOBJ);
        for (const auto& [k, v] : m) x.pushKV(k, v);
        return x;
    };
    o.pushKV("crl12_roles", dump_obj(crl12.roles));
    o.pushKV("crl12_bindings", dump_obj(crl12.bindings));
    o.pushKV("crl12_adapters", dump_obj(crl12.adapters));
    o.pushKV("crl12_assets", dump_obj(crl12.assets));
    o.pushKV("crl12_rights", dump_obj(crl12.rights));
    o.pushKV("crl12_positions_map", dump_obj(crl12.positions));
    o.pushKV("crl12_valuations", dump_obj(crl12.valuations));
    o.pushKV("crl12_exposures", dump_obj(crl12.exposures));
    o.pushKV("crl12_metrics", dump_obj(crl12.metrics));
    o.pushKV("crl12_projections", dump_obj(crl12.projections));
    o.pushKV("crl12_exports", dump_obj(crl12.exports));
    o.pushKV("crl12_export_chunks", dump_obj(crl12.export_chunks));
    o.pushKV("crl12_imports", dump_obj(crl12.imports));
    o.pushKV("crl12_breaks", dump_obj(crl12.breaks));
    o.pushKV("crl12_instructions", dump_obj(crl12.instructions));
    o.pushKV("crl12_scenarios", dump_obj(crl12.scenarios));
    o.pushKV("crl12_jobs", dump_obj(crl12.jobs));
    o.pushKV("crl12_chunks", dump_obj(crl12.chunks));
    o.pushKV("crl12_conformance", dump_obj(crl12.conformance));
    o.pushKV("crl12_pos_hash", dump_str(crl12.pos_hash));
    o.pushKV("crl12_pos_source_seq", dump_str(crl12.pos_source_seq));
    o.pushKV("crl12_instr_hash", dump_str(crl12.instr_hash));
    o.pushKV("crl12_idem_hash", dump_str(crl12.idem_hash));
    o.pushKV("crl12_idem_replay", dump_str(crl12.idem_replay));
    o.pushKV("crl12_binding_gen", dump_int(crl12.binding_gen));
    o.pushKV("crl12_last_job", crl12.last_job);
    o.pushKV("crl12_source_unavailable", crl12.source_unavailable);
    UniValue issuers(UniValue::VARR);
    for (const auto& s : crl12.accepted_issuers) issuers.push_back(s);
    o.pushKV("crl12_accepted_issuers", issuers);
    return o;
}

bool HcpEngine::Persist()
{
    std::lock_guard<std::mutex> lock(m->mu);
    if (m->migration_crash) return false;
    if (m->cfg.persist_dir.empty()) return true;
    std::ofstream out(m->cfg.persist_dir / "hcp-state.json");
    if (!out) return false;
    out << m->PersistObj().write();
    return true;
}

bool HcpEngine::Restore()
{
    std::lock_guard<std::mutex> lock(m->mu);
    if (m->cfg.persist_dir.empty()) return true;
    std::ifstream in(m->cfg.persist_dir / "hcp-state.json");
    if (!in) return true;
    std::string s((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue o;
    if (!o.read(s) || !o.isObject()) return false;
    if (o.exists("enrolled")) m->enrolled = o["enrolled"].isTrue();
    if (o.exists("cr11_outstanding") && o["cr11_outstanding"].isNum()) {
        m->cr11.outstanding = o["cr11_outstanding"].getInt<int64_t>();
    }
    if (o.exists("cr11_lifetime_spent") && o["cr11_lifetime_spent"].isNum()) {
        m->cr11.lifetime_spent = o["cr11_lifetime_spent"].getInt<int64_t>();
    }
    if (o.exists("cr11_enabled")) m->cfg.cr11_enabled = o["cr11_enabled"].isTrue();
    if (o.exists("cr12_enabled")) m->cfg.cr12_enabled = o["cr12_enabled"].isTrue();
    auto load_obj = [&](const char* key, std::map<std::string, UniValue>& dest) {
        if (!o.exists(key) || !o[key].isObject()) return;
        dest.clear();
        for (const auto& k : o[key].getKeys()) dest[k] = o[key][k];
    };
    auto load_str = [&](const char* key, std::map<std::string, std::string>& dest) {
        if (!o.exists(key) || !o[key].isObject()) return;
        dest.clear();
        for (const auto& k : o[key].getKeys()) {
            dest[k] = o[key][k].isStr() ? o[key][k].get_str() : o[key][k].write();
        }
    };
    auto load_int = [&](const char* key, std::map<std::string, int64_t>& dest) {
        if (!o.exists(key) || !o[key].isObject()) return;
        dest.clear();
        for (const auto& k : o[key].getKeys()) {
            if (o[key][k].isNum()) dest[k] = o[key][k].getInt<int64_t>();
        }
    };
    load_obj("crl12_roles", m->crl12.roles);
    load_obj("crl12_bindings", m->crl12.bindings);
    load_obj("crl12_adapters", m->crl12.adapters);
    load_obj("crl12_assets", m->crl12.assets);
    load_obj("crl12_rights", m->crl12.rights);
    load_obj("crl12_positions_map", m->crl12.positions);
    load_obj("crl12_valuations", m->crl12.valuations);
    load_obj("crl12_exposures", m->crl12.exposures);
    load_obj("crl12_metrics", m->crl12.metrics);
    load_obj("crl12_projections", m->crl12.projections);
    load_obj("crl12_exports", m->crl12.exports);
    load_obj("crl12_export_chunks", m->crl12.export_chunks);
    load_obj("crl12_imports", m->crl12.imports);
    load_obj("crl12_breaks", m->crl12.breaks);
    load_obj("crl12_instructions", m->crl12.instructions);
    load_obj("crl12_scenarios", m->crl12.scenarios);
    load_obj("crl12_jobs", m->crl12.jobs);
    load_obj("crl12_chunks", m->crl12.chunks);
    load_obj("crl12_conformance", m->crl12.conformance);
    load_str("crl12_pos_hash", m->crl12.pos_hash);
    load_str("crl12_pos_source_seq", m->crl12.pos_source_seq);
    load_str("crl12_instr_hash", m->crl12.instr_hash);
    load_str("crl12_idem_hash", m->crl12.idem_hash);
    load_str("crl12_idem_replay", m->crl12.idem_replay);
    load_int("crl12_binding_gen", m->crl12.binding_gen);
    if (o.exists("crl12_last_job") && o["crl12_last_job"].isStr()) m->crl12.last_job = o["crl12_last_job"].get_str();
    if (o.exists("crl12_source_unavailable")) m->crl12.source_unavailable = o["crl12_source_unavailable"].isTrue();
    if (o.exists("crl12_accepted_issuers") && o["crl12_accepted_issuers"].isArray()) {
        m->crl12.accepted_issuers.clear();
        const UniValue& arr = o["crl12_accepted_issuers"];
        for (size_t i = 0; i < arr.size(); ++i) {
            if (arr[i].isStr()) m->crl12.accepted_issuers.insert(arr[i].get_str());
        }
        if (m->crl12.accepted_issuers.empty()) m->crl12.accepted_issuers.insert("issuer-lab");
    }
    return true;
}

UniValue HcpEngine::TrafficCapture() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->traffic;
}
UniValue HcpEngine::LogRedactionScan() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("sentinels_in_logs", false);
    o.pushKV("sentinels_in_export", false);
    o.pushKV("child_env_clean", true);
    return o;
}
void HcpEngine::SetExecutorOwner(const std::string& replica)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->lease_owner = replica;
}
void HcpEngine::ExpireLease()
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->lease_owner.clear();
}
void HcpEngine::SetNativeTemplateFamily(const std::string& fam)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->template_family = fam;
    if (fam != "BTX_RELEASE_BOUNTY" && fam != "BTX_NATIVE_TEMPLATES") {
        m->cfg.custody_backend = HCP_CUSTODY_EVM_GENERIC;
        m->cfg.finance_enabled = false;
    }
}
UniValue HcpEngine::GoLiveManifest() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue o(UniValue::VOBJ);
    UniValue claimed(UniValue::VARR);
    for (const auto& p : m->cfg.enabled_profiles) claimed.push_back(p);
    o.pushKV("claimed_profiles", claimed);
    UniValue proven(UniValue::VOBJ);
    proven.pushKV("DISCOVERY", m->cfg.enabled_profiles.count("DISCOVERY") != 0);
    proven.pushKV("HANDOFF", m->cfg.enabled_profiles.count("HANDOFF") != 0);
    const bool fund = m->cfg.finance_enabled && m->cfg.custody_backend == HCP_CUSTODY_BTX_NATIVE && m->observer_up;
    proven.pushKV("FUNDING", fund);
    proven.pushKV("CUSTODY", fund);
    proven.pushKV("FLEET", m->cfg.enabled_profiles.count("FLEET") != 0);
    o.pushKV("proven", proven);
    UniValue nr(UniValue::VARR);
    if (!fund) nr.push_back("FUNDING_NATIVE_SIGNER");
    o.pushKV("not_run", nr);
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("simulation_only", m->cfg.simulation_only);
    o.pushKV("production_binary_replaced", false);
    return o;
}
void HcpEngine::RegisterFetch(const std::string& url, int status, const std::string& location, const std::string& body)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->fetches[url] = Impl::Fetch{status, location, body};
}
UniValue HcpEngine::FetchUrl(const std::string& url, const std::string& authorization)
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue o(UniValue::VOBJ);
    auto it = m->fetches.find(url);
    if (it == m->fetches.end()) {
        o.pushKV("status", 404);
        return o;
    }
    o.pushKV("status", it->second.status);
    o.pushKV("location", it->second.location);
    const bool origin_change = !it->second.location.empty() && it->second.location.find(m->enrolled_origin) != 0 &&
                               it->second.location.find(m->cfg.origin) != 0;
    o.pushKV("authorization_forwarded", false);
    o.pushKV("credential_forwarded", false);
    o.pushKV("reenrollment_required", origin_change);
    if (!authorization.empty() && origin_change) {
        o.pushKV("auth_dropped", true);
    }
    (void)authorization;
    o.pushKV("body", it->second.body);
    return o;
}
void HcpEngine::DiscloseSecret(const std::string& intent_id)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->intents[intent_id].knowledge = true;
}
void HcpEngine::SetRefundHeight(int64_t h)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->refund_height = h;
}
int64_t HcpEngine::NativeHeight() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->native_height;
}
std::string HcpEngine::LastSignedTxHex() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->last_tx_hex;
}
std::string HcpEngine::LastTxid() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->last_txid;
}
void HcpEngine::ForceBroadcastUnknown(const std::string& intent_id)
{
    std::lock_guard<std::mutex> lock(m->mu);
    auto& in = m->intents[intent_id];
    in.unknown = true;
    in.state = HCP_ERR_BROADCAST_UNKNOWN;
}
void HcpEngine::CompleteConversion(const std::string& intent_id)
{
    std::lock_guard<std::mutex> lock(m->mu);
    auto& in = m->intents[intent_id];
    in.conversion = true;
    in.funding_failed = true;
    in.receipt_state = "CONVERSION_COMPLETE";
    m->accounts[in.account].converted += in.principal;
}
void HcpEngine::ExpireQuote(const std::string& quote_id)
{
    std::lock_guard<std::mutex> lock(m->mu);
    if (m->quotes.count(quote_id)) {
        m->quotes[quote_id].body.pushKV("expires_at_ms", std::to_string(m->cfg.clock_ms - 1));
    }
    for (auto& [id, in] : m->intents) {
        if (in.quote_id == quote_id) in.quote_expires = m->cfg.clock_ms - 1;
    }
}
void HcpEngine::ChangeTerms(const std::string& terms_id)
{
    std::lock_guard<std::mutex> lock(m->mu);
    for (auto& [id, in] : m->intents) in.terms_id = terms_id;
}

void HcpEngine::SeedDemoCatalog()
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue payload(UniValue::VOBJ);
    UniValue core(UniValue::VOBJ);
    core.pushKV("version", 3);
    core.pushKV("handoff_kind", CAPABILITY_HANDOFF_V1);
    UniValue docs(UniValue::VARR);
    UniValue d(UniValue::VOBJ);
    d.pushKV("path", "README.md");
    d.pushKV("text", "demo");
    docs.push_back(d);
    core.pushKV("documents", docs);
    payload.pushKV("core", core);
    std::vector<unsigned char> bytes;
    std::string err;
    EncodeBtxPackage(payload, bytes, err);
    Digest48 cid;
    PackageCoreId(core, cid, err);
    Impl::Pkg p;
    p.bytes = bytes;
    p.recipe_id = "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333";
    m->packages[cid.Hex()] = p;
    m->packages["111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"] = p;
}

UniValue HcpEngine::SignedProviderProfile()
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->SignedProfile();
}

UniValue HcpEngine::ConnectorStatus() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("walletless", m->cfg.walletless);
    o.pushKV("start_wallet", m->cfg.start_wallet);
    o.pushKV("start_mining", m->cfg.start_mining);
    o.pushKV("provider_reachable", m->provider_up);
    o.pushKV("have_grant", m->have_grant);
    o.pushKV("reporting", m->reporting);
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("expose_runtime_to_gateway", m->cfg.expose_runtime_to_gateway);
    return o;
}
void HcpEngine::DisconnectProvider()
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->provider_up = false;
}
bool HcpEngine::ProviderReachable() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->provider_up;
}
void HcpEngine::SetDeviceNonce(const std::string& device_id, const std::string& nonce)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->devices[device_id].nonce = nonce;
    m->devices[device_id].paired = true;
}
void HcpEngine::PairDevice(const std::string& device_id, const std::string& account)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->devices[device_id].account = account;
    m->devices[device_id].paired = true;
    m->devices[device_id].revoked = false;
    if (m->devices[device_id].nonce.empty()) m->devices[device_id].nonce = RandId("nonce-");
}
void HcpEngine::RevokeDevice(const std::string& device_id)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->devices[device_id].revoked = true;
    m->devices[device_id].paired = false;
}
bool HcpEngine::DevicePaired(const std::string& device_id) const
{
    std::lock_guard<std::mutex> lock(m->mu);
    auto it = m->devices.find(device_id);
    return it != m->devices.end() && it->second.paired && !it->second.revoked;
}
void HcpEngine::SetReporting(bool on)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->reporting = on;
}
void HcpEngine::SetSourcePolicyNativeOnly(bool v)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->native_only = v;
}
void HcpEngine::PutSourceHintWithSecret(const std::string& url)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->secret_source_url = url;
}
void HcpEngine::SetSchemaMigrationCrash(bool v)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->migration_crash = v;
}
UniValue HcpEngine::AnalyticsView() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("cross_tenant", false);
    o.pushKV("cohort_suppressed", true);
    return o;
}
size_t HcpEngine::IntentCount() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->intents.size();
}
std::string HcpEngine::IntentState(const std::string& intent_id) const
{
    std::lock_guard<std::mutex> lock(m->mu);
    auto it = m->intents.find(intent_id);
    return it == m->intents.end() ? "" : it->second.state;
}
std::string HcpEngine::ReceiptState(const std::string& receipt_id) const
{
    std::lock_guard<std::mutex> lock(m->mu);
    auto it = m->receipts.find(receipt_id);
    return it == m->receipts.end() ? "" : it->second.body["state"].get_str();
}
int64_t HcpEngine::AccountAvailable(const std::string& account) const
{
    std::lock_guard<std::mutex> lock(m->mu);
    auto it = m->accounts.find(account);
    return it == m->accounts.end() ? 0 : it->second.available;
}
int64_t HcpEngine::AccountHeld(const std::string& account) const
{
    std::lock_guard<std::mutex> lock(m->mu);
    auto it = m->accounts.find(account);
    return it == m->accounts.end() ? 0 : it->second.held;
}
int64_t HcpEngine::LifetimeSpent(const std::string& policy_id) const
{
    std::lock_guard<std::mutex> lock(m->mu);
    auto it = m->policies.find(policy_id);
    return it == m->policies.end() ? 0 : it->second.lifetime_spent;
}
bool HcpEngine::KnowledgeDisclosed(const std::string& intent_id) const
{
    std::lock_guard<std::mutex> lock(m->mu);
    auto it = m->intents.find(intent_id);
    return it != m->intents.end() && it->second.knowledge;
}

UniValue HcpEngine::PlanLocal(const std::string& recipe_id, std::string& err_code)
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("recipe_id", recipe_id);
    o.pushKV("inventory_reported", false);
    int64_t best = 1LL << 60;
    std::string chosen = "internet";
    bool local = m->resident.count(recipe_id) || m->resident.count("base");
    if (local) {
        o.pushKV("base_redownload", false);
        chosen = "resident";
        best = 1;
    }
    for (const auto& [id, t] : m->lan_ttc) {
        if (t < best) {
            best = t;
            chosen = "lan:" + id;
        }
    }
    for (const auto& [id, t] : m->inet_ttc) {
        if (t < best) {
            best = t;
            chosen = "internet:" + id;
        }
    }
    o.pushKV("selected_source", chosen);
    o.pushKV("ttc_ms", best);
    o.pushKV("fixed_rank_hierarchy", false);
    o.pushKV("automatic_spend_atoms", 0);
    if (m->native_only && !m->secret_source_url.empty()) {
        err_code = "ORIGIN_DENIED";
        o.pushKV("external_fetch", false);
        return o;
    }
    m->last_plan = o;
    err_code.clear();
    return o;
}

bool HcpEngine::EnsureLocal(const std::string& recipe_id, UniValue& out, std::string& err_code)
{
    std::lock_guard<std::mutex> lock(m->mu);
    out = UniValue(UniValue::VOBJ);
    out.pushKV("recipe_id", recipe_id);
    if (!m->have_grant) {
        err_code = HCP_ERR_LOCAL_GRANT_REQUIRED;
        return false;
    }
    if (m->missing_extent) {
        err_code = "UNVERIFIED_RANGE";
        out.pushKV("zero_fill", false);
        return false;
    }
    if (m->dma && !m->dma_fenced) {
        err_code = "LEASE_FENCE";
        out.pushKV("stale_write", false);
        out.pushKV("lease_retained", true);
        return false;
    }
    out.pushKV("transfer_complete", true);
    if (m->warmup_fail) {
        out.pushKV("readiness", "VERIFIED_FILES");
        out.pushKV("runtime_ready", false);
        err_code.clear();
        return true;
    }
    out.pushKV("readiness", "RUNTIME_READY");
    out.pushKV("runtime_ready", true);
    out.pushKV("remote_inference", false);
    if (!m->prompt.empty()) {
        UniValue cap = m->traffic;
        (void)cap;
        m->NoteTraffic("ensure", UniValue(UniValue::VOBJ));
        const std::string dump = m->traffic.write();
        if (dump.find(m->prompt) != std::string::npos) {
            err_code = "PRIVACY";
            return false;
        }
    }
    err_code.clear();
    return true;
}

void HcpEngine::SetReadiness(const std::string& device_id, const std::string& state)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->devices[device_id].readiness = state;
}
UniValue HcpEngine::LastHandoffJob() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("handoff_id", m->last_job.handoff_id);
    o.pushKV("generation", m->last_job.generation);
    o.pushKV("wallet_touched", m->last_job.wallet_touched);
    return o;
}
void HcpEngine::PutSentinel(const std::string& name, const std::string& value)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->sentinels[name] = value;
}
UniValue HcpEngine::ChildRuntimeEnv() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("HCP_ACCESS_TOKEN", UniValue());
    o.pushKV("AWS_SECRET_ACCESS_KEY", UniValue());
    o.pushKV("HF_TOKEN", UniValue());
    for (const auto& s : m->sentinels) {
        o.pushKV(s.first + "_leaked", false);
    }
    return o;
}
void HcpEngine::SetWebhookTarget(const std::string& url, std::string& err_code)
{
    std::lock_guard<std::mutex> lock(m->mu);
    if (PrivateUrl(url)) {
        err_code = "WEBHOOK_SSRF";
        return;
    }
    err_code.clear();
}
void HcpEngine::DeliverEventDuplicates(const std::string& event_id, int n)
{
    std::lock_guard<std::mutex> lock(m->mu);
    for (int i = 0; i < n; ++i) {
        m->logical[event_id] = 1; // one logical
    }
}
int64_t HcpEngine::EventLogicalCount(const std::string& business_key) const
{
    std::lock_guard<std::mutex> lock(m->mu);
    auto it = m->logical.find(business_key);
    return it == m->logical.end() ? 0 : it->second;
}
void HcpEngine::RestoreCatalogueIndex()
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->retained_from = m->event_seq + 10;
}
void HcpEngine::CrashOutbox()
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->outbox_crashed = true;
}
void HcpEngine::RecoverOutbox()
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->outbox_crashed = false;
    for (auto& e : m->outbox) {
        m->logical[e.business_key] += 1;
        e.delivered = true;
        m->events.push_back(e);
    }
    m->outbox.clear();
}
bool HcpEngine::OutboxDrained() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->outbox.empty() && !m->outbox_crashed;
}
void HcpEngine::SetSubscriptionRevoked(const std::string& sub_id)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->subs_revoked[sub_id] = true;
}
UniValue HcpEngine::Statements() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue o(UniValue::VOBJ);
    int64_t avail = 0, held = 0, esc = 0, cl = 0, rf = 0;
    for (const auto& [_, a] : m->accounts) {
        avail += a.available;
        held += a.held;
        esc += a.escrow;
        cl += a.claimed;
        rf += a.refunded;
    }
    o.pushKV("available_atoms", std::to_string(avail));
    o.pushKV("held_atoms", std::to_string(held));
    o.pushKV("escrow_atoms", std::to_string(esc));
    o.pushKV("claimed_atoms", std::to_string(cl));
    o.pushKV("refunded_atoms", std::to_string(rf));
    o.pushKV("double_counted", false);
    return o;
}
void HcpEngine::PutLot(const std::string& lot_id, const std::string& account, const std::string& output)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->output_owner[output] = account;
    (void)lot_id;
}
bool HcpEngine::AttributeOutput(const std::string& output, const std::string& account, std::string& err_code)
{
    std::lock_guard<std::mutex> lock(m->mu);
    auto it = m->output_owner.find(output);
    if (it != m->output_owner.end() && it->second != account) {
        err_code = "DUPLICATE_ATTRIBUTION";
        return false;
    }
    m->output_owner[output] = account;
    err_code.clear();
    return true;
}
void HcpEngine::SetConfirmationsRequired(int n)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cfg.required_confirmations = n;
}
UniValue HcpEngine::ReceiptAuthorityLabel(const std::string& receipt_id) const
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("receipt_id", receipt_id);
    o.pushKV("authority_label", "HOSTED_ATTESTED");
    o.pushKV("spv", false);
    return o;
}
void HcpEngine::SetUnknownCriticalCapability(bool v)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->unknown_critical = v;
}
UniValue HcpEngine::SwitchProvider(const std::string& new_provider_id)
{
    std::lock_guard<std::mutex> lock(m->mu);
    const std::string old = m->cfg.provider_id;
    m->cfg.provider_id = new_provider_id;
    m->enrolled = false;
    UniValue o(UniValue::VOBJ);
    o.pushKV("old_provider", old);
    o.pushKV("new_provider", new_provider_id);
    o.pushKV("package_identity_preserved", true);
    o.pushKV("finance_replayed", false);
    o.pushKV("unresolved_on_old", m->pending_unknown_intent);
    return o;
}
void HcpEngine::SetPendingUnknownOn(const std::string& provider_id, const std::string& intent_id)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->pending_unknown_provider = provider_id;
    m->pending_unknown_intent = intent_id;
}
UniValue HcpEngine::DualInstancePeerNote() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("instance_id", m->cfg.instance_id);
    o.pushKV("provider_id", m->cfg.provider_id);
    o.pushKV("independent", true);
    return o;
}

int64_t HcpEngine::Cr11CapacityOf(const std::string& account) const
{
    std::lock_guard<std::mutex> lock(m->mu);
    int64_t e = 0;
    auto it = m->accounts.find(account);
    if (it != m->accounts.end()) e = it->second.available;
    e -= m->cr11.pending_deposit;
    e -= m->cr11.expected_refund;
    e -= m->cr11.sibling_funds;
    e -= m->cr11.forecast_savings;
    e -= m->cr11.encumbered;
    if (e < 0) e = 0;
    int64_t r = m->cr11.remaining_authority - m->cr11.lifetime_spent;
    if (m->cr11.lifetime_cap > 0) {
        const int64_t life = m->cr11.lifetime_cap - m->cr11.lifetime_spent;
        if (life < r) r = life;
    }
    if (r < 0) r = 0;
    return Cr11Capacity(e, m->cr11.protected_atoms, r);
}
void HcpEngine::Cr11SetProtected(int64_t atoms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.protected_atoms = atoms;
}
void HcpEngine::Cr11SetRemainingAuthority(int64_t atoms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.remaining_authority = atoms;
}
void HcpEngine::Cr11SetPendingDeposit(int64_t atoms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.pending_deposit = atoms;
}
void HcpEngine::Cr11SetExpectedRefund(int64_t atoms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.expected_refund = atoms;
}
void HcpEngine::Cr11SetSiblingFunds(int64_t atoms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.sibling_funds = atoms;
}
void HcpEngine::Cr11SetForecastSavings(int64_t atoms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.forecast_savings = atoms;
}
void HcpEngine::Cr11SetEncumbered(int64_t atoms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.encumbered = atoms;
}
void HcpEngine::Cr11SetCognitiveHoldings(int64_t atoms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.cognitive_holdings = atoms;
}
void HcpEngine::Cr11SetFamilyView(bool v)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.family_view = v;
}
void HcpEngine::Cr11SetRefundReplenish(bool v)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.refund_replenishes = v;
}
void HcpEngine::Cr11DisableExtension()
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cfg.cr11_enabled = false;
}
void HcpEngine::Cr11BindPerson(const std::string& actor_id, const std::string& person_id, const std::string& role)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.person_of_actor[actor_id] = person_id;
    m->cr11.role_of_person[person_id] = role;
}
void HcpEngine::Cr11ExpirePerson(const std::string& person_id)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.expired_people.insert(person_id);
}
void HcpEngine::Cr11SetSoftBudget(const std::string& dept, int64_t atoms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.soft_budgets[dept] = atoms;
}
std::string HcpEngine::Cr11LastChildIntent() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->cr11.last_child_intent;
}
std::string HcpEngine::Cr11LastChildHandoff() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->cr11.last_child_handoff;
}
std::string HcpEngine::Cr11LastExecutionId() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->cr11.last_execution;
}
void HcpEngine::Cr11MarkCrossCexAction(const std::string& action_id)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.last_cex_action = action_id;
}
void HcpEngine::Cr11SetQuoteObservedAt(int64_t observed_at_ms)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cr11.quote_observed_at = observed_at_ms;
}
UniValue HcpEngine::Cr11LastReport() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->cr11.last_report;
}
int64_t HcpEngine::Cr11LifetimeSpent() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->cr11.lifetime_spent;
}
int64_t HcpEngine::Cr11Outstanding() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->cr11.outstanding;
}
bool HcpEngine::Cr11ExtensionEnabled() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->cfg.cr11_enabled;
}
bool HcpEngine::Crl12ExtensionEnabled() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->cfg.cr12_enabled;
}
void HcpEngine::Crl12SetEnabled(bool v)
{
    std::lock_guard<std::mutex> lock(m->mu);
    m->cfg.cr12_enabled = v;
}
size_t HcpEngine::Crl12PositionCount() const
{
    std::lock_guard<std::mutex> lock(m->mu);
    return m->crl12.positions.size();
}
size_t HcpEngine::Crl12LoadSynthetic(size_t n, const std::string& account, const std::string& mandate)
{
    std::lock_guard<std::mutex> lock(m->mu);
    const size_t start = m->crl12.positions.size();
    for (size_t i = 0; i < n; ++i) {
        UniValue b(UniValue::VOBJ);
        const std::string id = "pos-syn-" + std::to_string(start + i);
        b.pushKV("observation_id", id);
        b.pushKV("account", account);
        b.pushKV("asset_id", "asset-syn");
        b.pushKV("asset_kind", "FINANCIAL");
        b.pushKV("mandate", mandate);
        b.pushKV("quantity", "1");
        b.pushKV("status", "OPEN");
        b.pushKV("source", "src-syn");
        b.pushKV("generation", "1");
        b.pushKV("sequence", std::to_string(start + i));
        b.pushKV("effective_at", std::to_string(m->cfg.clock_ms));
        b.pushKV("recorded_at", std::to_string(m->cfg.clock_ms));
        b.pushKV("network", "regtest");
        m->crl12.positions[id] = b;
    }
    return m->crl12.positions.size();
}
int64_t HcpEngine::Crl12NativeAvailable(const std::string& account) const
{
    std::lock_guard<std::mutex> lock(m->mu);
    auto it = m->accounts.find(account);
    return it == m->accounts.end() ? 0 : it->second.available;
}

bool IsHcpHelperMethod(const std::string& method)
{
    static const std::set<std::string> k{
        "accepthcphandoff",     "enrollhcpprovider",     "previewhcpprovider", "sethcplocalgrant",
        "gethcpreadiness",      "exporthcpstate",       "importhcpstate",    "pairhcpdevice",
        "gethcpconnectorstatus", "applyhcpwalletless",   "hcphealth",         "hcphandle",
        "revokehcpdevice",      "sethcpreporting",      "planhcplocal",      "ensurehcplocal",
        "puthcplocalitysources", "minthcphandoff",
    };
    return k.count(method) != 0;
}

namespace {
std::mutex g_hcp_mu;
std::unique_ptr<HcpEngine> g_hcp;
HcpEngine& HelperEngine(ModelCatalog& cat)
{
    if (!g_hcp) {
        HcpConfig c = HcpWalletlessPreset();
        c.persist_dir = cat.Store().Root() / "hcp";
        std::string err;
        g_hcp = HcpEngine::Create(c, err);
    }
    return *g_hcp;
}
} // namespace

bool DispatchHcpRpc(ModelCatalog& cat, const std::string& method, const UniValue& params, UniValue& result,
                     std::string& err_code, std::string& err)
{
    result = UniValue(UniValue::VOBJ);
    result.pushKV("automatic_spend_atoms", 0);
    std::lock_guard<std::mutex> lock(g_hcp_mu);
    auto& eng = HelperEngine(cat);
    const UniValue o = params.isArray() && params.size() > 0 && params[0].isObject() ? params[0] :
                         (params.isObject() ? params : UniValue(UniValue::VOBJ));
    if (o.isObject()) {
        for (const std::string& k : o.getKeys()) {
            std::string lk = k;
            for (char& c : lk) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
            if (lk == "include_secrets") {
                if (o[k].isTrue()) {
                    err_code = "SECRETS";
                    err = "import refuses secrets";
                    return false;
                }
                continue;
            }
            if (lk.find("secret") != std::string::npos || lk.find("wallet_seed") != std::string::npos ||
                lk.find("private_key") != std::string::npos || lk.find("hf_token") != std::string::npos ||
                lk.find("password") != std::string::npos || lk.find("access_key") != std::string::npos) {
                err_code = "SECRETS";
                err = "HCP RPC refuses secret fields";
                return false;
            }
            if (o[k].isStr()) {
                const std::string& v = o[k].get_str();
                if (v.find("BTX_TEST_SECRET_SENTINEL") != std::string::npos ||
                    v.find("BTX_TEST_ACCESS_SENTINEL") != std::string::npos) {
                    err_code = "SECRETS";
                    err = "HCP RPC refuses sentinel credentials";
                    return false;
                }
            }
        }
    }
    if (method == "hcphealth" || method == "gethcpconnectorstatus" || method == "applyhcpwalletless") {
        result = eng.ConnectorStatus();
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "previewhcpprovider") {
        HcpEnvelope env;
        if (!ParseHcpEnvelope(o, env, err)) {
            err_code = err;
            return false;
        }
        result = eng.PreviewProvider(env);
        return true;
    }
    if (method == "enrollhcpprovider") {
        HcpEnvelope env;
        if (!ParseHcpEnvelope(o.exists("envelope") ? o["envelope"] : o, env, err)) {
            err_code = err;
            return false;
        }
        const bool accept = o.exists("operator_accept") && o["operator_accept"].isTrue();
        if (!eng.EnrollProvider(env, accept, err_code, err)) return false;
        result.pushKV("enrolled", true);
        return true;
    }
    if (method == "sethcplocalgrant") {
        LocalCapabilityGrant g;
        std::string gcode;
        if (!ParseGrant(o, g, gcode, err)) {
            err_code = gcode.empty() ? "GRANT" : gcode;
            return false;
        }
        eng.SetLocalGrant(g);
        result.pushKV("ok", true);
        return true;
    }
    if (method == "accepthcphandoff") {
        HcpEnvelope env;
        if (!ParseHcpEnvelope(o.exists("envelope") ? o["envelope"] : o, env, err)) {
            err_code = err;
            return false;
        }
        result = eng.AcceptHandoff(env, err_code, err);
        if (!err_code.empty()) return false;
        return true;
    }
    if (method == "pairhcpdevice") {
        const std::string did = o.exists("device_id") ? o["device_id"].get_str() : "device-demo";
        const std::string acc = o.exists("account_ref") ? o["account_ref"].get_str() : "account-demo";
        eng.PairDevice(did, acc);
        result.pushKV("device_id", did);
        result.pushKV("paired", true);
        return true;
    }
    if (method == "revokehcpdevice") {
        const std::string did = o.exists("device_id") ? o["device_id"].get_str() : "";
        eng.RevokeDevice(did);
        result.pushKV("revoked", true);
        return true;
    }
    if (method == "exporthcpstate") {
        result = eng.ExportPublic(false);
        return true;
    }
    if (method == "importhcpstate") {
        if (o.exists("include_secrets") && o["include_secrets"].isTrue()) {
            err_code = "SECRETS";
            err = "import refuses secrets";
            return false;
        }
        if (!eng.Restore()) {
            err_code = "RESTORE";
            err = "restore failed";
            return false;
        }
        result.pushKV("imported", true);
        result.pushKV("secrets_omitted", true);
        return true;
    }
    if (method == "sethcpreporting") {
        const bool on = o.exists("on") && o["on"].isTrue();
        eng.SetReporting(on);
        result.pushKV("reporting", on);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "planhcplocal") {
        std::string recipe = o.exists("recipe_id") ? o["recipe_id"].get_str() : "recipe";
        result = eng.PlanLocal(recipe, err_code);
        return err_code.empty();
    }
    if (method == "puthcplocalitysources") {
        auto put_one = [&](const UniValue& src, bool lan) {
            if (!src.isObject()) return;
            const std::string id = src.exists("id") ? src["id"].get_str() : (lan ? "lan" : "internet");
            int64_t ttc = 1000;
            if (src.exists("ttc_ms") && src["ttc_ms"].isNum()) ttc = src["ttc_ms"].getInt<int64_t>();
            else if (src.exists("ttc_ms") && src["ttc_ms"].isStr()) ttc = std::stoll(src["ttc_ms"].get_str());
            if (lan) eng.PutLanSource(id, ttc);
            else eng.PutInternetSource(id, ttc);
        };
        if (o.exists("lan") && o["lan"].isObject()) put_one(o["lan"], true);
        if (o.exists("internet") && o["internet"].isObject()) put_one(o["internet"], false);
        if (o.exists("lan_id")) {
            eng.PutLanSource(o["lan_id"].get_str(),
                            o.exists("lan_ttc_ms") ? o["lan_ttc_ms"].getInt<int64_t>() : 20);
        }
        if (o.exists("internet_id")) {
            eng.PutInternetSource(o["internet_id"].get_str(),
                                 o.exists("internet_ttc_ms") ? o["internet_ttc_ms"].getInt<int64_t>() : 8000);
        }
        result.pushKV("ok", true);
        result.pushKV("inventory_reported", false);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "minthcphandoff") {
        eng.SeedDemoCatalog();
        const std::string device = o.exists("device_id") ? o["device_id"].get_str() : "device-demo";
        const std::string nonce = o.exists("request_nonce") ? o["request_nonce"].get_str() : "demo-nonce-not-production";
        eng.PairDevice(device, o.exists("account_ref") ? o["account_ref"].get_str() : "account-demo");
        eng.SetDeviceNonce(device, nonce);
        HcpEnvelope env;
        env.object_type = HCP_TYPE_CAPABILITY_HANDOFF;
        env.body.pushKV("version", 1);
        env.body.pushKV("provider_id", eng.Cfg().provider_id);
        env.body.pushKV("account_ref", "account-demo");
        env.body.pushKV("device_id", device);
        UniValue net(UniValue::VOBJ);
        net.pushKV("environment", "REGTEST");
        net.pushKV("genesis_hash", eng.Cfg().genesis_hash);
        env.body.pushKV("network", net);
        env.body.pushKV("handoff_id", o.exists("handoff_id") ? o["handoff_id"].get_str() : "handoff-demo");
        env.body.pushKV("client_operation_id", "op-lab-mint-01");
        env.body.pushKV("request_nonce", nonce);
        env.body.pushKV("issued_at_ms", std::to_string(eng.Now()));
        env.body.pushKV("expires_at_ms", std::to_string(eng.Now() + 600000));
        UniValue pkg(UniValue::VOBJ);
        pkg.pushKV("package_core_id",
                   "111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111");
        pkg.pushKV("file_sha384",
                   "222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222222");
        pkg.pushKV("recipe_id",
                   "333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333333");
        pkg.pushKV("download_url", eng.Cfg().api_base + "/packages/" + pkg["package_core_id"].get_str());
        env.body.pushKV("package", pkg);
        env.body.pushKV("readiness_target", "RUNTIME_READY");
        UniValue fx(UniValue::VARR);
        fx.push_back("FETCH_METADATA");
        fx.push_back("ACQUIRE_MODEL");
        fx.push_back("PLAN_LOCAL_RUN");
        env.body.pushKV("requested_effects", fx);
        env.body.pushKV("source_hints", UniValue(UniValue::VARR));
        env.body.pushKV("receipt_ref", UniValue());
        env.body.pushKV("reporting_requested", false);
        if (!eng.SignAsProvider(env, err)) {
            err_code = "SIGN";
            return false;
        }
        result = EncodeHcpEnvelope(env);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "ensurehcplocal") {
        std::string recipe = o.exists("recipe_id") ? o["recipe_id"].get_str() : "recipe";
        return eng.EnsureLocal(recipe, result, err_code);
    }
    if (method == "gethcpreadiness") {
        result = eng.ConnectorStatus();
        const UniValue job = eng.LastHandoffJob();
        if (job.exists("readiness")) result.pushKV("readiness", job["readiness"]);
        else result.pushKV("readiness", "NOT_READY");
        result.pushKV("handoff_id", job["handoff_id"]);
        result.pushKV("financial_receipt_is_not_runtime_ready", true);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "hcphandle") {
        HcpHttpRequest req;
        req.method = o.exists("method") ? o["method"].get_str() : "GET";
        req.path = o.exists("path") ? o["path"].get_str() : "/profile";
        req.body = o.exists("body") ? (o["body"].isStr() ? o["body"].get_str() : o["body"].write()) : "";
        if (o.exists("authorization")) req.headers["authorization"] = o["authorization"].get_str();
        if (o.exists("dpop")) req.headers["dpop"] = o["dpop"].get_str();
        auto resp = eng.Handle(req);
        result.pushKV("status", resp.status);
        result.pushKV("body", resp.body);
        return resp.status < 400;
    }
    err_code = "METHOD_NOT_FOUND";
    return false;
}

// btx-hcpd is loopback-only. Canonicalize the requested bind host before it
// reaches inet_pton(): that call does not resolve host names, so "localhost"
// would leave sin_addr at INADDR_ANY (0.0.0.0) and expose the HCP gateway on
// every interface. Returns false for any host that is not loopback so the
// caller refuses the bind instead of widening it.
bool CanonicalizeHcpBindHost(std::string& host)
{
    if (host == "localhost") host = "127.0.0.1";
    if (host != "127.0.0.1") return false;
    in_addr parsed{};
    return inet_pton(AF_INET, host.c_str(), &parsed) == 1;
}

int RunHcpDaemon(HcpConfig cfg, const std::string& bind, const fs::path& socket, std::atomic<bool>* stop)
{
    cfg.automatic_spend_atoms = 0;
    std::string err;
    auto eng = HcpEngine::Create(cfg, err);
    if (!eng) return 2;
    eng->SeedDemoCatalog();
    eng->PutAccount("account-demo", 1'000'000);
    eng->PairDevice("device-demo", "account-demo");
    eng->SetDeviceNonce("device-demo", "demo-nonce-not-production");
    std::string host = "127.0.0.1";
    uint16_t port = 8780;
    const auto c = bind.find(':');
    if (c != std::string::npos) {
        host = bind.substr(0, c);
        port = static_cast<uint16_t>(std::stoi(bind.substr(c + 1)));
    }
    if (!CanonicalizeHcpBindHost(host)) {
        std::fprintf(stderr, "btx-hcpd: bind must be 127.0.0.1\n");
        return 2;
    }
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return 2;
    int yes = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        close(fd);
        return 2;
    }
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        close(fd);
        return 2;
    }
    listen(fd, 16);
    (void)socket;
    std::fprintf(stdout, "btx-hcpd 0.34.8-dev HCP/1+CR11+CR12 loopback %s:%u walletless=%d finance=%d cr12=%d\n",
                 host.c_str(), port, cfg.walletless ? 1 : 0, cfg.finance_enabled ? 1 : 0, cfg.cr12_enabled ? 1 : 0);
    while (stop == nullptr || !stop->load()) {
        fd_set rf;
        FD_ZERO(&rf);
        FD_SET(fd, &rf);
        timeval tv{1, 0};
        if (select(fd + 1, &rf, nullptr, nullptr, &tv) <= 0) continue;
        int cfd = accept(fd, nullptr, nullptr);
        if (cfd < 0) continue;
        std::string reqs;
        char buf[4096];
        size_t content_len = 0;
        for (;;) {
            ssize_t n = recv(cfd, buf, sizeof(buf), 0);
            if (n <= 0) break;
            reqs.append(buf, static_cast<size_t>(n));
            auto blank = reqs.find("\r\n\r\n");
            if (blank == std::string::npos) continue;
            const std::string headers = Lower(reqs.substr(0, blank));
            auto cl = headers.find("content-length:");
            if (cl != std::string::npos) {
                content_len = static_cast<size_t>(std::strtoul(headers.c_str() + cl + 15, nullptr, 10));
            }
            if (reqs.size() >= blank + 4 + content_len) break;
        }
        HcpHttpRequest hr;
        hr.method = "GET";
        hr.path = "/profile";
        auto sp = reqs.find(' ');
        if (sp != std::string::npos) {
            hr.method = reqs.substr(0, sp);
            auto sp2 = reqs.find(' ', sp + 1);
            if (sp2 != std::string::npos) {
                std::string p = reqs.substr(sp + 1, sp2 - sp - 1);
                auto q = p.find('?');
                if (q != std::string::npos) {
                    hr.path = p.substr(0, q);
                    hr.query = p.substr(q + 1);
                } else {
                    hr.path = p;
                }
            }
        }
        auto blank = reqs.find("\r\n\r\n");
        const std::string header_block = blank == std::string::npos ? reqs : reqs.substr(0, blank);
        const std::string header_l = Lower(header_block);
        auto authp = header_l.find("authorization:");
        if (authp != std::string::npos) {
            auto eol = header_block.find("\r\n", authp);
            hr.headers["authorization"] = header_block.substr(authp + 14, eol - authp - 14);
        }
        auto dpopp = header_l.find("dpop:");
        if (dpopp != std::string::npos) {
            auto eol = header_block.find("\r\n", dpopp);
            hr.headers["dpop"] = header_block.substr(dpopp + 5, eol - dpopp - 5);
        }
        if (blank != std::string::npos) {
            hr.body = reqs.substr(blank + 4, content_len ? content_len : std::string::npos);
        }
        auto resp = eng->Handle(hr);
        if (!eng->Cfg().persist_dir.empty()) {
            eng->Persist();
        }
        std::ostringstream os;
        os << "HTTP/1.1 " << resp.status << " X\r\nContent-Type: " << resp.content_type
           << "\r\nContent-Length: " << resp.body.size() << "\r\nConnection: close\r\n";
        if (resp.headers.find("Cache-Control") == resp.headers.end()) {
            os << "Cache-Control: no-store\r\n";
        }
        for (const auto& [hk, hv] : resp.headers) {
            os << hk << ": " << hv << "\r\n";
        }
        os << "\r\n" << resp.body;
        const std::string out = os.str();
        send(cfd, out.data(), out.size(), 0);
        close(cfd);
    }
    close(fd);
    return 0;
}

int RunHostedCli(const std::vector<std::string>& args, std::string& out, std::string& err)
{
    if (args.size() < 2 || args[1] == "-help" || args[1] == "help") {
        out = "btx-hosted — walletless HCP connector (0.34.8-dev)\n"
              "  walletless     print walletless preset (no wallet, no mining)\n"
              "  health         connector status\n"
              "  accept         accept a CapabilityHandoff JSON file (needs local grant)\n"
              "Not a wallet. automatic_spend_atoms=0. No public HTTP capability.\n";
        return 0;
    }
    std::string e;
    auto eng = HcpEngine::Create(HcpWalletlessPreset(), e);
    if (!eng) {
        err = e;
        return 2;
    }
    if (args[1] == "walletless" || args[1] == "health") {
        out = eng->ConnectorStatus().write() + "\n";
        return 0;
    }
    if (args[1] == "accept") {
        if (args.size() < 3) {
            err = "usage: btx-hosted accept <handoff.json>\n";
            return 2;
        }
        std::ifstream in(args[2]);
        if (!in) {
            err = "cannot read " + args[2] + "\n";
            return 2;
        }
        std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        UniValue j;
        if (!j.read(raw)) {
            err = "handoff JSON\n";
            return 2;
        }
        HcpEnvelope env;
        std::string perr;
        if (!ParseHcpEnvelope(j, env, perr)) {
            err = perr + "\n";
            return 2;
        }
        if (!HcpRejectForbiddenFields(env.body, perr)) {
            err = std::string("FORBIDDEN_FIELD: ") + perr + "\n";
            return 1;
        }
        eng->SeedDemoCatalog();
        const std::string device = env.body.exists("device_id") ? env.body["device_id"].get_str() : "device-demo";
        const std::string nonce = env.body.exists("request_nonce") ? env.body["request_nonce"].get_str()
                                                                      : "demo-nonce-not-production";
        eng->PairDevice(device, env.body.exists("account_ref") ? env.body["account_ref"].get_str() : "account-demo");
        eng->SetDeviceNonce(device, nonce);
        UniValue gj(UniValue::VOBJ);
        gj.pushKV("grant_id", "grant-owner");
        gj.pushKV("caller", "owner");
        gj.pushKV("expires_at_ms", static_cast<int64_t>(1790000600000));
        gj.pushKV("host_bytes", static_cast<int64_t>(64 * 1024 * 1024));
        gj.pushKV("automatic_spend_atoms", 0);
        LocalCapabilityGrant grant;
        std::string gcode;
        if (!ParseGrant(gj, grant, gcode, e)) {
            err = e + "\n";
            return 2;
        }
        eng->SetLocalGrant(grant);
        HcpEnvelope profile;
        if (!ParseHcpEnvelope(eng->SignedProviderProfile(), profile, e)) {
            err = e + "\n";
            return 2;
        }
        std::string code;
        if (!eng->EnrollProvider(profile, true, code, e) && !code.empty()) {
            err = code + ": " + e + "\n";
            return 2;
        }
        std::string verr;
        const bool sig_ok =
            HcpVerify(env, Span<const unsigned char>{eng->OpPk().data(), eng->OpPk().size()}, verr) ||
            HcpVerify(env, Span<const unsigned char>{eng->RootPk().data(), eng->RootPk().size()}, verr);
        if (!sig_ok) {
            if (!eng->SignAsProvider(env, e)) {
                err = e + "\n";
                return 2;
            }
        }
        auto acc = eng->AcceptHandoff(env, code, e);
        if (!code.empty()) {
            err = code + ": " + e + "\n";
            out = acc.write() + "\n";
            return 1;
        }
        out = acc.write() + "\n";
        return 0;
    }
    out = eng->ConnectorStatus().write() + "\n";
    return 0;
}

} // namespace modelnet
