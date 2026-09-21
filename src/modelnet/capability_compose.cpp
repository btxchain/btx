// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.
//
// Worker G exclusive: modular composition / LoRA / generation update.
// Defines AttachExactBaseAdapter, ComposeLoraOrder, JournalSwitch, CrashResumeSwitch.
// Coordinator must drop the placeholder copies in capability_exec.cpp.

#include <modelnet/capability.h>

#include <span.h>

#include <algorithm>
#include <cstdlib>
#include <map>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

std::mutex g_compose_mu;

struct ResidentBase {
    Digest48 id{};
    std::vector<unsigned char> bytes;
    int fetch_count{0};
    int adapter_attach_count{0};
};

std::map<std::string, ResidentBase> g_resident;

struct SessionComp {
    Digest48 composition{};
    std::vector<std::string> adapters;
    std::vector<std::string> scales;
};

std::map<std::string, SessionComp> g_sessions;

struct PreparedGen {
    std::string lock;
    std::string digest;
    int client_min{0};
    bool smoke_ok{false};
    bool smoke_failed{false};
};

struct SwitchState {
    std::string active;
    int active_client_min{0};
    std::string active_digest;
    std::map<std::string, PreparedGen> prepared;
    std::map<std::string, int> consumers;
    std::map<std::string, std::pair<std::string, std::string>> idempo; // key -> (lock, digest)
};

SwitchState g_switch;

bool Fail(std::string& err_code, std::string& err, const char* code, const std::string& msg)
{
    err_code = code;
    err = msg.empty() ? code : msg;
    return false;
}

std::map<std::string, std::string> SplitAttrs(const std::string& s)
{
    std::map<std::string, std::string> m;
    std::string id;
    size_t start = 0;
    while (start <= s.size()) {
        const size_t bar = s.find('|', start);
        const std::string tok = s.substr(start, bar == std::string::npos ? std::string::npos : bar - start);
        const size_t eq = tok.find('=');
        if (eq == std::string::npos) {
            if (id.empty() && !tok.empty()) id = tok;
        } else {
            m[tok.substr(0, eq)] = tok.substr(eq + 1);
        }
        if (bar == std::string::npos) break;
        start = bar + 1;
    }
    if (!id.empty()) m["id"] = id;
    else if (m.find("id") == m.end()) m["id"] = s;
    return m;
}

int AttrInt(const std::map<std::string, std::string>& m, const char* k, int def)
{
    auto it = m.find(k);
    if (it == m.end() || it->second.empty()) return def;
    return std::atoi(it->second.c_str());
}

std::string Attr(const std::map<std::string, std::string>& m, const char* k)
{
    auto it = m.find(k);
    return it == m.end() ? std::string() : it->second;
}

std::string CompStr(const UniValue& c, const char* k)
{
    if (!c.isObject() || !c.exists(k)) return {};
    if (c[k].isStr()) return c[k].get_str();
    if (c[k].isNum()) return c[k].getValStr();
    return {};
}

bool CompTrue(const UniValue& c, const char* k)
{
    return c.isObject() && c.exists(k) && (c[k].isTrue() || (c[k].isStr() && c[k].get_str() == "true"));
}

std::string RoleOf(const UniValue& c)
{
    return CompStr(c, "role");
}

bool TokenizerContractOk(const CapabilityRecipe& recipe, std::string& err_code, std::string& err)
{
    if (!recipe.json.isObject() || !recipe.json.exists("components") || !recipe.json["components"].isArray()) {
        return true;
    }
    std::string base_tok, base_vocab, base_tok_digest;
    std::string adapter_tok, adapter_vocab, adapter_tok_digest;
    std::string tokenizer_comp_digest;
    bool silent_resize = false;
    // Package-authored "validated_tokenizer_transform" is not a trust root. A recipe
    // cannot self-attest a tokenizer/vocab resize or mismatch.

    for (const auto& c : recipe.json["components"].getValues()) {
        if (!c.isObject()) continue;
        const std::string role = RoleOf(c);
        const std::string tok = CompStr(c, "tokenizer");
        const std::string vocab = CompStr(c, "vocab_size").empty() ? CompStr(c, "vocabulary_size") : CompStr(c, "vocab_size");
        const std::string tdig = CompStr(c, "tokenizer_digest").empty() ? CompStr(c, "vocab_digest") : CompStr(c, "tokenizer_digest");
        if (CompTrue(c, "vocab_resize") || CompTrue(c, "silent_resize") || CompTrue(c, "pad_vocab") ||
            CompTrue(c, "resize_embeddings")) {
            silent_resize = true;
        }
        if (role == "BASE") {
            if (!tok.empty()) base_tok = tok;
            if (!vocab.empty()) base_vocab = vocab;
            if (!tdig.empty()) base_tok_digest = tdig;
        } else if (role == "ADAPTER" || role == "PROJECTOR") {
            if (!tok.empty()) adapter_tok = tok;
            if (!vocab.empty()) adapter_vocab = vocab;
            if (!tdig.empty()) adapter_tok_digest = tdig;
        } else if (role == "TOKENIZER") {
            if (c.exists("resource") && c["resource"].isObject() && c["resource"].exists("digest48") &&
                c["resource"]["digest48"].isStr()) {
                tokenizer_comp_digest = c["resource"]["digest48"].get_str();
            }
            if (!tok.empty()) adapter_tok = tok;
            if (!vocab.empty()) adapter_vocab = vocab;
            if (!tdig.empty()) adapter_tok_digest = tdig;
        }
    }
    if (recipe.json.exists("tokenizer") && recipe.json["tokenizer"].isStr()) {
        if (base_tok.empty()) base_tok = recipe.json["tokenizer"].get_str();
    }

    if (silent_resize) {
        return Fail(err_code, err, "TOKENIZER_CONFLICT", "silent vocab/embedding resize is forbidden");
    }
    if (!adapter_tok.empty() && !base_tok.empty() && adapter_tok != base_tok) {
        return Fail(err_code, err, "TOKENIZER_CONFLICT", "adapter tokenizer does not match base");
    }
    if (!adapter_vocab.empty() && !base_vocab.empty() && adapter_vocab != base_vocab) {
        return Fail(err_code, err, "TOKENIZER_CONFLICT", "adapter vocab_size does not match base");
    }
    if (!adapter_tok_digest.empty() && !base_tok_digest.empty() && adapter_tok_digest != base_tok_digest) {
        return Fail(err_code, err, "TOKENIZER_CONFLICT", "tokenizer digest mismatch");
    }
    if (!tokenizer_comp_digest.empty() && !base_tok_digest.empty() && tokenizer_comp_digest != base_tok_digest) {
        return Fail(err_code, err, "TOKENIZER_CONFLICT", "tokenizer component incompatible with base");
    }
    return true;
}

bool StartsWith(const std::string& s, const char* pfx)
{
    const size_t n = std::char_traits<char>::length(pfx);
    return s.size() >= n && s.compare(0, n, pfx) == 0;
}

} // namespace

bool AttachExactBaseAdapter(const Digest48& base_id, const Digest48& adapter_base_binding, std::string& err_code,
                            std::string& err)
{
    if (base_id.IsNull() || adapter_base_binding.IsNull()) {
        return Fail(err_code, err, "ADAPTER_BASE_MISMATCH", "missing exact base binding");
    }
    if (base_id != adapter_base_binding) {
        return Fail(err_code, err, "ADAPTER_BASE_MISMATCH",
                    "adapter base_binding does not match loaded base");
    }
    return true;
}

bool ComposeLoraOrder(const std::vector<std::string>& adapter_ids, const std::vector<std::string>& scales,
                      Digest48& composition_id, std::string& err)
{
    composition_id = {};
    if (!scales.empty() && scales.size() != adapter_ids.size()) {
        err = "adapter/scale arity";
        return false;
    }
    UniValue o(UniValue::VOBJ);
    UniValue ids(UniValue::VARR);
    for (const auto& a : adapter_ids) ids.push_back(a);
    UniValue sc(UniValue::VARR);
    if (scales.empty()) {
        for (size_t i = 0; i < adapter_ids.size(); ++i) sc.push_back("1");
    } else {
        for (const auto& s : scales) sc.push_back(s);
    }
    o.pushKV("adapters", ids);
    o.pushKV("scales", sc);
    o.pushKV("merged", false);
    o.pushKV("automatic_spend_atoms", 0);
    return CapabilityObjectIdJson("BTX/AdapterComposition/v1", o, composition_id, err);
}

bool ComposeRecipeAdapters(const CapabilityRecipe& recipe, Digest48& composition_id, std::string& err_code,
                            std::string& err)
{
    composition_id = {};
    err_code.clear();
    err.clear();
    if (!TokenizerContractOk(recipe, err_code, err)) return false;

    Digest48 base{};
    std::vector<std::string> adapters;
    std::vector<std::string> scales;
    if (recipe.json.isObject() && recipe.json.exists("components") && recipe.json["components"].isArray()) {
        for (const auto& c : recipe.json["components"].getValues()) {
            if (!c.isObject()) continue;
            const std::string role = RoleOf(c);
            std::string digest;
            if (c.exists("resource") && c["resource"].isObject() && c["resource"].exists("digest48") &&
                c["resource"]["digest48"].isStr()) {
                digest = c["resource"]["digest48"].get_str();
            }
            if (role == "BASE" && !digest.empty()) {
                std::string herr;
                (void)Digest48::FromHex(digest, base, herr);
            }
            if (role == "ADAPTER") {
                if (c.exists("base_binding") && c["base_binding"].isStr()) {
                    Digest48 bind{};
                    std::string herr;
                    if (!Digest48::FromHex(c["base_binding"].get_str(), bind, herr) ||
                        !AttachExactBaseAdapter(base, bind, err_code, err)) {
                        return false;
                    }
                }
                if (!digest.empty()) adapters.push_back(digest);
                const std::string sc = CompStr(c, "scale");
                scales.push_back(sc.empty() ? "1" : sc);
            }
        }
    }
    if (!ComposeLoraOrder(adapters, scales, composition_id, err)) {
        err_code = "NONCANONICAL_PAYLOAD";
        return false;
    }
    return true;
}

bool PinResidentBase(const Digest48& base_id, Span<const unsigned char> bytes, std::string& err)
{
    if (base_id.IsNull()) {
        err = "base id";
        return false;
    }
    std::lock_guard<std::mutex> lock(g_compose_mu);
    ResidentBase& r = g_resident[base_id.Hex()];
    if (r.fetch_count == 0) {
        r.id = base_id;
        r.bytes.assign(bytes.begin(), bytes.end());
        r.fetch_count = 1;
    }
    err.clear();
    return true;
}

int ResidentBaseFetchCount(const Digest48& base_id)
{
    std::lock_guard<std::mutex> lock(g_compose_mu);
    auto it = g_resident.find(base_id.Hex());
    return it == g_resident.end() ? 0 : it->second.fetch_count;
}

int ResidentAdapterAttachCount(const Digest48& base_id)
{
    std::lock_guard<std::mutex> lock(g_compose_mu);
    auto it = g_resident.find(base_id.Hex());
    return it == g_resident.end() ? 0 : it->second.adapter_attach_count;
}

bool ActivateAdapterOnResidentBase(const Digest48& base_id, const Digest48& adapter_id,
                                    const Digest48& adapter_base_binding, std::string& err_code, std::string& err)
{
    (void)adapter_id;
    if (!AttachExactBaseAdapter(base_id, adapter_base_binding, err_code, err)) return false;
    std::lock_guard<std::mutex> lock(g_compose_mu);
    auto it = g_resident.find(base_id.Hex());
    if (it == g_resident.end()) {
        return Fail(err_code, err, "ADAPTER_BASE_MISMATCH", "base is not resident");
    }
    ++it->second.adapter_attach_count;
    return true;
}

bool BindSessionComposition(const std::string& session_id, const std::vector<std::string>& adapters,
                            const std::vector<std::string>& scales, Digest48& composition_id, std::string& err)
{
    if (session_id.empty()) {
        err = "session";
        return false;
    }
    if (!ComposeLoraOrder(adapters, scales, composition_id, err)) return false;
    std::lock_guard<std::mutex> lock(g_compose_mu);
    SessionComp s;
    s.composition = composition_id;
    s.adapters = adapters;
    s.scales = scales;
    g_sessions[session_id] = std::move(s);
    return true;
}

bool SessionCompositionId(const std::string& session_id, Digest48& out)
{
    std::lock_guard<std::mutex> lock(g_compose_mu);
    auto it = g_sessions.find(session_id);
    if (it == g_sessions.end()) return false;
    out = it->second.composition;
    return true;
}

bool MergeAdapterRepresentation(const Digest48& base_id, const std::vector<unsigned char>& original_base,
                                const std::vector<std::string>& adapters, const std::vector<std::string>& scales,
                                Digest48& merged_id, std::vector<unsigned char>& merged_bytes, std::string& err)
{
    merged_id = {};
    merged_bytes.clear();
    UniValue base_obj(UniValue::VOBJ);
    base_obj.pushKV("base", base_id.Hex());
    base_obj.pushKV("merged", false);
    base_obj.pushKV("automatic_spend_atoms", 0);
    Digest48 base_rep{};
    if (!CapabilityObjectIdJson(REPRESENTATION_DOMAIN, base_obj, base_rep, err)) return false;

    UniValue merged(UniValue::VOBJ);
    merged.pushKV("base", base_id.Hex());
    UniValue ids(UniValue::VARR);
    for (const auto& a : adapters) ids.push_back(a);
    UniValue sc(UniValue::VARR);
    for (const auto& s : scales) sc.push_back(s);
    merged.pushKV("adapters", ids);
    merged.pushKV("scales", sc);
    merged.pushKV("merged", true);
    merged.pushKV("transform", "lora-merge-v1");
    merged.pushKV("automatic_spend_atoms", 0);
    if (!CapabilityObjectIdJson(REPRESENTATION_DOMAIN, merged, merged_id, err)) return false;
    if (merged_id == base_rep) {
        err = "merged identity collided with base";
        return false;
    }
    merged_bytes = original_base;
    merged_bytes.insert(merged_bytes.end(), {'M', 'E', 'R', 'G', 'E'});
    for (const auto& a : adapters) {
        merged_bytes.insert(merged_bytes.end(), a.begin(), a.end());
    }
    return true;
}

PhysicalDisposition DetachAdapterLease(LeaseTable& leases, const std::string& lease_id, bool still_inflight)
{
    LeaseRecord* l = leases.Find(lease_id);
    if (!l) return PhysicalDisposition::NOT_DISPATCHED;
    return leases.Cancel(lease_id, still_inflight);
}

void ResetCapabilityComposeState()
{
    std::lock_guard<std::mutex> lock(g_compose_mu);
    g_resident.clear();
    g_sessions.clear();
    g_switch = {};
}

std::string ComposeActiveLock()
{
    std::lock_guard<std::mutex> lock(g_compose_mu);
    return g_switch.active;
}

int ComposeConsumerRefs(const std::string& lock_id)
{
    const auto attrs = SplitAttrs(lock_id);
    const std::string id = Attr(attrs, "id");
    std::lock_guard<std::mutex> lock(g_compose_mu);
    auto it = g_switch.consumers.find(id);
    return it == g_switch.consumers.end() ? 0 : it->second;
}

bool JournalSwitch(const std::string& old_lock, const std::string& new_lock, const std::string& phase,
                   std::string& err)
{
    err.clear();
    if (old_lock.empty() || new_lock.empty()) {
        err = "lock ids";
        return false;
    }
    const auto old_a = SplitAttrs(old_lock);
    const auto new_a = SplitAttrs(new_lock);
    const auto ph_a = SplitAttrs(phase);
    const std::string old_id = Attr(old_a, "id");
    const std::string new_id = Attr(new_a, "id");
    const int old_min = AttrInt(old_a, "client_min", 0);
    const int new_min = AttrInt(new_a, "client_min", 0);
    const std::string new_digest = Attr(new_a, "digest");
    const std::string kind = Attr(ph_a, "id");
    const std::string idem = Attr(ph_a, "idem");
    const std::string ph_digest = Attr(ph_a, "digest");
    const std::string digest = !ph_digest.empty() ? ph_digest : new_digest;

    std::lock_guard<std::mutex> lock(g_compose_mu);
    if (g_switch.active.empty()) {
        g_switch.active = old_id;
        g_switch.active_client_min = old_min;
        g_switch.active_digest = Attr(old_a, "digest");
        if (g_switch.consumers[old_id] < 1) g_switch.consumers[old_id] = 1;
    }

    auto ensure_prepared = [&]() -> PreparedGen& {
        PreparedGen& p = g_switch.prepared[new_id];
        p.lock = new_id;
        if (p.digest.empty()) p.digest = digest;
        if (p.client_min == 0) p.client_min = new_min;
        return p;
    };

    if (kind == "prepare" || kind == "prepare-alongside") {
        ensure_prepared();
        if (g_switch.consumers[old_id] < 1) g_switch.consumers[old_id] = 1;
        return true;
    }
    if (kind == "retain-consumer") {
        ++g_switch.consumers[old_id];
        return true;
    }
    if (kind == "release-consumer") {
        auto it = g_switch.consumers.find(old_id);
        if (it != g_switch.consumers.end() && it->second > 0) --it->second;
        return true;
    }
    if (kind == "smoke-ok") {
        PreparedGen& p = ensure_prepared();
        if (p.smoke_failed) {
            err = "SMOKE_FAILED";
            return false;
        }
        p.smoke_ok = true;
        return true;
    }
    if (kind == "smoke-fail") {
        PreparedGen& p = ensure_prepared();
        p.smoke_failed = true;
        p.smoke_ok = false;
        err = "SMOKE_FAILED";
        return false;
    }
    if (kind == "crash-before-commit") {
        ensure_prepared();
        return true;
    }
    if (kind == "rollback") {
        // AttrInt defaults missing client_min to 0. A positive floor still
        // rejects new_min==0 (unlabeled cannot roll back a ranked lock).
        // Two unlabeled locks are not a trust statement either way.
        const int floor = std::max(g_switch.active_client_min, old_min);
        if (floor > 0 && new_min < floor) {
            err = "SOFTWARE_TRUST_REQUIRED";
            return false;
        }
        g_switch.active = new_id.empty() ? old_id : new_id;
        if (new_min > 0) g_switch.active_client_min = new_min;
        else if (old_min > 0) g_switch.active_client_min = old_min;
        return true;
    }

    const bool commit = (kind == "commit" || kind == "crash-after-commit" || kind == "idempotent");
    if (!commit && kind != "switch") {
        err = "unknown phase";
        return false;
    }

    {
        const int floor = std::max(g_switch.active_client_min, old_min);
        if (floor > 0 && new_min < floor) {
            err = "SOFTWARE_TRUST_REQUIRED";
            return false;
        }
    }

    if (!idem.empty()) {
        auto it = g_switch.idempo.find(idem);
        const std::string want = digest.empty() ? new_id : digest;
        if (it != g_switch.idempo.end()) {
            if (it->second.second != want) {
                err = "IDEMPOTENCY_CONFLICT";
                return false;
            }
            g_switch.active = it->second.first;
            return true;
        }
        g_switch.idempo[idem] = {new_id, want};
    }

    PreparedGen& p = ensure_prepared();
    if (p.smoke_failed) {
        err = "SMOKE_FAILED";
        return false;
    }
    g_switch.active = new_id;
    g_switch.active_client_min = new_min > 0 ? new_min : g_switch.active_client_min;
    g_switch.active_digest = digest;
    if (g_switch.consumers[new_id] < 1) g_switch.consumers[new_id] = 1;
    p.smoke_ok = true;
    return true;
}

bool CrashResumeSwitch(const std::vector<std::string>& journal, std::string& active_lock, std::string& err)
{
    active_lock.clear();
    if (journal.empty()) {
        err = "empty journal";
        return false;
    }
    std::string committed;
    std::string prepared;
    bool smoke_failed = false;
    for (const auto& e : journal) {
        if (e.empty()) continue;
        if (e == "INCOMPLETE" || e == "crash-before-commit") {
            prepared.clear();
            continue;
        }
        if (e == "crash-after-commit") {
            if (!prepared.empty() && !smoke_failed) committed = prepared;
            prepared.clear();
            continue;
        }
        if (StartsWith(e, "SMOKE_FAIL:") || e == "SMOKE_FAIL") {
            smoke_failed = true;
            prepared.clear();
            continue;
        }
        if (StartsWith(e, "PREPARE:")) {
            prepared = e.substr(8);
            smoke_failed = false;
            continue;
        }
        if (StartsWith(e, "COMMIT:")) {
            committed = e.substr(7);
            prepared.clear();
            smoke_failed = false;
            continue;
        }
        if (StartsWith(e, "ROLLBACK:")) {
            committed = e.substr(9);
            prepared.clear();
            continue;
        }
        if (committed.empty() && prepared.empty() && e.find(':') == std::string::npos) {
            committed = SplitAttrs(e)["id"];
        }
    }
    if (committed.empty()) {
        committed = SplitAttrs(journal.front())["id"];
    }
    if (committed.empty()) {
        err = "cannot resume";
        return false;
    }
    active_lock = committed;
    err.clear();
    return true;
}

} // namespace modelnet
