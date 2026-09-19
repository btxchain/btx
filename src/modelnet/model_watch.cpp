// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/model_watch.h>

#include <modelnet/crypto.h>
#include <modelnet/resource_uri.h>
#include <modelnet/subscription_mandate.h>
#include <random.h>
#include <span.h>
#include <util/strencodings.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <fstream>
#include <iterator>
#include <memory>
#include <set>
#include <sstream>
#include <utility>

namespace modelnet {
namespace {

std::unique_ptr<ModelWatchStore> g_watches;

int64_t NowMs()
{
    return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count());
}

/** Live, unrevoked SubscriptionMandate. Must not run while ModelWatchStore::m_mu is held. */
bool MandateAdmitsFund(const std::string& mandate_id)
{
    if (mandate_id.empty()) return false;
    UniValue arg(UniValue::VOBJ);
    arg.pushKV("mandate_id", mandate_id);
    UniValue params(UniValue::VARR);
    params.push_back(std::move(arg));
    UniValue status;
    std::string err_code, err;
    if (!GlobalSubscriptionStore().Dispatch("getsubscriptionmandate", params, status, err_code, err, NowMs())) {
        return false;
    }
    // StatusJson exports SubscriptionBudget::Revoked() as "revoked".
    if (status.exists("revoked") && status["revoked"].isTrue()) return false;
    return true;
}

std::string RandHex(size_t nbytes)
{
    std::vector<unsigned char> b(nbytes);
    GetStrongRandBytes(Span<unsigned char>{b.data(), b.size()});
    return HexStr(b);
}

const UniValue& ArgN(const UniValue& params, size_t i)
{
    static const UniValue none;
    if (params.isArray() && params.size() > i) return params[i];
    return none;
}

UniValue ObjArg(const UniValue& params, size_t i)
{
    const UniValue& a = ArgN(params, i);
    if (a.isObject()) return a;
    if (a.isStr()) {
        UniValue o;
        if (o.read(a.get_str()) && o.isObject()) return o;
    }
    return UniValue(UniValue::VOBJ);
}

std::string StrArg(const UniValue& params, size_t i, const std::string& key = {})
{
    const UniValue& a = ArgN(params, i);
    if (a.isStr()) return a.get_str();
    if (a.isNum()) return std::to_string(a.getInt<int64_t>());
    if (a.isObject() && !key.empty() && a.exists(key) && a[key].isStr()) return a[key].get_str();
    return {};
}

int64_t IntArg(const UniValue& params, size_t i, const std::string& key, int64_t def = 0)
{
    const UniValue& a = ArgN(params, i);
    if (a.isNum()) return a.getInt<int64_t>();
    if (a.isStr()) {
        try {
            return std::stoll(a.get_str());
        } catch (...) {
            return def;
        }
    }
    if (a.isObject() && !key.empty() && a.exists(key)) {
        if (a[key].isNum()) return a[key].getInt<int64_t>();
        if (a[key].isStr()) {
            try {
                return std::stoll(a[key].get_str());
            } catch (...) {
                return def;
            }
        }
    }
    return def;
}

uint64_t CursorField(const UniValue& o, const char* k, uint64_t def = 0)
{
    if (!o.exists(k)) return def;
    try {
        if (o[k].isStr() && !o[k].get_str().empty()) return std::stoull(o[k].get_str());
        if (o[k].isNum()) return static_cast<uint64_t>(o[k].getInt<int64_t>());
    } catch (...) {
        return def;
    }
    return def;
}

bool WriteJson(const fs::path& p, const UniValue& o, std::string& err)
{
    fs::create_directories(p.parent_path());
    const fs::path tmp = p + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            err = "write " + fs::PathToString(p);
            return false;
        }
        out << o.write() << "\n";
        out.flush();
        if (!out) {
            err = "flush " + fs::PathToString(p);
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, p, ec);
    if (ec) {
        err = "rename " + fs::PathToString(p);
        return false;
    }
    return true;
}

bool ReadJson(const fs::path& p, UniValue& o)
{
    std::ifstream in(p);
    if (!in) {
        o = UniValue(UniValue::VOBJ);
        return false;
    }
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return o.read(raw);
}

bool FieldHas(const std::vector<std::string>& v, const std::string& n)
{
    const std::string x = NormalizeSearchText(n);
    for (const auto& e : v) {
        if (NormalizeSearchText(e) == x) return true;
    }
    return false;
}

std::string JsonStr(const UniValue& o, const char* k)
{
    if (!o.exists(k) || !o[k].isStr()) return {};
    return o[k].get_str();
}

UniValue FiltersToJson(const SearchFilters& f)
{
    UniValue o(UniValue::VOBJ);
    auto put = [&](const char* k, const std::string& v) {
        if (!v.empty()) o.pushKV(k, v);
    };
    put("publisher_id", f.publisher_id);
    put("publisher_name", f.publisher_name);
    put("family", f.family);
    put("architecture", f.architecture);
    put("format", f.format);
    put("quantization", f.quantization);
    put("license", f.license);
    put("object_kind", f.object_kind);
    if (f.min_size_bytes >= 0) o.pushKV("min_size_bytes", f.min_size_bytes);
    if (f.max_size_bytes >= 0) o.pushKV("max_size_bytes", f.max_size_bytes);
    if (f.min_parameters >= 0) o.pushKV("min_parameters", f.min_parameters);
    if (f.max_parameters >= 0) o.pushKV("max_parameters", f.max_parameters);
    if (f.public_only) o.pushKV("public_only", true);
    if (f.funding_only) o.pushKV("funding_only", true);
    if (f.released_only) o.pushKV("released_only", true);
    if (f.unreleased_only) o.pushKV("unreleased_only", true);
    if (f.locally_verified) o.pushKV("locally_verified", true);
    if (!f.language.empty()) {
        UniValue a(UniValue::VARR);
        for (const auto& x : f.language) a.push_back(x);
        o.pushKV("language", a);
    }
    if (!f.tags.empty()) {
        UniValue a(UniValue::VARR);
        for (const auto& x : f.tags) a.push_back(x);
        o.pushKV("tags", a);
    }
    if (!f.lifecycle_state.empty()) {
        UniValue a(UniValue::VARR);
        for (const auto& x : f.lifecycle_state) a.push_back(x);
        o.pushKV("lifecycle_state", a);
    }
    return o;
}

bool FiltersEmpty(const SearchFilters& f, const std::string& query_text)
{
    if (!query_text.empty()) return false;
    return f.publisher_id.empty() && f.publisher_name.empty() && f.family.empty() && f.architecture.empty() &&
           f.format.empty() && f.quantization.empty() && f.license.empty() && f.object_kind.empty() &&
           f.min_size_bytes < 0 && f.max_size_bytes < 0 && f.min_parameters < 0 && f.max_parameters < 0 &&
           f.language.empty() && f.tags.empty() && f.lifecycle_state.empty() && !f.public_only &&
           !f.funding_only && !f.released_only && !f.unreleased_only;
}

bool ValidName(const std::string& name)
{
    if (name.empty() || name.size() > 64) return false;
    for (unsigned char c : name) {
        if (!(std::isalnum(c) || c == '.' || c == '_' || c == '-')) return false;
    }
    return true;
}

std::string ChannelKey(const std::string& publisher_id, const std::string& name, const std::string& channel)
{
    return publisher_id + "/" + name + ":" + channel;
}

std::vector<unsigned char> ChannelPreimage(const SignedChannel& ch)
{
    const std::string s = ch.publisher_id + "|" + ch.name + "|" + ch.channel + "|" + ch.target_uri + "|" +
                           std::to_string(ch.sequence) + "|" + std::to_string(ch.expiry);
    return std::vector<unsigned char>(s.begin(), s.end());
}

void ForwardEventToWatches(const ModelEvent& ev)
{
    if (g_watches) g_watches->NoteEvent(ev);
}

bool VerifiedEnough(const ModelEvent& ev)
{
    return ev.verification_state == "SIGNED_OK" || ev.verification_state == "CHAIN_OBSERVED";
}

bool QueryFiltersMatch(const ModelWatch& w, const EventMatchFields& m, const ModelEvent& ev)
{
    const SearchFilters& f = w.filters;
    if (!f.publisher_id.empty() && ev.publisher_id != f.publisher_id) return false;
    if (!f.publisher_name.empty() &&
        NormalizeSearchText(m.publisher_name).find(NormalizeSearchText(f.publisher_name)) == std::string::npos) {
        return false;
    }
    if (!f.family.empty() && NormalizeSearchText(m.family) != NormalizeSearchText(f.family)) return false;
    if (!f.architecture.empty() && NormalizeSearchText(m.architecture) != NormalizeSearchText(f.architecture)) {
        return false;
    }
    if (!f.format.empty() && NormalizeSearchText(m.format) != NormalizeSearchText(f.format)) return false;
    if (!f.quantization.empty() && NormalizeSearchText(m.quantization) != NormalizeSearchText(f.quantization)) {
        return false;
    }
    if (f.min_size_bytes >= 0 && (m.size_bytes < 0 || m.size_bytes < f.min_size_bytes)) return false;
    if (f.max_size_bytes >= 0 && (m.size_bytes < 0 || m.size_bytes > f.max_size_bytes)) return false;
    if (f.min_parameters >= 0 && m.parameter_count < f.min_parameters) return false;
    if (f.max_parameters >= 0 && (m.parameter_count <= 0 || m.parameter_count > f.max_parameters)) return false;
    if (!f.license.empty()) {
        const std::string tagged = std::string("license:") + f.license;
        if (!FieldHas(m.tags, f.license) && !FieldHas(m.tags, tagged)) return false;
    }
    if (!f.language.empty()) {
        bool ok = false;
        for (const auto& l : f.language) {
            if (FieldHas(m.languages, l)) ok = true;
        }
        if (!ok) return false;
    }
    if (!f.tags.empty()) {
        bool ok = false;
        for (const auto& t : f.tags) {
            if (FieldHas(m.tags, t)) ok = true;
        }
        if (!ok) return false;
    }
    const std::string kind = m.object_kind.empty() ? ev.object_kind : m.object_kind;
    if (!f.object_kind.empty() && NormalizeSearchText(kind) != NormalizeSearchText(f.object_kind)) return false;
    if (f.funding_only && ev.release_id.empty() && ev.bounty_id.empty()) return false;
    const std::string st = m.release_state.empty() ? "PUBLIC" : ToUpper(m.release_state);
    if (f.released_only && st != "PUBLIC" && st != "PUBLIC_RELEASED" && st != "SECRET_DISCLOSED") return false;
    if (f.unreleased_only && (ev.release_id.empty() || st == "PUBLIC" || st == "PUBLIC_RELEASED")) return false;
    if (f.public_only && !ev.release_id.empty() && st != "PUBLIC" && st != "PUBLIC_RELEASED") return false;
    if (!f.lifecycle_state.empty()) {
        bool ok = false;
        for (const auto& ls : f.lifecycle_state) {
            if (ToUpper(ls) == st) ok = true;
        }
        if (!ok) return false;
    }
    if (!w.query_text.empty()) {
        ModelSearchRecord rec;
        rec.canonical_name = m.canonical_name;
        rec.display_name = m.display_name;
        rec.family = m.family;
        rec.architecture = m.architecture;
        rec.format = m.format;
        rec.quantization = m.quantization;
        rec.tags = m.tags;
        rec.languages = m.languages;
        rec.short_description = ev.untrusted_text;
        rec.object_kind = kind;
        if (RelevanceScore(rec, TokenizeSearch(w.query_text)) <= 0) return false;
    }
    return true;
}

} // namespace

const char* WatchKindName(WatchKind k)
{
    switch (k) {
    case WatchKind::COLLECTION: return "COLLECTION";
    case WatchKind::QUERY: return "QUERY";
    case WatchKind::MODEL: return "MODEL";
    case WatchKind::PUBLISHER:
    default: return "PUBLISHER";
    }
}

bool ParseWatchKind(const std::string& s, WatchKind& out)
{
    const std::string x = ToUpper(s);
    if (x == "PUBLISHER") { out = WatchKind::PUBLISHER; return true; }
    if (x == "COLLECTION") { out = WatchKind::COLLECTION; return true; }
    if (x == "QUERY") { out = WatchKind::QUERY; return true; }
    if (x == "MODEL") { out = WatchKind::MODEL; return true; }
    return false;
}

const char* ActionPolicyName(ActionPolicy a)
{
    switch (a) {
    case ActionPolicy::FREE_DOWNLOAD: return "FREE_DOWNLOAD";
    case ActionPolicy::KEEP: return "KEEP";
    case ActionPolicy::SEED: return "SEED";
    case ActionPolicy::PREPARE_FUNDING: return "PREPARE_FUNDING";
    case ActionPolicy::FUND_WITH_MANDATE: return "FUND_WITH_MANDATE";
    case ActionPolicy::NOTIFY:
    default: return "NOTIFY";
    }
}

bool ParseActionPolicy(const std::string& s, ActionPolicy& out)
{
    const std::string x = ToUpper(s);
    if (x.empty() || x == "NOTIFY") { out = ActionPolicy::NOTIFY; return true; }
    if (x == "FREE_DOWNLOAD") { out = ActionPolicy::FREE_DOWNLOAD; return true; }
    if (x == "KEEP") { out = ActionPolicy::KEEP; return true; }
    if (x == "SEED") { out = ActionPolicy::SEED; return true; }
    if (x == "PREPARE_FUNDING") { out = ActionPolicy::PREPARE_FUNDING; return true; }
    if (x == "FUND_WITH_MANDATE") { out = ActionPolicy::FUND_WITH_MANDATE; return true; }
    return false;
}

bool NormalizeChannelName(const std::string& s, std::string& out)
{
    const std::string x = ToLower(s);
    if (x == "stable" || x == "latest" || x == "research") {
        out = x;
        return true;
    }
    return false;
}

bool SignSignedChannel(SignedChannel& ch, Span<const unsigned char> sk, std::string& err)
{
    if (ch.pubkey.size() != MLDSA44_PK) {
        err = "pubkey";
        return false;
    }
    if (!NormalizeChannelName(ch.channel, ch.channel)) {
        err = "channel";
        return false;
    }
    if (!ValidName(ch.name)) {
        err = "name";
        return false;
    }
    Resource res;
    if (!DecodeResource(ch.target_uri, res, err)) {
        err = "target_uri must be btx://";
        return false;
    }
    ch.publisher_id = ResearchIdentityId(Span<const unsigned char>{ch.pubkey.data(), ch.pubkey.size()}).Hex();
    const auto pre = ChannelPreimage(ch);
    const Digest48 h = DomainHash("BTX/SignedChannel/v1", Span<const unsigned char>{pre.data(), pre.size()});
    if (!SignMlDsa44(sk, Span<const unsigned char>{h.data.data(), h.data.size()}, ch.sig, err)) return false;
    ch.signature_ok = true;
    return true;
}

bool VerifySignedChannel(const SignedChannel& ch, int64_t now_ms, std::string& err)
{
    if (ch.expiry > 0 && now_ms > 0 && ch.expiry <= now_ms) {
        err = "expired";
        return false;
    }
    std::string chan;
    if (!NormalizeChannelName(ch.channel, chan)) {
        err = "channel";
        return false;
    }
    if (!ValidName(ch.name)) {
        err = "name";
        return false;
    }
    Resource res;
    if (!DecodeResource(ch.target_uri, res, err)) {
        err = "target_uri must be btx://";
        return false;
    }
    if (ch.pubkey.size() != MLDSA44_PK || ch.sig.empty()) {
        err = "unsigned";
        return false;
    }
    const Digest48 pid = ResearchIdentityId(Span<const unsigned char>{ch.pubkey.data(), ch.pubkey.size()});
    if (pid.Hex() != ch.publisher_id) {
        err = "publisher_id";
        return false;
    }
    SignedChannel tmp = ch;
    tmp.channel = chan;
    const auto pre = ChannelPreimage(tmp);
    const Digest48 h = DomainHash("BTX/SignedChannel/v1", Span<const unsigned char>{pre.data(), pre.size()});
    if (!VerifyMlDsa44(Span<const unsigned char>{ch.pubkey.data(), ch.pubkey.size()},
                        Span<const unsigned char>{h.data.data(), h.data.size()},
                        Span<const unsigned char>{ch.sig.data(), ch.sig.size()})) {
        err = "signature";
        return false;
    }
    return true;
}

std::string ChannelObjectId(const SignedChannel& ch)
{
    std::string chan = ch.channel;
    NormalizeChannelName(ch.channel, chan);
    return ChannelKey(ch.publisher_id, ch.name, chan);
}

UniValue ModelWatchToJson(const ModelWatch& w)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("watch_id", w.watch_id);
    o.pushKV("kind", WatchKindName(w.kind));
    o.pushKV("action", ActionPolicyName(w.action));
    o.pushKV("publisher_id", w.publisher_id);
    o.pushKV("collection_id", w.collection_id);
    o.pushKV("model_id", w.model_id);
    o.pushKV("filters", FiltersToJson(w.filters));
    o.pushKV("query_text", w.query_text);
    o.pushKV("keep_n", w.keep_n);
    o.pushKV("created_at", w.created_at);
    if (!w.mandate_id.empty()) o.pushKV("mandate_id", w.mandate_id);
    o.pushKV("downloads", false);
    o.pushKV("evaluates", false);
    o.pushKV("spends", false);
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("filesystem_watch", false);
    return o;
}

UniValue WatchActionToJson(const QueuedWatchAction& a)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("watch_id", a.watch_id);
    o.pushKV("action", ActionPolicyName(a.action));
    o.pushKV("object_id", a.object_id);
    o.pushKV("event_id", a.event_id);
    o.pushKV("job_id", a.job_id);
    o.pushKV("spends", false);
    o.pushKV("downloads", a.downloads);
    o.pushKV("requires_mandate", a.requires_mandate);
    o.pushKV("automatic_spend_atoms", 0);
    if (!a.publisher_id.empty()) o.pushKV("publisher_id", a.publisher_id);
    if (!a.mandate_id.empty()) o.pushKV("mandate_id", a.mandate_id);
    if (a.action == ActionPolicy::FREE_DOWNLOAD) {
        o.pushKV("getmodel_mode", "FREE_ONLY");
        o.pushKV("queued_for_coordinator", true);
    }
    if (a.action == ActionPolicy::PREPARE_FUNDING) {
        o.pushKV("unsigned", true);
        o.pushKV("wallet_signed", false);
        o.pushKV("wallet", false);
        o.pushKV("plan", "unsigned");
        o.pushKV("prepare_funding", true);
    }
    if (a.action == ActionPolicy::FUND_WITH_MANDATE) {
        o.pushKV("unsigned", true);
        o.pushKV("wallet_signed", false);
        o.pushKV("wallet", false);
        o.pushKV("spends", false);
        o.pushKV("plan", "unsigned");
    }
    return o;
}

UniValue SignedChannelToJson(const SignedChannel& ch)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("publisher_id", ch.publisher_id);
    o.pushKV("name", ch.name);
    o.pushKV("channel", ch.channel);
    o.pushKV("target_uri", ch.target_uri);
    o.pushKV("sequence", static_cast<int64_t>(ch.sequence));
    o.pushKV("expiry", ch.expiry);
    o.pushKV("signature_ok", ch.signature_ok);
    o.pushKV("object_id", ChannelObjectId(ch));
    o.pushKV("alias", false);
    o.pushKV("identity", false);
    return o;
}

bool WatchMatchesEvent(const ModelWatch& watch, const ModelEvent& ev)
{
    switch (watch.kind) {
    case WatchKind::PUBLISHER:
        if (watch.publisher_id.empty() || ev.publisher_id != watch.publisher_id) return false;
        return VerifiedEnough(ev);
    case WatchKind::COLLECTION:
        if (!watch.collection_id.empty()) {
            if (ev.collection_id == watch.collection_id || ev.object_id == watch.collection_id) return VerifiedEnough(ev);
        }
        return false;
    case WatchKind::MODEL: {
        const std::string want = watch.model_id;
        if (want.empty()) return false;
        if (ev.model_id != want && ev.object_id != want) return false;
        // Same admission as PUBLISHER / COLLECTION / QUERY. Unsigned remote
        // search records are LOCAL_OBSERVED and must not match a MODEL watch
        // (that would queue FREE_ONLY getmodel of an attacker-nominated id).
        return VerifiedEnough(ev);
    }
    case WatchKind::QUERY:
        if (!VerifiedEnough(ev)) return false;
        return QueryFiltersMatch(watch, ev.match, ev);
    }
    return false;
}

bool SearchRecordMatchesWatch(const ModelWatch& watch, const ModelSearchRecord& rec)
{
    ModelEvent ev;
    if (!ModelEventFromSearchRecord(rec, ev)) return false;
    return WatchMatchesEvent(watch, ev);
}

bool ModelWatchStore::PersistWatchesLocked(std::string& err) const
{
    if (m_watch_path.empty()) return true;
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 1);
    UniValue arr(UniValue::VARR);
    for (const auto& kv : m_watches) arr.push_back(ModelWatchToJson(kv.second));
    o.pushKV("watches", arr);
    return WriteJson(m_watch_path, o, err);
}

bool ModelWatchStore::PersistChannelsLocked(std::string& err) const
{
    if (m_channel_path.empty()) return true;
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 1);
    UniValue arr(UniValue::VARR);
    for (const auto& kv : m_channels) {
        UniValue c = SignedChannelToJson(kv.second);
        c.pushKV("pubkey", HexStr(kv.second.pubkey));
        c.pushKV("signature", HexStr(kv.second.sig));
        arr.push_back(c);
    }
    o.pushKV("channels", arr);
    return WriteJson(m_channel_path, o, err);
}

bool ModelWatchStore::LoadLocked(std::string& err)
{
    m_watches.clear();
    m_channels.clear();
    if (!m_watch_path.empty() && fs::exists(m_watch_path)) {
        UniValue o;
        if (ReadJson(m_watch_path, o) && o.isObject() && o.exists("watches") && o["watches"].isArray()) {
            for (const auto& wj : o["watches"].getValues()) {
                if (!wj.isObject()) continue;
                ModelWatch w;
                w.watch_id = JsonStr(wj, "watch_id");
                if (w.watch_id.empty()) continue;
                if (wj.exists("kind")) ParseWatchKind(wj["kind"].get_str(), w.kind);
                if (wj.exists("action")) ParseActionPolicy(wj["action"].get_str(), w.action);
                w.publisher_id = JsonStr(wj, "publisher_id");
                w.collection_id = JsonStr(wj, "collection_id");
                w.model_id = JsonStr(wj, "model_id");
                w.query_text = JsonStr(wj, "query_text");
                w.mandate_id = JsonStr(wj, "mandate_id");
                if (wj.exists("keep_n") && wj["keep_n"].isNum()) w.keep_n = wj["keep_n"].getInt<int>();
                if (wj.exists("created_at")) w.created_at = wj["created_at"].getInt<int64_t>();
                if (wj.exists("filters") && wj["filters"].isObject()) {
                    SearchQuery q;
                    UniValue qo(UniValue::VOBJ);
                    qo.pushKV("filters", wj["filters"]);
                    std::string perr;
                    (void)ParseSearchQuery(qo, q, perr);
                    w.filters = q.filters;
                }
                m_watches[w.watch_id] = std::move(w);
            }
        }
    }
    if (!m_channel_path.empty() && fs::exists(m_channel_path)) {
        UniValue o;
        if (ReadJson(m_channel_path, o) && o.isObject() && o.exists("channels") && o["channels"].isArray()) {
            for (const auto& cj : o["channels"].getValues()) {
                if (!cj.isObject()) continue;
                SignedChannel ch;
                ch.publisher_id = JsonStr(cj, "publisher_id");
                ch.name = JsonStr(cj, "name");
                ch.channel = JsonStr(cj, "channel");
                ch.target_uri = JsonStr(cj, "target_uri");
                if (cj.exists("sequence")) ch.sequence = static_cast<uint64_t>(cj["sequence"].getInt<int64_t>());
                if (cj.exists("expiry")) ch.expiry = cj["expiry"].getInt<int64_t>();
                ch.signature_ok = cj.exists("signature_ok") && cj["signature_ok"].get_bool();
                if (cj.exists("pubkey")) ch.pubkey = ParseHex(cj["pubkey"].get_str());
                if (cj.exists("signature")) ch.sig = ParseHex(cj["signature"].get_str());
                m_channels[ChannelObjectId(ch)] = std::move(ch);
            }
        }
    }
    (void)err;
    return true;
}

ModelWatchStore::ModelWatchStore(fs::path modeldir)
{
    if (!modeldir.empty()) {
        m_dir = std::move(modeldir);
        m_watch_path = m_dir / "watches.json";
        m_channel_path = m_dir / "channels.json";
        std::string err;
        (void)LoadLocked(err);
    }
}

bool ModelWatchStore::PutWatch(ModelWatch& w, std::string& err)
{
    if (w.watch_id.empty()) w.watch_id = RandHex(8);
    if (w.created_at <= 0) w.created_at = NowMs();
    if (w.kind == WatchKind::PUBLISHER && w.publisher_id.empty()) {
        err = "publisher_id";
        return false;
    }
    if (w.kind == WatchKind::COLLECTION && w.collection_id.empty()) {
        err = "collection_id";
        return false;
    }
    if (w.kind == WatchKind::MODEL && w.model_id.empty()) {
        err = "model_id";
        return false;
    }
    if (w.kind == WatchKind::QUERY && FiltersEmpty(w.filters, w.query_text)) {
        err = "query filters required";
        return false;
    }
    if (w.action == ActionPolicy::FUND_WITH_MANDATE && w.mandate_id.empty()) {
        err = "FUND_WITH_MANDATE requires mandate_id";
        return false;
    }
    std::lock_guard<std::mutex> lock(m_mu);
    m_watches[w.watch_id] = w;
    return PersistWatchesLocked(err);
}

bool ModelWatchStore::GetWatch(const std::string& watch_id, ModelWatch& out) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_watches.find(watch_id);
    if (it == m_watches.end()) return false;
    out = it->second;
    return true;
}

bool ModelWatchStore::RemoveWatch(const std::string& watch_id)
{
    std::lock_guard<std::mutex> lock(m_mu);
    const bool gone = m_watches.erase(watch_id) > 0;
    std::string err;
    (void)PersistWatchesLocked(err);
    return gone;
}

std::vector<ModelWatch> ModelWatchStore::List() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    std::vector<ModelWatch> out;
    out.reserve(m_watches.size());
    for (const auto& kv : m_watches) out.push_back(kv.second);
    return out;
}

void ModelWatchStore::EnqueueLocked(const ModelWatch& w, const ModelEvent& ev)
{
    if (w.action == ActionPolicy::NOTIFY) return;
    QueuedWatchAction a;
    a.watch_id = w.watch_id;
    a.action = w.action;
    a.object_id = ev.object_id;
    a.event_id = ev.event_id;
    a.job_id = RandHex(8);
    a.publisher_id = ev.publisher_id;
    a.mandate_id = w.mandate_id;
    a.spends = false;
    a.downloads = w.action == ActionPolicy::FREE_DOWNLOAD;
    a.requires_mandate = w.action == ActionPolicy::FUND_WITH_MANDATE;
    m_actions.push_back(std::move(a));
}

void ModelWatchStore::NoteEvent(const ModelEvent& ev)
{
    std::lock_guard<std::mutex> lock(m_mu);
    for (const auto& kv : m_watches) {
        if (WatchMatchesEvent(kv.second, ev)) EnqueueLocked(kv.second, ev);
    }
}

std::vector<QueuedWatchAction> ModelWatchStore::DrainActions()
{
    std::vector<QueuedWatchAction> queued;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        queued.swap(m_actions);
    }
    std::vector<QueuedWatchAction> out;
    out.reserve(queued.size());
    std::map<std::string, bool> fund_ok;
    for (auto& a : queued) {
        a.spends = false;
        if (a.action == ActionPolicy::FUND_WITH_MANDATE) {
            auto it = fund_ok.find(a.mandate_id);
            if (it == fund_ok.end()) {
                it = fund_ok.emplace(a.mandate_id, MandateAdmitsFund(a.mandate_id)).first;
            }
            if (!it->second) continue;
        }
        out.push_back(std::move(a));
    }
    return out;
}

std::vector<QueuedWatchAction> ModelWatchStore::PeekActions() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_actions;
}

bool ModelWatchStore::ApplySignedChannel(SignedChannel ch, std::string& err)
{
    if (!NormalizeChannelName(ch.channel, ch.channel)) {
        err = "channel must be stable|latest|research";
        return false;
    }
    if (ch.sequence == 0) {
        err = "sequence";
        return false;
    }
    const int64_t now = NowMs();
    if (!VerifySignedChannel(ch, now, err)) {
        ch.signature_ok = false;
        return false;
    }
    ch.signature_ok = true;
    const std::string key = ChannelObjectId(ch);
    ModelEvent ev;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        auto it = m_channels.find(key);
        if (it != m_channels.end()) {
            if (ch.sequence <= it->second.sequence) {
                err = "channel sequence rollback";
                return false;
            }
        }
        m_channels[key] = ch;
        if (!PersistChannelsLocked(err)) return false;
    }
    if (!m_journal) return true;
    ev.event_type = ModelEventType::CHANNEL_UPDATED;
    ev.object_kind = "ALIAS";
    ev.object_id = key;
    ev.publisher_id = ch.publisher_id;
    ev.record_sequence = ch.sequence;
    ev.source = "CHANNEL";
    ev.verification_state = "SIGNED_OK";
    ev.new_state = ch.target_uri;
    ev.old_state = "";
    ev.untrusted_text = SanitizeUntrustedEventText(ch.name);
    ev.provenance.setObject();
    ev.provenance.pushKV("channel", ch.channel);
    ev.provenance.pushKV("name", ch.name);
    ev.provenance.pushKV("locally_derived", true);
    ObserveResult ores;
    return m_journal->Observe(std::move(ev), ores, err);
}

bool ModelWatchStore::GetChannel(const std::string& publisher_id, const std::string& name, const std::string& channel,
                                SignedChannel& out) const
{
    std::string chan;
    if (!NormalizeChannelName(channel, chan)) return false;
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_channels.find(ChannelKey(publisher_id, name, chan));
    if (it == m_channels.end()) return false;
    out = it->second;
    return true;
}

std::vector<SignedChannel> ModelWatchStore::ListChannels() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    std::vector<SignedChannel> out;
    out.reserve(m_channels.size());
    for (const auto& kv : m_channels) out.push_back(kv.second);
    return out;
}

void BindModelEventLayer(const fs::path& modeldir, size_t cap)
{
    SetModelEventListener(nullptr);
    g_watches.reset();
    BindModelEventJournal(modeldir, cap);
    g_watches = std::make_unique<ModelWatchStore>(modeldir);
    if (ModelEventJournal* j = BoundModelEventJournal()) g_watches->BindJournal(j);
    SetModelEventListener(&ForwardEventToWatches);
}

ModelWatchStore* BoundModelWatchStore()
{
    return g_watches.get();
}

bool IsModelWatchHelperMethod(const std::string& method)
{
    static const std::set<std::string> k = {
        "watchmodelpublisher",
        "watchmodelcollection",
        "watchmodelquery",
        "watchmodel",
        "listmodelwatches",
        "getmodelwatch",
        "unwatchmodel",
        "getmodelevents",
        "getmodeleventsequence",
        "waitformodelevent",
        "getmodelwatchactions",
        "observemodelchannel",
        "seedlabmodelchannel",
        "getmodelchannel",
        "listmodelchannels",
    };
    return k.count(method) > 0;
}

bool DispatchModelWatchRpc(const std::string& method, const UniValue& params, UniValue& result, std::string& err_code,
                           std::string& err, std::atomic<bool>* stop)
{
    result = UniValue(UniValue::VOBJ);
    if (!IsModelWatchHelperMethod(method)) return false;
    auto fail = [&](const std::string& code, const std::string& e) {
        err_code = code;
        err = e;
        return false;
    };
    if (!BoundModelEventJournal() || !BoundModelWatchStore()) {
        return fail("NOT_READY", "event journal not bound");
    }
    ModelEventJournal& journal = *BoundModelEventJournal();
    ModelWatchStore& watches = *BoundModelWatchStore();
    const UniValue a = ObjArg(params, 0);

    auto parse_action = [&](ActionPolicy& act) -> bool {
        act = ActionPolicy::NOTIFY;
        std::string raw;
        if (a.exists("action") && a["action"].isStr()) raw = a["action"].get_str();
        if (raw.empty()) return true;
        if (!ParseActionPolicy(raw, act)) {
            err_code = "INVALID_PARAMETER";
            err = "action";
            return false;
        }
        return true;
    };
    auto parse_mandate = [&](ModelWatch& w) {
        if (a.exists("mandate_id") && a["mandate_id"].isStr()) w.mandate_id = a["mandate_id"].get_str();
    };

    if (method == "watchmodelpublisher") {
        ModelWatch w;
        w.kind = WatchKind::PUBLISHER;
        w.publisher_id = a.exists("publisher_id") ? JsonStr(a, "publisher_id") : StrArg(params, 0, "publisher_id");
        if (!parse_action(w.action)) return false;
        parse_mandate(w);
        if (!watches.PutWatch(w, err)) return fail("INVALID_PARAMETER", err);
        ModelWatch stored;
        watches.GetWatch(w.watch_id, stored);
        result = ModelWatchToJson(stored);
        return true;
    }
    if (method == "watchmodelcollection") {
        ModelWatch w;
        w.kind = WatchKind::COLLECTION;
        w.collection_id = a.exists("collection_id") ? JsonStr(a, "collection_id") : StrArg(params, 0, "collection_id");
        if (a.exists("keep_n")) w.keep_n = a["keep_n"].getInt<int>();
        if (!parse_action(w.action)) return false;
        parse_mandate(w);
        if (!watches.PutWatch(w, err)) return fail("INVALID_PARAMETER", err);
        ModelWatch stored;
        watches.GetWatch(w.watch_id, stored);
        result = ModelWatchToJson(stored);
        return true;
    }
    if (method == "watchmodelquery") {
        ModelWatch w;
        w.kind = WatchKind::QUERY;
        SearchQuery q;
        UniValue qo(UniValue::VOBJ);
        if (a.exists("filters") && a["filters"].isObject()) qo.pushKV("filters", a["filters"]);
        else qo.pushKV("filters", a);
        if (a.exists("text") && a["text"].isStr()) {
            qo.pushKV("text", a["text"].get_str());
            w.query_text = a["text"].get_str();
        }
        if (!ParseSearchQuery(qo, q, err)) return fail("INVALID_PARAMETER", err);
        w.filters = q.filters;
        if (w.query_text.empty()) w.query_text = q.text;
        if (!parse_action(w.action)) return false;
        parse_mandate(w);
        if (!watches.PutWatch(w, err)) return fail("INVALID_PARAMETER", err);
        ModelWatch stored;
        watches.GetWatch(w.watch_id, stored);
        result = ModelWatchToJson(stored);
        return true;
    }
    if (method == "watchmodel") {
        ModelWatch w;
        w.kind = WatchKind::MODEL;
        w.model_id = a.exists("model_id") ? JsonStr(a, "model_id") : StrArg(params, 0, "model_id");
        if (!parse_action(w.action)) return false;
        parse_mandate(w);
        if (!watches.PutWatch(w, err)) return fail("INVALID_PARAMETER", err);
        ModelWatch stored;
        watches.GetWatch(w.watch_id, stored);
        result = ModelWatchToJson(stored);
        return true;
    }
    if (method == "listmodelwatches") {
        UniValue arr(UniValue::VARR);
        for (const auto& w : watches.List()) arr.push_back(ModelWatchToJson(w));
        result.pushKV("watches", arr);
        result.pushKV("filesystem_watch", false);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodelwatch") {
        const std::string id = a.exists("watch_id") ? JsonStr(a, "watch_id") : StrArg(params, 0, "watch_id");
        ModelWatch w;
        if (!watches.GetWatch(id, w)) return fail("NOT_FOUND", "watch");
        result = ModelWatchToJson(w);
        return true;
    }
    if (method == "unwatchmodel") {
        const std::string id = a.exists("watch_id") ? JsonStr(a, "watch_id") : StrArg(params, 0, "watch_id");
        const bool removed = watches.RemoveWatch(id);
        result.pushKV("watch_id", id);
        result.pushKV("removed", removed);
        return true;
    }
    if (method == "getmodeleventsequence") {
        result.pushKV("sequence", static_cast<int64_t>(journal.Cursor()));
        result.pushKV("schema_version", MODEL_EVENT_SCHEMA_VERSION);
        return true;
    }
    if (method == "getmodelevents") {
        uint64_t cursor = CursorField(a, "cursor", 0);
        if (!a.exists("cursor") && params.isArray() && params.size() > 0 && ArgN(params, 0).isNum()) {
            cursor = static_cast<uint64_t>(ArgN(params, 0).getInt<int64_t>());
        }
        int limit = static_cast<int>(MODEL_EVENT_PAGE_MAX);
        if (a.exists("limit") && a["limit"].isNum()) limit = a["limit"].getInt<int>();
        if (limit <= 0) limit = static_cast<int>(MODEL_EVENT_PAGE_MAX);
        if (limit > static_cast<int>(MODEL_EVENT_PAGE_MAX)) limit = static_cast<int>(MODEL_EVENT_PAGE_MAX);
        const auto items = journal.ReplayAfter(cursor, static_cast<size_t>(limit));
        UniValue arr(UniValue::VARR);
        for (const auto& ev : items) arr.push_back(ModelEventToJson(ev));
        result.pushKV("events", arr);
        result.pushKV("cursor", std::to_string(journal.Cursor()));
        result.pushKV("gap", false);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "waitformodelevent") {
        uint64_t cursor = CursorField(a, "cursor", 0);
        if (!a.exists("cursor")) cursor = static_cast<uint64_t>(IntArg(params, 0, "cursor", 0));
        int timeout_ms = 0;
        if (a.exists("timeout_ms") && a["timeout_ms"].isNum()) timeout_ms = a["timeout_ms"].getInt<int>();
        else if (a.exists("timeout_ms") && a["timeout_ms"].isStr()) {
            try {
                timeout_ms = static_cast<int>(std::stoll(a["timeout_ms"].get_str()));
            } catch (...) {
                timeout_ms = 0;
            }
        } else if (params.isArray() && params.size() > 1) timeout_ms = static_cast<int>(IntArg(params, 1, "timeout_ms", 0));
        std::vector<ModelEvent> items;
        bool interrupted = false;
        if (!journal.WaitAfter(cursor, timeout_ms, stop, items, interrupted, err)) {
            return fail("INTERNAL", err.empty() ? "waitformodelevent" : err);
        }
        UniValue arr(UniValue::VARR);
        for (const auto& ev : items) arr.push_back(ModelEventToJson(ev));
        result.pushKV("events", arr);
        result.pushKV("cursor", std::to_string(journal.Cursor()));
        result.pushKV("interrupted", interrupted);
        result.pushKV("timeout", items.empty() && !interrupted);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "getmodelwatchactions") {
        const bool drain = !a.exists("drain") || a["drain"].get_bool();
        const auto acts = drain ? watches.DrainActions() : watches.PeekActions();
        UniValue arr(UniValue::VARR);
        for (const auto& act : acts) arr.push_back(WatchActionToJson(act));
        result.pushKV("actions", arr);
        result.pushKV("spends", false);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "observemodelchannel") {
        SignedChannel ch;
        ch.publisher_id = JsonStr(a, "publisher_id");
        ch.name = JsonStr(a, "name");
        ch.channel = JsonStr(a, "channel");
        ch.target_uri = JsonStr(a, "target_uri");
        if (a.exists("sequence")) ch.sequence = static_cast<uint64_t>(a["sequence"].getInt<int64_t>());
        if (a.exists("expiry")) ch.expiry = a["expiry"].getInt<int64_t>();
        if (a.exists("pubkey")) ch.pubkey = ParseHex(a["pubkey"].get_str());
        if (a.exists("signature")) ch.sig = ParseHex(a["signature"].get_str());
        if (!watches.ApplySignedChannel(ch, err)) return fail("REJECTED", err);
        SignedChannel stored;
        watches.GetChannel(ch.publisher_id, ch.name, ch.channel, stored);
        result = SignedChannelToJson(stored);
        return true;
    }
    if (method == "seedlabmodelchannel") {
        std::vector<unsigned char> pk, sk;
        if (!GenerateMlDsa44(pk, sk, err)) return fail("INTERNAL", err);
        Digest48 mid{};
        mid.data[0] = 0x51;
        if (a.exists("model_id") && a["model_id"].isStr()) {
            if (!Digest48::FromHex(a["model_id"].get_str(), mid, err)) return fail("INVALID_PARAMETER", err);
        }
        std::string uri;
        if (!EncodeResource(ResourceKind::MODEL, mid, uri, err)) return fail("INTERNAL", err);
        SignedChannel ch;
        ch.pubkey = pk;
        ch.name = a.exists("name") && a["name"].isStr() ? a["name"].get_str() : "coder";
        ch.channel = a.exists("channel") && a["channel"].isStr() ? a["channel"].get_str() : "stable";
        ch.target_uri = uri;
        ch.sequence = 1;
        ch.expiry = 0;
        if (!SignSignedChannel(ch, Span<const unsigned char>{sk.data(), sk.size()}, err)) {
            return fail("REJECTED", err);
        }
        if (!watches.ApplySignedChannel(ch, err)) return fail("REJECTED", err);
        SignedChannel stored;
        watches.GetChannel(ch.publisher_id, ch.name, ch.channel, stored);
        result = SignedChannelToJson(stored);
        result.pushKV("pubkey", HexStr(pk));
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("lab_seeded", true);
        return true;
    }
    if (method == "getmodelchannel") {
        SignedChannel ch;
        if (!watches.GetChannel(JsonStr(a, "publisher_id"), JsonStr(a, "name"), JsonStr(a, "channel"), ch)) {
            return fail("NOT_FOUND", "channel");
        }
        result = SignedChannelToJson(ch);
        result.pushKV("automatic_spend_atoms", 0);
        return true;
    }
    if (method == "listmodelchannels") {
        UniValue arr(UniValue::VARR);
        for (const auto& ch : watches.ListChannels()) arr.push_back(SignedChannelToJson(ch));
        result.pushKV("channels", arr);
        return true;
    }
    return fail("NOT_FOUND", "method");
}

} // namespace modelnet
