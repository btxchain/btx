// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/event_journal.h>

#include <modelnet/crypto.h>
#include <util/strencodings.h>

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <fstream>
#include <initializer_list>
#include <memory>
#include <sstream>
#include <thread>
#include <utility>

namespace modelnet {
namespace {

void (*g_listener)(const ModelEvent&) = nullptr;
std::unique_ptr<ModelEventJournal> g_journal;

int64_t NowMs()
{
    return static_cast<int64_t>(std::chrono::duration_cast<std::chrono::milliseconds>(
                                    std::chrono::system_clock::now().time_since_epoch())
                                    .count());
}

std::string JsonStr(const UniValue& o, const char* k)
{
    if (!o.exists(k) || !o[k].isStr()) return {};
    return o[k].get_str();
}

int64_t JsonI64(const UniValue& o, const char* k, int64_t def = 0)
{
    if (!o.exists(k)) return def;
    if (o[k].isNum()) return o[k].getInt<int64_t>();
    if (o[k].isStr() && !o[k].get_str().empty()) {
        try {
            return std::stoll(o[k].get_str());
        } catch (...) {
            return def;
        }
    }
    return def;
}

std::vector<std::string> JsonStrList(const UniValue& o, const char* k)
{
    std::vector<std::string> out;
    if (!o.exists(k) || !o[k].isArray()) return out;
    for (const auto& x : o[k].getValues()) {
        if (x.isStr()) out.push_back(x.get_str());
    }
    return out;
}

UniValue StrListJson(const std::vector<std::string>& v)
{
    UniValue a(UniValue::VARR);
    for (const auto& s : v) a.push_back(s);
    return a;
}

void FillMatchFromSearch(EventMatchFields& m, const ModelSearchRecord& r)
{
    m.family = r.family;
    m.architecture = r.architecture;
    m.format = r.format;
    m.quantization = r.quantization;
    m.publisher_name = r.publisher_display_name;
    m.canonical_name = r.canonical_name;
    m.display_name = r.display_name;
    m.object_kind = r.object_kind.empty() ? "MODEL" : r.object_kind;
    m.release_state = r.release_state;
    m.parameter_count = r.parameter_count;
    m.size_bytes = r.size_bytes > 0 ? static_cast<int64_t>(r.size_bytes) : -1;
    m.tags = r.tags;
    m.languages = r.languages;
}

std::string FirstNonEmpty(std::initializer_list<std::string> xs)
{
    for (const auto& s : xs) {
        if (!s.empty()) return s;
    }
    return {};
}

} // namespace

const char* ModelEventTypeName(ModelEventType t)
{
    switch (t) {
    case ModelEventType::MODEL_METADATA_UPDATED: return "MODEL_METADATA_UPDATED";
    case ModelEventType::MODEL_PROVIDER_AVAILABLE: return "MODEL_PROVIDER_AVAILABLE";
    case ModelEventType::MODEL_PROVIDER_LOST: return "MODEL_PROVIDER_LOST";
    case ModelEventType::MODEL_RECONSTRUCTABLE: return "MODEL_RECONSTRUCTABLE";
    case ModelEventType::MODEL_NO_LONGER_RECONSTRUCTABLE: return "MODEL_NO_LONGER_RECONSTRUCTABLE";
    case ModelEventType::RELEASE_CREATED: return "RELEASE_CREATED";
    case ModelEventType::RELEASE_FUNDING_CHANGED: return "RELEASE_FUNDING_CHANGED";
    case ModelEventType::RELEASE_FUNDED: return "RELEASE_FUNDED";
    case ModelEventType::RELEASE_FUNDING_REVERTED: return "RELEASE_FUNDING_REVERTED";
    case ModelEventType::RELEASE_SECRET_DISCLOSED: return "RELEASE_SECRET_DISCLOSED";
    case ModelEventType::RELEASE_UNLOCKED: return "RELEASE_UNLOCKED";
    case ModelEventType::BOUNTY_CREATED: return "BOUNTY_CREATED";
    case ModelEventType::BOUNTY_FUNDING_CHANGED: return "BOUNTY_FUNDING_CHANGED";
    case ModelEventType::BOUNTY_FUNDED: return "BOUNTY_FUNDED";
    case ModelEventType::BOUNTY_SUBMISSION_CREATED: return "BOUNTY_SUBMISSION_CREATED";
    case ModelEventType::BOUNTY_AWARDED: return "BOUNTY_AWARDED";
    case ModelEventType::BOUNTY_AWARD_REVERTED: return "BOUNTY_AWARD_REVERTED";
    case ModelEventType::COLLECTION_UPDATED: return "COLLECTION_UPDATED";
    case ModelEventType::PUBLISHER_RECORD_UPDATED: return "PUBLISHER_RECORD_UPDATED";
    case ModelEventType::CHANNEL_UPDATED: return "CHANNEL_UPDATED";
    case ModelEventType::MODEL_PUBLISHED:
    default: return "MODEL_PUBLISHED";
    }
}

bool ParseModelEventType(const std::string& s, ModelEventType& out)
{
    const std::string x = ToUpper(s);
    if (x == "MODEL_PUBLISHED") { out = ModelEventType::MODEL_PUBLISHED; return true; }
    if (x == "MODEL_METADATA_UPDATED") { out = ModelEventType::MODEL_METADATA_UPDATED; return true; }
    if (x == "MODEL_PROVIDER_AVAILABLE") { out = ModelEventType::MODEL_PROVIDER_AVAILABLE; return true; }
    if (x == "MODEL_PROVIDER_LOST") { out = ModelEventType::MODEL_PROVIDER_LOST; return true; }
    if (x == "MODEL_RECONSTRUCTABLE") { out = ModelEventType::MODEL_RECONSTRUCTABLE; return true; }
    if (x == "MODEL_NO_LONGER_RECONSTRUCTABLE") { out = ModelEventType::MODEL_NO_LONGER_RECONSTRUCTABLE; return true; }
    if (x == "RELEASE_CREATED" || x == "RELEASE_CAMPAIGN_CREATED") {
        out = ModelEventType::RELEASE_CREATED;
        return true;
    }
    if (x == "RELEASE_FUNDING_CHANGED") { out = ModelEventType::RELEASE_FUNDING_CHANGED; return true; }
    if (x == "RELEASE_FUNDED") { out = ModelEventType::RELEASE_FUNDED; return true; }
    if (x == "RELEASE_FUNDING_REVERTED") { out = ModelEventType::RELEASE_FUNDING_REVERTED; return true; }
    if (x == "RELEASE_SECRET_DISCLOSED") { out = ModelEventType::RELEASE_SECRET_DISCLOSED; return true; }
    if (x == "RELEASE_UNLOCKED" || x == "MODEL_UNLOCKED") {
        out = ModelEventType::RELEASE_UNLOCKED;
        return true;
    }
    if (x == "BOUNTY_CREATED") { out = ModelEventType::BOUNTY_CREATED; return true; }
    if (x == "BOUNTY_FUNDING_CHANGED") { out = ModelEventType::BOUNTY_FUNDING_CHANGED; return true; }
    if (x == "BOUNTY_FUNDED") { out = ModelEventType::BOUNTY_FUNDED; return true; }
    if (x == "BOUNTY_SUBMISSION_CREATED") { out = ModelEventType::BOUNTY_SUBMISSION_CREATED; return true; }
    if (x == "BOUNTY_AWARDED") { out = ModelEventType::BOUNTY_AWARDED; return true; }
    if (x == "BOUNTY_AWARD_REVERTED") { out = ModelEventType::BOUNTY_AWARD_REVERTED; return true; }
    if (x == "COLLECTION_UPDATED" || x == "COLLECTION_PUBLISHED") {
        out = ModelEventType::COLLECTION_UPDATED;
        return true;
    }
    if (x == "PUBLISHER_RECORD_UPDATED" || x == "PUBLISHER_FIRST_OBSERVED") {
        out = ModelEventType::PUBLISHER_RECORD_UPDATED;
        return true;
    }
    if (x == "CHANNEL_UPDATED") { out = ModelEventType::CHANNEL_UPDATED; return true; }
    return false;
}

ModelEventType ModelEventTypeFromFeed(FeedEventType t)
{
    switch (t) {
    case FeedEventType::MODEL_METADATA_UPDATED: return ModelEventType::MODEL_METADATA_UPDATED;
    case FeedEventType::MODEL_BECAME_AVAILABLE: return ModelEventType::MODEL_RECONSTRUCTABLE;
    case FeedEventType::MODEL_BECAME_FRAGILE: return ModelEventType::MODEL_NO_LONGER_RECONSTRUCTABLE;
    case FeedEventType::COLLECTION_PUBLISHED: return ModelEventType::COLLECTION_UPDATED;
    case FeedEventType::PUBLISHER_FIRST_OBSERVED: return ModelEventType::PUBLISHER_RECORD_UPDATED;
    case FeedEventType::RELEASE_CAMPAIGN_CREATED: return ModelEventType::RELEASE_CREATED;
    case FeedEventType::RELEASE_FUNDING_CHANGED: return ModelEventType::RELEASE_FUNDING_CHANGED;
    case FeedEventType::RELEASE_FUNDED: return ModelEventType::RELEASE_FUNDED;
    case FeedEventType::RELEASE_SECRET_DISCLOSED: return ModelEventType::RELEASE_SECRET_DISCLOSED;
    case FeedEventType::MODEL_UNLOCKED: return ModelEventType::RELEASE_UNLOCKED;
    case FeedEventType::MODEL_PUBLISHED:
    default: return ModelEventType::MODEL_PUBLISHED;
    }
}

bool RevertedEventType(ModelEventType t, ModelEventType& out)
{
    switch (t) {
    case ModelEventType::RELEASE_CREATED:
    case ModelEventType::RELEASE_FUNDING_CHANGED:
    case ModelEventType::RELEASE_FUNDED:
        out = ModelEventType::RELEASE_FUNDING_REVERTED;
        return true;
    case ModelEventType::BOUNTY_FUNDING_CHANGED:
    case ModelEventType::BOUNTY_FUNDED:
    case ModelEventType::BOUNTY_AWARDED:
        out = ModelEventType::BOUNTY_AWARD_REVERTED;
        return true;
    default:
        return false;
    }
}

std::string MakeDedupeKey(const std::string& object_id, uint64_t record_sequence, const std::string& transition)
{
    return object_id + "|" + std::to_string(record_sequence) + "|" + transition;
}

std::string MakeModelEventId(const std::string& dedupe_key)
{
    const Digest48 h = DomainHash("BTX/ModelEvent/v1",
                                 Span<const unsigned char>{reinterpret_cast<const unsigned char*>(dedupe_key.data()),
                                                             dedupe_key.size()});
    return h.Hex();
}

bool ModelEventFromFeed(const FeedEvent& fe, ModelEvent& out)
{
    out = {};
    out.event_type = ModelEventTypeFromFeed(fe.event_type);
    out.observed_at = fe.observed_at;
    out.model_id = fe.model_id.IsNull() ? std::string() : fe.model_id.Hex();
    out.release_id = fe.release_id;
    out.publisher_id = fe.rec.publisher_identity.IsNull() ? std::string() : fe.rec.publisher_identity.Hex();
    out.record_sequence = fe.rec.metadata_sequence > 0 ? fe.rec.metadata_sequence : fe.sequence;
    out.source = "FEED";
    out.verification_state = fe.signed_record ? "SIGNED_OK" : "LOCAL_OBSERVED";
    out.object_kind = fe.rec.object_kind.empty() ? "MODEL" : fe.rec.object_kind;
    if (out.event_type == ModelEventType::COLLECTION_UPDATED) out.object_kind = "COLLECTION";
    if (out.event_type == ModelEventType::PUBLISHER_RECORD_UPDATED) out.object_kind = "IDENTITY";
    if (out.event_type == ModelEventType::RELEASE_CREATED || out.event_type == ModelEventType::RELEASE_FUNDED ||
        out.event_type == ModelEventType::RELEASE_FUNDING_CHANGED ||
        out.event_type == ModelEventType::RELEASE_SECRET_DISCLOSED ||
        out.event_type == ModelEventType::RELEASE_UNLOCKED) {
        out.object_kind = "RELEASE";
    }
    out.bounty_id = fe.rec.bounty_id;
    FillMatchFromSearch(out.match, fe.rec);
    out.untrusted_text = SanitizeUntrustedEventText(fe.rec.description.empty() ? fe.rec.short_description : fe.rec.description);
    out.object_id = FirstNonEmpty({out.model_id, out.release_id, out.publisher_id, fe.event_id});
    if (out.event_type == ModelEventType::PUBLISHER_RECORD_UPDATED && !out.publisher_id.empty()) {
        out.object_id = out.publisher_id;
    }
    out.new_state = ModelEventTypeName(out.event_type);
    out.provenance.setObject();
    out.provenance.pushKV("signed_record", fe.signed_record);
    out.provenance.pushKV("feed_event_id", fe.event_id);
    out.provenance.pushKV("sources_observed", fe.sources_observed);
    out.provenance.pushKV("locally_derived", true);
    if (fe.has_campaign) {
        out.funding.setObject();
        out.funding.pushKV("target_atoms", fe.campaign.target_atoms);
        out.funding.pushKV("pledged_atoms", fe.campaign.pledged_atoms);
        out.funding.pushKV("funded_atoms", fe.campaign.funded_atoms);
        out.funding.pushKV("frozen", fe.campaign.frozen);
    }
    return !out.object_id.empty();
}

bool ModelEventFromSearchRecord(const ModelSearchRecord& r, ModelEvent& out)
{
    out = {};
    out.event_type = r.metadata_sequence > 1 ? ModelEventType::MODEL_METADATA_UPDATED : ModelEventType::MODEL_PUBLISHED;
    if (!r.release_id.empty() && r.metadata_sequence <= 1) out.event_type = ModelEventType::RELEASE_CREATED;
    if (ToUpper(r.object_kind) == "BOUNTY") out.event_type = ModelEventType::BOUNTY_CREATED;
    if (ToUpper(r.object_kind) == "COLLECTION") out.event_type = ModelEventType::COLLECTION_UPDATED;
    out.model_id = r.model_id.IsNull() ? std::string() : r.model_id.Hex();
    out.release_id = r.release_id;
    out.publisher_id = r.publisher_identity.IsNull() ? std::string() : r.publisher_identity.Hex();
    out.bounty_id = r.bounty_id;
    out.record_sequence = r.metadata_sequence;
    out.source = "SEARCH";
    out.verification_state = r.signed_ok ? "SIGNED_OK" : "LOCAL_OBSERVED";
    out.object_kind = r.object_kind.empty() ? "MODEL" : r.object_kind;
    FillMatchFromSearch(out.match, r);
    out.untrusted_text = SanitizeUntrustedEventText(r.description.empty() ? r.short_description : r.description);
    out.object_id = FirstNonEmpty({out.model_id, out.bounty_id, out.release_id, r.btx_uri});
    out.new_state = ModelEventTypeName(out.event_type);
    out.provenance.setObject();
    out.provenance.pushKV("signed_record", r.signed_ok);
    out.provenance.pushKV("locally_derived", true);
    return !out.object_id.empty();
}

bool ModelEventFromBountyEvent(const UniValue& e, ModelEvent& out)
{
    out = {};
    const std::string kind = ToUpper(JsonStr(e, "kind"));
    if (kind == "COMMIT") out.event_type = ModelEventType::BOUNTY_SUBMISSION_CREATED;
    else if (kind == "PLEDGE" || kind == "FREEZE") out.event_type = ModelEventType::BOUNTY_FUNDING_CHANGED;
    else if (kind == "AWARD" || kind == "APPROVE") out.event_type = ModelEventType::BOUNTY_AWARDED;
    else if (kind == "FUNDED") out.event_type = ModelEventType::BOUNTY_FUNDED;
    else if (kind == "REORG" || kind == "BOUNTY_CHAIN_REVERTED") out.event_type = ModelEventType::BOUNTY_FUNDING_CHANGED;
    else out.event_type = ModelEventType::BOUNTY_CREATED;

    out.bounty_id = JsonStr(e, "bounty_id");
    out.object_id = out.bounty_id;
    out.object_kind = "BOUNTY";
    out.source = "BOUNTY";
    out.verification_state = "CHAIN_OBSERVED";
    out.record_sequence = static_cast<uint64_t>(JsonI64(e, "seq"));
    out.observed_at = NowMs();
    if (e.exists("payload") && e["payload"].isObject()) {
        const UniValue& p = e["payload"];
        if (out.bounty_id.empty()) out.bounty_id = JsonStr(p, "bounty_id");
        out.terms_id = JsonStr(p, "terms_id");
        out.publisher_id = JsonStr(p, "requester_identity");
        out.untrusted_text = SanitizeUntrustedEventText(JsonStr(p, "description"));
        if (p.exists("economy") && p["economy"].isObject()) out.funding = p["economy"];
    }
    if (out.object_id.empty()) out.object_id = out.bounty_id;
    out.new_state = ModelEventTypeName(out.event_type);
    out.provenance.setObject();
    out.provenance.pushKV("bounty_kind", JsonStr(e, "kind"));
    out.provenance.pushKV("bounty_event_id", JsonStr(e, "event_id"));
    out.provenance.pushKV("locally_derived", true);
    out.provenance.pushKV("authority", JsonStr(e, "authority"));
    return !out.object_id.empty();
}

UniValue ModelEventToJson(const ModelEvent& ev)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", MODEL_EVENT_SCHEMA_VERSION);
    o.pushKV("event_id", ev.event_id);
    o.pushKV("local_sequence", static_cast<int64_t>(ev.local_sequence));
    o.pushKV("event_type", ModelEventTypeName(ev.event_type));
    o.pushKV("observed_at", ev.observed_at);
    o.pushKV("object_kind", ev.object_kind);
    o.pushKV("object_id", ev.object_id);
    o.pushKV("publisher_id", ev.publisher_id);
    if (!ev.collection_id.empty()) o.pushKV("collection_id", ev.collection_id);
    o.pushKV("record_sequence", static_cast<int64_t>(ev.record_sequence));
    o.pushKV("source", ev.source);
    o.pushKV("verification_state", ev.verification_state);
    o.pushKV("old_state", ev.old_state);
    o.pushKV("new_state", ev.new_state);
    if (!ev.model_id.empty()) o.pushKV("model_id", ev.model_id);
    if (!ev.release_id.empty()) o.pushKV("release_id", ev.release_id);
    if (!ev.bounty_id.empty()) o.pushKV("bounty_id", ev.bounty_id);
    if (!ev.terms_id.empty()) o.pushKV("terms_id", ev.terms_id);
    if (ev.funding.isObject() && !ev.funding.getKeys().empty()) o.pushKV("funding", ev.funding);
    o.pushKV("provenance", ev.provenance.isObject() ? ev.provenance : UniValue(UniValue::VOBJ));
    o.pushKV("dedupe_key", ev.dedupe_key);
    o.pushKV("untrusted_text", ev.untrusted_text);
    UniValue mf(UniValue::VOBJ);
    if (!ev.match.family.empty()) mf.pushKV("family", ev.match.family);
    if (!ev.match.architecture.empty()) mf.pushKV("architecture", ev.match.architecture);
    if (!ev.match.format.empty()) mf.pushKV("format", ev.match.format);
    if (!ev.match.quantization.empty()) mf.pushKV("quantization", ev.match.quantization);
    if (!ev.match.publisher_name.empty()) mf.pushKV("publisher_name", ev.match.publisher_name);
    if (!ev.match.canonical_name.empty()) mf.pushKV("canonical_name", ev.match.canonical_name);
    if (!ev.match.display_name.empty()) mf.pushKV("display_name", ev.match.display_name);
    if (!ev.match.object_kind.empty()) mf.pushKV("object_kind", ev.match.object_kind);
    if (!ev.match.release_state.empty()) mf.pushKV("release_state", ev.match.release_state);
    if (ev.match.parameter_count >= 0) mf.pushKV("parameter_count", ev.match.parameter_count);
    if (ev.match.size_bytes >= 0) mf.pushKV("size_bytes", ev.match.size_bytes);
    if (!ev.match.tags.empty()) mf.pushKV("tags", StrListJson(ev.match.tags));
    if (!ev.match.languages.empty()) mf.pushKV("languages", StrListJson(ev.match.languages));
    if (!mf.getKeys().empty()) o.pushKV("match", mf);
    return o;
}

bool ModelEventFromJson(const UniValue& o, ModelEvent& ev, std::string& err)
{
    ev = {};
    if (!o.isObject()) {
        err = "event object";
        return false;
    }
    ev.event_id = JsonStr(o, "event_id");
    ev.local_sequence = static_cast<uint64_t>(JsonI64(o, "local_sequence"));
    if (o.exists("event_type") && o["event_type"].isStr()) {
        if (!ParseModelEventType(o["event_type"].get_str(), ev.event_type)) {
            err = "event_type";
            return false;
        }
    }
    ev.observed_at = JsonI64(o, "observed_at");
    ev.object_kind = JsonStr(o, "object_kind");
    if (ev.object_kind.empty()) ev.object_kind = "MODEL";
    ev.object_id = JsonStr(o, "object_id");
    ev.publisher_id = JsonStr(o, "publisher_id");
    ev.collection_id = JsonStr(o, "collection_id");
    ev.record_sequence = static_cast<uint64_t>(JsonI64(o, "record_sequence"));
    ev.source = JsonStr(o, "source");
    if (ev.source.empty()) ev.source = "LOCAL";
    ev.verification_state = JsonStr(o, "verification_state");
    if (ev.verification_state.empty()) ev.verification_state = "LOCAL_OBSERVED";
    ev.old_state = JsonStr(o, "old_state");
    ev.new_state = JsonStr(o, "new_state");
    ev.model_id = JsonStr(o, "model_id");
    ev.release_id = JsonStr(o, "release_id");
    ev.bounty_id = JsonStr(o, "bounty_id");
    ev.terms_id = JsonStr(o, "terms_id");
    if (o.exists("funding") && o["funding"].isObject()) ev.funding = o["funding"];
    if (o.exists("provenance") && o["provenance"].isObject()) ev.provenance = o["provenance"];
    ev.dedupe_key = JsonStr(o, "dedupe_key");
    ev.untrusted_text = SanitizeUntrustedEventText(JsonStr(o, "untrusted_text"));
    if (o.exists("match") && o["match"].isObject()) {
        const UniValue& m = o["match"];
        ev.match.family = JsonStr(m, "family");
        ev.match.architecture = JsonStr(m, "architecture");
        ev.match.format = JsonStr(m, "format");
        ev.match.quantization = JsonStr(m, "quantization");
        ev.match.publisher_name = JsonStr(m, "publisher_name");
        ev.match.canonical_name = JsonStr(m, "canonical_name");
        ev.match.display_name = JsonStr(m, "display_name");
        ev.match.object_kind = JsonStr(m, "object_kind");
        ev.match.release_state = JsonStr(m, "release_state");
        ev.match.parameter_count = JsonI64(m, "parameter_count", -1);
        ev.match.size_bytes = JsonI64(m, "size_bytes", -1);
        ev.match.tags = JsonStrList(m, "tags");
        ev.match.languages = JsonStrList(m, "languages");
    }
    return true;
}

std::string SanitizeUntrustedEventText(std::string_view in)
{
    std::string o;
    o.reserve(in.size());
    for (unsigned char c : in) {
        if (c == 0) continue;
        o.push_back(static_cast<char>(c));
        if (o.size() >= SEARCH_DESC_MAX) break;
    }
    return o;
}

bool EventTextMayBecomeCommand(const std::string&) { return false; }
bool EventTextMayBecomeRpc(const std::string&) { return false; }
bool EventTextMayBecomePath(const std::string&) { return false; }
bool EventTextMayBecomeMandate(const std::string&) { return false; }

void ModelEventJournal::RebuildIndexLocked()
{
    m_by_id.clear();
    m_by_dedupe.clear();
    for (size_t i = 0; i < m_events.size(); ++i) {
        if (!m_events[i].event_id.empty()) m_by_id[m_events[i].event_id] = i;
        if (!m_events[i].dedupe_key.empty()) m_by_dedupe[m_events[i].dedupe_key] = i;
    }
}

bool ModelEventJournal::WriteSeqLocked(std::string& err) const
{
    if (m_seq_path.empty()) return true;
    fs::create_directories(m_seq_path.parent_path());
    const fs::path tmp = m_seq_path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            err = "seq write";
            return false;
        }
        out << m_seq << "\n";
        out.flush();
        if (!out) {
            err = "seq flush";
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, m_seq_path, ec);
    if (ec) {
        err = "seq rename";
        return false;
    }
    return true;
}

bool ModelEventJournal::AppendLineLocked(const ModelEvent& ev, std::string& err)
{
    if (m_journal_path.empty()) return true;
    fs::create_directories(m_journal_path.parent_path());
    std::ofstream out(m_journal_path, std::ios::app);
    if (!out) {
        err = "journal append";
        return false;
    }
    out << ModelEventToJson(ev).write() << "\n";
    out.flush();
    return static_cast<bool>(out);
}

bool ModelEventJournal::RewriteJournalLocked(std::string& err) const
{
    if (m_journal_path.empty()) return true;
    fs::create_directories(m_journal_path.parent_path());
    const fs::path tmp = m_journal_path + ".tmp";
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            err = "journal rewrite";
            return false;
        }
        for (const auto& ev : m_events) {
            out << ModelEventToJson(ev).write() << "\n";
        }
        out.flush();
        if (!out) {
            err = "journal flush";
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, m_journal_path, ec);
    if (ec) {
        err = "journal rename";
        return false;
    }
    return true;
}

bool ModelEventJournal::CompactLocked(std::string& err)
{
    if (m_cap == 0 || m_events.size() <= m_cap) return true;
    const size_t drop = m_events.size() - m_cap;
    m_events.erase(m_events.begin(), m_events.begin() + static_cast<std::ptrdiff_t>(drop));
    RebuildIndexLocked();
    return RewriteJournalLocked(err);
}

std::vector<ModelEvent> ModelEventJournal::ReplayAfterLocked(uint64_t cursor, size_t limit) const
{
    std::vector<ModelEvent> out;
    if (limit > MODEL_EVENT_PAGE_MAX) limit = MODEL_EVENT_PAGE_MAX;
    for (const auto& ev : m_events) {
        if (ev.local_sequence <= cursor) continue;
        out.push_back(ev);
        if (out.size() >= limit) break;
    }
    return out;
}

bool ModelEventJournal::LoadLocked(std::string& err)
{
    m_events.clear();
    m_seq = 0;
    if (!m_seq_path.empty() && fs::exists(m_seq_path)) {
        std::ifstream in(m_seq_path);
        std::string raw;
        std::getline(in, raw);
        if (!raw.empty()) {
            try {
                m_seq = static_cast<uint64_t>(std::stoull(raw));
            } catch (...) {
                m_seq = 0;
            }
        }
    }
    if (!m_journal_path.empty() && fs::exists(m_journal_path)) {
        std::ifstream in(m_journal_path);
        std::string line;
        while (std::getline(in, line)) {
            if (line.empty()) continue;
            UniValue o;
            if (!o.read(line) || !o.isObject()) continue;
            ModelEvent ev;
            std::string perr;
            if (!ModelEventFromJson(o, ev, perr)) continue;
            if (ev.event_id.empty() || ev.dedupe_key.empty()) continue;
            m_events.push_back(std::move(ev));
        }
    }
    for (const auto& ev : m_events) {
        if (ev.local_sequence > m_seq) m_seq = ev.local_sequence;
    }
    RebuildIndexLocked();
    if (m_cap > 0 && m_events.size() > m_cap) {
        if (!CompactLocked(err)) return false;
    }
    return true;
}

ModelEventJournal::ModelEventJournal(fs::path modeldir, size_t cap) : m_cap(cap == 0 ? MODEL_EVENT_CAP_DEFAULT : cap)
{
    if (!modeldir.empty()) {
        m_dir = modeldir / "events";
        m_journal_path = m_dir / "journal.jsonl";
        m_seq_path = m_dir / "seq";
        fs::create_directories(m_dir);
        std::string err;
        (void)LoadLocked(err);
    }
}

void ModelEventJournal::SetCap(size_t cap)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_cap = cap == 0 ? MODEL_EVENT_CAP_DEFAULT : cap;
    std::string err;
    (void)CompactLocked(err);
}

size_t ModelEventJournal::Cap() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_cap;
}

uint64_t ModelEventJournal::Cursor() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_seq;
}

size_t ModelEventJournal::Size() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_events.size();
}

bool ModelEventJournal::Observe(ModelEvent ev, ObserveResult& out, std::string& err)
{
    out = {};
    ev.untrusted_text = SanitizeUntrustedEventText(ev.untrusted_text);
    if (ev.object_id.empty()) {
        ev.object_id = FirstNonEmpty({ev.model_id, ev.bounty_id, ev.release_id, ev.collection_id, ev.publisher_id});
    }
    if (ev.object_id.empty()) {
        err = "object_id required";
        return false;
    }
    if (ev.observed_at <= 0) ev.observed_at = NowMs();
    if (ev.source.empty()) ev.source = "LOCAL";
    if (ev.verification_state.empty()) ev.verification_state = "LOCAL_OBSERVED";
    if (ev.object_kind.empty()) ev.object_kind = "MODEL";
    if (ev.new_state.empty()) ev.new_state = ModelEventTypeName(ev.event_type);
    if (!ev.provenance.isObject()) ev.provenance.setObject();
    if (!ev.provenance.exists("locally_derived")) ev.provenance.pushKV("locally_derived", true);
    const std::string transition = ModelEventTypeName(ev.event_type);
    if (ev.dedupe_key.empty()) ev.dedupe_key = MakeDedupeKey(ev.object_id, ev.record_sequence, transition);
    if (ev.event_id.empty()) ev.event_id = MakeModelEventId(ev.dedupe_key);

    ModelEvent stored;
    bool duplicate = false;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        auto dit = m_by_dedupe.find(ev.dedupe_key);
        if (dit != m_by_dedupe.end() && dit->second < m_events.size()) {
            stored = m_events[dit->second];
            duplicate = true;
        } else {
            ev.local_sequence = ++m_seq;
            stored = ev;
            m_events.push_back(ev);
            m_by_id[ev.event_id] = m_events.size() - 1;
            m_by_dedupe[ev.dedupe_key] = m_events.size() - 1;
            if (!AppendLineLocked(ev, err)) return false;
            if (!WriteSeqLocked(err)) return false;
            if (!CompactLocked(err)) return false;
            stored = m_events.back();
            // After compact the back is still the newest event.
        }
        out.event_id = stored.event_id;
        out.local_sequence = stored.local_sequence;
        out.duplicate = duplicate;
    }
    if (!duplicate && g_listener) g_listener(stored);
    return true;
}

bool ModelEventJournal::ObserveReorgCorrection(const std::string& original_event_id, ObserveResult& out,
                                               std::string& err)
{
    ModelEvent original;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        auto it = m_by_id.find(original_event_id);
        if (it == m_by_id.end() || it->second >= m_events.size()) {
            err = "original event";
            return false;
        }
        original = m_events[it->second];
    }
    ModelEventType reverted;
    if (!RevertedEventType(original.event_type, reverted)) {
        err = "no reverted type";
        return false;
    }
    return ObserveReorgCorrection(original_event_id, reverted, out, err);
}

bool ModelEventJournal::ObserveReorgCorrection(const std::string& original_event_id, ModelEventType reverted,
                                                 ObserveResult& out, std::string& err)
{
    ModelEvent original;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        auto it = m_by_id.find(original_event_id);
        if (it == m_by_id.end() || it->second >= m_events.size()) {
            err = "original event";
            return false;
        }
        original = m_events[it->second];
    }
    ModelEvent corr;
    corr.event_type = reverted;
    corr.object_id = original.object_id;
    corr.object_kind = original.object_kind;
    corr.publisher_id = original.publisher_id;
    corr.collection_id = original.collection_id;
    corr.record_sequence = original.record_sequence;
    corr.source = original.source.empty() ? "CHAIN" : original.source;
    corr.verification_state = "CHAIN_OBSERVED";
    corr.old_state = ModelEventTypeName(original.event_type);
    corr.new_state = ModelEventTypeName(reverted);
    corr.model_id = original.model_id;
    corr.release_id = original.release_id;
    corr.bounty_id = original.bounty_id;
    corr.terms_id = original.terms_id;
    corr.funding = original.funding;
    corr.match = original.match;
    corr.untrusted_text = original.untrusted_text;
    corr.provenance.setObject();
    corr.provenance.pushKV("corrected_from", original.event_id);
    corr.provenance.pushKV("locally_derived", true);
    corr.provenance.pushKV("reorg", true);
    return Observe(std::move(corr), out, err);
}

std::vector<ModelEvent> ModelEventJournal::ReplayAfter(uint64_t cursor, size_t limit) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return ReplayAfterLocked(cursor, limit);
}

bool ModelEventJournal::Get(const std::string& event_id, ModelEvent& out) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_by_id.find(event_id);
    if (it == m_by_id.end() || it->second >= m_events.size()) return false;
    out = m_events[it->second];
    return true;
}

bool ModelEventJournal::WaitAfter(uint64_t cursor, int timeout_ms, std::atomic<bool>* stop,
                                 std::vector<ModelEvent>& out, bool& interrupted, std::string& err)
{
    out.clear();
    interrupted = false;
    if (timeout_ms < 0) timeout_ms = 0;
    if (timeout_ms > MODEL_EVENT_WAIT_MAX_MS) timeout_ms = MODEL_EVENT_WAIT_MAX_MS;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
        if (stop && stop->load(std::memory_order_relaxed)) {
            interrupted = true;
            return true;
        }
        {
            std::lock_guard<std::mutex> lock(m_mu);
            out = ReplayAfterLocked(cursor, MODEL_EVENT_PAGE_MAX);
            if (!out.empty()) return true;
        }
        if (timeout_ms == 0) return true;
        const auto now = std::chrono::steady_clock::now();
        if (now >= deadline) return true;
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - now).count();
        if (left <= 0) return true;
        const auto slice = std::min<int64_t>(MODEL_EVENT_WAIT_SLICE_MS, left);
        std::this_thread::sleep_for(std::chrono::milliseconds(slice));
        (void)err;
    }
}

void BindModelEventJournal(const fs::path& modeldir, size_t cap)
{
    SetModelEventListener(nullptr);
    g_journal = std::make_unique<ModelEventJournal>(modeldir, cap);
}

ModelEventJournal* BoundModelEventJournal()
{
    return g_journal.get();
}

void SetModelEventListener(void (*fn)(const ModelEvent&))
{
    g_listener = fn;
}

bool JournalObserve(ModelEventJournal& journal, ModelEvent ev, ObserveResult& out, std::string& err)
{
    return journal.Observe(std::move(ev), out, err);
}

bool JournalObserve(ModelEvent ev, ObserveResult& out, std::string& err)
{
    if (!g_journal) {
        err = "event journal not bound";
        return false;
    }
    return g_journal->Observe(std::move(ev), out, err);
}

bool JournalObserveFeed(const FeedEvent& fe, ObserveResult& out, std::string& err)
{
    ModelEvent ev;
    if (!ModelEventFromFeed(fe, ev)) {
        err = "feed event";
        return false;
    }
    return JournalObserve(std::move(ev), out, err);
}

bool JournalObserveSearchRecord(const ModelSearchRecord& r, ObserveResult& out, std::string& err)
{
    ModelEvent ev;
    if (!ModelEventFromSearchRecord(r, ev)) {
        err = "search record";
        return false;
    }
    return JournalObserve(std::move(ev), out, err);
}

bool JournalObserveBounty(const UniValue& bounty_event, ObserveResult& out, std::string& err)
{
    ModelEvent ev;
    if (!ModelEventFromBountyEvent(bounty_event, ev)) {
        err = "bounty event";
        return false;
    }
    return JournalObserve(std::move(ev), out, err);
}

} // namespace modelnet
