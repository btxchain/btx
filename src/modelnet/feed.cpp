// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/feed.h>

#include <crypto/common.h>
#include <modelnet/crypto.h>
#include <util/strencodings.h>

#include <algorithm>
#include <fstream>

namespace modelnet {

const char* FeedModeName(FeedMode m)
{
    switch (m) {
    case FeedMode::NEW_RELEASE_CAMPAIGNS: return "NEW_RELEASE_CAMPAIGNS";
    case FeedMode::NEARLY_FUNDED: return "NEARLY_FUNDED";
    case FeedMode::FUNDED_AWAITING_RELEASE: return "FUNDED_AWAITING_RELEASE";
    case FeedMode::JUST_UNLOCKED: return "JUST_UNLOCKED";
    case FeedMode::TRENDING: return "TRENDING";
    case FeedMode::RARE: return "RARE";
    case FeedMode::NEW_PUBLISHERS: return "NEW_PUBLISHERS";
    case FeedMode::NEW_COLLECTIONS: return "NEW_COLLECTIONS";
    case FeedMode::FUNDING_ACTIVITY: return "FUNDING_ACTIVITY";
    case FeedMode::RECENTLY_AVAILABLE: return "RECENTLY_AVAILABLE";
    case FeedMode::NEWEST:
    default: return "NEWEST";
    }
}

bool ParseFeedMode(const std::string& s, FeedMode& out)
{
    const std::string x = ToUpper(s);
    if (x.empty() || x == "NEWEST") { out = FeedMode::NEWEST; return true; }
    if (x == "NEW_RELEASE_CAMPAIGNS" || x == "RELEASES" || x == "NEW") {
        out = FeedMode::NEW_RELEASE_CAMPAIGNS;
        return true;
    }
    if (x == "NEARLY_FUNDED") { out = FeedMode::NEARLY_FUNDED; return true; }
    if (x == "FUNDED_AWAITING_RELEASE" || x == "FUNDED") {
        out = FeedMode::FUNDED_AWAITING_RELEASE;
        return true;
    }
    if (x == "JUST_UNLOCKED" || x == "UNLOCKED") { out = FeedMode::JUST_UNLOCKED; return true; }
    if (x == "TRENDING") { out = FeedMode::TRENDING; return true; }
    if (x == "RARE") { out = FeedMode::RARE; return true; }
    if (x == "NEW_PUBLISHERS") { out = FeedMode::NEW_PUBLISHERS; return true; }
    if (x == "NEW_COLLECTIONS") { out = FeedMode::NEW_COLLECTIONS; return true; }
    if (x == "FUNDING_ACTIVITY") { out = FeedMode::FUNDING_ACTIVITY; return true; }
    if (x == "RECENTLY_AVAILABLE") { out = FeedMode::RECENTLY_AVAILABLE; return true; }
    return false;
}

const char* FeedEventTypeName(FeedEventType t)
{
    switch (t) {
    case FeedEventType::RELEASE_CAMPAIGN_CREATED: return "RELEASE_CAMPAIGN_CREATED";
    case FeedEventType::RELEASE_FUNDING_CHANGED: return "RELEASE_FUNDING_CHANGED";
    case FeedEventType::RELEASE_FUNDED: return "RELEASE_FUNDED";
    case FeedEventType::RELEASE_SECRET_DISCLOSED: return "RELEASE_SECRET_DISCLOSED";
    case FeedEventType::MODEL_UNLOCKED: return "MODEL_UNLOCKED";
    case FeedEventType::MODEL_BECAME_AVAILABLE: return "MODEL_BECAME_AVAILABLE";
    case FeedEventType::MODEL_BECAME_FRAGILE: return "MODEL_BECAME_FRAGILE";
    case FeedEventType::MODEL_METADATA_UPDATED: return "MODEL_METADATA_UPDATED";
    case FeedEventType::COLLECTION_PUBLISHED: return "COLLECTION_PUBLISHED";
    case FeedEventType::PUBLISHER_FIRST_OBSERVED: return "PUBLISHER_FIRST_OBSERVED";
    case FeedEventType::MODEL_PUBLISHED:
    default: return "MODEL_PUBLISHED";
    }
}

bool ParseFeedEventType(const std::string& s, FeedEventType& out)
{
    const std::string x = ToUpper(s);
    if (x == "MODEL_PUBLISHED") { out = FeedEventType::MODEL_PUBLISHED; return true; }
    if (x == "RELEASE_CAMPAIGN_CREATED") { out = FeedEventType::RELEASE_CAMPAIGN_CREATED; return true; }
    if (x == "RELEASE_FUNDING_CHANGED") { out = FeedEventType::RELEASE_FUNDING_CHANGED; return true; }
    if (x == "RELEASE_FUNDED") { out = FeedEventType::RELEASE_FUNDED; return true; }
    if (x == "RELEASE_SECRET_DISCLOSED") { out = FeedEventType::RELEASE_SECRET_DISCLOSED; return true; }
    if (x == "MODEL_UNLOCKED") { out = FeedEventType::MODEL_UNLOCKED; return true; }
    if (x == "MODEL_BECAME_AVAILABLE") { out = FeedEventType::MODEL_BECAME_AVAILABLE; return true; }
    if (x == "MODEL_BECAME_FRAGILE") { out = FeedEventType::MODEL_BECAME_FRAGILE; return true; }
    if (x == "MODEL_METADATA_UPDATED") { out = FeedEventType::MODEL_METADATA_UPDATED; return true; }
    if (x == "COLLECTION_PUBLISHED") { out = FeedEventType::COLLECTION_PUBLISHED; return true; }
    if (x == "PUBLISHER_FIRST_OBSERVED") { out = FeedEventType::PUBLISHER_FIRST_OBSERVED; return true; }
    return false;
}

std::string MakeFeedEventId(FeedEventType t, const Digest48& model_id, const std::string& release_id,
                            uint64_t metadata_sequence, const std::string& extra)
{
    std::string body = std::string(FeedEventTypeName(t)) + "|" + model_id.Hex() + "|" + release_id + "|" +
                        std::to_string(metadata_sequence) + "|" + extra;
    const Digest48 h = DomainHash("BTX/ModelFeedEvent/v1",
                                    Span<const unsigned char>{reinterpret_cast<const unsigned char*>(body.data()), body.size()});
    return h.Hex();
}

bool FeedStore::Note(FeedEvent ev, int64_t now_ms)
{
    Expire(now_ms);
    if (ev.event_id.empty()) {
        ev.event_id = MakeFeedEventId(ev.event_type, ev.model_id, ev.release_id, ev.rec.metadata_sequence, "");
    }
    auto it = m_by_id.find(ev.event_id);
    if (it != m_by_id.end()) {
        it->second.sources_observed += 1;
        it->second.observed_at = now_ms;
        return true;
    }
    if (m_by_id.size() >= m_cap) {
        Expire(now_ms + m_ttl_ms); // force ttl path
        if (m_by_id.size() >= m_cap) {
            // drop oldest first_seen
            auto oldest = m_by_id.begin();
            for (auto i = m_by_id.begin(); i != m_by_id.end(); ++i) {
                if (i->second.first_seen_at < oldest->second.first_seen_at) oldest = i;
            }
            if (oldest != m_by_id.end()) m_by_id.erase(oldest);
        }
    }
    if (ev.first_seen_at == 0) ev.first_seen_at = now_ms;
    if (ev.observed_at == 0) ev.observed_at = now_ms;
    ev.sequence = ++m_seq;
    m_by_id[ev.event_id] = std::move(ev);
    return true;
}

bool FeedStore::NoteSearchRecord(const ModelSearchRecord& r, int64_t now_ms)
{
    if (r.tombstone || r.model_id.IsNull()) return false;
    FeedEvent ev;
    ev.event_type = r.metadata_sequence > 1 ? FeedEventType::MODEL_METADATA_UPDATED : FeedEventType::MODEL_PUBLISHED;
    if (!r.release_id.empty() && r.metadata_sequence <= 1) ev.event_type = FeedEventType::RELEASE_CAMPAIGN_CREATED;
    ev.model_id = r.model_id;
    ev.release_id = r.release_id;
    ev.published_at = r.published_at;
    ev.signed_record = r.signed_ok;
    ev.rec = r;
    if (!r.release_id.empty()) {
        ev.campaign = CampaignFromSearchRecord(r);
        ev.has_campaign = true;
    }
    ev.event_id = MakeFeedEventId(ev.event_type, r.model_id, r.release_id, r.metadata_sequence, "");
    const bool ok = Note(std::move(ev), now_ms);

    const std::string pub = r.publisher_identity.Hex();
    if (!pub.empty() && !r.publisher_identity.IsNull()) {
        const int before = m_publisher_models[pub];
        m_publisher_models[pub] += 1;
        if (before == 0) {
            FeedEvent p;
            p.event_type = FeedEventType::PUBLISHER_FIRST_OBSERVED;
            p.model_id = r.model_id;
            p.rec = r;
            p.signed_record = r.signed_ok;
            p.published_at = r.published_at;
            p.event_id = MakeFeedEventId(p.event_type, r.publisher_identity, "", 0, pub);
            Note(std::move(p), now_ms);
        }
    }
    return ok;
}

bool FeedStore::NoteCampaign(const ReleaseCampaign& c, int64_t now_ms)
{
    FeedEvent ev;
    ev.event_type = FeedEventType::RELEASE_CAMPAIGN_CREATED;
    ev.model_id = c.model_id;
    ev.release_id = c.release_id.Hex();
    ev.published_at = c.campaign_created_at;
    ev.campaign = c;
    ev.has_campaign = true;
    ev.event_id = MakeFeedEventId(ev.event_type, c.model_id, c.release_id.Hex(), 0, "campaign");
    return Note(std::move(ev), now_ms);
}

bool FeedStore::NoteUnlock(const Digest48& model_id, const std::string& release_id, const ModelSearchRecord& r, int64_t now_ms)
{
    FeedEvent ev;
    ev.event_type = FeedEventType::MODEL_UNLOCKED;
    ev.model_id = model_id;
    ev.release_id = release_id;
    ev.published_at = now_ms;
    ev.rec = r;
    ev.event_id = MakeFeedEventId(FeedEventType::MODEL_UNLOCKED, model_id, release_id, 0, "unlock");
    Note(ev, now_ms);
    FeedEvent secret = ev;
    secret.event_type = FeedEventType::RELEASE_SECRET_DISCLOSED;
    secret.event_id = MakeFeedEventId(FeedEventType::RELEASE_SECRET_DISCLOSED, model_id, release_id, 0, "secret");
    return Note(std::move(secret), now_ms);
}

bool FeedStore::NoteFundingChanged(const ReleaseCampaign& c, int64_t now_ms)
{
    FeedEvent ev;
    ev.event_type = FeedEventType::RELEASE_FUNDING_CHANGED;
    ev.model_id = c.model_id;
    ev.release_id = c.release_id.Hex();
    ev.campaign = c;
    ev.has_campaign = true;
    ev.published_at = now_ms;
    // Dedupe per campaign + frozen/secret transition only, not every pledge tick:
    const std::string extra = std::string(c.frozen ? "1" : "0") + (c.secret_disclosed ? "1" : "0") +
                               std::to_string(c.pledged_atoms / std::max<int64_t>(1, c.target_atoms / 20));
    ev.event_id = MakeFeedEventId(ev.event_type, c.model_id, c.release_id.Hex(), 0, extra);
    if (c.target_atoms > 0 && c.funded_atoms >= c.target_atoms) {
        ev.event_type = FeedEventType::RELEASE_FUNDED;
        ev.event_id = MakeFeedEventId(FeedEventType::RELEASE_FUNDED, c.model_id, c.release_id.Hex(), 0, "funded");
    }
    return Note(std::move(ev), now_ms);
}

void FeedStore::Expire(int64_t now_ms)
{
    if (m_ttl_ms <= 0) return;
    for (auto it = m_by_id.begin(); it != m_by_id.end();) {
        if (it->second.observed_at > 0 && now_ms - it->second.observed_at > m_ttl_ms) {
            it = m_by_id.erase(it);
        } else {
            ++it;
        }
    }
}

std::vector<FeedEvent> FeedStore::Query(const FeedQuery& q, int64_t now_ms, std::string& next_cursor) const
{
    std::vector<FeedEvent> all;
    all.reserve(m_by_id.size());
    for (const auto& kv : m_by_id) {
        const auto& ev = kv.second;
        if (q.since > 0 && ev.published_at < q.since && ev.observed_at < q.since) continue;
        if (q.since_sequence > 0 && ev.sequence <= q.since_sequence) continue;
        switch (q.mode) {
        case FeedMode::NEW_RELEASE_CAMPAIGNS:
            if (ev.event_type != FeedEventType::RELEASE_CAMPAIGN_CREATED) continue;
            break;
        case FeedMode::JUST_UNLOCKED:
            if (ev.event_type != FeedEventType::MODEL_UNLOCKED &&
                ev.event_type != FeedEventType::RELEASE_SECRET_DISCLOSED) {
                continue;
            }
            break;
        case FeedMode::NEW_PUBLISHERS:
            if (ev.event_type != FeedEventType::PUBLISHER_FIRST_OBSERVED) continue;
            break;
        case FeedMode::NEW_COLLECTIONS:
            if (ev.event_type != FeedEventType::COLLECTION_PUBLISHED) continue;
            break;
        case FeedMode::FUNDING_ACTIVITY:
            if (ev.event_type != FeedEventType::RELEASE_FUNDING_CHANGED &&
                ev.event_type != FeedEventType::RELEASE_FUNDED &&
                ev.event_type != FeedEventType::RELEASE_CAMPAIGN_CREATED) {
                continue;
            }
            break;
        case FeedMode::FUNDED_AWAITING_RELEASE:
            if (ev.event_type != FeedEventType::RELEASE_FUNDED) continue;
            break;
        case FeedMode::NEARLY_FUNDED:
            if (!(ev.has_campaign || ev.event_type == FeedEventType::RELEASE_CAMPAIGN_CREATED ||
                  ev.event_type == FeedEventType::RELEASE_FUNDING_CHANGED)) {
                continue;
            }
            break;
        case FeedMode::TRENDING:
            break;
        case FeedMode::RARE:
            if (ev.event_type != FeedEventType::MODEL_BECAME_FRAGILE && ev.event_type != FeedEventType::MODEL_PUBLISHED) {
                continue;
            }
            break;
        case FeedMode::RECENTLY_AVAILABLE:
            if (ev.event_type != FeedEventType::MODEL_BECAME_AVAILABLE &&
                ev.event_type != FeedEventType::MODEL_PUBLISHED) {
                continue;
            }
            break;
        default:
            break;
        }
        all.push_back(ev);
    }
    std::sort(all.begin(), all.end(), [&](const FeedEvent& a, const FeedEvent& b) {
        if (q.mode == FeedMode::TRENDING) {
            if (a.sources_observed != b.sources_observed) return a.sources_observed > b.sources_observed;
        }
        if (q.mode == FeedMode::NEARLY_FUNDED && a.has_campaign && b.has_campaign) {
            auto rem = [](const ReleaseCampaign& c) {
                if (c.target_atoms <= 0) return int64_t{0};
                const int64_t funded = c.funded_atoms > 0 ? c.funded_atoms : 0;
                return RemainingAtoms(c.target_atoms, funded);
            };
            const int64_t ra = rem(a.campaign);
            const int64_t rb = rem(b.campaign);
            if (ra != rb) return ra < rb && ra > 0;
        }
        if (a.published_at != b.published_at) return a.published_at > b.published_at;
        if (a.first_seen_at != b.first_seen_at) return a.first_seen_at > b.first_seen_at;
        return a.event_id < b.event_id;
    });
    bool skip = !q.cursor.empty();
    std::vector<FeedEvent> page;
    const int limit = q.limit <= 0 ? FEED_PAGE_DEFAULT : std::min(q.limit, FEED_PAGE_MAX);
    for (const auto& ev : all) {
        if (skip) {
            if (ev.event_id == q.cursor) skip = false;
            continue;
        }
        page.push_back(ev);
        if (static_cast<int>(page.size()) >= limit) break;
    }
    next_cursor.clear();
    if (!page.empty() && static_cast<int>(page.size()) == limit) {
        next_cursor = page.back().event_id;
    }
    (void)now_ms;
    return page;
}

UniValue FeedStore::StatusJson(int public_models, int campaigns, int unreleased, int unlocked, const FeedCoverage& cov) const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", FEED_SCHEMA_VERSION);
    o.pushKV("feed_sequence", static_cast<int64_t>(m_seq));
    o.pushKV("records_known", static_cast<int>(m_by_id.size()));
    o.pushKV("campaigns_known", campaigns);
    o.pushKV("public_models_known", public_models);
    o.pushKV("unreleased_models_known", unreleased);
    o.pushKV("recently_unlocked_known", unlocked);
    o.pushKV("peers_contributing", cov.peers_contributing);
    o.pushKV("last_network_refresh", m_last_refresh);
    o.pushKV("coverage_complete", false);
    o.pushKV("global_complete", false);
    o.pushKV("coverage_disclaimer", "this node's current decentralized network view; not a global chronology");
    o.pushKV("ttl_ms", m_ttl_ms);
    o.pushKV("cap", static_cast<int>(m_cap));
    return o;
}

UniValue FeedStore::EventToJson(const FeedEvent& ev, const ModelEconomyEntry* entry) const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("event_id", ev.event_id);
    o.pushKV("event_type", FeedEventTypeName(ev.event_type));
    o.pushKV("observed_at", ev.observed_at);
    o.pushKV("published_at", ev.published_at);
    o.pushKV("first_seen_at", ev.first_seen_at);
    o.pushKV("model_id", ev.model_id.Hex());
    o.pushKV("release_id", ev.release_id);
    if (entry) o.pushKV("entry", EconomySearchCard(*entry));
    UniValue prov(UniValue::VOBJ);
    prov.pushKV("signed_record", ev.signed_record);
    prov.pushKV("publisher_signed", ev.signed_record);
    prov.pushKV("locally_derived", true);
    prov.pushKV("sources_observed", ev.sources_observed);
    o.pushKV("provenance", prov);
    return o;
}

bool FeedStore::Save(std::string& err) const
{
    if (m_path.empty()) return true;
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", FEED_SCHEMA_VERSION);
    o.pushKV("sequence", static_cast<int64_t>(m_seq));
    UniValue arr(UniValue::VARR);
    for (const auto& kv : m_by_id) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("event_id", kv.second.event_id);
        e.pushKV("event_type", FeedEventTypeName(kv.second.event_type));
        e.pushKV("observed_at", kv.second.observed_at);
        e.pushKV("published_at", kv.second.published_at);
        e.pushKV("first_seen_at", kv.second.first_seen_at);
        e.pushKV("model_id", kv.second.model_id.Hex());
        e.pushKV("release_id", kv.second.release_id);
        e.pushKV("sequence", static_cast<int64_t>(kv.second.sequence));
        e.pushKV("sources_observed", kv.second.sources_observed);
        e.pushKV("signed_record", kv.second.signed_record);
        e.pushKV("record", SearchRecordToJson(kv.second.rec));
        if (kv.second.has_campaign) e.pushKV("campaign", CampaignToJson(kv.second.campaign));
        arr.push_back(e);
    }
    o.pushKV("events", arr);
    fs::create_directories(m_path.parent_path());
    std::ofstream out(m_path, std::ios::trunc);
    if (!out) {
        err = "feed.json write";
        return false;
    }
    out << o.write() << "\n";
    return true;
}

bool FeedStore::Load(int64_t now_ms, std::string& err)
{
    if (m_path.empty() || !fs::exists(m_path)) return true;
    m_by_id.clear();
    m_seq = 0;
    std::ifstream in(m_path);
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue o;
    if (!o.read(raw) || !o.isObject() || !o.exists("events")) return true;
    if (o.exists("sequence")) m_seq = o["sequence"].getInt<int64_t>();
    for (const auto& ej : o["events"].getValues()) {
        FeedEvent ev;
        if (ej.exists("event_id")) ev.event_id = ej["event_id"].get_str();
        if (ej.exists("event_type")) ParseFeedEventType(ej["event_type"].get_str(), ev.event_type);
        if (ej.exists("observed_at")) ev.observed_at = ej["observed_at"].getInt<int64_t>();
        if (ej.exists("published_at")) ev.published_at = ej["published_at"].getInt<int64_t>();
        if (ej.exists("first_seen_at")) ev.first_seen_at = ej["first_seen_at"].getInt<int64_t>();
        if (ej.exists("model_id") && !ej["model_id"].get_str().empty()) {
            Digest48::FromHex(ej["model_id"].get_str(), ev.model_id, err);
        }
        if (ej.exists("release_id")) ev.release_id = ej["release_id"].get_str();
        if (ej.exists("sequence")) ev.sequence = ej["sequence"].getInt<int64_t>();
        if (ej.exists("sources_observed")) ev.sources_observed = ej["sources_observed"].getInt<int>();
        ev.signed_record = ej.exists("signed_record") && ej["signed_record"].get_bool();
        if (ej.exists("record")) SearchRecordFromJson(ej["record"], ev.rec, err);
        if (ej.exists("campaign")) {
            CampaignFromJson(ej["campaign"], ev.campaign, err);
            ev.has_campaign = true;
        }
        if (ev.sequence > m_seq) m_seq = ev.sequence;
        m_by_id[ev.event_id] = std::move(ev);
    }
    Expire(now_ms);
    return true;
}

UniValue FeedPageJson(const std::vector<FeedEvent>& items, const std::vector<ModelEconomyEntry>& entries,
                       const FeedQuery& q, const FeedCoverage& cov, uint64_t feed_sequence,
                       const std::string& next_cursor)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", FEED_SCHEMA_VERSION);
    o.pushKV("scope", SearchScopeName(q.scope));
    o.pushKV("mode", FeedModeName(q.mode));
    o.pushKV("feed_sequence", static_cast<int64_t>(feed_sequence));
    o.pushKV("cursor", q.cursor);
    o.pushKV("next_cursor", next_cursor);
    UniValue covj(UniValue::VOBJ);
    covj.pushKV("complete", false);
    covj.pushKV("global_complete", false);
    covj.pushKV("connected_peers_queried", cov.connected_peers_queried);
    covj.pushKV("index_peers_queried", cov.index_peers_queried);
    covj.pushKV("responses_received", cov.responses_received);
    covj.pushKV("timed_out", cov.timed_out);
    covj.pushKV("peers_contributing", cov.peers_contributing);
    covj.pushKV("last_network_refresh", cov.last_network_refresh);
    covj.pushKV("note", "this node's current decentralized network view; not a global chronology");
    o.pushKV("coverage", covj);
    UniValue arr(UniValue::VARR);
    for (size_t i = 0; i < items.size(); ++i) {
        FeedStore tmp;
        const ModelEconomyEntry* ent = i < entries.size() ? &entries[i] : nullptr;
        arr.push_back(tmp.EventToJson(items[i], ent));
    }
    o.pushKV("items", arr);
    o.pushKV("partial", true);
    o.pushKV("automatic_spend_atoms", 0);
    return o;
}

} // namespace modelnet
