// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/policy.h>

#include <crypto/common.h>
#include <crypto/sha256.h>
#include <util/strencodings.h>

#include <algorithm>
#include <cctype>
#include <limits>
#include <stdexcept>

namespace modelnet {

bool ChoosePlan(RetrievalMode mode,
                const std::optional<int>& free_eta_s,
                const PaidPlan* paid,
                int64_t budget_atoms,
                bool exposure_ok,
                const std::optional<int>& deadline_s,
                int64_t value_per_second_atoms,
                bool approved,
                PlanChoice& out,
                std::string& err)
{
    if (budget_atoms < 0 || value_per_second_atoms < 0) {
        err = "invalid policy amount";
        return false;
    }
    auto check_dur = [&](const std::optional<int>& d) {
        return !d || *d >= 0;
    };
    if (!check_dur(free_eta_s) || !check_dur(deadline_s) || (paid && paid->total_eta_s && *paid->total_eta_s < 0)) {
        err = "invalid ETA/deadline";
        return false;
    }
    if (mode == RetrievalMode::FREE_ONLY) {
        out = free_eta_s ? PlanChoice::FREE : PlanChoice::WAIT_FREE;
        return true;
    }
    if (!paid || !paid->safe || !paid->deliverable || paid->requires_release) {
        out = free_eta_s ? PlanChoice::FREE : PlanChoice::WAIT_FREE;
        return true;
    }
    if (paid->price_atoms < 0 || paid->fee_atoms < 0) {
        err = "bad price";
        return false;
    }
    const int64_t cost = paid->price_atoms + paid->fee_atoms;
    if (cost > MAX_MONEY_ATOMS || !exposure_ok) {
        out = free_eta_s ? PlanChoice::FREE : PlanChoice::WAIT_FREE;
        return true;
    }
    if (mode == RetrievalMode::EXPLICIT_PAID) {
        out = (approved && cost <= budget_atoms) ? PlanChoice::PAID : PlanChoice::APPROVAL_REQUIRED;
        return true;
    }
    const auto t = paid->total_eta_s;
    const bool saves = free_eta_s && t && *free_eta_s > *t;
    const bool missing = !free_eta_s && t;
    const bool deadline_gain = deadline_s && t && *t <= *deadline_s && (!free_eta_s || *free_eta_s > *deadline_s);
    const bool economical = saves && value_per_second_atoms * static_cast<int64_t>(*free_eta_s - *t) >= cost;
    const bool worthwhile = missing || deadline_gain || economical;
    if (!worthwhile) {
        out = free_eta_s ? PlanChoice::FREE : PlanChoice::WAIT_FREE;
        return true;
    }
    if (mode == RetrievalMode::FREE_FIRST_APPROVAL) {
        out = (approved && cost <= budget_atoms) ? PlanChoice::PAID : PlanChoice::APPROVAL_REQUIRED;
        return true;
    }
    if (cost <= budget_atoms) out = PlanChoice::PAID;
    else out = free_eta_s ? PlanChoice::FREE : PlanChoice::WAIT_FREE;
    return true;
}

bool ExposureWithinCeiling(int64_t outstanding_atoms, int64_t additional_atoms, int64_t ceiling)
{
    if (outstanding_atoms < 0 || additional_atoms < 0 || ceiling < 0) return false;
    if (outstanding_atoms > MAX_MONEY_ATOMS || additional_atoms > MAX_MONEY_ATOMS) return false;
    if (additional_atoms > MAX_MONEY_ATOMS - outstanding_atoms) return false;
    return outstanding_atoms + additional_atoms <= ceiling;
}

AclDecision DecideAcl(bool crypto_ok,
                       bool hard_limit_ok,
                       bool local_deny,
                       bool quarantined,
                       bool exact_allow,
                       bool subscribed_deny,
                       bool needs_spend,
                       bool budget_approved)
{
    if (!crypto_ok) return AclDecision::REJECT_CRYPTO;
    if (!hard_limit_ok) return AclDecision::RETRY_RESOURCE;
    if (local_deny) return AclDecision::DENY_LOCAL;
    if (quarantined) return AclDecision::QUARANTINE;
    if (subscribed_deny && !exact_allow) return AclDecision::DENY_SUBSCRIBED;
    if (needs_spend && !budget_approved) return AclDecision::REQUIRE_SPEND_APPROVAL;
    return AclDecision::ALLOW;
}

bool ReciprocityLedger::Received(const std::string& peer,
                                  const std::string& artifact,
                                  int file,
                                  int piece,
                                  int64_t nbytes,
                                  int64_t when,
                                  bool verified,
                                  bool needed,
                                  bool paid,
                                  int observed_sources,
                                  bool unsolicited)
{
    if (nbytes <= 0 || when < 0) throw std::runtime_error("invalid observation");
    const auto key = std::tuple<std::string, int, int>{artifact, file, piece};
    if (unsolicited || !verified || !needed || paid || m_seen.count(key)) return false;
    m_seen.insert(key);
    int64_t bonus = (observed_sources == 1 || observed_sources == 2) ? 2 : 1;
    if (bonus > 2) bonus = 2;
    if (bonus < 1) bonus = 1;
    m_events.push_back({peer, nbytes * bonus, when});
    return true;
}

bool ReciprocityLedger::CreditThirdPartyReceipt(const std::string& peer, int64_t nbytes, int64_t when)
{
    (void)peer;
    (void)nbytes;
    (void)when;
    return false;
}

int64_t ReciprocityLedger::Effective(const std::string& peer, int64_t now) const
{
    int64_t total = 0;
    for (const auto& e : m_events) {
        const int64_t age = std::max<int64_t>(0, now - e.when);
        if (e.peer == peer && age < 28 * DAY_SECONDS) {
            total += e.bytes >> (age / (7 * DAY_SECONDS));
        }
    }
    return std::min<int64_t>(total, int64_t{4} << 30);
}

int ReciprocityLedger::Weight(const std::string& peer, int64_t now) const
{
    const int64_t units = std::min<int64_t>(64, Effective(peer, now) / static_cast<int64_t>(64 * MIB));
    return static_cast<int>(1 + (3 * units) / 64);
}

UniValue ReciprocityLedger::Snapshot() const
{
    UniValue obj(UniValue::VOBJ);
    UniValue events(UniValue::VARR);
    for (const auto& e : m_events) {
        UniValue ev(UniValue::VOBJ);
        ev.pushKV("peer", e.peer);
        ev.pushKV("bytes", e.bytes);
        ev.pushKV("when", e.when);
        events.push_back(ev);
    }
    obj.pushKV("events", events);
    obj.pushKV("lane_bootstrap_share", 0.20);
    obj.pushKV("lane_reciprocal_share", 0.60);
    obj.pushKV("lane_preservation_share", 0.20);
    obj.pushKV("newcomer_bootstrap_ok", true);
    UniValue seen(UniValue::VARR);
    for (const auto& k : m_seen) {
        UniValue row(UniValue::VOBJ);
        row.pushKV("artifact", std::get<0>(k));
        row.pushKV("file", std::get<1>(k));
        row.pushKV("piece", std::get<2>(k));
        seen.push_back(row);
    }
    obj.pushKV("seen", seen);
    return obj;
}

bool ReciprocityLedger::Load(const UniValue& obj, std::string& err)
{
    if (!obj.isObject() || !obj.exists("events") || !obj["events"].isArray()) {
        err = "invalid ledger snapshot";
        return false;
    }
    m_events.clear();
    m_seen.clear();
    for (const auto& ev : obj["events"].getValues()) {
        m_events.push_back({ev["peer"].get_str(), ev["bytes"].getInt<int64_t>(), ev["when"].getInt<int64_t>()});
    }
    if (obj.exists("seen") && obj["seen"].isArray()) {
        for (const auto& row : obj["seen"].getValues()) {
            if (!row.isObject() || !row.exists("artifact") || !row.exists("file") || !row.exists("piece")) {
                err = "invalid ledger seen row";
                return false;
            }
            m_seen.insert({row["artifact"].get_str(), row["file"].getInt<int>(), row["piece"].getInt<int>()});
        }
    }
    return true;
}

std::vector<std::string> LaneSequence(const std::map<std::string, int>& backlogs, int quanta)
{
    std::map<std::string, int> b = backlogs;
    std::vector<std::string> out;
    static const std::vector<std::string> order{"bootstrap", "reciprocal", "reciprocal", "preservation", "reciprocal"};
    for (int i = 0; i < quanta; ++i) {
        const std::string& wanted = order[i % order.size()];
        std::vector<std::string> eligible;
        for (const auto& k : order) {
            if (b[k] > 0) eligible.push_back(k);
        }
        if (eligible.empty()) break;
        const std::string k = (b[wanted] > 0) ? wanted : eligible.front();
        out.push_back(k);
        b[k] -= 1;
    }
    return out;
}

const char* SeedModeName(SeedMode mode)
{
    switch (mode) {
    case SeedMode::OFF: return "off";
    case SeedMode::MANUAL: return "manual";
    case SeedMode::AUTO: return "auto";
    }
    return "auto";
}

bool SeedModeFromName(const std::string& name, SeedMode& out)
{
    const std::string n = ToLower(name);
    if (n == "off" || n == "0" || n == "false" || n == "no") {
        out = SeedMode::OFF;
        return true;
    }
    if (n == "manual") {
        out = SeedMode::MANUAL;
        return true;
    }
    if (n == "auto" || n == "1" || n == "true" || n == "yes") {
        out = SeedMode::AUTO;
        return true;
    }
    return false;
}

bool ParseModelBytes(const std::string& in, uint64_t& out, std::string& err)
{
    std::string s;
    s.reserve(in.size());
    for (char c : in) {
        if (c != ' ' && c != '_') s.push_back(c);
    }
    if (s.empty()) {
        err = "empty size";
        return false;
    }
    size_t i = 0;
    if (!std::isdigit(static_cast<unsigned char>(s[0]))) {
        err = "size must start with a digit";
        return false;
    }
    uint64_t n = 0;
    while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) {
        const int d = s[i] - '0';
        if (n > (std::numeric_limits<uint64_t>::max() - static_cast<uint64_t>(d)) / 10) {
            err = "size overflow";
            return false;
        }
        n = n * 10 + static_cast<uint64_t>(d);
        ++i;
    }
    std::string unit = s.substr(i);
    for (char& c : unit) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    uint64_t mul = 1;
    if (unit.empty() || unit == "b" || unit == "byte" || unit == "bytes") mul = 1;
    else if (unit == "k" || unit == "kib" || unit == "kb") mul = 1024;
    else if (unit == "m" || unit == "mib" || unit == "mb") mul = MIB;
    else if (unit == "g" || unit == "gib" || unit == "gb") mul = GIB;
    else if (unit == "t" || unit == "tib" || unit == "tb") mul = GIB * 1024;
    else {
        err = "unknown size unit";
        return false;
    }
    if (mul != 1 && n > std::numeric_limits<uint64_t>::max() / mul) {
        err = "size overflow";
        return false;
    }
    out = n * mul;
    return true;
}

bool ShouldDemandSeed(const PreservationPolicy& p, AdmissionLevel admission)
{
    if (p.storage_quota_bytes == 0) return false;
    if (p.seed_mode != SeedMode::AUTO) return false;
    if (admission == AdmissionLevel::FAILED) return false;
    return true;
}

bool MayPreserveFetch(const PreservationPolicy& p, AdmissionLevel admission, bool encrypted,
                      int observed_sources, uint64_t bytes, uint64_t spare_bytes)
{
    if (!p.preserve_rare || p.storage_quota_bytes == 0) return false;
    if (encrypted && !p.allow_encrypted) return false;
    if (admission == AdmissionLevel::FAILED) return false;
    if (observed_sources <= 0 || observed_sources > 2) return false;
    if (bytes == 0 || bytes > spare_bytes) return false;
    return true;
}

bool MayFollowConfiguredPeer(const PreservationPolicy& p, AdmissionLevel admission, bool encrypted,
                              uint64_t bytes, uint64_t spare_bytes)
{
    if (!p.follow_configured_peers) return false;
    if (p.storage_quota_bytes == 0) return false;
    if (p.seed_mode != SeedMode::AUTO) return false;
    if (encrypted && !p.allow_encrypted) return false;
    if (admission == AdmissionLevel::FAILED) return false;
    if (bytes == 0 || bytes > spare_bytes) return false;
    return true;
}

uint64_t PreserveRareJitterScore(const Digest48& model_id, int64_t now)
{
    const int64_t bucket = (now == 0) ? 0 : now / 300;
    const std::string hex = model_id.Hex();
    unsigned char bucket_le[8];
    WriteLE64(bucket_le, static_cast<uint64_t>(bucket));
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256()
        .Write(reinterpret_cast<const unsigned char*>(hex.data()), hex.size())
        .Write(bucket_le, sizeof(bucket_le))
        .Finalize(hash);
    return ReadLE64(hash);
}

bool SelectPreserveRare(const std::vector<PreserveCandidate>& observed,
                        const std::set<Digest48>& local,
                        uint64_t spare_bytes,
                        const PreservationPolicy& p,
                        PreserveCandidate& out,
                        int64_t now)
{
    const PreserveCandidate* best = nullptr;
    for (const auto& c : observed) {
        if (local.count(c.model_id)) continue;
        if (!MayPreserveFetch(p, c.admission, c.encrypted, c.observed_sources, c.bytes, spare_bytes)) continue;
        if (!best) {
            best = &c;
            continue;
        }
        if (c.observed_sources < best->observed_sources) {
            best = &c;
            continue;
        }
        if (c.observed_sources > best->observed_sources) continue;
        if (c.bytes < best->bytes) {
            best = &c;
            continue;
        }
        if (c.bytes > best->bytes) continue;
        if (now != 0 && PreserveRareJitterScore(c.model_id, now) < PreserveRareJitterScore(best->model_id, now)) {
            best = &c;
        }
    }
    if (!best) return false;
    out = *best;
    return true;
}

bool SelectPeerFollow(const std::vector<PreserveCandidate>& observed,
                       const std::set<Digest48>& local,
                       uint64_t spare_bytes,
                       const PreservationPolicy& p,
                       PreserveCandidate& out)
{
    const PreserveCandidate* best = nullptr;
    for (const auto& c : observed) {
        if (local.count(c.model_id)) continue;
        if (!MayFollowConfiguredPeer(p, c.admission, c.encrypted, c.bytes, spare_bytes)) continue;
        if (!best || c.bytes < best->bytes) best = &c;
    }
    if (!best) return false;
    out = *best;
    return true;
}

int EvictPriority(const EvictItem& item)
{
    if (item.pinned) return 1000;
    if (item.incomplete) return -40;
    if (item.expired_ciphertext) return -30;
    if (item.failed_unqualified) return -20;
    if (item.recently_protected) return 90;
    if (item.observed_sources > 0 && item.observed_sources <= 2) return 80;
    if (item.seeded) return 40;
    if (item.giveback_complete) return -10;
    return 0;
}

UniValue PolicyToJson(const PreservationPolicy& p)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("seed", SeedModeName(p.seed_mode));
    o.pushKV("seed_upon_download", p.seed_mode == SeedMode::AUTO);
    o.pushKV("seed_upon_download_opt_in", false);
    o.pushKV("preserve_rare", p.preserve_rare);
    o.pushKV("follow_configured_peers", p.follow_configured_peers);
    o.pushKV("allow_encrypted", p.allow_encrypted);
    o.pushKV("storage_quota_bytes", p.storage_quota_bytes);
    o.pushKV("upload_bps", p.upload_bps);
    o.pushKV("giveback_ratio", p.giveback_ratio);
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("retrieval_default", "FREE_ONLY");
    o.pushKV("demand_propagation", p.seed_mode == SeedMode::AUTO && p.storage_quota_bytes > 0);
    o.pushKV("preservation_propagation", p.preserve_rare && p.storage_quota_bytes > 0);
    o.pushKV("peer_follow_propagation", p.follow_configured_peers && p.seed_mode == SeedMode::AUTO && p.storage_quota_bytes > 0);
    o.pushKV("release_propagation", p.seed_mode == SeedMode::AUTO && p.storage_quota_bytes > 0);
    o.pushKV("unsolicited_fetch", "arbitrary advertised models stay off; catalog contacts (-modelpeer, addmodelnode, PEX) are followed when seed=auto and storage>0");
    return o;
}

bool PolicyFromJson(const UniValue& obj, PreservationPolicy& p, std::string& err)
{
    if (!obj.isObject()) {
        err = "policy object required";
        return false;
    }
    if (obj.exists("seed") && obj["seed"].isStr()) {
        if (!SeedModeFromName(obj["seed"].get_str(), p.seed_mode)) {
            err = "seed must be auto, manual, or off";
            return false;
        }
    } else if (obj.exists("seed_upon_download")) {
        // B0 0|1 alias used only when `seed` is omitted. Never a second gate.
        p.seed_mode = obj["seed_upon_download"].get_bool() ? SeedMode::AUTO : SeedMode::OFF;
    }
    p.seed_upon_download = p.seed_mode == SeedMode::AUTO;
    if (obj.exists("preserve_rare")) p.preserve_rare = obj["preserve_rare"].get_bool();
    if (obj.exists("follow_configured_peers")) p.follow_configured_peers = obj["follow_configured_peers"].get_bool();
    if (obj.exists("allow_encrypted")) p.allow_encrypted = obj["allow_encrypted"].get_bool();
    if (obj.exists("upload_bps")) p.upload_bps = obj["upload_bps"].getInt<uint64_t>();
    if (obj.exists("storage_quota_bytes")) p.storage_quota_bytes = obj["storage_quota_bytes"].getInt<uint64_t>();
    if (obj.exists("giveback_ratio")) p.giveback_ratio = obj["giveback_ratio"].get_real();
    return true;
}

TrustLabel ClassifyPeer(int64_t effective_bytes, int successful_sessions, int invalid_pieces, bool blocked, bool preferred, bool trusted)
{
    if (blocked) return TrustLabel::BLOCKED;
    if (trusted) return TrustLabel::TRUSTED;
    if (preferred) return TrustLabel::PREFERRED;
    if (invalid_pieces > 0 && successful_sessions == 0) return TrustLabel::OBSERVED;
    if (effective_bytes >= static_cast<int64_t>(64 * MIB) && successful_sessions >= 3) return TrustLabel::RELIABLE;
    if (effective_bytes > 0) return TrustLabel::RECIPROCAL;
    if (successful_sessions > 0) return TrustLabel::OBSERVED;
    return TrustLabel::NEW;
}

bool BootstrapLimiter::Allow(const std::string& service_id, const std::string& netgroup, int64_t bytes)
{
    if (bytes <= 0 || m_aggregate_cap <= 0) return false;
    if (bytes > PER_KEY_DAY || m_key_day[service_id] > PER_KEY_DAY - bytes) return false;
    if (bytes > GROUP_HOUR || m_group_hour[netgroup] > GROUP_HOUR - bytes) return false;
    if (bytes > m_aggregate_cap || m_aggregate_used > m_aggregate_cap - bytes) return false;
    m_key_day[service_id] += bytes;
    m_group_hour[netgroup] += bytes;
    m_aggregate_used += bytes;
    return true;
}

bool GiveBackComplete(const PreservationPolicy& p,
                      int64_t useful_served,
                      int64_t useful_received,
                      int64_t started_at,
                      int64_t now)
{
    if (useful_served < 0 || useful_received < 0 || now < started_at) return true;
    if (p.retain_seconds > 0 && now - started_at >= p.retain_seconds) return true;
    if (useful_received > 0 && p.giveback_ratio >= 0.0 &&
        static_cast<double>(useful_served) >= p.giveback_ratio * static_cast<double>(useful_received)) {
        return true;
    }
    return false;
}

bool NormalizeCollection(std::vector<Digest48>& ids, std::string& err)
{
    std::sort(ids.begin(), ids.end());
    ids.erase(std::unique(ids.begin(), ids.end()), ids.end());
    if (ids.size() > COLLECTION_MAX_ENTRIES) {
        err = "collection exceeds 512 models";
        return false;
    }
    return true;
}

bool ApplyAlias(AliasMapping& st, uint64_t sequence, uint8_t target_kind, const Digest48& target, std::string& err)
{
    if (target_kind == static_cast<uint8_t>(ResourceKind::ALIAS)) {
        err = "alias must not chain to another alias";
        return false;
    }
    if (st.frozen) {
        err = "alias frozen";
        return false;
    }
    if (st.sequence == 0) {
        st.sequence = sequence;
        st.target = target;
        st.target_kind = target_kind;
        return true;
    }
    if (sequence == st.sequence + 1) {
        st.sequence = sequence;
        st.target = target;
        st.target_kind = target_kind;
        return true;
    }
    st.frozen = true;
    err = "alias sequence conflict; prior mapping frozen";
    return false;
}

} // namespace modelnet
