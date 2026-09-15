// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/economy.h>

#include <util/strencodings.h>

#include <algorithm>
#include <cmath>
#include <limits>

namespace modelnet {

const char* ModelLifecycleName(ModelLifecycle s)
{
    switch (s) {
    case ModelLifecycle::FUNDING: return "FUNDING";
    case ModelLifecycle::FUNDING_FROZEN: return "FUNDING_FROZEN";
    case ModelLifecycle::FUNDED_AWAITING_RELEASE: return "FUNDED_AWAITING_RELEASE";
    case ModelLifecycle::SECRET_DISCLOSED: return "SECRET_DISCLOSED";
    case ModelLifecycle::UNLOCKING: return "UNLOCKING";
    case ModelLifecycle::PUBLIC_RELEASED: return "PUBLIC_RELEASED";
    case ModelLifecycle::REFUND_AVAILABLE: return "REFUND_AVAILABLE";
    case ModelLifecycle::RELEASE_EXPIRED: return "RELEASE_EXPIRED";
    case ModelLifecycle::UNAVAILABLE: return "UNAVAILABLE";
    case ModelLifecycle::PUBLIC:
    default: return "PUBLIC";
    }
}

bool ParseModelLifecycle(const std::string& s, ModelLifecycle& out)
{
    const std::string x = ToUpper(s);
    if (x == "PUBLIC") { out = ModelLifecycle::PUBLIC; return true; }
    if (x == "FUNDING") { out = ModelLifecycle::FUNDING; return true; }
    if (x == "FUNDING_FROZEN") { out = ModelLifecycle::FUNDING_FROZEN; return true; }
    if (x == "FUNDED_AWAITING_RELEASE") { out = ModelLifecycle::FUNDED_AWAITING_RELEASE; return true; }
    if (x == "SECRET_DISCLOSED") { out = ModelLifecycle::SECRET_DISCLOSED; return true; }
    if (x == "UNLOCKING") { out = ModelLifecycle::UNLOCKING; return true; }
    if (x == "PUBLIC_RELEASED") { out = ModelLifecycle::PUBLIC_RELEASED; return true; }
    if (x == "REFUND_AVAILABLE") { out = ModelLifecycle::REFUND_AVAILABLE; return true; }
    if (x == "RELEASE_EXPIRED") { out = ModelLifecycle::RELEASE_EXPIRED; return true; }
    if (x == "UNAVAILABLE") { out = ModelLifecycle::UNAVAILABLE; return true; }
    return false;
}

const char* ModelResultTypeName(ModelResultType t)
{
    switch (t) {
    case ModelResultType::RELEASE_CAMPAIGN: return "RELEASE_CAMPAIGN";
    case ModelResultType::FUNDED_PENDING_RELEASE: return "FUNDED_PENDING_RELEASE";
    case ModelResultType::JUST_RELEASED_MODEL: return "JUST_RELEASED_MODEL";
    case ModelResultType::LOCAL_MODEL: return "LOCAL_MODEL";
    case ModelResultType::PUBLIC_MODEL:
    default: return "PUBLIC_MODEL";
    }
}

const char* RefundStatusName(RefundStatus s)
{
    switch (s) {
    case RefundStatus::NOT_MATURE: return "NOT_MATURE";
    case RefundStatus::AVAILABLE: return "AVAILABLE";
    case RefundStatus::CLAIM_COMPETING: return "CLAIM_COMPETING";
    case RefundStatus::REFUNDED: return "REFUNDED";
    case RefundStatus::UNKNOWN:
    default: return "UNKNOWN";
    }
}

const char* EconomyActionName(EconomyAction a)
{
    switch (a) {
    case EconomyAction::KEEP: return "KEEP";
    case EconomyAction::COPY_URI: return "COPY_URI";
    case EconomyAction::VIEW_RELEASE: return "VIEW_RELEASE";
    case EconomyAction::FUND_RELEASE: return "FUND_RELEASE";
    case EconomyAction::WAIT_FOR_UNLOCK: return "WAIT_FOR_UNLOCK";
    case EconomyAction::CACHE_ENCRYPTED: return "CACHE_ENCRYPTED";
    case EconomyAction::REFUND: return "REFUND";
    case EconomyAction::DOWNLOAD:
    default: return "DOWNLOAD";
    }
}

bool LifecycleIsFundable(ModelLifecycle s)
{
    return s == ModelLifecycle::FUNDING;
}

bool LifecycleIsPublic(ModelLifecycle s)
{
    return s == ModelLifecycle::PUBLIC || s == ModelLifecycle::PUBLIC_RELEASED ||
           s == ModelLifecycle::SECRET_DISCLOSED;
}

bool FundedPercentMilli(int64_t funded_atoms, int64_t target_atoms, int64_t& milli_out)
{
    milli_out = 0;
    if (target_atoms <= 0 || funded_atoms < 0) return false;
    unsigned __int128 num = static_cast<unsigned __int128>(static_cast<uint64_t>(funded_atoms)) * 100000u;
    milli_out = static_cast<int64_t>(num / static_cast<unsigned __int128>(target_atoms));
    return true;
}

int64_t RemainingAtoms(int64_t target_atoms, int64_t confirmed_funded_atoms)
{
    if (target_atoms <= 0) return 0;
    if (confirmed_funded_atoms >= target_atoms) return 0;
    if (confirmed_funded_atoms < 0) return target_atoms;
    return target_atoms - confirmed_funded_atoms;
}

double MilliToDisplayPercent(int64_t milli)
{
    return static_cast<double>(milli) / 1000.0;
}

ReleaseCampaign CampaignFromSearchRecord(const ModelSearchRecord& r)
{
    ReleaseCampaign c;
    std::string err;
    if (!r.release_id.empty()) Digest48::FromHex(r.release_id, c.release_id, err);
    c.model_id = r.model_id;
    c.artifact_id = r.artifact_id;
    c.ciphertext_artifact_id = r.ciphertext_artifact_id.IsNull() ? r.artifact_id : r.ciphertext_artifact_id;
    c.key_hash = r.key_hash;
    c.target_atoms = r.release_target_atoms;
    c.refund_height = r.refund_height;
    c.campaign_created_at = r.campaign_created_at;
    c.assurance = r.assurance.empty() ? "KEY_RELEASE_ONLY" : r.assurance;
    return c;
}

namespace {

ModelLifecycle LifecycleFromReleaseState(const std::string& s)
{
    ModelLifecycle out;
    if (ParseModelLifecycle(s, out)) return out;
    const std::string x = ToUpper(s);
    if (x == "PUBLIC" || x.empty()) return ModelLifecycle::PUBLIC;
    return ModelLifecycle::FUNDING;
}

bool LooksPublic(const SearchHit& h)
{
    if (h.local.downloaded || h.local.known) return true;
    if (h.rec.release_id.empty() && (h.rec.release_state.empty() || ToUpper(h.rec.release_state) == "PUBLIC")) {
        return !h.rec.canonical_name.empty() || !h.rec.display_name.empty();
    }
    return false;
}

} // namespace

ModelLifecycle DeriveLifecycle(const SearchHit& h, const ReleaseCampaign* campaign, const FundingObservation& fund)
{
    if (fund.unlocking_locally) return ModelLifecycle::UNLOCKING;
    if (campaign) {
        if (campaign->plaintext_verified) return ModelLifecycle::PUBLIC_RELEASED;
        if (fund.refund_available_locally && fund.wallet_contributor) return ModelLifecycle::REFUND_AVAILABLE;
        if (campaign->secret_disclosed) return ModelLifecycle::SECRET_DISCLOSED;
        const int64_t confirmed = fund.confirmed_known ? fund.confirmed_funded_atoms : -1;
        if (campaign->target_atoms > 0 && fund.confirmed_known && confirmed >= campaign->target_atoms) {
            return ModelLifecycle::FUNDED_AWAITING_RELEASE;
        }
        if (fund.chain_height_known && campaign->refund_height > 0 && fund.chain_height >= campaign->refund_height &&
            !campaign->secret_disclosed) {
            if (fund.confirmed_known && confirmed >= campaign->target_atoms && campaign->target_atoms > 0) {
                return ModelLifecycle::FUNDED_AWAITING_RELEASE;
            }
            return ModelLifecycle::RELEASE_EXPIRED;
        }
        if (campaign->frozen) return ModelLifecycle::FUNDING_FROZEN;
        if (campaign->target_atoms > 0 || !campaign->release_id.IsNull()) return ModelLifecycle::FUNDING;
    }
    if (!h.rec.release_id.empty()) {
        const ModelLifecycle from_rec = LifecycleFromReleaseState(h.rec.release_state);
        if (from_rec != ModelLifecycle::PUBLIC) return from_rec;
    }
    if (LooksPublic(h)) return ModelLifecycle::PUBLIC;
    if (h.rec.canonical_name.empty() && h.rec.display_name.empty() && h.health.providers_observed == 0) {
        return ModelLifecycle::UNAVAILABLE;
    }
    return ModelLifecycle::PUBLIC;
}

ModelResultType ResultTypeFrom(ModelLifecycle s, const DirectoryLocalState& local)
{
    if (local.known && (s == ModelLifecycle::PUBLIC || s == ModelLifecycle::PUBLIC_RELEASED)) {
        return ModelResultType::LOCAL_MODEL;
    }
    switch (s) {
    case ModelLifecycle::FUNDING:
    case ModelLifecycle::FUNDING_FROZEN:
    case ModelLifecycle::RELEASE_EXPIRED:
        return ModelResultType::RELEASE_CAMPAIGN;
    case ModelLifecycle::FUNDED_AWAITING_RELEASE:
        return ModelResultType::FUNDED_PENDING_RELEASE;
    case ModelLifecycle::SECRET_DISCLOSED:
    case ModelLifecycle::UNLOCKING:
    case ModelLifecycle::PUBLIC_RELEASED:
        return ModelResultType::JUST_RELEASED_MODEL;
    default:
        return ModelResultType::PUBLIC_MODEL;
    }
}

std::vector<EconomyAction> RecommendActions(const ModelEconomyEntry& e)
{
    std::vector<EconomyAction> a;
    switch (e.lifecycle) {
    case ModelLifecycle::FUNDING:
        a.push_back(EconomyAction::VIEW_RELEASE);
        if (e.fundable_now) a.push_back(EconomyAction::FUND_RELEASE);
        if (e.ciphertext_cacheable) a.push_back(EconomyAction::CACHE_ENCRYPTED);
        break;
    case ModelLifecycle::FUNDING_FROZEN:
        a.push_back(EconomyAction::VIEW_RELEASE);
        break;
    case ModelLifecycle::FUNDED_AWAITING_RELEASE:
        a.push_back(EconomyAction::VIEW_RELEASE);
        a.push_back(EconomyAction::WAIT_FOR_UNLOCK);
        if (e.ciphertext_cacheable) a.push_back(EconomyAction::CACHE_ENCRYPTED);
        break;
    case ModelLifecycle::REFUND_AVAILABLE:
        a.push_back(EconomyAction::VIEW_RELEASE);
        if (e.refund_available_locally) a.push_back(EconomyAction::REFUND);
        break;
    case ModelLifecycle::SECRET_DISCLOSED:
    case ModelLifecycle::UNLOCKING:
    case ModelLifecycle::PUBLIC_RELEASED:
    case ModelLifecycle::PUBLIC:
        a.push_back(EconomyAction::DOWNLOAD);
        a.push_back(EconomyAction::KEEP);
        a.push_back(EconomyAction::COPY_URI);
        break;
    case ModelLifecycle::RELEASE_EXPIRED:
        a.push_back(EconomyAction::VIEW_RELEASE);
        break;
    case ModelLifecycle::UNAVAILABLE:
    default:
        a.push_back(EconomyAction::COPY_URI);
        break;
    }
    return a;
}

ModelEconomyEntry ComposeEconomyEntry(const SearchHit& h, const ReleaseCampaign* campaign, const FundingObservation& fund)
{
    ModelEconomyEntry e;
    e.hit = h;
    e.fund = fund;
    if (campaign) {
        e.campaign = *campaign;
        e.has_campaign = !campaign->release_id.IsNull();
    } else if (!h.rec.release_id.empty()) {
        e.campaign = CampaignFromSearchRecord(h.rec);
        e.has_campaign = !e.campaign.release_id.IsNull();
        campaign = e.has_campaign ? &e.campaign : nullptr;
    }
    e.lifecycle = DeriveLifecycle(h, e.has_campaign ? &e.campaign : nullptr, fund);
    e.result_type = ResultTypeFrom(e.lifecycle, h.local);

    const int64_t confirmed = fund.confirmed_known ? fund.confirmed_funded_atoms : 0;
    e.value_known = fund.confirmed_known && e.has_campaign && e.campaign.target_atoms > 0;
    if (e.value_known) {
        e.remaining_atoms = RemainingAtoms(e.campaign.target_atoms, confirmed);
        e.funded_percent_known = FundedPercentMilli(confirmed, e.campaign.target_atoms, e.funded_percent_milli);
    }
    if (e.has_campaign && e.campaign.target_atoms > 0 && e.campaign.pledged_atoms >= 0) {
        e.pledged_percent_known = FundedPercentMilli(e.campaign.pledged_atoms, e.campaign.target_atoms, e.pledged_percent_milli);
    }

    e.ciphertext_available = false;
    if (e.has_campaign) {
        const bool have_id = !e.campaign.artifact_id.IsNull() || !e.campaign.ciphertext_artifact_id.IsNull();
        if (have_id) {
            if (h.local.known || h.local.downloaded || h.local.partial) e.ciphertext_available = true;
            if (fund.ciphertext_providers_observed > 0) e.ciphertext_available = true;
        }
    }

    e.downloadable_plaintext = LifecycleIsPublic(e.lifecycle) &&
                                (h.local.downloaded || h.health.providers_observed > 0 || h.local.known);
    if (e.lifecycle == ModelLifecycle::PUBLIC || e.lifecycle == ModelLifecycle::PUBLIC_RELEASED ||
        e.lifecycle == ModelLifecycle::SECRET_DISCLOSED) {
        e.downloadable_now = true;
        e.downloadable_plaintext = true;
    }
    e.fundable_now = e.lifecycle == ModelLifecycle::FUNDING && e.has_campaign && e.campaign.target_atoms > 0 &&
                      (!e.value_known || e.remaining_atoms > 0) && !e.campaign.frozen;
    e.ciphertext_cacheable = e.has_campaign && e.ciphertext_available && !e.downloadable_plaintext;
    e.refund_available_locally = fund.refund_available_locally && fund.wallet_contributor;
    e.requires_wallet = e.fundable_now || e.refund_available_locally;
    e.requires_user_approval = e.requires_wallet;
    e.actions = RecommendActions(e);
    e.first_seen_at = h.rec.updated_at > 0 ? h.rec.updated_at : h.rec.published_at;
    return e;
}

bool MatchesEconomyFilters(const ModelEconomyEntry& e, const SearchFilters& f)
{
    if (f.public_only && !LifecycleIsPublic(e.lifecycle)) return false;
    if (f.funding_only && e.result_type != ModelResultType::RELEASE_CAMPAIGN &&
        e.lifecycle != ModelLifecycle::FUNDING && e.lifecycle != ModelLifecycle::FUNDING_FROZEN) {
        return false;
    }
    if (f.released_only && !LifecycleIsPublic(e.lifecycle)) return false;
    if (f.unreleased_only && LifecycleIsPublic(e.lifecycle)) return false;
    if (f.fundable_only && !e.fundable_now) return false;
    if (f.refund_available && !e.refund_available_locally) return false;
    if (!f.lifecycle_state.empty()) {
        bool ok = false;
        const std::string name = ModelLifecycleName(e.lifecycle);
        for (const auto& s : f.lifecycle_state) {
            if (ToUpper(s) == name) ok = true;
        }
        if (!ok) return false;
    }
    if (f.min_funded_percent >= 0) {
        if (!e.funded_percent_known) return false;
        if (e.funded_percent_milli / 1000 < f.min_funded_percent) return false;
    }
    if (f.max_funded_percent >= 0) {
        if (!e.funded_percent_known) return false;
        if (e.funded_percent_milli / 1000 > f.max_funded_percent) return false;
    }
    if (f.max_remaining_atoms >= 0) {
        if (!e.value_known) return false;
        if (e.remaining_atoms > f.max_remaining_atoms) return false;
    }
    if (f.release_created_after >= 0 && e.has_campaign) {
        if (e.campaign.campaign_created_at < f.release_created_after) return false;
    }
    if (f.release_created_before >= 0 && e.has_campaign) {
        if (e.campaign.campaign_created_at > f.release_created_before) return false;
    }
    if (f.unlocked_after >= 0) {
        if (e.lifecycle != ModelLifecycle::SECRET_DISCLOSED && e.lifecycle != ModelLifecycle::PUBLIC_RELEASED &&
            e.lifecycle != ModelLifecycle::UNLOCKING) {
            return false;
        }
        const int64_t t = e.fund.reveal_time > 0 ? e.fund.reveal_time : e.hit.rec.updated_at;
        if (t < f.unlocked_after) return false;
    }
    if (f.ciphertext_available && !e.ciphertext_available) return false;
    if (f.min_ciphertext_provider_count > 0 && e.fund.ciphertext_providers_observed < f.min_ciphertext_provider_count) {
        return false;
    }
    if (f.min_provider_count > 0 && e.hit.health.providers_observed < f.min_provider_count) return false;
    if (f.locally_available && !e.hit.local.downloaded && !e.hit.local.known) return false;
    if (f.pinned && !e.hit.local.pinned) return false;
    if (f.seeded && !e.hit.local.seeded) return false;
    if (!f.modalities.empty()) {
        bool ok = false;
        for (const auto& m : f.modalities) {
            for (const auto& have : e.hit.rec.modalities) {
                if (NormalizeSearchText(have) == NormalizeSearchText(m)) ok = true;
            }
        }
        if (!ok) return false;
    }
    return true;
}

void SortEconomyEntries(std::vector<ModelEconomyEntry>& entries, SearchSort sort)
{
    std::sort(entries.begin(), entries.end(), [&](const ModelEconomyEntry& a, const ModelEconomyEntry& b) {
        auto id_lt = [&] { return a.hit.rec.model_id.Hex() < b.hit.rec.model_id.Hex(); };
        switch (sort) {
        case SearchSort::NEWEST:
        case SearchSort::NEWEST_RELEASES:
            if (a.hit.rec.published_at != b.hit.rec.published_at) return a.hit.rec.published_at > b.hit.rec.published_at;
            if (a.first_seen_at != b.first_seen_at) return a.first_seen_at > b.first_seen_at;
            return id_lt();
        case SearchSort::RECENTLY_UNLOCKED: {
            const int64_t ta = a.fund.reveal_time > 0 ? a.fund.reveal_time : a.hit.rec.updated_at;
            const int64_t tb = b.fund.reveal_time > 0 ? b.fund.reveal_time : b.hit.rec.updated_at;
            if (ta != tb) return ta > tb;
            return id_lt();
        }
        case SearchSort::NEARLY_FUNDED: {
            const bool af = a.fundable_now && a.value_known;
            const bool bf = b.fundable_now && b.value_known;
            if (af != bf) return af;
            if (a.funded_percent_milli != b.funded_percent_milli) return a.funded_percent_milli > b.funded_percent_milli;
            if (a.remaining_atoms != b.remaining_atoms) return a.remaining_atoms < b.remaining_atoms;
            return id_lt();
        }
        case SearchSort::MOST_FUNDED:
            if (a.funded_percent_milli != b.funded_percent_milli) return a.funded_percent_milli > b.funded_percent_milli;
            return id_lt();
        case SearchSort::MOST_FUNDING_NEEDED:
            if (a.remaining_atoms != b.remaining_atoms) return a.remaining_atoms > b.remaining_atoms;
            return id_lt();
        case SearchSort::RAREST_AVAILABLE:
        case SearchSort::RARITY:
            if (a.hit.health.providers_observed != b.hit.health.providers_observed)
                return a.hit.health.providers_observed < b.hit.health.providers_observed;
            return id_lt();
        case SearchSort::TRENDING:
        case SearchSort::PROVIDERS:
        case SearchSort::AVAILABILITY:
            if (a.hit.health.providers_observed != b.hit.health.providers_observed)
                return a.hit.health.providers_observed > b.hit.health.providers_observed;
            if (a.hit.sources != b.hit.sources) return a.hit.sources > b.hit.sources;
            return id_lt();
        case SearchSort::NAME:
            return a.hit.rec.display_name < b.hit.rec.display_name;
        case SearchSort::OLDEST:
            return a.hit.rec.published_at < b.hit.rec.published_at;
        case SearchSort::SIZE_ASC:
            return a.hit.rec.size_bytes < b.hit.rec.size_bytes;
        case SearchSort::SIZE_DESC:
            return a.hit.rec.size_bytes > b.hit.rec.size_bytes;
        case SearchSort::PUBLISHER:
            return a.hit.rec.publisher_display_name < b.hit.rec.publisher_display_name;
        case SearchSort::RELEVANCE:
        default:
            if (a.hit.score != b.hit.score) return a.hit.score > b.hit.score;
            return id_lt();
        }
    });
}

UniValue EconomyActionsJson(const std::vector<EconomyAction>& actions)
{
    UniValue arr(UniValue::VARR);
    for (const auto& a : actions) arr.push_back(EconomyActionName(a));
    return arr;
}

UniValue EconomyLifecycleJson(const ModelEconomyEntry& e)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("state", ModelLifecycleName(e.lifecycle));
    o.pushKV("public", LifecycleIsPublic(e.lifecycle));
    o.pushKV("downloadable_plaintext", e.downloadable_plaintext);
    o.pushKV("ciphertext_available", e.ciphertext_available);
    o.pushKV("consensus", false);
    return o;
}

UniValue EconomyReleaseJson(const ModelEconomyEntry& e)
{
    UniValue rel(UniValue::VOBJ);
    if (!e.has_campaign) {
        rel.pushKV("id", e.hit.rec.release_id);
        rel.pushKV("state", e.hit.rec.release_state.empty() ? ModelLifecycleName(e.lifecycle) : e.hit.rec.release_state);
        rel.pushKV("actions", EconomyActionsJson(e.actions));
        return rel;
    }
    rel.pushKV("id", e.campaign.release_id.Hex());
    rel.pushKV("release_id", e.campaign.release_id.Hex());
    rel.pushKV("state", ModelLifecycleName(e.lifecycle));
    rel.pushKV("assurance", e.campaign.assurance.empty() ? "KEY_RELEASE_ONLY" : e.campaign.assurance);
    rel.pushKV("hashlock_algorithm", "SHA256");
    rel.pushKV("key_hash", e.campaign.key_hash.Hex());
    rel.pushKV("key_hash_sha256", e.campaign.key_hash.Hex());
    rel.pushKV("target_atoms", e.campaign.target_atoms);
    rel.pushKV("pledged_atoms", e.campaign.pledged_atoms);
    rel.pushKV("funded_atoms", e.fund.confirmed_known ? e.fund.confirmed_funded_atoms : e.campaign.funded_atoms);
    rel.pushKV("confirmed_funded_atoms", e.fund.confirmed_funded_atoms);
    rel.pushKV("pending_funded_atoms", e.fund.pending_funded_atoms);
    rel.pushKV("remaining_atoms", e.remaining_atoms);
    rel.pushKV("value_known", e.value_known);
    if (e.funded_percent_known) {
        rel.pushKV("funded_percent", MilliToDisplayPercent(e.funded_percent_milli));
        rel.pushKV("funded_percent_milli", e.funded_percent_milli);
    }
    if (e.pledged_percent_known) {
        rel.pushKV("pledged_percent", MilliToDisplayPercent(e.pledged_percent_milli));
        rel.pushKV("pledged_percent_milli", e.pledged_percent_milli);
    }
    rel.pushKV("refund_height", static_cast<int64_t>(e.campaign.refund_height));
    rel.pushKV("latest_funding_height", static_cast<int64_t>(e.campaign.latest_funding_height));
    rel.pushKV("refund_status", RefundStatusName(e.fund.refund_status));
    rel.pushKV("frozen", e.campaign.frozen);
    rel.pushKV("secret_disclosed", e.campaign.secret_disclosed);
    if (e.campaign.secret_disclosed) {
        if (!e.fund.claim_txid.empty()) rel.pushKV("claim_txid", e.fund.claim_txid);
        if (e.fund.reveal_height > 0) rel.pushKV("reveal_height", e.fund.reveal_height);
        if (e.fund.reveal_time > 0) rel.pushKV("reveal_time", e.fund.reveal_time);
    }
    rel.pushKV("plaintext_verified", e.campaign.plaintext_verified);
    rel.pushKV("ciphertext_artifact_id", e.campaign.ciphertext_artifact_id.IsNull() ? e.campaign.artifact_id.Hex()
                                                                                       : e.campaign.ciphertext_artifact_id.Hex());
    if (!e.campaign.output_script_hex.empty()) rel.pushKV("output_script", e.campaign.output_script_hex);
    rel.pushKV("ciphertext_providers_observed", e.fund.ciphertext_providers_observed);
    rel.pushKV("funding_source", e.fund.funding_source.empty() ? "UNKNOWN" : e.fund.funding_source);
    rel.pushKV("helper_observation", e.fund.funding_source != "CHAIN_OBSERVATION");
    rel.pushKV("chain_observation", e.fund.funding_source == "CHAIN_OBSERVATION");
    rel.pushKV("wallet_local_state", e.fund.wallet_contributor);
    rel.pushKV("actions", EconomyActionsJson(e.actions));
    return rel;
}

UniValue EconomyEntryToJson(const ModelEconomyEntry& e)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", ECONOMY_SCHEMA_VERSION);
    UniValue model(UniValue::VOBJ);
    model.pushKV("model_id", e.hit.rec.model_id.Hex());
    model.pushKV("artifact_id", e.hit.rec.artifact_id.Hex());
    model.pushKV("uri", e.hit.rec.btx_uri);
    model.pushKV("name", e.hit.rec.display_name.empty() ? e.hit.rec.canonical_name : e.hit.rec.display_name);
    UniValue al(UniValue::VARR);
    for (const auto& a : e.hit.rec.aliases) al.push_back(a);
    model.pushKV("aliases", al);
    model.pushKV("description", e.hit.rec.short_description);
    model.pushKV("family", e.hit.rec.family);
    model.pushKV("architecture", e.hit.rec.architecture);
    model.pushKV("parameter_count", e.hit.rec.parameter_count);
    model.pushKV("format", e.hit.rec.format);
    model.pushKV("quantization", e.hit.rec.quantization);
    UniValue langs(UniValue::VARR);
    for (const auto& x : e.hit.rec.languages) langs.push_back(x);
    model.pushKV("languages", langs);
    UniValue mods(UniValue::VARR);
    for (const auto& x : e.hit.rec.modalities) mods.push_back(x);
    model.pushKV("modalities", mods);
    UniValue tags(UniValue::VARR);
    for (const auto& x : e.hit.rec.tags) tags.push_back(x);
    model.pushKV("tags", tags);
    model.pushKV("size_bytes", e.hit.rec.size_bytes);
    model.pushKV("published_at", e.hit.rec.published_at);
    o.pushKV("model", model);

    UniValue pub(UniValue::VOBJ);
    pub.pushKV("id", e.hit.rec.publisher_identity.Hex());
    pub.pushKV("display_name", e.hit.rec.publisher_display_name);
    pub.pushKV("metadata_verified", e.hit.rec.signed_ok);
    o.pushKV("publisher", pub);
    o.pushKV("lifecycle", EconomyLifecycleJson(e));
    o.pushKV("release", EconomyReleaseJson(e));
    o.pushKV("availability", AvailabilityJson(e.hit.health));
    UniValue loc(UniValue::VOBJ);
    loc.pushKV("known", e.hit.local.known);
    loc.pushKV("downloaded", e.hit.local.downloaded);
    loc.pushKV("partial", e.hit.local.partial);
    loc.pushKV("seeded", e.hit.local.seeded);
    loc.pushKV("pinned", e.hit.local.pinned);
    loc.pushKV("qualification", e.hit.local.qualification);
    o.pushKV("local", loc);
    UniValue se(UniValue::VOBJ);
    se.pushKV("score", e.hit.score);
    se.pushKV("metadata_verified", e.hit.rec.signed_ok);
    se.pushKV("publisher_signed", e.hit.rec.signed_ok);
    se.pushKV("locally_derived", true);
    UniValue prov(UniValue::VARR);
    for (const auto& p : e.hit.provenance) prov.push_back(p);
    se.pushKV("provenance", prov);
    o.pushKV("search", se);
    o.pushKV("result_type", ModelResultTypeName(e.result_type));
    o.pushKV("actions", EconomyActionsJson(e.actions));
    o.pushKV("downloadable_now", e.downloadable_now);
    o.pushKV("fundable_now", e.fundable_now);
    o.pushKV("ciphertext_cacheable", e.ciphertext_cacheable);
    o.pushKV("refund_available_locally", e.refund_available_locally);
    o.pushKV("requires_wallet", e.requires_wallet);
    o.pushKV("requires_user_approval", e.requires_user_approval);
    o.pushKV("automatic_spend_atoms", AutomaticSpendAtoms());
    o.pushKV("sources_observed", e.hit.sources);
    o.pushKV("first_seen_at", e.first_seen_at);
    o.pushKV("published_at", e.hit.rec.published_at);
    return o;
}

UniValue EconomySearchCard(const ModelEconomyEntry& e)
{
    UniValue o = SearchResultCard(e.hit);
    o.pushKV("schema_version", ECONOMY_SCHEMA_VERSION);
    o.pushKV("result_type", ModelResultTypeName(e.result_type));
    o.pushKV("lifecycle_state", ModelLifecycleName(e.lifecycle));
    o.pushKV("actions", EconomyActionsJson(e.actions));
    o.pushKV("downloadable_now", e.downloadable_now);
    o.pushKV("fundable_now", e.fundable_now);
    o.pushKV("ciphertext_cacheable", e.ciphertext_cacheable);
    o.pushKV("entry", EconomyEntryToJson(e));
    UniValue rel = EconomyReleaseJson(e);
    o.pushKV("release", rel);
    o.pushKV("economy", EconomyEntryToJson(e));
    return o;
}

bool EconomyTouchesMonetaryConsensus()
{
    return false;
}

int64_t AutomaticSpendAtoms()
{
    return 0;
}

void ApplyChainObservationJson(UniValue& card, const UniValue& obs)
{
    if (!card.isObject() || !obs.isObject()) return;
    if (!obs.exists("funding_source") || !obs["funding_source"].isStr() ||
        obs["funding_source"].get_str() != "CHAIN_OBSERVATION") {
        return; // remote unsigned / helper-only claims are not chain authority
    }
    const bool confirmed_known = obs.exists("confirmed_known") && obs["confirmed_known"].get_bool();
    if (!confirmed_known && !(obs.exists("chain_height_known") && obs["chain_height_known"].get_bool())) {
        return;
    }
    auto patch_rel = [&](UniValue& rel) {
        if (!rel.isObject()) return;
        if (confirmed_known) {
            const int64_t confirmed = obs.exists("confirmed_funded_atoms") ? obs["confirmed_funded_atoms"].getInt<int64_t>() : 0;
            const int64_t pending = obs.exists("pending_funded_atoms") ? obs["pending_funded_atoms"].getInt<int64_t>() : 0;
            const int64_t target = rel.exists("target_atoms") ? rel["target_atoms"].getInt<int64_t>() : 0;
            rel.pushKV("confirmed_funded_atoms", confirmed);
            rel.pushKV("pending_funded_atoms", pending);
            rel.pushKV("funded_atoms", confirmed);
            rel.pushKV("value_known", target > 0);
            rel.pushKV("funding_source", "CHAIN_OBSERVATION");
            rel.pushKV("helper_observation", false);
            rel.pushKV("chain_observation", true);
            if (target > 0) {
                rel.pushKV("remaining_atoms", RemainingAtoms(target, confirmed));
                int64_t milli = 0;
                if (FundedPercentMilli(confirmed, target, milli)) {
                    rel.pushKV("funded_percent", MilliToDisplayPercent(milli));
                    rel.pushKV("funded_percent_milli", milli);
                }
            }
        }
        if (obs.exists("wallet_contributor")) rel.pushKV("wallet_local_state", obs["wallet_contributor"].get_bool());
        if (obs.exists("refund_status") && obs["refund_status"].isStr()) {
            rel.pushKV("refund_status", obs["refund_status"].get_str());
        }
        if (obs.exists("claim_txid") && obs["claim_txid"].isStr() && !obs["claim_txid"].get_str().empty()) {
            rel.pushKV("claim_txid", obs["claim_txid"].get_str());
        }
        if (obs.exists("chain_height")) rel.pushKV("latest_funding_height", obs["chain_height"].getInt<int64_t>());
    };
    auto apply_card_flags = [&](UniValue& o) {
        if (!o.isObject() || !confirmed_known) return;
        UniValue* relp = nullptr;
        UniValue rel_copy;
        if (o.exists("release") && o["release"].isObject()) {
            rel_copy = o["release"].get_obj();
            relp = &rel_copy;
        } else {
            relp = &o;
        }
        const int64_t target = relp->exists("target_atoms") ? (*relp)["target_atoms"].getInt<int64_t>() : 0;
        const int64_t confirmed = obs.exists("confirmed_funded_atoms") ? obs["confirmed_funded_atoms"].getInt<int64_t>() : 0;
        if (target > 0 && confirmed >= target) {
            o.pushKV("fundable_now", false);
            o.pushKV("lifecycle_state", "FUNDED_AWAITING_RELEASE");
            UniValue acts(UniValue::VARR);
            bool has_wait = false;
            if (o.exists("actions") && o["actions"].isArray()) {
                for (const auto& a : o["actions"].getValues()) {
                    if (a.isStr() && a.get_str() == "FUND_RELEASE") continue;
                    if (a.isStr() && a.get_str() == "WAIT_FOR_UNLOCK") has_wait = true;
                    acts.push_back(a);
                }
            }
            if (!has_wait) acts.push_back("WAIT_FOR_UNLOCK");
            o.pushKV("actions", acts);
        }
    };
    if (card.exists("release") && card["release"].isObject()) {
        UniValue rel = card["release"].get_obj();
        patch_rel(rel);
        card.pushKV("release", rel);
    } else {
        patch_rel(card);
    }
    if (card.exists("entry") && card["entry"].isObject()) {
        UniValue e = card["entry"].get_obj();
        if (e.exists("release") && e["release"].isObject()) {
            UniValue rel = e["release"].get_obj();
            patch_rel(rel);
            e.pushKV("release", rel);
        } else {
            patch_rel(e);
        }
        apply_card_flags(e);
        card.pushKV("entry", e);
    }
    if (card.exists("economy") && card["economy"].isObject()) {
        UniValue e = card["economy"].get_obj();
        if (e.exists("release") && e["release"].isObject()) {
            UniValue rel = e["release"].get_obj();
            patch_rel(rel);
            e.pushKV("release", rel);
        }
        apply_card_flags(e);
        card.pushKV("economy", e);
    }
    apply_card_flags(card);
    if (obs.exists("wallet_contributor") && obs["wallet_contributor"].isTrue()) {
        card.pushKV("requires_wallet", true);
    }
}

} // namespace modelnet
