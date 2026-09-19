// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/origin_broker.h>

#include <algorithm>
#include <cctype>

namespace modelnet {
namespace {

bool KeyLooksSecret(const std::string& key)
{
    std::string k = key;
    std::transform(k.begin(), k.end(), k.begin(), [](unsigned char c) { return std::tolower(c); });
    if (k == "external_url" || k == "locator" || k == "url" || k == "presigned_get" || k == "presignedurl") {
        return true;
    }
    if (k.find("authorization") != std::string::npos) return true;
    if (k.find("credential") != std::string::npos) return true;
    if (k.find("token") != std::string::npos) return true;
    if (k.find("secret") != std::string::npos) return true;
    if (k.find("x-amz-") != std::string::npos) return true;
    if (k.find("signature") != std::string::npos) return true;
    if (k.find("password") != std::string::npos) return true;
    return false;
}

bool AllHex(const std::string& s)
{
    if (s.empty()) return false;
    for (unsigned char c : s) {
        if (!std::isxdigit(c)) return false;
    }
    return true;
}

} // namespace

const char* OriginDeliveryModeName(OriginDeliveryMode m)
{
    switch (m) {
    case OriginDeliveryMode::PROXIED_NATIVE: return "PROXIED_NATIVE";
    case OriginDeliveryMode::DIRECT_BEST_EFFORT: return "DIRECT_BEST_EFFORT";
    case OriginDeliveryMode::DIRECT_GATEWAY_METERED: return "DIRECT_GATEWAY_METERED";
    }
    return "PROXIED_NATIVE";
}

bool OriginDeliveryModeFromName(const std::string& name, OriginDeliveryMode& out)
{
    if (name == "PROXIED_NATIVE" || name == "PROXY" || name == "NATIVE_PROXY") {
        out = OriginDeliveryMode::PROXIED_NATIVE;
        return true;
    }
    if (name == "DIRECT_BEST_EFFORT") {
        out = OriginDeliveryMode::DIRECT_BEST_EFFORT;
        return true;
    }
    if (name == "DIRECT_GATEWAY_METERED") {
        out = OriginDeliveryMode::DIRECT_GATEWAY_METERED;
        return true;
    }
    return false;
}

OriginMode OriginModeFromDelivery(OriginDeliveryMode m)
{
    return m == OriginDeliveryMode::PROXIED_NATIVE ? OriginMode::NATIVE_PROXY : OriginMode::EXPLICIT_EXTERNAL;
}

bool PresignedGetIsMeter()
{
    return false;
}

bool OriginFollowRedirectsAllowed()
{
    return false;
}

bool LocatorEmbedsUserinfo(const std::string& locator)
{
    const auto se = locator.find("://");
    if (se == std::string::npos) return false;
    const size_t host_begin = se + 3;
    const size_t host_end = locator.find_first_of("/?#", host_begin);
    const size_t n = (host_end == std::string::npos ? locator.size() : host_end) - host_begin;
    const std::string auth = locator.substr(host_begin, n);
    return auth.find('@') != std::string::npos;
}

bool OriginJsonHasCredential(const UniValue& json)
{
    if (!json.isObject()) return false;
    for (const auto& k : json.getKeys()) {
        if (KeyLooksSecret(k)) return true;
        if (!json[k].isStr()) continue;
        const std::string v = json[k].get_str();
        if (v.find("X-Amz-") != std::string::npos || v.find("x-amz-") != std::string::npos) return true;
        if (v.find("AWSAccessKeyId") != std::string::npos) return true;
        if (v.find("Signature=") != std::string::npos) return true;
    }
    return false;
}

OriginBroker::OriginBroker(OriginBrokerPolicy policy) : m_policy(policy)
{
    if (m_policy.max_piece_bytes == 0) m_policy.max_piece_bytes = PIECE_SIZE;
    if (m_policy.max_full_file_bytes == 0) m_policy.max_full_file_bytes = 400ull * GIB;
    if (m_policy.offer_ttl_ms <= 0) m_policy.offer_ttl_ms = 3600 * 1000;
}

bool OriginBroker::Issue(const OriginBrokerRequest& req, int64_t now_ms, OriginBrokerOffer& out, std::string& err)
{
    out = {};
    if (m_policy.follow_redirects) {
        err = "redirects forbidden";
        return false;
    }
    if (req.artifact_id.empty()) {
        err = "artifact_id";
        return false;
    }
    if (req.artifact_id.size() == 96 && !AllHex(req.artifact_id)) {
        err = "artifact_id";
        return false;
    }
    if (req.file_index < 0) {
        err = "file_index";
        return false;
    }
    if (req.length_bytes == 0) {
        err = "empty range";
        return false;
    }
    if (req.offset_bytes + req.length_bytes < req.offset_bytes) {
        err = "range overflow";
        return false;
    }
    if (req.object_generation.size() > 512) {
        err = "object_generation";
        return false;
    }

    const bool want_direct = req.requested_delivery != OriginDeliveryMode::PROXIED_NATIVE;
    OriginDeliveryMode delivery = OriginDeliveryMode::PROXIED_NATIVE;
    if (want_direct) {
        if (!m_policy.operator_allows_external) {
            err = "operator disabled external origin";
            return false;
        }
        if (!req.requester_allows_external) {
            err = "requester disabled external origin";
            return false;
        }
        if (req.locator.empty()) {
            err = "external origin requires locator";
            return false;
        }
        if (LocatorEmbedsUserinfo(req.locator)) {
            err = "locator must not embed credentials";
            return false;
        }
        if (req.object_generation.empty()) {
            err = "object_generation";
            return false;
        }
        delivery = req.requested_delivery;
    }

    bool requires_full = false;
    if (req.length_bytes > m_policy.max_piece_bytes) {
        if (!req.requester_accepts_full_ingest) {
            err = "full ingest not accepted";
            return false;
        }
        requires_full = true;
    }
    if (req.length_bytes > m_policy.max_full_file_bytes) {
        err = "range exceeds policy";
        return false;
    }

    OriginOffer legacy;
    legacy.mode = OriginModeFromDelivery(delivery);
    legacy.locator = want_direct ? req.locator : std::string{};
    legacy.follow_redirects = false;
    if (!OriginOfferAllowed(legacy, err)) return false;

    if (want_direct && m_grants_issued >= m_policy.grant_issuance_limit) {
        err = "grant issuance limit";
        return false;
    }

    if (now_ms < 0) now_ms = 0;
    out.version = 1;
    out.offer_id = "offer-" + std::to_string(m_next_offer++);
    out.mode = legacy.mode;
    out.delivery = delivery;
    out.artifact_id = req.artifact_id;
    out.file_index = req.file_index;
    out.offset_bytes = req.offset_bytes;
    out.length_bytes = req.length_bytes;
    out.object_generation = req.object_generation;
    out.expires_at_ms = now_ms + m_policy.offer_ttl_ms;
    out.allowed_operation = "GET";
    out.follow_redirects = false;
    out.requires_full_ingest = requires_full;
    out.native_pq = (delivery == OriginDeliveryMode::PROXIED_NATIVE);
    if (delivery == OriginDeliveryMode::DIRECT_BEST_EFFORT) {
        out.external_url = req.locator;
        out.bearer_reusable = true; // disclosed bearer reuse; not a meter
        out.native_pq = false;
        ++m_grants_issued;
    } else if (delivery == OriginDeliveryMode::DIRECT_GATEWAY_METERED) {
        out.external_url = req.locator;
        out.bearer_reusable = false; // gateway nonce; the URL itself is still not a meter
        out.native_pq = false;
        ++m_grants_issued;
    } else {
        out.external_url.clear();
        out.bearer_reusable = false;
        out.native_pq = true;
    }
    return true;
}

UniValue OriginBroker::PublicJson(const OriginBrokerOffer& offer) const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("version", offer.version);
    o.pushKV("offer_id", offer.offer_id);
    o.pushKV("mode", OriginDeliveryModeName(offer.delivery));
    o.pushKV("artifact_id", offer.artifact_id);
    o.pushKV("file_index", offer.file_index);
    o.pushKV("offset_bytes", std::to_string(offer.offset_bytes));
    o.pushKV("length_bytes", std::to_string(offer.length_bytes));
    o.pushKV("object_generation", offer.object_generation);
    o.pushKV("expires_at_ms", std::to_string(offer.expires_at_ms));
    o.pushKV("bearer_reusable", offer.bearer_reusable);
    o.pushKV("native_pq", offer.native_pq);
    o.pushKV("requires_full_ingest", offer.requires_full_ingest);
    return o;
}

UniValue OriginBroker::PrivateJson(const OriginBrokerOffer& offer) const
{
    UniValue o = PublicJson(offer);
    if (!offer.external_url.empty()) o.pushKV("external_url", offer.external_url);
    o.pushKV("allowed_operation", offer.allowed_operation);
    o.pushKV("origin_mode", offer.mode == OriginMode::NATIVE_PROXY ? "NATIVE_PROXY" : "EXPLICIT_EXTERNAL");
    o.pushKV("follow_redirects", false);
    o.pushKV("presigned_get_is_meter", PresignedGetIsMeter());
    return o;
}

OriginOffer OriginBroker::ToLegacyOffer(const OriginBrokerOffer& offer) const
{
    OriginOffer legacy;
    legacy.mode = offer.mode;
    legacy.locator = offer.mode == OriginMode::EXPLICIT_EXTERNAL ? offer.external_url : std::string{};
    legacy.follow_redirects = false;
    return legacy;
}

UniValue OriginBroker::StatusJson() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("operator_allows_external", m_policy.operator_allows_external);
    o.pushKV("follow_redirects", false);
    o.pushKV("grants_issued", std::to_string(m_grants_issued));
    o.pushKV("grant_issuance_limit", std::to_string(m_policy.grant_issuance_limit));
    o.pushKV("presigned_get_is_meter", PresignedGetIsMeter());
    return o;
}

} // namespace modelnet
