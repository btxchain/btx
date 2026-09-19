// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/subscription_mandate.h>

#include <modelnet/canonical_codec.h>
#include <modelnet/policy.h>
#include <random.h>
#include <util/strencodings.h>
#include <util/time.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <set>
#include <sstream>
#include <string>
#include <system_error>
#include <utility>

namespace modelnet {
namespace {

std::string LowerAscii(std::string s)
{
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool IsWildcardToken(const std::string& raw)
{
    const std::string s = LowerAscii(raw);
    if (s.empty() || s == "*" || s == "all" || s == "any" || s == "unlimited") return true;
    if (s == "all_publishers" || s == "all-publishers" || s == "allpublishers") return true;
    if (s == "all_recipients" || s == "all-recipients" || s == "allrecipients") return true;
    return s.find('*') != std::string::npos;
}

bool FlagTrue(const UniValue& o, const char* key)
{
    return o.exists(key) && o[key].isBool() && o[key].get_bool();
}

bool LowerHex(const std::string& s, size_t n)
{
    if (s.size() != n) return false;
    for (char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    }
    return true;
}

bool ValidIdentityHex(const std::string& s)
{
    return LowerHex(s, 96);
}

bool ValidNetworkHex(const std::string& s)
{
    return LowerHex(s, 64);
}

bool KnownKind(const std::string& k)
{
    static const std::set<std::string> ok = {
        "MODEL", "RELEASE", "COLLECTION", "BOUNTY", "ARTIFACT", "PUBLISHER", "QUERY", "CHANNEL"};
    return ok.count(k) > 0;
}

bool KnownAction(const std::string& a)
{
    WatchAction w;
    return ParseWatchAction(a, w);
}

bool HasStr(const std::vector<std::string>& v, const std::string& s)
{
    return std::find(v.begin(), v.end(), s) != v.end();
}

const UniValue& ArgN(const UniValue& params, size_t i)
{
    static const UniValue none;
    if (params.isArray() && params.size() > i) return params[i];
    if (params.isObject() && i == 0) return params;
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

std::string StrField(const UniValue& o, const char* key)
{
    if (!o.exists(key)) return {};
    if (o[key].isStr()) return o[key].get_str();
    return {};
}

std::string RandHex(size_t nbytes)
{
    std::vector<unsigned char> b(nbytes);
    GetStrongRandBytes(Span<unsigned char>{b.data(), b.size()});
    return HexStr(b);
}

bool ReadAtoms(const UniValue& o, const char* key, int64_t& n, std::string& err, bool required)
{
    if (!o.exists(key)) {
        if (required) {
            err = std::string("missing ") + key;
            return false;
        }
        n = 0;
        return true;
    }
    if (o[key].isStr()) return CanonicalAtoms(o[key].get_str(), n, err);
    if (o[key].isNum()) {
        n = o[key].getInt<int64_t>();
        if (n < 0 || n > MAX_MONEY_ATOMS) {
            err = "MoneyRange";
            return false;
        }
        return true;
    }
    err = std::string("invalid ") + key;
    return false;
}

bool ReadCount(const UniValue& o, const char* key, int64_t& n, std::string& err)
{
    if (!o.exists(key)) {
        err = std::string("missing ") + key;
        return false;
    }
    if (o[key].isNum()) {
        n = o[key].getInt<int64_t>();
        return true;
    }
    if (o[key].isStr()) {
        const std::string& s = o[key].get_str();
        if (s.empty() || s[0] == '-' || (s.size() > 1 && s[0] == '0')) {
            err = std::string("noncanonical ") + key;
            return false;
        }
        if (!std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isdigit(c); })) {
            err = std::string("invalid ") + key;
            return false;
        }
        try {
            n = std::stoll(s);
        } catch (...) {
            err = std::string("invalid ") + key;
            return false;
        }
        return true;
    }
    err = std::string("invalid ") + key;
    return false;
}

bool ReadStringList(const UniValue& o, const char* key, std::vector<std::string>& out, std::string& err, bool required)
{
    out.clear();
    if (!o.exists(key)) {
        if (required) {
            err = std::string("missing ") + key;
            return false;
        }
        return true;
    }
    if (!o[key].isArray()) {
        err = std::string("invalid ") + key;
        return false;
    }
    for (const auto& x : o[key].getValues()) {
        if (!x.isStr()) {
            err = std::string("invalid ") + key;
            return false;
        }
        if (IsWildcardToken(x.get_str())) {
            err = "wildcard";
            return false;
        }
        out.push_back(x.get_str());
    }
    return true;
}

/**
 * A refund destination that names an identity must name the mandate owner: the
 * only refund policy this type accepts is OWNER_CONTROLLED_ONLY. A destination
 * that is not an identity (a wallet-plane label or script alias) cannot be
 * resolved here and is left to the signer.
 */
bool RefundBoundToOwner(const std::string& refund_key, const SubscriptionMandate& m)
{
    if (refund_key.empty() || !ValidIdentityHex(refund_key)) return true;
    return refund_key == m.owner_identity;
}

/** A payout destination that names an identity must be the bound publisher or the owner. */
bool RecipientBound(const std::string& recipient, const SubscriptionMandate& m)
{
    if (recipient.empty() || !ValidIdentityHex(recipient)) return true;
    return recipient == m.publisher_id || recipient == m.owner_identity;
}

bool ReadStateFile(const fs::path& path, UniValue& out)
{
    std::ifstream in(path);
    if (!in) {
        out = UniValue(UniValue::VOBJ);
        return true;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    const std::string text = ss.str();
    if (text.empty()) {
        out = UniValue(UniValue::VOBJ);
        return true;
    }
    if (!out.read(text) || !out.isObject()) {
        out = UniValue(UniValue::VOBJ);
        return false;
    }
    return true;
}

bool WriteStateFile(const fs::path& path, const UniValue& o, std::string& err)
{
    if (!path.parent_path().empty()) fs::create_directories(path.parent_path());
    const fs::path tmp = fs::PathFromString(fs::PathToString(path) + ".tmp");
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) {
            err = "write " + fs::PathToString(path);
            return false;
        }
        out << o.write() << "\n";
        out.flush();
        if (!out) {
            err = "write " + fs::PathToString(path);
            return false;
        }
    }
    std::error_code ec;
    fs::rename(tmp, path, ec);
    if (ec) {
        err = "rename " + fs::PathToString(path);
        return false;
    }
    return true;
}

bool NestedTrick(const SubscriptionEvent& event, const SignedTerms& terms, std::string& err)
{
    if (!event.nested_publisher_id.empty() && event.nested_publisher_id != event.publisher_id) {
        err = "nested publisher";
        return true;
    }
    if (!event.nested_recipient.empty()) {
        err = "nested recipient";
        return true;
    }
    if (terms.all_recipients) {
        err = "all recipients";
        return true;
    }
    if (!terms.nested_recipient.empty()) {
        err = "nested recipient";
        return true;
    }
    if (!terms.nested_publisher_id.empty() && terms.nested_publisher_id != terms.publisher_id) {
        err = "nested publisher";
        return true;
    }
    if (terms.recipients.size() > 1) {
        err = "nested recipient";
        return true;
    }
    if (FlagTrue(terms.raw, "all_recipients") || FlagTrue(terms.raw, "all_publishers")) {
        err = "wildcard";
        return true;
    }
    if (terms.raw.exists("pay_to") || terms.raw.exists("forward_to") || terms.raw.exists("alternate_recipient")) {
        err = "nested recipient";
        return true;
    }
    if (terms.raw.exists("inner") && terms.raw["inner"].isObject()) {
        const UniValue& inner = terms.raw["inner"];
        if (inner.exists("publisher_id") || inner.exists("recipient_id") || inner.exists("recipients")) {
            err = "nested recipient";
            return true;
        }
    }
    return false;
}

} // namespace

const char* WatchActionName(WatchAction a)
{
    switch (a) {
    case WatchAction::NOTIFY: return "NOTIFY";
    case WatchAction::FREE_DOWNLOAD: return "FREE_DOWNLOAD";
    case WatchAction::KEEP: return "KEEP";
    case WatchAction::SEED: return "SEED";
    case WatchAction::PREPARE_FUNDING: return "PREPARE_FUNDING";
    case WatchAction::FUND_WITH_MANDATE: return "FUND_WITH_MANDATE";
    }
    return "";
}

bool ParseWatchAction(const std::string& s, WatchAction& out)
{
    if (s == "NOTIFY") {
        out = WatchAction::NOTIFY;
        return true;
    }
    if (s == "FREE_DOWNLOAD") {
        out = WatchAction::FREE_DOWNLOAD;
        return true;
    }
    if (s == "KEEP") {
        out = WatchAction::KEEP;
        return true;
    }
    if (s == "SEED") {
        out = WatchAction::SEED;
        return true;
    }
    if (s == "PREPARE_FUNDING") {
        out = WatchAction::PREPARE_FUNDING;
        return true;
    }
    if (s == "FUND_WITH_MANDATE") {
        out = WatchAction::FUND_WITH_MANDATE;
        return true;
    }
    return false;
}

bool ValidateWatchActionPolicy(const WatchActionPolicy& p, std::string& err)
{
    if (p.action == WatchAction::FUND_WITH_MANDATE && p.mandate_id.empty()) {
        err = "FUND_WITH_MANDATE requires mandate_id";
        return false;
    }
    return true;
}

bool ValidateMandate(const SubscriptionMandate& m, std::string& err)
{
    if (m.mandate_version != SUBSCRIPTION_MANDATE_VERSION) {
        err = "mandate_version";
        return false;
    }
    if (!ValidIdentityHex(m.owner_identity)) {
        err = "owner_identity";
        return false;
    }
    if (!ValidIdentityHex(m.publisher_id) || IsWildcardToken(m.publisher_id)) {
        err = "publisher_id";
        return false;
    }
    if (m.allowed_kinds.empty()) {
        err = "allowed_kinds";
        return false;
    }
    for (const auto& k : m.allowed_kinds) {
        if (IsWildcardToken(k) || !KnownKind(k)) {
            err = "allowed_kinds";
            return false;
        }
    }
    if (m.allowed_actions.empty()) {
        err = "allowed_actions";
        return false;
    }
    for (const auto& a : m.allowed_actions) {
        if (IsWildcardToken(a) || !KnownAction(a)) {
            err = "allowed_actions";
            return false;
        }
    }
    if (IsWildcardToken(m.collection_id) && !m.collection_id.empty()) {
        err = "collection_id";
        return false;
    }
    if (IsWildcardToken(m.query_filter) && !m.query_filter.empty()) {
        err = "query_filter";
        return false;
    }
    if (m.per_action_principal_limit_atoms < 0 || m.per_action_principal_limit_atoms > MAX_MONEY_ATOMS) {
        err = "per_action_principal_limit_atoms";
        return false;
    }
    if (m.total_principal_limit_atoms < 0 || m.total_principal_limit_atoms > MAX_MONEY_ATOMS) {
        err = "total_principal_limit_atoms";
        return false;
    }
    if (m.total_fee_limit_atoms < 0 || m.total_fee_limit_atoms > MAX_MONEY_ATOMS) {
        err = "total_fee_limit_atoms";
        return false;
    }
    if (m.outstanding_exposure_limit_atoms < 0 || m.outstanding_exposure_limit_atoms > MAX_MONEY_ATOMS) {
        err = "outstanding_exposure_limit_atoms";
        return false;
    }
    if (m.max_actions < 1) {
        err = "max_actions";
        return false;
    }
    if (m.max_concurrent_reservations < 1 || m.max_concurrent_reservations > SUBSCRIPTION_CONCURRENT_MAX) {
        err = "max_concurrent_reservations";
        return false;
    }
    if (m.expires_at_ms <= 0) {
        err = "expires_at_ms";
        return false;
    }
    if (m.refund_key_policy != SUBSCRIPTION_REFUND_POLICY) {
        err = "refund_key_policy";
        return false;
    }
    if (m.minimum_confirmations < 0) {
        err = "minimum_confirmations";
        return false;
    }
    if (m.revocation_counter < 0) {
        err = "revocation_counter";
        return false;
    }
    for (const auto& a : m.assurance_mode_restrictions) {
        if (IsWildcardToken(a)) {
            err = "assurance_mode_restrictions";
            return false;
        }
    }
    return true;
}

bool MandateFromJson(const UniValue& src, SubscriptionMandate& m, std::string& err)
{
    const UniValue& o = (src.exists("mandate") && src["mandate"].isObject()) ? src["mandate"] : src;
    if (FlagTrue(o, "all_publishers") || FlagTrue(src, "all_publishers") || FlagTrue(o, "all_recipients") ||
        FlagTrue(src, "all_recipients") || FlagTrue(o, "unlimited") || FlagTrue(o, "no_expiry")) {
        err = "wildcard";
        return false;
    }
    m = SubscriptionMandate{};
    if (o.exists("mandate_version")) {
        int64_t v = 0;
        if (!ReadCount(o, "mandate_version", v, err) || v != SUBSCRIPTION_MANDATE_VERSION) {
            err = "mandate_version";
            return false;
        }
    }
    m.mandate_id = StrField(o, "mandate_id");
    m.owner_identity = StrField(o, "owner_identity");
    const std::string nid = StrField(o, "network_id");
    if (nid.empty() || !ValidNetworkHex(nid) || !NetworkId::FromHex(nid, m.network_id, err)) {
        err = "network_id";
        return false;
    }
    m.publisher_id = StrField(o, "publisher_id");
    if (!ReadStringList(o, "allowed_kinds", m.allowed_kinds, err, true)) return false;
    if (!ReadStringList(o, "allowed_actions", m.allowed_actions, err, true)) return false;
    m.collection_id = StrField(o, "collection_id");
    m.query_filter = StrField(o, "query_filter");
    if (!o.exists("per_action_principal_limit_atoms") || !o.exists("total_principal_limit_atoms") ||
        !o.exists("total_fee_limit_atoms") || !o.exists("outstanding_exposure_limit_atoms")) {
        err = "missing caps";
        return false;
    }
    if (!ReadAtoms(o, "per_action_principal_limit_atoms", m.per_action_principal_limit_atoms, err, true)) return false;
    if (!ReadAtoms(o, "total_principal_limit_atoms", m.total_principal_limit_atoms, err, true)) return false;
    if (!ReadAtoms(o, "total_fee_limit_atoms", m.total_fee_limit_atoms, err, true)) return false;
    if (!ReadAtoms(o, "outstanding_exposure_limit_atoms", m.outstanding_exposure_limit_atoms, err, true)) return false;
    if (!ReadCount(o, "max_actions", m.max_actions, err)) return false;
    int64_t conc = 0;
    if (!ReadCount(o, "max_concurrent_reservations", conc, err)) return false;
    if (conc < 1 || conc > SUBSCRIPTION_CONCURRENT_MAX) {
        err = "max_concurrent_reservations";
        return false;
    }
    m.max_concurrent_reservations = static_cast<int>(conc);
    if (!o.exists("expires_at_ms")) {
        err = "expires_at_ms";
        return false;
    }
    if (!ReadCount(o, "expires_at_ms", m.expires_at_ms, err)) return false;
    m.refund_key_policy = StrField(o, "refund_key_policy");
    if (m.refund_key_policy.empty()) m.refund_key_policy = SUBSCRIPTION_REFUND_POLICY;
    int64_t minc = 1;
    if (o.exists("minimum_confirmations")) {
        if (!ReadCount(o, "minimum_confirmations", minc, err)) return false;
    } else {
        err = "minimum_confirmations";
        return false;
    }
    m.minimum_confirmations = static_cast<int>(minc);
    if (!ReadStringList(o, "assurance_mode_restrictions", m.assurance_mode_restrictions, err, true)) return false;
    if (!ReadCount(o, "revocation_counter", m.revocation_counter, err)) return false;
    if (o.exists("revoked") && o["revoked"].isBool()) m.revoked = o["revoked"].get_bool();
    // Extra JSON (model card text, extra_publishers, raised caps under other names) is ignored.
    return ValidateMandate(m, err);
}

UniValue MandateToJson(const SubscriptionMandate& m)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("mandate_version", m.mandate_version);
    o.pushKV("mandate_id", m.mandate_id);
    o.pushKV("owner_identity", m.owner_identity);
    o.pushKV("network_id", m.network_id.Hex());
    o.pushKV("publisher_id", m.publisher_id);
    UniValue kinds(UniValue::VARR);
    for (const auto& k : m.allowed_kinds) kinds.push_back(k);
    o.pushKV("allowed_kinds", kinds);
    UniValue acts(UniValue::VARR);
    for (const auto& a : m.allowed_actions) acts.push_back(a);
    o.pushKV("allowed_actions", acts);
    if (!m.collection_id.empty()) o.pushKV("collection_id", m.collection_id);
    if (!m.query_filter.empty()) o.pushKV("query_filter", m.query_filter);
    o.pushKV("per_action_principal_limit_atoms", std::to_string(m.per_action_principal_limit_atoms));
    o.pushKV("total_principal_limit_atoms", std::to_string(m.total_principal_limit_atoms));
    o.pushKV("total_fee_limit_atoms", std::to_string(m.total_fee_limit_atoms));
    o.pushKV("outstanding_exposure_limit_atoms", std::to_string(m.outstanding_exposure_limit_atoms));
    o.pushKV("max_actions", m.max_actions);
    o.pushKV("max_concurrent_reservations", m.max_concurrent_reservations);
    o.pushKV("expires_at_ms", std::to_string(m.expires_at_ms));
    o.pushKV("refund_key_policy", m.refund_key_policy);
    o.pushKV("minimum_confirmations", m.minimum_confirmations);
    UniValue asr(UniValue::VARR);
    for (const auto& a : m.assurance_mode_restrictions) asr.push_back(a);
    o.pushKV("assurance_mode_restrictions", asr);
    o.pushKV("revocation_counter", std::to_string(m.revocation_counter));
    o.pushKV("revoked", m.revoked);
    o.pushKV("automatic_spend_atoms", SUBSCRIPTION_AUTOMATIC_SPEND_ATOMS);
    o.pushKV("private_keys", false);
    o.pushKV("wallet_signed", false);
    return o;
}

bool EventFromJson(const UniValue& o, SubscriptionEvent& ev, std::string& err)
{
    ev = SubscriptionEvent{};
    ev.event_id = StrField(o, "event_id");
    ev.publisher_id = StrField(o, "publisher_id");
    ev.object_kind = StrField(o, "object_kind");
    ev.object_id = StrField(o, "object_id");
    ev.collection_id = StrField(o, "collection_id");
    ev.terms_id = StrField(o, "terms_id");
    ev.action = StrField(o, "action");
    ev.mandate_id = StrField(o, "mandate_id");
    ev.query_text = StrField(o, "query_text");
    ev.nested_publisher_id = StrField(o, "nested_publisher_id");
    ev.nested_recipient = StrField(o, "nested_recipient");
    if (o.exists("observed_at_ms")) {
        int64_t n = 0;
        if (!ReadCount(o, "observed_at_ms", n, err)) return false;
        ev.observed_at_ms = n;
    }
    if (ev.event_id.empty()) {
        err = "event_id";
        return false;
    }
    return true;
}

bool TermsFromJson(const UniValue& o, SignedTerms& t, std::string& err)
{
    t = SignedTerms{};
    t.raw = o;
    if (o.empty() && !o.exists("terms_id") && !o.exists("publisher_id")) {
        t.known = false;
        return true;
    }
    t.terms_id = StrField(o, "terms_id");
    t.publisher_id = StrField(o, "publisher_id");
    t.network_id_hex = StrField(o, "network_id");
    t.recipient_id = StrField(o, "recipient_id");
    t.refund_key = StrField(o, "refund_key");
    t.object_kind = StrField(o, "object_kind");
    t.collection_id = StrField(o, "collection_id");
    t.assurance_mode = StrField(o, "assurance_mode");
    t.nested_recipient = StrField(o, "nested_recipient");
    t.nested_publisher_id = StrField(o, "nested_publisher_id");
    t.all_recipients = FlagTrue(o, "all_recipients");
    if (o.exists("recipients") && o["recipients"].isArray()) {
        for (const auto& x : o["recipients"].getValues()) {
            if (x.isStr()) t.recipients.push_back(x.get_str());
        }
    }
    if (o.exists("confirmations")) {
        int64_t n = 0;
        if (!ReadCount(o, "confirmations", n, err)) return false;
        t.confirmations = static_cast<int>(n);
    }
    if (o.exists("principal_atoms") && !ReadAtoms(o, "principal_atoms", t.principal_atoms, err, true)) return false;
    if (o.exists("fee_atoms") && !ReadAtoms(o, "fee_atoms", t.fee_atoms, err, false)) return false;
    t.known = !t.terms_id.empty() && !t.publisher_id.empty();
    return true;
}

UniValue ReservationToJson(const Reservation& r)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("reservation_id", r.reservation_id);
    o.pushKV("mandate_id", r.mandate_id);
    o.pushKV("event_id", r.event_id);
    o.pushKV("principal_atoms", std::to_string(r.principal_atoms));
    o.pushKV("fee_atoms", std::to_string(r.fee_atoms));
    o.pushKV("wallet_signed", false);
    o.pushKV("broadcast", r.broadcast);
    o.pushKV("contains_wallet_material", false);
    o.pushKV("private_keys", false);
    o.pushKV("automatic_spend_atoms", SUBSCRIPTION_AUTOMATIC_SPEND_ATOMS);
    return o;
}

bool Evaluate(const SubscriptionEvent& event, const SignedTerms& terms,
              const SubscriptionMandate& mandate, int64_t now_ms, std::string& err)
{
    if (!ValidateMandate(mandate, err)) return false;
    if (mandate.revoked) {
        err = "revoked";
        return false;
    }
    if (now_ms > mandate.expires_at_ms) {
        err = "expired";
        return false;
    }
    // Publisher binding is evaluated even when terms are unknown.
    if (event.publisher_id != mandate.publisher_id) {
        err = "publisher binding";
        return false;
    }
    if (NestedTrick(event, terms, err)) return false;
    WatchAction act;
    if (!ParseWatchAction(event.action, act) || !HasStr(mandate.allowed_actions, event.action)) {
        err = "action";
        return false;
    }
    if (act == WatchAction::FUND_WITH_MANDATE) {
        // An unnamed mandate would authorize an event carrying any mandate id.
        if (mandate.mandate_id.empty()) {
            err = "mandate_id";
            return false;
        }
        if (event.mandate_id.empty()) {
            err = "FUND_WITH_MANDATE requires mandate_id";
            return false;
        }
        if (event.mandate_id != mandate.mandate_id) {
            err = "mandate_id";
            return false;
        }
    }
    // allowed_kinds is mandatory, so an absent kind is not a wildcard: the event or
    // the terms must name a kind, and the two must agree.
    const std::string kind = !event.object_kind.empty() ? event.object_kind : terms.object_kind;
    if (kind.empty() || !HasStr(mandate.allowed_kinds, kind)) {
        err = "object_kind";
        return false;
    }
    if (!terms.object_kind.empty() && terms.object_kind != kind) {
        err = "object_kind";
        return false;
    }
    if (!mandate.collection_id.empty()) {
        const std::string coll = !event.collection_id.empty() ? event.collection_id : terms.collection_id;
        if (coll != mandate.collection_id) {
            err = "collection_id";
            return false;
        }
    }
    if (!mandate.query_filter.empty() && event.query_text != mandate.query_filter) {
        err = "query_filter";
        return false;
    }
    if (act == WatchAction::NOTIFY || act == WatchAction::FREE_DOWNLOAD || act == WatchAction::KEEP ||
        act == WatchAction::SEED) {
        return true;
    }
    if (!terms.known) {
        err = "unknown terms";
        return false;
    }
    if (terms.publisher_id != mandate.publisher_id) {
        err = "publisher binding";
        return false;
    }
    // Known terms must state their network. Silence is not a match.
    if (terms.network_id_hex.empty() || terms.network_id_hex != mandate.network_id.Hex()) {
        err = "network_id";
        return false;
    }
    if (!RefundBoundToOwner(terms.refund_key, mandate)) {
        err = "refund_key";
        return false;
    }
    if (!RecipientBound(terms.recipient_id, mandate)) {
        err = "recipient binding";
        return false;
    }
    if (terms.recipients.size() == 1 && !RecipientBound(terms.recipients.front(), mandate)) {
        err = "recipient binding";
        return false;
    }
    if (terms.confirmations < mandate.minimum_confirmations) {
        err = "confirmations";
        return false;
    }
    if (!mandate.assurance_mode_restrictions.empty()) {
        if (!HasStr(mandate.assurance_mode_restrictions, terms.assurance_mode)) {
            err = "assurance_mode";
            return false;
        }
    } else if (!terms.assurance_mode.empty()) {
        err = "assurance_mode";
        return false;
    }
    if (act == WatchAction::FUND_WITH_MANDATE) {
        if (terms.principal_atoms <= 0) {
            err = "principal_atoms";
            return false;
        }
        if (terms.principal_atoms > mandate.per_action_principal_limit_atoms) {
            err = "per-action cap";
            return false;
        }
        if (terms.fee_atoms < 0) {
            err = "fee_atoms";
            return false;
        }
        if (!terms.refund_key.empty() && mandate.refund_key_policy != SUBSCRIPTION_REFUND_POLICY) {
            err = "refund_key_policy";
            return false;
        }
    }
    return true;
}

UniValue PrepareFundingPlan(const SubscriptionEvent& event, const SignedTerms& terms)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("event_id", event.event_id);
    o.pushKV("terms_id", terms.terms_id);
    o.pushKV("principal_atoms", std::to_string(terms.principal_atoms));
    o.pushKV("fee_atoms", std::to_string(terms.fee_atoms));
    o.pushKV("unsigned", true);
    o.pushKV("wallet_signed", false);
    o.pushKV("automatic_spend_atoms", SUBSCRIPTION_AUTOMATIC_SPEND_ATOMS);
    o.pushKV("private_keys", false);
    return o;
}

bool SubscriptionBudget::Bind(const SubscriptionMandate& m, std::string& err)
{
    if (!ValidateMandate(m, err)) return false;
    std::lock_guard<std::mutex> lock(m_mu);
    m_mandate = m;
    m_used_principal = 0;
    m_used_fees = 0;
    m_outstanding = 0;
    m_action_count = 0;
    m_concurrent = 0;
    m_reorgs = 0;
    m_by_event.clear();
    m_bound = true;
    return true;
}

bool SubscriptionBudget::EvaluateAndReserve(const SubscriptionEvent& event, const SignedTerms& terms,
                                            Reservation& out, int64_t now_ms, std::string& err)
{
    SubscriptionMandate snap;
    {
        std::lock_guard<std::mutex> lock(m_mu);
        if (!m_bound) {
            err = "unbound";
            return false;
        }
        snap = m_mandate;
    }
    if (!Evaluate(event, terms, snap, now_ms, err)) return false;
    if (event.action != "FUND_WITH_MANDATE") {
        err = "not a spend action";
        return false;
    }
    std::lock_guard<std::mutex> lock(m_mu);
    if (m_mandate.revoked) {
        err = "revoked";
        return false;
    }
    if (now_ms > m_mandate.expires_at_ms) {
        err = "expired";
        return false;
    }
    auto it = m_by_event.find(event.event_id);
    if (it != m_by_event.end()) {
        // The event id alone does not identify what was authorized: a second object or
        // a second terms document under a reused id is a conflict, not a replay.
        if (it->second.principal_atoms != terms.principal_atoms || it->second.fee_atoms != terms.fee_atoms ||
            it->second.object_id != event.object_id || it->second.terms_id != terms.terms_id) {
            err = "idempotency conflict";
            return false;
        }
        out = it->second;
        out.wallet_signed = false;
        out.contains_wallet_material = false;
        return true;
    }
    if (m_action_count >= m_mandate.max_actions) {
        err = "max actions";
        return false;
    }
    if (m_concurrent >= m_mandate.max_concurrent_reservations) {
        err = "max concurrent";
        return false;
    }
    if (terms.principal_atoms > m_mandate.per_action_principal_limit_atoms) {
        err = "per-action cap";
        return false;
    }
    if (!ExposureWithinCeiling(m_used_principal, terms.principal_atoms, m_mandate.total_principal_limit_atoms)) {
        err = "principal budget";
        return false;
    }
    if (!ExposureWithinCeiling(m_used_fees, terms.fee_atoms, m_mandate.total_fee_limit_atoms)) {
        err = "fee budget";
        return false;
    }
    // Exposure is what is reserved and not yet settled, not the lifetime total. The
    // lifetime totals are capped separately above.
    const int64_t add_exp = terms.principal_atoms + terms.fee_atoms;
    if (!ExposureWithinCeiling(m_outstanding, add_exp, m_mandate.outstanding_exposure_limit_atoms)) {
        err = "exposure cap";
        return false;
    }
    Reservation r;
    r.reservation_id = RandHex(16);
    r.mandate_id = m_mandate.mandate_id;
    r.event_id = event.event_id;
    r.object_id = event.object_id;
    r.terms_id = terms.terms_id;
    r.principal_atoms = terms.principal_atoms;
    r.fee_atoms = terms.fee_atoms;
    r.wallet_signed = false;
    r.broadcast = false;
    r.contains_wallet_material = false;
    m_by_event[event.event_id] = r;
    m_used_principal += terms.principal_atoms;
    m_used_fees += terms.fee_atoms;
    m_outstanding += add_exp;
    ++m_action_count;
    ++m_concurrent;
    out = r;
    return true;
}

void SubscriptionBudget::Revoke()
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_mandate.revoked = true;
    ++m_mandate.revocation_counter;
}

bool SubscriptionBudget::Revoked() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_mandate.revoked;
}

bool SubscriptionBudget::Expired(int64_t now_ms) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return now_ms > m_mandate.expires_at_ms;
}

int64_t SubscriptionBudget::UsedPrincipal() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_used_principal;
}

int64_t SubscriptionBudget::UsedFees() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_used_fees;
}

int64_t SubscriptionBudget::OutstandingExposure() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_outstanding;
}

int64_t SubscriptionBudget::ActionCount() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_action_count;
}

int SubscriptionBudget::ConcurrentReservations() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_concurrent;
}

int64_t SubscriptionBudget::ReorgCount() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_reorgs;
}

void SubscriptionBudget::NoteChainReorg()
{
    // Spent stays spent: used principal and used fees never decrease, and the
    // wallet plane restores UTXOs on its own. What a reorg does invalidate is the
    // idempotency entry of a reservation that was already broadcast, because the
    // transaction it authorized is no longer in the chain. Dropping it forces the
    // replayed event through Evaluate again instead of returning a settled
    // reservation that would look like a fresh authorization to the caller.
    std::lock_guard<std::mutex> lock(m_mu);
    ++m_reorgs;
    for (auto it = m_by_event.begin(); it != m_by_event.end();) {
        if (it->second.broadcast) {
            it = m_by_event.erase(it);
        } else {
            ++it;
        }
    }
}

bool SubscriptionBudget::MarkBroadcast(const std::string& event_id, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_by_event.find(event_id);
    if (it == m_by_event.end()) {
        err = "not found";
        return false;
    }
    if (!it->second.broadcast) {
        it->second.broadcast = true;
        if (m_concurrent > 0) --m_concurrent;
        const int64_t settled = it->second.principal_atoms + it->second.fee_atoms;
        m_outstanding = m_outstanding > settled ? m_outstanding - settled : 0;
    }
    return true;
}

SubscriptionMandate SubscriptionBudget::Mandate() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_mandate;
}

UniValue SubscriptionBudget::StatusJson() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    UniValue o = MandateToJson(m_mandate);
    o.pushKV("used_principal_atoms", std::to_string(m_used_principal));
    o.pushKV("used_fee_atoms", std::to_string(m_used_fees));
    o.pushKV("outstanding_exposure_atoms", std::to_string(m_outstanding));
    o.pushKV("action_count", m_action_count);
    o.pushKV("concurrent_reservations", m_concurrent);
    o.pushKV("reorg_count", m_reorgs);
    o.pushKV("automatic_spend_atoms", SUBSCRIPTION_AUTOMATIC_SPEND_ATOMS);
    o.pushKV("wallet_signed", false);
    o.pushKV("private_keys", false);
    return o;
}

UniValue SubscriptionBudget::ActivityPage(const std::string& cursor, int limit) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    UniValue actions(UniValue::VARR);
    bool skipping = !cursor.empty();
    bool saw_cursor = cursor.empty();
    std::string last;
    int n = 0;
    for (const auto& kv : m_by_event) {
        if (skipping) {
            if (kv.first == cursor) {
                skipping = false;
                saw_cursor = true;
            }
            continue;
        }
        UniValue row = ReservationToJson(kv.second);
        row.pushKV("object_id", kv.second.object_id);
        row.pushKV("terms_id", kv.second.terms_id);
        row.pushKV("txid", "");
        actions.push_back(row);
        last = kv.first;
        if (++n >= limit) break;
    }
    UniValue page(UniValue::VOBJ);
    page.pushKV("mandate_id", m_mandate.mandate_id);
    page.pushKV("actions", actions);
    page.pushKV("cursor_ok", saw_cursor);
    page.pushKV("next_cursor", (n >= limit && !last.empty()) ? last : "");
    page.pushKV("limit", limit);
    page.pushKV("telemetry", false);
    page.pushKV("automatic_spend_atoms", SUBSCRIPTION_AUTOMATIC_SPEND_ATOMS);
    page.pushKV("wallet_signed", false);
    page.pushKV("private_keys", false);
    return page;
}

UniValue SubscriptionBudget::SaveStateJson() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    UniValue o(UniValue::VOBJ);
    o.pushKV("mandate", MandateToJson(m_mandate));
    o.pushKV("used_principal_atoms", std::to_string(m_used_principal));
    o.pushKV("used_fee_atoms", std::to_string(m_used_fees));
    o.pushKV("action_count", std::to_string(m_action_count));
    o.pushKV("reorg_count", std::to_string(m_reorgs));
    UniValue rs(UniValue::VARR);
    for (const auto& [event_id, r] : m_by_event) {
        UniValue e(UniValue::VOBJ);
        e.pushKV("reservation_id", r.reservation_id);
        e.pushKV("event_id", event_id);
        e.pushKV("object_id", r.object_id);
        e.pushKV("terms_id", r.terms_id);
        e.pushKV("principal_atoms", std::to_string(r.principal_atoms));
        e.pushKV("fee_atoms", std::to_string(r.fee_atoms));
        e.pushKV("broadcast", r.broadcast);
        rs.push_back(e);
    }
    o.pushKV("reservations", rs);
    return o;
}

bool SubscriptionBudget::LoadStateJson(const UniValue& state, std::string& err)
{
    if (!state.isObject() || !state.exists("mandate") || !state["mandate"].isObject()) {
        err = "mandate";
        return false;
    }
    SubscriptionMandate m;
    if (!MandateFromJson(state["mandate"], m, err)) return false;
    int64_t used_principal = 0, used_fees = 0, actions = 0, reorgs = 0;
    if (!ReadAtoms(state, "used_principal_atoms", used_principal, err, true)) return false;
    if (!ReadAtoms(state, "used_fee_atoms", used_fees, err, true)) return false;
    if (!ReadCount(state, "action_count", actions, err)) return false;
    if (!ReadCount(state, "reorg_count", reorgs, err)) return false;

    std::map<std::string, Reservation> by_event;
    int64_t outstanding = 0;
    int concurrent = 0;
    if (state.exists("reservations")) {
        if (!state["reservations"].isArray()) {
            err = "reservations";
            return false;
        }
        for (const UniValue& e : state["reservations"].getValues()) {
            if (!e.isObject()) {
                err = "reservations";
                return false;
            }
            Reservation r;
            r.reservation_id = StrField(e, "reservation_id");
            r.event_id = StrField(e, "event_id");
            r.object_id = StrField(e, "object_id");
            r.terms_id = StrField(e, "terms_id");
            if (r.reservation_id.empty() || r.event_id.empty()) {
                err = "reservations";
                return false;
            }
            if (!ReadAtoms(e, "principal_atoms", r.principal_atoms, err, true)) return false;
            if (!ReadAtoms(e, "fee_atoms", r.fee_atoms, err, true)) return false;
            r.broadcast = e.exists("broadcast") && e["broadcast"].isBool() && e["broadcast"].get_bool();
            if (!r.broadcast) {
                outstanding += r.principal_atoms + r.fee_atoms;
                ++concurrent;
            }
            by_event[r.event_id] = r;
        }
    }
    // Derive exposure and concurrency from the reservations themselves so a truncated
    // or hand-edited counter cannot hand back budget that was already committed.
    std::lock_guard<std::mutex> lock(m_mu);
    m_mandate = m;
    m_used_principal = used_principal;
    m_used_fees = used_fees;
    m_outstanding = outstanding;
    m_action_count = actions;
    m_concurrent = concurrent;
    m_reorgs = reorgs;
    m_by_event = std::move(by_event);
    m_bound = true;
    return true;
}

bool EvaluateAndReserve(SubscriptionBudget& budget, const SubscriptionEvent& event,
                        const SignedTerms& terms, Reservation& out, int64_t now_ms, std::string& err)
{
    return budget.EvaluateAndReserve(event, terms, out, now_ms, err);
}

void SubscriptionStore::Reset()
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_mandates.clear();
    m_budgets.clear();
    m_path.clear();
    m_node_network.clear();
}

bool SubscriptionStore::SaveLocked(std::string& err) const
{
    if (m_path.empty()) return true;
    UniValue root(UniValue::VOBJ);
    root.pushKV("version", SUBSCRIPTION_MANDATE_VERSION);
    UniValue arr(UniValue::VARR);
    for (const auto& entry : m_budgets) {
        arr.push_back(entry.second->SaveStateJson());
    }
    root.pushKV("mandates", arr);
    return WriteStateFile(m_path, root, err);
}

bool SubscriptionStore::SetPersistPath(const fs::path& path, std::string& err)
{
    if (path.empty()) {
        err = "path";
        return false;
    }
    std::lock_guard<std::mutex> lock(m_mu);
    m_mandates.clear();
    m_budgets.clear();
    m_path = path;
    UniValue root;
    if (!ReadStateFile(m_path, root)) {
        // Refuse to start on a corrupt file rather than silently freeing a spent budget.
        m_path.clear();
        err = "corrupt " + fs::PathToString(path);
        return false;
    }
    if (!root.exists("mandates") || !root["mandates"].isArray()) return true;
    for (const UniValue& state : root["mandates"].getValues()) {
        auto slot = std::make_unique<SubscriptionBudget>();
        if (!slot->LoadStateJson(state, err)) {
            m_mandates.clear();
            m_budgets.clear();
            m_path.clear();
            return false;
        }
        const SubscriptionMandate m = slot->Mandate();
        if (m.mandate_id.empty() || m_budgets.count(m.mandate_id)) {
            m_mandates.clear();
            m_budgets.clear();
            m_path.clear();
            err = "mandate_id";
            return false;
        }
        m_mandates[m.mandate_id] = m;
        m_budgets[m.mandate_id] = std::move(slot);
    }
    return true;
}

bool SubscriptionStore::Persisted() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return !m_path.empty();
}

bool SubscriptionStore::SetNodeNetwork(const std::string& network_hex, std::string& err)
{
    if (!network_hex.empty() && !ValidNetworkHex(network_hex)) {
        err = "network_id";
        return false;
    }
    std::lock_guard<std::mutex> lock(m_mu);
    m_node_network = network_hex;
    return true;
}

std::string SubscriptionStore::NodeNetwork() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_node_network;
}

bool SubscriptionStore::Dispatch(const std::string& method, const UniValue& params, UniValue& result,
                                 std::string& err_code, std::string& err, int64_t now_ms)
{
    auto fail = [&](const char* code, const std::string& e) {
        err_code = code;
        err = e;
        return false;
    };
    auto ok = [&]() {
        err_code.clear();
        err.clear();
        return true;
    };

    std::lock_guard<std::mutex> lock(m_mu);
    const UniValue a = ObjArg(params, 0);

    if (method == "createsubscriptionmandate") {
        SubscriptionMandate m;
        if (!MandateFromJson(a, m, err)) return fail("REJECTED", err);
        if (!m_node_network.empty() && m.network_id.Hex() != m_node_network) {
            return fail("REJECTED", "network_id");
        }
        if (m.mandate_id.empty()) m.mandate_id = RandHex(16);
        if (m_mandates.count(m.mandate_id)) return fail("REJECTED", "mandate_id");
        auto slot = std::make_unique<SubscriptionBudget>();
        if (!slot->Bind(m, err)) return fail("REJECTED", err);
        m_mandates[m.mandate_id] = m;
        m_budgets[m.mandate_id] = std::move(slot);
        if (!SaveLocked(err)) {
            m_mandates.erase(m.mandate_id);
            m_budgets.erase(m.mandate_id);
            return fail("REJECTED", err);
        }
        result = m_budgets[m.mandate_id]->StatusJson();
        result.pushKV("mandate_id", m.mandate_id);
        return ok();
    }

    if (method == "getsubscriptionmandate") {
        const std::string id = StrField(a, "mandate_id").empty() && ArgN(params, 0).isStr() ?
                                   ArgN(params, 0).get_str() :
                                   StrField(a, "mandate_id");
        auto it = m_budgets.find(id);
        if (it == m_budgets.end()) return fail("NOT_FOUND", "mandate");
        result = it->second->StatusJson();
        return ok();
    }

    if (method == "getsubscriptionactivity") {
        const std::string id = StrField(a, "mandate_id").empty() && ArgN(params, 0).isStr() ?
                                   ArgN(params, 0).get_str() :
                                   StrField(a, "mandate_id");
        if (id.empty()) return fail("INVALID_PARAMETER", "mandate_id");
        auto it = m_budgets.find(id);
        if (it == m_budgets.end()) return fail("NOT_FOUND", "mandate");
        int limit = 50;
        if (a.exists("limit")) {
            if (a["limit"].isNum()) limit = a["limit"].getInt<int>();
            else if (a["limit"].isStr()) {
                try {
                    limit = std::stoi(a["limit"].get_str());
                } catch (...) {
                    return fail("INVALID_PARAMETER", "limit");
                }
            } else {
                return fail("INVALID_PARAMETER", "limit");
            }
        }
        if (limit < 1 || limit > 100) return fail("INVALID_PARAMETER", "limit");
        const std::string cursor = StrField(a, "cursor");
        result = it->second->ActivityPage(cursor, limit);
        if (result.exists("cursor_ok") && result["cursor_ok"].isBool() && !result["cursor_ok"].get_bool()) {
            return fail("INVALID_PARAMETER", "cursor");
        }
        UniValue page(UniValue::VOBJ);
        for (const std::string& k : result.getKeys()) {
            if (k == "cursor_ok") continue;
            page.pushKV(k, result[k]);
        }
        result = std::move(page);
        return ok();
    }

    if (method == "revokesubscriptionmandate") {
        const std::string id = StrField(a, "mandate_id").empty() && ArgN(params, 0).isStr() ?
                                   ArgN(params, 0).get_str() :
                                   StrField(a, "mandate_id");
        auto it = m_budgets.find(id);
        if (it == m_budgets.end()) return fail("NOT_FOUND", "mandate");
        it->second->Revoke();
        auto mit = m_mandates.find(id);
        if (mit != m_mandates.end()) {
            mit->second.revoked = true;
            ++mit->second.revocation_counter;
        }
        // A revocation that is not on disk is a revocation that a restart undoes.
        if (!SaveLocked(err)) return fail("REJECTED", err);
        result = it->second->StatusJson();
        return ok();
    }

    if (method == "reservesubscriptionmandate") {
        const std::string id = StrField(a, "mandate_id");
        if (id.empty()) return fail("INVALID_PARAMETER", "FUND_WITH_MANDATE requires mandate_id");
        auto it = m_budgets.find(id);
        if (it == m_budgets.end()) return fail("NOT_FOUND", "mandate");
        if (!m_node_network.empty() && it->second->Mandate().network_id.Hex() != m_node_network) {
            return fail("REJECTED", "network_id");
        }
        SubscriptionEvent ev;
        if (!EventFromJson(a, ev, err)) return fail("INVALID_PARAMETER", err);
        ev.mandate_id = id;
        if (ev.action.empty()) ev.action = "FUND_WITH_MANDATE";
        SignedTerms terms;
        if (a.exists("signed_terms") && a["signed_terms"].isObject()) {
            if (!TermsFromJson(a["signed_terms"], terms, err)) return fail("INVALID_PARAMETER", err);
        } else {
            if (!TermsFromJson(a, terms, err)) return fail("INVALID_PARAMETER", err);
            if (!terms.known && a.exists("principal_atoms")) {
                terms.known = false;
            }
        }
        Reservation r;
        if (!it->second->EvaluateAndReserve(ev, terms, r, now_ms, err)) return fail("REJECTED", err);
        // Spent budget that is only in memory is spendable again after a restart.
        if (!SaveLocked(err)) return fail("REJECTED", err);
        result = ReservationToJson(r);
        result.pushKV("used_principal_atoms", std::to_string(it->second->UsedPrincipal()));
        result.pushKV("used_fee_atoms", std::to_string(it->second->UsedFees()));
        return ok();
    }

    return fail("NOT_FOUND", "method");
}

bool IsSubscriptionHelperMethod(const std::string& method)
{
    return method == "createsubscriptionmandate" || method == "getsubscriptionmandate" ||
           method == "getsubscriptionactivity" || method == "revokesubscriptionmandate" ||
           method == "reservesubscriptionmandate";
}

SubscriptionStore& GlobalSubscriptionStore()
{
    static SubscriptionStore s;
    return s;
}

bool DispatchSubscriptionRpc(const std::string& method, const UniValue& params, UniValue& result,
                             std::string& err_code, std::string& err)
{
    if (!IsSubscriptionHelperMethod(method)) return false;
    const int64_t now = static_cast<int64_t>(GetTime<std::chrono::milliseconds>().count());
    return GlobalSubscriptionStore().Dispatch(method, params, result, err_code, err, now);
}

} // namespace modelnet
