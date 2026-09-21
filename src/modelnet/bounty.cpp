// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/bounty.h>

#include <modelnet/catalog.h>
#include <modelnet/event_journal.h>
#include <modelnet/identity.h>
#include <modelnet/search.h>
#include <crypto/sha384.h>
#include <random.h>
#include <util/strencodings.h>

#include <algorithm>
#include <fstream>
#include <set>
#include <sstream>
#include <mutex>
#include <string>
#include <vector>

namespace modelnet {
namespace {

std::string RandHex(size_t nbytes)
{
    std::vector<unsigned char> b(nbytes);
    GetStrongRandBytes(Span<unsigned char>{b.data(), b.size()});
    return HexStr(b);
}

const std::set<std::string>& HelperMethods()
{
    static const std::set<std::string> k = {
        "searchbounties",
        "getmodelbounties",
        "getbounty",
        "getbountyeconomy",
        "getbountyterms",
        "getbountycapabilities",
        "createbountydraft",
        "listbountydrafts",
        "getbountydraft",
        "updatebountydraft",
        "deletebountydraft",
        "validatebountyterms",
        "publishbounty",
        "revisebounty",
        "nominatebountyevaluator",
        "acceptbountyappointment",
        "listbountyevaluators",
        "pledgebounty",
        "withdrawbountypledge",
        "freezebountyfundinground",
        "getbountyfunding",
        "commitbountysubmission",
        "revealbountysubmission",
        "getbountysubmission",
        "listbountysubmissions",
        "withdrawbountysubmission",
        "preparebountyevaluation",
        "runbountyevaluation",
        "getbountyevaluationjob",
        "cancelbountyevaluation",
        "publishbountyevaluation",
        "listbountyevaluations",
        "createbountychallenge",
        "listbountychallenges",
        "resolvebountychallenge",
        "proposebountyaward",
        "approvebountyaward",
        "getbountyaward",
        "getbountyevents",
        "watchbounty",
        "unwatchbounty",
        "getagentmandate",
        "createagentmandate",
        "revokeagentmandate",
        "getagentactivity",
        "reservemandate",
        "observebountychain",
        "reorgbountychain",
        "exportbountyrecovery",
        "importbountyrecovery",
    };
    return k;
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
    UniValue o(UniValue::VOBJ);
    return o;
}

std::string StrArg(const UniValue& params, size_t i, const std::string& key = {})
{
    const UniValue& a = ArgN(params, i);
    if (a.isStr()) return a.get_str();
    if (a.isObject() && !key.empty() && a.exists(key) && a[key].isStr()) return a[key].get_str();
    return {};
}

bool CanonicalAtomsField(const UniValue& v, int64_t& n, std::string& err)
{
    if (v.isStr()) return CanonicalAtoms(v.get_str(), n, err);
    if (v.isNum()) return CanonicalAtoms(std::to_string(v.getInt<int64_t>()), n, err);
    err = "amount_atoms";
    n = 0;
    return false;
}

/** floor(atoms * 10000 / total) without overflowing int64 inside MoneyRange. */
int64_t AtomsToBps(int64_t atoms, int64_t total)
{
    if (total <= 0 || atoms <= 0) return 0;
    if (atoms >= total) return 10000;
    const unsigned __int128 num =
        static_cast<unsigned __int128>(static_cast<uint64_t>(atoms)) * 10000u;
    const int64_t bps =
        static_cast<int64_t>(num / static_cast<unsigned __int128>(static_cast<uint64_t>(total)));
    return bps > 10000 ? 10000 : bps;
}

bool AddMoneyAtoms(int64_t& total, int64_t amount, std::string& err)
{
    if (amount < 0 || amount > MAX_MONEY_ATOMS) {
        err = "MoneyRange";
        return false;
    }
    if (total > MAX_MONEY_ATOMS - amount) {
        err = "total MoneyRange";
        return false;
    }
    total += amount;
    return true;
}

std::string IdemKey(const UniValue& params)
{
    const UniValue& a = ArgN(params, 0);
    if (a.isObject() && a.exists("idempotency_key") && a["idempotency_key"].isStr()) {
        return a["idempotency_key"].get_str();
    }
    for (size_t i = 0; i < (params.isArray() ? params.size() : 0); ++i) {
        const UniValue& p = params[i];
        if (p.isObject() && p.exists("idempotency_key") && p["idempotency_key"].isStr()) {
            return p["idempotency_key"].get_str();
        }
    }
    return {};
}

int64_t HeightField(const UniValue& o, const char* k)
{
    if (!o.exists(k)) return 0;
    if (o[k].isNum()) return o[k].getInt<int64_t>();
    if (o[k].isStr()) return std::stoll(o[k].get_str());
    return 0;
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

bool WriteJson(const fs::path& p, const UniValue& o, std::string& err)
{
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::trunc);
    if (!out) {
        err = "write " + fs::PathToString(p);
        return false;
    }
    out << o.write() << "\n";
    return true;
}

Digest48 Sha384Bytes(Span<const unsigned char> b)
{
    Digest48 id;
    CSHA384 hasher;
    hasher.Write(b.data(), b.size());
    hasher.Finalize(id.data.data());
    return id;
}

std::string LotId(const std::string& round_id, uint32_t ordinal)
{
    std::vector<unsigned char> b;
    b.insert(b.end(), round_id.begin(), round_id.end());
    b.push_back(static_cast<unsigned char>(ordinal));
    b.push_back(static_cast<unsigned char>(ordinal >> 8));
    b.push_back(static_cast<unsigned char>(ordinal >> 16));
    b.push_back(static_cast<unsigned char>(ordinal >> 24));
    return Sha384Bytes(Span<const unsigned char>{b.data(), b.size()}).Hex();
}

const std::vector<std::string> kTermsKeyOrder = {
    "terms_version",
    "network_id",
    "requester_identity",
    "title",
    "description",
    "tags",
    "deliverable_classes",
    "evaluation_spec_id",
    "submission_mode",
    "payout_authority",
    "council",
    "threshold",
    "nomination_min_bps",
    "target_atoms",
    "max_lots_per_round",
    "funding_close_height",
    "submission_close_height",
    "evaluation_close_height",
    "earliest_award_height",
    "last_safe_award_height",
    "refund_height",
    "minimum_confirmations",
    "claim_margin_blocks",
    "challenge_policy",
    "selection_rule",
    "license_statement",
    "max_model_bytes",
    "fee_policy",
    "sealed_confidentiality_disclosure",
};

const std::set<std::string> kTermsKeys(kTermsKeyOrder.begin(), kTermsKeyOrder.end());

const std::set<std::string> kDerivedAtPublish = {
    "terms_version",
    "network_id",
    "requester_identity",
};

std::vector<std::string> MissingTermsFields(const UniValue& terms)
{
    std::vector<std::string> missing;
    for (const auto& req : kTermsKeyOrder) {
        if (!terms.exists(req)) missing.push_back(req);
    }
    return missing;
}

std::vector<std::string> UnknownTermsFields(const UniValue& terms)
{
    std::vector<std::string> unknown;
    for (const std::string& k : terms.getKeys()) {
        if (!kTermsKeys.count(k)) unknown.push_back(k);
    }
    return unknown;
}

std::string TermsIdPreview(const UniValue& terms)
{
    Digest48 id;
    CSHA384 hasher;
    std::vector<unsigned char> canon;
    std::string err;
    if (CanonicalEncode(terms, canon, err)) {
        hasher.Write(canon.data(), canon.size());
    } else {
        const std::string raw = terms.write();
        hasher.Write(reinterpret_cast<const unsigned char*>(raw.data()), raw.size());
    }
    hasher.Finalize(id.data.data());
    return id.Hex();
}

void PushChecklist(UniValue& o, const UniValue& terms)
{
    struct Section {
        const char* name;
        std::vector<const char*> keys;
        const char* note;
    };
    const Section sections[] = {
        {"overview", {"title"}, nullptr},
        {"description", {"description", "tags", "deliverable_classes", "license_statement"}, nullptr},
        {"evaluation", {"evaluation_spec_id", "submission_mode", "challenge_policy", "selection_rule", "max_model_bytes", "sealed_confidentiality_disclosure"}, nullptr},
        {"money_terms", {"target_atoms", "fee_policy", "payout_authority", "max_lots_per_round", "nomination_min_bps"}, "declared goal, not funding; automatic_spend_atoms=0"},
        {"council", {"council", "threshold"}, "operator-supplied ML-DSA-44 keys only; never synthesized"},
        {"timeline", {"funding_close_height", "submission_close_height", "evaluation_close_height", "earliest_award_height", "last_safe_award_height", "refund_height", "minimum_confirmations", "claim_margin_blocks"}, "Gitcoin milestone analog: ordered heights, not payout tranches"},
    };
    UniValue checklist(UniValue::VOBJ);
    for (const auto& sec : sections) {
        UniValue s(UniValue::VOBJ);
        UniValue missing(UniValue::VARR);
        for (const char* k : sec.keys) {
            if (!terms.exists(k)) missing.push_back(k);
        }
        s.pushKV("ok", missing.empty());
        s.pushKV("missing", missing);
        if (sec.note) s.pushKV("note", sec.note);
        checklist.pushKV(sec.name, s);
    }
    o.pushKV("checklist", checklist);
}

void PushDraftCompleteness(UniValue& o, const UniValue& terms, bool complete)
{
    const auto missing = MissingTermsFields(terms);
    UniValue miss(UniValue::VARR);
    UniValue user_miss(UniValue::VARR);
    for (const auto& f : missing) {
        miss.push_back(f);
        if (!kDerivedAtPublish.count(f)) user_miss.push_back(f);
    }
    UniValue derived(UniValue::VARR);
    derived.push_back("terms_version");
    derived.push_back("network_id");
    derived.push_back("requester_identity");
    UniValue unknown(UniValue::VARR);
    for (const auto& f : UnknownTermsFields(terms)) unknown.push_back(f);
    o.pushKV("missing_fields", miss);
    o.pushKV("missing_count", static_cast<int>(miss.size()));
    o.pushKV("user_missing_fields", user_miss);
    o.pushKV("user_missing_count", static_cast<int>(user_miss.size()));
    o.pushKV("required_count", static_cast<int>(kTermsKeyOrder.size()));
    o.pushKV("derived_at_publish", derived);
    o.pushKV("unknown_fields", unknown);
    PushChecklist(o, terms);
    const std::string preview = TermsIdPreview(terms);
    if (!preview.empty()) o.pushKV("terms_id_preview", preview);
    o.pushKV("automatic_spend_atoms", 0);
    if (complete) o.pushKV("one_liner", "publishbounty is wallet-plane; automatic_spend_atoms stays 0");
    else if (user_miss.size() > 0 && user_miss[0].isStr()) o.pushKV("one_liner", "fill missing field: " + user_miss[0].get_str());
    else if (miss.size() > 0) o.pushKV("one_liner", "ready to publish; remaining fields stamped at publish");
    else if (unknown.size() > 0) o.pushKV("one_liner", "drop unknown fields before publish");
    else o.pushKV("one_liner", "incomplete draft stays local");
}

UniValue BountyNextActions(bool complete, bool published)
{
    UniValue a(UniValue::VARR);
    if (!complete) {
        a.push_back("fill remaining BountyTerms fields; council and heights are required to publish");
        a.push_back("validatebountyterms");
    } else if (!published) {
        a.push_back("publishbounty {\"draft_id\":\"...\"}  # research identity; does not spend");
    } else {
        a.push_back("preparebountyfunding  # wallet plane; never automatic");
    }
    a.push_back("automatic_spend_atoms stays 0");
    return a;
}

} // namespace

bool ValidateTimeline(int64_t funding, int64_t submission, int64_t evaluation, int64_t award,
                      int64_t last_safe, int64_t refund, int confirmations, int margin, std::string& err)
{
    const int64_t vals[] = {funding, submission, evaluation, award, last_safe, refund};
    for (int64_t v : vals) {
        if (v < 1 || v > BOUNTY_MAX_HEIGHT) {
            err = "height range";
            return false;
        }
    }
    if (!(funding < submission && submission < evaluation && evaluation <= award && award <= last_safe &&
          last_safe < refund)) {
        err = "timeline ordering";
        return false;
    }
    if (confirmations < 1 || margin < 1 || last_safe + confirmations + margin >= refund) {
        err = "claim margin";
        return false;
    }
    return true;
}

bool ValidateCouncil(const UniValue& council, int threshold, std::string& err)
{
    if (!council.isArray()) {
        err = "council";
        return false;
    }
    const int n = static_cast<int>(council.size());
    if (n < 1 || n > BOUNTY_COUNCIL_MAX) {
        err = "council size/threshold";
        return false;
    }
    if (threshold < 1 || threshold > n) {
        err = "council size/threshold";
        return false;
    }
    std::set<std::string> keys;
    for (const auto& m : council.getValues()) {
        if (!m.isObject() || !m.exists("public_key_hex")) {
            err = "council key";
            return false;
        }
        const std::string k = ToLower(m["public_key_hex"].get_str());
        if (!keys.insert(k).second) {
            err = "duplicate council key";
            return false;
        }
        if (k.size() != 2624 || !IsHex(k)) {
            err = "council key must be ML-DSA-44 hex";
            return false;
        }
    }
    return true;
}

bool ValidateBountyTerms(const UniValue& terms, const NetworkId& network, std::string& err)
{
    if (!terms.isObject()) {
        err = "terms object";
        return false;
    }
    std::map<std::string, UniValue> kv;
    terms.getObjMap(kv);
    for (const auto& e : kv) {
        if (!kTermsKeys.count(e.first)) {
            err = "unknown fields";
            return false;
        }
    }
    for (const auto& req : kTermsKeys) {
        if (!terms.exists(req)) {
            err = "missing " + req;
            return false;
        }
    }
    if (terms["terms_version"].getInt<int>() != 1) {
        err = "terms_version";
        return false;
    }
    NetworkId nid;
    if (!NetworkId::FromHex(terms["network_id"].get_str(), nid, err)) return false;
    if (nid.data != network.data) {
        err = "wrong network";
        return false;
    }
    if (terms["title"].get_str().empty() || terms["title"].get_str().size() > 160) {
        err = "title";
        return false;
    }
    if (terms["description"].get_str().size() > 1024) {
        err = "description";
        return false;
    }
    int64_t target = 0;
    if (!CanonicalAtoms(terms["target_atoms"].get_str(), target, err) || target <= 0) {
        err = err.empty() ? "positive target required" : err;
        return false;
    }
    const int threshold = terms["threshold"].getInt<int>();
    if (!ValidateCouncil(terms["council"], threshold, err)) return false;
    const int lots = terms["max_lots_per_round"].getInt<int>();
    if (lots < 1 || lots > BOUNTY_LOTS_MAX) {
        err = "max_lots_per_round";
        return false;
    }
    const std::string mode = terms["submission_mode"].get_str();
    if (mode != "PUBLIC" && mode != "SEALED_REVIEW_TRUSTED") {
        err = "submission_mode";
        return false;
    }
    if (mode == "SEALED_REVIEW_TRUSTED" && terms["sealed_confidentiality_disclosure"].get_str().empty()) {
        err = "sealed fields required";
        return false;
    }
    return ValidateTimeline(HeightField(terms, "funding_close_height"), HeightField(terms, "submission_close_height"),
                            HeightField(terms, "evaluation_close_height"), HeightField(terms, "earliest_award_height"),
                            HeightField(terms, "last_safe_award_height"), HeightField(terms, "refund_height"),
                            terms["minimum_confirmations"].getInt<int>(), terms["claim_margin_blocks"].getInt<int>(),
                            err);
}

UniValue FundingView(const std::string& target, const std::string& pledged, const UniValue& confirmed)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("target_atoms", target);
    o.pushKV("pledged_atoms", pledged);
    int64_t t = 0;
    std::string err;
    if (!CanonicalAtoms(target, t, err)) t = 0;
    if (confirmed.isNull()) {
        o.pushKV("confirmed_atoms", UniValue::VNULL);
        o.pushKV("remaining_atoms", UniValue::VNULL);
        o.pushKV("funding_progress_known", false);
        o.pushKV("funded_bps", UniValue::VNULL);
        return o;
    }
    const std::string cs = confirmed.isStr() ? confirmed.get_str() : std::to_string(confirmed.getInt<int64_t>());
    int64_t c = 0;
    if (!CanonicalAtoms(cs, c, err)) {
        o.pushKV("confirmed_atoms", UniValue::VNULL);
        o.pushKV("remaining_atoms", UniValue::VNULL);
        o.pushKV("funding_progress_known", false);
        o.pushKV("funded_bps", UniValue::VNULL);
        return o;
    }
    o.pushKV("confirmed_atoms", cs);
    o.pushKV("remaining_atoms", std::to_string(std::max<int64_t>(0, t - c)));
    o.pushKV("funding_progress_known", true);
    o.pushKV("funded_bps", AtomsToBps(c, t));
    return o;
}

bool EligibleBps(const std::string& principal, const std::string& frozen_total, int min_bps, std::string& err)
{
    int64_t p = 0, t = 0;
    if (!CanonicalAtoms(principal, p, err) || !CanonicalAtoms(frozen_total, t, err)) return false;
    if (t <= 0 || p > t || min_bps < 0 || min_bps > 10000) {
        err = "eligibility range";
        return false;
    }
    const unsigned __int128 lhs =
        static_cast<unsigned __int128>(static_cast<uint64_t>(p)) * 10000u;
    const unsigned __int128 rhs = static_cast<unsigned __int128>(static_cast<uint64_t>(t)) *
                                  static_cast<unsigned __int128>(static_cast<uint32_t>(min_bps));
    return lhs >= rhs;
}

bool AllocateFeeReserve(const std::vector<int64_t>& reserves, int64_t fee, std::vector<int64_t>& charges,
                        std::vector<int64_t>& remaining, std::string& err)
{
    if (fee < 0) {
        err = "reserve exceeded";
        return false;
    }
    int64_t total = 0;
    for (int64_t x : reserves) {
        if (x < 0) {
            err = "reserve exceeded";
            return false;
        }
        total += x;
    }
    if (fee > total) {
        err = "reserve exceeded";
        return false;
    }
    charges.assign(reserves.size(), 0);
    remaining = reserves;
    if (total == 0) return true;
    int64_t sum = 0;
    for (size_t i = 0; i < reserves.size(); ++i) {
        charges[i] = fee * reserves[i] / total;
        sum += charges[i];
    }
    int64_t left = fee - sum;
    std::vector<size_t> order(reserves.size());
    for (size_t i = 0; i < order.size(); ++i) order[i] = i;
    std::sort(order.begin(), order.end(), [&](size_t a, size_t b) {
        const int64_t ra = fee * reserves[a] % total;
        const int64_t rb = fee * reserves[b] % total;
        if (ra != rb) return ra > rb;
        return a < b;
    });
    for (size_t i = 0; i < static_cast<size_t>(left) && i < order.size(); ++i) charges[order[i]] += 1;
    for (size_t i = 0; i < reserves.size(); ++i) remaining[i] = reserves[i] - charges[i];
    return true;
}

int64_t DedupePrincipal(const std::vector<std::pair<std::string, int64_t>>& lots, std::string& err)
{
    std::map<std::string, int64_t> values;
    for (const auto& [op, amount] : lots) {
        if (amount < 0 || amount > MAX_MONEY_ATOMS) {
            err = "MoneyRange";
            return -1;
        }
        auto it = values.find(op);
        if (it != values.end() && it->second != amount) {
            err = "conflicting outpoint amount";
            return -1;
        }
        values[op] = amount;
    }
    int64_t total = 0;
    for (const auto& kv : values) {
        if (!AddMoneyAtoms(total, kv.second, err)) return -1;
    }
    return total;
}

bool BuildSignedEnvelope(const std::string& record_type, const NetworkId& network, Span<const unsigned char> pk,
                         Span<const unsigned char> sk, const UniValue& payload, const UniValue& delegation_id,
                         SignedEnvelope& out, std::string& err)
{
    if (pk.size() != MLDSA44_PK) {
        err = "pubkey";
        return false;
    }
    UniValue body(UniValue::VOBJ);
    body.pushKV("envelope_version", 1);
    body.pushKV("record_type", record_type);
    body.pushKV("network_id", network.Hex());
    body.pushKV("signer_id", ResearchIdentityId(pk).Hex());
    body.pushKV("public_key_hex", HexStr(pk));
    body.pushKV("delegation_id", delegation_id);
    body.pushKV("payload", payload);
    std::vector<unsigned char> pre;
    if (!EnvelopePreimage(body, pre, err)) return false;
    Digest48 id;
    if (!EnvelopeDigest(body, id, err)) return false;
    std::vector<unsigned char> sig;
    if (!SignMlDsa44(sk, Span<const unsigned char>{id.data.data(), id.data.size()}, sig, err)) return false;
    out.body = body;
    out.signature = std::move(sig);
    out.record_id = id;
    out.verified = true;
    return true;
}

bool VerifySignedEnvelope(const SignedEnvelope& env, const NetworkId& expected_network, std::string& err)
{
    if (!env.body.isObject()) {
        err = "body";
        return false;
    }
    if (env.body.exists("signed_ok")) {
        err = "unknown fields";
        return false;
    }
    NetworkId nid;
    if (!EnvelopeNetworkId(env.body, nid, err)) return false;
    if (nid.data != expected_network.data) {
        err = "wrong network";
        return false;
    }
    Digest48 id;
    if (!EnvelopeDigest(env.body, id, err)) return false;
    if (!env.record_id.IsNull() && id != env.record_id) {
        err = "record id";
        return false;
    }
    if (!env.body.exists("public_key_hex") || !env.body["public_key_hex"].isStr()) {
        err = "pubkey";
        return false;
    }
    const auto pk = ParseHex(env.body["public_key_hex"].get_str());
    const Digest48 sid = ResearchIdentityId(Span<const unsigned char>{pk.data(), pk.size()});
    if (!env.body.exists("signer_id") || sid.Hex() != env.body["signer_id"].get_str()) {
        err = "wrong signer";
        return false;
    }
    if (env.signature.empty()) {
        err = "unsigned";
        return false;
    }
    Digest48 msg = id;
    if (!VerifyMlDsa44(Span<const unsigned char>{pk.data(), pk.size()},
                       Span<const unsigned char>{id.data.data(), id.data.size()},
                       Span<const unsigned char>{env.signature.data(), env.signature.size()})) {
        err = "bad signature";
        return false;
    }
    (void)msg;
    return true;
}

bool EnvelopeFromJson(const UniValue& o, SignedEnvelope& env, std::string& err)
{
    env = {};
    if (!o.isObject() || !o.exists("body")) {
        err = "envelope";
        return false;
    }
    env.body = o["body"];
    if (o.exists("signature")) env.signature = ParseHex(o["signature"].get_str());
    if (o.exists("record_id") && o["record_id"].isStr()) {
        if (!Digest48::FromHex(o["record_id"].get_str(), env.record_id, err)) return false;
    } else if (!EnvelopeDigest(env.body, env.record_id, err)) {
        return false;
    }
    env.verified = false;
    return true;
}

UniValue EnvelopeToJson(const SignedEnvelope& env)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("record_id", env.record_id.Hex());
    o.pushKV("body", env.body);
    o.pushKV("signature", HexStr(env.signature));
    o.pushKV("verified", env.verified);
    return o;
}

void MandateBudget::Reset(int64_t total, int64_t per_action)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_total = total;
    m_per_action = per_action;
    m_used = 0;
    m_revoked = false;
    m_req.clear();
}

bool MandateBudget::Reserve(const std::string& key, int64_t amount, std::string& err)
{
    return Reserve(key, amount, {}, err);
}

bool MandateBudget::Reserve(const std::string& key, int64_t amount, const std::string& refund_key, std::string& err)
{
    std::lock_guard<std::mutex> lock(m_mu);
    auto it = m_req.find(key);
    if (it != m_req.end()) {
        if (it->second.first != amount) {
            err = "idempotency conflict";
            return false;
        }
        if (!refund_key.empty() && !it->second.second.empty() && it->second.second != refund_key) {
            err = "refund key substitution";
            return false;
        }
        return true;
    }
    if (m_revoked) {
        err = "revoked";
        return false;
    }
    if (amount <= 0 || amount > m_per_action || m_used + amount > m_total) {
        err = "budget exhausted";
        return false;
    }
    m_req[key] = {amount, refund_key};
    m_used += amount;
    return true;
}

void MandateBudget::Revoke()
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_revoked = true;
}

bool MandateBudget::Revoked() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_revoked;
}

int64_t MandateBudget::Used() const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return m_used;
}

void BountyChainIndex::Observe(const BountyChainFact& f)
{
    m_undo.push_back(m_facts);
    m_facts[f.outpoint] = f;
    if (f.height > m_height) m_height = f.height;
    ++m_epoch;
}

void BountyChainIndex::DisconnectTip()
{
    if (!m_undo.empty()) {
        m_facts = m_undo.back();
        m_undo.pop_back();
        ++m_epoch;
    }
}

const BountyChainFact* BountyChainIndex::Get(const std::string& outpoint) const
{
    auto it = m_facts.find(outpoint);
    return it == m_facts.end() ? nullptr : &it->second;
}

int64_t BountyChainIndex::ConfirmedAtoms(const std::string& bounty_id) const
{
    int64_t n = 0;
    for (const auto& kv : m_facts) {
        if (kv.second.bounty_id != bounty_id || kv.second.spent) continue;
        const int64_t a = kv.second.amount_atoms;
        if (a < 0 || a > MAX_MONEY_ATOMS) continue;
        std::string err;
        if (!AddMoneyAtoms(n, a, err)) return MAX_MONEY_ATOMS;
    }
    return n;
}

UniValue BountyChainIndex::Snapshot(const std::string& bounty_id) const
{
    UniValue arr(UniValue::VARR);
    for (const auto& kv : m_facts) {
        if (!bounty_id.empty() && kv.second.bounty_id != bounty_id) continue;
        UniValue o(UniValue::VOBJ);
        o.pushKV("outpoint", kv.second.outpoint);
        o.pushKV("amount_atoms", std::to_string(kv.second.amount_atoms));
        o.pushKV("confirmations", kv.second.confirmations);
        o.pushKV("height", static_cast<int64_t>(kv.second.height));
        o.pushKV("spent", kv.second.spent);
        o.pushKV("lot_id", kv.second.lot_id);
        arr.push_back(o);
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("epoch", static_cast<int64_t>(m_epoch));
    o.pushKV("height", static_cast<int64_t>(m_height));
    o.pushKV("facts", arr);
    if (bounty_id.empty()) {
        o.pushKV("confirmed_atoms", UniValue());
    } else {
        o.pushKV("confirmed_atoms", std::to_string(ConfirmedAtoms(bounty_id)));
    }
    o.pushKV("completeness", "local_watch_only");
    return o;
}

UniValue BountyChainIndex::ExportRecovery(const std::string& bounty_id, const std::vector<std::string>& lot_ids) const
{
    UniValue lots(UniValue::VARR);
    for (const auto& kv : m_facts) {
        if (kv.second.bounty_id != bounty_id) continue;
        if (!lot_ids.empty() && std::find(lot_ids.begin(), lot_ids.end(), kv.second.lot_id) == lot_ids.end()) continue;
        UniValue o(UniValue::VOBJ);
        o.pushKV("lot_id", kv.second.lot_id);
        o.pushKV("outpoint", kv.second.outpoint);
        o.pushKV("amount_atoms", std::to_string(kv.second.amount_atoms));
        o.pushKV("wallet_seed", false);
        o.pushKV("private_keys", false);
        lots.push_back(o);
    }
    UniValue o(UniValue::VOBJ);
    o.pushKV("bounty_id", bounty_id);
    o.pushKV("lots", lots);
    o.pushKV("secrets", false);
    o.pushKV("private_keys", false);
    o.pushKV("wallet_seed", false);
    return o;
}

bool BountyChainIndex::ImportManifest(const UniValue& manifest, std::string& err)
{
    if (!manifest.isObject() || !manifest.exists("lots") || !manifest["lots"].isArray()) {
        err = "manifest";
        return false;
    }
    if (manifest.exists("path") || manifest.exists("host_path")) {
        err = "manifest object only, not a host path";
        return false;
    }
    std::vector<BountyChainFact> facts;
    std::vector<std::pair<std::string, int64_t>> lots;
    for (const auto& lot : manifest["lots"].getValues()) {
        if (!lot.isObject() || !lot.exists("outpoint")) continue;
        BountyChainFact f;
        f.outpoint = lot["outpoint"].get_str();
        f.lot_id = lot.exists("lot_id") ? lot["lot_id"].get_str() : "";
        f.bounty_id = manifest.exists("bounty_id") ? manifest["bounty_id"].get_str() : "";
        if (lot.exists("amount_atoms")) {
            if (!CanonicalAtomsField(lot["amount_atoms"], f.amount_atoms, err)) return false;
        }
        facts.push_back(f);
        lots.emplace_back(f.outpoint, f.amount_atoms);
    }
    if (DedupePrincipal(lots, err) < 0) return false;
    for (const auto& f : facts) Observe(f);
    return true;
}

void BountyStore::Bind(const fs::path& dir, const NetworkId& network)
{
    std::lock_guard<std::mutex> lock(m_mu);
    m_dir = dir;
    m_network = network;
    std::string err;
    Load(err);
}

bool BountyStore::Load(std::string& err)
{
    UniValue o;
    if (!ReadJson(m_dir / "bounty-store.json", o) || !o.isObject()) return true;
    if (o.exists("epoch")) m_epoch = o["epoch"].getInt<int64_t>();
    if (o.exists("seq")) m_seq = o["seq"].getInt<int64_t>();
    auto load_map = [&](const char* k, auto& dst) {
        if (!o.exists(k) || !o[k].isObject()) return;
        for (const auto& key : o[k].getKeys()) dst[key] = o[k][key];
    };
    load_map("drafts", m_drafts);
    load_map("bounties", m_bounties);
    load_map("rounds", m_rounds);
    load_map("submissions", m_submissions);
    load_map("eval_jobs", m_eval_jobs);
    load_map("awards", m_awards);
    load_map("watches", m_watches);
    load_map("mandates", m_mandates);
    if (o.exists("terms") && o["terms"].isObject()) {
        for (const auto& key : o["terms"].getKeys()) {
            SignedEnvelope env;
            if (EnvelopeFromJson(o["terms"][key], env, err)) m_terms[key] = env;
        }
    }
    return true;
}

bool BountyStore::PersistLocked(std::string& err) const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("seq", static_cast<int64_t>(m_seq));
    o.pushKV("epoch", static_cast<int64_t>(m_epoch));
    auto dump = [&](const char* k, const auto& m) {
        UniValue x(UniValue::VOBJ);
        for (const auto& kv : m) x.pushKV(kv.first, kv.second);
        o.pushKV(k, x);
    };
    dump("drafts", m_drafts);
    dump("bounties", m_bounties);
    dump("rounds", m_rounds);
    dump("submissions", m_submissions);
    dump("eval_jobs", m_eval_jobs);
    dump("awards", m_awards);
    dump("watches", m_watches);
    dump("mandates", m_mandates);
    UniValue terms(UniValue::VOBJ);
    for (const auto& kv : m_terms) terms.pushKV(kv.first, EnvelopeToJson(kv.second));
    o.pushKV("terms", terms);
    return WriteJson(m_dir / "bounty-store.json", o, err);
}

bool BountyStore::Save(std::string& err) const
{
    std::lock_guard<std::mutex> lock(m_mu);
    return PersistLocked(err);
}

bool BountyStore::LoadIdentity(std::vector<unsigned char>& pk, std::vector<unsigned char>& sk, Digest48& id,
                              std::string& err)
{
    UniValue store;
    ReadJson(m_dir / "research_identity.json", store);
    if (store.exists("pk_hex") && store.exists("sk_hex")) {
        pk = ParseHex(store["pk_hex"].get_str());
        sk = ParseHex(store["sk_hex"].get_str());
        if (pk.size() == MLDSA44_PK && sk.size() == MLDSA44_SK) {
            id = ResearchIdentityId(pk);
            return true;
        }
    }
    if (!GenerateMlDsa44(pk, sk, err)) return false;
    id = ResearchIdentityId(pk);
    store.setObject();
    store.pushKV("pk_hex", HexStr(pk));
    store.pushKV("sk_hex", HexStr(sk));
    return WriteJson(m_dir / "research_identity.json", store, err);
}

bool BountyStore::Idem(const std::string& method, const std::string& key, UniValue& out) const
{
    if (key.empty()) return false;
    auto it = m_idem.find(method + "|" + key);
    if (it == m_idem.end()) return false;
    out = it->second;
    return true;
}

void BountyStore::Remember(const std::string& method, const std::string& key, const UniValue& result)
{
    if (!key.empty()) m_idem[method + "|" + key] = result;
}

UniValue BountyStore::Event(const std::string& kind, const std::string& bounty_id, const UniValue& payload)
{
    UniValue e(UniValue::VOBJ);
    e.pushKV("event_id", RandHex(16));
    e.pushKV("kind", kind);
    e.pushKV("bounty_id", bounty_id);
    e.pushKV("seq", static_cast<int64_t>(++m_seq));
    e.pushKV("epoch", static_cast<int64_t>(m_epoch));
    e.pushKV("payload", payload);
    e.pushKV("authority", "local_signed_or_chain");
    m_events.push_back(e);
    if (BoundModelEventJournal()) {
        ObserveResult ores;
        std::string jerr;
        (void)JournalObserveBounty(e, ores, jerr);
    }
    return e;
}

UniValue BountyStore::BountyEntryLocked(const std::string& bounty_id) const
{
    UniValue o(UniValue::VOBJ);
    auto it = m_bounties.find(bounty_id);
    if (it == m_bounties.end()) return o;
    o = it->second;
    auto tit = m_terms.find(bounty_id);
    if (tit != m_terms.end()) {
        o.pushKV("terms", tit->second.body.exists("payload") ? tit->second.body["payload"] : UniValue::VOBJ);
        o.pushKV("terms_id", tit->second.record_id.Hex());
        o.pushKV("verified", tit->second.verified);
    }
    std::string pledged = "0";
    int64_t psum = 0;
    std::string err;
    for (const auto& kv : m_pledges) {
        if (!kv.second.body.exists("payload")) continue;
        const UniValue& p = kv.second.body["payload"];
        if (p.exists("bounty_id") && p["bounty_id"].get_str() == bounty_id && p.exists("principal_atoms")) {
            int64_t n = 0;
            if (CanonicalAtoms(p["principal_atoms"].get_str(), n, err)) {
                if (!AddMoneyAtoms(psum, n, err)) psum = MAX_MONEY_ATOMS;
            }
        }
    }
    pledged = std::to_string(psum);
    const int64_t confirmed = m_chain.ConfirmedAtoms(bounty_id);
    const UniValue conf = confirmed > 0 ? UniValue(std::to_string(confirmed)) : UniValue(UniValue::VNULL);
    std::string target = "1";
    if (o.exists("target_atoms")) target = o["target_atoms"].get_str();
    o.pushKV("economy", FundingView(target, pledged, confirmed > 0 ? UniValue(std::to_string(confirmed)) : UniValue(UniValue::VNULL)));
    o.pushKV("chain", m_chain.Snapshot(bounty_id));
    o.pushKV("trust_label", BOUNTY_TRUST_LABEL);
    o.pushKV("wallet", false);
    return o;
}

UniValue BountyStore::Capabilities() const
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 1);
    o.pushKV("trust_label", BOUNTY_TRUST_LABEL);
    UniValue rec(UniValue::VARR);
    for (const char* t : {"BountyTerms", "EvaluationSpec", "FundingRound", "Submission", "EvaluationReport",
                           "AwardProposal", "ModelSearchRecordV2", "CouncilAppointment", "SubmissionCommitment",
                           "AcceptanceCertificate", "Challenge", "AwardPolicyApproval"}) {
        rec.push_back(t);
    }
    o.pushKV("record_types", rec);
    UniValue profiles(UniValue::VARR);
    UniValue exact(UniValue::VOBJ);
    exact.pushKV("id", "EXACT_CHECKS");
    exact.pushKV("ready", true);
    profiles.push_back(exact);
    auto maybe = [&](const char* id) {
        UniValue p(UniValue::VOBJ);
        p.pushKV("id", id);
        p.pushKV("ready", EvaluationProfileReady(id));
        profiles.push_back(p);
    };
    maybe("REPRODUCIBLE_BENCHMARK");
    maybe("STATISTICAL_BENCHMARK");
    maybe("REVIEWED_RESEARCH");
    o.pushKV("evaluation_profiles", profiles);
    o.pushKV("script_profile", "mr(cltv_multi_pq,refund) and mr(htlc_sha256,refund)");
    o.pushKV("n_max", BOUNTY_COUNCIL_MAX);
    o.pushKV("height_max", BOUNTY_MAX_HEIGHT);
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("unexecuted_profiles_advertised", false);
    UniValue helper_rpcs(UniValue::VARR);
    for (const auto& n : HelperMethods()) helper_rpcs.push_back(n);
    o.pushKV("helper_rpcs", helper_rpcs);
    UniValue wallet_rpcs(UniValue::VARR);
    for (const char* n : {"preparebountyfunding", "inspectbountytransaction", "signbountyfunding", "submitbountyfunding",
                           "inspectbountyaward", "signbountyaward", "submitbountyaward", "preparebountyclaim",
                           "signbountyclaim", "submitbountyclaim", "preparebountyrefund", "signbountyrefund",
                           "submitbountyrefund"}) {
        wallet_rpcs.push_back(n);
    }
    o.pushKV("wallet_rpcs", wallet_rpcs);
    o.pushKV("wallet_on_helper", false);
    o.pushKV("public_http_wallet", false);
    return o;
}

bool BountyStore::Dispatch(const std::string& method, const UniValue& params, UniValue& result, std::string& err_code,
                          std::string& err)
{
    std::unique_lock<std::mutex> lock(m_mu);
    const std::string idem = IdemKey(params);
    const bool skip_idem = (method == "reservemandate");
    if (!skip_idem && Idem(method, idem, result)) return true;

    auto fail = [&](const char* code, const std::string& e) {
        err_code = code;
        err = e;
        return false;
    };
    auto ok = [&]() {
        Remember(method, idem, result);
        PersistLocked(err);
        return true;
    };

    if (method == "getbountycapabilities") {
        result = Capabilities();
        return true;
    }

    if (method == "createbountydraft") {
        UniValue terms = ObjArg(params, 0);
        if (terms.exists("terms")) terms = terms["terms"];
        const bool complete = ValidateBountyTerms(terms, m_network, err);
        if (!complete) {
            if (!terms.exists("title") || !terms["title"].isStr() || terms["title"].get_str().empty()) {
                return fail("INVALID_PARAMETER", err.empty() ? "title required" : err);
            }
            err.clear();
            err_code.clear();
        }
        const std::string id = RandHex(16);
        m_drafts[id] = terms;
        result.setObject();
        result.pushKV("draft_id", id);
        result.pushKV("copy_text", "draft_id=" + id);
        result.pushKV("local_only", true);
        result.pushKV("published", false);
        result.pushKV("recipe_complete", complete);
        result.pushKV("next_actions", BountyNextActions(complete, false));
        PushDraftCompleteness(result, terms, complete);
        Event("draft", id, terms);
        return ok();
    }

    if (method == "listbountydrafts") {
        result.setObject();
        UniValue arr(UniValue::VARR);
        bool all_complete = !m_drafts.empty();
        std::string first_one_liner;
        for (const auto& kv : m_drafts) {
            UniValue o(UniValue::VOBJ);
            o.pushKV("draft_id", kv.first);
            o.pushKV("copy_text", "draft_id=" + kv.first);
            o.pushKV("title", kv.second.exists("title") ? kv.second["title"] : "");
            const bool complete = ValidateBountyTerms(kv.second, m_network, err);
            err.clear();
            err_code.clear();
            o.pushKV("recipe_complete", complete);
            o.pushKV("next_actions", BountyNextActions(complete, false));
            PushDraftCompleteness(o, kv.second, complete);
            if (!complete) all_complete = false;
            if (first_one_liner.empty() && o.exists("one_liner") && o["one_liner"].isStr()) {
                first_one_liner = o["one_liner"].get_str();
            }
            arr.push_back(o);
        }
        result.pushKV("drafts", arr);
        result.pushKV("count", static_cast<int>(arr.size()));
        result.pushKV("next_actions", arr.empty() ? [] {
            UniValue a(UniValue::VARR);
            a.push_back("createbountydraft");
            a.push_back("automatic_spend_atoms stays 0");
            return a;
        }() : BountyNextActions(all_complete, false));
        result.pushKV("automatic_spend_atoms", 0);
        if (arr.empty()) result.pushKV("one_liner", "no local drafts");
        else if (arr.size() == 1) result.pushKV("one_liner", first_one_liner);
        else result.pushKV("one_liner", std::to_string(arr.size()) + " local drafts; " + first_one_liner);
        return true;
    }

    if (method == "getbountydraft") {
        const std::string id = StrArg(params, 0, "draft_id");
        auto it = m_drafts.find(id);
        if (it == m_drafts.end()) return fail("NOT_FOUND", "draft");
        result.setObject();
        result.pushKV("draft_id", id);
        result.pushKV("copy_text", "draft_id=" + id);
        result.pushKV("terms", it->second);
        const bool complete = ValidateBountyTerms(it->second, m_network, err);
        err.clear();
        err_code.clear();
        result.pushKV("recipe_complete", complete);
        result.pushKV("next_actions", BountyNextActions(complete, false));
        PushDraftCompleteness(result, it->second, complete);
        return true;
    }

    if (method == "updatebountydraft") {
        std::string id = StrArg(params, 0, "draft_id");
        UniValue patch = ObjArg(params, 1);
        if (ArgN(params, 0).isObject() && patch.empty()) {
            patch = ArgN(params, 0);
        }
        if (id.empty() && patch.exists("draft_id") && patch["draft_id"].isStr()) {
            id = patch["draft_id"].get_str();
        }
        if (patch.exists("terms") && patch["terms"].isObject()) patch = patch["terms"];
        auto it = m_drafts.find(id);
        if (it == m_drafts.end()) return fail("NOT_FOUND", "draft");
        UniValue merged(UniValue::VOBJ);
        std::set<std::string> overlay;
        for (const std::string& k : patch.getKeys()) {
            if (k == "draft_id") continue;
            merged.pushKV(k, patch[k]);
            overlay.insert(k);
        }
        for (const std::string& k : it->second.getKeys()) {
            if (overlay.count(k)) continue;
            merged.pushKV(k, it->second[k]);
        }
        it->second = merged;
        const bool complete = ValidateBountyTerms(it->second, m_network, err);
        err.clear();
        err_code.clear();
        result.setObject();
        result.pushKV("draft_id", id);
        result.pushKV("copy_text", "draft_id=" + id);
        result.pushKV("terms", it->second);
        result.pushKV("local_only", true);
        result.pushKV("published", false);
        result.pushKV("recipe_complete", complete);
        result.pushKV("next_actions", BountyNextActions(complete, false));
        PushDraftCompleteness(result, it->second, complete);
        Event("draft", id, it->second);
        return ok();
    }

    if (method == "deletebountydraft") {
        const std::string id = StrArg(params, 0, "draft_id");
        if (m_drafts.erase(id) == 0) return fail("NOT_FOUND", "draft");
        result.setObject();
        result.pushKV("draft_id", id);
        result.pushKV("deleted", true);
        result.pushKV("local_only", true);
        result.pushKV("automatic_spend_atoms", 0);
        result.pushKV("one_liner", "draft deleted; still local, never spent");
        UniValue next(UniValue::VARR);
        next.push_back("listbountydrafts");
        next.push_back("automatic_spend_atoms stays 0");
        result.pushKV("next_actions", next);
        return ok();
    }

    if (method == "validatebountyterms") {
        UniValue terms = ObjArg(params, 0);
        if (terms.exists("terms")) terms = terms["terms"];
        result.setObject();
        const bool ok_terms = ValidateBountyTerms(terms, m_network, err);
        result.pushKV("ok", ok_terms);
        result.pushKV("error", err);
        result.pushKV("recipe_complete", ok_terms);
        result.pushKV("next_actions", BountyNextActions(ok_terms, false));
        PushDraftCompleteness(result, terms, ok_terms);
        err.clear();
        err_code.clear();
        return true;
    }

    auto sign_terms = [&](const UniValue& terms, SignedEnvelope& env) -> bool {
        std::vector<unsigned char> pk, sk;
        Digest48 id;
        if (!LoadIdentity(pk, sk, id, err)) return false;
        if (terms.exists("requester_identity") && terms["requester_identity"].isStr()) {
            const std::string want = terms["requester_identity"].get_str();
            if (!want.empty() && want != id.Hex()) {
                err = "issuer mismatch";
                return false;
            }
        }
        UniValue payload = terms;
        payload.pushKV("requester_identity", id.Hex());
        payload.pushKV("network_id", m_network.Hex());
        UniValue del;
        del.setNull();
        return BuildSignedEnvelope("BountyTerms", m_network, pk, sk, payload, del, env, err);
    };

    if (method == "publishbounty") {
        const UniValue a = ObjArg(params, 0);
        const std::string draft_id = a.exists("draft_id") ? a["draft_id"].get_str() : StrArg(params, 0);
        auto it = m_drafts.find(draft_id);
        if (it == m_drafts.end()) return fail("NOT_FOUND", "draft");
        // Gitcoin-comparable gate: an incomplete draft may be saved, but it must
        // never be signed or published. Re-validate here (createbountydraft allows
        // title-only drafts) so a partial checklist can never reach the chain view.
        if (!ValidateBountyTerms(it->second, m_network, err)) {
            return fail("INVALID_PARAMETER", err.empty() ? "recipe incomplete" : ("recipe incomplete: " + err));
        }
        SignedEnvelope env;
        if (!sign_terms(it->second, env)) return fail("REJECTED", err);
        if (!VerifySignedEnvelope(env, m_network, err)) return fail("REJECTED", err);
        const std::string bounty_id = env.record_id.Hex();
        m_terms[bounty_id] = env;
        UniValue b(UniValue::VOBJ);
        b.pushKV("bounty_id", bounty_id);
        b.pushKV("title", it->second["title"]);
        b.pushKV("description", it->second["description"]);
        b.pushKV("target_atoms", it->second["target_atoms"]);
        b.pushKV("object_kind", "BOUNTY");
        b.pushKV("state", "PUBLISHED");
        m_bounties[bounty_id] = b;
        result = EnvelopeToJson(env);
        result.pushKV("bounty_id", bounty_id);
        UniValue rec(UniValue::VOBJ);
        rec.pushKV("object_kind", "BOUNTY");
        rec.pushKV("model_id", bounty_id);
        rec.pushKV("artifact_id", bounty_id);
        rec.pushKV("canonical_name", it->second["title"]);
        rec.pushKV("display_name", it->second["title"]);
        rec.pushKV("short_description", it->second["description"]);
        rec.pushKV("description", it->second["description"]);
        rec.pushKV("bounty_id", bounty_id);
        rec.pushKV("published_at", 1);
        rec.pushKV("expires_at", 0);
        rec.pushKV("metadata_sequence", 1);
        result.pushKV("search_record", rec);
        result.pushKV("next_actions", BountyNextActions(true, true));
        result.pushKV("automatic_spend_atoms", 0);
        Event("publish", bounty_id, result);
        return ok();
    }

    if (method == "revisebounty") {
        const UniValue a = ObjArg(params, 0);
        const std::string old_id = a.exists("bounty_id") ? a["bounty_id"].get_str() : StrArg(params, 0);
        if (!m_bounties.count(old_id)) return fail("NOT_FOUND", "bounty");
        UniValue terms = a.exists("terms") ? a["terms"] : ObjArg(params, 1);
        if (!ValidateBountyTerms(terms, m_network, err)) return fail("INVALID_PARAMETER", err);
        SignedEnvelope env;
        if (!sign_terms(terms, env)) return fail("REJECTED", err);
        const std::string bounty_id = env.record_id.Hex();
        if (bounty_id == old_id) return fail("REJECTED", "terms id must change");
        m_terms[bounty_id] = env;
        UniValue b(UniValue::VOBJ);
        b.pushKV("bounty_id", bounty_id);
        b.pushKV("supersedes", old_id);
        b.pushKV("title", terms["title"]);
        b.pushKV("description", terms["description"]);
        b.pushKV("target_atoms", terms["target_atoms"]);
        b.pushKV("object_kind", "BOUNTY");
        b.pushKV("deposits_migrated", false);
        m_bounties[bounty_id] = b;
        result = EnvelopeToJson(env);
        result.pushKV("bounty_id", bounty_id);
        result.pushKV("old_bounty_id", old_id);
        result.pushKV("deposits_migrated", false);
        Event("revise", bounty_id, result);
        return ok();
    }

    if (method == "getbounty" || method == "getbountyterms" || method == "getbountyeconomy") {
        const std::string id = StrArg(params, 0, "bounty_id");
        if (!m_bounties.count(id)) return fail("NOT_FOUND", "bounty");
        result = BountyEntryLocked(id);
        if (method == "getbountyterms") {
            auto it = m_terms.find(id);
            result = it == m_terms.end() ? UniValue(UniValue::VOBJ) : EnvelopeToJson(it->second);
        }
        return true;
    }

    if (method == "searchbounties" || method == "getmodelbounties") {
        UniValue q = ObjArg(params, 0);
        const std::string text = q.exists("text") ? q["text"].get_str() : (q.exists("query") ? q["query"].get_str() : "");
        const auto terms = TokenizeSearch(text);
        const std::string scope = q.exists("scope") ? q["scope"].get_str() : "LOCAL";
        int limit = q.exists("limit") ? q["limit"].getInt<int>() : 50;
        if (limit < 1) limit = 1;
        if (limit > BOUNTY_PAGE_MAX) limit = BOUNTY_PAGE_MAX;
        UniValue arr(UniValue::VARR);
        for (const auto& kv : m_bounties) {
            const UniValue& b = kv.second;
            if (b.exists("tombstone") && b["tombstone"].get_bool()) continue;
            if (!terms.empty()) {
                ModelSearchRecord r;
                r.canonical_name = b.exists("title") ? b["title"].get_str() : "";
                r.display_name = r.canonical_name;
                r.short_description = b.exists("description") ? b["description"].get_str() : "";
                if (RelevanceScore(r, terms) <= 0) continue;
            }
            UniValue card(UniValue::VOBJ);
            card.pushKV("bounty_id", kv.first);
            card.pushKV("object_kind", "BOUNTY");
            if (b.exists("title")) card.pushKV("title", b["title"]);
            if (b.exists("description")) card.pushKV("description", b["description"]);
            if (b.exists("target_atoms")) card.pushKV("target_atoms", b["target_atoms"]);
            card.pushKV("trust_label", BOUNTY_TRUST_LABEL);
            card.pushKV("wallet", false);
            arr.push_back(card);
            if (static_cast<int>(arr.size()) >= limit) break;
        }
        result.setObject();
        result.pushKV("schema_version", 1);
        result.pushKV("results", arr);
        result.pushKV("scope", scope);
        result.pushKV("global_complete", false);
        result.pushKV("complete", scope == "LOCAL" || ToUpper(scope) == "LOCAL");
        result.pushKV("cursor", m_seq > 0 ? std::to_string(m_seq) : "");
        result.pushKV("epoch", static_cast<int64_t>(m_epoch));
        return true;
    }

    auto sign_payload = [&](const std::string& type, const UniValue& payload, SignedEnvelope& env) -> bool {
        std::vector<unsigned char> pk, sk;
        Digest48 id;
        if (!LoadIdentity(pk, sk, id, err)) return false;
        UniValue del;
        del.setNull();
        return BuildSignedEnvelope(type, m_network, pk, sk, payload, del, env, err);
    };

    if (method == "nominatebountyevaluator") {
        const UniValue a = ObjArg(params, 0);
        const std::string bounty_id = a["bounty_id"].get_str();
        if (!m_bounties.count(bounty_id)) return fail("NOT_FOUND", "bounty");
        UniValue p(UniValue::VOBJ);
        p.pushKV("bounty_id", bounty_id);
        p.pushKV("nominee_identity", a["nominee_identity"]);
        p.pushKV("nominee_key", a["nominee_key"]);
        p.pushKV("seat", false);
        p.pushKV("spending_authority", false);
        SignedEnvelope env;
        if (!sign_payload("CouncilAppointment", p, env)) return fail("REJECTED", err);
        m_noms[bounty_id].push_back(env);
        result = EnvelopeToJson(env);
        result.pushKV("nomination_only", true);
        Event("nominate", bounty_id, result);
        return ok();
    }

    if (method == "acceptbountyappointment") {
        const UniValue a = ObjArg(params, 0);
        SignedEnvelope env;
        if (!sign_payload("CouncilAppointment", a.exists("appointment") ? a["appointment"] : a, env))
            return fail("REJECTED", err);
        const std::string terms_id = a.exists("terms_id") ? a["terms_id"].get_str() : "";
        m_appointments[terms_id].push_back(env);
        result = EnvelopeToJson(env);
        result.pushKV("spending_authority", false);
        return ok();
    }

    if (method == "listbountyevaluators") {
        const std::string bounty_id = StrArg(params, 0, "bounty_id");
        UniValue arr(UniValue::VARR);
        for (const auto& e : m_noms[bounty_id]) arr.push_back(EnvelopeToJson(e));
        for (const auto& e : m_appointments[bounty_id]) arr.push_back(EnvelopeToJson(e));
        result.setObject();
        result.pushKV("evaluators", arr);
        return true;
    }

    if (method == "pledgebounty") {
        const UniValue a = ObjArg(params, 0);
        const std::string bounty_id = a["bounty_id"].get_str();
        if (!m_bounties.count(bounty_id)) return fail("NOT_FOUND", "bounty");
        int64_t n = 0;
        if (!CanonicalAtoms(a["principal_atoms"].get_str(), n, err)) return fail("INVALID_PARAMETER", err);
        UniValue p(UniValue::VOBJ);
        p.pushKV("bounty_id", bounty_id);
        p.pushKV("principal_atoms", a["principal_atoms"]);
        p.pushKV("binding", false);
        SignedEnvelope env;
        if (!sign_payload("FundingRound", p, env)) return fail("REJECTED", err);
        m_pledges[env.record_id.Hex()] = env;
        result = EnvelopeToJson(env);
        result.pushKV("confirmed", false);
        result.pushKV("pledge_id", env.record_id.Hex());
        Event("pledge", bounty_id, result);
        return ok();
    }

    if (method == "withdrawbountypledge") {
        const std::string pid = StrArg(params, 0, "pledge_id");
        auto it = m_pledges.find(pid);
        if (it == m_pledges.end()) return fail("NOT_FOUND", "pledge");
        m_pledges.erase(it);
        result.setObject();
        result.pushKV("pledge_id", pid);
        result.pushKV("withdrawn", true);
        result.pushKV("money_moved", false);
        return ok();
    }

    if (method == "freezebountyfundinground") {
        const UniValue a = ObjArg(params, 0);
        const std::string terms_id = a.exists("terms_id") ? a["terms_id"].get_str() : a["bounty_id"].get_str();
        auto tit = m_terms.find(terms_id);
        if (tit == m_terms.end()) return fail("NOT_FOUND", "terms");
        for (const auto& kv : m_rounds) {
            if (kv.second.exists("terms_id") && kv.second["terms_id"].get_str() == terms_id)
                return fail("REJECTED", "round already frozen");
        }
        UniValue round = a.exists("round") ? a["round"] : a;
        UniValue lots = round.exists("lots") ? round["lots"] : UniValue(UniValue::VARR);
        if (!lots.isArray() || lots.empty() || static_cast<int>(lots.size()) > BOUNTY_LOTS_MAX)
            return fail("INVALID_PARAMETER", "lots");
        int64_t frozen = 0;
        std::string err2;
        std::vector<std::string> keys;
        UniValue out_lots(UniValue::VARR);
        uint32_t ordinal = 0;
        for (const auto& lot : lots.getValues()) {
            int64_t p = 0;
            if (!lot.exists("principal_atoms") || !CanonicalAtoms(lot["principal_atoms"].get_str(), p, err2))
                return fail("INVALID_PARAMETER", "principal");
            frozen += p;
            UniValue L = lot;
            const std::string rid_placeholder = "pending";
            (void)rid_placeholder;
            L.pushKV("ordinal", static_cast<int>(ordinal));
            out_lots.push_back(L);
            ++ordinal;
        }
        UniValue payload(UniValue::VOBJ);
        payload.pushKV("terms_id", terms_id);
        payload.pushKV("lots", out_lots);
        payload.pushKV("frozen_total_atoms", std::to_string(frozen));
        payload.pushKV("council", tit->second.body["payload"]["council"]);
        payload.pushKV("threshold", tit->second.body["payload"]["threshold"]);
        payload.pushKV("mutable_outputs", false);
        SignedEnvelope env;
        if (!sign_payload("FundingRound", payload, env)) return fail("REJECTED", err);
        const std::string round_id = env.record_id.Hex();
        UniValue stored = payload;
        stored.pushKV("round_id", round_id);
        UniValue lots2(UniValue::VARR);
        ordinal = 0;
        for (const auto& lot : out_lots.getValues()) {
            UniValue L = lot;
            L.pushKV("lot_id", LotId(round_id, ordinal));
            lots2.push_back(L);
            ++ordinal;
        }
        stored.pushKV("lots", lots2);
        m_rounds[round_id] = stored;
        result = stored;
        result.pushKV("verified", true);
        Event("freeze", terms_id, result);
        return ok();
    }

    if (method == "getbountyfunding") {
        const std::string bounty_id = StrArg(params, 0, "bounty_id");
        result = m_chain.Snapshot(bounty_id);
        UniValue pledges(UniValue::VARR);
        for (const auto& kv : m_pledges) {
            if (kv.second.body.exists("payload") && kv.second.body["payload"]["bounty_id"].get_str() == bounty_id)
                pledges.push_back(EnvelopeToJson(kv.second));
        }
        result.pushKV("pledges", pledges);
        result.pushKV("pledged_is_not_confirmed", true);
        return true;
    }

    if (method == "commitbountysubmission") {
        const UniValue a = ObjArg(params, 0);
        UniValue p = a.exists("commitment") ? a["commitment"] : a;
        p.pushKV("bounty_id", a["bounty_id"]);
        SignedEnvelope env;
        if (!sign_payload("SubmissionCommitment", p, env)) return fail("REJECTED", err);
        UniValue s(UniValue::VOBJ);
        s.pushKV("commitment_id", env.record_id.Hex());
        s.pushKV("bounty_id", a["bounty_id"]);
        s.pushKV("revealed", false);
        s.pushKV("originality_proof", false);
        m_submissions[env.record_id.Hex()] = s;
        result = EnvelopeToJson(env);
        result.pushKV("commitment_id", env.record_id.Hex());
        Event("commit", a["bounty_id"].get_str(), result);
        return ok();
    }

    if (method == "revealbountysubmission") {
        const UniValue a = ObjArg(params, 0);
        const std::string cid = a.exists("commitment_id") ? a["commitment_id"].get_str() : StrArg(params, 0);
        auto it = m_submissions.find(cid);
        if (it == m_submissions.end()) return fail("NOT_FOUND", "commitment");
        UniValue sub = a.exists("submission") ? a["submission"] : a;
        if (sub.exists("secret") || sub.exists("preimage")) return fail("REJECTED", "public secret forbidden");
        SignedEnvelope env;
        if (!sign_payload("Submission", sub, env)) return fail("REJECTED", err);
        it->second.pushKV("revealed", true);
        it->second.pushKV("submission_id", env.record_id.Hex());
        it->second.pushKV("submission", sub);
        m_submissions[env.record_id.Hex()] = it->second;
        result = EnvelopeToJson(env);
        result.pushKV("submission_id", env.record_id.Hex());
        return ok();
    }

    if (method == "getbountysubmission") {
        const std::string id = StrArg(params, 0, "submission_id");
        auto it = m_submissions.find(id);
        if (it == m_submissions.end()) return fail("NOT_FOUND", "submission");
        result = it->second;
        return true;
    }

    if (method == "listbountysubmissions") {
        const std::string bounty_id = StrArg(params, 0, "bounty_id");
        UniValue arr(UniValue::VARR);
        for (const auto& kv : m_submissions) {
            if (kv.second.exists("bounty_id") && kv.second["bounty_id"].get_str() == bounty_id) arr.push_back(kv.second);
        }
        result.setObject();
        result.pushKV("submissions", arr);
        return true;
    }

    if (method == "withdrawbountysubmission") {
        const std::string id = StrArg(params, 0, "submission_id");
        auto it = m_submissions.find(id);
        if (it == m_submissions.end()) return fail("NOT_FOUND", "submission");
        it->second.pushKV("withdrawn", true);
        it->second.pushKV("erased", false);
        result = it->second;
        return ok();
    }

    if (method == "preparebountyevaluation") {
        const UniValue a = ObjArg(params, 0);
        const std::string sid = a.exists("submission_id") ? a["submission_id"].get_str() : "";
        auto it = m_submissions.find(sid);
        UniValue spec(UniValue::VOBJ);
        spec.pushKV("profile_id", a.exists("profile_id") ? a["profile_id"].get_str() : "EXACT_CHECKS");
        if (a.exists("required_files")) spec.pushKV("required_files", a["required_files"]);
        UniValue sub = (it != m_submissions.end() && it->second.exists("submission")) ? it->second["submission"] : a;
        UniValue plan;
        if (!PrepareEvaluation(spec, sub, a.exists("resources") ? a["resources"] : UniValue(UniValue::VOBJ), plan, err))
            return fail("REJECTED", err);
        const std::string plan_id = RandHex(16);
        plan.pushKV("plan_id", plan_id);
        plan.pushKV("submission_id", sid);
        m_eval_plans[plan_id] = plan;
        result = plan;
        return ok();
    }

    if (method == "runbountyevaluation") {
        const UniValue a = ObjArg(params, 0);
        const std::string plan_id = a.exists("plan_id") ? a["plan_id"].get_str() : StrArg(params, 0);
        auto it = m_eval_plans.find(plan_id);
        if (it == m_eval_plans.end()) return fail("NOT_FOUND", "plan");
        if (!a.exists("execution_approval_ref") && !a.exists("approval")) return fail("REJECTED", "execution approval required");
        UniValue job(UniValue::VOBJ);
        const std::string job_id = RandHex(16);
        job.pushKV("job_id", job_id);
        job.pushKV("plan", it->second);
        job.pushKV("state", "RUNNING");
        m_eval_jobs[job_id] = job;
        lock.unlock();
        const bool ran = RunEvaluationJob(job, err);
        lock.lock();
        m_eval_jobs[job_id] = job;
        if (!ran) return fail("EVAL_FAILED", err);
        result = job;
        return ok();
    }

    if (method == "getbountyevaluationjob") {
        const std::string id = StrArg(params, 0, "job_id");
        auto it = m_eval_jobs.find(id);
        if (it == m_eval_jobs.end()) return fail("NOT_FOUND", "job");
        result = it->second;
        return true;
    }

    if (method == "cancelbountyevaluation") {
        const std::string id = StrArg(params, 0, "job_id");
        auto it = m_eval_jobs.find(id);
        if (it == m_eval_jobs.end()) return fail("NOT_FOUND", "job");
        if (!CancelEvaluationJob(it->second, err)) return fail("REJECTED", err);
        result = it->second;
        return ok();
    }

    if (method == "publishbountyevaluation") {
        const UniValue a = ObjArg(params, 0);
        const std::string job_id = a.exists("job_id") ? a["job_id"].get_str() : "";
        auto it = m_eval_jobs.find(job_id);
        if (it == m_eval_jobs.end()) return fail("NOT_FOUND", "job");
        UniValue report = a.exists("report") ? a["report"] : it->second.exists("report") ? it->second["report"] : a;
        report.pushKV("job_id", job_id);
        report.pushKV("award_signature", false);
        SignedEnvelope env;
        if (!sign_payload("EvaluationReport", report, env)) return fail("REJECTED", err);
        m_eval_reports[env.record_id.Hex()] = env;
        result = EnvelopeToJson(env);
        result.pushKV("is_award", false);
        result.pushKV("is_transaction_signature", false);
        return ok();
    }

    if (method == "listbountyevaluations") {
        const std::string sid = StrArg(params, 0, "submission_id");
        UniValue arr(UniValue::VARR);
        for (const auto& kv : m_eval_reports) arr.push_back(EnvelopeToJson(kv.second));
        (void)sid;
        result.setObject();
        result.pushKV("evaluations", arr);
        return true;
    }

    if (method == "createbountychallenge") {
        const UniValue a = ObjArg(params, 0);
        SignedEnvelope env;
        if (!sign_payload("Challenge", a.exists("challenge") ? a["challenge"] : a, env)) return fail("REJECTED", err);
        m_challenges[env.record_id.Hex()] = env;
        result = EnvelopeToJson(env);
        result.pushKV("challenge_id", env.record_id.Hex());
        return ok();
    }

    if (method == "listbountychallenges") {
        const std::string bounty_id = StrArg(params, 0, "bounty_id");
        UniValue arr(UniValue::VARR);
        for (const auto& kv : m_challenges) arr.push_back(EnvelopeToJson(kv.second));
        (void)bounty_id;
        result.setObject();
        result.pushKV("challenges", arr);
        return true;
    }

    if (method == "resolvebountychallenge") {
        const UniValue a = ObjArg(params, 0);
        const std::string cid = a.exists("challenge_id") ? a["challenge_id"].get_str() : "";
        if (!m_challenges.count(cid)) return fail("NOT_FOUND", "challenge");
        SignedEnvelope env;
        if (!sign_payload("Challenge", a.exists("resolution") ? a["resolution"] : a, env)) return fail("REJECTED", err);
        result = EnvelopeToJson(env);
        result.pushKV("revokes_released_signature", false);
        return ok();
    }

    if (method == "proposebountyaward") {
        const UniValue a = ObjArg(params, 0);
        UniValue p(UniValue::VOBJ);
        p.pushKV("bounty_id", a["bounty_id"]);
        p.pushKV("submission_id", a["submission_id"]);
        p.pushKV("lot_ids", a.exists("lot_ids") ? a["lot_ids"] : UniValue(UniValue::VARR));
        p.pushKV("mode", a.exists("mode") ? a["mode"] : "PUBLIC_PAYOUT");
        p.pushKV("paid", false);
        SignedEnvelope env;
        if (!sign_payload("AwardProposal", p, env)) return fail("REJECTED", err);
        UniValue aw(UniValue::VOBJ);
        aw.pushKV("award_id", env.record_id.Hex());
        aw.pushKV("proposal", p);
        aw.pushKV("policy_approvals", UniValue(UniValue::VARR));
        aw.pushKV("tx_signatures", 0);
        aw.pushKV("automatic", false);
        m_awards[env.record_id.Hex()] = aw;
        result = EnvelopeToJson(env);
        result.pushKV("award_id", env.record_id.Hex());
        result.pushKV("paid", false);
        return ok();
    }

    if (method == "approvebountyaward") {
        const UniValue a = ObjArg(params, 0);
        const std::string award_id = a.exists("award_id") ? a["award_id"].get_str() : "";
        auto it = m_awards.find(award_id);
        if (it == m_awards.end()) return fail("NOT_FOUND", "award");
        if (a.exists("decision") && a["decision"].get_str() == "REJECT") {
            it->second.pushKV("rejected", true);
            result = it->second;
            result.pushKV("transaction_signature", false);
            return ok();
        }
        SignedEnvelope env;
        UniValue p(UniValue::VOBJ);
        p.pushKV("award_id", award_id);
        p.pushKV("decision", "APPROVE");
        p.pushKV("transaction_signature", false);
        if (!sign_payload("AwardPolicyApproval", p, env)) return fail("REJECTED", err);
        UniValue apps = it->second.exists("policy_approvals") ? it->second["policy_approvals"] : UniValue(UniValue::VARR);
        apps.push_back(EnvelopeToJson(env));
        it->second.pushKV("policy_approvals", apps);
        result = EnvelopeToJson(env);
        result.pushKV("transaction_signature", false);
        return ok();
    }

    if (method == "getbountyaward") {
        const std::string id = StrArg(params, 0, "award_id");
        auto it = m_awards.find(id);
        if (it == m_awards.end()) return fail("NOT_FOUND", "award");
        result = it->second;
        return true;
    }

    if (method == "getbountyevents") {
        const UniValue a = ObjArg(params, 0);
        const std::string bounty_id = a.exists("bounty_id") ? a["bounty_id"].get_str() : StrArg(params, 0);
        uint64_t since = 0;
        if (a.exists("cursor") && a["cursor"].isStr() && !a["cursor"].get_str().empty())
            since = std::stoull(a["cursor"].get_str());
        int limit = a.exists("limit") ? a["limit"].getInt<int>() : 50;
        if (limit > BOUNTY_PAGE_MAX) limit = BOUNTY_PAGE_MAX;
        UniValue arr(UniValue::VARR);
        for (const auto& e : m_events) {
            if (e["seq"].getInt<int64_t>() <= static_cast<int64_t>(since)) continue;
            if (!bounty_id.empty() && e["bounty_id"].get_str() != bounty_id) continue;
            arr.push_back(e);
            if (static_cast<int>(arr.size()) >= limit) break;
        }
        result.setObject();
        result.pushKV("events", arr);
        result.pushKV("epoch", static_cast<int64_t>(m_epoch));
        result.pushKV("cursor", std::to_string(m_seq));
        result.pushKV("gap", false);
        return true;
    }

    if (method == "watchbounty") {
        const std::string id = StrArg(params, 0, "bounty_id");
        const std::string wid = RandHex(8);
        UniValue w(UniValue::VOBJ);
        w.pushKV("watch_id", wid);
        w.pushKV("bounty_id", id);
        w.pushKV("downloads", false);
        w.pushKV("evaluates", false);
        w.pushKV("spends", false);
        m_watches[wid] = w;
        result = w;
        return ok();
    }

    if (method == "unwatchbounty") {
        const std::string id = StrArg(params, 0, "watch_id");
        m_watches.erase(id);
        result.setObject();
        result.pushKV("watch_id", id);
        result.pushKV("removed", true);
        return ok();
    }

    if (method == "createagentmandate") {
        const UniValue a = ObjArg(params, 0);
        if (!a.exists("owner_approval_ref") && !(a.exists("mandate") && a["mandate"].exists("owner_approval_ref")))
            return fail("REJECTED", "owner approval required");
        UniValue m = a.exists("mandate") ? a["mandate"] : a;
        if (!m.exists("total_atoms") || !m.exists("per_action_atoms")) return fail("INVALID_PARAMETER", "finite budget required");
        int64_t total = 0, per = 0;
        if (!CanonicalAtoms(m["total_atoms"].isStr() ? m["total_atoms"].get_str() : std::to_string(m["total_atoms"].getInt<int64_t>()),
                            total, err))
            return fail("INVALID_PARAMETER", err);
        if (!CanonicalAtoms(m["per_action_atoms"].isStr() ? m["per_action_atoms"].get_str() :
                                                              std::to_string(m["per_action_atoms"].getInt<int64_t>()),
                            per, err))
            return fail("INVALID_PARAMETER", err);
        auto unbounded = [](const UniValue& o) {
            return o.exists("all_recipients") && o["all_recipients"].get_bool();
        };
        if (unbounded(a) || unbounded(m)) return fail("REJECTED", "unbounded mandate");
        const std::string mid = RandHex(16);
        m.pushKV("mandate_id", mid);
        m.pushKV("revoked", false);
        m_mandates[mid] = m;
        auto slot = std::make_unique<MandateBudget>();
        slot->Reset(total, per);
        m_budgets[mid] = std::move(slot);
        m_budget.Reset(total, per);
        result = m;
        Event("mandate", mid, m);
        return ok();
    }

    if (method == "getagentmandate") {
        const std::string id = StrArg(params, 0, "mandate_id");
        auto it = m_mandates.find(id);
        if (it == m_mandates.end()) return fail("NOT_FOUND", "mandate");
        result = it->second;
        auto bit = m_budgets.find(id);
        result.pushKV("used_atoms", std::to_string(bit != m_budgets.end() ? bit->second->Used() : m_budget.Used()));
        const bool revoked = (bit != m_budgets.end() && bit->second->Revoked()) ||
                             (it->second.exists("revoked") && it->second["revoked"].get_bool());
        result.pushKV("revoked", revoked);
        return true;
    }

    if (method == "revokeagentmandate") {
        const std::string id = StrArg(params, 0, "mandate_id");
        auto it = m_mandates.find(id);
        if (it == m_mandates.end()) return fail("NOT_FOUND", "mandate");
        it->second.pushKV("revoked", true);
        auto bit = m_budgets.find(id);
        if (bit != m_budgets.end()) bit->second->Revoke();
        result = it->second;
        return ok();
    }

    if (method == "getagentactivity") {
        UniValue arr(UniValue::VARR);
        for (const auto& kv : m_activity) arr.push_back(kv.second);
        result.setObject();
        result.pushKV("activity", arr);
        result.pushKV("telemetry", false);
        return true;
    }

    if (method == "reservemandate") {
        const UniValue a = ObjArg(params, 0);
        int64_t amount = a["amount_atoms"].isStr() ? 0 : a["amount_atoms"].getInt<int64_t>();
        if (a["amount_atoms"].isStr() && !CanonicalAtoms(a["amount_atoms"].get_str(), amount, err))
            return fail("INVALID_PARAMETER", err);
        std::string mid = a.exists("mandate_id") && a["mandate_id"].isStr() ? a["mandate_id"].get_str() : "";
        if (mid.empty()) {
            if (m_mandates.size() == 1) mid = m_mandates.begin()->first;
            else return fail("INVALID_PARAMETER", "mandate_id");
        }
        auto mit = m_mandates.find(mid);
        if (mit == m_mandates.end()) return fail("NOT_FOUND", "mandate");
        if (mit->second.exists("revoked") && mit->second["revoked"].get_bool()) return fail("REJECTED", "revoked");
        auto bit = m_budgets.find(mid);
        if (bit == m_budgets.end()) return fail("NOT_FOUND", "mandate");
        if (!bit->second->Reserve(a["idempotency_key"].get_str(), amount,
                                  a.exists("refund_key") ? a["refund_key"].get_str() : "", err))
            return fail("REJECTED", err);
        UniValue act(UniValue::VOBJ);
        act.pushKV("key", a["idempotency_key"]);
        act.pushKV("amount_atoms", std::to_string(amount));
        act.pushKV("mandate_id", mid);
        m_activity[a["idempotency_key"].get_str()] = act;
        result.setObject();
        result.pushKV("reserved", amount);
        result.pushKV("used", bit->second->Used());
        return ok();
    }

    if (method == "observebountychain") {
        const UniValue a = ObjArg(params, 0);
        BountyChainFact f;
        f.outpoint = a["outpoint"].get_str();
        f.bounty_id = a.exists("bounty_id") ? a["bounty_id"].get_str() : "";
        f.lot_id = a.exists("lot_id") ? a["lot_id"].get_str() : "";
        if (a.exists("amount_atoms")) {
            if (!CanonicalAtomsField(a["amount_atoms"], f.amount_atoms, err))
                return fail("INVALID_PARAMETER", err.empty() ? "amount_atoms" : err);
        }
        if (a.exists("confirmations")) f.confirmations = a["confirmations"].getInt<int>();
        if (a.exists("height")) f.height = static_cast<uint32_t>(a["height"].getInt<int64_t>());
        if (a.exists("spent")) f.spent = a["spent"].get_bool();
        if (!f.spent) {
            int64_t confirmed = m_chain.ConfirmedAtoms(f.bounty_id);
            if (const BountyChainFact* prev = m_chain.Get(f.outpoint)) {
                if (prev->bounty_id == f.bounty_id && !prev->spent && prev->amount_atoms >= 0 &&
                    prev->amount_atoms <= confirmed) {
                    confirmed -= prev->amount_atoms;
                }
            }
            if (!AddMoneyAtoms(confirmed, f.amount_atoms, err))
                return fail("INVALID_PARAMETER", err.empty() ? "total MoneyRange" : err);
        }
        m_chain.Observe(f);
        result = m_chain.Snapshot(f.bounty_id);
        return ok();
    }

    if (method == "reorgbountychain") {
        const std::string bounty_id = StrArg(params, 0, "bounty_id");
        m_chain.DisconnectTip();
        result = m_chain.Snapshot(bounty_id);
        UniValue payload(UniValue::VOBJ);
        payload.pushKV("corrective", true);
        payload.pushKV("silent_delete", false);
        result.pushKV("reorg", true);
        result.pushKV("event", Event("REORG", bounty_id, payload));
        return ok();
    }

    if (method == "exportbountyrecovery") {
        const UniValue a = ObjArg(params, 0);
        const std::string bounty_id = a.exists("bounty_id") ? a["bounty_id"].get_str() : StrArg(params, 0);
        std::vector<std::string> lots;
        if (a.exists("lot_ids") && a["lot_ids"].isArray()) {
            for (const auto& x : a["lot_ids"].getValues()) lots.push_back(x.get_str());
        }
        result = m_chain.ExportRecovery(bounty_id, lots);
        result.pushKV("wallet_seed", false);
        result.pushKV("private_keys", false);
        return true;
    }

    if (method == "importbountyrecovery") {
        const UniValue a = ObjArg(params, 0);
        const UniValue man = a.exists("manifest") ? a["manifest"] : a;
        if (!m_chain.ImportManifest(man, err)) return fail("REJECTED", err);
        result.setObject();
        result.pushKV("imported", true);
        result.pushKV("broadcast", false);
        return ok();
    }

    return fail("NOT_FOUND", "method");
}

bool IsBountyHelperMethod(const std::string& method)
{
    return HelperMethods().count(method) > 0;
}

BountyStore& GlobalBountyStore()
{
    static BountyStore s;
    return s;
}

bool DispatchBountyHelperRpc(ModelCatalog& cat, const std::string& method, const UniValue& params, UniValue& result,
                             std::string& err_code, std::string& err)
{
    if (!IsBountyHelperMethod(method)) return false;
    auto& st = GlobalBountyStore();
    NetworkId nid{};
    st.Bind(cat.Store().Root().parent_path(), nid);
    return st.Dispatch(method, params, result, err_code, err);
}

} // namespace modelnet
