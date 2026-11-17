// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/free_grant.h>

#include <logging.h>
#include <modelnet/identity.h>
#include <random.h>
#include <util/strencodings.h>
#include <util/fs_helpers.h>

#include <algorithm>
#include <ctime>
#include <fstream>
#include <mutex>
#include <sstream>
#include <unordered_map>

namespace modelnet {
namespace {

std::mutex g_grant_store_mu;

bool LooksPaymentKey(const std::string& k)
{
    static const char* names[] = {
        "payment", "payment_script", "payment_address", "address", "amount", "amount_atoms",
        "fee", "fee_atoms", "fee_cap_atoms", "price", "price_atoms", "script", "script_pubkey",
        "chain_confirmation", "chain_confirmations", "confirmation", "confirmations",
        "htlc", "funding_txid", "value", "value_atoms",
    };
    const std::string n = ToLower(k);
    for (const char* name : names) {
        if (n == name) return true;
    }
    return false;
}

bool ReadObj(const fs::path& path, UniValue& out)
{
    std::ifstream in(path);
    if (!in) {
        out = UniValue(UniValue::VOBJ);
        return true;
    }
    std::ostringstream ss;
    ss << in.rdbuf();
    if (!out.read(ss.str()) || !out.isObject()) {
        out = UniValue(UniValue::VOBJ);
        return false;
    }
    return true;
}

bool WriteObj(const fs::path& path, const UniValue& obj, std::string& err)
{
    // Write a sibling and rename it over the store, so a crash or a short
    // write never leaves a half file that refuses every later grant.
    TryCreateDirectories(path.parent_path());
    const fs::path tmp = fs::PathFromString(fs::PathToString(path) + ".tmp");
    {
        std::ofstream out(tmp, std::ios::trunc);
        if (!out) {
            err = "write " + fs::PathToString(path);
            return false;
        }
        out << obj.write() << "\n";
        out.flush();
        if (!out) {
            err = "write " + fs::PathToString(path);
            return false;
        }
    }
    if (!RenameOver(tmp, path)) {
        err = "write " + fs::PathToString(path);
        return false;
    }
    return true;
}

/** Read a grant store (grant_redeems.json or grant_nonces.json). An unparsable
 *  store (an older in-place write cut short) is moved aside to .quarantine and
 *  replaced by an empty one. Both stores are bounded (redeems by the 600 s
 *  grant lifetime, nonces by kGrantNonceCap), so the rename is cheap. Every
 *  grant expires within FREE_GRANT_LIFETIME_S, so at most one lifetime of
 *  uses can repeat, and a re-issued nonce still meets its recorded uses. */
bool ReadOrQuarantine(const fs::path& path, UniValue& out)
{
    if (ReadObj(path, out)) return true;
    const fs::path q = fs::PathFromString(fs::PathToString(path) + ".quarantine");
    std::error_code ec;
    fs::rename(path, q, ec);
    if (ec) {
        LogPrintf("btx-modeld: %s is unreadable and cannot be moved aside: %s\n", fs::PathToString(path), ec.message());
        out = UniValue(UniValue::VOBJ);
        return false;
    }
    LogPrintf("btx-modeld: %s was unreadable; moved to %s and started empty\n", fs::PathToString(path), fs::PathToString(q));
    out = UniValue(UniValue::VOBJ);
    return true;
}

/** Drop the uses of grants that have expired: an expired grant never verifies
 *  again, so its record only grows the file that every piece GET rewrites. */
void PruneExpiredUses(UniValue& store, int64_t now)
{
    const UniValue empty(UniValue::VOBJ);
    const UniValue& exp = store.exists("expires_at") && store["expires_at"].isObject() ? store["expires_at"] : empty;
    const UniValue& used = store.exists("uses") && store["uses"].isObject() ? store["uses"] : empty;
    const UniValue& bytes = store.exists("redeemed_bytes") && store["redeemed_bytes"].isObject() ? store["redeemed_bytes"] : empty;
    // Index once: UniValue key lookup is linear, so per-nonce exists()/[] on a
    // large store would make this quadratic.
    std::unordered_map<std::string, const UniValue*> exp_by, bytes_by;
    for (size_t i = 0; i < exp.getKeys().size(); ++i) exp_by.emplace(exp.getKeys()[i], &exp.getValues()[i]);
    for (size_t i = 0; i < bytes.getKeys().size(); ++i) bytes_by.emplace(bytes.getKeys()[i], &bytes.getValues()[i]);
    UniValue kept_used(UniValue::VOBJ), kept_bytes(UniValue::VOBJ), kept_exp(UniValue::VOBJ);
    for (size_t i = 0; i < used.getKeys().size(); ++i) {
        const std::string& nonce = used.getKeys()[i];
        int64_t until = now + FREE_GRANT_LIFETIME_S; // no record (older store): keep one lifetime
        const auto e = exp_by.find(nonce);
        if (e != exp_by.end() && e->second->isNum()) {
            try {
                until = e->second->getInt<int64_t>();
            } catch (...) {
            }
        }
        if (until < now) continue;
        kept_used.pushKVEnd(nonce, used.getValues()[i]);
        const auto bb = bytes_by.find(nonce);
        if (bb != bytes_by.end()) kept_bytes.pushKVEnd(nonce, *bb->second);
        kept_exp.pushKVEnd(nonce, until);
    }
    store.pushKV("uses", std::move(kept_used));
    store.pushKV("redeemed_bytes", std::move(kept_bytes));
    store.pushKV("expires_at", std::move(kept_exp));
}

} // namespace

bool GrantHasPaymentFields(const UniValue& body)
{
    if (body.isObject()) {
        for (const auto& k : body.getKeys()) {
            if (LooksPaymentKey(k)) return true;
            if (GrantHasPaymentFields(body[k])) return true;
        }
        return false;
    }
    if (body.isArray()) {
        for (const auto& v : body.getValues()) {
            if (GrantHasPaymentFields(v)) return true;
        }
    }
    return false;
}

Digest48 ServiceSignerId(Span<const unsigned char> pubkey)
{
    return ProviderId(pubkey);
}

bool IssueFreeGrant(const FreeGrantParams& p_in,
                    Span<const unsigned char> sk,
                    Span<const unsigned char> pk,
                    SignedFreeGrant& out,
                    std::string& err)
{
    out = {};
    if (pk.size() != MLDSA44_PK || sk.size() != MLDSA44_SK) {
        err = "service identity";
        return false;
    }
    FreeGrantParams p = p_in;
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    if (p.piece_count == 0 || p.maximum_bytes == 0) {
        err = "free range";
        return false;
    }
    if (p.issued_at <= 0) p.issued_at = now;
    if (p.expires_at <= p.issued_at) p.expires_at = p.issued_at + FREE_GRANT_LIFETIME_S;
    if (p.expires_at - p.issued_at > FREE_GRANT_LIFETIME_S) {
        err = "free grant too long";
        return false;
    }
    if (p.expires_at <= now) {
        err = "expired";
        return false;
    }
    if (p.transfer_id.Hex() == std::string(64, '0')) {
        GetStrongRandBytes(Span<unsigned char>{p.transfer_id.data.data(), p.transfer_id.data.size()});
    }
    if (p.grant_nonce.Hex() == std::string(64, '0')) {
        GetStrongRandBytes(Span<unsigned char>{p.grant_nonce.data.data(), p.grant_nonce.data.size()});
    }

    UniValue body(UniValue::VOBJ);
    body.pushKV("ext_version", static_cast<int>(EXT_VERSION_V11));
    body.pushKV("network", std::string(64, '0'));
    body.pushKV("signer_role", 0);
    body.pushKV("signer_id", ServiceSignerId(pk).Hex());
    body.pushKV("sequence", static_cast<uint64_t>(p.sequence == 0 ? 1 : p.sequence));
    body.pushKV("issued_at", p.issued_at);
    body.pushKV("expires_at", p.expires_at);
    body.pushKV("transfer_id", p.transfer_id.Hex());
    body.pushKV("buyer_id", p.buyer_id.Hex());
    body.pushKV("model_id", p.model_id.Hex());
    body.pushKV("artifact_id", p.artifact_id.Hex());
    body.pushKV("file_index", static_cast<int>(p.file_index));
    body.pushKV("first_piece", static_cast<int>(p.first_piece));
    body.pushKV("piece_count", static_cast<int>(p.piece_count));
    body.pushKV("maximum_bytes", p.maximum_bytes);
    body.pushKV("grant_nonce", p.grant_nonce.Hex());
    body.pushKV("queue_class", p.queue_class);

    if (GrantHasPaymentFields(body)) {
        err = "payment fields";
        return false;
    }
    if (!EncodeRecord(RECORD_FREE_GRANT, body, out.payload, err)) return false;
    Digest48 msg;
    if (!SigningMessage(RECORD_FREE_GRANT, body, msg, err)) return false;
    if (!SignMlDsa44(sk, Span<const unsigned char>{msg.data.data(), msg.data.size()}, out.signature, err)) {
        return false;
    }
    if (!RecordId(RECORD_FREE_GRANT, body, out.object_id, err)) return false;
    out.body = std::move(body);
    out.pubkey.assign(pk.begin(), pk.end());
    return true;
}

bool VerifyFreeGrant(Span<const unsigned char> payload,
                     Span<const unsigned char> sig,
                     Span<const unsigned char> pk,
                     int64_t now,
                     const std::set<std::string>& seen_nonces,
                     UniValue& body,
                     std::string& err)
{
    body = UniValue(UniValue::VOBJ);
    if (!DecodeRecord(RECORD_FREE_GRANT, payload, body, err)) return false;
    if (GrantHasPaymentFields(body)) {
        err = "payment fields";
        return false;
    }
    Digest48 msg;
    if (!SigningMessage(RECORD_FREE_GRANT, body, msg, err)) return false;
    if (!VerifyMlDsa44(pk, Span<const unsigned char>{msg.data.data(), msg.data.size()}, sig)) {
        err = "signature";
        return false;
    }
    if (!body.exists("signer_id") || !body["signer_id"].isStr() ||
        body["signer_id"].get_str() != ServiceSignerId(pk).Hex()) {
        err = "signer identity mismatch";
        return false;
    }
    const int64_t expires = body["expires_at"].getInt<int64_t>();
    if (now > 0 && now >= expires) {
        err = "expired";
        return false;
    }
    const std::string nonce = body["grant_nonce"].get_str();
    if (seen_nonces.count(nonce)) {
        err = "replay";
        return false;
    }
    return true;
}

bool RejectExpiredTamperedReplay(Span<const unsigned char> payload,
                                  Span<const unsigned char> sig,
                                  Span<const unsigned char> pk,
                                  int64_t now,
                                  const std::set<std::string>& seen_nonces,
                                  GrantRejectReason& reason,
                                  std::string& err)
{
    reason = GrantRejectReason::NONE;
    UniValue body;
    if (!VerifyFreeGrant(payload, sig, pk, /*now=*/0, {}, body, err)) {
        reason = GrantRejectReason::TAMPERED;
        return true;
    }
    const int64_t expires = body["expires_at"].getInt<int64_t>();
    if (now >= expires) {
        reason = GrantRejectReason::EXPIRED;
        err = "expired";
        return true;
    }
    if (seen_nonces.count(body["grant_nonce"].get_str())) {
        reason = GrantRejectReason::REPLAY;
        err = "replay";
        return true;
    }
    err.clear();
    return false;
}

UniValue SignedGrantToJson(const SignedFreeGrant& g)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("grant_type", "FREE");
    o.pushKV("signed", !g.signature.empty());
    o.pushKV("object_id", [&] {
        Digest48 id;
        std::string err;
        RecordId(RECORD_FREE_GRANT, g.body, id, err);
        return id.Hex();
    }());
    if (g.body.isObject()) {
        for (const auto& k : g.body.getKeys()) {
            if (k != "price_atoms" && k != "fee_atoms" && k != "address") o.pushKV(k, g.body[k]);
        }
    }
    o.pushKV("payload_hex", HexStr(g.payload));
    o.pushKV("sig_hex", HexStr(g.signature));
    o.pushKV("pubkey_hex", HexStr(g.pubkey));
    o.pushKV("note", "no payment script, address, fee or chain field");
    return o;
}

bool EncodeGrantEnvelope(const SignedFreeGrant& g, std::vector<unsigned char>& out, std::string& err)
{
    (void)err;
    out.clear();
    out.insert(out.end(), g.payload.begin(), g.payload.end());
    out.insert(out.end(), g.signature.begin(), g.signature.end());
    return !out.empty();
}

bool GrantUseConflicts(const UniValue& arr, const std::string& use_key, std::string& err)
{
    const bool file_all = use_key.find(":all") != std::string::npos;
    const std::string file_prefix = use_key.substr(0, use_key.find(':'));
    for (const auto& v : arr.getValues()) {
        if (!v.isStr()) continue;
        const std::string& have = v.get_str();
        if (have == use_key) {
            // A redemption is single-use. Retrying the same piece must not
            // serve the bytes again without a new grant.
            err = "replay";
            return true;
        }
        if (file_all && have.rfind(file_prefix + ":", 0) == 0) {
            err = "replay";
            return true;
        }
        if (!file_all && have == file_prefix + ":all") {
            err = "replay";
            return true;
        }
    }
    return false;
}

uint64_t RedeemedBytes(const UniValue& store, const std::string& nonce_hex)
{
    if (!store.exists("redeemed_bytes") || !store["redeemed_bytes"].isObject()) return 0;
    const UniValue& bytes = store["redeemed_bytes"];
    if (!bytes.exists(nonce_hex) || !bytes[nonce_hex].isNum()) return 0;
    return bytes[nonce_hex].getInt<uint64_t>();
}

bool RedeemGrantUseUnlocked(UniValue& store, const std::string& nonce_hex, const std::string& use_key,
                            uint64_t redeem_bytes, uint64_t maximum_bytes, std::string& err)
{
    if (nonce_hex.size() != 64 || use_key.empty()) {
        err = "grant_nonce";
        return false;
    }
    UniValue used = store.exists("uses") ? store["uses"] : UniValue(UniValue::VOBJ);
    UniValue arr = used.exists(nonce_hex) ? used[nonce_hex] : UniValue(UniValue::VARR);
    if (GrantUseConflicts(arr, use_key, err)) return false;
    if (arr.size() >= FREE_GRANT_MAX_USES) {
        err = "grant use cap";
        return false;
    }
    const uint64_t already = RedeemedBytes(store, nonce_hex);
    if (maximum_bytes > 0 &&
        (redeem_bytes > maximum_bytes || already > maximum_bytes - redeem_bytes)) {
        err = "maximum_bytes";
        return false;
    }
    arr.push_back(use_key);
    used.pushKV(nonce_hex, arr);
    store.pushKV("uses", used);
    UniValue bytes = store.exists("redeemed_bytes") && store["redeemed_bytes"].isObject()
                         ? store["redeemed_bytes"]
                         : UniValue(UniValue::VOBJ);
    bytes.pushKV(nonce_hex, already + redeem_bytes);
    store.pushKV("redeemed_bytes", bytes);
    return true;
}

bool VerifyHostedFreeGrant(const fs::path& helper_dir,
                           Span<const unsigned char> payload,
                           Span<const unsigned char> sig,
                           Span<const unsigned char> presented_pk,
                           int64_t now,
                           const std::string& use_key,
                           UniValue& body,
                           std::string& err,
                           bool record_use,
                           uint64_t redeem_bytes)
{
    std::vector<unsigned char> host_pk, host_sk;
    Digest48 signer_id;
    if (!LoadOrCreateServiceIdentity(helper_dir, host_pk, host_sk, signer_id, err)) return false;
    if (!presented_pk.empty() &&
        (presented_pk.size() != host_pk.size() ||
         !std::equal(presented_pk.begin(), presented_pk.end(), host_pk.begin()))) {
        err = "grant identity";
        return false;
    }
    std::lock_guard<std::mutex> lock(g_grant_store_mu);
    if (!VerifyFreeGrant(payload, sig, host_pk, now, {}, body, err)) return false;
    uint64_t maximum_bytes = 0;
    if (body.exists("maximum_bytes") && body["maximum_bytes"].isNum()) {
        maximum_bytes = body["maximum_bytes"].getInt<uint64_t>();
    }
    UniValue store;
    if (!ReadOrQuarantine(helper_dir / "grant_redeems.json", store)) {
        err = "grant redeem store";
        return false;
    }
    const std::string nonce = body.exists("grant_nonce") && body["grant_nonce"].isStr() ? body["grant_nonce"].get_str() : "";
    UniValue used = store.exists("uses") && store["uses"].isObject() ? store["uses"] : UniValue(UniValue::VOBJ);
    UniValue arr = used.exists(nonce) ? used[nonce] : UniValue(UniValue::VARR);
    if (!arr.isArray()) arr = UniValue(UniValue::VARR);
    if (GrantUseConflicts(arr, use_key, err)) return false;
    if (!record_use) return true;
    if (!RedeemGrantUseUnlocked(store, nonce, use_key, redeem_bytes, maximum_bytes, err)) return false;
    {
        UniValue exp = store.exists("expires_at") && store["expires_at"].isObject() ? store["expires_at"] : UniValue(UniValue::VOBJ);
        int64_t until = now + FREE_GRANT_LIFETIME_S;
        if (body.exists("expires_at") && body["expires_at"].isNum()) {
            try {
                until = body["expires_at"].getInt<int64_t>();
            } catch (...) {
            }
        }
        exp.pushKV(nonce, until);
        store.pushKV("expires_at", exp);
    }
    PruneExpiredUses(store, now);
    return WriteObj(helper_dir / "grant_redeems.json", store, err);
}

bool ConsumeGrantNonce(const fs::path& helper_dir, const std::string& nonce_hex, uint64_t& sequence, std::string& err)
{
    if (nonce_hex.size() != 64) {
        err = "grant_nonce";
        return false;
    }
    std::lock_guard<std::mutex> lock(g_grant_store_mu);
    UniValue store;
    if (!ReadOrQuarantine(helper_dir / "grant_nonces.json", store)) {
        err = "grant nonce store";
        return false;
    }
    UniValue arr = store.exists("nonces") && store["nonces"].isArray() ? store["nonces"] : UniValue(UniValue::VARR);
    for (const auto& n : arr.getValues()) {
        if (n.isStr() && n.get_str() == nonce_hex) {
            err = "replay";
            return false;
        }
    }
    constexpr size_t kGrantNonceCap = 4096;
    UniValue kept(UniValue::VARR);
    const auto values = arr.getValues();
    const size_t start = values.size() > kGrantNonceCap - 1 ? values.size() - (kGrantNonceCap - 1) : 0;
    for (size_t i = start; i < values.size(); ++i) {
        kept.push_back(values[i]);
    }
    kept.push_back(nonce_hex);
    store.pushKV("nonces", kept);
    uint64_t seq = 1;
    if (store.exists("sequence") && store["sequence"].isNum()) {
        try {
            seq = store["sequence"].getInt<uint64_t>() + 1;
        } catch (...) {
        }
    }
    store.pushKV("sequence", seq);
    sequence = seq;
    return WriteObj(helper_dir / "grant_nonces.json", store, err);
}

bool LoadOrCreateServiceIdentity(const fs::path& helper_dir,
                                std::vector<unsigned char>& pk,
                                std::vector<unsigned char>& sk,
                                Digest48& signer_id,
                                std::string& err)
{
    std::lock_guard<std::mutex> lock(g_grant_store_mu);
    UniValue store;
    ReadObj(helper_dir / "grant_identity.json", store);
    if (store.exists("pk_hex") && store.exists("sk_hex")) {
        auto pkb = TryParseHex<unsigned char>(store["pk_hex"].get_str());
        auto skb = TryParseHex<unsigned char>(store["sk_hex"].get_str());
        if (pkb && skb) {
            pk = *pkb;
            sk = *skb;
            signer_id = ServiceSignerId(pk);
            return true;
        }
    }
    if (!GenerateMlDsa44(pk, sk, err)) return false;
    signer_id = ServiceSignerId(pk);
    store.pushKV("pk_hex", HexStr(pk));
    store.pushKV("sk_hex", HexStr(sk));
    store.pushKV("signer_id", signer_id.Hex());
    return WriteObj(helper_dir / "grant_identity.json", store, err);
}

} // namespace modelnet
