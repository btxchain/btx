// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/transfer.h>

#include <modelnet/crypto.h>
#include <random.h>
#include <tinyformat.h>
#include <util/strencodings.h>

#include <span.h>
#include <cctype>
#include <ctime>
#include <fstream>
#include <limits>

namespace modelnet {

bool DuplicatePayment(const std::vector<PaymentJournal>& journal, const std::string& txid)
{
    for (const auto& e : journal) {
        if (e.txid == txid) return true;
    }
    return false;
}

bool RangesOverlap(uint32_t file_a, uint32_t first_a, uint32_t count_a,
                   uint32_t file_b, uint32_t first_b, uint32_t count_b)
{
    if (count_a == 0 || count_b == 0) return false;
    if (file_a != file_b) return false;
    const uint64_t a0 = first_a;
    const uint64_t a1 = uint64_t{first_a} + count_a;
    const uint64_t b0 = first_b;
    const uint64_t b1 = uint64_t{first_b} + count_b;
    return a0 < b1 && b0 < a1;
}

bool DuplicateReservedRange(const std::vector<PaymentJournal>& journal,
                            uint32_t file_index, uint32_t first_piece, uint32_t piece_count)
{
    if (piece_count == 0) return false;
    for (const auto& e : journal) {
        if (e.piece_count == 0) continue;
        if (RangesOverlap(e.file_index, e.first_piece, e.piece_count, file_index, first_piece, piece_count)) {
            return true;
        }
    }
    return false;
}

int EtaWithFees(int queue_s, int conf_s, int64_t fee_atoms, int mempool_s)
{
    if (queue_s < 0 || conf_s < 0 || mempool_s < 0 || fee_atoms < 0) return -1;
    int eta = queue_s;
    if (fee_atoms > 0) {
        if (conf_s > std::numeric_limits<int>::max() - eta) return -1;
        eta += conf_s;
        if (mempool_s > std::numeric_limits<int>::max() - eta) return -1;
        eta += mempool_s;
    }
    return eta;
}

bool QuoteMayBeTakenAsFree(const Quote& accepted, const UniValue& requester_json)
{
    (void)requester_json;
    return accepted.price_atoms == 0 && accepted.fee_cap_atoms <= 0;
}

bool QuoteMutationRequiresReapproval(const Quote& approved, const Quote& observed)
{
    if (approved.offer_id != observed.offer_id) return true;
    if (approved.provider_id != observed.provider_id) return true;
    if (approved.model_id != observed.model_id) return true;
    if (approved.artifact_id != observed.artifact_id) return true;
    if (approved.file_index != observed.file_index) return true;
    if (approved.first_piece != observed.first_piece) return true;
    if (approved.piece_count != observed.piece_count) return true;
    if (approved.maximum_bytes != observed.maximum_bytes) return true;
    if (approved.price_atoms != observed.price_atoms) return true;
    if (approved.fee_cap_atoms != observed.fee_cap_atoms) return true;
    return false;
}

bool ApplyPaymentDelivery(PaymentJournal& e, bool reorg_hold_active, std::string& err)
{
    if (e.txid.empty()) {
        err = "txid required";
        return false;
    }
    e.accepted = true;
    if (reorg_hold_active) {
        e.delivered = false;
        e.held_for_reorg = true;
        err = "reorg payment hold; reserved range not credited";
        return false;
    }
    e.held_for_reorg = false;
    e.delivered = true;
    err.clear();
    return true;
}

bool ReleaseReorgHold(std::vector<PaymentJournal>& journal, const std::string& txid, std::string& err)
{
    if (txid.empty()) {
        err = "txid required";
        return false;
    }
    for (auto& e : journal) {
        if (e.txid != txid) continue;
        return ApplyPaymentDelivery(e, /*reorg_hold_active=*/false, err);
    }
    err = "txid not in journal";
    return false;
}

bool RemainingUndeliveredRange(const std::vector<PaymentJournal>& journal,
                                uint32_t file_index, uint32_t first_piece, uint32_t piece_count,
                                uint32_t& out_first, uint32_t& out_count)
{
    out_first = 0;
    out_count = 0;
    if (piece_count == 0) return false;
    auto delivered = [&](uint32_t piece) {
        for (const auto& e : journal) {
            if (!e.delivered || e.piece_count == 0) continue;
            if (RangesOverlap(e.file_index, e.first_piece, e.piece_count, file_index, piece, 1)) {
                return true;
            }
        }
        return false;
    };
    bool in_hole = false;
    for (uint32_t i = 0; i < piece_count; ++i) {
        const uint32_t piece = first_piece + i;
        if (delivered(piece)) {
            if (in_hole) break;
            continue;
        }
        if (!in_hole) {
            out_first = piece;
            out_count = 1;
            in_hole = true;
        } else {
            ++out_count;
        }
    }
    return in_hole;
}

UniValue QuoteToJson(const Quote& q)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("schema_version", 2);
    o.pushKV("offer_id", q.offer_id.Hex());
    o.pushKV("provider_id", q.provider_id.Hex());
    o.pushKV("buyer_id", q.buyer_id.Hex());
    o.pushKV("model_id", q.model_id.Hex());
    o.pushKV("artifact_id", q.artifact_id.Hex());
    o.pushKV("file_index", static_cast<int>(q.file_index));
    o.pushKV("first_piece", static_cast<int>(q.first_piece));
    o.pushKV("piece_count", static_cast<int>(q.piece_count));
    o.pushKV("maximum_bytes", q.maximum_bytes);
    o.pushKV("price_atoms", q.price_atoms);
    o.pushKV("fee_cap_atoms", q.fee_cap_atoms);
    o.pushKV("expires_at", q.expires_at);
    o.pushKV("automatic_spend_atoms", 0);
    o.pushKV("settlement", "0.34.6 htlc_sha256 / buildhtlcclaim / buildhtlcrefund");
    o.pushKV("note", "Quote is not an inference tariff. Chain settlement is wallet-side. Helper does not spend.");
    return o;
}

bool QuoteFromJson(const UniValue& o, Quote& q, std::string& err)
{
    q = {};
    if (!Digest48::FromHex(o["offer_id"].get_str(), q.offer_id, err)) return false;
    if (o.exists("provider_id") && !o["provider_id"].get_str().empty()) {
        if (!Digest48::FromHex(o["provider_id"].get_str(), q.provider_id, err)) return false;
    }
    if (o.exists("buyer_id") && !o["buyer_id"].get_str().empty() && o["buyer_id"].get_str() != std::string(96, '0')) {
        if (!Digest48::FromHex(o["buyer_id"].get_str(), q.buyer_id, err)) return false;
    }
    if (!Digest48::FromHex(o["model_id"].get_str(), q.model_id, err)) return false;
    if (o.exists("artifact_id") && !o["artifact_id"].get_str().empty()) {
        if (!Digest48::FromHex(o["artifact_id"].get_str(), q.artifact_id, err)) return false;
    }
    q.file_index = o.exists("file_index") ? o["file_index"].getInt<uint32_t>() : 0;
    q.first_piece = o.exists("first_piece") ? o["first_piece"].getInt<uint32_t>() : 0;
    q.piece_count = o.exists("piece_count") ? o["piece_count"].getInt<uint32_t>() : 0;
    q.maximum_bytes = o.exists("maximum_bytes") ? o["maximum_bytes"].getInt<uint64_t>() : 0;
    q.price_atoms = o.exists("price_atoms") ? o["price_atoms"].getInt<int64_t>() : 0;
    q.fee_cap_atoms = o.exists("fee_cap_atoms") ? o["fee_cap_atoms"].getInt<int64_t>() : 0;
    q.expires_at = o.exists("expires_at") ? o["expires_at"].getInt<int64_t>() : 0;
    return true;
}

bool LoadPaymentState(const fs::path& dir, std::vector<Quote>& quotes, std::vector<PaymentJournal>& journal, std::string& err)
{
    quotes.clear();
    journal.clear();
    const fs::path path = dir / "quotes.json";
    if (!fs::exists(path)) return true;
    std::ifstream in(path);
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    UniValue o;
    if (!o.read(raw) || !o.isObject()) {
        err = "quotes.json";
        return false;
    }
    if (o.exists("quotes")) {
        for (const auto& qj : o["quotes"].getValues()) {
            Quote q;
            if (!QuoteFromJson(qj, q, err)) return false;
            quotes.push_back(q);
        }
    }
    if (o.exists("journal")) {
        for (const auto& jj : o["journal"].getValues()) {
            PaymentJournal e;
            e.quote_id = jj["quote_id"].get_str();
            e.txid = jj["txid"].get_str();
            e.accepted = jj.exists("accepted") && jj["accepted"].get_bool();
            e.delivered = jj.exists("delivered") && jj["delivered"].get_bool();
            e.held_for_reorg = jj.exists("held_for_reorg") && jj["held_for_reorg"].get_bool();
            e.file_index = jj.exists("file_index") ? jj["file_index"].getInt<uint32_t>() : 0;
            e.first_piece = jj.exists("first_piece") ? jj["first_piece"].getInt<uint32_t>() : 0;
            e.piece_count = jj.exists("piece_count") ? jj["piece_count"].getInt<uint32_t>() : 0;
            journal.push_back(e);
        }
    }
    return true;
}

bool SavePaymentState(const fs::path& dir, const std::vector<Quote>& quotes, const std::vector<PaymentJournal>& journal, std::string& err)
{
    UniValue o(UniValue::VOBJ);
    UniValue qa(UniValue::VARR);
    for (const auto& q : quotes) qa.push_back(QuoteToJson(q));
    UniValue ja(UniValue::VARR);
    for (const auto& e : journal) {
        UniValue j(UniValue::VOBJ);
        j.pushKV("quote_id", e.quote_id);
        j.pushKV("txid", e.txid);
        j.pushKV("accepted", e.accepted);
        j.pushKV("delivered", e.delivered);
        j.pushKV("held_for_reorg", e.held_for_reorg);
        j.pushKV("file_index", static_cast<int64_t>(e.file_index));
        j.pushKV("first_piece", static_cast<int64_t>(e.first_piece));
        j.pushKV("piece_count", static_cast<int64_t>(e.piece_count));
        ja.push_back(j);
    }
    o.pushKV("quotes", qa);
    o.pushKV("journal", ja);
    fs::create_directories(dir);
    std::ofstream out(dir / "quotes.json", std::ios::trunc);
    if (!out) {
        err = "quotes.json write";
        return false;
    }
    out << o.write() << "\n";
    return true;
}

bool MakePrepaidQuote(Quote& q, const Digest48& model_id, const Digest48& artifact_id, uint32_t first_piece,
                      uint32_t piece_count, int64_t price_atoms, std::string& err)
{
    q = {};
    unsigned char nonce[32];
    GetStrongRandBytes(Span<unsigned char>{nonce, 32});
    q.offer_id = DomainHash("BTX/QuoteOffer/v1", Span<const unsigned char>{nonce, 32});
    q.model_id = model_id;
    q.artifact_id = artifact_id;
    q.first_piece = first_piece;
    q.piece_count = piece_count;
    q.maximum_bytes = uint64_t{piece_count} * PIECE_SIZE;
    q.price_atoms = price_atoms;
    q.expires_at = static_cast<int64_t>(std::time(nullptr)) + 3600;
    (void)err;
    return true;
}

namespace {
bool HexToken(const std::string& s, size_t want)
{
    if (s.size() != want * 2) return false;
    for (char c : s) {
        if (!std::isxdigit(static_cast<unsigned char>(c))) return false;
    }
    return true;
}
} // namespace

std::string HtlcSha256Descriptor(const std::string& key_hash_hex,
                                const std::string& claimant,
                                uint32_t refund_height,
                                const std::string& refund_pubkey)
{
    return strprintf("mr(htlc_sha256(%s,%s),refund(%u,%s))", key_hash_hex, claimant, refund_height, refund_pubkey);
}

std::string FundingFingerprint(const FrozenModelFunding& f)
{
    const std::string canon = f.descriptor + "|" + strprintf("%d", f.amount_atoms) + "|" + f.key_hash_hex + "|" +
                               strprintf("%u", f.refund_height) + "|" + f.claimant + "|" + f.refund_pubkey;
    return DomainHash("BTX/ModelFunding/v1", Span<const unsigned char>{
                         reinterpret_cast<const unsigned char*>(canon.data()), canon.size()}).Hex();
}

bool FreezeModelFunding(const FrozenModelFunding& in, FrozenModelFunding& out, std::string& err)
{
    out = in;
    if (in.amount_atoms <= 0 || in.amount_atoms > MAX_MONEY_ATOMS) {
        err = "amount_atoms";
        return false;
    }
    if (in.max_atoms < in.amount_atoms) {
        err = "amount exceeds approved max_atoms";
        return false;
    }
    if (!HexToken(ToLower(in.key_hash_hex), 32)) {
        err = "key_hash must be 32-byte SHA-256 hex";
        return false;
    }
    if (in.claimant.empty() || in.refund_pubkey.empty()) {
        err = "claimant and refund_pubkey required";
        return false;
    }
    if (in.refund_height == 0) {
        err = "refund_height";
        return false;
    }
    out.key_hash_hex = ToLower(in.key_hash_hex);
    out.descriptor = HtlcSha256Descriptor(out.key_hash_hex, in.claimant, in.refund_height, in.refund_pubkey);
    out.fingerprint = FundingFingerprint(out);
    return true;
}

bool FundingUnchanged(const FrozenModelFunding& frozen, const FrozenModelFunding& now, std::string& err)
{
    if (frozen.fingerprint.empty() || now.fingerprint != frozen.fingerprint) {
        err = "quote or cohort mutated; preparemodelfunding again";
        return false;
    }
    return true;
}

} // namespace modelnet
