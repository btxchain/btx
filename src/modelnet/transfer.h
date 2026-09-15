// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_TRANSFER_H
#define BITCOIN_MODELNET_TRANSFER_H

#include <modelnet/types.h>
#include <univalue.h>
#include <util/fs.h>

#include <string>
#include <vector>

namespace modelnet {

struct Quote {
    Digest48 offer_id;
    Digest48 provider_id;
    Digest48 buyer_id;
    Digest48 model_id;
    Digest48 artifact_id;
    uint32_t file_index{0};
    uint32_t first_piece{0};
    uint32_t piece_count{0};
    uint64_t maximum_bytes{0};
    int64_t price_atoms{0};
    int64_t fee_cap_atoms{0};
    int64_t expires_at{0};
};

struct PaymentJournal {
    std::string quote_id;
    std::string txid;
    bool accepted{false};
    bool delivered{false};
    bool held_for_reorg{false};
    uint32_t file_index{0};
    uint32_t first_piece{0};
    uint32_t piece_count{0};
};

bool DuplicatePayment(const std::vector<PaymentJournal>& journal, const std::string& txid);

/** Half-open [first, first+count). count 0 is not a range (never overlaps). */
bool RangesOverlap(uint32_t file_a, uint32_t first_a, uint32_t count_a,
                   uint32_t file_b, uint32_t first_b, uint32_t count_b);

/** True if any journal entry with piece_count>0 overlaps the given range. */
bool DuplicateReservedRange(const std::vector<PaymentJournal>& journal,
                            uint32_t file_index, uint32_t first_piece, uint32_t piece_count);

/** Queue + confirmation + mempool when a fee is required. Negative inputs return -1. */
int EtaWithFees(int queue_s, int conf_s, int64_t fee_atoms, int mempool_s);

/** Accepted quote terms are authoritative; requester JSON price=0 cannot make a paid quote free. */
bool QuoteMayBeTakenAsFree(const Quote& accepted, const UniValue& requester_json);

/** True when signed quote terms changed and a new approval is required. */
bool QuoteMutationRequiresReapproval(const Quote& approved, const Quote& observed);

/** PAY-05: reorg hold reserves the range but does not credit pieces. */
bool ApplyPaymentDelivery(PaymentJournal& e, bool reorg_hold_active, std::string& err);
/** Credit a previously held journal txid once the reorg hold clears. */
bool ReleaseReorgHold(std::vector<PaymentJournal>& journal, const std::string& txid, std::string& err);

/** PAY-09: first contiguous undelivered subrange of [first, first+count). False if nothing remains. */
bool RemainingUndeliveredRange(const std::vector<PaymentJournal>& journal,
                                uint32_t file_index, uint32_t first_piece, uint32_t piece_count,
                                uint32_t& out_first, uint32_t& out_count);

UniValue QuoteToJson(const Quote& q);
bool QuoteFromJson(const UniValue& o, Quote& q, std::string& err);
bool LoadPaymentState(const fs::path& dir, std::vector<Quote>& quotes, std::vector<PaymentJournal>& journal, std::string& err);
bool SavePaymentState(const fs::path& dir, const std::vector<Quote>& quotes, const std::vector<PaymentJournal>& journal, std::string& err);
bool MakePrepaidQuote(Quote& q, const Digest48& model_id, const Digest48& artifact_id, uint32_t first_piece,
                      uint32_t piece_count, int64_t price_atoms, std::string& err);

struct FrozenModelFunding {
    std::string descriptor;
    std::string key_hash_hex;
    std::string claimant;
    std::string refund_pubkey;
    uint32_t refund_height{0};
    int64_t amount_atoms{0};
    int64_t max_atoms{0};
    std::string fingerprint;
};

std::string HtlcSha256Descriptor(const std::string& key_hash_hex,
                                const std::string& claimant,
                                uint32_t refund_height,
                                const std::string& refund_pubkey);
std::string FundingFingerprint(const FrozenModelFunding& f);
bool FreezeModelFunding(const FrozenModelFunding& in, FrozenModelFunding& out, std::string& err);
bool FundingUnchanged(const FrozenModelFunding& frozen, const FrozenModelFunding& now, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_TRANSFER_H
