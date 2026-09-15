// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_FREE_GRANT_H
#define BITCOIN_MODELNET_FREE_GRANT_H

#include <modelnet/records.h>
#include <modelnet/types.h>
#include <span.h>
#include <univalue.h>
#include <util/fs.h>

#include <cstdint>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

constexpr int64_t FREE_GRANT_LIFETIME_S = 600;
constexpr int64_t FREE_GRANT_MAX_TTL_S = FREE_GRANT_LIFETIME_S;

enum class GrantRejectReason : uint8_t {
    NONE = 0,
    EXPIRED = 1,
    TAMPERED = 2,
    REPLAY = 3,
};

struct FreeGrantParams {
    uint64_t sequence{1};
    int64_t issued_at{0};
    int64_t expires_at{0};
    Digest48 buyer_id;
    Digest48 model_id;
    Digest48 artifact_id;
    uint32_t file_index{0};
    uint32_t first_piece{0};
    uint32_t piece_count{0};
    uint64_t maximum_bytes{0};
    Hash32 grant_nonce;
    Hash32 transfer_id;
    uint8_t queue_class{0};
};

struct SignedFreeGrant {
    UniValue body;
    std::vector<unsigned char> payload;
    std::vector<unsigned char> signature;
    std::vector<unsigned char> pubkey;
    Digest48 object_id;
};

bool GrantHasPaymentFields(const UniValue& body);
inline bool GrantRequestHasPaymentFields(const UniValue& body) { return GrantHasPaymentFields(body); }

Digest48 ServiceSignerId(Span<const unsigned char> pubkey);

bool IssueFreeGrant(const FreeGrantParams& p,
                    Span<const unsigned char> sk,
                    Span<const unsigned char> pk,
                    SignedFreeGrant& out,
                    std::string& err);

bool VerifyFreeGrant(Span<const unsigned char> payload,
                     Span<const unsigned char> sig,
                     Span<const unsigned char> pk,
                     int64_t now,
                     const std::set<std::string>& seen_nonces,
                     UniValue& body,
                     std::string& err);

bool RejectExpiredTamperedReplay(Span<const unsigned char> payload,
                                  Span<const unsigned char> sig,
                                  Span<const unsigned char> pk,
                                  int64_t now,
                                  const std::set<std::string>& seen_nonces,
                                  GrantRejectReason& reason,
                                  std::string& err);

UniValue SignedGrantToJson(const SignedFreeGrant& g);
bool EncodeGrantEnvelope(const SignedFreeGrant& g, std::vector<unsigned char>& out, std::string& err);

bool ConsumeGrantNonce(const fs::path& helper_dir, const std::string& nonce_hex, uint64_t& sequence, std::string& err);
bool LoadOrCreateServiceIdentity(const fs::path& helper_dir,
                                std::vector<unsigned char>& pk,
                                std::vector<unsigned char>& sk,
                                Digest48& signer_id,
                                std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_FREE_GRANT_H
