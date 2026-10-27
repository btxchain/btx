// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_CHANNEL_H
#define BITCOIN_MODELNET_SWARM_CHANNEL_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

struct SwarmHtlcLot {
    bool ok{false};
    std::string code;
    std::vector<unsigned char> sponsor_pubkey;
    std::vector<unsigned char> claimant_pubkey;
    std::vector<unsigned char> preimage_hash;
    int64_t refund_height{0};
    std::vector<unsigned char> claim_script;
    std::vector<unsigned char> refund_script;
};

SwarmHtlcLot SwarmBuildHtlcLot(const std::vector<unsigned char>& sponsor_pubkey,
                               const std::vector<unsigned char>& claimant_pubkey,
                               const std::vector<unsigned char>& preimage_hash,
                               int64_t refund_height);

bool SwarmAmendHtlcRefund(SwarmHtlcLot& lot, int64_t new_height, const std::vector<unsigned char>& new_sponsor);

struct SwarmMonotonic {
    std::string id;
    std::string payer;
    std::string recipient;
    int64_t capacity{0};
    int64_t fee_reserve{0};
    int refund_height{0};
    int close_margin{160};
    int sequence{0};
    int64_t cumulative{0};
    bool refund_signed{false};
    bool funded{false};
    bool spend_key_present{false};
};

bool SwarmSignRefund(SwarmMonotonic& channel, std::string& err);
bool SwarmNoteFunding(SwarmMonotonic& channel, int confirmations, std::string& err);
bool SwarmOffer(const SwarmMonotonic& channel, int sequence, int64_t cumulative, int height, std::string& err);
bool SwarmAcceptOffer(SwarmMonotonic& channel, int sequence, int64_t cumulative, int height, std::string& err);

struct SwarmRouteEdge {
    std::string id;
    std::string source;
    std::string target;
    int64_t liquidity{0};
    int64_t base_fee{0};
    int64_t ppm_fee{0};
    int cltv_delta{160};
    bool active{true};
};

struct SwarmRouteHop {
    std::string edge;
    std::string source;
    std::string target;
    int64_t forward_atoms{0};
    int outgoing_expiry{0};
};

struct SwarmRoute {
    bool ok{false};
    std::string code;
    std::vector<SwarmRouteHop> hops;
    int64_t send_atoms{0};
    int64_t receive_atoms{0};
    int64_t fee_atoms{0};
    int incoming_expiry{0};
};

SwarmRoute SwarmRoutePayment(const std::vector<SwarmRouteEdge>& edges, const std::string& source, const std::string& destination,
                             int64_t amount, int final_expiry, int current_height, int64_t max_fee, int max_hops, int max_expiry_delta);

struct SwarmConditional {
    int64_t capacity{0};
    int64_t settled{0};
    std::map<std::string, int64_t> amounts;
    std::map<std::string, std::string> hashes;
    std::map<std::string, int> expiries;
    std::map<std::string, std::string> history;
};

bool SwarmLockPayment(SwarmConditional& box, const std::string& id, int64_t amount, const std::string& payment_hash, int expiry, int height, std::string& err);
bool SwarmResolvePayment(SwarmConditional& box, const std::string& id, const std::vector<unsigned char>& preimage, int height, std::string& err);
bool SwarmExpirePayment(SwarmConditional& box, const std::string& id, int height, std::string& err);
bool SwarmPaymentsConserved(const SwarmConditional& box);

struct SwarmWatch {
    std::string action;
    bool secp_penalty{false};
    bool hashlock_remedy{false};
};

SwarmWatch SwarmWatchtower(int observed_sequence, int latest_sequence, int height, int refund_height, int close_margin, bool prior_secret_released);

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_CHANNEL_H
