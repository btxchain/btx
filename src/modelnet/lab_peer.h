// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAB_PEER_H
#define BITCOIN_MODELNET_LAB_PEER_H

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

struct PeerRecord {
    bool exists{false};
    bool is_private{false};
    std::string body;
};

struct PeerView {
    virtual ~PeerView() = default;
    virtual bool Record(const std::string& id, PeerRecord& out) const = 0;
    virtual bool Piece(const std::string& model_digest, uint64_t index, std::string& bytes) const = 0;
    virtual bool Channel(const std::string& realm_id, const std::string& channel, int64_t& sequence, std::string& update_id) const = 0;
    virtual bool Realm(const std::string& realm_id, std::string& policy_id, int& threshold) const = 0;
    virtual void PublicResearch(std::vector<std::string>& ids) const = 0;
    virtual bool Ticket(const std::string& ticket_id) const = 0;
    virtual bool VerifySession(const std::string& message, const std::string& signature_hex) const = 0;
};

/** Dispatch one `/btx-model/3/` peer route. Failure leaves `response_json` empty and `err` a BTX035_* code. */
bool DispatchPeerRoute(const std::string& route, const std::string& request_json, const PeerView& view,
                       std::string& response_json, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAB_PEER_H
