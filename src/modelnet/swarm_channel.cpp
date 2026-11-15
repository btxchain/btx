// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_channel.h>

#include <crypto/sha256.h>
#include <pqkey.h>
#include <script/pqm.h>
#include <span.h>
#include <util/strencodings.h>

#include <queue>
#include <set>

namespace modelnet {
namespace {

int64_t EdgeFee(const SwarmRouteEdge& edge, int64_t amount)
{
    return edge.base_fee + (amount * edge.ppm_fee + 999999) / 1000000;
}

struct Search {
    int64_t needed{0};
    int counter{0};
    int hops{0};
    std::string node;
    int expiry{0};
    std::vector<SwarmRouteHop> path;
    std::vector<std::string> visited;
};

struct SearchOrder {
    bool operator()(const Search& a, const Search& b) const
    {
        if (a.needed != b.needed) return a.needed > b.needed;
        return a.counter > b.counter;
    }
};

} // namespace

SwarmHtlcLot SwarmBuildHtlcLot(const std::vector<unsigned char>& sponsor_pubkey,
                               const std::vector<unsigned char>& claimant_pubkey,
                               const std::vector<unsigned char>& preimage_hash,
                               int64_t refund_height)
{
    SwarmHtlcLot lot;
    lot.sponsor_pubkey = sponsor_pubkey;
    lot.claimant_pubkey = claimant_pubkey;
    lot.preimage_hash = preimage_hash;
    lot.refund_height = refund_height;
    if (refund_height < 1 || preimage_hash.size() != 32 || sponsor_pubkey.size() != MLDSA44_PUBKEY_SIZE ||
        claimant_pubkey.size() != MLDSA44_PUBKEY_SIZE) {
        lot.code = "HTLC_LOT";
        return lot;
    }
    lot.claim_script = BuildP2MRHTLCSha256Leaf(preimage_hash, PQAlgorithm::ML_DSA_44, claimant_pubkey);
    lot.refund_script = BuildP2MRRefundLeaf(refund_height, PQAlgorithm::ML_DSA_44, sponsor_pubkey);
    if (lot.claim_script.empty() || lot.refund_script.empty()) {
        lot.code = "HTLC_SCRIPT";
        return lot;
    }
    lot.ok = true;
    lot.code = "LOT";
    return lot;
}

bool SwarmAmendHtlcRefund(SwarmHtlcLot& lot, int64_t new_height, const std::vector<unsigned char>& new_sponsor)
{
    (void)new_height;
    (void)new_sponsor;
    return false;
}

bool SwarmSignRefund(SwarmMonotonic& channel, std::string& err)
{
    if (channel.spend_key_present) {
        err = "SPEND_KEY_FORBIDDEN";
        return false;
    }
    if (channel.capacity <= 0 || channel.fee_reserve < 0 || channel.fee_reserve >= channel.capacity || channel.refund_height < 1) {
        err = "CHANNEL";
        return false;
    }
    channel.refund_signed = true;
    err.clear();
    return true;
}

bool SwarmNoteFunding(SwarmMonotonic& channel, int confirmations, std::string& err)
{
    if (!channel.refund_signed) {
        err = "REFUND_NOT_SIGNED";
        return false;
    }
    if (confirmations < 1) {
        err = "UNCONFIRMED";
        channel.funded = false;
        return false;
    }
    channel.funded = true;
    err.clear();
    return true;
}

bool SwarmOffer(const SwarmMonotonic& channel, int sequence, int64_t cumulative, int height, std::string& err)
{
    if (!channel.funded) {
        err = "CHANNEL_UNFUNDED";
        return false;
    }
    if (sequence <= channel.sequence) {
        err = "STALE_VOUCHER";
        return false;
    }
    if (cumulative < channel.cumulative) {
        err = "DECREASING_PAYMENT";
        return false;
    }
    if (cumulative + channel.fee_reserve > channel.capacity) {
        err = "CHANNEL_CAPACITY";
        return false;
    }
    if (height + channel.close_margin >= channel.refund_height) {
        err = "CHANNEL_DRAINING";
        return false;
    }
    err.clear();
    return true;
}

bool SwarmAcceptOffer(SwarmMonotonic& channel, int sequence, int64_t cumulative, int height, std::string& err)
{
    if (!SwarmOffer(channel, sequence, cumulative, height, err)) return false;
    channel.sequence = sequence;
    channel.cumulative = cumulative;
    return true;
}

SwarmRoute SwarmRoutePayment(const std::vector<SwarmRouteEdge>& edges, const std::string& source, const std::string& destination,
                             int64_t amount, int final_expiry, int current_height, int64_t max_fee, int max_hops, int max_expiry_delta)
{
    SwarmRoute route;
    if (amount <= 0 || final_expiry <= current_height || max_hops < 1 || max_hops > 12 || max_fee < 0) {
        route.code = "AMOUNT";
        return route;
    }
    std::priority_queue<Search, std::vector<Search>, SearchOrder> queue;
    int counter = 0;
    queue.push(Search{amount, counter++, 0, destination, final_expiry, {}, {}});
    int scanned = 0;
    while (!queue.empty()) {
        Search cur = queue.top();
        queue.pop();
        if (++scanned > 100000) {
            route.code = "ROUTE_SEARCH_LIMIT";
            return route;
        }
        if (cur.node == source) {
            route.ok = true;
            route.code = "ROUTE";
            route.hops = cur.path;
            route.send_atoms = cur.needed;
            route.receive_atoms = amount;
            route.fee_atoms = cur.needed - amount;
            route.incoming_expiry = cur.expiry;
            return route;
        }
        if (cur.hops >= max_hops) continue;
        for (const SwarmRouteEdge& edge : edges) {
            if (!edge.active || edge.target != cur.node) continue;
            if (edge.source == cur.node) continue;
            bool seen = false;
            for (const std::string& hop : cur.visited) {
                if (hop == edge.source) seen = true;
            }
            if (seen) continue;
            const int64_t fee = edge.source == source ? 0 : EdgeFee(edge, cur.needed);
            const int64_t send = cur.needed + fee;
            const int incoming = cur.expiry + (edge.source == source ? 0 : edge.cltv_delta);
            if (cur.needed > edge.liquidity || send - amount > max_fee || incoming - current_height > max_expiry_delta) continue;
            Search next = cur;
            next.needed = send;
            next.counter = counter++;
            next.hops = cur.hops + 1;
            next.node = edge.source;
            next.expiry = incoming;
            SwarmRouteHop hop;
            hop.edge = edge.id;
            hop.source = edge.source;
            hop.target = cur.node;
            hop.forward_atoms = cur.needed;
            hop.outgoing_expiry = cur.expiry;
            next.path.insert(next.path.begin(), hop);
            next.visited.push_back(cur.node);
            queue.push(std::move(next));
        }
    }
    route.code = "NO_LIQUID_ROUTE";
    return route;
}

bool SwarmLockPayment(SwarmConditional& box, const std::string& id, int64_t amount, const std::string& payment_hash, int expiry, int height, std::string& err)
{
    if (box.amounts.count(id) || box.history.count(id)) {
        err = "HTLC_REPLAY";
        return false;
    }
    if (payment_hash.size() != 64 || amount < 1 || expiry <= height) {
        err = "HTLC_CAPACITY_OR_EXPIRY";
        return false;
    }
    int64_t inflight = 0;
    for (const auto& [key, value] : box.amounts) {
        (void)key;
        inflight += value;
    }
    if (box.settled + inflight + amount > box.capacity) {
        err = "HTLC_CAPACITY_OR_EXPIRY";
        return false;
    }
    box.amounts[id] = amount;
    box.hashes[id] = payment_hash;
    box.expiries[id] = expiry;
    err.clear();
    return true;
}

bool SwarmResolvePayment(SwarmConditional& box, const std::string& id, const std::vector<unsigned char>& preimage, int height, std::string& err)
{
    const auto it = box.amounts.find(id);
    if (it == box.amounts.end()) {
        err = "HTLC_UNKNOWN";
        return false;
    }
    if (preimage.size() != 32) {
        err = "PREIMAGE";
        return false;
    }
    unsigned char hash[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(preimage.data(), preimage.size()).Finalize(hash);
    if (HexStr(Span<const unsigned char>(hash, CSHA256::OUTPUT_SIZE)) != box.hashes[id]) {
        err = "PREIMAGE";
        return false;
    }
    if (height >= box.expiries[id]) {
        err = "HTLC_EXPIRED";
        return false;
    }
    box.settled += it->second;
    box.history[id] = "FULFILLED";
    box.amounts.erase(id);
    box.hashes.erase(id);
    box.expiries.erase(id);
    err.clear();
    return true;
}

bool SwarmExpirePayment(SwarmConditional& box, const std::string& id, int height, std::string& err)
{
    const auto it = box.amounts.find(id);
    if (it == box.amounts.end() || height < box.expiries[id]) {
        err = "HTLC_NOT_EXPIRED";
        return false;
    }
    box.history[id] = "EXPIRED";
    box.amounts.erase(id);
    box.hashes.erase(id);
    box.expiries.erase(id);
    err.clear();
    return true;
}

bool SwarmPaymentsConserved(const SwarmConditional& box)
{
    int64_t inflight = 0;
    for (const auto& [key, value] : box.amounts) {
        (void)key;
        inflight += value;
    }
    return box.settled + inflight <= box.capacity;
}

SwarmWatch SwarmWatchtower(int observed_sequence, int latest_sequence, int height, int refund_height, int close_margin, bool prior_secret_released)
{
    SwarmWatch watch;
    watch.secp_penalty = false;
    if (observed_sequence < latest_sequence) {
        watch.hashlock_remedy = prior_secret_released;
        watch.action = prior_secret_released ? "HASHLOCK_REMEDY" : "STALE_STATE_ALERT";
        return watch;
    }
    if (height + close_margin >= refund_height) {
        watch.action = "DRAIN_AND_NOTIFY";
        return watch;
    }
    watch.action = "OBSERVE";
    return watch;
}

} // namespace modelnet
