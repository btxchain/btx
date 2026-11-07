// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_CLEARING_H
#define BTX_MODELNET_SWARM_CLEARING_H

#include <primitives/transaction.h>
#include <util/fs.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/** Scoped slice of one shared channel. Not a channel of its own. */
struct SwarmPoolSlice {
    std::string pool_id;
    int64_t reserved{0};
};

/** One leg of a coordinated batch. Settled by netting, not by an L1 transaction. */
struct SwarmCoordinatedPayment {
    std::string payment_id;
    std::string from_pool;
    std::string to_pool;
    int64_t atoms{0};
};

/**
 * Result of one committed batch. l1_transactions stays 0, broadcast stays
 * false, and automatic_spend_atoms stays "0". close_outputs counts pools
 * whose balance is still positive: one close template for the channel.
 */
struct SwarmClearingReceipt {
    int64_t sequence{0};
    int payments{0};
    int l1_transactions{0};
    int close_outputs{0};
    bool broadcast{false};
    std::string automatic_spend_atoms{"0"};
};

/**
 * Many pools, one channel. Apply nets a whole batch on a scratch copy and
 * advances the sequence by one. It does not build, sign, or broadcast a
 * transaction.
 */
class SwarmClearingBook {
public:
    bool Open(int64_t capacity, const std::vector<SwarmPoolSlice>& slices, std::string& err);
    bool Apply(const std::vector<SwarmCoordinatedPayment>& payments, SwarmClearingReceipt& receipt, std::string& err);
    int64_t Balance(const std::string& pool_id) const;
    std::vector<std::pair<std::string, int64_t>> Balances() const;
    int64_t Sequence() const;
    bool Persist(const fs::path& modeldir, std::string& err);
    bool Load(const fs::path& modeldir, std::string& err);

private:
    bool m_open{false};
    int64_t m_capacity{0};
    int64_t m_sequence{0};
    std::map<std::string, int64_t> m_balances;
    std::set<std::string> m_seen;
};

/**
 * One close transaction for the whole channel. Each positive pool balance is
 * one output. The payment count does not become a transaction count.
 * Nothing is signed and nothing is broadcast.
 */
struct SwarmClearingClose {
    CMutableTransaction tx;
    int templates{0};
    int outputs{0};
    bool broadcast{false};
};

bool SwarmBuildClearingClose(const SwarmClearingBook& book, const Txid& funding,
                             const std::map<std::string, std::vector<unsigned char>>& scripts,
                             const std::string& worker_pool, int64_t previous_worker_atoms,
                             SwarmClearingClose& out, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_CLEARING_H
