// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_DEBITCAP_H
#define BTX_MODELNET_SWARM_DEBITCAP_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory remaining capacity for named channels.
 *
 * Open stores remaining equal to the capacity. Debit subtracts atoms
 * from that remaining amount. A debit larger than the remaining capacity
 * is refused and the remaining capacity stays.
 *
 * This ledger does not broadcast, spend, spawn a child process, open a
 * network connection, or use a hostname or IP.
 */
class SwarmDebitCap {
public:
    /**
     * An empty channel is CHANNEL and stores nothing. capacity below 1
     * is CAPACITY and stores nothing. A second Open for the same channel
     * is REPLAY and leaves the stored remaining. Success stores remaining
     * equal to capacity, clears err, and returns true.
     */
    bool Open(const std::string& channel, int64_t capacity, std::string& err);

    /**
     * An unknown channel is CHANNEL. atoms below 1 is ATOMS and leaves
     * remaining. atoms greater than remaining is SHORT and leaves
     * remaining. Otherwise subtracts atoms from remaining, clears err,
     * and returns true.
     */
    bool Debit(const std::string& channel, int64_t atoms, std::string& err);

    /** Remaining capacity, or -1 when the channel is unknown. */
    int64_t Remaining(const std::string& channel) const;

private:
    std::map<std::string, int64_t> m_remaining;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_DEBITCAP_H
