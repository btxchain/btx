// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_BODYGATE_LEDGER_H
#define BITCOIN_MODELNET_SWARM_BODYGATE_LEDGER_H

#include <modelnet/swarm_bodygate/piece.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * Stored piece sizes. Each entry is an index, a size, and a last flag.
 * No payload bytes are kept. The running sum stays within the body cap.
 */
class SwarmBodyLedger {
public:
    /**
     * Store one piece size.
     * size < 1 is SHORT and stores nothing.
     * A duplicate index is REPLAY and keeps the first size and last flag.
     * A sum of stored sizes that would rise above the body cap is BODY
     * and does not store the piece. A sum equal to the cap is stored.
     * Success clears code.
     */
    bool Admit(int64_t index, int64_t size, bool last, std::string& code);

    int64_t count() const { return static_cast<int64_t>(m_pieces.size()); }
    int64_t sum() const { return m_sum; }
    bool contains(int64_t index) const { return m_pieces.find(index) != m_pieces.end(); }
    int64_t size_of(int64_t index) const;
    bool last_of(int64_t index) const;
    const std::map<int64_t, SwarmBodyPiece>& pieces() const { return m_pieces; }

private:
    std::map<int64_t, SwarmBodyPiece> m_pieces;
    int64_t m_sum{0};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_BODYGATE_LEDGER_H
