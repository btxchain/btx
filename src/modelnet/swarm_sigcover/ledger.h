// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SIGCOVER_LEDGER_H
#define BITCOIN_MODELNET_SWARM_SIGCOVER_LEDGER_H

#include <modelnet/swarm_sigcover/types.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory signature-cover rows keyed by id.
 * A row enters the map only when Cover or Preimage accepts a one-way mark.
 * A refused call leaves the map unchanged.
 * Cover never clears outputs_covered. Preimage never replaces a stored 32.
 */
class SwarmSigCoverLedger {
public:
    /**
     * Empty id is SIGHASH and stores nothing.
     * The first covers_outputs false is NOT_SIGNED and stores nothing.
     * The first covers_outputs true stores the id as covered and returns true.
     * A later covers_outputs false is NOT_SIGNED and leaves the covered row covered.
     * A later covers_outputs true on a covered id is REPLAY and keeps the row.
     */
    bool Cover(const std::string& id, bool covers_outputs, std::string& err);

    /**
     * Empty id is SIGHASH and stores nothing.
     * length other than 32 is PREIMAGE and stores nothing.
     * length 32 stores a 32-byte preimage description and returns true.
     * A second length 32 for the same id is REPLAY and keeps the description.
     */
    bool Preimage(const std::string& id, int64_t length, std::string& err);

    /** True when Cover has stored this id as covered. */
    bool covered(const std::string& id) const;

    /** 32 when a 32-byte preimage description is stored, otherwise -1. */
    int preimage_len(const std::string& id) const;

    /** The stored row, or nullptr when id has no row. The pointer is const. */
    const SwarmSigCoverRecord* Find(const std::string& id) const;

private:
    /** Apply an accepted plan. A refused plan must not call this. */
    bool Apply(const std::string& id, const SwarmSigCoverPlan& plan);

    std::map<std::string, SwarmSigCoverRecord> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SIGCOVER_LEDGER_H
