// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SPECBRANCH_H
#define BTX_MODELNET_SWARM_SPECBRANCH_H

#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory speculative branch book. CommitPrimary stores one primary
 * digest per id. Speculate stores a side digest. confirmed_speculative
 * never replaces the primary. There is no method that promotes a
 * conflicting branch.
 */
class SwarmSpeculativeBook {
public:
    /**
     * An empty id or an empty digest is SPECULATIVE.
     * A second different digest for the same id is REPLAY and the first
     * digest stays. The same digest is idempotent.
     */
    bool CommitPrimary(const std::string& id, const std::string& digest, std::string& err);

    /**
     * An unknown id is SPECULATIVE. An empty digest is SPECULATIVE.
     * A digest equal to the primary is stored as speculative and returns
     * MATCH. The committed digest is unchanged.
     * A different digest is stored and returns CONFLICT. The committed
     * digest is unchanged.
     * err is set to the same code that is returned.
     */
    std::string Speculate(const std::string& id, const std::string& digest, std::string& err);

    /** The primary digest, or empty when id is unknown. */
    std::string Committed(const std::string& id) const;

private:
    struct Row {
        std::string primary;
        std::string speculative;
        // True only when the stored speculative digest equals primary.
        // This flag is never copied onto primary.
        bool confirmed_speculative{false};
    };

    std::map<std::string, Row> m_rows;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SPECBRANCH_H
