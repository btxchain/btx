// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_AGENTEXEC_JOURNAL_H
#define BITCOIN_MODELNET_SWARM_AGENTEXEC_JOURNAL_H

#include <map>
#include <string>
#include <utility>

namespace modelnet {

/**
 * Digests already computed for a path and payload pair.
 * Seen is true when that pair was stored.
 * Put refuses a pair that is already stored and leaves the first digest.
 * The payload bytes are the key, not a path on disk.
 */
class SwarmAgentExecJournal {
public:
    bool Seen(const std::string& path, const std::string& payload) const;
    bool Put(const std::string& path, const std::string& payload, const std::string& digest);

private:
    std::map<std::pair<std::string, std::string>, std::string> m_runs;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_AGENTEXEC_JOURNAL_H
