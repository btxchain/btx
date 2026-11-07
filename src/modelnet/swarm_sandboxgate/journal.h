// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_SANDBOXGATE_JOURNAL_H
#define BITCOIN_MODELNET_SWARM_SANDBOXGATE_JOURNAL_H

#include <modelnet/swarm_sandboxgate/record.h>

#include <cstddef>
#include <vector>

namespace modelnet {

/**
 * Actions recorded by a successful Act.
 * record refuses an unusable action and a private path.
 * A refusal appends nothing. Net and Run do not write here.
 */
class SwarmSandboxGateJournal {
public:
    std::size_t size() const;
    bool record(const SwarmSandboxGateAction& action);

private:
    std::vector<SwarmSandboxGateAction> m_actions;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_SANDBOXGATE_JOURNAL_H
