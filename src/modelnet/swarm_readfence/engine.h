// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_READFENCE_ENGINE_H
#define BITCOIN_MODELNET_SWARM_READFENCE_ENGINE_H

#include <string>

namespace modelnet {

/**
 * Engine status for one fence.
 * It starts unset, which is not INSTALLED.
 * Install records a known name and sets the status to INSTALLED.
 * An unknown name is refused and the previous status stays.
 * Install does not start a process, qualify the engine, or advertise it.
 */
class SwarmReadEngine {
public:
    bool installed() const { return m_installed; }
    const std::string& name() const { return m_name; }
    const std::string& status() const { return m_status; }

    bool Install(const std::string& name);

private:
    bool m_installed{false};
    std::string m_name;
    std::string m_status;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_READFENCE_ENGINE_H
