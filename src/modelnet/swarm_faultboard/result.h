// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_FAULTBOARD_RESULT_H
#define BITCOIN_MODELNET_SWARM_FAULTBOARD_RESULT_H

#include <map>
#include <string>

namespace modelnet {

/**
 * One receipt per task.
 * The same receipt is accepted again. A different receipt is refused
 * and the first stays. There is no erase.
 */
class SwarmFaultResultBook {
public:
    bool Keep(const std::string& task, const std::string& receipt, std::string& err);
    bool contains(const std::string& task) const;
    std::string receipt_for(const std::string& task) const;

private:
    std::map<std::string, std::string> m_rows;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_FAULTBOARD_RESULT_H
