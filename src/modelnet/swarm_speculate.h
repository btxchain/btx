// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_SPECULATE_H
#define BTX_MODELNET_SWARM_SPECULATE_H

#include <map>
#include <string>

namespace modelnet {

/**
 * Local record of speculative branches under a primary id.
 *
 * Open stores a branch under a primary. Finish stores one result hash on
 * that branch. Reuse returns a finished branch under the primary whose
 * stored hash matches. Branches stay stored after reuse.
 *
 * The record stays in this process. It does not broadcast, spend, spawn a
 * child process, or use the network. No hostnames or IPs are used.
 */
class SwarmSpeculate {
public:
    bool Open(const std::string& primary, const std::string& branch, std::string& err);
    bool Finish(const std::string& branch, const std::string& result_hash, std::string& err);
    bool Reuse(const std::string& primary, const std::string& primary_hash, std::string& reused_branch, std::string& err);

private:
    struct Branch {
        std::string primary;
        std::string result_hash;
        bool finished{false};
    };

    std::map<std::string, Branch> m_branches;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_SPECULATE_H
