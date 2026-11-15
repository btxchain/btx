// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_JOBCANCEL_H
#define BTX_MODELNET_SWARM_JOBCANCEL_H

#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory record of open, finished, and cancelled tasks.
 * Open stores a task. Finish stores one result and accepts that same result
 * again. Cancel marks an unfinished task. A finished result is left in place.
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or address.
 */
class SwarmJobCancel {
public:
    bool Open(const std::string& task, std::string& err);
    bool Finish(const std::string& task, const std::string& result, std::string& err);
    bool Cancel(const std::string& task, std::string& err);
    bool cancelled(const std::string& task) const;
    std::string result(const std::string& task) const;

private:
    struct Job {
        bool finished{false};
        bool cancelled{false};
        std::string result;
    };

    std::map<std::string, Job> m_jobs;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_JOBCANCEL_H
