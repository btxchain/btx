// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_RECEIPT_H
#define BTX_MODELNET_SWARM_RECEIPT_H

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory receipt book. Nothing is broadcast and nothing is executed.
 * Accept returns true only for a new store or an idempotent repeat.
 * An empty task, worker, receipt, or body, or a generation below 1, is RECEIPT.
 * The same receipt with a different body or generation is CONFLICT.
 * A different receipt at or below the stored generation is DUPLICATE.
 * A reconnect at the same generation is included. The disconnected flag
 * does not change the decision. A different receipt at a higher generation
 * replaces that task and worker pair.
 */
class SwarmReceiptBook {
public:
    bool Accept(const std::string& task_id, const std::string& worker_id, const std::string& receipt_id,
                const std::string& body, int64_t generation, bool disconnected, std::string& err);
    int Count() const;
    bool Found(const std::string& task_id, const std::string& worker_id, const std::string& receipt_id,
               const std::string& body, int64_t generation) const;

private:
    struct Record {
        std::string receipt_id;
        std::string body;
        int64_t generation{0};
    };
    // key is task_id + '\n' + worker_id
    std::map<std::string, Record> m_rows;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_RECEIPT_H
