// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_receipt.h>

namespace modelnet {
namespace {

std::string PairKey(const std::string& task_id, const std::string& worker_id)
{
    return task_id + '\n' + worker_id;
}

} // namespace

bool SwarmReceiptBook::Accept(const std::string& task_id, const std::string& worker_id, const std::string& receipt_id,
                              const std::string& body, int64_t generation, bool disconnected, std::string& err)
{
    (void)disconnected;
    if (task_id.empty() || worker_id.empty() || receipt_id.empty() || body.empty() || generation < 1) {
        err = "RECEIPT";
        return false;
    }
    const auto it = m_rows.find(PairKey(task_id, worker_id));
    if (it != m_rows.end()) {
        Record& row = it->second;
        if (row.receipt_id == receipt_id) {
            if (row.body == body && row.generation == generation) {
                err.clear();
                return true;
            }
            err = "CONFLICT";
            return false;
        }
        if (generation <= row.generation) {
            err = "DUPLICATE";
            return false;
        }
        row.receipt_id = receipt_id;
        row.body = body;
        row.generation = generation;
        err.clear();
        return true;
    }
    Record row;
    row.receipt_id = receipt_id;
    row.body = body;
    row.generation = generation;
    m_rows.emplace(PairKey(task_id, worker_id), row);
    err.clear();
    return true;
}

int SwarmReceiptBook::Count() const
{
    return static_cast<int>(m_rows.size());
}

bool SwarmReceiptBook::Found(const std::string& task_id, const std::string& worker_id, const std::string& receipt_id,
                             const std::string& body, int64_t generation) const
{
    const auto it = m_rows.find(PairKey(task_id, worker_id));
    if (it == m_rows.end()) return false;
    const Record& row = it->second;
    return row.receipt_id == receipt_id && row.body == body && row.generation == generation;
}

} // namespace modelnet
