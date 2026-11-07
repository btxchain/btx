// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_ATTEMPT_H
#define BTX_MODELNET_SWARM_ATTEMPT_H

#include <util/fs.h>

#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * One fenced attempt. The lease binds the worker, checkpoint, and recipe, and
 * it has a finite expiry. Quiescence is the worker acknowledgment required
 * before another item is taken from the batch. accepted is not reset by a
 * repeated grant of the same lease. There is no spend key.
 */
struct SwarmAttempt {
    std::string attempt_id;
    std::string worker_id;
    std::string checkpoint_id;
    std::string recipe;
    int64_t expiry_ms{0};
    int batch_size{0};
    int accepted{0};
    bool quiescent{false};
};

/**
 * Local attempt book. An expired lease stays stored so a restart can see it,
 * and it is not active. automatic_spend_atoms stays "0". This book does not
 * broadcast and does not start a thread.
 */
class SwarmAttemptBook {
public:
    bool Grant(const SwarmAttempt& attempt, int64_t now_ms, std::string& err);
    bool Heartbeat(const std::string& attempt_id, int64_t now_ms, bool quiescent, std::string& err);
    bool AcceptOne(const std::string& attempt_id, int64_t now_ms, std::string& err);
    int Active(int64_t now_ms) const;
    SwarmAttempt* Find(const std::string& attempt_id);
    bool Persist(const fs::path& modeldir, std::string& err);
    bool Load(const fs::path& modeldir, std::string& err);

private:
    std::vector<SwarmAttempt> m_rows;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_ATTEMPT_H
