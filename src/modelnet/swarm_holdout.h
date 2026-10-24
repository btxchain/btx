// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_HOLDOUT_H
#define BTX_MODELNET_SWARM_HOLDOUT_H

#include <set>
#include <string>

namespace modelnet {

/**
 * One hidden-holdout round. The book stores the digest only.
 * It does not score a model, does not train, and does not move bytes.
 */
struct SwarmHoldoutOpen {
    std::string suite_id;
    std::string holdout_digest;
    bool author_sees_holdout{false};
    bool precommitted{false};
};

/**
 * In-memory rotating hidden-holdout book. A consumed digest cannot be
 * opened again. Measured stays false: this book does not score a model,
 * does not train, and does not move bytes.
 */
class SwarmHoldoutBook {
public:
    /** Returns false and sets err on refusal. On success err is clear and a round is open. */
    bool Open(const SwarmHoldoutOpen& round, std::string& err);
    /** Consumes the open round so its digest cannot be opened again. measured stays false. */
    bool Consume(std::string& err);
    bool HasOpen() const;
    bool Measured() const;

private:
    bool m_open{false};
    bool m_measured{false};
    std::string m_digest;
    std::set<std::string> m_used;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_HOLDOUT_H
