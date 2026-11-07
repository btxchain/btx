// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_DISTILLREC_H
#define BTX_MODELNET_SWARM_DISTILLREC_H

#include <map>
#include <string>

namespace modelnet {

/**
 * In-memory record of one distillation: the child, the teacher it was
 * distilled from, and a digest. Distillation stores that triple. It does
 * not average weights. Merge is refused and does not combine records.
 *
 * This record does not broadcast, spend, spawn a child process, open a
 * network connection, or record a hostname or address.
 */
class SwarmDistillRec {
public:
    /**
     * An empty child, teacher, or digest is DISTILL and stores nothing.
     * child equal to teacher is SELF and stores nothing.
     * A second Record for a child already stored is REPLAY and leaves
     * the first teacher and digest in place.
     * Otherwise the call stores the triple, clears err, and returns true.
     */
    bool Record(const std::string& child, const std::string& teacher, const std::string& digest, std::string& err);

    /**
     * Always returns false and sets err to NOT_MERGED. Every stored
     * record stays in place. Records are not combined and weights are
     * not averaged.
     */
    bool Merge(const std::string& left, const std::string& right, std::string& err);

    /** True when child was stored by a successful Record. */
    bool Has(const std::string& child) const;

private:
    struct Row {
        std::string teacher;
        std::string digest;
    };

    std::map<std::string, Row> m_records;
};

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_DISTILLREC_H
