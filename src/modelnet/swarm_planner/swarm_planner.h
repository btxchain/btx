// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PLANNER_H
#define BITCOIN_MODELNET_SWARM_PLANNER_H

#include <modelnet/swarm_planner/codes.h>
#include <modelnet/swarm_planner/limits.h>

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Durable planner and four graph views.
 *
 * Planner state is the member fields of this object. A model or session
 * replaced elsewhere leaves this object as it is.
 *
 * The views are resource, work, topology, and evidence. Each view keeps
 * its own records. The same id admitted to two views is two records.
 *
 * Admit stores an id in one view. An unknown view is VIEW. An empty id
 * is ID. An id already present in that view is REPLAY.
 *
 * Depend records that `before` finishes before `after`. Both ids must
 * already be in the work view, or the result is WORK. An edge that would
 * cycle, including a self-edge, is CYCLE and is not stored. A repeated
 * legal edge is REPLAY. Dispatch returns true only when every predecessor
 * is finished. An unfinished predecessor is BLOCKED. Walking a stored
 * cycle is CYCLE, and that walk does not dispatch. A predecessor whose
 * evidence record is retracted is INVALID. Finish marks a work id finished.
 *
 * Wake appends a new event id to the outbox and leaves the cursor in
 * place, so the wake remains until CommitCursor. An empty event id is
 * EVENT. A repeated event id is REPLAY and is not appended.
 * CommitCursor moves the cursor to the outbox size and returns that size.
 * A later CommitCursor with no new wake returns the same size.
 *
 * Propose stores the first epoch as the current authority. A later epoch
 * below current is STALE and leaves the body unchanged. An equal epoch
 * is REPLAY. A greater epoch replaces the body and becomes current.
 *
 * Quiesce sets quiescent() and returns true. The call returns immediately.
 *
 * Retract appends a history row and marks an evidence id retracted. An
 * unknown evidence id is ID. The original admit row stays in the history.
 * history_count() grows by one. The evidence record stays queryable.
 *
 * Search applies the allowed filter before it consults membership or
 * counts. A false allowed value returns NOT_VISIBLE whether or not the
 * id is stored, and visible_count() stays the same. An allowed search
 * returns true when the id is in that view and is not retracted. An
 * allowed search for an absent id returns NOT_VISIBLE as well, so the
 * code matches a disallowed search.
 *
 * launched(), gpu(), and broadcast() stay false. automatic_spend()
 * returns "0". bytes_moved() returns 0. This class does not call a model
 * and does not spend.
 */
class SwarmPlanner {
public:
    bool Admit(const std::string& view, const std::string& id, std::string& err);
    bool Depend(const std::string& before, const std::string& after, std::string& err);

    /**
     * True only when every predecessor of id is finished.
     * An unknown work id is WORK. A cycle on the walk is CYCLE.
     * A retracted evidence predecessor is INVALID.
     * An unfinished predecessor is BLOCKED.
     */
    bool Dispatch(const std::string& id, std::string& err) const;
    bool Finish(const std::string& id, std::string& err);

    bool Wake(const std::string& event_id, std::string& err);
    /** Move the cursor to the outbox size and return that size. */
    uint64_t CommitCursor();

    bool Propose(int64_t epoch, const std::string& body, std::string& err);
    /** Set quiescent() and return true. */
    bool Quiesce(std::string& err);
    bool Retract(const std::string& evidence_id, std::string& err);

    /**
     * Allowed is applied first. A false value returns NOT_VISIBLE and
     * leaves visible_count() unchanged.
     */
    bool Search(const std::string& view, const std::string& id, bool allowed, std::string& err) const;

    bool admitted(const std::string& view, const std::string& id) const;
    bool finished(const std::string& id) const;
    bool retracted(const std::string& evidence_id) const;

    bool quiescent() const;
    int64_t history_count() const;
    int64_t visible_count() const;

    bool proposed() const;
    int64_t epoch() const;
    const std::string& body() const;

    uint64_t cursor() const;
    uint64_t outbox_size() const;

    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    std::string automatic_spend() const;
    int64_t bytes_moved() const;

private:
    enum class ViewKind { Resource, Work, Topology, Evidence };

    struct WorkRecord {
        std::vector<std::string> predecessors;
        bool finished{false};
    };

    struct EvidenceRecord {
        bool retracted{false};
    };

    struct HistoryRecord {
        std::string view;
        std::string id;
        bool retraction{false};
    };

    bool ParseView(const std::string& view, ViewKind& out) const;
    bool Contains(ViewKind view, const std::string& id) const;
    /** True when `after` is already required before `start`, or start is after. */
    bool DependsOn(const std::string& start, const std::string& target) const;

    std::set<std::string> m_resource;
    std::map<std::string, WorkRecord> m_work;
    std::set<std::string> m_topology;
    std::map<std::string, EvidenceRecord> m_evidence;
    std::vector<HistoryRecord> m_history;

    std::vector<std::string> m_outbox;
    std::set<std::string> m_events;
    uint64_t m_cursor{0};

    bool m_proposed{false};
    int64_t m_epoch{0};
    std::string m_body;
    bool m_quiescent{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PLANNER_H
