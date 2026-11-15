// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_GRAPH_VIEWS_GRAPH_VIEWS_H
#define BITCOIN_MODELNET_GRAPH_VIEWS_GRAPH_VIEWS_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Four in-memory graph views: record, dependency, evidence, and replication.
 *
 * Add stores an id under one of those kinds. An empty id is FIELD and
 * stores nothing. Any other kind is KIND and stores nothing. A second Add
 * of a stored id is NIFDT_REPLAY and leaves the first text in place.
 *
 * Link stores a directed edge. Both ids must already exist. An empty
 * endpoint is FIELD. A missing endpoint is ABSENT and stores nothing.
 * An edge that would cycle, including a self-edge, is CYCLE and is not
 * stored. A repeated edge is NIFDT_REPLAY.
 *
 * Dispatch walks stored edges. A cycle on that walk is CYCLE and returns
 * false. An acyclic graph, including one whose closing edge was refused,
 * returns true.
 *
 * Retract marks an evidence id retracted and appends a later history row.
 * The original record stays stored. History returns the first text.
 * An empty id is FIELD. An unknown id is ABSENT. A stored id of another
 * kind is KIND. A second retract is NIFDT_REPLAY.
 *
 * View accepts only the four kinds and sets the count filter. Any other
 * name is KIND and leaves the filter unchanged. Count counts stored
 * records that match the filter. It does not rank records ahead of the
 * filter. With no view selected, Count counts every stored record,
 * including retracted evidence.
 *
 * Release returns NIFDT_UNQUALIFIED. qualified() and release_qualified()
 * stay false. hosts() and physical_hosts() stay 1. bytes_moved() stays 0.
 * Spend returns NIFDT_AUTOMATIC_SPEND. Vendor and Gpu return
 * NIFDT_ENGINE_ABSENT. launched(), gpu(), and broadcast() stay false.
 * This class opens no file, no socket, and no process.
 */
class GraphViews {
public:
    bool Add(const std::string& id, const std::string& kind, std::string& err);
    bool Link(const std::string& from, const std::string& to, std::string& err);
    bool Dispatch(std::string& err) const;
    bool Retract(const std::string& id, std::string& err);
    std::string History(const std::string& id) const;
    bool View(const std::string& name, std::string& err);
    int64_t Count() const;

    bool Release(std::string& err);
    bool Spend(std::string& err);
    bool Vendor(std::string& err);
    bool Gpu(std::string& err);

    bool contains(const std::string& id) const;
    bool has_link(const std::string& from, const std::string& to) const;
    bool retracted(const std::string& id) const;

    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    bool qualified() const { return false; }
    bool release_qualified() const { return false; }
    int64_t hosts() const { return static_cast<int64_t>(1); }
    int64_t physical_hosts() const { return static_cast<int64_t>(1); }
    int64_t bytes_moved() const { return static_cast<int64_t>(0); }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct Node {
        std::string kind;
        std::string text;
        bool retracted{false};
        std::vector<std::string> history;
        std::vector<std::string> out;
    };

    /** True when `start` already reaches `target`, including start == target. */
    bool Reaches(const std::string& start, const std::string& target) const;
    bool HasCycle() const;

    std::map<std::string, Node> m_nodes;
    std::string m_view;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_GRAPH_VIEWS_GRAPH_VIEWS_H
