// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_DESCENDANTS_H
#define BITCOIN_MODELNET_SWARM_DESCENDANTS_H

#include <modelnet/swarm_descendants/book.h>
#include <modelnet/swarm_descendants/integer_bound.h>
#include <modelnet/swarm_descendants/node.h>
#include <modelnet/swarm_descendants/realm.h>

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace modelnet {

/**
 * Competing-descendant plane.
 *
 * AddBaseline stores an empty-parent head. An empty id is LINEAGE and
 * stores nothing. A duplicate is REPLAY.
 * Fork: unknown parent is PARENT, empty child is LINEAGE, and a child
 * equal to the parent is SELF. A compatible child stays on the parent
 * head. An incompatible child becomes its own head, the parent head
 * stays, and err is FORK. A second fork of that child is REPLAY and
 * keeps the first parent.
 * Average always returns NOT_AVERAGED and changes no head. Incompatible
 * branches are not averaged.
 * Assign takes general, coding, or research. Any other channel is NICHE
 * and stores nothing. One channel does not remove another.
 * Measure: author equal to the child is NOT_SCORED, independent false
 * is HELD, and a stored score does not replace a head. Two distinct
 * authors on the same child with score spread <= 10000 set accepted.
 * Scores are not averaged.
 * bytes_moved() is 0, gpu() is false, and graduated() stays false.
 * This plane does not promote a realm and does not mine.
 */
class SwarmDescendants {
public:
    bool AddBaseline(const std::string& id, std::string& err);
    bool Fork(const std::string& parent, const std::string& child, bool compatible, std::string& err);
    bool Average(std::string& err);
    bool Average(const std::string& left, const std::string& right, std::string& err);
    bool Assign(const std::string& child, const std::string& channel, std::string& err);
    bool Measure(const std::string& child, const std::string& author, bool independent, int64_t score, std::string& err);

    bool contains(const std::string& id) const { return m_book.contains(id); }
    std::size_t size() const { return m_book.size(); }
    bool is_head(const std::string& id) const { return m_book.is_head(id); }
    std::string parent_of(const std::string& id) const { return m_book.parent_of(id); }
    std::string head_of(const std::string& id) const { return m_book.head_of(id); }
    std::vector<std::string> on_head(const std::string& head) const { return m_book.on_head(head); }
    std::vector<std::string> heads() const { return m_book.heads(); }
    std::vector<std::string> heads(const std::string& channel) const { return m_book.heads(channel); }
    std::vector<std::string> channels(const std::string& id) const { return m_book.channels(id); }
    bool accepted(const std::string& child) const;
    std::vector<SwarmDescendantScore> scores(const std::string& child) const;

    uint64_t bytes_moved() const { return m_realm.bytes_moved(); }
    bool gpu() const { return m_realm.gpu(); }
    bool graduated() const { return m_realm.graduated(); }
    bool promotes_realm() const { return m_realm.promotes_realm(); }
    bool mines() const { return m_realm.mines(); }
    std::size_t integer_pairs() const { return m_integers.pairs(); }
    const char* integer_profile() const { return m_integers.profile(); }
    bool extends_dataset() const { return m_integers.extends_dataset(); }

private:
    DescendantBook m_book;
    SwarmDescendantRealm m_realm;
    SwarmDescendantIntegerBound m_integers;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_DESCENDANTS_H
