// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RESEARCH_GRAPH_H
#define BITCOIN_MODELNET_RESEARCH_GRAPH_H

#include <modelnet/types.h>

#include <cstddef>
#include <map>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace modelnet {

/** Domain separation for research topic labels. Body is the raw UTF-8 label. */
inline constexpr char RESEARCH_TOPIC_DOMAIN[] = "BTX/035/Topic/v1.1";

/** Largest Page limit. Zero and every larger limit fail with BTX035_PAGE. */
inline constexpr size_t RESEARCH_PAGE_MAX = 64;

/**
 * One stored contribution. `negative` stays queryable for the life of the row.
 * The caller chooses topic, contribution_id, and author_id.
 */
struct ResearchContribution {
    Digest48 topic{};
    Digest48 contribution_id{};
    Digest48 author_id{};
    bool negative{false};
    std::string summary;
};

/** One topic page. A null next_cursor means this page finished the topic. */
struct ResearchPage {
    std::vector<ResearchContribution> rows;
    Digest48 next_cursor{};
};

/**
 * False, with err "BTX035_TOPIC", when `label` has a leading or trailing
 * ASCII space or any ASCII A-Z. An empty label is left to TopicId.
 */
bool RejectCanonical(std::string_view label, std::string& err);

/**
 * Topic id = DomainHash(RESEARCH_TOPIC_DOMAIN, UTF-8 label bytes).
 * An empty label or a RejectCanonical failure sets err to "BTX035_TOPIC".
 */
bool TopicId(std::string_view label, Digest48& out, std::string& err);

/**
 * Local research graph. Publish stores the contribution the caller selected.
 * Negative rows remain in Find and Page. ContinueWithout removes an author
 * from the peer set and leaves that author's rows stored. AdoptSuccessor
 * copies memory ids when the child grant is non-empty and different from
 * the parent grant.
 */
class ResearchBook {
public:
    /**
     * Store the caller's row. The same topic and contribution_id with the
     * same author, sign, and summary is idempotent. A different body under
     * that id fails with "BTX035_CONFLICT" and leaves the stored row in place.
     */
    bool Publish(const Digest48& topic, const Digest48& contribution_id, const Digest48& author_id,
                 bool negative, std::string_view summary, std::string& err);

    /** Copy the stored row, positive or negative. False when it is absent. */
    bool Find(const Digest48& topic, const Digest48& contribution_id, ResearchContribution& out) const;

    /**
     * Child inherits a copy of memory_ids. Fails with "BTX035_GRANT" when
     * either grant is empty or the grants are equal. An empty memory_ids
     * vector is a successful inheritance of no memories.
     */
    bool AdoptSuccessor(const Digest48& parent_agent, const Digest48& child_agent,
                        std::string_view parent_grant, std::string_view child_grant,
                        const std::vector<Digest48>& memory_ids, std::string& err);

    /** Copy of the memory ids inherited by child_agent. Empty when none were adopted. */
    std::vector<Digest48> MemoryOf(const Digest48& child_agent) const;

    /** Drop author_id from the peer set. Published rows stay stored. */
    void ContinueWithout(const Digest48& author_id);

    /** True after Publish until ContinueWithout. */
    bool HasPeer(const Digest48& author_id) const;

    /**
     * Contribution rows for topic, ordered by contribution_id, strictly after
     * cursor. A null cursor starts at the first id. limit 0 or limit > 64
     * fails with "BTX035_PAGE". next_cursor is the last returned id while
     * more rows remain, and null when the topic is exhausted.
     */
    bool Page(const Digest48& topic, const Digest48& cursor, size_t limit, ResearchPage& out, std::string& err) const;

private:
    std::map<Digest48, std::map<Digest48, ResearchContribution>> m_by_topic;
    std::set<Digest48> m_peers;
    std::map<Digest48, std::vector<Digest48>> m_memory;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_RESEARCH_GRAPH_H
