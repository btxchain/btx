// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RESEARCH_INDEX_H
#define BITCOIN_MODELNET_RESEARCH_INDEX_H

#include <modelnet/research_graph.h>
#include <modelnet/research_views/research_views.h>

#include <string>
#include <string_view>
#include <vector>

namespace modelnet {

/**
 * Topic-scoped wrapper over ResearchBook.
 * Announce publishes on the canonical topic id and, when the summary is
 * non-empty, records that row for the local views. Query returns that topic
 * only. View answers LEADING, CONTESTED, NEGLECTED, RECENT, and REPRODUCED.
 * A label that fails RejectCanonical fails BTX035_TOPIC. There is no method
 * that assigns work to an author.
 */
class ResearchIndex {
public:
    bool Announce(std::string_view topic_label, const Digest48& contribution_id, const Digest48& author_id,
                  bool negative, std::string_view summary, std::string& err);

    bool Query(std::string_view topic_label, const Digest48& cursor, size_t limit, ResearchPage& out,
               std::string& err) const;

    std::vector<std::string> View(const std::string& name, const std::string& topic, std::string& err) const;

private:
    ResearchBook m_book;
    ResearchViews m_views;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_RESEARCH_INDEX_H
