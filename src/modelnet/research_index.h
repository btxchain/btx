// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RESEARCH_INDEX_H
#define BITCOIN_MODELNET_RESEARCH_INDEX_H

#include <modelnet/research_graph.h>

#include <string>
#include <string_view>

namespace modelnet {

/**
 * Topic-scoped wrapper over ResearchBook.
 * Announce publishes on the canonical topic id. Query returns that topic only.
 * A label that fails RejectCanonical fails BTX035_TOPIC. There is no method
 * that assigns work to an author.
 */
class ResearchIndex {
public:
    bool Announce(std::string_view topic_label, const Digest48& contribution_id, const Digest48& author_id,
                  bool negative, std::string_view summary, std::string& err);

    bool Query(std::string_view topic_label, const Digest48& cursor, size_t limit, ResearchPage& out,
               std::string& err) const;

private:
    ResearchBook m_book;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_RESEARCH_INDEX_H
