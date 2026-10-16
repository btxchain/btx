// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/research_index.h>

namespace modelnet {

bool ResearchIndex::Announce(std::string_view topic_label, const Digest48& contribution_id, const Digest48& author_id,
                             bool negative, std::string_view summary, std::string& err)
{
    Digest48 topic;
    if (!TopicId(topic_label, topic, err)) return false;
    return m_book.Publish(topic, contribution_id, author_id, negative, summary, err);
}

bool ResearchIndex::Query(std::string_view topic_label, const Digest48& cursor, size_t limit, ResearchPage& out,
                          std::string& err) const
{
    out = {};
    Digest48 topic;
    if (!TopicId(topic_label, topic, err)) return false;
    return m_book.Page(topic, cursor, limit, out, err);
}

} // namespace modelnet
