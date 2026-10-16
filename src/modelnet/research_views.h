// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_RESEARCH_VIEWS_H
#define BITCOIN_MODELNET_RESEARCH_VIEWS_H

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace modelnet {

/** Local sort of retained records. None of these is a consensus order. */
enum class ResearchView {
    LEADING,
    CONTESTED,
    NEGLECTED,
    RECENT,
    REPRODUCED,
};

struct ResearchObservation {
    std::string record_id;
    std::string topic_id;
    std::string author_id;
    std::string content_hash;
    bool negative{false};
    bool is_private{false};
    uint64_t sequence{0};
    uint32_t reproduction_count{0};
    uint32_t contest_count{0};
    /** Empty unless this row is a research contribution. View sorts do not read these. */
    std::string kind;
    std::vector<std::string> physical_parent_ids;
    std::vector<std::string> informed_by;
};

bool ParseResearchView(std::string_view name, ResearchView& out, std::string& err);

/**
 * Sort `rows` for `view`. A public query drops every private row, including
 * one whose content hash matches a public row. Record id breaks ties.
 * There is no function here that assigns an experiment to an author.
 */
bool SortResearchView(ResearchView view, const std::vector<ResearchObservation>& rows, bool public_query,
                      std::vector<std::string>& ids, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_RESEARCH_VIEWS_H
