// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_LAB_ANCESTRY_H
#define BITCOIN_MODELNET_LAB_ANCESTRY_H

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace modelnet {

struct ContributionLink {
    std::string record_id; // 96 lowercase hex, or empty for a missing cited id that is not stored
    std::string kind; // HYPOTHESIS, EXPERIMENT, NEGATIVE_RESULT, REPRODUCTION, CRITIQUE, SYNTHESIS, TOOL_IMPROVEMENT, or empty
    std::vector<std::string> physical_parent_ids;
    std::vector<std::string> informed_by;
    bool announcement{false}; // ActivityAnnouncement: visible to callers, never a graph node
};

struct AncestryReport {
    std::vector<std::string> record_ids; // start id first, then retained ancestors, deterministic, unique
    uint32_t physical_edges{0}; // edges followed that were physical parents and existed
    uint32_t informed_edges{0}; // edges followed that were informed_by and existed
    std::vector<std::string> missing_ids; // cited ids with no stored contribution, sorted unique
    bool includes_negative{false};
};

/**
 * Depth-first ancestry from start_id. Physical parents are visited before informed_by.
 * On failure out is empty and err is BTX035_NOT_FOUND, BTX035_RECORD_TYPE, or BTX035_SCHEMA.
 */
bool WalkAncestry(const std::string& start_id, const std::map<std::string, ContributionLink>& links, AncestryReport& out, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_LAB_ANCESTRY_H
