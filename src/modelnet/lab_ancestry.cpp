// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/lab_ancestry.h>

#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace modelnet {
namespace {

enum class EdgeKind { Physical, Informed };

struct Walk {
    const std::map<std::string, ContributionLink>& links;
    AncestryReport report;
    std::set<std::string> retained;
    std::set<std::string> stack;
    std::set<std::string> missing;
    std::string& err;

    bool Consider(const std::string& cited, EdgeKind kind)
    {
        if (stack.find(cited) != stack.end()) {
            err = "BTX035_SCHEMA";
            return false;
        }
        const auto found = links.find(cited);
        if (found == links.end()) {
            missing.insert(cited);
            return true;
        }
        // A stored announcement is not a graph node and is not a missing id.
        if (found->second.announcement) {
            return true;
        }
        if (kind == EdgeKind::Physical) {
            ++report.physical_edges;
        } else {
            ++report.informed_edges;
        }
        if (retained.find(cited) != retained.end()) {
            return true;
        }
        return Enter(cited);
    }

    bool Enter(const std::string& id)
    {
        const auto found = links.find(id);
        const ContributionLink& link = found->second;
        report.record_ids.push_back(id);
        retained.insert(id);
        stack.insert(id);
        if (link.kind == "NEGATIVE_RESULT") {
            report.includes_negative = true;
        }

        const std::vector<std::string> physical_ids = link.physical_parent_ids;
        const std::vector<std::string> informed_ids = link.informed_by;
        for (const std::string& parent_id : physical_ids) {
            if (!Consider(parent_id, EdgeKind::Physical)) return false;
        }
        for (const std::string& informed_id : informed_ids) {
            if (!Consider(informed_id, EdgeKind::Informed)) return false;
        }
        stack.erase(id);
        return true;
    }
};

} // namespace

bool WalkAncestry(const std::string& start_id, const std::map<std::string, ContributionLink>& links, AncestryReport& out, std::string& err)
{
    out = AncestryReport{};
    err.clear();
    const auto start = links.find(start_id);
    if (start == links.end()) {
        err = "BTX035_NOT_FOUND";
        return false;
    }
    if (start->second.announcement) {
        err = "BTX035_RECORD_TYPE";
        return false;
    }

    Walk walk{links, AncestryReport{}, {}, {}, {}, err};
    if (!walk.Enter(start_id)) {
        out = AncestryReport{};
        return false;
    }
    walk.report.missing_ids.assign(walk.missing.begin(), walk.missing.end());
    out = std::move(walk.report);
    return true;
}

} // namespace modelnet
