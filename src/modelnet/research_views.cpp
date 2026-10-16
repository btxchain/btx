// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/research_views.h>

#include <algorithm>
#include <string>

namespace modelnet {
namespace {

bool Fail(std::string& err, const char* code)
{
    err = code;
    return false;
}

bool LessId(const ResearchObservation& a, const ResearchObservation& b)
{
    return a.record_id < b.record_id;
}

} // namespace

bool ParseResearchView(std::string_view name, ResearchView& out, std::string& err)
{
    if (name == "LEADING") out = ResearchView::LEADING;
    else if (name == "CONTESTED") out = ResearchView::CONTESTED;
    else if (name == "NEGLECTED") out = ResearchView::NEGLECTED;
    else if (name == "RECENT") out = ResearchView::RECENT;
    else if (name == "REPRODUCED") out = ResearchView::REPRODUCED;
    else return Fail(err, "BTX035_SCHEMA");
    err.clear();
    return true;
}

bool SortResearchView(ResearchView view, const std::vector<ResearchObservation>& rows, bool public_query,
                      std::vector<std::string>& ids, std::string& err)
{
    std::vector<ResearchObservation> kept;
    kept.reserve(rows.size());
    for (const ResearchObservation& row : rows) {
        if (row.record_id.empty()) return Fail(err, "BTX035_SCHEMA");
        if (public_query && row.is_private) continue;
        if (view == ResearchView::REPRODUCED && row.reproduction_count == 0) continue;
        kept.push_back(row);
    }
    std::sort(kept.begin(), kept.end(), [&](const ResearchObservation& a, const ResearchObservation& b) {
        switch (view) {
        case ResearchView::RECENT:
            if (a.sequence != b.sequence) return a.sequence > b.sequence;
            return LessId(a, b);
        case ResearchView::LEADING:
            if (a.reproduction_count != b.reproduction_count) return a.reproduction_count > b.reproduction_count;
            if (a.sequence != b.sequence) return a.sequence > b.sequence;
            return LessId(a, b);
        case ResearchView::CONTESTED:
            if (a.contest_count != b.contest_count) return a.contest_count > b.contest_count;
            return LessId(a, b);
        case ResearchView::NEGLECTED:
            if (a.reproduction_count != b.reproduction_count) return a.reproduction_count < b.reproduction_count;
            if (a.sequence != b.sequence) return a.sequence < b.sequence;
            return LessId(a, b);
        case ResearchView::REPRODUCED:
            if (a.reproduction_count != b.reproduction_count) return a.reproduction_count > b.reproduction_count;
            return LessId(a, b);
        }
        return LessId(a, b);
    });
    ids.clear();
    ids.reserve(kept.size());
    for (const ResearchObservation& row : kept) ids.push_back(row.record_id);
    err.clear();
    return true;
}

} // namespace modelnet
