// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_qualitygrade.h>

namespace modelnet {

SwarmQualityGradeResult SwarmNoteQualityGrade(const SwarmQualityGrade& grade, std::string& err)
{
    SwarmQualityGradeResult result;
    result.promoted = false;
    // A quality grade does not promote a realm.
    if (grade.grade_id.empty()) {
        result.code = "GRADE";
        result.promoted = false;
        err = "GRADE";
        return result;
    }
    if (grade.want_promote) {
        result.code = "HELD";
        result.promoted = false;
        err = "HELD";
        return result;
    }
    result.code = "NOTED";
    result.promoted = false;
    err.clear();
    return result;
}

} // namespace modelnet
