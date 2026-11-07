// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/dt_distill/dt_distill.h>

#include <limits>

namespace modelnet {
namespace {

bool AddReward(int64_t weight, int64_t reward, int64_t& next)
{
    const __int128 sum = static_cast<__int128>(weight) + static_cast<__int128>(reward);
    if (sum > static_cast<__int128>(std::numeric_limits<int64_t>::max()) ||
        sum < static_cast<__int128>(std::numeric_limits<int64_t>::min())) {
        return false;
    }
    next = static_cast<int64_t>(sum);
    return true;
}

} // namespace

bool DtDistill::Bind(const std::string& teacher, const std::string& student, std::string& err)
{
    if (teacher.empty()) {
        err = DT_DISTILL_TEACHER;
        return false;
    }
    if (student.empty()) {
        err = DT_DISTILL_STUDENT;
        return false;
    }
    if (teacher == student) {
        err = DT_DISTILL_SELF;
        return false;
    }
    if (m_bound.count(teacher) != 0) {
        err = NIFDT_REPLAY;
        return false;
    }
    m_bound.emplace(teacher, student);
    err.clear();
    return true;
}

bool DtDistill::Score(const std::string& teacher,
                      const std::string& student,
                      int64_t reward,
                      bool self_scored,
                      std::string& err)
{
    if (self_scored) {
        err = DT_DISTILL_SELF;
        return false;
    }
    if (teacher.empty()) {
        err = DT_DISTILL_TEACHER;
        return false;
    }
    if (student.empty()) {
        err = DT_DISTILL_STUDENT;
        return false;
    }
    if (teacher == student) {
        err = DT_DISTILL_SELF;
        return false;
    }
    const auto bound = m_bound.find(teacher);
    if (bound == m_bound.end()) {
        err = DT_DISTILL_TEACHER;
        return false;
    }
    if (bound->second != student) {
        err = DT_DISTILL_STUDENT;
        return false;
    }
    auto& by_student = m_scores[teacher];
    if (by_student.count(student) != 0) {
        err = NIFDT_REPLAY;
        return false;
    }
    ScoreRec rec;
    rec.reward = reward;
    by_student.emplace(student, rec);
    ++m_stored;
    err.clear();
    return true;
}

bool DtDistill::Update(std::string& err)
{
    if (m_stored == 0) {
        err = DT_DISTILL_MISSING;
        return false;
    }

    int64_t next = m_student_weight;
    bool pending = false;
    for (const auto& teacher : m_scores) {
        for (const auto& row : teacher.second) {
            if (row.second.applied) continue;
            pending = true;
            if (!AddReward(next, row.second.reward, next)) {
                err = DT_DISTILL_UNCHANGED;
                return false;
            }
        }
    }
    if (!pending) {
        err = DT_DISTILL_UNCHANGED;
        return false;
    }

    for (auto& teacher : m_scores) {
        for (auto& row : teacher.second) {
            row.second.applied = true;
        }
    }
    m_student_weight = next;
    m_new_generation = true;
    err.clear();
    return true;
}

bool DtDistill::GpuStep(std::string& err)
{
    err = NIFDT_ENGINE_ABSENT;
    return false;
}

bool DtDistill::bound(const std::string& teacher) const
{
    return m_bound.count(teacher) != 0;
}

std::string DtDistill::student_of(const std::string& teacher) const
{
    const auto it = m_bound.find(teacher);
    if (it == m_bound.end()) return std::string();
    return it->second;
}

const DtDistill::ScoreRec* DtDistill::FindScore(const std::string& teacher,
                                                const std::string& student) const
{
    const auto tit = m_scores.find(teacher);
    if (tit == m_scores.end()) return nullptr;
    const auto sit = tit->second.find(student);
    if (sit == tit->second.end()) return nullptr;
    return &sit->second;
}

bool DtDistill::has_score(const std::string& teacher, const std::string& student) const
{
    return FindScore(teacher, student) != nullptr;
}

int64_t DtDistill::reward_of(const std::string& teacher, const std::string& student) const
{
    const ScoreRec* rec = FindScore(teacher, student);
    if (rec == nullptr) return static_cast<int64_t>(0);
    return rec->reward;
}

} // namespace modelnet
