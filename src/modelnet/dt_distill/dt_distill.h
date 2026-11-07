// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_DT_DISTILL_DT_DISTILL_H
#define BITCOIN_MODELNET_DT_DISTILL_DT_DISTILL_H

#include <modelnet/nifdt_contract/contract.h>

#include <cstdint>
#include <map>
#include <string>

namespace modelnet {

/** The teacher name was empty, or that teacher was not bound. Nothing is stored. */
inline constexpr char DT_DISTILL_TEACHER[] = "TEACHER";

/** The student name was empty, or it is not the student bound to that teacher. */
inline constexpr char DT_DISTILL_STUDENT[] = "STUDENT";

/** The student is the teacher, or the caller scored itself. Nothing is stored. */
inline constexpr char DT_DISTILL_SELF[] = "SELF";

/** Update found no stored score. student_weight() stays 0. */
inline constexpr char DT_DISTILL_MISSING[] = "MISSING";

/** Update found no new score. student_weight() is not moved again. */
inline constexpr char DT_DISTILL_UNCHANGED[] = "UNCHANGED";

/**
 * In-memory teacher/student distillation step. This is not a V4.1 claim.
 * qualified_v41() stays false.
 *
 * Bind stores one student under a teacher. An empty teacher is TEACHER.
 * An empty student is STUDENT. A teacher equal to the student is SELF.
 * Those refusals store nothing. A second bind of the same teacher is
 * NIFDT_REPLAY and keeps the first student. The teacher record has no
 * weight.
 *
 * Score stores one reward for a bound pair. self_scored true is SELF and
 * stores nothing. A teacher that was not bound is TEACHER and stores
 * nothing. The student must not be the teacher. A stored score records
 * the reward once and does not change student_weight(). A second score
 * of the same pair is NIFDT_REPLAY and keeps the first reward.
 *
 * Update adds each stored reward that has not yet been applied.
 * student_weight() starts at 0 and moves by that reward only when a
 * score exists. No stored score is MISSING and leaves the weight at 0.
 * A later Update with no new score is UNCHANGED and does not change the
 * weight again. new_generation() becomes true only on the first
 * successful Update.
 *
 * GpuStep returns false with NIFDT_ENGINE_ABSENT and does not change
 * student_weight(). launched(), gpu(), and broadcast() stay false.
 * automatic_spend() is "0". No process is started and no socket is opened.
 */
class DtDistill {
public:
    bool Bind(const std::string& teacher, const std::string& student, std::string& err);
    bool Score(const std::string& teacher,
               const std::string& student,
               int64_t reward,
               bool self_scored,
               std::string& err);
    bool Update(std::string& err);
    bool GpuStep(std::string& err);

    bool bound(const std::string& teacher) const;
    /** Bound student, or empty when that teacher was not stored. */
    std::string student_of(const std::string& teacher) const;
    bool has_score(const std::string& teacher, const std::string& student) const;
    /** Stored reward, or 0 when that pair was not stored. */
    int64_t reward_of(const std::string& teacher, const std::string& student) const;
    int64_t stored_scores() const { return m_stored; }
    int64_t student_weight() const { return m_student_weight; }
    bool new_generation() const { return m_new_generation; }

    bool qualified_v41() const { return false; }
    bool launched() const { return false; }
    bool gpu() const { return false; }
    bool broadcast() const { return false; }
    std::string automatic_spend() const { return NIFDT_AUTOMATIC_SPEND; }

private:
    struct ScoreRec {
        int64_t reward{0};
        bool applied{false};
    };

    const ScoreRec* FindScore(const std::string& teacher, const std::string& student) const;

    std::map<std::string, std::string> m_bound;
    std::map<std::string, std::map<std::string, ScoreRec>> m_scores;
    int64_t m_stored{0};
    int64_t m_student_weight{0};
    bool m_new_generation{false};
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_DT_DISTILL_DT_DISTILL_H
