// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_evolve/graduate_gate.h>

#include <modelnet/swarm_frontier.h>
#include <modelnet/swarm_gradrealm.h>
#include <modelnet/training_integer.h>

namespace modelnet {

namespace {

void ApplyEffect(const SwarmGradEffect& effect, bool& graduated, bool& realm, bool& exact)
{
    graduated = effect.quality_graduated;
    realm = effect.realm_promoted;
    exact = effect.exact_replay_admitted;
}

} // namespace

bool SwarmEvolveGraduate::Commit(bool measure_accepted, const std::string& parent, const std::string& weights,
                                 uint64_t generation, const SwarmEvolveGraduateRequest& request, std::string& err)
{
    m_graduated = false;
    m_realm_promoted = false;
    m_exact_replay_admitted = false;
    m_id.clear();

    if (request.realm_promote) {
        SwarmGradRealm note;
        note.candidate_id = parent.empty() ? std::string("candidate") : parent;
        note.quality_passed = measure_accepted;
        note.want_realm_promotion = true;
        note.want_exact_replay = false;
        std::string note_err;
        const SwarmGradRealmResult noted = SwarmNoteGraduationRealm(note, note_err);
        const SwarmGradEffect effect = SwarmGraduate(false);
        ApplyEffect(effect, m_graduated, m_realm_promoted, m_exact_replay_admitted);
        if (noted.realm_promoted) m_realm_promoted = true;
        if (noted.exact_replay_admitted) m_exact_replay_admitted = true;
        m_graduated = false;
        m_id.clear();
        err = "REALM";
        return false;
    }

    if (!measure_accepted) {
        const SwarmGradEffect effect = SwarmGraduate(false);
        ApplyEffect(effect, m_graduated, m_realm_promoted, m_exact_replay_admitted);
        m_graduated = false;
        err = "MEASURE";
        return false;
    }

    if (!SwarmSafetyAllowsGraduation(request.safety_regression, request.broad_regression)) {
        const SwarmGradEffect effect = SwarmGraduate(false);
        ApplyEffect(effect, m_graduated, m_realm_promoted, m_exact_replay_admitted);
        m_graduated = false;
        err = "REGRESSION";
        return false;
    }

    SwarmGradRealm note;
    note.candidate_id = parent.empty() ? std::string("candidate") : parent;
    note.quality_passed = true;
    note.want_realm_promotion = false;
    note.want_exact_replay = false;
    std::string note_err;
    const SwarmGradRealmResult noted = SwarmNoteGraduationRealm(note, note_err);
    if (noted.realm_promoted || noted.exact_replay_admitted) {
        m_realm_promoted = noted.realm_promoted;
        m_exact_replay_admitted = noted.exact_replay_admitted;
        err = "REALM";
        return false;
    }

    const SwarmGradEffect effect = SwarmGraduate(true);
    ApplyEffect(effect, m_graduated, m_realm_promoted, m_exact_replay_admitted);
    if (!effect.quality_graduated || effect.realm_promoted || effect.exact_replay_admitted) {
        m_graduated = false;
        m_realm_promoted = false;
        m_exact_replay_admitted = false;
        err = "REALM";
        return false;
    }

    std::string id_err;
    const SwarmCandidateRecord record = SwarmMakeCandidateRecord(
        parent, std::string(INTEGER_PROFILE), weights, std::to_string(generation), "cpu-integer-step", id_err);
    if (record.id.empty() || record.automatic_spend_atoms != kSwarmAutomaticSpendAtoms) {
        m_graduated = false;
        err = id_err.empty() ? std::string("CANONICAL") : id_err;
        return false;
    }

    m_id = record.id;
    m_graduated = true;
    m_realm_promoted = false;
    m_exact_replay_admitted = false;
    err.clear();
    return true;
}

void SwarmEvolveGraduate::Reset()
{
    m_graduated = false;
    m_realm_promoted = false;
    m_exact_replay_admitted = false;
    m_id.clear();
}

} // namespace modelnet
