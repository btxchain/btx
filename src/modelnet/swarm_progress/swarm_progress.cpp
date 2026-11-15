// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <modelnet/swarm_progress/swarm_progress.h>

#include <cstdint>
#include <string>

namespace modelnet {

bool SwarmProgress::Sample(const std::string& id, int64_t loss_ppm, int64_t step, std::string& err)
{
    if (id.empty()) {
        err = kSwarmProgressWork;
        return false;
    }
    if (loss_ppm < 0 || step < 0) {
        err = kSwarmProgressSample;
        return false;
    }
    if (!m_sampled) {
        m_loss_ppm = loss_ppm;
        m_step = step;
        m_sampled = true;
        err.clear();
        return true;
    }
    // A different loss or a higher step replaces the stored sample.
    if (loss_ppm != m_loss_ppm || step > m_step) {
        m_loss_ppm = loss_ppm;
        m_step = step;
        m_meaningful = true;
        err.clear();
        return true;
    }
    // Identical values, and a same loss with a lower step, are not stored.
    // Neither path sets correcting().
    err = kSwarmProgressReplay;
    return false;
}

bool SwarmProgress::Stall(const std::string& id, int64_t same_count, std::string& err)
{
    if (id.empty()) {
        err = kSwarmProgressWork;
        return false;
    }
    if (!m_sampled || same_count < kSwarmProgressIdenticalStall) {
        err = kSwarmProgressPlateau;
        return false;
    }
    m_correcting = true;
    err.clear();
    return true;
}

bool SwarmProgress::Correct(const std::string& id, const std::string& recipe, std::string& err)
{
    if (id.empty()) {
        err = kSwarmProgressWork;
        return false;
    }
    if (!m_correcting) {
        err = kSwarmProgressNotCorrecting;
        return false;
    }
    if (!m_has_recipe) {
        m_recipe = recipe;
        m_has_recipe = true;
        err.clear();
        return true;
    }
    if (recipe != m_recipe) {
        err = kSwarmProgressSecret;
        return false;
    }
    err.clear();
    return true;
}

bool SwarmProgress::sampled() const
{
    return m_sampled;
}

int64_t SwarmProgress::loss_ppm() const
{
    return m_loss_ppm;
}

int64_t SwarmProgress::step() const
{
    return m_step;
}

bool SwarmProgress::meaningful() const
{
    return m_meaningful;
}

bool SwarmProgress::correcting() const
{
    return m_correcting;
}

bool SwarmProgress::killed() const
{
    return kSwarmProgressKilled;
}

const std::string& SwarmProgress::recipe() const
{
    return m_recipe;
}

bool SwarmProgress::launched() const
{
    return kSwarmProgressLaunched;
}

bool SwarmProgress::gpu() const
{
    return kSwarmProgressGpu;
}

bool SwarmProgress::broadcast() const
{
    return kSwarmProgressBroadcast;
}

std::string SwarmProgress::automatic_spend() const
{
    return std::string{kSwarmProgressAutomaticSpend};
}

int64_t SwarmProgress::bytes_moved() const
{
    return kSwarmProgressBytesMoved;
}

} // namespace modelnet
