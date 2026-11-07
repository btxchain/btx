// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_PROGRESS_H
#define BITCOIN_MODELNET_SWARM_PROGRESS_H

#include <modelnet/swarm_progress/codes.h>
#include <modelnet/swarm_progress/limits.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Progress of one stored sample.
 *
 * Sample stores one loss_ppm and step. An empty id is WORK and stores
 * nothing. loss_ppm < 0 or step < 0 is SAMPLE and stores nothing. The
 * first accepted sample is stored. A later sample with a different
 * loss_ppm or a higher step is stored and counts as a meaningful change.
 * An identical loss_ppm and step is REPLAY, is not stored again, and is
 * not a correction trigger. A same loss_ppm with a lower step is not
 * stored, returns REPLAY, and is not a correction trigger. A refused
 * sample leaves the stored sample unchanged.
 *
 * Stall reports identical samples. same_count >= 3 returns true and sets
 * correcting() true when a sample is already stored. same_count < 3
 * returns false with PLATEAU and does not set correcting(). With no
 * stored sample the result is PLATEAU. A plateau is not a kill. killed()
 * stays false. Sample never sets correcting().
 *
 * Correct changes nothing unless correcting() is true. If correcting()
 * is false, the result is NOT_CORRECTING and the recipe is unchanged.
 * The first recipe is stored. A later recipe is accepted only when it
 * equals the stored recipe, and that acceptance does not change the
 * bytes. A different recipe is SECRET and the stored recipe stays.
 * Correction does not mutate the recipe.
 *
 * killed(), launched(), gpu(), and broadcast() stay false.
 * automatic_spend() returns "0". bytes_moved() returns 0. This class
 * does not open a socket and does not spend.
 */
class SwarmProgress {
public:
    bool Sample(const std::string& id, int64_t loss_ppm, int64_t step, std::string& err);
    bool Stall(const std::string& id, int64_t same_count, std::string& err);
    bool Correct(const std::string& id, const std::string& recipe, std::string& err);

    bool sampled() const;
    int64_t loss_ppm() const;
    int64_t step() const;
    bool meaningful() const;
    bool correcting() const;
    bool killed() const;
    const std::string& recipe() const;

    bool launched() const;
    bool gpu() const;
    bool broadcast() const;
    std::string automatic_spend() const;
    int64_t bytes_moved() const;

private:
    bool m_sampled{false};
    int64_t m_loss_ppm{0};
    int64_t m_step{0};
    bool m_meaningful{false};
    bool m_correcting{false};
    bool m_has_recipe{false};
    std::string m_recipe;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_PROGRESS_H
