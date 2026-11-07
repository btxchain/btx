// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_SWARM_LAUNCHPROFILE_H
#define BITCOIN_MODELNET_SWARM_LAUNCHPROFILE_H

#include <modelnet/swarm_launchprof/book.h>
#include <modelnet/swarm_launchprof/quiet.h>
#include <modelnet/swarm_launchprof/stay.h>

#include <cstddef>
#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Launch profile plane.
 * A rename is recorded and does not change the profile.
 *
 * Rename stores a non-empty name and returns false. err is HELD.
 * profile() stays BTX035-LAUNCH-DECODER-2x64. renamed() stays false.
 * An empty name is PROFILE and stores nothing.
 * A second Rename of the same name is REPLAY and keeps the first.
 * PROFILE is decided before REPLAY. REPLAY is decided before HELD.
 *
 * bytes_moved() stays 0. gpu() stays false. launched() stays false.
 * There is no method that changes the profile string or sets renamed() true.
 */
class SwarmLaunchProfile {
public:
    /**
     * Record one rename.
     * An empty name is PROFILE and stores nothing.
     * A non-empty name is stored and the call returns false. err is HELD.
     * A second Rename of the same name is REPLAY and keeps the first.
     * profile() stays BTX035-LAUNCH-DECODER-2x64. renamed() stays false.
     */
    bool Rename(const std::string& name, std::string& err);

    /** Stays BTX035-LAUNCH-DECODER-2x64. Rename does not change it. */
    std::string profile() const;

    /** True when Rename kept this name. */
    bool stored(const std::string& name) const;

    /** The kept name, or empty when it was not stored. */
    std::string stored_name(const std::string& name) const;

    /** Number of kept names. */
    std::size_t rename_count() const;

    /** Stays false. A recorded name does not rename the profile. */
    bool renamed() const;

    /** Stays 0. Nothing is sent. */
    int64_t bytes_moved() const;

    /** Stays false. The gpu is not used. */
    bool gpu() const;

    /** Stays false. Nothing is launched. */
    bool launched() const;

private:
    SwarmLaunchProfileBook m_book;
    SwarmLaunchProfileQuiet m_quiet;
    SwarmLaunchProfileStay m_stay;
};

} // namespace modelnet

#endif // BITCOIN_MODELNET_SWARM_LAUNCHPROFILE_H
