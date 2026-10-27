// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BTX_MODELNET_SWARM_APPOINTMENT_H
#define BTX_MODELNET_SWARM_APPOINTMENT_H

#include <util/fs.h>

#include <cstdint>
#include <string>

namespace modelnet {

/**
 * Local watchtower appointment. The action is a label. Writing it does not
 * build, sign, or broadcast a transaction, and it is not a native remedy.
 * contest_blocks of 160 is the minimum close margin. That floor is not a
 * claim that the window is production-qualified.
 */
struct SwarmAppointment {
    std::string channel_id;
    int64_t sequence{0};
    int contest_blocks{0};
    bool native_remedy_available{false};
    bool secp_penalty{false};
    std::string action;
};

/**
 * Writes modeldir/swarm/appointment.json by creating the directory, writing a
 * temporary sibling, and renaming it into place. Empty channel_id, a negative
 * sequence, or an action other than HASHLOCK_REMEDY, STALE_STATE_ALERT, or
 * DRAIN_AND_NOTIFY is APPOINTMENT. contest_blocks below 160 is CONTEST_WINDOW.
 * native_remedy_available must be false, else NATIVE_REMEDY. secp_penalty must
 * be false, else SECP_PENALTY.
 */
bool SwarmWriteAppointment(const fs::path& modeldir, const SwarmAppointment& appointment, std::string& err);

/** Restores the stored appointment. A missing or unreadable file is APPOINTMENT_READ. */
bool SwarmReadAppointment(const fs::path& modeldir, SwarmAppointment& appointment, std::string& err);

} // namespace modelnet

#endif // BTX_MODELNET_SWARM_APPOINTMENT_H
