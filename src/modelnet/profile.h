// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_PROFILE_H
#define BITCOIN_MODELNET_PROFILE_H

#include <modelnet/types.h>
#include <univalue.h>
#include <util/fs.h>

#include <cstdint>
#include <functional>
#include <optional>
#include <string>

namespace modelnet {

/** Operator config preset. Not a protocol role, not consensus, not bounty privilege. */
enum class OperatorProfile : uint8_t {
    PERSONAL = 0,
    INFRASTRUCTURE = 1,
    MIRROR = 2,
    CUSTOM = 3,
};

/** -modelhost parser. AUTO means "host when proven", never "advertise because the helper started". */
enum class HostMode : uint8_t {
    OFF = 0,
    ON = 1,
    AUTO = 2,
};

/** Ordinary launch policy only. No monetary, search-authority, consensus, or bounty fields. */
struct ProfilePolicy {
    bool relay{false};
    bool index{false};
    HostMode host_mode{HostMode::OFF};
    std::string storage_arg{"auto"};
    uint64_t auto_cap_bytes{0};
    uint64_t upload_bps{0};
    bool follow_peers{true};
    bool preserve_rare{false};
    std::string seed{"auto"};
};

/** CLI / file fields that win over a named preset when present. */
struct ProfileOverrides {
    std::optional<bool> relay;
    std::optional<bool> index;
    std::optional<HostMode> host_mode;
    std::optional<std::string> storage_arg;
    std::optional<uint64_t> auto_cap_bytes;
    std::optional<uint64_t> upload_bps;
    std::optional<bool> follow_peers;
    std::optional<bool> preserve_rare;
    std::optional<std::string> seed;
};

constexpr uint64_t PERSONAL_AUTO_CAP_BYTES = 64 * GIB;
constexpr uint64_t INFRASTRUCTURE_AUTO_CAP_BYTES = 512 * GIB;
constexpr uint64_t MIRROR_AUTO_CAP_BYTES = 2048 * GIB;
constexpr uint64_t PERSONAL_UPLOAD_BPS = 2 * MIB;
constexpr uint64_t INFRASTRUCTURE_UPLOAD_BPS = 32 * MIB;
constexpr uint64_t MIRROR_UPLOAD_BPS = 128 * MIB;

const char* OperatorProfileName(OperatorProfile p);
bool ParseOperatorProfile(const std::string& in, OperatorProfile& out);

const char* HostModeName(HostMode m);
/** Accepts auto|1|0|true|false (and on/off/yes/no). Do not use GetBoolArg: "auto" is not a boolean. */
bool ParseHostMode(const std::string& in, HostMode& out);

inline bool HostModeWantsHosting(HostMode m) { return m != HostMode::OFF; }

ProfilePolicy ResolveProfile(OperatorProfile profile, const ProfileOverrides& existing = {});
ProfilePolicy ApplyProfileOverrides(ProfilePolicy policy, const ProfileOverrides& existing);
ProfileOverrides OverridesFromPolicy(const ProfilePolicy& policy);

fs::path OperatorProfilePath(const fs::path& modeldir);
bool LoadOperatorProfile(const fs::path& path, OperatorProfile& profile, ProfilePolicy& policy, std::string& err);
bool SaveOperatorProfile(const fs::path& path, OperatorProfile profile, const ProfilePolicy& policy, std::string& err);
UniValue OperatorProfileToJson(OperatorProfile profile, const ProfilePolicy& policy);

/**
 * Profile may raise an upload ceiling; governor remaining always wins.
 * seeding_allowed=false or governor_upload_bps<=0 is a hard stop (not unlimited).
 */
uint64_t EffectiveHostUploadBps(uint64_t profile_upload_bps, int64_t governor_upload_bps,
                                bool seeding_allowed);

/**
 * Auto-host advertisement (INFRA-04..06,11). All five must be true.
 * may_advertise_reachability is ReachabilityTracker::MayAdvertiseHost (PUBLIC_DIRECT / PUBLIC_MAPPED only).
 */
bool AutoHostShouldAdvertise(bool modelnet, bool helper_ready, uint64_t effective_storage,
                             bool has_verified_seeded_range, bool may_advertise_reachability);

inline bool MayAdvertiseHostAuto(bool modelnet, bool helper_ready, uint64_t effective_storage,
                                bool has_verified_seeded_range, bool may_advertise_reachability)
{
    return AutoHostShouldAdvertise(modelnet, helper_ready, effective_storage,
                                   has_verified_seeded_range, may_advertise_reachability);
}

/**
 * Desired NODE_MODEL_HOST advertisement. Does not touch g_local_services (anonymous in init.cpp).
 * btxd registers SetModelHostServiceBitHook to Add/RemoveLocalServices on CConnman.
 */
void SetNodeModelHostAdvertised(bool on);
bool NodeModelHostAdvertisedWanted();
void SetModelHostServiceBitHook(std::function<void(bool)> hook);
/** Alias used by supervisor: same as SetNodeModelHostAdvertised. */
void ApplyModelHostServiceBit(bool on);

} // namespace modelnet

#endif // BITCOIN_MODELNET_PROFILE_H
