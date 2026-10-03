// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MATMUL_COMPUTE_PROFILE_H
#define BITCOIN_MATMUL_COMPUTE_PROFILE_H

#include <matmul/matmul_v4_rc.h>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

class UniValue;

namespace pwc {

inline constexpr uint64_t P1E_MICROUNITS = 1000000;
inline constexpr char kProductionProfileName[] = "btx-rc-p1e-v1";
inline constexpr char kToyProfileName[] = "btx-rc-p1e-toy-v1";
inline constexpr uint32_t kProfileSchemaVersion = 1;
inline constexpr uint32_t kSemanticsVersion = 1;
inline constexpr uint32_t kSeedDerivationVersion = 1;
inline constexpr uint32_t kHeaderConstructionVersion = 1;
inline constexpr uint32_t kDigestVersion = 1;

struct WorkProfile {
    std::string kind{"compute_work_profile_v1"};
    uint32_t schema_version{kProfileSchemaVersion};
    std::string profile_name;
    std::string workload_family{"btx-rc-exactreplay"};
    bool test_only{false};
    uint32_t rc_profile{1};
    matmul::v4::rc::RCEpisodeParams params{};
    uint32_t mx_block{32};
    uint32_t seg_len{0};
    bool segment_leaves{false};
    bool growth_schedule{false};
    uint32_t transcript_version{0};
    std::string arithmetic_mode{"int8_x_int8_exact_integer"};
    uint32_t seed_derivation_version{kSeedDerivationVersion};
    uint32_t header_construction_version{kHeaderConstructionVersion};
    uint32_t digest_version{kDigestVersion};
    bool exactness_required{true};
    std::string unit_name{"P1E"};
    uint64_t microunits_per_episode{P1E_MICROUNITS};
    uint32_t semantics_version{kSemanticsVersion};
    uint32_t mx_operand_abs_max{0};
    std::string episode_domain{"BTX_RC_EPISODE_V1"};
    std::array<unsigned char, 48> id{};
};

/** Canonical descriptor bytes. Profile identity is this encoding, not a git revision. */
std::vector<unsigned char> CanonicalDescriptor(const WorkProfile& profile);
std::array<unsigned char, 48> ProfileId(const WorkProfile& profile);
std::string ProfileIdHex(const WorkProfile& profile);

const WorkProfile& ProductionProfile();
const WorkProfile& ToyProfile();

/** `allow_test` is false on mainnet. Toy is never a substitute for production. */
const WorkProfile* FindWorkProfile(std::string_view name_or_id, bool allow_test, std::string& err_code);

UniValue WorkProfileJson(const WorkProfile& profile);
UniValue ListWorkProfilesJson(bool allow_test);

} // namespace pwc

#endif
