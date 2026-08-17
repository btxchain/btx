// Copyright (c) 2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <node/chainstatemanager_args.h>

#include <arith_uint256.h>
#include <common/args.h>
#include <common/system.h>
#include <logging.h>
#include <node/coins_view_args.h>
#include <node/database_args.h>
#include <pow.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/result.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <validation.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <limits>
#include <optional>
#include <string>

namespace node {
namespace {
std::optional<kernel::ReorgProtectionProfile> ParseReorgProtectionProfile(std::string profile)
{
    std::transform(profile.begin(), profile.end(), profile.begin(), [](unsigned char c) {
        return std::tolower(c);
    });

    if (profile == "standard" || profile == "miner") return kernel::ReorgProtectionProfile::STANDARD;
    if (profile == "archive") return kernel::ReorgProtectionProfile::ARCHIVE;
    if (profile == "balanced") return kernel::ReorgProtectionProfile::BALANCED;
    if (profile == "strict") return kernel::ReorgProtectionProfile::STRICT;
    if (profile == "emergency") return kernel::ReorgProtectionProfile::EMERGENCY;
    return std::nullopt;
}

util::Result<uint32_t> ParsePositiveDepthArg(const char* arg_name, int64_t value)
{
    if (value < 1) {
        return util::Error{Untranslated(strprintf(
            "Invalid %s value (%d), must be at least 1", arg_name, value))};
    }
    return static_cast<uint32_t>(std::min<int64_t>(value, std::numeric_limits<uint32_t>::max()));
}
} // namespace

util::Result<void> ApplyArgsManOptions(const ArgsManager& args, ChainstateManager::Options& opts)
{
    if (auto value{args.GetIntArg("-checkblockindex")}) {
        // Interpret bare -checkblockindex argument as 1 instead of 0.
        opts.check_block_index = args.GetArg("-checkblockindex")->empty() ? 1 : *value;
    }

    if (auto value{args.GetBoolArg("-checkpoints")}) opts.checkpoints_enabled = *value;

    if (auto value{args.GetArg("-minimumchainwork")}) {
        if (auto min_work{uint256::FromUserHex(*value)}) {
            opts.minimum_chain_work = UintToArith256(*min_work);
        } else {
            return util::Error{Untranslated(strprintf("Invalid minimum work specified (%s), must be up to %d hex digits", *value, uint256::size() * 2))};
        }
    }

    if (auto value{args.GetArg("-assumevalid")}) {
        if (auto block_hash{uint256::FromUserHex(*value)}) {
            opts.assumed_valid_block = *block_hash;
        } else {
            return util::Error{Untranslated(strprintf("Invalid assumevalid block hash specified (%s), must be up to %d hex digits (or 0 to disable)", *value, uint256::size() * 2))};
        }
    }

    if (auto value{args.GetIntArg("-maxtipage")}) opts.max_tip_age = std::chrono::seconds{*value};

    if (auto value{args.GetArg("-matmulvalidation")}) {
        if (*value == "consensus") {
            opts.matmul_validation_mode = kernel::MatMulValidationMode::CONSENSUS;
        } else if (*value == "trusted") {
            opts.matmul_validation_mode = kernel::MatMulValidationMode::TRUSTED;
        } else if (*value == "economic") {
            opts.matmul_validation_mode = kernel::MatMulValidationMode::ECONOMIC;
        } else if (*value == "spv") {
            opts.matmul_validation_mode = kernel::MatMulValidationMode::SPV;
        } else {
            return util::Error{Untranslated(strprintf(
                "Invalid -matmulvalidation value (%s). Valid values: consensus, trusted, economic, spv", *value))};
        }
    }

    if (auto value{args.GetBoolArg("-retainshieldedcommitmentindex")}) {
        opts.retain_shielded_commitment_index = *value;
    }

    if (auto value{args.GetBoolArg("-shieldedstartupaudit")}) {
        opts.shielded_startup_audit = *value;
    }

    if (auto value{args.GetBoolArg("-fastshieldedstartup")}) {
        opts.fast_shielded_startup = *value;
    }

    if (auto value{args.GetBoolArg("-resetshieldedstate")}) {
        opts.reset_shielded_state = *value;
    }

    if (auto value{args.GetBoolArg("-allowunpinnedshieldedsnapshot")}) {
        opts.allow_unpinned_shielded_snapshot = *value;
    }

    // Deep-reorg defense. These are PER-NODE, NON-CONSENSUS fork-choice
    // controls. The named profile supplies warn/finality/hysteresis depths;
    // manual parking remains an explicit opt-in.
    if (auto value{args.GetArg("-reorgprotectionprofile")}) {
        const auto profile = ParseReorgProtectionProfile(*value);
        if (!profile) {
            return util::Error{Untranslated(strprintf(
                "Invalid -reorgprotectionprofile value (%s), expected standard, miner, archive, balanced, strict, or emergency", *value))};
        }
        opts.reorg_protection_profile = *profile;
        opts.deep_reorg_action = kernel::GetReorgProtectionProfileSettings(*profile).action;
    } else {
        opts.deep_reorg_action = kernel::GetReorgProtectionProfileSettings(opts.reorg_protection_profile).action;
    }

    if (auto value{args.GetBoolArg("-parkdeepreorg")}) {
        opts.deep_reorg_action = *value ? kernel::DeepReorgAction::PARK
                                        : kernel::DeepReorgAction::WARN;
    }

    if (auto value{args.GetIntArg("-maxreorgdepthwarn")}) {
        auto parsed = ParsePositiveDepthArg("-maxreorgdepthwarn", *value);
        if (!parsed) return util::Error{util::ErrorString(parsed)};
        opts.max_reorg_depth_warn = *parsed;
    }

    if (auto value{args.GetIntArg("-maxreorgdepthpark")}) {
        auto parsed = ParsePositiveDepthArg("-maxreorgdepthpark", *value);
        if (!parsed) return util::Error{util::ErrorString(parsed)};
        opts.max_reorg_depth_park = *parsed;
    }

    if (auto value{args.GetIntArg("-localfinalitydepth")}) {
        auto parsed = ParsePositiveDepthArg("-localfinalitydepth", *value);
        if (!parsed) return util::Error{util::ErrorString(parsed)};
        opts.local_finality_depth = *parsed;
    }

    if (auto value{args.GetIntArg("-reorghysteresisdepth")}) {
        if (*value < 0) {
            return util::Error{Untranslated(strprintf(
                "Invalid -reorghysteresisdepth value (%d), must be at least 0", *value))};
        }
        opts.reorg_hysteresis_depth =
            static_cast<uint32_t>(std::min<int64_t>(*value, std::numeric_limits<uint32_t>::max()));
    }

    if (auto value{args.GetIntArg("-reorghysteresisworkmargin")}) {
        if (*value < 0) {
            return util::Error{Untranslated(strprintf(
                "Invalid -reorghysteresisworkmargin value (%d), must be at least 0", *value))};
        }
        opts.reorg_hysteresis_work_margin =
            static_cast<uint32_t>(std::min<int64_t>(*value, std::numeric_limits<uint32_t>::max()));
    }

    if (auto value{args.GetArg("-signermintargetcompact")}) {
        std::string hex = *value;
        if (hex.size() >= 2 && hex[0] == '0' && (hex[1] == 'x' || hex[1] == 'X')) {
            hex = hex.substr(2);
        }
        if (hex.size() != 8) {
            return util::Error{Untranslated(strprintf(
                "Invalid -signermintargetcompact value (%s), expected 8 hex digits (compact nBits)", *value))};
        }
        uint32_t compact = 0;
        for (char c : hex) {
            const int digit = HexDigit(c);
            if (digit < 0) {
                return util::Error{Untranslated(strprintf(
                    "Invalid -signermintargetcompact value (%s), expected 8 hex digits (compact nBits)", *value))};
            }
            compact = (compact << 4) | static_cast<uint32_t>(digit);
        }
        if (!DeriveTarget(compact, opts.chainparams.GetConsensus().powLimit)) {
            return util::Error{Untranslated(strprintf(
                "Invalid -signermintargetcompact value (%s), compact target is negative, zero, overflowed, or exceeds powLimit", *value))};
        }
        opts.signer_min_target_compact = compact;
    }

    if (auto value{args.GetIntArg("-signerextraworkfromheight")}) {
        if (*value < 0) {
            return util::Error{Untranslated(strprintf(
                "Invalid -signerextraworkfromheight value (%d), must be at least 0", *value))};
        }
        opts.signer_extra_work_from_height =
            static_cast<int32_t>(std::min<int64_t>(*value, std::numeric_limits<int32_t>::max()));
    }

    if (opts.signer_min_target_compact.has_value() != opts.signer_extra_work_from_height.has_value()) {
        return util::Error{Untranslated(
            "-signermintargetcompact and -signerextraworkfromheight must be set together")};
    }
    if (opts.signer_min_target_compact.has_value()) {
        LogInfo("Local signer extra-work pin enabled (NOT consensus): compact=0x%08x fromheight=%d\n",
                *opts.signer_min_target_compact,
                *opts.signer_extra_work_from_height);
    }

    ReadDatabaseArgs(args, opts.coins_db);
    ReadCoinsViewArgs(args, opts.coins_view);

    int script_threads = args.GetIntArg("-par", DEFAULT_SCRIPTCHECK_THREADS);
    if (script_threads <= 0) {
        // -par=0 means autodetect (number of cores - 1 script threads)
        // -par=-n means "leave n cores free" (number of cores - n - 1 script threads)
        script_threads += GetNumCores();
    }
    // Subtract 1 because the main thread counts towards the par threads.
    opts.worker_threads_num = script_threads - 1;

    if (auto value{args.GetIntArg("-prevoutfetchthreads")}) {
        if (*value < 0) {
            return util::Error{Untranslated(strprintf(
                "-prevoutfetchthreads must be non-negative (got %d). Use 0 to disable parallel input fetching.",
                *value))};
        }
        opts.prevoutfetch_threads_num = static_cast<int32_t>(std::min<int64_t>(*value, MAX_PREVOUTFETCH_THREADS));
    }

    if (auto max_size = args.GetIntArg("-maxsigcachesize")) {
        // 1. When supplied with a max_size of 0, both the signature cache and
        //    script execution cache create the minimum possible cache (2
        //    elements). Therefore, we can use 0 as a floor here.
        // 2. Multiply first, divide after to avoid integer truncation.
        size_t clamped_size_each = std::max<int64_t>(*max_size, 0) * (1 << 20) / 2;
        opts.script_execution_cache_bytes = clamped_size_each;
        opts.signature_cache_bytes = clamped_size_each;
    }

    return {};
}
} // namespace node
