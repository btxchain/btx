// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_MODELNET_FIRSTRUN_H
#define BITCOIN_MODELNET_FIRSTRUN_H

#include <modelnet/auto_storage.h>
#include <modelnet/policy.h>
#include <util/fs.h>

#include <cstdint>
#include <string>

namespace modelnet {

/** Operator-consented first-run storage policy. Missing or zero budget stores no payload. */
struct FirstRunConsent {
    uint64_t storage_bytes{0};
    StorageMode storage_mode{StorageMode::DISABLED};
    SeedMode seed{SeedMode::AUTO};
    bool preserve_rare{false};
    /** When true, -resourcegovernor=auto (use spare resources). Default on for new installs. */
    bool resource_governor_auto{true};
    /** When true, idle mining may run under the governor (-automining). Default off until opted in. */
    bool mining_idle{false};
    int64_t consented_unix{0};
};

/** `<datadir>/modelnet/firstrun.json`. Never under wallet/chainstate. */
fs::path FirstRunConsentPath(const fs::path& datadir);

bool LoadFirstRunConsent(const fs::path& path, FirstRunConsent& out, std::string& err);
bool SaveFirstRunConsent(const fs::path& path, const FirstRunConsent& in, std::string& err);

/** False when DISABLED or explicit 0. AUTO is allowed even if storage_bytes is 0. */
bool AllowPayloadStorage(const FirstRunConsent& in);
bool AllowPayloadStorageFile(const fs::path& path);

/** Same parser as -modelstorage / -modelcache (`80GiB`, raw bytes). */
bool ParseStorageBudget(const std::string& in, uint64_t& out, std::string& err);

/** Headless start: the payload budget the helper may be launched with.
 *  `requested` is the budget the launch config would use ("auto", "0", "80GiB", ...).
 *  It is kept when the operator consented: `explicit_operator_choice` (an
 *  explicit -modelstorage / -modelprofile, or a profile the operator saved),
 *  a first-run consent file that allows payload storage, or a positive
 *  BTX_MODEL_STORAGE. Saved and environment budgets are honored exactly.
 *  With no existing policy, "auto" gets a bounded 1 GiB free-model starter
 *  cache. Explicit zero, a saved refusal, or invalid policy keeps storage off.
 *  Storage does not authorize inference, training, private data, or spending. */
std::string ResolveHeadlessStorageArg(const std::string& requested, bool explicit_operator_choice, const fs::path& consent_path);

/** `BTX_MODEL_STORAGE`. False if unset, empty, zero, or unparsable. */
bool EnvHasPositiveStorageBudget(uint64_t& bytes, std::string& err);

} // namespace modelnet

#endif // BITCOIN_MODELNET_FIRSTRUN_H
