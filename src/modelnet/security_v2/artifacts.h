// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BITCOIN_MODELNET_SECURITY_V2_ARTIFACTS_H
#define BITCOIN_MODELNET_SECURITY_V2_ARTIFACTS_H
#include <modelnet/security_v2/trust.h>
namespace modelnet::security {
/** Only data files explicitly named in a signed composition are admitted.
 * This copy boundary never imports README code, Python, shared objects, hooks,
 * or executable permissions. Existing model origins remain usable upstream. */
fs::path ImportResident(Database& db, const Policy& policy, const std::string& composition,
                        const fs::path& source, uint64_t byte_budget, int64_t now);
fs::path VerifyResident(Database& db, const std::string& composition);
std::string FileDigest(const fs::path& path, uint64_t expected_bytes);
/** Bounded file-frame for descriptor-only tests. Large-model engines must use
 * an independently qualified full runtime image; this API never truncates. */
std::string ResidentFrame(Database& db, const std::string& composition,
                          std::string_view public_input, uint64_t maximum = 8*1024*1024);
} // namespace modelnet::security
#endif
