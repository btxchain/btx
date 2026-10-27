// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BITCOIN_MODELNET_SECURITY_V2_EVALUATION_H
#define BITCOIN_MODELNET_SECURITY_V2_EVALUATION_H
#include <modelnet/security_v2/artifacts.h>
#include <modelnet/security_v2/sandbox.h>
namespace modelnet::security {
KeyPair LoadLocalIdentity(Database& db, const Policy& policy, std::string_view role, int64_t now);
Json ReadLocalConfig(Database& db);
std::string PlanId(const Json& plan);
/** Runs an owner-pinned native test over the actual verified composition bytes.
 * Local plans, executable paths and expected outcomes are not peer inputs. */
struct PlanRun { Json receipt; std::string outcome, reason; uint64_t cases{0}; };
PlanRun RunApprovedPlan(Database& db, const Policy& policy, const KeyPair& key,
                        const std::string& composition, const std::string& package,
                        const std::string& request, const std::function<bool()>& allowed);
Json EvaluateChallenge(Database& db, const std::string& challenge, int64_t now);
Json RunChannelCanary(Database& db, const std::string& channel, int64_t now);
} // namespace modelnet::security
#endif
