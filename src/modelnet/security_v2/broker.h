// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BITCOIN_MODELNET_SECURITY_V2_BROKER_H
#define BITCOIN_MODELNET_SECURITY_V2_BROKER_H
#include <modelnet/security_v2/trust.h>
#include <modelnet/security_v2/sandbox.h>
namespace modelnet::security {
/** Policy/credential holder, never a model. Workspace paths and executable
 * registrations are local-owner input, not fields accepted from a model. */
class Broker {
    Database& m_db;
    std::string m_boot;
    Json LocalConfig();
    Json Authorize(const Policy& policy, const std::string& grant_id,
                   const Json& context, const Json& request, int64_t now);
    Json Dispatch(const Json& grant, const Json& context, const Json& request,
                  const std::function<bool()>& still_authorized);
public:
    Broker(Database& db, std::string boot);
    Json Prepare(const std::string& grant_id, const Json& context, const Json& request, int64_t now);
    Json Execute(const std::string& secret, const Json& context, const Json& request, int64_t now);
    Json Result(const std::string& permit_id);
    bool CanRelease(const std::string& grant,const Json& context,const Json& request,int64_t now);
    void Pause(int64_t now);
    void Resume(const Json& owner_envelope, int64_t now);
};
void ValidateGrant(const Json& body);
std::string ContextDigest(const Json& context);
std::string RequestDigest(const Json& request);
} // namespace modelnet::security
#endif
