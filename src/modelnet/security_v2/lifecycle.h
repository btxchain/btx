// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BITCOIN_MODELNET_SECURITY_V2_LIFECYCLE_H
#define BITCOIN_MODELNET_SECURITY_V2_LIFECYCLE_H
#include <modelnet/security_v2/evaluation.h>
namespace modelnet::security {
/** A channel is a signed proposal, not host authority. The owner subscription
 * keeps explicit runtime, tool-schema and privilege ceilings across updates. */
class Lifecycle {
    Database& m_db;
    void CheckMandate(const Policy&, const Json&, const Admission&, int64_t now);
    bool Eligible(const Policy&,const std::string&,int64_t now);
public:
    explicit Lifecycle(Database& db):m_db(db){}
    void Follow(const std::string& mandate_id,int64_t now);
    void Stage(const std::string& update_id,int64_t now);
    void Observe(const std::string& channel,const std::string& receipt_id,int64_t now);
    void Activate(const std::string& channel,int64_t now);
    void Tick(int64_t now);
    Json Status();
};
} // namespace modelnet::security
#endif
