// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BTX_SHARED_P2P_MODELNET_ADAPTER_H
#define BTX_SHARED_P2P_MODELNET_ADAPTER_H
#include <shared_p2p/core.h>
namespace shared_p2p {
/** Called after strict PQ1 and network admission, never from untrusted JSON. */
inline bool ObserveModel(const std::string& network,const std::string& endpoint,
                         const std::string& verified_pin,bool network_verified) {
    if(!network_verified || verified_pin.size()!=96 || !std::all_of(verified_pin.begin(),verified_pin.end(),[](char c){return (c>='0'&&c<='9')||(c>='a'&&c<='f');}))return false;
    const auto now=Now();auto c=ModelCore(network);const std::string peer="pq1:"+endpoint;
    if(!c->Admit("modelnet",peer,Transport::PQ1,network,true,now))return false;
    return c->Learn("modelnet",verified_pin,peer,verified_pin,now+90000,now);
}
inline bool ModelControlBudget(const std::string& network,const std::string& endpoint,std::size_t bytes) {
    return ModelCore(network)->Ingress("modelnet","pq1:"+endpoint,bytes,Now());
}
inline std::size_t ModelSearchOffset(const std::string& network,const std::string& endpoint) {
    return ModelCore(network)->CursorGet("modelnet","pq1:"+endpoint,Now());
}
inline void ModelSearchAdvance(const std::string& network,const std::string& endpoint,bool more) {
    ModelCore(network)->CursorAdvance("modelnet","pq1:"+endpoint,16,more,Now());
}
} // namespace shared_p2p
#endif
