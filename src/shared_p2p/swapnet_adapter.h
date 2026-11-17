// Copyright (c) 2026 The BTX developers. MIT license.
#ifndef BTX_SHARED_P2P_SWAPNET_ADAPTER_H
#define BTX_SHARED_P2P_SWAPNET_ADAPTER_H
#include <shared_p2p/core.h>
#include <univalue.h>
#include <functional>
namespace shared_p2p {
/** Internal native callback; deliberately NOT registered as a JSON-RPC method. */
inline std::string SwapRouteCall(const std::string& network,const std::string& params,
                                 const std::function<bool(std::int64_t)>& admitted) {
    UniValue a;if(!a.read(params)||!a.isArray()||a.size()!=2||!a[0].isStr()||!a[1].isObject())throw std::invalid_argument("route parameters");
    const auto action=a[0].get_str();const auto& p=a[1];auto c=SwapCore(network);UniValue out(UniValue::VOBJ);
    if(action=="learn") {
        auto peer=p["peer"].getInt<std::int64_t>();auto ttl=p["ttl_ms"].getInt<std::int64_t>();
        if(peer<0 || !admitted(peer) || ttl<=0 || ttl>600000)throw std::invalid_argument("unadmitted route");
        const auto key="btx:"+std::to_string(peer);const auto now=Now();
        if(!c->Admit("swapnet",key,Transport::BTX,network,false,now))throw std::runtime_error("peer limit");
        out.pushKV("ok",c->Learn("swapnet",p["identity"].get_str(),key,p["proof"].get_str(),now+ttl,now));
    } else if(action=="candidates") {
        UniValue rows(UniValue::VARR);auto attempt=p["attempt"].getInt<std::uint64_t>();
        for(const auto& key:c->Routes("swapnet",p["identity"].get_str(),attempt,Now())) {
            auto peer=std::stoll(key.substr(4));if(admitted(peer))rows.push_back(static_cast<std::int64_t>(peer));
        }
        out.pushKV("peers",rows);
    } else if(action=="closed") {c->Close("swapnet","btx:"+std::to_string(p["peer"].getInt<std::int64_t>()));out.pushKV("ok",true);
    } else if(action=="status") {auto s=c->Status();out.pushKV("services",static_cast<std::uint64_t>(s.services));out.pushKV("routes",static_cast<std::uint64_t>(s.routes));out.pushKV("rejected",s.rejected);UniValue modules(UniValue::VOBJ);for(const auto& [name,count]:c->ServicePeers())modules.pushKV(name,static_cast<std::uint64_t>(count));out.pushKV("registered_services",modules);out.pushKV("runtime_broker","private_local_ipc");
    } else throw std::invalid_argument("route action");
    return out.write();
}
} // namespace shared_p2p
#endif
