// Copyright (c) 2026 The BTX developers. MIT license.
// Internal callback only: deliberately NOT registered in the public RPC table.
#include <swapnet/wallet_bridge.h>
#include <swapnet/node.h>
#include <key_io.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <script/descriptor.h>
#include <script/signingprovider.h>
#include <addresstype.h>
#include <sync.h>
#include <util/strencodings.h>
#include <util/time.h>
#include <wallet/rpc/util.h>
#include <wallet/scriptpubkeyman.h>
#include <wallet/wallet.h>
namespace swapnet {
namespace {
UniValue ImportHTLC(const JSONRPCRequest& request) {
    using namespace wallet;
    if(request.authUser!="__swapnet_internal__"||request.params.size()!=5)
        throw JSONRPCError(RPC_INVALID_PARAMETER,"Internal wallet operation required");
    auto w=GetWalletForJSONRPCRequest(request);
    if(!w)throw JSONRPCError(RPC_WALLET_NOT_FOUND,"SwapNet wallet not found");
    const auto hash=request.params[0].get_str(), claim=request.params[1].get_str(), refund=request.params[2].get_str();
    const auto height=request.params[3].getInt<int64_t>();const auto address=request.params[4].get_str();
    if(hash.size()!=64||!IsHex(hash)||claim.size()!=2624||!IsHex(claim)||refund.size()!=2624||!IsHex(refund)||height<1||height>=500000000)
        throw JSONRPCError(RPC_INVALID_PARAMETER,"Invalid native HTLC terms");
    LOCK(w->cs_wallet);EnsureWalletIsUnlocked(*w);
    const auto dest=DecodeDestination(address);
    if(!IsValidDestination(dest)||!(w->IsMine(dest)&ISMINE_SPENDABLE))throw JSONRPCError(RPC_WALLET_ERROR,"Local HTLC key is not spendable");
    const auto script=GetScriptForDestination(dest);
    FlatSigningProvider provider;bool found=false;
    auto managers=w->GetScriptPubKeyMans(script);if(managers.empty())managers=w->GetAllScriptPubKeyMans();
    for(auto* manager:managers) {
        auto* d=dynamic_cast<DescriptorScriptPubKeyMan*>(manager);if(!d)continue;
        auto keys=d->GetSigningProvider(script,true);if(!keys)continue;
        for(const auto& [pub,key]:keys->pq_keys) {
            const auto hex=HexStr(pub);
            if(key.IsValid()&&(hex==claim||hex==refund)){provider.pq_keys.emplace(pub,key);found=true;}
        }
    }
    if(!found)throw JSONRPCError(RPC_WALLET_ERROR,"Owned key does not match either signed contract branch");
    const auto text="mr(htlc_sha256("+hash+","+claim+"),refund("+std::to_string(height)+","+refund+"))";
    std::string error;
    auto descriptors=Parse(AddChecksum(text),provider,error,true);
    if(descriptors.size()!=1)throw JSONRPCError(RPC_INVALID_PARAMETER,"Native HTLC descriptor was rejected");
    WalletDescriptor descriptor(std::move(descriptors[0]),GetTime(),0,0,0);
    if(!w->AddWalletDescriptor(descriptor,provider,"swapnet-htlc",false))
        throw JSONRPCError(RPC_WALLET_ERROR,"Could not persist the native HTLC descriptor");
    UniValue result(UniValue::VOBJ);result.pushKV("success",true);return result;
}
}
void InstallWalletBridge() {SetWalletBridge(ImportHTLC);}
}
