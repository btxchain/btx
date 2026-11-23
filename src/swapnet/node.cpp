// Copyright (c) 2026 The BTX developers. MIT license.
#include <bitcoin-build-config.h>

#include <swapnet/node.h>
#include <swapnet/embed.h>
#include <swapnet/runtime.h>
#include <chainparams.h>
#include <clientversion.h>
#include <node/context.h>
#include <interfaces/wallet.h>
#include <rpc/protocol.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <common/args.h>
#include <crypto/hex_base.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <logging.h>
#include <random.h>
#include <shared_p2p/runtime.h>
#include <algorithm>
#include <chrono>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>

#if defined(SWAPNET_WITH_WALLET) && defined(USE_SQLITE)
#include <wallet/sqlite.h>
#endif

namespace swapnet {
namespace {
std::mutex g_mutex;
std::shared_ptr<Runtime> g_runtime;
#if defined(SWAPNET_WITH_WALLET) && defined(USE_SQLITE)
struct SQLiteRuntime {
    // Runtime stops and closes the Python connection before the guard releases SQLite.
    wallet::SQLiteLibrary sqlite;
    Runtime runtime;

    SQLiteRuntime(const std::string& network, std::string config, Callbacks callbacks)
        : runtime(network, std::move(config), std::move(callbacks)) {}
};
#endif
WalletBridge g_wallet_bridge;
std::set<std::string> g_owners;
std::shared_ptr<Runtime> Current() { std::lock_guard<std::mutex> lock(g_mutex); return g_runtime; }
std::int64_t NowMS() { return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count(); }
std::string EncodePath(const std::string& s) {
    static constexpr char HEX[]="0123456789ABCDEF"; std::string out;
    for (unsigned char c:s) {
        if ((c>='a'&&c<='z')||(c>='A'&&c<='Z')||(c>='0'&&c<='9')||c=='-'||c=='_'||c=='.'||c=='~') out+=c;
        else { out+='%'; out+=HEX[c>>4]; out+=HEX[c&15]; }
    } return out;
}
std::string RequestWallet(const JSONRPCRequest& r) {
    if (r.URI.rfind("/wallet/",0)!=0) return {};
    std::string out, encoded=r.URI.substr(8);
    if (encoded.size()>3072) throw JSONRPCError(RPC_INVALID_PARAMETER,"Wallet path too long");
    for (std::size_t i=0;i<encoded.size();++i) {
        if (encoded[i]=='%') {
            if (i+2>=encoded.size()||HexDigit(encoded[i+1])<0||HexDigit(encoded[i+2])<0) throw JSONRPCError(RPC_INVALID_PARAMETER,"Invalid wallet path");
            char c=static_cast<char>(HexDigit(encoded[i+1])*16+HexDigit(encoded[i+2]));
            if (!c) throw JSONRPCError(RPC_INVALID_PARAMETER,"Invalid wallet path");
            out+=c; i+=2;
        } else out+=encoded[i];
    } return out;
}
bool NativeObjectAbsent(const UniValue& error) {
    // Only the fixed not-found texts. A txindex that is still syncing uses a
    // different sentence and must stay a failure, or a confirmed transaction
    // would be broadcast again. The message itself is not returned to Python.
    if (!error.isObject() || !error.exists("code") || !error["code"].isNum()) return false;
    if (error["code"].getInt<int>() != RPC_INVALID_ADDRESS_OR_KEY) return false;
    if (!error.exists("message") || !error["message"].isStr()) return false;
    const std::string& message = error["message"].get_str();
    static constexpr const char* kPrefixes[] = {
        "Transaction not in mempool",
        "Invalid or non-wallet transaction id",
        "No such mempool or blockchain transaction",
        "No such mempool transaction. Use -txindex",
        "No such transaction found in the provided block",
    };
    for (const char* prefix : kPrefixes) {
        const std::size_t n = std::char_traits<char>::length(prefix);
        if (message.size() >= n && message.compare(0, n, prefix) == 0) return true;
    }
    return false;
}
const std::set<std::string> NATIVE_METHODS={
 "getblockchaininfo","getblockhash","getblockcount","getbestblockhash","getblockheader","getblock",
 "getrawtransaction","gettxout","scantxoutset","getmempoolentry","gettxspendingprevout","getdescriptorinfo","deriveaddresses","validateaddress",
 "decodescript","decodepsbt","decoderawtransaction","createpsbt","finalizepsbt","sendrawtransaction","testmempoolaccept",
 "listwallets","getwalletinfo","getnewaddress","getaddressinfo","listunspent","listlockunspent","lockunspent","gettransaction","listtransactions",
 "exportpqkey","walletcreatefundedpsbt","walletprocesspsbt","importdescriptors","signmessage","verifymessage","_swapnet_import_htlc","_swapnet_connect_peer","_shared_p2p"};
std::string CoreCall(node::NodeContext& node,const std::string& wallet,const std::string& method,const std::string& params) {
    if (!NATIVE_METHODS.count(method)||params.size()>4*1024*1024) throw std::runtime_error("Native request rejected");
    JSONRPCRequest r; r.context=&node; r.strMethod=method; r.authUser="__swapnet_internal__";
    // "-" blocks every wallet. A named call is limited to that wallet.
    // listwallets is the only unnamed read used to discover a single wallet.
    if (!wallet.empty()) {
        r.URI="/wallet/"+EncodePath(wallet);
        r.m_wallet_restriction=wallet;
    } else if (method=="listwallets") r.m_wallet_restriction.clear();
    if (!r.params.read(params)||!r.params.isArray()) throw std::runtime_error("Invalid native parameters");
    if (method=="_swapnet_connect_peer") {
        if (!wallet.empty() || r.params.size()!=1 || !r.params[0].isStr()) throw std::runtime_error("Invalid peer request");
        const std::string endpoint=r.params[0].get_str();
        if (endpoint.empty() || endpoint.size()>300 || std::any_of(endpoint.begin(),endpoint.end(),
            [](unsigned char c){return c<=32||c=='/'||c=='?'||c=='#'||c=='@'||c=='%'||c=='\\';}))
            throw std::runtime_error("Unsafe endpoint");
        r.strMethod="addnode";
        r.params=UniValue(UniValue::VARR);
        r.params.push_back(endpoint);
        r.params.push_back("onetry");
        auto text=tableRPC.execute(r).write();
        if (text.size()>4*1024*1024) throw std::runtime_error("Native result exceeds bound");
        return text;
    }
    if (method=="_shared_p2p") {
        if (!wallet.empty() || r.params.size()!=2 || !r.params[0].isStr() || !r.params[1].isObject())
            throw std::runtime_error("Invalid shared control request");
        const auto op=r.params[0].get_str();
        const auto& body=r.params[1];
        auto& core=btx::p2p::AuthoritativeCore();
        UniValue out(UniValue::VOBJ);
        out.pushKV("available",core.Running());
        out.pushKV("network",core.Network());
        out.pushKV("wallet_authority",false);
        if (op=="status") return out.write();
        if (op=="learn") {
            if (!body.exists("identity")||!body.exists("peer")||!body.exists("expires_at")) throw std::runtime_error("Missing route scope");
            const auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            out.pushKV("recorded",core.LearnRoute(btx::p2p::Service::SwapNet,body["identity"].get_str(),body["peer"].get_str(),body["expires_at"].getInt<int64_t>(),now));
            return out.write();
        }
        if (op=="record") {
            if (!body.exists("key") || !body.exists("sequence") || !body.exists("expires_at") || !body.exists("record"))
                throw std::runtime_error("Missing local record fields");
            if (!body["key"].isStr() || !body["record"].isStr() || body["record"].get_str().size()>24576)
                throw std::runtime_error("Unbounded public record");
            const auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            btx::p2p::Record record{body["key"].get_str(),body["record"].get_str(),
                static_cast<uint64_t>(body["sequence"].getInt<int64_t>()),body["expires_at"].getInt<int64_t>()};
            out.pushKV("recorded",core.PublishVerified(btx::p2p::Service::SwapNet,record,now));
            return out.write();
        }
        if (op=="routes") {
            if (!body.exists("identity")||!body["identity"].isStr()) throw std::runtime_error("Missing identity");
            const auto now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
            UniValue routes(UniValue::VARR);
            for (const auto& peer:core.Routes(btx::p2p::Service::SwapNet,body["identity"].get_str(),now)) routes.push_back(peer);
            out.pushKV("routes",routes);
            return out.write();
        }
        throw std::runtime_error("Unsupported shared control request");
    }
    UniValue result;
    try {
        if (method=="_swapnet_import_htlc") {
            WalletBridge bridge; {std::lock_guard<std::mutex> lock(g_mutex); bridge=g_wallet_bridge;}
            if (!bridge||!node.wallet_loader) throw std::runtime_error("Wallet integration is unavailable");
            // Wallet RPCs require WalletContext. The public table swaps it in;
            // this internal bridge does not go through that table.
            node.wallet_loader->assignContextHACK(r.context);
            result=bridge(r);
        } else result=tableRPC.execute(r);
    } catch (const UniValue& error) {
        if (NativeObjectAbsent(error)) throw NativeAbsent();
        throw;
    }
    auto text=result.write(); if(text.size()>4*1024*1024) throw std::runtime_error("Native result exceeds bound");
    return text;
}
}
void SetWalletBridge(WalletBridge bridge) { std::lock_guard<std::mutex> lock(g_mutex);g_wallet_bridge=std::move(bridge); }
void SetupArgs(ArgsManager& args) {
    args.AddArg("-swapnet", "Run native SwapNet so peers dogfood discovery and taker participation (default: 1). Set -swapnet=0 to leave it stopped. Spending requires an explicit mandate.", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    args.AddArg("-swapnetmode=<observe|taker|maker|recovery>", "Participation override (default: taker when unset, and a saved owner choice is kept). taker can request quotes. maker publishes markets. observe is read-only. recovery keeps existing obligations and starts no new trades. Maker and taker still require an owner mandate.", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    args.AddArg("-swapnetwallet=<name>", "Bind SwapNet to this already-loaded native wallet; otherwise require exactly one loaded wallet.", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
    args.AddArg("-swapnetowner=<rpcuser>", "Grant this authenticated RPC username owner-level SwapNet policy authority; repeatable. Cookie and local Qt console are owners.", ArgsManager::ALLOW_ANY, OptionsCategory::CONNECTION);
}
bool StartNode(node::NodeContext& node, std::string& error) {
    if (!node.args) {
        error = "node arguments unavailable";
        LogPrintf("SwapNet: startup failed (%s). No funds were authorized by startup.\n", error);
        return false;
    }
    auto& args=*node.args;
    if (!args.GetBoolArg("-swapnet", true)) return true;
    try {
        UniValue config(UniValue::VOBJ); const auto genesis=Params().GenesisBlock().GetHash().GetHex();
        config.pushKV("network",genesis);
        // An unset mode leaves the saved owner choice, or taker on a new journal.
        // Passing a default here would wipe a maker or observe choice on every restart.
        if (args.IsArgSet("-swapnetmode")) {
            const std::string mode = args.GetArg("-swapnetmode", "taker");
            if (mode!="observe" && mode!="taker" && mode!="maker" && mode!="recovery") {
                error = "unknown -swapnetmode";
                LogPrintf("SwapNet: startup failed (%s). No funds were authorized by startup.\n", error);
                return false;
            }
            config.pushKV("market_startup_mode", mode);
        }
        // Chain class comes from local parameters. Startup must not call RPC:
        // the RPC server is still in warmup until this function returns.
        config.pushKV("chain",ChainTypeToString(args.GetChainType()));
        // getswapvalidationinfo reports the build, since the SwapNet source version alone does not change per release.
        config.pushKV("client_version",FormatFullVersion());
        config.pushKV("datadir",fs::PathToString(args.GetDataDirNet()));config.pushKV("wallet",args.GetArg("-swapnetwallet",""));
        try {
            btx::p2p::StartRuntime(genesis, fs::PathToString(args.GetDataDirNet() / "shared-p2p"), GetRandHash().GetHex());
        } catch (const std::exception& e) {
            LogPrintf("SwapNet: shared control plane did not start (%s). Peer discovery continues. No funds were authorized by startup.\n", e.what());
        }
        Callbacks callbacks;
        callbacks.core=[&node](const auto& wallet,const auto& method,const auto& params){return CoreCall(node,wallet,method,params);};
#if defined(SWAPNET_WITH_WALLET) && defined(USE_SQLITE)
        auto state = std::make_shared<SQLiteRuntime>(genesis, config.write(), std::move(callbacks));
        std::shared_ptr<Runtime> runtime(state, &state->runtime);
#else
        auto runtime=std::make_shared<Runtime>(genesis,config.write(),std::move(callbacks));
#endif
        runtime->Start();
        {std::lock_guard<std::mutex> lock(g_mutex);g_owners.clear();for(const auto& user:args.GetArgs("-swapnetowner"))g_owners.insert(user);g_runtime=runtime;}
        LogPrintf("SwapNet: embedded runtime started; discovery enabled; no implicit spending authorization\n");return true;
    } catch (const UniValue& e) {
        btx::p2p::StopRuntime();
        error = e.write();
        LogPrintf("SwapNet: startup failed (%s). No funds were authorized by startup.\n", error);
        return false;
    } catch (const std::exception& e) {
        btx::p2p::StopRuntime();
        error = e.what();
        LogPrintf("SwapNet: startup failed (%s). No funds were authorized by startup.\n", error);
        return false;
    } catch (...) {
        btx::p2p::StopRuntime();
        error = "inspect local dependency/wallet/state configuration";
        LogPrintf("SwapNet: startup failed; inspect local dependency/wallet/state configuration. No funds were authorized by startup.\n");
        return false;
    }
}
void StopNode() {
    std::shared_ptr<Runtime> runtime;
    {std::lock_guard<std::mutex> lock(g_mutex);runtime=std::move(g_runtime);}
    if(runtime) runtime->Stop();
    btx::p2p::StopRuntime();
}
void PeerReady(PeerId peer) {if(auto r=Current())r->Wire().PeerReady(peer,NowMS());}
void PeerClosed(PeerId peer) {if(auto r=Current())r->Wire().PeerClosed(peer);}
bool Receive(PeerId peer,const std::string& command,const std::string& payload) {if(auto r=Current())return r->Wire().Receive(peer,command,payload,NowMS());return false;}
std::vector<Frame> Drain(PeerId peer) {
    std::vector<Frame> frames;if(auto r=Current())for(int i=0;i<8;++i){auto f=r->Wire().TakeOutboundForPeer(peer);if(!f)break;frames.push_back(std::move(*f));}return frames;
}
UniValue ExecuteRPC(const JSONRPCRequest& request,const std::string& method,const UniValue& params) {
    auto runtime=Current();if(!runtime)throw JSONRPCError(RPC_MISC_ERROR,"SwapNet is disabled or not initialized");
    if(!params.isObject())throw JSONRPCError(RPC_INVALID_PARAMETER,"SwapNet request must be an object");
    Auth auth;auth.wallet=RequestWallet(request);
    // An -rpcauth wallet restriction is not a SwapNet owner and cannot name another wallet.
    if (!request.m_wallet_restriction.empty()) {
        if (request.m_wallet_restriction=="-"||(!auth.wallet.empty()&&auth.wallet!=request.m_wallet_restriction))
            throw JSONRPCError(RPC_WALLET_NOT_FOUND,"Wallet restriction does not allow this SwapNet wallet");
        auth.wallet=request.m_wallet_restriction;
    }
    const bool cookie=request.authUser=="__cookie__";
    const bool console=request.authUser.empty()&&request.peerAddr.empty();
    auth.owner=cookie||console;
    {std::lock_guard<std::mutex> lock(g_mutex);auth.owner=auth.owner||g_owners.count(request.authUser)>0;}
    if (!request.m_wallet_restriction.empty()) auth.owner=false;
    if (cookie||console) auth.principal="owner:cookie";
    else {
        if (request.authUser.empty()||request.authUser=="local-owner"||request.authUser.rfind("owner:",0)==0)
            throw JSONRPCError(RPC_INVALID_PARAMETER,"Reserved SwapNet principal");
        auth.principal="rpc:"+request.authUser;
    }
    UniValue reply;
    try {if(!reply.read(runtime->Call(auth,method,params.write())))throw std::runtime_error("Malformed reply");}
    catch(...) {throw JSONRPCError(RPC_MISC_ERROR,"SwapNet runtime failed or request timed out; inspect getswaphealth after restart");}
    if(reply.exists("error")) {
        const auto& e=reply["error"];
        throw JSONRPCError(RPC_MISC_ERROR,e["code"].get_str()+": "+e["message"].get_str());
    }
    return reply["result"];
}
}
