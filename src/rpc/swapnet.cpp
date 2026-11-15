// Generated registration source; compile against the inspected BTX baseline before release.
#include <rpc/server.h>
#include <rpc/util.h>
#include <swapnet/node.h>
#include <univalue.h>
namespace {
RPCHelpMan SwapRPC(const char* name) {
    const std::string method{name};
    return RPCHelpMan{method,"SwapNet v2. Named request object; no implicit funding authorization.\n",
        {{"request",RPCArg::Type::OBJ_USER_KEYS,RPCArg::Optional::OMITTED,"Method-specific fields; see doc/swapnet/RPC.md",std::vector<RPCArg>{}}},
        RPCResult{RPCResult::Type::ANY,"","Typed SwapNet result; see schemas"},
        RPCExamples{""},
        [method](const RPCHelpMan&,const JSONRPCRequest& request)->UniValue {
            const UniValue params=request.params.empty()?UniValue(UniValue::VOBJ):request.params[0];
            return swapnet::ExecuteRPC(request,method,params);
        }};
}
RPCHelpMan getswapnetworkinfo() { return SwapRPC("getswapnetworkinfo"); }
RPCHelpMan listswapassets() { return SwapRPC("listswapassets"); }
RPCHelpMan listswapproviders() { return SwapRPC("listswapproviders"); }
RPCHelpMan searchswaps() { return SwapRPC("searchswaps"); }
RPCHelpMan requestswapquote() { return SwapRPC("requestswapquote"); }
RPCHelpMan getswapquotes() { return SwapRPC("getswapquotes"); }
RPCHelpMan acceptswapquote() { return SwapRPC("acceptswapquote"); }
RPCHelpMan listswaps() { return SwapRPC("listswaps"); }
RPCHelpMan getswap() { return SwapRPC("getswap"); }
RPCHelpMan cancelswap() { return SwapRPC("cancelswap"); }
RPCHelpMan getswaptranscript() { return SwapRPC("getswaptranscript"); }
RPCHelpMan listswapmandates() { return SwapRPC("listswapmandates"); }
RPCHelpMan createswapmandate() { return SwapRPC("createswapmandate"); }
RPCHelpMan revokeswapmandate() { return SwapRPC("revokeswapmandate"); }
RPCHelpMan getswapcapabilities() { return SwapRPC("getswapcapabilities"); }
RPCHelpMan resumeswap() { return SwapRPC("resumeswap"); }
RPCHelpMan refundswap() { return SwapRPC("refundswap"); }
RPCHelpMan listswapoperations() { return SwapRPC("listswapoperations"); }
RPCHelpMan getswaphealth() { return SwapRPC("getswaphealth"); }
RPCHelpMan publishswapprovider() { return SwapRPC("publishswapprovider"); }
RPCHelpMan withdrawswapprovider() { return SwapRPC("withdrawswapprovider"); }
RPCHelpMan getswapbootstrapinfo() { return SwapRPC("getswapbootstrapinfo"); }
RPCHelpMan getswaprecoveryinfo() { return SwapRPC("getswaprecoveryinfo"); }
RPCHelpMan setswapmarket() { return SwapRPC("setswapmarket"); }
RPCHelpMan listswapmarkets() { return SwapRPC("listswapmarkets"); }
RPCHelpMan getswapwalletinfo() { return SwapRPC("getswapwalletinfo"); }
RPCHelpMan setswapassetpolicy() { return SwapRPC("setswapassetpolicy"); }
RPCHelpMan listswapassetpolicies() { return SwapRPC("listswapassetpolicies"); }
RPCHelpMan getswaprouteinfo() { return SwapRPC("getswaprouteinfo"); }
RPCHelpMan exportswaprecovery() { return SwapRPC("exportswaprecovery"); }
RPCHelpMan bumpswapfee() { return SwapRPC("bumpswapfee"); }
RPCHelpMan getswapevents() { return SwapRPC("getswapevents"); }
RPCHelpMan getswapvalidationinfo() { return SwapRPC("getswapvalidationinfo"); }
}
void RegisterSwapNetRPCCommands(CRPCTable& table) {
    static const CRPCCommand commands[] = {
        {"swapnet", &getswapnetworkinfo},
        {"swapnet", &listswapassets},
        {"swapnet", &listswapproviders},
        {"swapnet", &searchswaps},
        {"swapnet", &requestswapquote},
        {"swapnet", &getswapquotes},
        {"swapnet", &acceptswapquote},
        {"swapnet", &listswaps},
        {"swapnet", &getswap},
        {"swapnet", &cancelswap},
        {"swapnet", &getswaptranscript},
        {"swapnet", &listswapmandates},
        {"swapnet", &createswapmandate},
        {"swapnet", &revokeswapmandate},
        {"swapnet", &getswapcapabilities},
        {"swapnet", &resumeswap},
        {"swapnet", &refundswap},
        {"swapnet", &listswapoperations},
        {"swapnet", &getswaphealth},
        {"swapnet", &publishswapprovider},
        {"swapnet", &withdrawswapprovider},
        {"swapnet", &getswapbootstrapinfo},
        {"swapnet", &getswaprecoveryinfo},
        {"swapnet", &setswapmarket},
        {"swapnet", &listswapmarkets},
        {"swapnet", &getswapwalletinfo},
        {"swapnet", &setswapassetpolicy},
        {"swapnet", &listswapassetpolicies},
        {"swapnet", &getswaprouteinfo},
        {"swapnet", &exportswaprecovery},
        {"swapnet", &bumpswapfee},
        {"swapnet", &getswapevents},
        {"swapnet", &getswapvalidationinfo},
    };
    for (const auto& command:commands) table.appendCommand(command.name,&command);
}
