// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <node/resource_governor.h>
#include <rpc/protocol.h>
#include <rpc/server.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <univalue.h>
#include <util/time.h>

#include <string>

using node::GlobalResourceGovernor;
using node::GovernorMode;
using node::ParseGovernorMode;

static RPCHelpMan getresourcegovernorinfo()
{
    return RPCHelpMan{
        "getresourcegovernorinfo",
        "Local resource-governor status. Never consensus, never a spend grant.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "schema_version", "1"},
            {RPCResult::Type::STR, "mode", "AUTO|PERFORMANCE|BALANCED|ECO|MANUAL|OFF"},
            {RPCResult::Type::BOOL, "enabled", "false when OFF"},
            {RPCResult::Type::ELISION, "", "cpu/memory/gpu/network/storage/power/jobs"},
        }},
        RPCExamples{HelpExampleCli("getresourcegovernorinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            (void)request;
            return GlobalResourceGovernor().InfoJson();
        },
    };
}

static RPCHelpMan setresourcegovernormode()
{
    return RPCHelpMan{
        "setresourcegovernormode",
        "Persist local resource mode only. No blockchain transaction.\n",
        {{"mode", RPCArg::Type::STR, RPCArg::Optional::NO, "AUTO|PERFORMANCE|BALANCED|ECO|MANUAL|OFF"}},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::STR, "mode", "effective mode"},
        }},
        RPCExamples{HelpExampleCli("setresourcegovernormode", "AUTO")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            GovernorMode m;
            if (!ParseGovernorMode(request.params[0].get_str(), m)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown resource governor mode");
            }
            GlobalResourceGovernor().SetMode(m);
            UniValue o(UniValue::VOBJ);
            o.pushKV("mode", node::GovernorModeName(m));
            return o;
        },
    };
}

static RPCHelpMan getresourcegovernorpolicy()
{
    return RPCHelpMan{
        "getresourcegovernorpolicy",
        "Effective local governor policy.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "thresholds and caps"},
        }},
        RPCExamples{HelpExampleCli("getresourcegovernorpolicy", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            (void)request;
            return GlobalResourceGovernor().PolicyJson();
        },
    };
}

static RPCHelpMan setresourcegovernorpolicy()
{
    return RPCHelpMan{
        "setresourcegovernorpolicy",
        "Advanced local override. Rejects unbounded/unsafe values.\n",
        {{"policy", RPCArg::Type::STR, RPCArg::Optional::NO, "JSON object of bounded fields", RPCArgOptions{.skip_type_check = true}}},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "effective policy"},
        }},
        RPCExamples{HelpExampleCli("setresourcegovernorpolicy", "'{\"mining_max_intensity\":50}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            UniValue o(UniValue::VOBJ);
            if (request.params[0].isObject()) {
                o = request.params[0];
            } else if (request.params[0].isStr()) {
                if (!o.read(request.params[0].get_str()) || !o.isObject()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "policy must be a JSON object");
                }
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "policy object required");
            }
            std::string err;
            if (!GlobalResourceGovernor().ApplyPolicyJson(o, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            return GlobalResourceGovernor().PolicyJson();
        },
    };
}

static RPCHelpMan resetresourcegovernorpolicy()
{
    return RPCHelpMan{
        "resetresourcegovernorpolicy",
        "Restore platform defaults.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "defaults"},
        }},
        RPCExamples{HelpExampleCli("resetresourcegovernorpolicy", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            (void)request;
            GlobalResourceGovernor().ResetPolicy();
            return GlobalResourceGovernor().PolicyJson();
        },
    };
}

static RPCHelpMan pausebackgroundwork()
{
    return RPCHelpMan{
        "pausebackgroundwork",
        "Pause mining, preservation, and ordinary background seeding. Validation and user retrieval continue.\n",
        {{"duration", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Seconds to pause; omit for until resumebackgroundwork"}},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "paused", "true"},
        }},
        RPCExamples{HelpExampleCli("pausebackgroundwork", "300")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            int64_t dur_ms = 0;
            if (!request.params[0].isNull()) {
                const int64_t sec = request.params[0].getInt<int64_t>();
                if (sec < 0 || sec > 86400) throw JSONRPCError(RPC_INVALID_PARAMETER, "duration out of range");
                dur_ms = sec * 1000;
            }
            GlobalResourceGovernor().PauseBackground(
                TicksSinceEpoch<std::chrono::milliseconds>(NodeClock::now()), dur_ms);
            UniValue o(UniValue::VOBJ);
            o.pushKV("paused", true);
            return o;
        },
    };
}

static RPCHelpMan resumebackgroundwork()
{
    return RPCHelpMan{
        "resumebackgroundwork",
        "Resume governor-managed work. Does not bypass resource checks.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::BOOL, "paused", "false"},
        }},
        RPCExamples{HelpExampleCli("resumebackgroundwork", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            (void)request;
            GlobalResourceGovernor().ResumeBackground();
            UniValue o(UniValue::VOBJ);
            o.pushKV("paused", false);
            return o;
        },
    };
}

static RPCHelpMan getbackgroundjobs()
{
    return RPCHelpMan{
        "getbackgroundjobs",
        "Current governor-managed jobs and pause reasons.\n",
        {},
        RPCResult{RPCResult::Type::ARR, "", "", {
            {RPCResult::Type::ELISION, "", "jobs"},
        }},
        RPCExamples{HelpExampleCli("getbackgroundjobs", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            (void)request;
            return GlobalResourceGovernor().JobsJson();
        },
    };
}

static RPCHelpMan getmininggovernorinfo()
{
    return RPCHelpMan{
        "getmininggovernorinfo",
        "Mining slice of the local resource governor. No profitability promise.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "enabled/automatic/active/intensity/pause_reason"},
        }},
        RPCExamples{HelpExampleCli("getmininggovernorinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            (void)request;
            return GlobalResourceGovernor().MiningInfoJson();
        },
    };
}

static RPCHelpMan getmodelbandwidthinfo()
{
    return RPCHelpMan{
        "getmodelbandwidthinfo",
        "Model-plane bandwidth as seen by the local governor.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "upload/download ceilings"},
        }},
        RPCExamples{HelpExampleCli("getmodelbandwidthinfo", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            (void)request;
            return GlobalResourceGovernor().BandwidthJson();
        },
    };
}

void RegisterResourceGovernorRPCCommands(CRPCTable& t)
{
    static const CRPCCommand commands[]{
        {"control", &getresourcegovernorinfo},
        {"control", &setresourcegovernormode},
        {"control", &getresourcegovernorpolicy},
        {"control", &setresourcegovernorpolicy},
        {"control", &resetresourcegovernorpolicy},
        {"control", &pausebackgroundwork},
        {"control", &resumebackgroundwork},
        {"control", &getbackgroundjobs},
        {"control", &getmininggovernorinfo},
        {"control", &getmodelbandwidthinfo},
    };
    for (const auto& c : commands) t.appendCommand(c.name, &c);
}
