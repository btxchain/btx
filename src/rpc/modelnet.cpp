// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <common/args.h>
#include <modelnet/catalog.h>
#include <modelnet/helper.h>
#include <modelnet/bridge.h>
#include <modelnet/economy.h>
#include <modelnet/policy.h>
#include <modelnet/resource_uri.h>
#include <modelnet/supervisor.h>
#include <core_io.h>
#include <kernel/chainstatemanager_opts.h>
#include <net.h>
#include <node/context.h>
#include <node/mining_guard.h>
#include <node/transaction.h>
#include <primitives/transaction.h>
#include <rpc/server.h>
#include <rpc/protocol.h>
#include <rpc/server_util.h>
#include <rpc/util.h>
#include <txmempool.h>
#include <uint256.h>
#include <validation.h>
#include <map>
#include <memory>
#include <stdexcept>
#include <sync.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>

#ifdef ENABLE_WALLET
#include <interfaces/wallet.h>
#include <wallet/bounty_funding.h>
#include <wallet/model_funding.h>
#include <wallet/rpc/util.h>
#include <wallet/wallet.h>
#include <wallet/context.h>
#endif

namespace {

fs::path ModelRpcSocket()
{
#ifdef ENABLE_MODELNET
    const std::string explicit_path = gArgs.GetArg("-modelrpcsocket", "");
    if (!explicit_path.empty()) return fs::PathFromString(explicit_path);
    return gArgs.GetDataDirNet() / "modelnet" / "modeld.sock";
#else
    return {};
#endif
}

bool HelperCall(const std::string& method, const UniValue& params, UniValue& result, std::string& err)
{
    return modelnet::CallUnixRpc(ModelRpcSocket(), method, params, result, err);
}

UniValue LocalNetworkInfo()
{
    const auto st = modelnet::GetModelBridge().SnapshotStatus();
    const auto helper = modelnet::SnapshotManagedHelper();
    UniValue r(UniValue::VOBJ);
    r.pushKV("schema_version", 2);
    r.pushKV("enabled", gArgs.GetBoolArg("-modelnet", true));
    r.pushKV("helper_ready", helper.state == modelnet::HelperState::READY);
    r.pushKV("helper_managed_by_btxd", helper.managed_by_btxd);
    r.pushKV("helper_state", modelnet::HelperStateName(helper.state));
    r.pushKV("helper_pid", helper.pid);
    r.pushKV("helper_restart_count", helper.restart_count);
    r.pushKV("pq1_ready", st.pq1_ready);
    r.pushKV("error", helper.error.empty() ? "btx-modeld not connected" : helper.error);
    r.pushKV("retrieval_default", "FREE_ONLY");
    r.pushKV("automatic_spend_atoms", 0);
    r.pushKV("public_host_reachable", helper.public_host_reachable);
    r.pushKV("advertised_host", helper.advertised_host);
    r.pushKV("nat_limited", !helper.public_host_reachable);
    r.pushKV("capabilities", modelnet::CapabilitiesObject());
    r.pushKV("note", "A BTX node already has compute. BTX gives it models and money. Not inference-as-a-service.");
    r.pushKV("htlc", "reuses final 0.34.6 htlc_sha256 / buildhtlcclaim / buildhtlcrefund; HASH160 htlc_tx is recovery-only");
    return r;
}

#ifdef ENABLE_WALLET
std::shared_ptr<wallet::CWallet> WalletForModelFunding(const JSONRPCRequest& request)
{
    node::NodeContext& node = EnsureAnyNodeContext(request.context);
    if (!node.wallet_loader || !node.wallet_loader->context()) {
        throw JSONRPCError(RPC_WALLET_NOT_FOUND,
                           "No wallet is loaded. Load a wallet using loadwallet or create a new one with createwallet. Model funding RPCs run in btxd, not btx-modeld.");
    }
    JSONRPCRequest wallet_req = request;
    node.wallet_loader->assignContextHACK(wallet_req.context);
    return wallet::GetWalletForJSONRPCRequest(wallet_req);
}

/** Optional wallet for joining confirmed HTLC UTXOs into economy cards. Never throws. */
std::shared_ptr<wallet::CWallet> MaybeWalletForObservation(const JSONRPCRequest& request)
{
    try {
        node::NodeContext& node = EnsureAnyNodeContext(request.context);
        if (!node.wallet_loader || !node.wallet_loader->context()) return nullptr;
        JSONRPCRequest wallet_req = request;
        node.wallet_loader->assignContextHACK(wallet_req.context);
        wallet::WalletContext& context = wallet::EnsureWalletContext(wallet_req.context);
        size_t count = 0;
        return wallet::GetDefaultWallet(context, count);
    } catch (...) {
        return nullptr;
    }
}

wallet::FrozenFundingQuote QuoteFromRequest(const std::string& release_id, const UniValue& options)
{
    wallet::FrozenFundingQuote q;
    q.release_id = release_id;
    std::string err;
    if (!wallet::ParseFrozenFundingQuote(options.isNull() ? UniValue(UniValue::VOBJ) : options, q, err)) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, err);
    }
    if (!release_id.empty()) q.release_id = release_id;
    UniValue helper;
    std::string helper_err;
    UniValue params(UniValue::VARR);
    if (!release_id.empty()) params.push_back(release_id);
    if (HelperCall("getmodelrelease", params, helper, helper_err)) {
        wallet::MergeHelperCampaign(helper, release_id, q);
    }
    return q;
}
#endif

RPCHelpMan ProxyOrLocal(const std::string& name, const std::string& help, std::vector<RPCArg> args)
{
    return RPCHelpMan{
        name,
        help,
        std::move(args),
        RPCResult{RPCResult::Type::OBJ, "", /*optional=*/false, "Helper result object", {
            {RPCResult::Type::ELISION, "", "helper-defined keys (rpcdoccheck-safe)"},
        }},
        RPCExamples{HelpExampleCli(name, "")},
        [name](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            UniValue params(UniValue::VARR);
            for (size_t i = 0; i < request.params.size(); ++i) params.push_back(request.params[i]);
            UniValue req(UniValue::VOBJ);
            req.pushKV("method", name);
            req.pushKV("params", params);
            UniValue result;
            std::string err;
            if (HelperCall(name, params, result, err)) {
                if (name == "getmodelnetworkinfo") {
                    const auto helper = modelnet::SnapshotManagedHelper();
                    result.pushKV("helper_managed_by_btxd", helper.managed_by_btxd);
                    result.pushKV("helper_restart_count", helper.restart_count);
                    if (helper.pid > 0) result.pushKV("owner_helper_pid", helper.pid);
                    if (helper.state != modelnet::HelperState::DISABLED) {
                        result.pushKV("helper_state", modelnet::HelperStateName(helper.state));
                    }
                    // Unix RPC succeeded: the helper is answering even if the
                    // supervisor has not yet latched READY.
                    result.pushKV("helper_ready", true);
                    result.pushKV("enabled", gArgs.GetBoolArg("-modelnet", true));
                    if (!result.exists("nat_limited")) {
                        const bool reachable = result.exists("public_host_reachable") && result["public_host_reachable"].isTrue();
                        result.pushKV("nat_limited", !reachable);
                    }
                }
                if (name == "getmodeleconomyentry" || name == "getmodelreleaseeconomics" ||
                    name == "getmodelfeed" || name == "getrecentreleases" || name == "getfundablemodels" ||
                    name == "getrecentlyunlockedmodels" || name == "getreleasefeed") {
#ifdef ENABLE_WALLET
                    auto join_card = [&](UniValue& card) {
                        std::string kh;
                        uint32_t rh = 0;
                        const UniValue* rel = (card.exists("release") && card["release"].isObject()) ? &card["release"] : &card;
                        if (rel->exists("key_hash") && (*rel)["key_hash"].isStr()) kh = (*rel)["key_hash"].get_str();
                        else if (rel->exists("key_hash_sha256") && (*rel)["key_hash_sha256"].isStr()) {
                            kh = (*rel)["key_hash_sha256"].get_str();
                        }
                        if (rel->exists("refund_height") && (*rel)["refund_height"].isNum()) {
                            rh = static_cast<uint32_t>((*rel)["refund_height"].getInt<int64_t>());
                        }
                        std::string os;
                        if (rel->exists("output_script") && (*rel)["output_script"].isStr()) {
                            os = (*rel)["output_script"].get_str();
                        }
                        if (kh.empty() && os.empty()) return;
                        std::shared_ptr<wallet::CWallet> w = MaybeWalletForObservation(request);
                        if (!w) return;
                        UniValue obs = wallet::ObserveReleaseFunding(*w, kh, rh, os);
                        if (rel->exists("release_id") && (*rel)["release_id"].isStr()) {
                            obs.pushKV("release_id", (*rel)["release_id"].get_str());
                        } else if (card.exists("release_id") && card["release_id"].isStr()) {
                            obs.pushKV("release_id", card["release_id"].get_str());
                        }
                        modelnet::ApplyChainObservationJson(card, obs);
                        UniValue ingest_params(UniValue::VARR);
                        ingest_params.push_back(obs);
                        UniValue ign;
                        std::string ierr;
                        HelperCall("ingestchainfundingobservation", ingest_params, ign, ierr);
                    };
                    if (result.exists("results") && result["results"].isArray()) {
                        UniValue arr(UniValue::VARR);
                        for (UniValue card : result["results"].getValues()) {
                            join_card(card);
                            arr.push_back(card);
                        }
                        result.pushKV("results", arr);
                    } else if (result.exists("items") && result["items"].isArray()) {
                        UniValue arr(UniValue::VARR);
                        for (UniValue it : result["items"].getValues()) {
                            if (it.isObject() && it.exists("entry") && it["entry"].isObject()) {
                                UniValue e = it["entry"];
                                join_card(e);
                                it.pushKV("entry", e);
                            } else {
                                join_card(it);
                            }
                            arr.push_back(it);
                        }
                        result.pushKV("items", arr);
                    } else {
                        join_card(result);
                    }
#endif
                }
                return result;
            }
            if (err.find("WALLET_REQUIRED") != std::string::npos) {
                throw JSONRPCError(RPC_WALLET_ERROR, err);
            }
            if (name == "getmodelnetworkinfo" || name == "getmodelcryptoinfo") {
                UniValue r = LocalNetworkInfo();
                r.pushKV("helper_error", err);
                // Unix just failed: do not keep a stale READY latch from the
                // supervisor poll (up to ~2s for -modelrpcsocket).
                r.pushKV("helper_ready", false);
                return r;
            }
            throw JSONRPCError(RPC_MISC_ERROR, "model helper unavailable: " + err);
        },
    };
}

} // namespace

static RPCHelpMan getmodelnetworkinfo()
{
    return ProxyOrLocal("getmodelnetworkinfo",
                        "Return model-network helper state. Model failures never affect chain validity.\n",
                        {});
}

static RPCHelpMan getmodelcryptoinfo()
{
    return ProxyOrLocal("getmodelcryptoinfo",
                        "Return negotiated/required PQ1 suite identity for the model helper.\n",
                        {});
}

static RPCHelpMan decoderesource()
{
    return RPCHelpMan{
        "decoderesource",
        "Decode a canonical btx:// resource URI (or permitted convenience form).\n",
        {
            {"uri", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// token"},
        },
        RPCResult{
            RPCResult::Type::OBJ, "", "", {
                {RPCResult::Type::STR, "uri", "canonical URI"},
                {RPCResult::Type::STR, "kind", "resource class"},
                {RPCResult::Type::STR, "digest", "SHA-384 hex"},
            }},
        RPCExamples{HelpExampleCli("decoderesource", "btx://pqwy06q0q7wwzy70aeq45sxnlvq3mr067yt4jzphzvnfn2c4zc24zxz665zdprf0nwgskvqq9cq365u9n8l25")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            modelnet::Resource r;
            std::string err;
            if (!modelnet::DecodeResource(request.params[0].get_str(), r, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            UniValue obj(UniValue::VOBJ);
            obj.pushKV("schema_version", 2);
            obj.pushKV("uri", r.Uri());
            obj.pushKV("kind", modelnet::ResourceKindName(r.kind));
            obj.pushKV("digest", r.digest.Hex());
            return obj;
        },
    };
}

static RPCHelpMan encoderesource()
{
    return RPCHelpMan{
        "encoderesource",
        "Encode a SHA-384 digest and resource kind as a canonical btx:// URI.\n",
        {
            {"kind", RPCArg::Type::STR, RPCArg::Optional::NO, "MODEL, ARTIFACT, COLLECTION, IDENTITY, RELEASE, POLICY_BUNDLE, CIRCLE, ALIAS, PROVIDER"},
            {"digest", RPCArg::Type::STR, RPCArg::Optional::NO, "96 lowercase hex characters"},
        },
        RPCResult{RPCResult::Type::STR, "uri", "canonical btx:// URI"},
        RPCExamples{HelpExampleCli("encoderesource", "MODEL <96-hex>")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            const std::string name = request.params[0].get_str();
            modelnet::ResourceKind kind = modelnet::ResourceKind::MODEL;
            bool found = false;
            for (int i = 0; i <= 8; ++i) {
                modelnet::ResourceKind k;
                if (modelnet::ResourceKindFromInt(i, k) && name == modelnet::ResourceKindName(k)) {
                    kind = k;
                    found = true;
                    break;
                }
            }
            if (!found) throw JSONRPCError(RPC_INVALID_PARAMETER, "unknown resource kind");
            modelnet::Digest48 d;
            std::string err;
            if (!modelnet::Digest48::FromHex(request.params[1].get_str(), d, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            std::string uri;
            if (!modelnet::EncodeResource(kind, d, uri, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            return uri;
        },
    };
}

static RPCHelpMan getmodel()
{
    return ProxyOrLocal("getmodel",
                        "Plan or retrieve an exact model. Default mode is FREE_ONLY; automatic spend is zero.\n"
                        "A qualified public retrieve/import is demand-seeded when -modelseed=auto and storage > 0.\n",
                        {
                            {"uri", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// MODEL token or digest48 hex"},
                            {"mode", RPCArg::Type::STR, RPCArg::Default{"FREE_ONLY"}, "FREE_ONLY | FREE_FIRST_APPROVAL | FREE_FIRST_BUDGET | EXPLICIT_PAID, or an options object", RPCArgOptions{.skip_type_check = true}},
                        });
}

static RPCHelpMan listmodels()
{
    return ProxyOrLocal("listmodels", "List locally known models. Remote coverage is always incomplete.\n", {});
}

static RPCHelpMan searchmodels()
{
    return ProxyOrLocal("searchmodels",
                        "Bounded decentralized model search. Coverage is always incomplete (current network view, not a global directory).\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "query object or text string", RPCArgOptions{.skip_type_check = true}}});
}

static RPCHelpMan getmodelsearchrecord()
{
    return ProxyOrLocal("getmodelsearchrecord", "Return signed searchable metadata for a model.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "model_id or btx://"}});
}
static RPCHelpMan publishmodelsearchrecord()
{
    return ProxyOrLocal("publishmodelsearchrecord", "Sign and announce ModelSearchRecord. Creates a local research identity if none exists. Not a wallet spend.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "model_id or btx://"},
                         {"metadata", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "searchable metadata object", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan updatemodelsearchrecord()
{
    return ProxyOrLocal("updatemodelsearchrecord", "Publish next sequence of ModelSearchRecord. Does not mutate in place.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "model_id or btx://"},
                         {"patch", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "metadata patch object", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan removemodelsearchrecord()
{
    return ProxyOrLocal("removemodelsearchrecord", "Publish a local tombstone. Global delete is not guaranteed.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "model_id or btx://"}});
}
static RPCHelpMan listmodelsearchrecords()
{
    return ProxyOrLocal("listmodelsearchrecords", "Paginated local search index.\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "cursor/limit/updated_after", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan getmodeldirectoryentry()
{
    return ProxyOrLocal("getmodeldirectoryentry", "Normalized directory card: identity, metadata, swarm, local, release.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "model_id or btx://"}});
}
static RPCHelpMan getmodeldirectory()
{
    return ProxyOrLocal("getmodeldirectory", "Browse directory view (current network view).\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "filters/sort/cursor", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan getmodelproviders()
{
    return ProxyOrLocal("getmodelproviders", "Observed providers for a model. Not a global census.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "model_id or btx://"}});
}
static RPCHelpMan getmodelavailability()
{
    return ProxyOrLocal("getmodelavailability", "Aggregate swarm health from this node's observations.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "model_id or btx://"}});
}
static RPCHelpMan getmodelpeercount()
{
    return ProxyOrLocal("getmodelpeercount", "Observed complete/partial provider counts.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "model_id or btx://"}});
}
static RPCHelpMan getnetworkmodelstats()
{
    return ProxyOrLocal("getnetworkmodelstats", "This node's model-plane observations only. No central telemetry.\n", {});
}
static RPCHelpMan getmodelaliases()
{
    return ProxyOrLocal("getmodelaliases", "Aliases with provenance. Omit id to list every local alias.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "model_id or btx://"}});
}
static RPCHelpMan searchpublishers()
{
    return ProxyOrLocal("searchpublishers", "Search publisher/research identities in the local index.\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "text/limit", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan getpublisher()
{
    return ProxyOrLocal("getpublisher", "Public signed publisher profile only.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "identity id hex"}});
}
static RPCHelpMan searchcollections()
{
    return ProxyOrLocal("searchcollections", "Search signed collections.\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "text/limit", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan getcollection()
{
    return ProxyOrLocal("getcollection", "Signed collection detail.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "collection id"}});
}
static RPCHelpMan browsemodels()
{
    return ProxyOrLocal("browsemodels", "Directory browse without requiring a text query. Popularity is local observation, not global truth.\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "sort/limit", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan gettrendingmodels()
{
    return ProxyOrLocal("gettrendingmodels", "Local/network-sample trend. No user telemetry.\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "limit", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan getsimilarmodels()
{
    return ProxyOrLocal("getsimilarmodels", "Metadata similarity only (family/tags/arch). No remote embeddings.\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "family/tags", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan getnewmodels()
{
    return ProxyOrLocal("getnewmodels", "Recently published models from this node's index.\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "since/limit", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan getrecentreleases()
{
    return ProxyOrLocal("getrecentreleases", "Public release-campaign coordination data. scope=NETWORK uses the current decentralized view; scope=LOCAL is local campaigns.\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "limit/scope", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan getmodeleconomyentry()
{
    return ProxyOrLocal("getmodeleconomyentry", "Normalized ModelEconomyEntry (schema 3): search + swarm + local + release economics + actions.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "model_id, btx://, or release_id"}});
}
static RPCHelpMan getmodelfeed()
{
    return ProxyOrLocal("getmodelfeed", "Decentralized current-network model/campaign feed. Not a global chronology. Default scope NETWORK.\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "scope/mode/since/limit/cursor/filters", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan getmodelfeedstatus()
{
    return ProxyOrLocal("getmodelfeedstatus", "Feed sequence and coverage disclaimer for this node's network view.\n", {});
}
static RPCHelpMan getmodelfeedsequence()
{
    return ProxyOrLocal("getmodelfeedsequence", "Monotonic local feed_sequence for polling.\n", {});
}
static RPCHelpMan getfundablemodels()
{
    return ProxyOrLocal("getfundablemodels", "Campaigns that can still accept a meaningful contribution. Pledged is not funded.\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "sort/limit", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan getmodelreleaseeconomics()
{
    return ProxyOrLocal("getmodelreleaseeconomics", "Lifecycle, pledged vs confirmed funded, hashlock, refund terms, ciphertext availability. Helper observation is not wallet authority.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "release_id or model_id"}});
}
static RPCHelpMan getrecentlyunlockedmodels()
{
    return ProxyOrLocal("getrecentlyunlockedmodels", "Models whose campaign secret was recently disclosed (network-capable feed).\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "since/limit", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan getreleasefeed()
{
    return ProxyOrLocal("getreleasefeed", "Convenience wrapper over getmodelfeed for release campaigns.\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "mode/limit", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan preparefundmodelrelease()
{
    return ProxyOrLocal("preparefundmodelrelease", "Unsigned funding plan for a campaign. Never spends. automatic_spend_atoms=0. Wallet must sign/submit separately.\n",
                        {{"release_id", RPCArg::Type::STR, RPCArg::Optional::NO, "release_id"},
                         {"amount_atoms", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "amount or options object", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan cacheencryptedmodel()
{
    return ProxyOrLocal("cacheencryptedmodel", "Explicit ciphertext pre-cache. Never auto-downloads from a feed card. Does not reveal plaintext.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "release_id or model_id"}});
}
static RPCHelpMan getsearchstatus()
{
    return ProxyOrLocal("getsearchstatus", "Async search job status. complete is never global-true.\n",
                        {{"query_id", RPCArg::Type::STR, RPCArg::Optional::NO, "query_id"}});
}
static RPCHelpMan cancelmodelsearch()
{
    return ProxyOrLocal("cancelmodelsearch", "Stop additional search forwarding for query_id.\n",
                        {{"query_id", RPCArg::Type::STR, RPCArg::Optional::NO, "query_id"}});
}
static RPCHelpMan getsearchpeers()
{
    return ProxyOrLocal("getsearchpeers", "Known search/index peers. Model-plane only.\n", {});
}
static RPCHelpMan addmodelindex()
{
    return ProxyOrLocal("addmodelindex", "Add a preferred search/index endpoint. Not monetary addnode.\n",
                        {{"endpoint", RPCArg::Type::STR, RPCArg::Optional::NO, "endpoint or identity"}});
}
static RPCHelpMan removemodelindex()
{
    return ProxyOrLocal("removemodelindex", "Remove a local index preference. Not a global blacklist.\n",
                        {{"endpoint", RPCArg::Type::STR, RPCArg::Optional::NO, "endpoint or identity"}});
}
static RPCHelpMan exportmodelindex()
{
    return ProxyOrLocal("exportmodelindex", "Export public signed search records. No secrets.\n",
                        {{"query", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "since/limit", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan importmodelindex()
{
    return ProxyOrLocal("importmodelindex", "Import signed records; every signature is revalidated.\n",
                        {{"snapshot", RPCArg::Type::STR, RPCArg::Optional::NO, "records snapshot object", RPCArgOptions{.skip_type_check = true}}});
}
static RPCHelpMan hidesearchmodel()
{
    return ProxyOrLocal("hidesearchmodel", "Local hide. Not global moderation.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "model_id"}});
}
static RPCHelpMan unhidesearchmodel()
{
    return ProxyOrLocal("unhidesearchmodel", "Undo local hide.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "model_id"}});
}
static RPCHelpMan mutesearchpublisher()
{
    return ProxyOrLocal("mutesearchpublisher", "Local mute publisher. Not global moderation.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "publisher identity hex"}});
}
static RPCHelpMan unmutesearchpublisher()
{
    return ProxyOrLocal("unmutesearchpublisher", "Undo local publisher mute.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "publisher identity hex"}});
}

static RPCHelpMan getmodelmanifest()
{
    return ProxyOrLocal("getmodelmanifest", "Return verified metadata for a known model or artifact root.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// URI or 96-hex id"}});
}

static RPCHelpMan importmodel()
{
    return ProxyOrLocal("importmodel", "Import a local file or directory, hash, chunk, optionally pin, and by default publish a signed search card. Never executes pickle/.pt.\n",
                        {
                            {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "filesystem path"},
                            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "import options", {
                                {"pin", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "pin after import (default true)"},
                                {"publish", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "sign and publish a search record (default true)"},
                            }},
                        });
}

static RPCHelpMan hostmodel()
{
    return ProxyOrLocal("hostmodel", "Alias of importmodel: pin, demand-seed, and publish a signed search card. Never spends. Never starts inference.\n",
                        {
                            {"path", RPCArg::Type::STR, RPCArg::Optional::NO, "filesystem path"},
                            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "import options", {
                                {"pin", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "pin after import (default true)"},
                                {"publish", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "sign and publish a search record (default true)"},
                            }},
                        });
}

static RPCHelpMan checkmodelsetup()
{
    return ProxyOrLocal("checkmodelsetup", "First-run doctor for the model helper: identity, quota, PQ1, next_actions. Never spends.\n", {});
}

static RPCHelpMan previewmodelimport()
{
    return ProxyOrLocal("previewmodelimport", "Size and inferred metadata vs quota. Does not hash or import.\n",
                        {{"path", RPCArg::Type::STR, RPCArg::Optional::NO, "filesystem path"}});
}

static RPCHelpMan getmodelsharecard()
{
    return ProxyOrLocal("getmodelsharecard", "Copy-paste share card (btx:// plus family/format/quant). Magnet analog.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// URI or hex id"}});
}

static RPCHelpMan getmodeltransfers()
{
    return ProxyOrLocal("getmodeltransfers", "Local torrent-style transfer list: state, ratio, seeded, pinned.\n", {});
}

static RPCHelpMan setmodelalias()
{
    return ProxyOrLocal("setmodelalias", "Add an Ollama-style alias and re-sign the search card. Not a wallet label.\n",
                        {
                            {"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// URI or hex id"},
                            {"alias", RPCArg::Type::STR, RPCArg::Optional::NO, "short name"},
                        });
}

static RPCHelpMan scanmodelwatch()
{
    return ProxyOrLocal("scanmodelwatch", "Scan -modelwatch directory and host new GGUF/SafeTensors. Idempotent.\n",
                        {{"dir", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "override watch dir for this scan"}});
}

static RPCHelpMan getmodelwatchstatus()
{
    return ProxyOrLocal("getmodelwatchstatus", "Report -modelwatch path. Side-effect-free. Never spends.\n", {});
}

static RPCHelpMan showmodel()
{
    return ProxyOrLocal("showmodel", "Ollama-style show: share card, aliases, local bytes. Never spends. Never inference.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// URI, hex, alias, or copy_text"}});
}

static RPCHelpMan exportmodellink()
{
    return ProxyOrLocal("exportmodellink", "Write or return a .btx magnet analog (canonical URI + copy_text). Not a torrent file.\n",
                        {
                            {"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// URI, hex, or alias"},
                            {"path", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "optional filesystem path to write"},
                        });
}

static RPCHelpMan unhostmodel()
{
    return ProxyOrLocal("unhostmodel", "Unpin and unseed in one call. Does not delete pieces. Never spends.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// URI, hex, or alias"}});
}

static RPCHelpMan removemodelalias()
{
    return ProxyOrLocal("removemodelalias", "Remove an Ollama-style alias and re-sign the search card.\n",
                        {
                            {"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// URI, hex, or alias"},
                            {"alias", RPCArg::Type::STR, RPCArg::Optional::NO, "alias to drop"},
                        });
}

static RPCHelpMan openmodelshare()
{
    return ProxyOrLocal("openmodelshare", "Parse share.copy_text or a .btx link. Preview only; never retrieve or spend.\n",
                        {{"text", RPCArg::Type::STR, RPCArg::Optional::NO, "copy_text, btx:// URI, or link contents"}});
}

static RPCHelpMan getsetupstatus()
{
    return RPCHelpMan{
        "getsetupstatus",
        "First-run doctor for money (ExactReplay mining) and models. Never spends. Never starts inference.\n",
        {},
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "doctor fields"},
        }},
        RPCExamples{HelpExampleCli("getsetupstatus", "")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
            UniValue out(UniValue::VOBJ);
            out.pushKV("schema_version", 1);
            out.pushKV("automatic_spend_atoms", 0);
            UniValue next(UniValue::VARR);

            UniValue money(UniValue::VOBJ);
            try {
                node::NodeContext& node = EnsureAnyNodeContext(request.context);
                const auto guard = node::GetMiningChainGuardStatus(node);
                money.pushKV("blocks", guard.local_tip_height);
                money.pushKV("peer_count", guard.peer_count);
                money.pushKV("initialblockdownload", guard.initial_block_download);
                money.pushKV("ibd", guard.initial_block_download);
                money.pushKV("network_active", guard.network_active);
                money.pushKV("mining_healthy", guard.healthy);
                money.pushKV("unattended_healthy", guard.healthy);
                money.pushKV("min_peers", guard.min_peer_count);
                money.pushKV("mining_recommended_action", node::GetMiningChainGuardRecommendedAction(guard));
                money.pushKV("chain", gArgs.GetChainTypeString());
                money.pushKV("rpc", "getmininginfo");
                bool refuse_template = guard.initial_block_download;
                try {
                    ChainstateManager& chainman = EnsureChainman(node);
                    LOCK(cs_main);
                    if (const CBlockIndex* tip = chainman.ActiveChain().Tip()) {
                        money.pushKV("verificationprogress", chainman.GuessVerificationProgress(tip));
                        money.pushKV("headers", chainman.m_best_header ? chainman.m_best_header->nHeight : tip->nHeight);
                        const bool loading = chainman.m_blockman.LoadingBlocks();
                        const bool work = tip->nChainWork >= chainman.MinimumChainWork();
                        refuse_template = kernel::MiningTemplateShouldRefuseIbd(loading, /*has_tip=*/true, work);
                        const bool age_only = kernel::IbdIsAgeOnlyStaleTip(guard.initial_block_download, loading, true, work);
                        std::string ibd_kind = "none";
                        if (loading) ibd_kind = "loading";
                        else if (!work) ibd_kind = "insufficient_chain_work";
                        else if (age_only) ibd_kind = "age_only";
                        money.pushKV("ibd_kind", ibd_kind);
                        if (age_only) money.pushKV("one_liner", "Tip is stale by age; keep requesting ExactReplay work.");
                        else if (refuse_template) money.pushKV("one_liner", "Waiting for chain sync.");
                        else money.pushKV("one_liner", node::GetMiningChainGuardRecommendedAction(guard));
                    }
                } catch (const std::exception&) {
                }
                money.pushKV("ready_to_mine", guard.healthy && !refuse_template);
                money.pushKV("template_issuable", !refuse_template);
                if (node.connman) {
                    UniValue conn(UniValue::VOBJ);
                    conn.pushKV("in", static_cast<uint64_t>(node.connman->GetNodeCount(ConnectionDirection::In)));
                    conn.pushKV("out", static_cast<uint64_t>(node.connman->GetNodeCount(ConnectionDirection::Out)));
                    conn.pushKV("total", static_cast<uint64_t>(node.connman->GetNodeCount(ConnectionDirection::Both)));
                    money.pushKV("connections", conn);
                }
                if (refuse_template) next.push_back("wait for chain sync before mining");
                else next.push_back(std::string("mining: ") + node::GetMiningChainGuardRecommendedAction(guard));
            } catch (const std::exception& e) {
                money.pushKV("error", e.what());
                next.push_back("start btxd");
            }
            out.pushKV("money", money);

            UniValue models;
            std::string err;
            if (HelperCall("checkmodelsetup", UniValue(UniValue::VARR), models, err)) {
                out.pushKV("models", models);
                if (models.exists("ready_to_host") && models["ready_to_host"].isTrue()) {
                    next.push_back("hostmodel <path>");
                }
            } else {
                UniValue m(UniValue::VOBJ);
                m.pushKV("helper_ready", false);
                m.pushKV("error", err.empty() ? "btx-modeld not connected" : err);
                m.pushKV("automatic_spend_atoms", 0);
                out.pushKV("models", m);
                next.push_back("start btx-modeld or wait for owned helper");
            }
            next.push_back("automatic_spend_atoms stays 0");
            out.pushKV("next_actions", next);
            std::string one = "hostmodel <path>";
            if (models.exists("one_liner") && models["one_liner"].isStr()) one = models["one_liner"].get_str();
            else if (money.exists("mining_recommended_action") && money["mining_recommended_action"].isStr()) {
                one = money["mining_recommended_action"].get_str();
            }
            out.pushKV("one_liner", one);
            return out;
        },
    };
}

static RPCHelpMan seedmodel()
{
    return ProxyOrLocal("seedmodel", "Publish a free hosting offer. Default -modelseed=auto already does this after import/getmodel; required only for -modelseed=manual.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// MODEL URI or hex"}});
}

static RPCHelpMan unseedmodel()
{
    return ProxyOrLocal("unseedmodel", "Withdraw a previously published hosting offer.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// MODEL URI or hex"}});
}

static RPCHelpMan pinmodel()
{
    return ProxyOrLocal("pinmodel", "Keep this model. Pinned pieces are never automatically evicted.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// MODEL URI or hex"}});
}

static RPCHelpMan unpinmodel()
{
    return ProxyOrLocal("unpinmodel", "Remove Keep. The model becomes eligible for automatic cache eviction.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// MODEL URI or hex"}});
}

static RPCHelpMan qualifymodel()
{
    return ProxyOrLocal("qualifymodel", "Static SafeTensors/GGUF check. Never a usefulness or safety claim.\n",
                        {{"path", RPCArg::Type::STR, RPCArg::Optional::NO, "filesystem path"}});
}

static RPCHelpMan addmodelnode()
{
    return ProxyOrLocal("addmodelnode", "Add a model-plane contact (not a monetary addnode; not AddrMan).\n",
                        {{"endpoint", RPCArg::Type::STR, RPCArg::Optional::NO, "host:port of a model helper"}});
}

static RPCHelpMan getmodelpeers()
{
    return ProxyOrLocal("getmodelpeers", "Inspect model-purpose contacts.\n", {});
}

static RPCHelpMan getmodeljob()
{
    return ProxyOrLocal("getmodeljob", "Job progress. Payment consequences shown when a paid job exists.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "job id"}});
}

static RPCHelpMan cancelmodeljob()
{
    return ProxyOrLocal("cancelmodeljob", "Cancel a model job and show payment consequences.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "job id"}});
}

static RPCHelpMan createmodelrelease()
{
    return ProxyOrLocal("createmodelrelease", "Commit an encrypted release campaign (secret stored as SHA-256 only). Monetary claim/refund uses 0.34.6 buildhtlcclaim / buildhtlcrefund.\n",
                        {{"body", RPCArg::Type::OBJ, RPCArg::Optional::NO, "campaign", {
                            {"uri", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "model uri"},
                            {"secret32_hex", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "32-byte secret hex; stored as SHA-256 only"},
                            {"refund_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "refund height"},
                        }}});
}

static RPCHelpMan pledgemodelrelease()
{
    return ProxyOrLocal("pledgemodelrelease", "Nonbinding local pledge accounting. Does not send BTX.\n",
                        {
                            {"release_id", RPCArg::Type::STR, RPCArg::Optional::NO, "digest48 hex"},
                            {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::NO, "atoms pledged locally"},
                        });
}

static RPCHelpMan getmodelrelease()
{
    return ProxyOrLocal("getmodelrelease", "List or inspect local campaign objects (pledge/funded/claimed are coordination state, not consensus).\n",
                        {{"release_id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "digest48 hex"}});
}

static RPCHelpMan claimmodelrelease()
{
    return ProxyOrLocal("claimmodelrelease", "Local campaign pointer; monetary claim is buildmodelhtlcclaim (0.34.6 htlc_sha256).\n", {});
}

static RPCHelpMan refundmodelrelease()
{
    return ProxyOrLocal("refundmodelrelease", "Local campaign pointer; monetary refund is buildmodelhtlcrefund (0.34.6 htlc_sha256). HASH160 htlc_tx is recovery-only.\n", {});
}

static RPCHelpMan decoderesourceuri()
{
    return ProxyOrLocal("decoderesourceuri", "Alias of decoderesource. Pure local parse; no network.\n",
                        {{"uri", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// token"}});
}

static RPCHelpMan encoderesourceuri()
{
    return ProxyOrLocal("encoderesourceuri", "Alias of encoderesource.\n",
                        {
                            {"kind", RPCArg::Type::STR, RPCArg::Optional::NO, "MODEL | ARTIFACT | ..."},
                            {"digest", RPCArg::Type::STR, RPCArg::Optional::NO, "96-hex digest48"},
                        });
}

static RPCHelpMan openbtxuri()
{
    return ProxyOrLocal("openbtxuri", "Preview-only URI dispatch. Never runs inference, mining, or wallet spend.\n",
                        {{"uri", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// token"}});
}

static RPCHelpMan resolveresource()
{
    return ProxyOrLocal("resolveresource", "Typed lookup with incomplete coverage. Local catalog first.\n",
                        {{"query", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "digest48 / text", {
                            {"digest48", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "96-hex"},
                            {"text", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "search text"},
                        }}});
}

static RPCHelpMan exportmodelpath()
{
    return ProxyOrLocal("exportmodelpath", "Return verified local store paths. Never starts a runtime.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "btx:// URI or digest48"}});
}

static RPCHelpMan getmodelpolicy()
{
    return ProxyOrLocal("getmodelpolicy",
                        "Local free-first and propagation policy. Automatic spend default is 0.\n"
                        "Demand-seed is the default once a storage budget is allocated. Catalog contacts (-modelpeer, addmodelnode, PEX) are followed by default. Arbitrary advertised models are not fetched; preserve_rare remains opt-in.\n",
                        {});
}

static RPCHelpMan setmodelpolicy()
{
    return ProxyOrLocal("setmodelpolicy", "Update local policy. auto_pay and non-zero automatic spend are refused.\n",
                        {{"policy", RPCArg::Type::OBJ, RPCArg::Optional::NO, "policy object", {
                            {"seed", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "auto | manual | off"},
                            {"seed_upon_download", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "B0 alias of seed=auto (true) or seed=off (false); not a second opt-in"},
                            {"preserve_rare", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "fetch under-replicated qualified models into spare quota"},
                            {"follow_configured_peers", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "follow FREE models announced by catalog contacts (default true)"},
                            {"retrieval_default", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "FREE_ONLY"},
                            {"upload_bps", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "serving cap in bytes/s; 0 = connection ceilings only"},
                        }}});
}

static RPCHelpMan listmodelidentities()
{
    return ProxyOrLocal("listmodelidentities", "Identity-only key store. Never wallet keys.\n", {});
}

static RPCHelpMan createmodelidentity()
{
    return ProxyOrLocal("createmodelidentity", "Create a local ML-DSA research identity. Not a spending key.\n",
                        {{"label", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "local label"}});
}

static RPCHelpMan getmodelreciprocity()
{
    return ProxyOrLocal("getmodelreciprocity", "Local useful-byte observations. Not money and not consensus.\n", {});
}

static RPCHelpMan exportmodelcontacts()
{
    return ProxyOrLocal("exportmodelcontacts", "Public model-plane contacts. No secret keys.\n", {});
}

static RPCHelpMan importmodelcontacts()
{
    return ProxyOrLocal("importmodelcontacts", "Previewed import of public endpoints. Downloading a model cannot modify trust.\n",
                        {{"peers", RPCArg::Type::ARR, RPCArg::Optional::NO, "host:port list", {
                            {"peer", RPCArg::Type::STR, RPCArg::Optional::NO, "host:port"},
                        }}});
}

static RPCHelpMan exportmodelpeers()
{
    return ProxyOrLocal("exportmodelpeers", "Alias of exportmodelcontacts.\n", {});
}

static RPCHelpMan importmodelpeers()
{
    return ProxyOrLocal("importmodelpeers", "Alias of importmodelcontacts.\n",
                        {{"peers", RPCArg::Type::ARR, RPCArg::Optional::NO, "host:port list", {
                            {"peer", RPCArg::Type::STR, RPCArg::Optional::NO, "host:port"},
                        }}});
}

static RPCHelpMan importmodeltrust()
{
    return ProxyOrLocal("importmodeltrust", "Operator-authorized peer import. Downloading a model cannot modify trusted identities.\n",
                        {{"peers", RPCArg::Type::ARR, RPCArg::Optional::NO, "host:port list", {
                            {"peer", RPCArg::Type::STR, RPCArg::Optional::NO, "host:port"},
                        }}});
}

static RPCHelpMan listmodelrules()
{
    return ProxyOrLocal("listmodelrules", "Scoped model ACL. Never writes BanMan.\n", {});
}

static RPCHelpMan setmodelrule()
{
    return ProxyOrLocal("setmodelrule", "Add a local model ACL rule. Never a monetary ban.\n",
                        {{"rule", RPCArg::Type::OBJ, RPCArg::Optional::NO, "rule object", {
                            {"deny_endpoint", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "endpoint"},
                            {"deny_artifact", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "artifact id"},
                        }}});
}

static RPCHelpMan removemodelrule()
{
    return ProxyOrLocal("removemodelrule", "Remove a local model ACL rule by index.\n",
                        {{"index", RPCArg::Type::NUM, RPCArg::Optional::NO, "rule index"}});
}

static RPCHelpMan joinmodelcircle()
{
    return ProxyOrLocal("joinmodelcircle", "Local voluntary storage/egress policy. No on-chain membership.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "circle id"}});
}

static RPCHelpMan leavemodelcircle()
{
    return ProxyOrLocal("leavemodelcircle", "Leave a local preservation circle.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "circle id"}});
}

static RPCHelpMan subscribemodelcollection()
{
    return ProxyOrLocal("subscribemodelcollection", "Local collection subscription. Preview by default.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "collection id"}});
}

static RPCHelpMan subscribemodelpolicy()
{
    return ProxyOrLocal("subscribemodelpolicy", "Local policy subscription. Does not approve spend.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "policy id"}});
}

static RPCHelpMan unsubscribemodelcollection()
{
    return ProxyOrLocal("unsubscribemodelcollection",
                        "Stop new automatic preservation for a collection. Local pins are kept. No on-chain membership.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "collection id"}});
}

static RPCHelpMan unsubscribemodelpolicy()
{
    return ProxyOrLocal("unsubscribemodelpolicy",
                        "Stop following a policy bundle. Local denials and pins remain.\n",
                        {{"id", RPCArg::Type::STR, RPCArg::Optional::NO, "policy id"}});
}

static RPCHelpMan delegatemodelservice()
{
    return ProxyOrLocal("delegatemodelservice", "Typed root-authorized operation. Never a money signature.\n",
                        {{"body", RPCArg::Type::OBJ, RPCArg::Optional::NO, "delegation", {
                            {"delegate", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "delegate id"},
                            {"scope", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "scope"},
                        }}});
}

static RPCHelpMan revokemodelservice()
{
    return ProxyOrLocal("revokemodelservice", "Revoke a local service delegation. Never a money signature.\n",
                        {{"body", RPCArg::Type::OBJ, RPCArg::Optional::NO, "revocation", {
                            {"target_id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "target id"},
                        }}});
}

static RPCHelpMan preparemodelfunding()
{
    return RPCHelpMan{
        "preparemodelfunding",
        "Freeze a bounded cohort and exact unsigned funding transaction paying a 0.34.6 htlc_sha256 HTLC.\n"
        "Coordinator only: never signs and never broadcasts. Claim/refund use buildhtlcclaim / buildhtlcrefund.\n",
        {
            {"release_id", RPCArg::Type::STR, RPCArg::Optional::NO, "Campaign release id (digest48 hex). An options object may be passed as the first argument instead.", RPCArgOptions{.skip_type_check = true}},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Funding terms if the model helper is unavailable", {
                {"key_hash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "32-byte SHA-256 hex of the release secret"},
                {"claimant", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "PQ claimant pubkey hex (or pk_slh(...))"},
                {"claimant_pubkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Alias of claimant"},
                {"refund_pubkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "PQ refund pubkey hex"},
                {"refund_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "CLTV refund height"},
                {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "HTLC output value in atoms"},
                {"fee_cap_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Maximum network fee in atoms"},
                {"max_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Alias of amount_atoms / approval ceiling"},
                {"auto_pay", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Must be false; automatic spend is zero"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "frozen quote fields (key_hash, claimant, refund_*, amount, fee, scripts, note)"},
            {RPCResult::Type::NUM, "schema_version", "2"},
            {RPCResult::Type::BOOL, "frozen", "true"},
            {RPCResult::Type::STR_HEX, "unsigned_hex", "Unsigned funding transaction"},
            {RPCResult::Type::STR, "descriptor", "mr(htlc_sha256(...),refund(...))"},
            {RPCResult::Type::NUM, "fee_cap_atoms", "Fee ceiling"},
            {RPCResult::Type::NUM, "automatic_spend", "Always 0"},
            {RPCResult::Type::STR, "htlc", "Always htlc_sha256"},
        }},
        RPCExamples{HelpExampleCli("preparemodelfunding", "\"<release_id>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            std::string release_id;
            UniValue options(UniValue::VOBJ);
            if (request.params[0].isStr()) {
                release_id = request.params[0].get_str();
                if (!request.params[1].isNull()) options = request.params[1];
            } else if (request.params[0].isObject()) {
                options = request.params[0];
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "release_id string or options object required");
            }
            wallet::FrozenFundingQuote q = QuoteFromRequest(release_id, options);
            if (q.amount_atoms == 0 && options.exists("max_atoms") && options["max_atoms"].isNum()) {
                q.amount_atoms = options["max_atoms"].getInt<int64_t>();
            }
            std::string err;
            if (!wallet::ValidateFundingAmount(q.amount_atoms, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            if (!wallet::BuildHtlcSha256Descriptor(q, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            auto pwallet = WalletForModelFunding(request);
            if (!wallet::CreateUnsignedFunding(*pwallet, q, err)) {
                const bool funds = err.find("nsufficient") != std::string::npos;
                throw JSONRPCError(funds ? RPC_WALLET_INSUFFICIENT_FUNDS : RPC_WALLET_ERROR, err);
            }
            if (!q.release_id.empty() && !q.output_script.empty()) {
                UniValue notify_params(UniValue::VARR);
                UniValue body(UniValue::VOBJ);
                body.pushKV("release_id", q.release_id);
                body.pushKV("output_script", HexStr(q.output_script));
                if (!q.key_hash_hex.empty()) body.pushKV("key_hash", q.key_hash_hex);
                notify_params.push_back(body);
                UniValue ign;
                std::string ierr;
                HelperCall("setreleaseoutputscript", notify_params, ign, ierr);
            }
            return wallet::FrozenQuoteToJson(q);
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan signmodelfunding()
{
    return RPCHelpMan{
        "signmodelfunding",
        "Validate and sign an exact frozen model-funding transaction through wallet policy.\n"
        "Txid mutation or HTLC output-script change is rejected; run preparemodelfunding again.\n"
        "Never auto_pay. Never broadcasts.\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Unsigned (or partially signed) funding transaction hex"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Frozen quote from preparemodelfunding", {
                {"unsigned_hex", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Exact unsigned template hex from prepare"},
                {"unsigned_txid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Frozen unsigned txid"},
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "mr(htlc_sha256(...),refund(...))"},
                {"output_script", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "HTLC scriptPubKey hex"},
                {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Frozen HTLC output value"},
                {"key_hash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "SHA-256 hex"},
                {"claimant", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "claimant pubkey"},
                {"refund_pubkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "refund pubkey"},
                {"refund_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "refund height"},
                {"auto_pay", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Must be false"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "echoed frozen quote fields"},
            {RPCResult::Type::NUM, "schema_version", "2"},
            {RPCResult::Type::STR_HEX, "hex", "Signed transaction hex"},
            {RPCResult::Type::BOOL, "complete", "Whether all inputs are signed"},
            {RPCResult::Type::NUM, "automatic_spend", "Always 0"},
            {RPCResult::Type::STR, "htlc", "Always htlc_sha256"},
        }},
        RPCExamples{HelpExampleCli("signmodelfunding", "\"<hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            UniValue options(UniValue::VOBJ);
            std::string hex;
            if (request.params[0].isStr()) {
                hex = request.params[0].get_str();
                if (!request.params[1].isNull()) options = request.params[1];
            } else if (request.params[0].isObject()) {
                options = request.params[0];
                if (!options.exists("hex") || !options["hex"].isStr()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "hex required");
                }
                hex = options["hex"].get_str();
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "hex required");
            }
            wallet::FrozenFundingQuote frozen = QuoteFromRequest(/*release_id=*/"", options);
            std::string err;
            CMutableTransaction mtx;
            if (!wallet::DecodeFundingTxHex(hex, mtx, err)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
            }
            if (!wallet::MatchFrozenTemplate(frozen, mtx, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            auto pwallet = WalletForModelFunding(request);
            bool complete{false};
            if (!wallet::SignFrozenFunding(*pwallet, mtx, complete, err)) {
                throw JSONRPCError(RPC_WALLET_ERROR, err);
            }
            UniValue out(UniValue::VOBJ);
            out.pushKV("schema_version", 2);
            out.pushKV("hex", EncodeHexTx(CTransaction(mtx)));
            out.pushKV("complete", complete);
            out.pushKV("txid", mtx.GetHash().GetHex());
            out.pushKV("frozen", true);
            out.pushKV("automatic_spend", 0);
            out.pushKV("htlc", "htlc_sha256");
            if (!complete && !err.empty()) out.pushKV("error", err);
            return out;
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan submitmodelfunding()
{
    return RPCHelpMan{
        "submitmodelfunding",
        "Revalidate a signed model-funding transaction and broadcast it.\n"
        "A duplicate txid is reported and is not double-spent.\n",
        {
            {"hex", RPCArg::Type::STR_HEX, RPCArg::Optional::NO, "Signed funding transaction hex"},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Frozen quote from preparemodelfunding", {
                {"unsigned_hex", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Exact unsigned template hex from prepare"},
                {"unsigned_txid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Frozen unsigned txid"},
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "mr(htlc_sha256(...),refund(...))"},
                {"output_script", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "HTLC scriptPubKey hex"},
                {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Frozen HTLC output value"},
                {"auto_pay", RPCArg::Type::BOOL, RPCArg::Optional::OMITTED, "Must be false"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::ELISION, "", "echoed frozen quote fields"},
            {RPCResult::Type::NUM, "schema_version", "2"},
            {RPCResult::Type::STR_HEX, "txid", "Broadcast or duplicate txid"},
            {RPCResult::Type::BOOL, "submitted", "true if this call introduced the tx"},
            {RPCResult::Type::BOOL, "duplicate", "true if the txid was already known"},
            {RPCResult::Type::NUM, "automatic_spend", "Always 0"},
            {RPCResult::Type::STR, "htlc", "Always htlc_sha256"},
        }},
        RPCExamples{HelpExampleCli("submitmodelfunding", "\"<hex>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            UniValue options(UniValue::VOBJ);
            std::string hex;
            if (request.params[0].isStr()) {
                hex = request.params[0].get_str();
                if (!request.params[1].isNull()) options = request.params[1];
            } else if (request.params[0].isObject()) {
                options = request.params[0];
                if (!options.exists("hex") || !options["hex"].isStr()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "hex required");
                }
                hex = options["hex"].get_str();
            } else {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "hex required");
            }
            std::string err;
            CMutableTransaction mtx;
            if (!wallet::DecodeFundingTxHex(hex, mtx, err)) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
            }
            if (options.isObject() && !options.empty()) {
                wallet::FrozenFundingQuote frozen = QuoteFromRequest(/*release_id=*/"", options);
                if (!frozen.unsigned_txid.IsNull() || !frozen.output_script.empty()) {
                    if (!wallet::MatchFrozenTemplate(frozen, mtx, err)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, err);
                    }
                }
            }
            const uint256 txid = mtx.GetHash().ToUint256();
            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            std::shared_ptr<wallet::CWallet> pwallet;
            try {
                pwallet = WalletForModelFunding(request);
            } catch (const UniValue&) {
                pwallet = nullptr;
            }
            bool duplicate = false;
            if (pwallet) {
                LOCK(pwallet->cs_wallet);
                if (pwallet->GetWalletTx(txid)) duplicate = true;
            }
            if (node.mempool && node.mempool->exists(GenTxid::Txid(txid))) duplicate = true;

            auto result_obj = [&](bool submitted, bool dup) {
                UniValue o(UniValue::VOBJ);
                o.pushKV("schema_version", 2);
                o.pushKV("txid", txid.GetHex());
                o.pushKV("submitted", submitted);
                o.pushKV("duplicate", dup);
                o.pushKV("automatic_spend", 0);
                o.pushKV("htlc", "htlc_sha256");
                return o;
            };
            if (duplicate) return result_obj(false, true);

            CTransactionRef tx = MakeTransactionRef(std::move(mtx));
            std::string bcast_err;
            const node::TransactionError terr = node::BroadcastTransaction(
                node, tx, bcast_err, node::DEFAULT_MAX_RAW_TX_FEE_RATE, /*relay=*/true, /*wait_callback=*/true);
            if (terr == node::TransactionError::ALREADY_IN_UTXO_SET) {
                return result_obj(false, true);
            }
            if (terr != node::TransactionError::OK) {
                throw JSONRPCTransactionError(terr, bcast_err);
            }
            if (pwallet) {
                wallet::mapValue_t map_value;
                map_value["modelnet"] = "funding";
                pwallet->CommitTransaction(tx, std::move(map_value), /*orderForm=*/{});
            }
            return result_obj(true, false);
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan exportmodelrecovery()
{
    return RPCHelpMan{
        "exportmodelrecovery",
        "Export public recovery material for a model-funding HTLC (descriptor, key_hash, refund height, addresses).\n"
        "Never dumps wallet seeds or ML-DSA service secret keys.\n",
        {
            {"release_id", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Campaign release id (digest48 hex)", RPCArgOptions{.skip_type_check = true}},
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Public terms if the helper is unavailable", {
                {"key_hash", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "32-byte SHA-256 hex"},
                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "mr(htlc_sha256(...),refund(...))"},
                {"claimant", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "PQ claimant pubkey hex"},
                {"refund_pubkey", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "PQ refund pubkey hex"},
                {"refund_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "CLTV refund height"},
                {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "HTLC output value"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {
            {RPCResult::Type::NUM, "schema_version", "2"},
            {RPCResult::Type::STR, "descriptor", "Public descriptor"},
            {RPCResult::Type::STR, "key_hash", "SHA-256 hashlock"},
            {RPCResult::Type::NUM, "refund_height", "CLTV height"},
            {RPCResult::Type::BOOL, "secrets", "Always false"},
        }},
        RPCExamples{HelpExampleCli("exportmodelrecovery", "\"<release_id>\"")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            std::string release_id;
            UniValue options(UniValue::VOBJ);
            if (!request.params[0].isNull()) {
                if (request.params[0].isStr()) {
                    release_id = request.params[0].get_str();
                } else if (request.params[0].isObject()) {
                    options = request.params[0];
                }
            }
            if (!request.params[1].isNull() && request.params[1].isObject()) {
                options = request.params[1];
            }
            wallet::FrozenFundingQuote q = QuoteFromRequest(release_id, options);
            std::string err;
            if (q.descriptor.empty() && !q.key_hash_hex.empty() && !q.claimant_key.empty() &&
                !q.refund_key.empty() && q.refund_height > 0) {
                if (!wallet::BuildHtlcSha256Descriptor(q, err)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, err);
                }
            } else if (!q.descriptor.empty() && q.output_script.empty()) {
                std::string canonical;
                if (!wallet::ExpandHtlcSha256Descriptor(q.descriptor, q.output_script, canonical, err)) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, err);
                }
                q.descriptor = canonical;
            }
            UniValue out = wallet::ExportModelRecoveryJson(q);
            if (q.descriptor.empty() && q.key_hash_hex.empty()) {
                out.pushKV("error", "no public recovery material; pass descriptor/key_hash or a known release_id");
            }
            return out;
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan buildmodelhtlcclaim()
{
    return ProxyOrLocal("buildmodelhtlcclaim",
                        "Build an unsigned 0.34.6 htlc_sha256 claim (SHA-256 preimage). HASH160 htlc_tx is recovery-only.\n"
                        "The helper never holds wallet keys: complete=false until the tx is signed.\n",
                        {
                            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Claim terms", {
                                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "mr(htlc_sha256(...),refund(...))"},
                                {"preimage", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "SHA-256 preimage hex"},
                                {"prevout", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Funding outpoint", {
                                    {"txid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Funding txid"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Output index"},
                                }},
                                {"destination", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Claim destination address"},
                                {"destination_script", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Claim scriptPubKey hex"},
                                {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "HTLC output value"},
                                {"fee_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Absolute fee"},
                            }},
                        });
}

static RPCHelpMan buildmodelhtlcrefund()
{
    return ProxyOrLocal("buildmodelhtlcrefund",
                        "Build an unsigned 0.34.6 htlc_sha256 refund (CLTV). HASH160 htlc_tx is recovery-only.\n",
                        {
                            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Refund terms", {
                                {"descriptor", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "mr(htlc_sha256(...),refund(...))"},
                                {"refund_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "CLTV height"},
                                {"prevout", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "Funding outpoint", {
                                    {"txid", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Funding txid"},
                                    {"vout", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Output index"},
                                }},
                                {"destination", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Refund destination address"},
                                {"destination_script", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Refund scriptPubKey hex"},
                                {"amount_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "HTLC output value"},
                                {"fee_atoms", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "Absolute fee"},
                            }},
                        });
}

#define BOUNTY_PROXY(n, h) \
    static RPCHelpMan n() \
    { \
        return ProxyOrLocal(#n, h, {{"request", RPCArg::Type::OBJ, RPCArg::Optional::OMITTED, "arguments", std::vector<RPCArg>{}, RPCArgOptions{.skip_type_check = true}}}); \
    }

BOUNTY_PROXY(searchbounties, "Search published bounties by description. Not a complete global directory.\n")
BOUNTY_PROXY(getmodelbounties, "List/search bounties. Not globally complete.\n")
BOUNTY_PROXY(getbounty, "Inspect a bounty entry. Unknown chain facts are null.\n")
BOUNTY_PROXY(getbountyeconomy, "Pledged vs confirmed funding. Pledged is never confirmed.\n")
BOUNTY_PROXY(getbountyterms, "Return the signed BountyTerms envelope.\n")
BOUNTY_PROXY(getbountycapabilities, "Installed records, scripts, and executed evaluation profiles only.\n")
BOUNTY_PROXY(createbountydraft, "Local draft. Title-only drafts are incomplete until all BountyTerms fields exist. No publication or deposit.\n")
BOUNTY_PROXY(listbountydrafts, "List local bounty drafts. No chain spend.\n")
BOUNTY_PROXY(getbountydraft, "Inspect a local bounty draft. No chain spend.\n")
BOUNTY_PROXY(updatebountydraft, "Patch a local bounty draft in place. Never publishes or spends.\n")
BOUNTY_PROXY(deletebountydraft, "Delete a local bounty draft. Never spends.\n")
BOUNTY_PROXY(validatebountyterms, "Schema, timeline, council, and money checks. Does not predict quality.\n")
BOUNTY_PROXY(publishbounty, "Sign exact terms with the research key. No wallet spend.\n")
BOUNTY_PROXY(revisebounty, "New terms id. Old deposits never migrate.\n")
BOUNTY_PROXY(nominatebountyevaluator, "Nomination only. No seat or spend authority.\n")
BOUNTY_PROXY(acceptbountyappointment, "Accept a frozen roster. Not a spend signature.\n")
BOUNTY_PROXY(listbountyevaluators, "Nominations and appointments for a bounty.\n")
BOUNTY_PROXY(pledgebounty, "Nonbinding pledge. Never presented as confirmed funding.\n")
BOUNTY_PROXY(withdrawbountypledge, "Withdraw a pledge, not deposited money.\n")
BOUNTY_PROXY(freezebountyfundinground, "Freeze contributors, council, and lots. Outputs immutable after this.\n")
BOUNTY_PROXY(getbountyfunding, "Public outpoints and watch-only completeness.\n")
BOUNTY_PROXY(commitbountysubmission, "Salted commitment. Not an originality proof.\n")
BOUNTY_PROXY(revealbountysubmission, "Reveal matching commitment. No public secrets.\n")
BOUNTY_PROXY(getbountysubmission, "Submission entry.\n")
BOUNTY_PROXY(listbountysubmissions, "Submissions for a bounty.\n")
BOUNTY_PROXY(withdrawbountysubmission, "Cannot erase public bytes or rewrite a settled award.\n")
BOUNTY_PROXY(preparebountyevaluation, "Installed profiles only. No execution yet.\n")
BOUNTY_PROXY(runbountyevaluation, "Isolated process. Requires execution approval. No wallet keys.\n")
BOUNTY_PROXY(getbountyevaluationjob, "Evaluation job status.\n")
BOUNTY_PROXY(cancelbountyevaluation, "Kills the worker process, not only JSON state.\n")
BOUNTY_PROXY(publishbountyevaluation, "Report signature is not an award or transaction signature.\n")
BOUNTY_PROXY(listbountyevaluations, "Published evaluation reports.\n")
BOUNTY_PROXY(createbountychallenge, "Bounded typed challenge.\n")
BOUNTY_PROXY(listbountychallenges, "Challenges for a bounty.\n")
BOUNTY_PROXY(resolvebountychallenge, "Cannot revoke a released transaction signature.\n")
BOUNTY_PROXY(proposebountyaward, "Complete binding. No payment yet. Never automatic.\n")
BOUNTY_PROXY(approvebountyaward, "Policy approval. Explicitly not a transaction signature.\n")
BOUNTY_PROXY(getbountyaward, "Award entry.\n")
BOUNTY_PROXY(getbountyevents, "Node-local cursor with epoch/gap detection.\n")
BOUNTY_PROXY(watchbounty, "Local watch. Does not download, evaluate, or spend.\n")
BOUNTY_PROXY(unwatchbounty, "Remove a local watch.\n")
BOUNTY_PROXY(getagentmandate, "Owner-only mandate view.\n")
BOUNTY_PROXY(createagentmandate, "Finite mandate. No unbounded all-recipient default.\n")
BOUNTY_PROXY(revokeagentmandate, "Blocks new signatures, not already released ones.\n")
BOUNTY_PROXY(getagentactivity, "Redacted local audit. No telemetry.\n")
BOUNTY_PROXY(reservemandate, "Atomic mandate reservation. Cannot exceed budget or swap refund keys.\n")
BOUNTY_PROXY(createsubscriptionmandate, "Finite SubscriptionMandate for future objects. Distinct from AgentMandate. Never unbounded. automatic_spend_atoms remains 0.\n")
BOUNTY_PROXY(getsubscriptionmandate, "Inspect a SubscriptionMandate. No wallet keys.\n")
BOUNTY_PROXY(getsubscriptionactivity, "WALLET_OWNER ActionPage: event to terms to reservation. Never wallet keys or telemetry. automatic_spend_atoms remains 0.\n")
BOUNTY_PROXY(revokesubscriptionmandate, "Blocks new SubscriptionMandate signatures. Already broadcast stays real.\n")
BOUNTY_PROXY(reservesubscriptionmandate, "Atomic SubscriptionMandate reservation. Cannot exceed budget.\n")
BOUNTY_PROXY(watchmodelpublisher, "Local publisher watch. Distinct from filesystem -modelwatch. Default NOTIFY. No spend.\n")
BOUNTY_PROXY(watchmodelcollection, "Local collection watch. No spend.\n")
BOUNTY_PROXY(watchmodelquery, "Stored bounded search filter. Uses ordinary feed/search sync. No extra fanout.\n")
BOUNTY_PROXY(watchmodel, "Watch one model id. No spend.\n")
BOUNTY_PROXY(listmodelwatches, "List local network watches. Not filesystem drop-folder status.\n")
BOUNTY_PROXY(getmodelwatch, "Inspect one network watch. Not getmodelwatchstatus.\n")
BOUNTY_PROXY(unwatchmodel, "Remove a local network watch.\n")
BOUNTY_PROXY(getmodelevents, "Replay local ModelEventJournal after a cursor. Node-local observations, not consensus.\n")
BOUNTY_PROXY(getmodeleventsequence, "Current local event sequence / cursor.\n")
BOUNTY_PROXY(waitformodelevent, "Long-poll events after a cursor. Timeout, bounded page, no shell.\n")
BOUNTY_PROXY(getmodelwatchactions, "Drain queued watch actions. FREE_DOWNLOAD is coordinator getmodel FREE_ONLY. Never auto-spend.\n")
BOUNTY_PROXY(observemodelchannel, "Apply a publisher-signed channel pointer. Not model identity.\n")
BOUNTY_PROXY(seedlabmodelchannel, "Lab-only: generate a publisher key, sign a stable channel, and store it. Not identity. automatic_spend_atoms stays 0.\n")
BOUNTY_PROXY(getmodelchannel, "Inspect a signed channel pointer.\n")
BOUNTY_PROXY(listmodelchannels, "List local signed channels.\n")
BOUNTY_PROXY(getmodelprofile, "Operator profile preset. Ordinary policy only.\n")
BOUNTY_PROXY(setmodelprofile, "Persist personal|infrastructure|mirror|custom. Host-auto/follow/preserve/upload apply live; NODE_MODEL_HOST still follows AutoHostShouldAdvertise.\n")
BOUNTY_PROXY(setcloudstorage, "Persist local S3/R2/MinIO origin config. Credential ref only; secrets never in RPC JSON, search, events, or GUI. allow_link_local is rejected.\n")
BOUNTY_PROXY(testcloudstorage, "Local origin probe. FakeS3 or configured backend. Not WAN evidence. No secrets out.\n")
BOUNTY_PROXY(getcloudstorageinfo, "Cloud origin health and layout. No credentials. Live R2 WAN remains NOT_RUN.\n")
BOUNTY_PROXY(getmodelmirror, "Local mirror keep/follow policy. Node role only; not consensus or search privilege. Never auto-spends.\n")
BOUNTY_PROXY(setmodelmirror, "Persist publisher/collection/query keep-N. automatic_spend_atoms stays 0.\n")
BOUNTY_PROXY(executemodelimport, "Execute an ImportPlan. Staging UUID until VerifiedManifest. HF/torrent integrity is not authorship. No live HTTP; no auto-spend.\n")
BOUNTY_PROXY(getmodelimport, "Import job status. Source integrity is not publisher authorship.\n")
BOUNTY_PROXY(cancelmodelimport, "Drop a local import job. Never spends.\n")
BOUNTY_PROXY(resumemodelimport, "Re-prepare staging for a local ImportPlan. No live HTTP.\n")
BOUNTY_PROXY(publishmodelimport, "Status only until VerifiedManifest is accepted. Does not wallet-sign.\n")
BOUNTY_PROXY(createbtxpackage, "Binary .btxbundle (secret-scan). Distinct from exportmodellink magnet analog. No secrets.\n")
BOUNTY_PROXY(inspectbtxpackage, "Decode a public .btxbundle. Does not mutate the catalog.\n")
BOUNTY_PROXY(verifybtxpackage, "Verify public .btxbundle framing. Catalog install still needs VerifiedManifest.\n")
BOUNTY_PROXY(importbtxpackage, "Inspect a .btxbundle. Does not auto-install or spend.\n")
BOUNTY_PROXY(exportbtxbundle, "Alias of createbtxpackage. exportmodellink remains the JSON magnet analog.\n")
BOUNTY_PROXY(exportbtxpackage, "AHP catalog name. Alias of exportbtxbundle/createbtxpackage. Not a magnet analog.\n")
BOUNTY_PROXY(getbtxpackagedocument, "Inert escaped virtual document. Never writes project or home AGENTS.md.\n")
BOUNTY_PROXY(getbtxpackagecapabilities, "Actually supported package/handoff profiles. GUI remains DEFERRED_WITH_EVIDENCE.\n")
BOUNTY_PROXY(planbtxacquisition, "FREE_ONLY AcquisitionPlan. Does not download. automatic_spend_atoms stays 0.\n")
BOUNTY_PROXY(executebtxacquisition, "Execute a finite FREE_ONLY plan. Verified local files become MODEL_READY; otherwise SELECTION_READY without claiming swarm bytes. No auto-spend.\n")
BOUNTY_PROXY(getbtxacquisition, "Owned acquisition job status and receipt. Never spends.\n")
BOUNTY_PROXY(cancelbtxacquisition, "Cancel an owned acquisition job. Reservations released; no spend.\n")
BOUNTY_PROXY(planbtxclientinstall, "InstallPlan from independently trusted catalogue. TRUST_REQUIRED otherwise. Does not install.\n")
BOUNTY_PROXY(planbtxruntime, "RuntimePlan only. Does not execute. No arbitrary argv or remote inference.\n")
BOUNTY_PROXY(resolvebtxcapability, "Owner-local capability resolver. Typed plan required. Never public HTTP. automatic_spend_atoms stays 0.\n")
BOUNTY_PROXY(planbtxcapability, "Finite CapabilityPlan. No spend. No remote inference.\n")
BOUNTY_PROXY(ensurebtxcapability, "IMPLEMENTED_LAB. Runs the local fixture path for a granted plan; does not yet dereference recipe digests.\n")
BOUNTY_PROXY(getbtxcapability, "Owner-local job/lease readiness. No public pointers.\n")
BOUNTY_PROXY(cancelbtxcapability, "Logical cancel. Physical disposition may remain STILL_IN_FLIGHT.\n")
BOUNTY_PROXY(releasebtxcapability, "Release a quiescent lease only.\n")
BOUNTY_PROXY(prefetchbtxcapability, "Bounded speculative prefetch. Rejects prompt transcripts. automatic_spend_atoms stays 0.\n")
BOUNTY_PROXY(sleepbtxcapability, "Preserve weights; discard KV/workspace. Not readiness.\n")
BOUNTY_PROXY(wakebtxcapability, "Rebuild discarded KV before readiness. Remap alone is not success.\n")
BOUNTY_PROXY(getbtxresidency, "Owner-local residency facts. Never public raw pointers.\n")
BOUNTY_PROXY(inspectbtxtensormap, "Derive a bounded TensorRangeMap from verified header bytes.\n")
BOUNTY_PROXY(exportbtxlock, "Export canonical lock bytes. No secrets.\n")
BOUNTY_PROXY(importbtxlock, "Import a digest-bound lock. ensure --locked performs no re-resolution.\n")
BOUNTY_PROXY(planbtxcapabilityupdate, "Propose a new lock beside the active generation.\n")
BOUNTY_PROXY(switchbtxcapability, "Atomic generation switch with journal/rollback.\n")
BOUNTY_PROXY(getbtxcapabilityevents, "Owner-local capability lifecycle events.\n")
BOUNTY_PROXY(getbtxruntimecapabilities, "Actual probed local adapters. Absent hardware is NOT_RUN, never a stub PASS.\n")
BOUNTY_PROXY(getbtxttctrace, "Critical-path TTC, not occupancy sum.\n")
BOUNTY_PROXY(accepthcphandoff, "Accept a signed HCP/1 CapabilityHandoff. Requires LocalCapabilityGrant. Not a wallet. automatic_spend_atoms stays 0.\n")
BOUNTY_PROXY(enrollhcpprovider, "Operator-accepted HCP provider enrollment. Package self-signature never auto-enrolls.\n")
BOUNTY_PROXY(previewhcpprovider, "Preview an HCP ProviderProfile without trusting it or connecting an account.\n")
BOUNTY_PROXY(sethcplocalgrant, "Install an owner-local capability grant. HostedAccountPolicy is not runtime or spend authority.\n")
BOUNTY_PROXY(gethcpreadiness, "Local readiness is independent of FinancialReceipt.\n")
BOUNTY_PROXY(exporthcpstate, "Export public HCP/package state. No secrets, prompts, KV, or custody keys.\n")
BOUNTY_PROXY(importhcpstate, "Import public HCP state. Secrets are refused. Not a wallet restore.\n")
BOUNTY_PROXY(sethcpreporting, "Owner opt-in readiness reporting. Default off. No prompts/KV.\n")
BOUNTY_PROXY(hcphandle, "Owner-local typed HCP handle. Not public HTTP capability. No /rpc passthrough.\n")
BOUNTY_PROXY(pairhcpdevice, "Pair a device for outbound-only HCP handoff. No inbound runtime port.\n")
BOUNTY_PROXY(revokehcpdevice, "Revoke a paired HCP device. Local public capability remains under owner policy.\n")
BOUNTY_PROXY(gethcpconnectorstatus, "Walletless connector status. start_wallet and start_mining stay off in the preset.\n")
BOUNTY_PROXY(applyhcpwalletless, "Apply the walletless HCP client preset. No monetary wallet or mining.\n")
BOUNTY_PROXY(hcphealth, "HCP connector health. automatic_spend_atoms stays 0.\n")
BOUNTY_PROXY(planhcplocal, "Local TTC plan for a hosted handoff recipe. Does not report private inventory.\n")
BOUNTY_PROXY(puthcplocalitysources, "Lab-only LAN vs internet TTC sources for planhcplocal. Does not report inventory. automatic_spend_atoms stays 0.\n")
BOUNTY_PROXY(minthcphandoff, "Mint a lab-signed CapabilityHandoff. Not a wallet. automatic_spend_atoms stays 0.\n")
BOUNTY_PROXY(ensurehcplocal, "Owner-local ensure for a hosted recipe. No remote inference. No second downloader.\n")
BOUNTY_PROXY(preparemodelerasure, "Evaluate per-stripe erasure health. Global n is not reconstructability.\n")
BOUNTY_PROXY(executemodelerasure, "Evaluate erasure plan. Does not change canonical model identity.\n")
BOUNTY_PROXY(getmodelerasurehealth, "Per-stripe reconstructability. Global shard count is informational only.\n")
BOUNTY_PROXY(repairmodel, "Report per-stripe deficit. Does not auto-repair or spend.\n")
BOUNTY_PROXY(gettorrentsourcestatus, "Torrent/magnet infohash status. Packaged bridge; btx-torrentd is not a process.\n")
BOUNTY_PROXY(getmodeloriginoffer, "Native-proxy origin offer. Presigned GET is not a meter. No secrets out.\n")
BOUNTY_PROXY(getmodeloriginstatus, "Origin broker counters. Native proxy default.\n")
BOUNTY_PROXY(querymodelsummary, "Bounded query summary (sample cap 32). Not a global census.\n")
BOUNTY_PROXY(reconcilemodelindex, "Anti-entropy want list (cap 256). Digests do not authorize insert.\n")
BOUNTY_PROXY(getmodelobjectlayout, "WHOLE_FILE / LARGE_EXTENTS / PIECE_OBJECTS arithmetic. Does not replace R2 SOURCE_FILES.\n")
BOUNTY_PROXY(validatesubpiece, "SUBPIECE_V1 256 KiB request check. Overlap/overflow rejected. Partial pieces are not advertised.\n")
BOUNTY_PROXY(getmodelbulkstatus, "Low-priority bulk share. Interactive piece traffic keeps priority.\n")
BOUNTY_PROXY(getmodelioexecutor, "Bounded outstanding I/O. Not io_uring.\n")
BOUNTY_PROXY(getevaluatedtransport, "uTP/QUIC/dedup/64-80/10M catalog disposition. NONSHIPPING / NOT_RUN stay honest.\n")
BOUNTY_PROXY(addmodelstorage, "Catalog alias of setcloudstorage. Does not duplicate the private method.\n")
BOUNTY_PROXY(inspectmodelstorage, "Catalog alias of testcloudstorage. Not WAN evidence.\n")
BOUNTY_PROXY(testmodelstorage, "Catalog alias of testcloudstorage. Bounded probe only.\n")
BOUNTY_PROXY(listmodelstorage, "Catalog alias of getcloudstorageinfo. No secrets.\n")
BOUNTY_PROXY(getmodelcapabilities, "Catalog alias of getmodelnetworkinfo. No unexecuted capability flags.\n")
BOUNTY_PROXY(getmodeltransfermetrics, "Catalog alias of getmodeltransfers.\n")
BOUNTY_PROXY(requestmodelorigin, "Catalog alias of getmodeloriginoffer. Presigned GET is not a meter.\n")
BOUNTY_PROXY(getmodeloriginhealth, "Catalog alias of getmodeloriginstatus.\n")
BOUNTY_PROXY(getmodelmirrorstatus, "Catalog alias of getmodelmirror.\n")
BOUNTY_PROXY(removemodelstorage, "Detach local cloud handle. Never deletes remote bucket objects.\n")
BOUNTY_PROXY(setmodelstoragepolicy, "Local handle policy. Credentials do not approve unlimited I/O.\n")
BOUNTY_PROXY(setbootstrapdistributor, "Truthful bootstrap leases. Does not advertise false missing bitfields.\n")
BOUNTY_PROXY(getbootstrapstatus, "Bootstrap lease counters. Origin independence is a later disable-origin proof.\n")
BOUNTY_PROXY(setmodeluploadpolicy, "Finite upload slots. Connection count is not service capacity.\n")
BOUNTY_PROXY(getmodeluploadinfo, "Upload scheduler slots and per-identity/netgroup caps.\n")
BOUNTY_PROXY(planmodelstoragemigration, "Local migration plan. No bulk I/O.\n")
BOUNTY_PROXY(executemodelstoragemigration, "Does not execute a second 400 GiB copy. Plan only unless authorized.\n")
BOUNTY_PROXY(setmodelswarmhealer, "Local healer policy. Repair is not auto-spend.\n")
BOUNTY_PROXY(settorrentsourcepolicy, "Torrent worker gets no S3 credentials. btx-torrentd is not a process.\n")
BOUNTY_PROXY(getmodelroutingstatus, "Query/LAN/delegated routing diagnostics. Not consensus.\n")
BOUNTY_PROXY(setmodeldiscoverypolicy, "Local discovery policy. Throughput is not ranking authority.\n")
BOUNTY_PROXY(getmodelresidency, "ABSENT/STAGING/VERIFIED_*/REPAIRABLE/UNAVAILABLE. HeadObject is not VERIFIED_REMOTE.\n")
BOUNTY_PROXY(getmodeldedupinfo, "Physical byte digest reuse. Content-defined dedup is NONSHIPPING.\n")
BOUNTY_PROXY(getmodellandiscovery, "LAN endpoint observation. Not a public-address requirement.\n")
BOUNTY_PROXY(getmodelfileselection, "SELECTIVE_FILES_V1. Unselected files are not HAVE.\n")
BOUNTY_PROXY(getmultipartjournal, "Multipart journal. ETag is not SHA-384 identity.\n")
BOUNTY_PROXY(getsourcepolicy, "SSRF pin. Torrent worker receives no S3 credentials. No redirects.\n")
BOUNTY_PROXY(observebountychain, "Watch-only outpoint observation. Not a consensus oracle.\n")
BOUNTY_PROXY(reorgbountychain, "Disconnect last observed tip. Secret knowledge is not chain state.\n")
BOUNTY_PROXY(exportbountyrecovery, "Scripts and lineage. No seed or private keys.\n")
BOUNTY_PROXY(importbountyrecovery, "Manifest object only. No automatic broadcast.\n")

static RPCHelpMan preparebountyfunding()
{
    return RPCHelpMan{
        "preparebountyfunding",
        "Freeze an exact two-leaf CLTV-multisig+refund funding transaction. User amount and refund key required. Helper defaults are ignored.\n",
        {
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "Funding plan", {
                {"principal_atoms", RPCArg::Type::STR, RPCArg::Optional::NO, "Exact user-selected amount"},
                {"refund_key", RPCArg::Type::STR, RPCArg::Optional::NO, "Contributor refund pubkey"},
                {"fee_reserve_atoms", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "Fee ceiling"},
                {"council_keys", RPCArg::Type::ARR, RPCArg::Optional::OMITTED, "Council pubkeys", {{"key", RPCArg::Type::STR, RPCArg::Optional::OMITTED, "hex"}}},
                {"threshold", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "m"},
                {"award_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "CLTV award height"},
                {"refund_height", RPCArg::Type::NUM, RPCArg::Optional::OMITTED, "CLTV refund height"},
            }},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", "plan"}}},
        RPCExamples{HelpExampleCli("preparebountyfunding", "'{}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            std::string err;
            wallet::BountyEscrowPlan plan;
            if (!wallet::ParseBountyPlan(request.params[0], plan, err)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            }
            if (plan.principal_atoms <= 0 || plan.refund_key.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "principal_atoms and refund_key are required from the user");
            }
            auto pwallet = WalletForModelFunding(request);
            if (!wallet::PrepareBountyFunding(*pwallet, plan, err)) {
                throw JSONRPCError(RPC_WALLET_ERROR, err);
            }
            return wallet::BountyPlanToJson(plan);
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan inspectbountytransaction()
{
    return RPCHelpMan{
        "inspectbountytransaction",
        "No signing. Full authorized/unauthorized diff of a bounty transaction.\n",
        {
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "plan + hex", std::vector<RPCArg>{}, RPCArgOptions{.skip_type_check = true}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", "inspection"}}},
        RPCExamples{HelpExampleCli("inspectbountytransaction", "'{}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            std::string err;
            wallet::BountyEscrowPlan plan;
            const UniValue& o = request.params[0];
            if (!wallet::ParseBountyPlan(o, plan, err)) throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            CMutableTransaction tx;
            const std::string hex = o.exists("hex") ? o["hex"].get_str() : (o.exists("transaction") ? o["transaction"].get_str() : plan.unsigned_hex);
            if (!wallet::DecodeFundingTxHex(hex, tx, err)) throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
            UniValue out;
            if (!wallet::InspectBountyTransaction(plan, tx, out, err)) throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            return out;
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan signbountyfunding()
{
    return RPCHelpMan{
        "signbountyfunding",
        "SIGHASH_ALL only. Refuse ANYONECANPAY. Exact inspected fingerprint.\n",
        {
            {"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "plan + hex", std::vector<RPCArg>{}, RPCArgOptions{.skip_type_check = true}},
        },
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", "signed"}}},
        RPCExamples{HelpExampleCli("signbountyfunding", "'{}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            std::string err;
            wallet::BountyEscrowPlan plan;
            const UniValue& o = request.params[0];
            if (!wallet::ParseBountyPlan(o, plan, err)) throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            CMutableTransaction tx;
            if (!wallet::DecodeFundingTxHex(o.exists("hex") ? o["hex"].get_str() : plan.unsigned_hex, tx, err))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
            auto pwallet = WalletForModelFunding(request);
            if (!wallet::SignBountyTransaction(*pwallet, plan, tx, err)) throw JSONRPCError(RPC_WALLET_ERROR, err);
            UniValue out = wallet::BountyPlanToJson(plan);
            out.pushKV("hex", EncodeHexTx(CTransaction(tx)));
            out.pushKV("txid", tx.GetHash().GetHex());
            return out;
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan NamedBountyInspect(const std::string& name)
{
    return RPCHelpMan{
        name,
        "No signing. Recompute inputs, principal, output keys, exact tree, fees and deadlines.\n",
        {{"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "plan + hex", std::vector<RPCArg>{}, RPCArgOptions{.skip_type_check = true}}},
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", "inspection"}}},
        RPCExamples{HelpExampleCli(name, "'{}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            std::string err;
            wallet::BountyEscrowPlan plan;
            const UniValue& o = request.params[0];
            if (!wallet::ParseBountyPlan(o, plan, err)) throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            CMutableTransaction tx;
            const std::string hex = o.exists("hex") ? o["hex"].get_str() : plan.unsigned_hex;
            if (!wallet::DecodeFundingTxHex(hex, tx, err)) throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
            UniValue out;
            if (!wallet::InspectBountyTransaction(plan, tx, out, err)) throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            return out;
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan NamedBountySign(const std::string& name)
{
    return RPCHelpMan{
        name,
        "SIGHASH_ALL only. Exact inspected fingerprint. No implicit ANYONECANPAY.\n",
        {{"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "plan + hex", std::vector<RPCArg>{}, RPCArgOptions{.skip_type_check = true}}},
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", "signed"}}},
        RPCExamples{HelpExampleCli(name, "'{}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            std::string err;
            wallet::BountyEscrowPlan plan;
            const UniValue& o = request.params[0];
            if (!wallet::ParseBountyPlan(o, plan, err)) throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            CMutableTransaction tx;
            if (!wallet::DecodeFundingTxHex(o.exists("hex") ? o["hex"].get_str() : plan.unsigned_hex, tx, err))
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
            auto pwallet = WalletForModelFunding(request);
            if (!wallet::SignBountyTransaction(*pwallet, plan, tx, err)) throw JSONRPCError(RPC_WALLET_ERROR, err);
            UniValue out = wallet::BountyPlanToJson(plan);
            out.pushKV("hex", EncodeHexTx(CTransaction(tx)));
            out.pushKV("txid", tx.GetHash().GetHex());
            return out;
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan NamedBountySubmit(const std::string& name)
{
    return RPCHelpMan{
        name,
        "Live revalidation then broadcast. Duplicate txid is reported.\n",
        {{"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "signed hex", std::vector<RPCArg>{}, RPCArgOptions{.skip_type_check = true}}},
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", "broadcast"}}},
        RPCExamples{HelpExampleCli(name, "'{}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            const UniValue& o = request.params[0];
            std::string err;
            CMutableTransaction mtx;
            const std::string hex = o.exists("hex") ? o["hex"].get_str() : o.exists("signed_transaction") ? o["signed_transaction"].get_str() : "";
            if (!wallet::DecodeFundingTxHex(hex, mtx, err)) throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
            node::NodeContext& node = EnsureAnyNodeContext(request.context);
            std::string err_string;
            const CTransactionRef tx = MakeTransactionRef(mtx);
            const node::TransactionError err_code = node::BroadcastTransaction(
                node, tx, err_string, node::DEFAULT_MAX_RAW_TX_FEE_RATE, /*relay=*/true, /*wait_callback=*/false);
            UniValue out(UniValue::VOBJ);
            out.pushKV("txid", tx->GetHash().GetHex());
            out.pushKV("submitted", err_code == node::TransactionError::OK);
            out.pushKV("duplicate", err_code == node::TransactionError::ALREADY_IN_UTXO_SET);
            out.pushKV("error", err_string);
            out.pushKV("automatic_spend", 0);
            return out;
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}

static RPCHelpMan submitbountyfunding() { return NamedBountySubmit("submitbountyfunding"); }
static RPCHelpMan inspectbountyaward() { return NamedBountyInspect("inspectbountyaward"); }
static RPCHelpMan signbountyaward() { return NamedBountySign("signbountyaward"); }
static RPCHelpMan submitbountyaward() { return NamedBountySubmit("submitbountyaward"); }
static RPCHelpMan preparebountyclaim()
{
    return RPCHelpMan{
        "preparebountyclaim",
        "Prepare staged SHA256 claim. Does not log preimages. Revalidate chain, branch, maturity, keys and fee policy.\n",
        {{"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "lot_ids, secret_ref, fee_ceiling", std::vector<RPCArg>{}, RPCArgOptions{.skip_type_check = true}}},
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", "plan"}}},
        RPCExamples{HelpExampleCli("preparebountyclaim", "'{}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            std::string err;
            wallet::BountyEscrowPlan plan;
            if (!wallet::ParseBountyPlan(request.params[0], plan, err)) throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            if (request.params[0].exists("secret") || request.params[0].exists("preimage")) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "preimages are not accepted on the wire; use secret_ref");
            }
            plan.mode = "STAGED_RELEASE";
            if (!wallet::BuildStagedHtlcDescriptor(plan, err)) throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            return wallet::BountyPlanToJson(plan);
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}
static RPCHelpMan signbountyclaim() { return NamedBountySign("signbountyclaim"); }
static RPCHelpMan submitbountyclaim() { return NamedBountySubmit("submitbountyclaim"); }
static RPCHelpMan preparebountyrefund()
{
    return RPCHelpMan{
        "preparebountyrefund",
        "Prepare contributor refund after maturity. Council/helper may be offline.\n",
        {{"options", RPCArg::Type::OBJ, RPCArg::Optional::NO, "owned lots", std::vector<RPCArg>{}, RPCArgOptions{.skip_type_check = true}}},
        RPCResult{RPCResult::Type::OBJ, "", "", {{RPCResult::Type::ELISION, "", "plan"}}},
        RPCExamples{HelpExampleCli("preparebountyrefund", "'{}'")},
        [&](const RPCHelpMan& self, const JSONRPCRequest& request) -> UniValue {
            (void)self;
#ifdef ENABLE_WALLET
            std::string err;
            wallet::BountyEscrowPlan plan;
            if (!wallet::ParseBountyPlan(request.params[0], plan, err)) throw JSONRPCError(RPC_INVALID_PARAMETER, err);
            if (plan.principal_atoms <= 0 || plan.refund_key.empty()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "principal_atoms and refund_key are required from the user");
            }
            auto pwallet = WalletForModelFunding(request);
            if (!wallet::PrepareBountyFunding(*pwallet, plan, err)) throw JSONRPCError(RPC_WALLET_ERROR, err);
            return wallet::BountyPlanToJson(plan);
#else
            throw JSONRPCError(RPC_WALLET_NOT_FOUND, "Wallet support is not compiled into this btxd");
#endif
        },
    };
}
static RPCHelpMan signbountyrefund() { return NamedBountySign("signbountyrefund"); }
static RPCHelpMan submitbountyrefund() { return NamedBountySubmit("submitbountyrefund"); }

void RegisterModelNetRPCCommands(CRPCTable& t)
{
#ifdef ENABLE_MODELNET
    static const CRPCCommand commands[]{
        {"modelnet", &getmodelnetworkinfo},
        {"modelnet", &getmodelcryptoinfo},
        {"modelnet", &decoderesource},
        {"modelnet", &encoderesource},
        {"modelnet", &decoderesourceuri},
        {"modelnet", &encoderesourceuri},
        {"modelnet", &openbtxuri},
        {"modelnet", &resolveresource},
        {"modelnet", &getmodel},
        {"modelnet", &listmodels},
        {"modelnet", &searchmodels},
        {"modelnet", &getmodelsearchrecord},
        {"modelnet", &publishmodelsearchrecord},
        {"modelnet", &updatemodelsearchrecord},
        {"modelnet", &removemodelsearchrecord},
        {"modelnet", &listmodelsearchrecords},
        {"modelnet", &getmodeldirectoryentry},
        {"modelnet", &getmodeldirectory},
        {"modelnet", &getmodelproviders},
        {"modelnet", &getmodelavailability},
        {"modelnet", &getmodelpeercount},
        {"modelnet", &getnetworkmodelstats},
        {"modelnet", &getmodelaliases},
        {"modelnet", &searchpublishers},
        {"modelnet", &getpublisher},
        {"modelnet", &searchcollections},
        {"modelnet", &getcollection},
        {"modelnet", &browsemodels},
        {"modelnet", &gettrendingmodels},
        {"modelnet", &getsimilarmodels},
        {"modelnet", &getnewmodels},
        {"modelnet", &getrecentreleases},
        {"modelnet", &getmodeleconomyentry},
        {"modelnet", &getmodelfeed},
        {"modelnet", &getmodelfeedstatus},
        {"modelnet", &getmodelfeedsequence},
        {"modelnet", &getfundablemodels},
        {"modelnet", &getmodelreleaseeconomics},
        {"modelnet", &getrecentlyunlockedmodels},
        {"modelnet", &getreleasefeed},
        {"modelnet", &preparefundmodelrelease},
        {"modelnet", &cacheencryptedmodel},
        {"modelnet", &getsearchstatus},
        {"modelnet", &cancelmodelsearch},
        {"modelnet", &getsearchpeers},
        {"modelnet", &addmodelindex},
        {"modelnet", &removemodelindex},
        {"modelnet", &exportmodelindex},
        {"modelnet", &importmodelindex},
        {"modelnet", &hidesearchmodel},
        {"modelnet", &unhidesearchmodel},
        {"modelnet", &mutesearchpublisher},
        {"modelnet", &unmutesearchpublisher},
        {"modelnet", &getmodelmanifest},
        {"modelnet", &importmodel},
        {"modelnet", &hostmodel},
        {"modelnet", &checkmodelsetup},
        {"modelnet", &previewmodelimport},
        {"modelnet", &getmodelsharecard},
        {"modelnet", &getmodeltransfers},
        {"modelnet", &setmodelalias},
        {"modelnet", &scanmodelwatch},
        {"modelnet", &getmodelwatchstatus},
        {"modelnet", &showmodel},
        {"modelnet", &exportmodellink},
        {"modelnet", &unhostmodel},
        {"modelnet", &removemodelalias},
        {"modelnet", &openmodelshare},
        {"modelnet", &getsetupstatus},
        {"modelnet", &seedmodel},
        {"modelnet", &unseedmodel},
        {"modelnet", &pinmodel},
        {"modelnet", &unpinmodel},
        {"modelnet", &qualifymodel},
        {"modelnet", &addmodelnode},
        {"modelnet", &getmodelpeers},
        {"modelnet", &getmodeljob},
        {"modelnet", &cancelmodeljob},
        {"modelnet", &exportmodelpath},
        {"modelnet", &getmodelpolicy},
        {"modelnet", &setmodelpolicy},
        {"modelnet", &listmodelidentities},
        {"modelnet", &createmodelidentity},
        {"modelnet", &getmodelreciprocity},
        {"modelnet", &exportmodelcontacts},
        {"modelnet", &importmodelcontacts},
        {"modelnet", &exportmodelpeers},
        {"modelnet", &importmodelpeers},
        {"modelnet", &importmodeltrust},
        {"modelnet", &listmodelrules},
        {"modelnet", &setmodelrule},
        {"modelnet", &removemodelrule},
        {"modelnet", &joinmodelcircle},
        {"modelnet", &leavemodelcircle},
        {"modelnet", &subscribemodelcollection},
        {"modelnet", &subscribemodelpolicy},
        {"modelnet", &unsubscribemodelcollection},
        {"modelnet", &unsubscribemodelpolicy},
        {"modelnet", &delegatemodelservice},
        {"modelnet", &revokemodelservice},
        {"modelnet", &createmodelrelease},
        {"modelnet", &pledgemodelrelease},
        {"modelnet", &getmodelrelease},
        {"modelnet", &claimmodelrelease},
        {"modelnet", &refundmodelrelease},
        {"modelnet", &preparemodelfunding},
        {"modelnet", &signmodelfunding},
        {"modelnet", &submitmodelfunding},
        {"modelnet", &exportmodelrecovery},
        {"modelnet", &buildmodelhtlcclaim},
        {"modelnet", &buildmodelhtlcrefund},
        {"modelnet", &searchbounties},
        {"modelnet", &getmodelbounties},
        {"modelnet", &getbounty},
        {"modelnet", &getbountyeconomy},
        {"modelnet", &getbountyterms},
        {"modelnet", &getbountycapabilities},
        {"modelnet", &createbountydraft},
        {"modelnet", &listbountydrafts},
        {"modelnet", &getbountydraft},
        {"modelnet", &updatebountydraft},
        {"modelnet", &deletebountydraft},
        {"modelnet", &validatebountyterms},
        {"modelnet", &publishbounty},
        {"modelnet", &revisebounty},
        {"modelnet", &nominatebountyevaluator},
        {"modelnet", &acceptbountyappointment},
        {"modelnet", &listbountyevaluators},
        {"modelnet", &pledgebounty},
        {"modelnet", &withdrawbountypledge},
        {"modelnet", &freezebountyfundinground},
        {"modelnet", &getbountyfunding},
        {"modelnet", &commitbountysubmission},
        {"modelnet", &revealbountysubmission},
        {"modelnet", &getbountysubmission},
        {"modelnet", &listbountysubmissions},
        {"modelnet", &withdrawbountysubmission},
        {"modelnet", &preparebountyevaluation},
        {"modelnet", &runbountyevaluation},
        {"modelnet", &getbountyevaluationjob},
        {"modelnet", &cancelbountyevaluation},
        {"modelnet", &publishbountyevaluation},
        {"modelnet", &listbountyevaluations},
        {"modelnet", &createbountychallenge},
        {"modelnet", &listbountychallenges},
        {"modelnet", &resolvebountychallenge},
        {"modelnet", &proposebountyaward},
        {"modelnet", &approvebountyaward},
        {"modelnet", &getbountyaward},
        {"modelnet", &getbountyevents},
        {"modelnet", &watchbounty},
        {"modelnet", &unwatchbounty},
        {"modelnet", &getagentmandate},
        {"modelnet", &createagentmandate},
        {"modelnet", &revokeagentmandate},
        {"modelnet", &getagentactivity},
        {"modelnet", &reservemandate},
        {"modelnet", &createsubscriptionmandate},
        {"modelnet", &getsubscriptionmandate},
        {"modelnet", &getsubscriptionactivity},
        {"modelnet", &revokesubscriptionmandate},
        {"modelnet", &reservesubscriptionmandate},
        {"modelnet", &watchmodelpublisher},
        {"modelnet", &watchmodelcollection},
        {"modelnet", &watchmodelquery},
        {"modelnet", &watchmodel},
        {"modelnet", &listmodelwatches},
        {"modelnet", &getmodelwatch},
        {"modelnet", &unwatchmodel},
        {"modelnet", &getmodelevents},
        {"modelnet", &getmodeleventsequence},
        {"modelnet", &waitformodelevent},
        {"modelnet", &getmodelwatchactions},
        {"modelnet", &observemodelchannel},
        {"modelnet", &seedlabmodelchannel},
        {"modelnet", &getmodelchannel},
        {"modelnet", &listmodelchannels},
        {"modelnet", &getmodelprofile},
        {"modelnet", &setmodelprofile},
        {"modelnet", &setcloudstorage},
        {"modelnet", &testcloudstorage},
        {"modelnet", &getcloudstorageinfo},
        {"modelnet", &getmodelmirror},
        {"modelnet", &setmodelmirror},
        {"modelnet", &executemodelimport},
        {"modelnet", &getmodelimport},
        {"modelnet", &cancelmodelimport},
        {"modelnet", &resumemodelimport},
        {"modelnet", &publishmodelimport},
        {"modelnet", &createbtxpackage},
        {"modelnet", &inspectbtxpackage},
        {"modelnet", &verifybtxpackage},
        {"modelnet", &importbtxpackage},
        {"modelnet", &exportbtxbundle},
        {"modelnet", &exportbtxpackage},
        {"modelnet", &getbtxpackagedocument},
        {"modelnet", &getbtxpackagecapabilities},
        {"modelnet", &planbtxacquisition},
        {"modelnet", &executebtxacquisition},
        {"modelnet", &getbtxacquisition},
        {"modelnet", &cancelbtxacquisition},
        {"modelnet", &planbtxclientinstall},
        {"modelnet", &planbtxruntime},
        {"modelnet", &resolvebtxcapability},
        {"modelnet", &planbtxcapability},
        {"modelnet", &ensurebtxcapability},
        {"modelnet", &getbtxcapability},
        {"modelnet", &cancelbtxcapability},
        {"modelnet", &releasebtxcapability},
        {"modelnet", &prefetchbtxcapability},
        {"modelnet", &sleepbtxcapability},
        {"modelnet", &wakebtxcapability},
        {"modelnet", &getbtxresidency},
        {"modelnet", &inspectbtxtensormap},
        {"modelnet", &exportbtxlock},
        {"modelnet", &importbtxlock},
        {"modelnet", &planbtxcapabilityupdate},
        {"modelnet", &switchbtxcapability},
        {"modelnet", &getbtxcapabilityevents},
        {"modelnet", &getbtxruntimecapabilities},
        {"modelnet", &getbtxttctrace},
        {"modelnet", &accepthcphandoff},
        {"modelnet", &enrollhcpprovider},
        {"modelnet", &previewhcpprovider},
        {"modelnet", &sethcplocalgrant},
        {"modelnet", &gethcpreadiness},
        {"modelnet", &exporthcpstate},
        {"modelnet", &importhcpstate},
        {"modelnet", &sethcpreporting},
        {"modelnet", &hcphandle},
        {"modelnet", &pairhcpdevice},
        {"modelnet", &revokehcpdevice},
        {"modelnet", &gethcpconnectorstatus},
        {"modelnet", &applyhcpwalletless},
        {"modelnet", &hcphealth},
        {"modelnet", &planhcplocal},
        {"modelnet", &puthcplocalitysources},
        {"modelnet", &minthcphandoff},
        {"modelnet", &ensurehcplocal},
        {"modelnet", &preparemodelerasure},
        {"modelnet", &executemodelerasure},
        {"modelnet", &getmodelerasurehealth},
        {"modelnet", &repairmodel},
        {"modelnet", &gettorrentsourcestatus},
        {"modelnet", &getmodeloriginoffer},
        {"modelnet", &getmodeloriginstatus},
        {"modelnet", &querymodelsummary},
        {"modelnet", &reconcilemodelindex},
        {"modelnet", &getmodelobjectlayout},
        {"modelnet", &validatesubpiece},
        {"modelnet", &getmodelbulkstatus},
        {"modelnet", &getmodelioexecutor},
        {"modelnet", &getevaluatedtransport},
        {"modelnet", &addmodelstorage},
        {"modelnet", &inspectmodelstorage},
        {"modelnet", &testmodelstorage},
        {"modelnet", &listmodelstorage},
        {"modelnet", &getmodelcapabilities},
        {"modelnet", &getmodeltransfermetrics},
        {"modelnet", &requestmodelorigin},
        {"modelnet", &getmodeloriginhealth},
        {"modelnet", &getmodelmirrorstatus},
        {"modelnet", &removemodelstorage},
        {"modelnet", &setmodelstoragepolicy},
        {"modelnet", &setbootstrapdistributor},
        {"modelnet", &getbootstrapstatus},
        {"modelnet", &setmodeluploadpolicy},
        {"modelnet", &getmodeluploadinfo},
        {"modelnet", &planmodelstoragemigration},
        {"modelnet", &executemodelstoragemigration},
        {"modelnet", &setmodelswarmhealer},
        {"modelnet", &settorrentsourcepolicy},
        {"modelnet", &getmodelroutingstatus},
        {"modelnet", &setmodeldiscoverypolicy},
        {"modelnet", &getmodelresidency},
        {"modelnet", &getmodeldedupinfo},
        {"modelnet", &getmodellandiscovery},
        {"modelnet", &getmodelfileselection},
        {"modelnet", &getmultipartjournal},
        {"modelnet", &getsourcepolicy},
        {"modelnet", &observebountychain},
        {"modelnet", &reorgbountychain},
        {"modelnet", &exportbountyrecovery},
        {"modelnet", &importbountyrecovery},
        {"modelnet", &preparebountyfunding},
        {"modelnet", &inspectbountytransaction},
        {"modelnet", &signbountyfunding},
        {"modelnet", &submitbountyfunding},
        {"modelnet", &inspectbountyaward},
        {"modelnet", &signbountyaward},
        {"modelnet", &submitbountyaward},
        {"modelnet", &preparebountyclaim},
        {"modelnet", &signbountyclaim},
        {"modelnet", &submitbountyclaim},
        {"modelnet", &preparebountyrefund},
        {"modelnet", &signbountyrefund},
        {"modelnet", &submitbountyrefund},
    };
    for (const auto& c : commands) t.appendCommand(c.name, &c);
#else
    (void)t;
#endif
}
