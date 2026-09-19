// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// PR 157 review regression coverage for the BCP/1 custody profile.
//
// 1. walletprocesspsbt(sign=true) keeps refusing in-process private signing on
//    a BCP/1 watch-only wallet, but must not apply that refusal to a
//    WALLET_FLAG_EXTERNAL_SIGNER wallet, which has to reach FillPSBT so the
//    -signer adapter can sign. Leftover keys on disable_private_keys wallets
//    without EXTERNAL_SIGNER must not FillPSBT(sign=true) even when BCP/1 is off.
// 2. dumpprivkey / signrawtransactionwithwallet / signmessage keep refusing on
//    both wallet shapes: they can only ever use wallet-resident private material.
// 3. getexchangereadiness() must not advertise `ready` for an empty watch-only
//    descriptor wallet (descriptors + !IBD is not enough). ready is
//    descriptors_ok && watchonly_ok && synced_ok && (deposits_ok || signer_ok)
//    && !pkcs11_live && !kmip_live && !https_live. PKCS#11/KMIP/HTTPS stay false.
// 4. deriveexchangeaddress() must reject an index that does not fit uint32 and
//    must not resolve another account's pool entry.
// 5. BCP/1 refusal is opt-in: -exchange-watchonly is required. A descriptor
//    disable_private_keys wallet (hardware / external signer) on a node that
//    never set the arg must not be refused, and the startup LoadWallets() path
//    must run the same EnsureExchangeWatchOnly gate as the wallet RPCs.

#include <bitcoin-build-config.h> // IWYU pragma: keep

#include <addresstype.h>
#include <chainparams.h>
#include <common/args.h>
#include <core_io.h>
#include <key_io.h>
#include <pq/pq_keyderivation.h>
#include <pqkey.h>
#include <psbt.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <script/pqm.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/bcp1_package.h>
#include <wallet/bcp1_watchonly.h>
#include <wallet/context.h>
#include <wallet/rpc/bcp1.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <limits>
#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace wallet {
RPCHelpMan walletprocesspsbt();
RPCHelpMan dumpprivkey();
RPCHelpMan signrawtransactionwithwallet();
RPCHelpMan signmessage();

namespace {

//! Marker of PrivateSignRefusedMessage() in wallet/bcp1_watchonly.cpp.
const std::string BCP1_REFUSAL_MARKER{"BCP/1 exchange watch-only"};

uint32_t CoinTypeForParams()
{
    return Params().IsTestChain() ? 1 : 0;
}

std::shared_ptr<CWallet> MakeBcp1WatchOnlyWallet(const WalletTestingSetup& setup, const std::string& name, bool external_signer)
{
    auto wallet = std::make_shared<CWallet>(setup.m_node.chain.get(), name, CreateMockableWalletDatabase());
    {
        LOCK(wallet->cs_wallet);
        wallet->SetMinVersion(FEATURE_LATEST);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
        if (external_signer) wallet->SetWalletFlag(WALLET_FLAG_EXTERNAL_SIGNER);
        wallet->SetLastBlockProcessed(0, Params().GenesisBlock().GetHash());
    }
    return wallet;
}

JSONRPCRequest WalletRpc(WalletContext& context, UniValue params = UniValue(UniValue::VARR))
{
    JSONRPCRequest req;
    req.context = &context;
    req.m_wallet_restriction = "";
    req.params = std::move(params);
    return req;
}

CMutableTransaction MakeUnsignedSpendTx()
{
    const auto prev_hash = uint256::FromHex("0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0");
    CScript spk;
    spk << OP_FALSE;
    CMutableTransaction mtx;
    // uint256 is the raw blob; Txid has no implicit conversion from it.
    mtx.vin.emplace_back(COutPoint{Txid::FromUint256(prev_hash.value_or(uint256{})), /*n=*/0});
    mtx.vout.emplace_back(/*nValue=*/25000000, spk);
    return mtx;
}

std::string UnsignedPsbtBase64()
{
    const CMutableTransaction mtx = MakeUnsignedSpendTx();
    PartiallySignedTransaction psbtx(mtx);
    psbtx.inputs.at(0).witness_utxo = CTxOut(25000000, mtx.vout.at(0).scriptPubKey);
    DataStream ss{};
    ss << psbtx;
    return EncodeBase64(ss.str());
}

struct ReviewDeposit
{
    CPQKey key;
    std::string address;

    bool IsValid() const { return key.IsValid() && !address.empty(); }
};

ReviewDeposit MakeReviewDeposit(uint32_t branch = bcp1::BRANCH_DEPOSIT)
{
    std::array<unsigned char, 32> seed{};
    for (size_t i = 0; i < seed.size(); ++i) seed[i] = static_cast<unsigned char>(i + 1);

    ReviewDeposit deposit;
    auto key = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::ML_DSA_44, CoinTypeForParams(),
                                        /*account=*/0, branch, /*index=*/0);
    if (!key) return deposit;
    deposit.key = *key;
    const auto leaf = BuildP2MRScript(PQAlgorithm::ML_DSA_44, deposit.key.GetPubKey());
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf)});
    deposit.address = EncodeDestination(WitnessV2P2MR{root});
    return deposit;
}

bool AddressFromResult(const UniValue& result, std::string& address)
{
    if (!result.isObject() || !result.exists("address") || !result["address"].isStr()) return false;
    address = result["address"].get_str();
    return true;
}

//! PR 157 publishes the readiness predicate report as "ready_capabilities";
//! "capabilities" is accepted as a fallback name for the same object.
const UniValue* ReadinessCapabilities(const UniValue& readiness)
{
    for (const char* name : {"ready_capabilities", "capabilities"}) {
        if (readiness.exists(name) && readiness[name].isObject()) return &readiness[name];
    }
    return nullptr;
}

//! Set -exchange-watchonly on the process-global arg manager for a scope.
//! BasicTestingSetup does not reset forced settings between cases, so a case
//! must not assume the arg is unset by whatever ran before it.
class ScopedExchangeWatchOnlyArg
{
public:
    explicit ScopedExchangeWatchOnlyArg(bool enabled)
        : m_previous{gArgs.GetBoolArg(EXCHANGE_WATCHONLY_ARG, false)}
    {
        gArgs.ForceSetArg(EXCHANGE_WATCHONLY_ARG, enabled ? "1" : "0");
    }
    ~ScopedExchangeWatchOnlyArg()
    {
        gArgs.ForceSetArg(EXCHANGE_WATCHONLY_ARG, m_previous ? "1" : "0");
    }
    ScopedExchangeWatchOnlyArg(const ScopedExchangeWatchOnlyArg&) = delete;
    ScopedExchangeWatchOnlyArg& operator=(const ScopedExchangeWatchOnlyArg&) = delete;

private:
    const bool m_previous;
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(bcp1_review_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(walletprocesspsbt_refuses_inprocess_private_sign)
{
    // BCP/1 refusal is opt-in: this case models a node running -exchange-watchonly.
    ScopedExchangeWatchOnlyArg exchange_watchonly{true};

    auto wallet = MakeBcp1WatchOnlyWallet(*this, "bcp1-review-plain", /*external_signer=*/false);

    bilingual_str refuse_err;
    BOOST_REQUIRE_MESSAGE(RefusePrivateSign(*wallet, refuse_err), "a BCP/1 watch-only wallet must refuse private signing");
    BOOST_CHECK(refuse_err.original.find(BCP1_REFUSAL_MARKER) != std::string::npos);
    BOOST_CHECK(!CanDelegateExternalPsbtSign(*wallet));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);

    UniValue params(UniValue::VARR);
    params.push_back(UnsignedPsbtBase64());
    UniValue options(UniValue::VOBJ);
    options.pushKV("sign", true);
    params.push_back(options);
    JSONRPCRequest req = WalletRpc(context, params);

    bool refused{false};
    try {
        const UniValue result = walletprocesspsbt().HandleRequest(req);
        BOOST_TEST_MESSAGE("walletprocesspsbt returned: " + result.write());
    } catch (const UniValue& rpc_err) {
        refused = rpc_err.write().find(BCP1_REFUSAL_MARKER) != std::string::npos;
    }
    BOOST_CHECK_MESSAGE(refused,
                        "walletprocesspsbt(sign=true) must refuse in-process private signing on a BCP/1 watch-only wallet");

    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_CASE(walletprocesspsbt_delegates_for_external_signer)
{
    ScopedExchangeWatchOnlyArg exchange_watchonly{true};

    auto wallet = MakeBcp1WatchOnlyWallet(*this, "bcp1-review-ext", /*external_signer=*/true);

    bilingual_str refuse_err;
    BOOST_CHECK_MESSAGE(RefusePrivateSign(*wallet, refuse_err),
                        "external-signer wallets still disable wallet-resident private keys");
    BOOST_CHECK(!refuse_err.original.empty());
    BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
    BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_EXTERNAL_SIGNER));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);

    UniValue params(UniValue::VARR);
    params.push_back(UnsignedPsbtBase64());
    UniValue options(UniValue::VOBJ);
    options.pushKV("sign", true);
    params.push_back(options);
    JSONRPCRequest req = WalletRpc(context, params);

    bool threw{false};
    bool saw_bcp1_refusal{false};
    UniValue result;
    try {
        result = walletprocesspsbt().HandleRequest(req);
    } catch (const UniValue& rpc_err) {
        threw = true;
        saw_bcp1_refusal = rpc_err.write().find(BCP1_REFUSAL_MARKER) != std::string::npos;
    }

    const bool can_delegate = CanDelegateExternalPsbtSign(*wallet);
#ifdef ENABLE_EXTERNAL_SIGNER
    BOOST_REQUIRE_MESSAGE(can_delegate,
                          "external-signer support is compiled in; an EXTERNAL_SIGNER wallet must be able to delegate");
#endif
    if (can_delegate) {
        BOOST_CHECK_MESSAGE(!saw_bcp1_refusal,
                            "walletprocesspsbt(sign=true) must reach FillPSBT for an EXTERNAL_SIGNER wallet instead of "
                            "throwing the BCP/1 private-sign refusal");
        if (!threw) {
            BOOST_REQUIRE(result.isObject());
            BOOST_REQUIRE(result.exists("complete"));
            BOOST_CHECK_MESSAGE(!result["complete"].get_bool(),
                                "no external signer device is reachable in unit tests, so the PSBT must stay incomplete");
        }
    } else {
        BOOST_TEST_MESSAGE("external-signer delegation is unavailable in this build; the private-sign refusal is expected");
        BOOST_CHECK(threw);
    }

    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_CASE(walletprocesspsbt_leftover_keys_without_external_signer)
{
    // Leftover-key close is independent of -exchange-watchonly: a
    // disable_private_keys wallet without EXTERNAL_SIGNER must not
    // FillPSBT(sign=true). sign=false stays the updater path.
    ScopedExchangeWatchOnlyArg exchange_watchonly{false};

    auto wallet = MakeBcp1WatchOnlyWallet(*this, "bcp1-review-leftover", /*external_signer=*/false);
    BOOST_CHECK(!CanDelegateExternalPsbtSign(*wallet));
    BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));

    bilingual_str refuse_err;
    BOOST_CHECK(!RefusePrivateSign(*wallet, refuse_err));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);

    {
        UniValue params(UniValue::VARR);
        params.push_back(UnsignedPsbtBase64());
        UniValue options(UniValue::VOBJ);
        options.pushKV("sign", true);
        params.push_back(options);
        JSONRPCRequest req = WalletRpc(context, params);

        bool threw{false};
        bool saw_bcp1_refusal{false};
        bool saw_disabled{false};
        try {
            const UniValue result = walletprocesspsbt().HandleRequest(req);
            BOOST_TEST_MESSAGE("walletprocesspsbt(sign=true) returned: " + result.write());
        } catch (const UniValue& rpc_err) {
            threw = true;
            const std::string err = rpc_err.write();
            saw_bcp1_refusal = err.find(BCP1_REFUSAL_MARKER) != std::string::npos;
            saw_disabled = err.find("Error: Private keys are disabled for this wallet") != std::string::npos;
        }
        BOOST_CHECK_MESSAGE(threw, "walletprocesspsbt(sign=true) must not FillPSBT with leftover keys");
        BOOST_CHECK_MESSAGE(!saw_bcp1_refusal, "leftover-key close must not use the BCP/1 message when the node did not opt in");
        BOOST_CHECK_MESSAGE(saw_disabled, "leftover-key close must be the disable-private-keys error");
    }

    {
        UniValue params(UniValue::VARR);
        params.push_back(UnsignedPsbtBase64());
        UniValue options(UniValue::VOBJ);
        options.pushKV("sign", false);
        params.push_back(options);
        JSONRPCRequest req = WalletRpc(context, params);

        bool threw{false};
        bool saw_bcp1_refusal{false};
        bool saw_disabled{false};
        UniValue result;
        try {
            result = walletprocesspsbt().HandleRequest(req);
        } catch (const UniValue& rpc_err) {
            threw = true;
            const std::string err = rpc_err.write();
            saw_bcp1_refusal = err.find(BCP1_REFUSAL_MARKER) != std::string::npos;
            saw_disabled = err.find("Error: Private keys are disabled for this wallet") != std::string::npos;
        }
        BOOST_CHECK_MESSAGE(!saw_bcp1_refusal, "walletprocesspsbt(sign=false) must remain available as the updater path");
        BOOST_CHECK_MESSAGE(!saw_disabled, "walletprocesspsbt(sign=false) must not hit the leftover-key close");
        if (!threw) {
            BOOST_REQUIRE(result.isObject());
            BOOST_REQUIRE(result.exists("complete"));
            BOOST_CHECK(!result["complete"].get_bool());
        }
    }

    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_CASE(dumpprivkey_and_wallet_sign_still_refuse)
{
    ScopedExchangeWatchOnlyArg exchange_watchonly{true};

    const ReviewDeposit deposit = MakeReviewDeposit();
    BOOST_REQUIRE_MESSAGE(deposit.IsValid(), "could not derive the BCP/1 review deposit key");
    const std::string unsigned_hex = EncodeHexTx(CTransaction{MakeUnsignedSpendTx()});

    for (const bool external_signer : {false, true}) {
        auto wallet = MakeBcp1WatchOnlyWallet(*this, external_signer ? "bcp1-review-refuse-ext" : "bcp1-review-refuse-plain",
                                              external_signer);
        WalletContext context;
        context.args = &m_args;
        context.chain = m_node.chain.get();
        AddWallet(context, wallet);

        {
            UniValue params(UniValue::VARR);
            params.push_back(deposit.address);
            JSONRPCRequest req = WalletRpc(context, params);
            bool threw{false};
            bool saw_bcp1_refusal{false};
            try {
                const UniValue dumped = dumpprivkey().HandleRequest(req);
                BOOST_TEST_MESSAGE("dumpprivkey returned: " + dumped.write());
            } catch (const UniValue& rpc_err) {
                threw = true;
                saw_bcp1_refusal = rpc_err.write().find(BCP1_REFUSAL_MARKER) != std::string::npos;
            }
            BOOST_CHECK_MESSAGE(threw, "dumpprivkey must refuse on a BCP/1 watch-only wallet");
            if (!external_signer) {
                BOOST_CHECK_MESSAGE(saw_bcp1_refusal, "dumpprivkey must refuse with the BCP/1 private-sign message");
            }
        }

        {
            UniValue params(UniValue::VARR);
            params.push_back(unsigned_hex);
            params.push_back(UniValue::VNULL);
            JSONRPCRequest req = WalletRpc(context, params);
            bool completed{false};
            bool threw{false};
            try {
                const UniValue result = signrawtransactionwithwallet().HandleRequest(req);
                completed = result.exists("complete") && result["complete"].isBool() && result["complete"].get_bool();
            } catch (const UniValue&) {
                threw = true;
            }
            BOOST_CHECK_MESSAGE(!completed, "signrawtransactionwithwallet must not complete on a BCP/1 watch-only wallet");
            if (!external_signer) {
                BOOST_CHECK_MESSAGE(threw, "signrawtransactionwithwallet must refuse with the BCP/1 private-sign message");
            }
        }

        {
            UniValue params(UniValue::VARR);
            params.push_back(deposit.address);
            params.push_back("bcp1 watch-only must not sign messages in-process");
            JSONRPCRequest req = WalletRpc(context, params);
            bool threw{false};
            bool saw_bcp1_refusal{false};
            try {
                const UniValue signed_msg = signmessage().HandleRequest(req);
                BOOST_TEST_MESSAGE("signmessage returned: " + signed_msg.write());
            } catch (const UniValue& rpc_err) {
                threw = true;
                saw_bcp1_refusal = rpc_err.write().find(BCP1_REFUSAL_MARKER) != std::string::npos;
            }
            BOOST_CHECK_MESSAGE(threw, "signmessage must refuse on a BCP/1 watch-only wallet");
            BOOST_CHECK_MESSAGE(saw_bcp1_refusal,
                                "signmessage must refuse with the BCP/1 private-sign message, not a generic key error");
        }

        RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
    }
}

BOOST_AUTO_TEST_CASE(exchange_watchonly_refusal_requires_node_opt_in)
{
    // #159: without -exchange-watchonly, a descriptor disable_private_keys
    // wallet is a hardware / external-signer wallet, not BCP/1 custody. It must
    // not be treated as exchange watch-only and must not hit RefusePrivateSign.
    ScopedExchangeWatchOnlyArg exchange_watchonly{false};

    const std::string unsigned_hex = EncodeHexTx(CTransaction{MakeUnsignedSpendTx()});

    for (const bool external_signer : {false, true}) {
        auto wallet = MakeBcp1WatchOnlyWallet(*this, external_signer ? "bcp1-review-nooptin-ext" : "bcp1-review-nooptin-plain",
                                              external_signer);
        BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_DESCRIPTORS));
        BOOST_CHECK(wallet->IsWalletFlagSet(WALLET_FLAG_DISABLE_PRIVATE_KEYS));
        BOOST_CHECK_MESSAGE(!ExchangeWatchOnlyActive(*wallet),
                            "BCP/1 must stay inactive until the node opts in with -exchange-watchonly");

        bilingual_str refuse_err;
        BOOST_CHECK_MESSAGE(!RefusePrivateSign(*wallet, refuse_err),
                            "a disable_private_keys descriptor wallet without -exchange-watchonly must not be refused");
        BOOST_CHECK(refuse_err.empty());

        WalletContext context;
        context.args = &m_args;
        context.chain = m_node.chain.get();
        AddWallet(context, wallet);

        // signrawtransactionwithwallet may still fail for other reasons (there
        // is no key material), but it must not raise the BCP/1 message.
        {
            UniValue params(UniValue::VARR);
            params.push_back(unsigned_hex);
            params.push_back(UniValue::VNULL);
            JSONRPCRequest req = WalletRpc(context, params);
            bool saw_bcp1_refusal{false};
            try {
                const UniValue result = signrawtransactionwithwallet().HandleRequest(req);
                BOOST_TEST_MESSAGE("signrawtransactionwithwallet returned: " + result.write());
            } catch (const UniValue& rpc_err) {
                saw_bcp1_refusal = rpc_err.write().find(BCP1_REFUSAL_MARKER) != std::string::npos;
            }
            BOOST_CHECK_MESSAGE(!saw_bcp1_refusal,
                                "signrawtransactionwithwallet must not report the BCP/1 refusal when -exchange-watchonly is off");
        }

        // signmessage is in-process only. Without BCP/1 it still must not use
        // leftover keys on a disable_private_keys wallet.
        {
            UniValue params(UniValue::VARR);
            params.push_back("bcrt1qinvalid-placeholder");
            params.push_back("leftover keys must not sign messages");
            JSONRPCRequest req = WalletRpc(context, params);
            bool threw{false};
            bool saw_bcp1_refusal{false};
            bool saw_disabled{false};
            try {
                const UniValue signed_msg = signmessage().HandleRequest(req);
                BOOST_TEST_MESSAGE("signmessage returned: " + signed_msg.write());
            } catch (const UniValue& rpc_err) {
                threw = true;
                const std::string err = rpc_err.write();
                saw_bcp1_refusal = err.find(BCP1_REFUSAL_MARKER) != std::string::npos;
                saw_disabled = err.find("Error: Private keys are disabled for this wallet") != std::string::npos;
            }
            BOOST_CHECK_MESSAGE(threw, "signmessage must refuse leftover keys on a disable_private_keys wallet");
            BOOST_CHECK_MESSAGE(!saw_bcp1_refusal,
                                "signmessage must not report the BCP/1 refusal when -exchange-watchonly is off");
            BOOST_CHECK_MESSAGE(saw_disabled, "signmessage leftover-key close must be the disable-private-keys error");
        }

        RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
    }
}

BOOST_AUTO_TEST_CASE(load_path_gate_refuses_keyed_wallet_under_exchange_watchonly)
{
    // #164: LoadWallets() now runs the same EnsureExchangeWatchOnly gate as the
    // loadwallet / createwallet RPCs, so a wallet with private keys must not be
    // left loaded on an -exchange-watchonly node.
    m_args.ForceSetArg(EXCHANGE_WATCHONLY_ARG, "1");

    auto keyed = std::make_shared<CWallet>(m_node.chain.get(), "bcp1-review-keyed", CreateMockableWalletDatabase());
    {
        LOCK(keyed->cs_wallet);
        keyed->SetMinVersion(FEATURE_LATEST);
        keyed->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    }

    bilingual_str keyed_err;
    BOOST_CHECK_MESSAGE(!EnsureExchangeWatchOnly(*keyed, m_args, keyed_err),
                        "a keyed wallet must be refused on an -exchange-watchonly node");
    BOOST_CHECK(!keyed_err.original.empty());

    // The same gate is a no-op when the node did not opt in.
    m_args.ForceSetArg(EXCHANGE_WATCHONLY_ARG, "0");
    bilingual_str no_opt_in_err;
    BOOST_CHECK(EnsureExchangeWatchOnly(*keyed, m_args, no_opt_in_err));
    BOOST_CHECK(no_opt_in_err.empty());
}

BOOST_AUTO_TEST_CASE(getexchangereadiness_empty_watchonly_is_not_ready)
{
    ScopedExchangeWatchOnlyArg exchange_watchonly{true};

    auto wallet = MakeBcp1WatchOnlyWallet(*this, "bcp1-review-ready", /*external_signer=*/false);

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);

    JSONRPCRequest req = WalletRpc(context);
    const UniValue result = getexchangereadiness().HandleRequest(req);
    BOOST_REQUIRE(result.isObject());

    BOOST_CHECK_EQUAL(result["watch_only"].get_bool(), true);
    BOOST_CHECK_EQUAL(result["ready"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["pkcs11_live"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["kmip_live"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["https_live"].get_bool(), false);
    const UniValue* caps = ReadinessCapabilities(result);
    BOOST_REQUIRE_MESSAGE(caps != nullptr, "getexchangereadiness must publish a capabilities object");
    BOOST_REQUIRE(caps->exists("deposit_pool"));
    BOOST_CHECK_EQUAL((*caps)["deposit_pool"].get_bool(), false);
    BOOST_REQUIRE(caps->exists("signer_available"));
    BOOST_CHECK_EQUAL((*caps)["signer_available"].get_bool(), false);
    BOOST_REQUIRE(caps->exists("descriptors"));
    BOOST_CHECK_EQUAL((*caps)["descriptors"].get_bool(), true);
    BOOST_REQUIRE(caps->exists("disable_private_keys"));
    BOOST_CHECK_EQUAL((*caps)["disable_private_keys"].get_bool(), true);
    BOOST_REQUIRE(caps->exists("descriptors_ok"));
    BOOST_CHECK_EQUAL((*caps)["descriptors_ok"].get_bool(), true);
    BOOST_REQUIRE(caps->exists("watchonly_ok"));
    BOOST_CHECK_EQUAL((*caps)["watchonly_ok"].get_bool(), true);
    BOOST_REQUIRE(caps->exists("deposits_ok"));
    BOOST_CHECK_EQUAL((*caps)["deposits_ok"].get_bool(), false);
    BOOST_REQUIRE(caps->exists("signer_ok"));
    BOOST_CHECK_EQUAL((*caps)["signer_ok"].get_bool(), false);
    BOOST_CHECK_EQUAL((*caps)["pkcs11_live"].get_bool(), false);
    BOOST_CHECK_EQUAL((*caps)["kmip_live"].get_bool(), false);
    BOOST_CHECK_EQUAL((*caps)["https_live"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["automatic_spend_atoms"].getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(result["can_sign_in_process"].get_bool(), false);

    const Bcp1Readiness eval = EvaluateBcp1Readiness(*wallet, gArgs);
    BOOST_CHECK(eval.descriptors_ok);
    BOOST_CHECK(eval.watchonly_ok);
    BOOST_CHECK(!eval.deposits_ok);
    BOOST_CHECK(!eval.signer_ok);
    BOOST_CHECK(!eval.pkcs11_live);
    BOOST_CHECK(!eval.kmip_live);
    BOOST_CHECK(!eval.Ready());

    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_CASE(getexchangereadiness_keyed_descriptor_is_not_ready)
{
    ScopedExchangeWatchOnlyArg exchange_watchonly{false};

    auto wallet = std::make_shared<CWallet>(m_node.chain.get(), "bcp1-review-keyed-ready", CreateMockableWalletDatabase());
    {
        LOCK(wallet->cs_wallet);
        wallet->SetMinVersion(FEATURE_LATEST);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->SetLastBlockProcessed(0, Params().GenesisBlock().GetHash());
    }

    const Bcp1Readiness eval = EvaluateBcp1Readiness(*wallet, gArgs);
    BOOST_CHECK(eval.descriptors_ok);
    BOOST_CHECK(!eval.watchonly_ok);
    BOOST_CHECK(!eval.deposits_ok);
    BOOST_CHECK(!eval.signer_ok);
    BOOST_CHECK(!eval.Ready());

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);
    JSONRPCRequest req = WalletRpc(context);
    const UniValue result = getexchangereadiness().HandleRequest(req);
    BOOST_REQUIRE(result.isObject());
    BOOST_CHECK_EQUAL(result["ready"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["watchonly_ok"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["can_sign_in_process"].get_bool(), true);
    BOOST_CHECK_EQUAL(result["pkcs11_live"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["kmip_live"].get_bool(), false);
    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_CASE(getexchangereadiness_setlabel_p2mr_is_not_deposit_pool)
{
    ScopedExchangeWatchOnlyArg exchange_watchonly{true};

    const ReviewDeposit deposit = MakeReviewDeposit();
    BOOST_REQUIRE_MESSAGE(deposit.IsValid(), "could not derive the BCP/1 review deposit key");
    const CTxDestination dest = DecodeDestination(deposit.address);
    BOOST_REQUIRE(std::holds_alternative<WitnessV2P2MR>(dest));

    auto wallet = MakeBcp1WatchOnlyWallet(*this, "bcp1-review-ready-setlabel", /*external_signer=*/false);
    {
        LOCK(wallet->cs_wallet);
        BOOST_REQUIRE(wallet->SetAddressBook(dest, "customer-deposit", AddressPurpose::RECEIVE));
    }
    BOOST_CHECK(!WalletHasDepositMaterial(*wallet));
    const Bcp1Readiness eval = EvaluateBcp1Readiness(*wallet, gArgs);
    BOOST_CHECK(!eval.deposits_ok);
    BOOST_CHECK(!eval.Ready());
}

BOOST_AUTO_TEST_CASE(getexchangereadiness_pool_sets_deposits_ok)
{
    ScopedExchangeWatchOnlyArg exchange_watchonly{true};

    const ReviewDeposit deposit = MakeReviewDeposit();
    BOOST_REQUIRE_MESSAGE(deposit.IsValid(), "could not derive the BCP/1 review deposit key");

    auto wallet = MakeBcp1WatchOnlyWallet(*this, "bcp1-review-ready-pool", /*external_signer=*/false);
    UniValue entries(UniValue::VARR);
    UniValue item(UniValue::VOBJ);
    item.pushKV("index", 0);
    item.pushKV("address", deposit.address);
    item.pushKV("pubkey", HexStr(deposit.key.GetPubKey()));
    entries.push_back(item);
    bilingual_str import_err;
    UniValue details;
    BOOST_REQUIRE_MESSAGE(ImportDepositPool(*wallet, entries, import_err, details), import_err.original);

    const Bcp1Readiness eval = EvaluateBcp1Readiness(*wallet, gArgs);
    BOOST_CHECK(eval.descriptors_ok);
    BOOST_CHECK(eval.watchonly_ok);
    BOOST_CHECK(eval.deposits_ok);
    BOOST_CHECK(!eval.signer_ok);
    BOOST_CHECK(!eval.pkcs11_live);
    BOOST_CHECK(!eval.kmip_live);
    BOOST_CHECK_EQUAL(eval.Ready(), eval.synced_ok);

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);
    JSONRPCRequest req = WalletRpc(context);
    const UniValue result = getexchangereadiness().HandleRequest(req);
    BOOST_REQUIRE(result.isObject());
    BOOST_CHECK_EQUAL(result["deposits_ok"].get_bool(), true);
    BOOST_CHECK_EQUAL(result["signer_ok"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["pkcs11_live"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["kmip_live"].get_bool(), false);
    BOOST_CHECK_EQUAL(result["ready"].get_bool(), result["synced_ok"].get_bool());
    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_CASE(deriveexchangeaddress_index_and_account_guards)
{
    const ReviewDeposit deposit = MakeReviewDeposit();
    const ReviewDeposit change = MakeReviewDeposit(bcp1::BRANCH_CHANGE);
    BOOST_REQUIRE_MESSAGE(deposit.IsValid(), "could not derive the BCP/1 review deposit key");
    BOOST_REQUIRE_MESSAGE(change.IsValid(), "could not derive the BCP/1 review change key");
    BOOST_REQUIRE(deposit.address != change.address);

    auto wallet = MakeBcp1WatchOnlyWallet(*this, "bcp1-review-pool", /*external_signer=*/false);
    UniValue entries(UniValue::VARR);
    UniValue item(UniValue::VOBJ);
    item.pushKV("index", 0);
    item.pushKV("address", deposit.address);
    item.pushKV("pubkey", HexStr(deposit.key.GetPubKey()));
    entries.push_back(item);
    UniValue change_item(UniValue::VOBJ);
    change_item.pushKV("index", 0);
    change_item.pushKV("branch", 1);
    change_item.pushKV("address", change.address);
    change_item.pushKV("pubkey", HexStr(change.key.GetPubKey()));
    entries.push_back(change_item);
    bilingual_str import_err;
    UniValue details;
    BOOST_REQUIRE_MESSAGE(ImportDepositPool(*wallet, entries, import_err, details), import_err.original);

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);

    // Account 0 / index 0 still resolves from the imported pool.
    {
        UniValue params(UniValue::VARR);
        params.push_back(0);
        JSONRPCRequest req = WalletRpc(context, params);
        bool resolved{false};
        UniValue result;
        try {
            result = deriveexchangeaddress().HandleRequest(req);
            resolved = true;
        } catch (const UniValue& rpc_err) {
            BOOST_TEST_MESSAGE(rpc_err.write());
        }
        BOOST_REQUIRE_MESSAGE(resolved, "deriveexchangeaddress(0) must resolve the imported pool entry");
        BOOST_REQUIRE(result.isObject());
        BOOST_CHECK_EQUAL(result["address"].get_str(), deposit.address);
        BOOST_CHECK_EQUAL(result["source"].get_str(), "pool");
        BOOST_CHECK_EQUAL(result["account"].getInt<int64_t>(), 0);
    }

    // A branch-1 entry is labelled with its branch, so it resolves as change
    // rather than as the deposit at the same index.
    {
        UniValue params(UniValue::VARR);
        params.push_back(0);
        UniValue options(UniValue::VOBJ);
        options.pushKV("branch", 1);
        params.push_back(options);
        JSONRPCRequest req = WalletRpc(context, params);
        bool resolved{false};
        UniValue result;
        try {
            result = deriveexchangeaddress().HandleRequest(req);
            resolved = true;
        } catch (const UniValue& rpc_err) {
            BOOST_TEST_MESSAGE(rpc_err.write());
        }
        BOOST_REQUIRE_MESSAGE(resolved, "deriveexchangeaddress(branch=1) must resolve the imported change entry");
        BOOST_REQUIRE(result.isObject());
        BOOST_CHECK_EQUAL(result["address"].get_str(), change.address);
        BOOST_CHECK_EQUAL(result["source"].get_str(), "pool");
        BOOST_CHECK_EQUAL(result["branch"].getInt<int64_t>(), 1);
    }

    // An account-0 pool entry must not be returned for account 1.
    {
        UniValue params(UniValue::VARR);
        params.push_back(0);
        UniValue options(UniValue::VOBJ);
        options.pushKV("account", 1);
        params.push_back(options);
        JSONRPCRequest req = WalletRpc(context, params);
        std::string address;
        bool returned_pool_address{false};
        try {
            const UniValue result = deriveexchangeaddress().HandleRequest(req);
            returned_pool_address = AddressFromResult(result, address) && address == deposit.address;
        } catch (const UniValue&) {
            // Fail closed: no pool entry for that account.
        }
        BOOST_CHECK_MESSAGE(!returned_pool_address,
                            "deriveexchangeaddress(account=1) must not resolve an account-0 pool entry");
    }

    // 2^32 does not fit uint32 and must not wrap around to index 0.
    {
        UniValue params(UniValue::VARR);
        params.push_back(UniValue(static_cast<int64_t>(1) << 32));
        JSONRPCRequest req = WalletRpc(context, params);
        std::string address;
        bool threw{false};
        bool returned_pool_address{false};
        try {
            const UniValue result = deriveexchangeaddress().HandleRequest(req);
            returned_pool_address = AddressFromResult(result, address) && address == deposit.address;
        } catch (const UniValue&) {
            threw = true;
        }
        BOOST_CHECK_MESSAGE(threw, "deriveexchangeaddress must reject an index above the uint32 range");
        BOOST_CHECK_MESSAGE(!returned_pool_address, "an oversized index must not wrap around to index 0");
    }

    // The largest valid uint32 index is in range; it simply has no pool entry.
    {
        UniValue params(UniValue::VARR);
        params.push_back(UniValue(static_cast<int64_t>(std::numeric_limits<uint32_t>::max())));
        JSONRPCRequest req = WalletRpc(context, params);
        bool threw{false};
        try {
            const UniValue result = deriveexchangeaddress().HandleRequest(req);
            BOOST_TEST_MESSAGE("deriveexchangeaddress(uint32 max) returned: " + result.write());
        } catch (const UniValue&) {
            threw = true;
        }
        BOOST_CHECK_MESSAGE(threw, "an unimported index must not produce an address");
    }

    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
