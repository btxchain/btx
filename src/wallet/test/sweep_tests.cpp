// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <chainparams.h>
#include <common/args.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/translation.h>
#include <wallet/bcp1_watchonly.h>
#include <wallet/context.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <memory>
#include <string>

namespace wallet {
RPCHelpMan sweeptoself();

namespace {

const std::string BCP1_REFUSAL_MARKER{"BCP/1 exchange watch-only"};

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

BOOST_FIXTURE_TEST_SUITE(sweep_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(sweeptoself_refuses_bcp1_watchonly)
{
    ScopedExchangeWatchOnlyArg exchange_watchonly{true};

    for (const bool external_signer : {false, true}) {
        auto wallet = MakeBcp1WatchOnlyWallet(*this, external_signer ? "sweep-bcp1-ext" : "sweep-bcp1-plain",
                                              external_signer);
        bilingual_str refuse_err;
        BOOST_REQUIRE_MESSAGE(RefusePrivateSign(*wallet, refuse_err),
                              "a BCP/1 watch-only wallet must refuse private signing");
        BOOST_CHECK(refuse_err.original.find(BCP1_REFUSAL_MARKER) != std::string::npos);

        WalletContext context;
        context.args = &m_args;
        context.chain = m_node.chain.get();
        AddWallet(context, wallet);

        bool threw{false};
        bool saw_bcp1_refusal{false};
        try {
            const UniValue result = sweeptoself().HandleRequest(WalletRpc(context));
            BOOST_TEST_MESSAGE("sweeptoself returned: " + result.write());
        } catch (const UniValue& rpc_err) {
            threw = true;
            saw_bcp1_refusal = rpc_err.write().find(BCP1_REFUSAL_MARKER) != std::string::npos;
        }
        BOOST_CHECK_MESSAGE(threw, "sweeptoself must refuse on a BCP/1 watch-only wallet");
        BOOST_CHECK_MESSAGE(saw_bcp1_refusal,
                            "sweeptoself must refuse with the BCP/1 private-sign message, not a generic key or UTXO error");

        RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
    }
}

BOOST_AUTO_TEST_CASE(sweeptoself_leftover_keys_without_bcp1)
{
    ScopedExchangeWatchOnlyArg exchange_watchonly{false};

    auto wallet = MakeBcp1WatchOnlyWallet(*this, "sweep-leftover", /*external_signer=*/false);
    BOOST_CHECK_MESSAGE(!ExchangeWatchOnlyActive(*wallet),
                        "BCP/1 must stay inactive until the node opts in with -exchange-watchonly");
    bilingual_str refuse_err;
    BOOST_CHECK(!RefusePrivateSign(*wallet, refuse_err));

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);

    bool threw{false};
    bool saw_bcp1_refusal{false};
    bool saw_disabled{false};
    try {
        const UniValue result = sweeptoself().HandleRequest(WalletRpc(context));
        BOOST_TEST_MESSAGE("sweeptoself returned: " + result.write());
    } catch (const UniValue& rpc_err) {
        threw = true;
        const std::string err = rpc_err.write();
        saw_bcp1_refusal = err.find(BCP1_REFUSAL_MARKER) != std::string::npos;
        saw_disabled = err.find("Private keys are disabled") != std::string::npos;
    }
    BOOST_CHECK_MESSAGE(threw, "sweeptoself must not auto-spend leftover keys on a disable_private_keys wallet");
    BOOST_CHECK_MESSAGE(!saw_bcp1_refusal,
                        "sweeptoself must not report the BCP/1 refusal when -exchange-watchonly is off");
    BOOST_CHECK_MESSAGE(saw_disabled, "sweeptoself must close leftover-key spend when private keys are disabled");

    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
