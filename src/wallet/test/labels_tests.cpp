// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <key.h>
#include <key_io.h>
#include <rpc/request.h>
#include <rpc/server.h>
#include <rpc/util.h>
#include <test/util/setup_common.h>
#include <uint256.h>
#include <univalue.h>
#include <util/fs.h>
#include <wallet/context.h>
#include <wallet/rpc/wallet.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <variant>

namespace wallet {
RPCHelpMan exportlabels();
RPCHelpMan importlabels();

namespace {

JSONRPCRequest WalletRpc(WalletContext& context, UniValue params = UniValue(UniValue::VARR))
{
    JSONRPCRequest req;
    req.context = &context;
    req.m_wallet_restriction = "";
    req.params = std::move(params);
    return req;
}

void WriteFile(const fs::path& path, const std::string& contents)
{
    std::ofstream out{path, std::ios::binary | std::ios::trunc};
    BOOST_REQUIRE(out.good());
    out << contents;
    BOOST_REQUIRE(out.good());
}

std::string ReadFile(const fs::path& path)
{
    std::ifstream in{path, std::ios::binary};
    BOOST_REQUIRE(in.good());
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(labels_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(export_import_labels_bip329)
{
    bool found_export{false};
    bool found_import{false};
    for (const CRPCCommand& cmd : GetWalletRPCCommands()) {
        found_export |= cmd.name == "exportlabels";
        found_import |= cmd.name == "importlabels";
    }
    BOOST_CHECK(found_export);
    BOOST_CHECK(found_import);

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    const std::shared_ptr<CWallet> wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    wallet->LoadWallet();
    AddWallet(context, wallet);

    const CTxDestination p2mr{WitnessV2P2MR{uint256{1}}};
    const CTxDestination p2mr_b{WitnessV2P2MR{uint256{2}}};
    const std::string p2mr_ref = EncodeDestination(p2mr);
    CKey secp_key;
    secp_key.MakeNewKey(/*compressed=*/true);
    const CTxDestination secp_dest{PKHash(secp_key.GetPubKey())};
    const std::string secp_ref = EncodeDestination(secp_dest);
    {
        LOCK(wallet->cs_wallet);
        BOOST_CHECK(wallet->SetAddressBook(p2mr, "tabby", AddressPurpose::RECEIVE));
        BOOST_CHECK(wallet->SetAddressBook(p2mr_b, "mittens", AddressPurpose::SEND));
        BOOST_CHECK(wallet->SetAddressBook(secp_dest, "secp-label", AddressPurpose::SEND));
    }

    auto expect_rpc_error = [](const auto& call, const char* needle) {
        try {
            call();
            BOOST_FAIL(std::string("expected RPC error containing: ") + needle);
        } catch (const UniValue& err) {
            BOOST_CHECK_MESSAGE(err.write().find(needle) != std::string::npos, err.write());
        }
    };

    UniValue traversal_params(UniValue::VARR);
    traversal_params.push_back("../labels.jsonl");
    expect_rpc_error([&] { exportlabels().HandleRequest(WalletRpc(context, traversal_params)); }, "parent-directory");
    expect_rpc_error([&] { importlabels().HandleRequest(WalletRpc(context, traversal_params)); }, "parent-directory");

    const fs::path export_path = m_args.GetDataDirNet() / "labels.jsonl";
    UniValue export_params(UniValue::VARR);
    export_params.push_back(fs::PathToString(export_path));
    const UniValue exported = exportlabels().HandleRequest(WalletRpc(context, export_params));
    BOOST_CHECK_EQUAL(exported["labels"].getInt<int>(), 2);
    BOOST_CHECK_EQUAL(exported["filename"].get_str(), export_path.utf8string());

    const std::string jsonl = ReadFile(export_path);
    BOOST_CHECK(jsonl.find("bitcoin:") == std::string::npos);
    BOOST_CHECK(jsonl.find(secp_ref) == std::string::npos);
    bool saw_tabby{false};
    bool saw_mittens{false};
    std::string line;
    std::istringstream jsonl_stream{jsonl};
    while (std::getline(jsonl_stream, line)) {
        if (line.empty()) continue;
        UniValue rec;
        BOOST_REQUIRE(rec.read(line));
        BOOST_CHECK_EQUAL(rec["type"].get_str(), "addr");
        BOOST_CHECK(std::holds_alternative<WitnessV2P2MR>(DecodeDestination(rec["ref"].get_str())));
        if (rec["ref"].get_str() == p2mr_ref) {
            BOOST_CHECK_EQUAL(rec["label"].get_str(), "tabby");
            saw_tabby = true;
        }
        if (rec["label"].get_str() == "mittens") saw_mittens = true;
        if (rec.exists("origin")) {
            BOOST_CHECK_EQUAL(rec["origin"].get_str().front(), '[');
        }
    }
    BOOST_CHECK(saw_tabby);
    BOOST_CHECK(saw_mittens);

    expect_rpc_error([&] { exportlabels().HandleRequest(WalletRpc(context, export_params)); }, "already exists");

    const fs::path reject_path = m_args.GetDataDirNet() / "labels-reject.jsonl";
    WriteFile(reject_path,
              "{\"type\":\"addr\",\"ref\":\"bitcoin:" + p2mr_ref + "\",\"label\":\"nope\"}\n");
    UniValue reject_params(UniValue::VARR);
    reject_params.push_back(fs::PathToString(reject_path));
    expect_rpc_error([&] { importlabels().HandleRequest(WalletRpc(context, reject_params)); }, "bitcoin:");

    const fs::path secp_path = m_args.GetDataDirNet() / "labels-secp.jsonl";
    WriteFile(secp_path,
              "{\"type\":\"addr\",\"ref\":\"" + secp_ref + "\",\"label\":\"secp\"}\n");
    UniValue secp_params(UniValue::VARR);
    secp_params.push_back(fs::PathToString(secp_path));
    expect_rpc_error([&] { importlabels().HandleRequest(WalletRpc(context, secp_params)); }, "P2MR");

    const std::shared_ptr<CWallet> dest_wallet = std::make_shared<CWallet>(m_node.chain.get(), "dest", CreateMockableWalletDatabase());
    dest_wallet->LoadWallet();
    AddWallet(context, dest_wallet);

    // Fail closed: a valid P2MR line must not be applied if a later line is bitcoin:.
    const fs::path mixed_path = m_args.GetDataDirNet() / "labels-mixed.jsonl";
    WriteFile(mixed_path,
              "{\"type\":\"addr\",\"ref\":\"" + p2mr_ref + "\",\"label\":\"tabby\"}\n"
              "{\"type\":\"addr\",\"ref\":\"bitcoin:" + EncodeDestination(p2mr_b) + "\",\"label\":\"bad\"}\n");
    UniValue mixed_params(UniValue::VARR);
    mixed_params.push_back(fs::PathToString(mixed_path));
    JSONRPCRequest mixed_req = WalletRpc(context, mixed_params);
    mixed_req.URI = "/wallet/dest";
    expect_rpc_error([&] { importlabels().HandleRequest(mixed_req); }, "bitcoin:");
    {
        LOCK(dest_wallet->cs_wallet);
        BOOST_CHECK(dest_wallet->FindAddressBookEntry(p2mr) == nullptr);
    }

    const fs::path roundtrip_path = m_args.GetDataDirNet() / "labels-ok.jsonl";
    WriteFile(roundtrip_path,
              "{\"type\":\"tx\",\"ref\":\"aa\",\"label\":\"ignored\"}\n"
              "{\"type\":\"addr\",\"ref\":\"" + p2mr_ref + "\",\"label\":\"tabby\"}\n"
              "{\"type\":\"addr\",\"ref\":\"" + EncodeDestination(p2mr_b) + "\",\"label\":\"mittens\",\"origin\":\"[deadbeef/87h/0h]\"}\n");
    UniValue ok_params(UniValue::VARR);
    ok_params.push_back(fs::PathToString(roundtrip_path));
    JSONRPCRequest ok_req = WalletRpc(context, ok_params);
    ok_req.URI = "/wallet/dest";
    const UniValue imported = importlabels().HandleRequest(ok_req);
    BOOST_CHECK_EQUAL(imported["imported"].getInt<int>(), 2);
    BOOST_CHECK_EQUAL(imported["skipped"].getInt<int>(), 1);
    {
        LOCK(dest_wallet->cs_wallet);
        const auto* tabby = dest_wallet->FindAddressBookEntry(p2mr);
        BOOST_REQUIRE(tabby);
        BOOST_CHECK_EQUAL(tabby->GetLabel(), "tabby");
        const auto* mittens = dest_wallet->FindAddressBookEntry(p2mr_b);
        BOOST_REQUIRE(mittens);
        BOOST_CHECK_EQUAL(mittens->GetLabel(), "mittens");
    }

    RemoveWallet(context, dest_wallet, /*load_on_start=*/std::nullopt);
    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
