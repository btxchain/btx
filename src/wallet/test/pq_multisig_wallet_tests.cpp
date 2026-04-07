// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <addresstype.h>
#include <chainparams.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <streams.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <wallet/spend.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <map>

namespace wallet {
namespace {

static constexpr int64_t P2MR_TEST_RANGE_END{2};

std::array<unsigned char, 32> MakePQSeed(unsigned char seed)
{
    std::array<unsigned char, 32> out{};
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<unsigned char>(seed + i);
    }
    return out;
}

std::string MakeP2MRKeyPathExprWithBranch(const std::array<unsigned char, 32>& seed, uint32_t branch, bool internal)
{
    std::string expr = "pqhd(" + HexStr(seed);
    expr += Params().IsTestChain() ? "/1h" : "/0h";
    expr += strprintf("/%uh", branch);
    expr += internal ? "/1" : "/0";
    expr += "/*)";
    return expr;
}

std::shared_ptr<CWallet> CreateP2MRDescriptorWalletFromStrings(const WalletTestingSetup& setup,
                                                               const std::string& receive_desc_str,
                                                               const std::string& change_desc_str,
                                                               const CExtKey* master_key = nullptr)
{
    auto wallet = std::make_shared<CWallet>(setup.m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet->m_keypool_size = P2MR_TEST_RANGE_END;

    FlatSigningProvider receive_keys;
    if (master_key) receive_keys.AddMasterKey(*master_key);
    std::string receive_error;
    auto receive_parsed = Parse(receive_desc_str, receive_keys, receive_error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!receive_parsed.empty(), "receive descriptor parse failed: " + receive_error);
    BOOST_REQUIRE_EQUAL(receive_parsed.size(), 1U);
    WalletDescriptor receive_desc{std::move(receive_parsed[0]), static_cast<uint64_t>(GetTime()), /*range_start=*/0, /*range_end=*/P2MR_TEST_RANGE_END, /*next_index=*/0};
    ScriptPubKeyMan* receive_spkm = wallet->AddWalletDescriptor(receive_desc, receive_keys, "", /*internal=*/false);

    FlatSigningProvider change_keys;
    if (master_key) change_keys.AddMasterKey(*master_key);
    std::string change_error;
    auto change_parsed = Parse(change_desc_str, change_keys, change_error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!change_parsed.empty(), "change descriptor parse failed: " + change_error);
    BOOST_REQUIRE_EQUAL(change_parsed.size(), 1U);
    WalletDescriptor change_desc{std::move(change_parsed[0]), static_cast<uint64_t>(GetTime()), /*range_start=*/0, /*range_end=*/P2MR_TEST_RANGE_END, /*next_index=*/0};
    ScriptPubKeyMan* change_spkm = wallet->AddWalletDescriptor(change_desc, change_keys, "", /*internal=*/true);

    BOOST_REQUIRE(receive_spkm);
    BOOST_REQUIRE(change_spkm);
    wallet->AddActiveScriptPubKeyMan(receive_spkm->GetID(), OutputType::P2MR, /*internal=*/false);
    wallet->AddActiveScriptPubKeyMan(change_spkm->GetID(), OutputType::P2MR, /*internal=*/true);
    return wallet;
}

std::shared_ptr<CWallet> CreateDescriptorWalletWithSingleImportedDescriptor(
    const WalletTestingSetup& setup,
    const std::string& descriptor,
    const CExtKey* master_key = nullptr,
    bool disable_private_keys = false)
{
    auto wallet = std::make_shared<CWallet>(setup.m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    if (disable_private_keys) {
        wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
    }
    wallet->m_keypool_size = 1;

    FlatSigningProvider keys;
    if (master_key) keys.AddMasterKey(*master_key);
    std::string error;
    auto parsed = Parse(descriptor, keys, error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), "descriptor parse failed: " + error);
    BOOST_REQUIRE_EQUAL(parsed.size(), 1U);

    WalletDescriptor imported_desc{
        std::move(parsed[0]),
        static_cast<uint64_t>(GetTime()),
        /*range_start=*/0,
        /*range_end=*/0,
        /*next_index=*/0};
    ScriptPubKeyMan* spk_man = wallet->AddWalletDescriptor(imported_desc, keys, "", /*internal=*/false);
    BOOST_REQUIRE(spk_man);
    return wallet;
}

bool SignAndCheckP2MRTransaction(const std::shared_ptr<CWallet>& wallet, CMutableTransaction& tx, const Coin& prev_coin)
{
    std::map<COutPoint, Coin> coins;
    coins.emplace(tx.vin[0].prevout, prev_coin);
    std::map<int, bilingual_str> input_errors;
    if (!wallet->SignTransaction(tx, coins, SIGHASH_DEFAULT, input_errors, /*inputs_amount_sum=*/nullptr)) return false;
    if (!input_errors.empty()) return false;

    const CTransaction tx_const{tx};
    PrecomputedTransactionData txdata;
    txdata.Init(tx_const, {prev_coin.out}, /*force=*/true);
    ScriptError serror = SCRIPT_ERR_OK;
    if (!VerifyScript(
            tx.vin[0].scriptSig,
            prev_coin.out.scriptPubKey,
            &tx.vin[0].scriptWitness,
            STANDARD_SCRIPT_VERIFY_FLAGS,
            TransactionSignatureChecker(&tx_const, 0, prev_coin.out.nValue, txdata, MissingDataBehavior::FAIL),
            &serror)) {
        return false;
    }
    return serror == SCRIPT_ERR_OK;
}

PartiallySignedTransaction RoundTripPSBT(const PartiallySignedTransaction& psbt)
{
    DataStream ss{};
    ss << psbt;

    PartiallySignedTransaction decoded;
    ss >> decoded;
    return decoded;
}

bool CachedP2MRPartialSigValid(const PartiallySignedTransaction& psbt,
                               unsigned int input_index,
                               const std::pair<uint256, std::vector<unsigned char>>& leaf_pubkey,
                               const std::vector<unsigned char>& sig,
                               const PrecomputedTransactionData& txdata)
{
    const auto algo = GetPQAlgorithmByPubKeySize(leaf_pubkey.second.size());
    if (!algo.has_value()) return false;

    const size_t expected_sig_size = GetPQSignatureSize(*algo);
    uint8_t hash_type = SIGHASH_DEFAULT;
    Span<const unsigned char> sig_to_check{sig};
    if (sig_to_check.size() == expected_sig_size + 1) {
        hash_type = sig_to_check.back();
        sig_to_check = sig_to_check.first(expected_sig_size);
    } else if (sig_to_check.size() != expected_sig_size) {
        return false;
    }

    CTxOut utxo;
    if (!psbt.GetInputUTXO(utxo, input_index)) return false;

    MutableTransactionSignatureCreator creator(*psbt.tx, input_index, utxo.nValue, &txdata, SIGHASH_DEFAULT);
    ScriptExecutionData execdata;
    execdata.m_annex_init = true;
    execdata.m_annex_present = false;
    execdata.m_codeseparator_pos_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFF;
    execdata.m_tapleaf_hash_init = true;
    execdata.m_tapleaf_hash = leaf_pubkey.first;
    return creator.Checker().CheckPQSignature(sig_to_check, leaf_pubkey.second, *algo, hash_type, SigVersion::P2MR, execdata);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_multisig_wallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(sign_p2mr_transaction_multisig_leaf)
{
    const auto pq_seed = MakePQSeed(0x10);

    const std::string receive_desc = AddChecksum(
        "mr(multi_pq(2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/false) + ")))");
    const std::string change_desc = AddChecksum(
        "mr(multi_pq(2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/true) + ")))");

    const auto wallet = CreateP2MRDescriptorWalletFromStrings(*this, receive_desc, change_desc);
    const CTxDestination from_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination to_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));

    const COutPoint prevout{Txid::FromUint256(uint256{42}), 0};
    const CAmount input_value{10 * COIN};
    Coin prev_coin{CTxOut{input_value, GetScriptForDestination(from_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(input_value - 1000, GetScriptForDestination(to_dest));

    BOOST_REQUIRE(SignAndCheckP2MRTransaction(wallet, tx, prev_coin));
    BOOST_REQUIRE(tx.vin[0].scriptSig.empty());
    BOOST_REQUIRE_EQUAL(tx.vin[0].scriptWitness.stack.size(), 5U);

    // 3 signature slots (reversed), then leaf script and control block.
    const auto& sig3 = tx.vin[0].scriptWitness.stack[0];
    const auto& sig2 = tx.vin[0].scriptWitness.stack[1];
    const auto& sig1 = tx.vin[0].scriptWitness.stack[2];
    const auto& leaf_script = tx.vin[0].scriptWitness.stack[3];
    const auto& control = tx.vin[0].scriptWitness.stack[4];
    BOOST_CHECK(!leaf_script.empty());
    BOOST_CHECK(!control.empty());
    BOOST_CHECK_EQUAL(control[0], P2MR_LEAF_VERSION);

    int non_empty = 0;
    non_empty += !sig1.empty();
    non_empty += !sig2.empty();
    non_empty += !sig3.empty();
    BOOST_CHECK_EQUAL(non_empty, 2);
}

BOOST_AUTO_TEST_CASE(sign_p2mr_transaction_cltv_multisig_leaf_updates_locktime)
{
    const auto pq_seed = MakePQSeed(0x11);

    const std::string receive_desc = AddChecksum(
        "mr(cltv_multi_pq(700,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/false) + ")))");
    const std::string change_desc = AddChecksum(
        "mr(cltv_multi_pq(700,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/true) + ")))");

    const auto wallet = CreateP2MRDescriptorWalletFromStrings(*this, receive_desc, change_desc);
    const CTxDestination from_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination to_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));

    const COutPoint prevout{Txid::FromUint256(uint256{111}), 0};
    const CAmount input_value{8 * COIN};
    Coin prev_coin{CTxOut{input_value, GetScriptForDestination(from_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(input_value - 1000, GetScriptForDestination(to_dest));

    BOOST_REQUIRE(SignAndCheckP2MRTransaction(wallet, tx, prev_coin));
    BOOST_CHECK_EQUAL(tx.nLockTime, 700U);
    BOOST_CHECK_EQUAL(tx.vin[0].nSequence, CTxIn::SEQUENCE_FINAL - 1);
}

BOOST_AUTO_TEST_CASE(sign_p2mr_transaction_csv_multisig_leaf_updates_sequence)
{
    const auto pq_seed = MakePQSeed(0x12);

    const std::string receive_desc = AddChecksum(
        "mr(csv_multi_pq(144,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/false) + ")))");
    const std::string change_desc = AddChecksum(
        "mr(csv_multi_pq(144,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/true) + ")))");

    const auto wallet = CreateP2MRDescriptorWalletFromStrings(*this, receive_desc, change_desc);
    const CTxDestination from_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination to_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));

    const COutPoint prevout{Txid::FromUint256(uint256{112}), 0};
    const CAmount input_value{8 * COIN};
    Coin prev_coin{CTxOut{input_value, GetScriptForDestination(from_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(input_value - 1000, GetScriptForDestination(to_dest));

    BOOST_REQUIRE(SignAndCheckP2MRTransaction(wallet, tx, prev_coin));
    BOOST_CHECK_EQUAL(tx.version, 2);
    BOOST_CHECK_EQUAL(tx.vin[0].nSequence, 144U);
}

BOOST_AUTO_TEST_CASE(psbt_signs_p2mr_multisig_with_pubkey_fallback)
{
    const auto pq_seed = MakePQSeed(0x20);

    const std::string multisig_receive_desc = AddChecksum(
        "mr(multi_pq(2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/false) + ")))");
    const std::string multisig_change_desc = AddChecksum(
        "mr(multi_pq(2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/true) + ")))");
    const auto watch_wallet = CreateP2MRDescriptorWalletFromStrings(*this, multisig_receive_desc, multisig_change_desc);

    const std::string signer_receive_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ")");
    const std::string signer_change_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ")");
    const auto signer_wallet = CreateP2MRDescriptorWalletFromStrings(*this, signer_receive_desc, signer_change_desc);

    const CTxDestination multisig_dest = *Assert(watch_wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination spend_dest = *Assert(signer_wallet->GetNewDestination(OutputType::P2MR, ""));

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{77}), 0});
    tx.vout.emplace_back(5 * COIN - 1000, GetScriptForDestination(spend_dest));

    Coin prev_coin{CTxOut{5 * COIN, GetScriptForDestination(multisig_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};
    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = prev_coin.out;

    bool complete = true;
    const auto update_err = watch_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!update_err);
    BOOST_REQUIRE(!psbt.inputs[0].m_p2mr_leaf_script.empty());
    BOOST_REQUIRE(!psbt.inputs[0].m_p2mr_control_block.empty());

    complete = true;
    const auto sign_err = signer_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!sign_err);
    BOOST_CHECK_EQUAL(psbt.inputs[0].m_p2mr_pq_sigs.size(), 1U);
    BOOST_CHECK(!complete);
}

BOOST_AUTO_TEST_CASE(psbt_signs_cltv_p2mr_multisig_with_pubkey_fallback)
{
    const auto pq_seed = MakePQSeed(0x21);

    const std::string multisig_receive_desc = AddChecksum(
        "mr(cltv_multi_pq(700,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/false) + ")))");
    const std::string multisig_change_desc = AddChecksum(
        "mr(cltv_multi_pq(700,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/true) + ")))");
    const auto watch_wallet = CreateP2MRDescriptorWalletFromStrings(*this, multisig_receive_desc, multisig_change_desc);

    const std::string signer_receive_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ")");
    const std::string signer_change_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ")");
    const auto signer_wallet = CreateP2MRDescriptorWalletFromStrings(*this, signer_receive_desc, signer_change_desc);

    const CTxDestination multisig_dest = *Assert(watch_wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination spend_dest = *Assert(signer_wallet->GetNewDestination(OutputType::P2MR, ""));

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{78}), 0});
    tx.vout.emplace_back(5 * COIN - 1000, GetScriptForDestination(spend_dest));

    Coin prev_coin{CTxOut{5 * COIN, GetScriptForDestination(multisig_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};
    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = prev_coin.out;

    bool complete = true;
    const auto update_err = watch_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!update_err);
    BOOST_REQUIRE(!psbt.inputs[0].m_p2mr_leaf_script.empty());
    BOOST_REQUIRE(!psbt.inputs[0].m_p2mr_control_block.empty());

    complete = true;
    const auto sign_err = signer_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!sign_err);
    BOOST_CHECK_EQUAL(psbt.inputs[0].m_p2mr_pq_sigs.size(), 1U);
    BOOST_CHECK(!complete);
}

BOOST_AUTO_TEST_CASE(psbt_signs_csv_p2mr_multisig_with_pubkey_fallback)
{
    const auto pq_seed = MakePQSeed(0x22);

    const std::string multisig_receive_desc = AddChecksum(
        "mr(csv_multi_pq(144,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/false) + ")))");
    const std::string multisig_change_desc = AddChecksum(
        "mr(csv_multi_pq(144,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/true) + ")))");
    const auto watch_wallet = CreateP2MRDescriptorWalletFromStrings(*this, multisig_receive_desc, multisig_change_desc);

    const std::string signer_receive_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ")");
    const std::string signer_change_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ")");
    const auto signer_wallet = CreateP2MRDescriptorWalletFromStrings(*this, signer_receive_desc, signer_change_desc);

    const CTxDestination multisig_dest = *Assert(watch_wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination spend_dest = *Assert(signer_wallet->GetNewDestination(OutputType::P2MR, ""));

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{79}), 0});
    tx.vout.emplace_back(5 * COIN - 1000, GetScriptForDestination(spend_dest));

    Coin prev_coin{CTxOut{5 * COIN, GetScriptForDestination(multisig_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};
    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = prev_coin.out;

    bool complete = true;
    const auto update_err = watch_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!update_err);
    BOOST_REQUIRE(!psbt.inputs[0].m_p2mr_leaf_script.empty());
    BOOST_REQUIRE(!psbt.inputs[0].m_p2mr_control_block.empty());

    complete = true;
    const auto sign_err = signer_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!sign_err);
    BOOST_CHECK_EQUAL(psbt.inputs[0].m_p2mr_pq_sigs.size(), 1U);
    BOOST_CHECK(!complete);
}

BOOST_AUTO_TEST_CASE(psbt_combines_and_finalizes_csv_p2mr_multisig_from_wallet_signers)
{
    const auto pq_seed = MakePQSeed(0x23);

    const std::string multisig_receive_desc = AddChecksum(
        "mr(csv_multi_pq(1,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + "))");
    const std::string multisig_change_desc = AddChecksum(
        "mr(csv_multi_pq(1,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + "))");
    const auto coordinator_wallet = CreateP2MRDescriptorWalletFromStrings(*this, multisig_receive_desc, multisig_change_desc);

    const std::string signer_a_receive_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ")");
    const std::string signer_a_change_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ")");
    const auto signer_a_wallet = CreateP2MRDescriptorWalletFromStrings(*this, signer_a_receive_desc, signer_a_change_desc);

    const std::string signer_b_receive_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + ")");
    const std::string signer_b_change_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + ")");
    const auto signer_b_wallet = CreateP2MRDescriptorWalletFromStrings(*this, signer_b_receive_desc, signer_b_change_desc);

    const CTxDestination multisig_dest = *Assert(coordinator_wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination receiver_dest = *Assert(signer_a_wallet->GetNewDestination(OutputType::P2MR, ""));

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{123}), 0});
    tx.vout.emplace_back(2 * COIN, GetScriptForDestination(receiver_dest));
    tx.vout.emplace_back(3 * COIN - 1000, GetScriptForDestination(multisig_dest));

    Coin prev_coin{CTxOut{5 * COIN + 1000, GetScriptForDestination(multisig_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};
    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = prev_coin.out;

    bool complete = true;
    const auto update_err = coordinator_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!update_err);
    BOOST_CHECK_EQUAL(psbt.tx->version, 2);
    BOOST_CHECK_EQUAL(psbt.tx->vin[0].nSequence, 1U);
    BOOST_REQUIRE(!psbt.inputs[0].m_p2mr_leaf_script.empty());
    BOOST_REQUIRE(!psbt.inputs[0].m_p2mr_control_block.empty());

    PartiallySignedTransaction psbt_a = RoundTripPSBT(psbt);
    PartiallySignedTransaction psbt_b = RoundTripPSBT(psbt);

    complete = true;
    const auto sign_a_err = signer_a_wallet->FillPSBT(psbt_a, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!sign_a_err);
    BOOST_CHECK(!complete);
    BOOST_CHECK_EQUAL(psbt_a.inputs[0].m_p2mr_pq_sigs.size(), 1U);

    complete = true;
    const auto sign_b_err = signer_b_wallet->FillPSBT(psbt_b, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!sign_b_err);
    BOOST_CHECK(!complete);
    BOOST_CHECK_EQUAL(psbt_b.inputs[0].m_p2mr_pq_sigs.size(), 1U);

    PartiallySignedTransaction combined;
    BOOST_REQUIRE(CombinePSBTs(combined, {RoundTripPSBT(psbt_a), RoundTripPSBT(psbt_b)}));
    BOOST_CHECK_EQUAL(combined.inputs[0].m_p2mr_pq_sigs.size(), 2U);
    BOOST_CHECK_EQUAL(combined.tx->version, 2);
    BOOST_CHECK_EQUAL(combined.tx->vin[0].nSequence, 1U);

    const PrecomputedTransactionData combined_txdata = PrecomputePSBTData(combined);
    for (const auto& [leaf_pubkey, sig] : combined.inputs[0].m_p2mr_pq_sigs) {
        BOOST_CHECK(CachedP2MRPartialSigValid(combined, /*input_index=*/0, leaf_pubkey, sig, combined_txdata));
    }

    SignatureData manual_sigdata;
    combined.inputs[0].FillSignatureData(manual_sigdata);
    MutableTransactionSignatureCreator creator(*combined.tx, /*input_idx=*/0, prev_coin.out.nValue, &combined_txdata, SIGHASH_ALL);
    const bool manual_complete = ProduceSignature(DUMMY_SIGNING_PROVIDER, creator, prev_coin.out.scriptPubKey, manual_sigdata);
    BOOST_CHECK_EQUAL(manual_sigdata.scriptWitness.stack.size(), 4U);
    BOOST_CHECK(manual_complete);
    ScriptError manual_serror = SCRIPT_ERR_OK;
    const bool manual_verified = VerifyScript(manual_sigdata.scriptSig,
                                              prev_coin.out.scriptPubKey,
                                              &manual_sigdata.scriptWitness,
                                              STANDARD_SCRIPT_VERIFY_FLAGS,
                                              creator.Checker(),
                                              &manual_serror);
    BOOST_CHECK_EQUAL(manual_serror, SCRIPT_ERR_OK);
    BOOST_CHECK(manual_verified);

    BOOST_REQUIRE(FinalizePSBT(combined));
    const PrecomputedTransactionData txdata = PrecomputePSBTData(combined);
    BOOST_CHECK(PSBTInputSignedAndVerified(combined, /*input_index=*/0, &txdata));
}

BOOST_AUTO_TEST_CASE(psbt_signer_replaces_invalid_cached_p2mr_partial_sig)
{
    const auto pq_seed = MakePQSeed(0x30);

    const std::string multisig_receive_desc = AddChecksum(
        "mr(multi_pq(2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/false) + ")))");
    const std::string multisig_change_desc = AddChecksum(
        "mr(multi_pq(2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/true) + ")))");
    const auto watch_wallet = CreateP2MRDescriptorWalletFromStrings(*this, multisig_receive_desc, multisig_change_desc);

    const std::string signer_receive_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ")");
    const std::string signer_change_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ")");
    const auto signer_wallet = CreateP2MRDescriptorWalletFromStrings(*this, signer_receive_desc, signer_change_desc);

    const CTxDestination multisig_dest = *Assert(watch_wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination spend_dest = *Assert(signer_wallet->GetNewDestination(OutputType::P2MR, ""));

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{177}), 0});
    tx.vout.emplace_back(5 * COIN - 1000, GetScriptForDestination(spend_dest));

    Coin prev_coin{CTxOut{5 * COIN, GetScriptForDestination(multisig_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};
    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = prev_coin.out;

    bool complete = true;
    const auto update_err = watch_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!update_err);
    BOOST_REQUIRE(!psbt.inputs[0].m_p2mr_leaf_script.empty());
    BOOST_REQUIRE(!psbt.inputs[0].m_p2mr_control_block.empty());

    complete = true;
    const auto sign_err = signer_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!sign_err);
    BOOST_REQUIRE_EQUAL(psbt.inputs[0].m_p2mr_pq_sigs.size(), 1U);

    const auto key = psbt.inputs[0].m_p2mr_pq_sigs.begin()->first;
    BOOST_REQUIRE_EQUAL(key.second.size(), MLDSA44_PUBKEY_SIZE);

    // Simulate malicious coordinator data poisoning: cached partial sig for our key is invalid.
    psbt.inputs[0].m_p2mr_pq_sigs[key] = std::vector<unsigned char>{0x00};

    complete = true;
    const auto resign_err = signer_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!resign_err);

    const auto it = psbt.inputs[0].m_p2mr_pq_sigs.find(key);
    BOOST_REQUIRE(it != psbt.inputs[0].m_p2mr_pq_sigs.end());
    BOOST_CHECK_EQUAL(it->second.size(), MLDSA44_SIGNATURE_SIZE);
}

BOOST_AUTO_TEST_CASE(psbt_updater_sets_leaf_for_fixed_watchonly_multisig)
{
    auto make_slh_key = [](unsigned char seed) {
        std::vector<unsigned char> key(SLHDSA128S_PUBKEY_SIZE);
        for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<unsigned char>(seed + i);
        return HexStr(key);
    };

    const std::string k1 = make_slh_key(0x11);
    const std::string k2 = make_slh_key(0x33);
    const std::string k3 = make_slh_key(0x55);

    const std::string receive_desc = AddChecksum(
        "mr(sortedmulti_pq(2,pk_slh(" + k1 + "),pk_slh(" + k2 + "),pk_slh(" + k3 + ")))");
    const std::string change_desc = AddChecksum(
        "mr(sortedmulti_pq(2,pk_slh(" + k1 + "),pk_slh(" + k2 + "),pk_slh(" + k3 + ")))");

    const auto watch_wallet = CreateP2MRDescriptorWalletFromStrings(*this, receive_desc, change_desc);
    DescriptorScriptPubKeyMan* spk_man{nullptr};
    for (ScriptPubKeyMan* man : watch_wallet->GetAllScriptPubKeyMans()) {
        spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(man);
        if (spk_man) break;
    }
    BOOST_REQUIRE(spk_man);
    const auto scripts = spk_man->GetScriptPubKeys();
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
    const CScript from_script = *scripts.begin();

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{88}), 0});
    tx.vout.emplace_back(7 * COIN - 1000, from_script);

    Coin prev_coin{CTxOut{7 * COIN, from_script}, /*nHeight=*/1, /*fCoinBase=*/false};
    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = prev_coin.out;

    bool complete = true;
    const auto update_err = watch_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!update_err);
    BOOST_CHECK(!psbt.inputs[0].m_p2mr_leaf_script.empty());
    BOOST_CHECK(!psbt.inputs[0].m_p2mr_control_block.empty());
}

BOOST_AUTO_TEST_CASE(psbt_updater_sets_cltv_fields_for_watchonly_timelocked_multisig)
{
    const auto pq_seed = MakePQSeed(0x61);

    const std::string receive_desc = AddChecksum(
        "mr(cltv_multi_pq(700,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/false) + ")))");
    const std::string change_desc = AddChecksum(
        "mr(cltv_multi_pq(700,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/true) + ")))");
    const auto watch_wallet = CreateP2MRDescriptorWalletFromStrings(*this, receive_desc, change_desc);

    const CTxDestination multisig_dest = *Assert(watch_wallet->GetNewDestination(OutputType::P2MR, ""));
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{161}), 0});
    tx.vout.emplace_back(5 * COIN - 1000, GetScriptForDestination(multisig_dest));

    Coin prev_coin{CTxOut{5 * COIN, GetScriptForDestination(multisig_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};
    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = prev_coin.out;

    bool complete = true;
    const auto update_err = watch_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!update_err);
    BOOST_CHECK_EQUAL(psbt.tx->nLockTime, 700U);
    BOOST_CHECK_EQUAL(psbt.tx->vin[0].nSequence, CTxIn::SEQUENCE_FINAL - 1);
    BOOST_CHECK(!psbt.inputs[0].m_p2mr_leaf_script.empty());
}

BOOST_AUTO_TEST_CASE(psbt_updater_preserves_existing_nonfinal_sequence_for_cltv_watchonly_timelocked_multisig)
{
    const auto pq_seed = MakePQSeed(0x64);

    const std::string receive_desc = AddChecksum(
        "mr(cltv_multi_pq(700,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/false) + ")))");
    const std::string change_desc = AddChecksum(
        "mr(cltv_multi_pq(700,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/true) + ")))");
    const auto watch_wallet = CreateP2MRDescriptorWalletFromStrings(*this, receive_desc, change_desc);

    const CTxDestination multisig_dest = *Assert(watch_wallet->GetNewDestination(OutputType::P2MR, ""));
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{164}), 0}, CScript{}, MAX_BIP125_RBF_SEQUENCE);
    tx.vout.emplace_back(5 * COIN - 1000, GetScriptForDestination(multisig_dest));

    Coin prev_coin{CTxOut{5 * COIN, GetScriptForDestination(multisig_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};
    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = prev_coin.out;

    bool complete = true;
    const auto update_err = watch_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!update_err);
    BOOST_CHECK_EQUAL(psbt.tx->nLockTime, 700U);
    BOOST_CHECK_EQUAL(psbt.tx->vin[0].nSequence, MAX_BIP125_RBF_SEQUENCE);
    BOOST_CHECK(!psbt.inputs[0].m_p2mr_leaf_script.empty());
}

BOOST_AUTO_TEST_CASE(psbt_updater_rejects_cltv_field_mutation_after_partial_signing)
{
    const auto pq_seed = MakePQSeed(0x65);

    const std::string multisig_receive_desc = AddChecksum(
        "mr(cltv_multi_pq(700,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + "))");
    const std::string multisig_change_desc = AddChecksum(
        "mr(cltv_multi_pq(700,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + "))");
    const auto coordinator_wallet = CreateP2MRDescriptorWalletFromStrings(*this, multisig_receive_desc, multisig_change_desc);

    const std::string signer_receive_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ")");
    const std::string signer_change_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ")");
    const auto signer_wallet = CreateP2MRDescriptorWalletFromStrings(*this, signer_receive_desc, signer_change_desc);

    const CTxDestination multisig_dest = *Assert(coordinator_wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination receiver_dest = *Assert(signer_wallet->GetNewDestination(OutputType::P2MR, ""));

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{165}), 0});
    tx.vout.emplace_back(5 * COIN - 1000, GetScriptForDestination(receiver_dest));

    Coin prev_coin{CTxOut{5 * COIN, GetScriptForDestination(multisig_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};
    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = prev_coin.out;

    bool complete = true;
    const auto update_err = coordinator_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!update_err);
    BOOST_CHECK_EQUAL(psbt.tx->nLockTime, 700U);
    BOOST_CHECK_EQUAL(psbt.tx->vin[0].nSequence, CTxIn::SEQUENCE_FINAL - 1);

    complete = true;
    const auto sign_err = signer_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!sign_err);
    BOOST_REQUIRE_EQUAL(psbt.inputs[0].m_p2mr_pq_sigs.size(), 1U);

    psbt.tx->nLockTime = 699;
    complete = false;
    const auto mutated_err = coordinator_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(mutated_err.has_value());
    BOOST_CHECK(*mutated_err == common::PSBTError::P2MR_TIMELOCK_MISMATCH);
    BOOST_CHECK_EQUAL(psbt.tx->nLockTime, 699U);
}

BOOST_AUTO_TEST_CASE(psbt_updater_sets_csv_fields_for_watchonly_timelocked_multisig)
{
    const auto pq_seed = MakePQSeed(0x62);

    const std::string receive_desc = AddChecksum(
        "mr(csv_multi_pq(144,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/false) + ")))");
    const std::string change_desc = AddChecksum(
        "mr(csv_multi_pq(144,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/2, /*internal=*/true) + ")))");
    const auto watch_wallet = CreateP2MRDescriptorWalletFromStrings(*this, receive_desc, change_desc);

    const CTxDestination multisig_dest = *Assert(watch_wallet->GetNewDestination(OutputType::P2MR, ""));
    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{162}), 0});
    tx.vout.emplace_back(5 * COIN - 1000, GetScriptForDestination(multisig_dest));

    Coin prev_coin{CTxOut{5 * COIN, GetScriptForDestination(multisig_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};
    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = prev_coin.out;

    bool complete = true;
    const auto update_err = watch_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!update_err);
    BOOST_CHECK_EQUAL(psbt.tx->version, 2);
    BOOST_CHECK_EQUAL(psbt.tx->vin[0].nSequence, 144U);
    BOOST_CHECK(!psbt.inputs[0].m_p2mr_leaf_script.empty());
}

BOOST_AUTO_TEST_CASE(psbt_updater_rejects_csv_field_mutation_after_partial_signing)
{
    const auto pq_seed = MakePQSeed(0x66);

    const std::string multisig_receive_desc = AddChecksum(
        "mr(csv_multi_pq(144,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/false) + "))");
    const std::string multisig_change_desc = AddChecksum(
        "mr(csv_multi_pq(144,2,"
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/1, /*internal=*/true) + "))");
    const auto coordinator_wallet = CreateP2MRDescriptorWalletFromStrings(*this, multisig_receive_desc, multisig_change_desc);

    const std::string signer_receive_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/false) + ")");
    const std::string signer_change_desc = AddChecksum("mr(" + MakeP2MRKeyPathExprWithBranch(pq_seed, /*branch=*/0, /*internal=*/true) + ")");
    const auto signer_wallet = CreateP2MRDescriptorWalletFromStrings(*this, signer_receive_desc, signer_change_desc);

    const CTxDestination multisig_dest = *Assert(coordinator_wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination receiver_dest = *Assert(signer_wallet->GetNewDestination(OutputType::P2MR, ""));

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{166}), 0});
    tx.vout.emplace_back(5 * COIN - 1000, GetScriptForDestination(receiver_dest));

    Coin prev_coin{CTxOut{5 * COIN, GetScriptForDestination(multisig_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};
    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = prev_coin.out;

    bool complete = true;
    const auto update_err = coordinator_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!update_err);
    BOOST_CHECK_EQUAL(psbt.tx->version, 2);
    BOOST_CHECK_EQUAL(psbt.tx->vin[0].nSequence, 144U);

    complete = true;
    const auto sign_err = signer_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/true, /*bip32derivs=*/false, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!sign_err);
    BOOST_REQUIRE_EQUAL(psbt.inputs[0].m_p2mr_pq_sigs.size(), 1U);

    psbt.tx->version = 1;
    psbt.tx->vin[0].nSequence = 0xffffffffU;
    complete = false;
    const auto mutated_err = coordinator_wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(mutated_err.has_value());
    BOOST_CHECK(*mutated_err == common::PSBTError::P2MR_TIMELOCK_MISMATCH);
    BOOST_CHECK_EQUAL(psbt.tx->version, 1);
    BOOST_CHECK_EQUAL(psbt.tx->vin[0].nSequence, 0xffffffffU);
}

BOOST_AUTO_TEST_CASE(psbt_updater_sets_leaf_for_rpc_style_imported_fixed_multisig)
{
    auto make_slh_key = [](unsigned char seed) {
        std::vector<unsigned char> key(SLHDSA128S_PUBKEY_SIZE);
        for (size_t i = 0; i < key.size(); ++i) key[i] = static_cast<unsigned char>(seed + i);
        return HexStr(key);
    };

    const std::string k1 = make_slh_key(0x21);
    const std::string k2 = make_slh_key(0x43);
    const std::string k3 = make_slh_key(0x65);
    const std::string descriptor = AddChecksum(
        "mr(sortedmulti_pq(2,pk_slh(" + k1 + "),pk_slh(" + k2 + "),pk_slh(" + k3 + ")))");

    const auto wallet = CreateDescriptorWalletWithSingleImportedDescriptor(
        *this,
        descriptor,
        /*master_key=*/nullptr,
        /*disable_private_keys=*/true);

    DescriptorScriptPubKeyMan* spk_man{nullptr};
    for (ScriptPubKeyMan* man : wallet->GetAllScriptPubKeyMans()) {
        spk_man = dynamic_cast<DescriptorScriptPubKeyMan*>(man);
        if (spk_man) break;
    }
    BOOST_REQUIRE(spk_man);
    const auto scripts = spk_man->GetScriptPubKeys();
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);
    const CScript script = *scripts.begin();

    CMutableTransaction tx;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256{99}), 0});
    tx.vout.emplace_back(7 * COIN - 1000, script);

    Coin prev_coin{CTxOut{7 * COIN, script}, /*nHeight=*/1, /*fCoinBase=*/false};
    PartiallySignedTransaction psbt(tx);
    psbt.inputs[0].witness_utxo = prev_coin.out;

    bool complete = true;
    const auto update_err = wallet->FillPSBT(psbt, complete, SIGHASH_DEFAULT, /*sign=*/false, /*bip32derivs=*/true, /*n_signed=*/nullptr, /*finalize=*/false);
    BOOST_REQUIRE(!update_err);
    BOOST_CHECK(!psbt.inputs[0].m_p2mr_leaf_script.empty());
    BOOST_CHECK(!psbt.inputs[0].m_p2mr_control_block.empty());
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
