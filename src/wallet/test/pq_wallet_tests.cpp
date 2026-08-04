// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chainparams.h>
#include <consensus/tx_check.h>
#include <consensus/amount.h>
#include <consensus/validation.h>
#include <key.h>
#include <key_io.h>
#include <outputtype.h>
#include <pqkey.h>
#include <psbt.h>
#include <script/descriptor.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/script.h>
#include <script/sign.h>
#include <script/solver.h>
#include <shielded/smile2/ct_proof.h>
#include <test/util/shielded_v2_egress_fixture.h>
#include <test/util/setup_common.h>
#include <tinyformat.h>
#include <util/strencodings.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/coincontrol.h>
#include <wallet/wallet.h>
#include <wallet/walletdb.h>
#include <wallet/spend.h>
#include <wallet/walletutil.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdlib>
#include <map>
#include <optional>

namespace wallet {
namespace {

static constexpr int64_t P2MR_TEST_RANGE_END{2};
static constexpr unsigned int SLHDSA_FIPS205_SCRIPT_VERIFY_FLAGS{STANDARD_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_SLHDSA_FIPS205};

std::array<unsigned char, 32> MakePQSeed(unsigned char seed)
{
    std::array<unsigned char, 32> out{};
    for (size_t i = 0; i < out.size(); ++i) {
        out[i] = static_cast<unsigned char>(seed + i);
    }
    return out;
}

std::vector<unsigned char> MakePattern(size_t size, unsigned char seed)
{
    std::vector<unsigned char> out(size);
    for (size_t i = 0; i < out.size(); ++i) out[i] = static_cast<unsigned char>(seed + i);
    return out;
}

std::string MakeP2MRKeyPathExpr(const std::array<unsigned char, 32>& seed, bool internal)
{
    std::string expr = "pqhd(" + HexStr(seed);
    expr += Params().IsTestChain() ? "/1h" : "/0h";
    expr += "/0h";
    expr += internal ? "/1" : "/0";
    expr += "/*)";
    return expr;
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

WalletDescriptor MakeRangedDescriptor(const std::array<unsigned char, 32>& seed, bool internal)
{
    WalletDescriptor base = GeneratePQWalletDescriptor(seed, internal);
    return WalletDescriptor(base.descriptor, base.creation_time, /*range_start=*/0, /*range_end=*/P2MR_TEST_RANGE_END, /*next_index=*/0);
}

std::shared_ptr<CWallet> CreateP2MRDescriptorWalletFromStrings(const WalletTestingSetup& setup,
                                                               const std::string& receive_desc_str,
                                                               const std::string& change_desc_str,
                                                               const DescriptorCache* receive_cache = nullptr,
                                                               const DescriptorCache* change_cache = nullptr)
{
    auto wallet = std::make_shared<CWallet>(setup.m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet->m_keypool_size = P2MR_TEST_RANGE_END;

    FlatSigningProvider receive_keys;
    std::string receive_error;
    auto receive_parsed = Parse(receive_desc_str, receive_keys, receive_error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!receive_parsed.empty(), "receive descriptor parse failed: " + receive_error + " desc=" + receive_desc_str);
    BOOST_REQUIRE_EQUAL(receive_parsed.size(), 1U);
    WalletDescriptor receive_desc{std::move(receive_parsed[0]), static_cast<uint64_t>(GetTime()), /*range_start=*/0, /*range_end=*/P2MR_TEST_RANGE_END, /*next_index=*/0};
    if (receive_cache) receive_desc.cache = *receive_cache;
    ScriptPubKeyMan* receive_spkm = wallet->AddWalletDescriptor(receive_desc, receive_keys, "", /*internal=*/false);

    FlatSigningProvider change_keys;
    std::string change_error;
    auto change_parsed = Parse(change_desc_str, change_keys, change_error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!change_parsed.empty(), "change descriptor parse failed: " + change_error + " desc=" + change_desc_str);
    BOOST_REQUIRE_EQUAL(change_parsed.size(), 1U);
    WalletDescriptor change_desc{std::move(change_parsed[0]), static_cast<uint64_t>(GetTime()), /*range_start=*/0, /*range_end=*/P2MR_TEST_RANGE_END, /*next_index=*/0};
    if (change_cache) change_desc.cache = *change_cache;
    ScriptPubKeyMan* change_spkm = wallet->AddWalletDescriptor(change_desc, change_keys, "", /*internal=*/true);

    BOOST_REQUIRE(receive_spkm);
    BOOST_REQUIRE(change_spkm);
    wallet->AddActiveScriptPubKeyMan(receive_spkm->GetID(), OutputType::P2MR, /*internal=*/false);
    wallet->AddActiveScriptPubKeyMan(change_spkm->GetID(), OutputType::P2MR, /*internal=*/true);
    return wallet;
}

std::shared_ptr<CWallet> CreateP2MRDescriptorWallet(const WalletTestingSetup& setup)
{
    const auto seed = MakePQSeed(0x01);
    WalletDescriptor receive = MakeRangedDescriptor(seed, /*internal=*/false);
    WalletDescriptor change = MakeRangedDescriptor(seed, /*internal=*/true);
    std::string receive_desc_priv;
    std::string change_desc_priv;
    BOOST_REQUIRE(receive.descriptor->ToPrivateString(DUMMY_SIGNING_PROVIDER, receive_desc_priv));
    BOOST_REQUIRE(change.descriptor->ToPrivateString(DUMMY_SIGNING_PROVIDER, change_desc_priv));
    return CreateP2MRDescriptorWalletFromStrings(
        setup,
        receive_desc_priv,
        change_desc_priv);
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

struct DirectP2MRSpendFixture {
    FlatSigningProvider provider;
    Coin prev_coin;
    CMutableTransaction tx;
    std::map<COutPoint, Coin> coins;
};

struct P2MRWeightFixture {
    FlatSigningProvider provider;
    CScript script_pubkey;
    std::vector<unsigned char> control;
};

P2MRWeightFixture MakeP2MRWeightFixture(const std::vector<unsigned char>& leaf_script, size_t depth)
{
    BOOST_REQUIRE_LE(depth, (P2MR_CONTROL_MAX_SIZE - P2MR_CONTROL_BASE_SIZE) / P2MR_CONTROL_NODE_SIZE);
    std::vector<unsigned char> control{P2MR_LEAF_VERSION};
    uint256 root{ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script)};
    for (size_t i{0}; i < depth; ++i) {
        uint256 node;
        node.begin()[0] = static_cast<unsigned char>(i + 1);
        root = ComputeP2MRBranchHash(root, node);
        control.insert(control.end(), node.begin(), node.end());
    }

    const WitnessV2P2MR output{root};
    FlatSigningProvider provider;
    provider.p2mr_spends[output].scripts[leaf_script].insert(control);
    return {std::move(provider), GetScriptForDestination(output), std::move(control)};
}

DirectP2MRSpendFixture MakeDirectP2MRSpendFixture(const std::string& desc_str, unsigned char prev_txid_seed)
{
    FlatSigningProvider descriptor_keys;
    std::string error;
    auto parsed = Parse(desc_str, descriptor_keys, error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), "descriptor parse failed: " + error + " desc=" + desc_str);
    BOOST_REQUIRE_EQUAL(parsed.size(), 1U);

    FlatSigningProvider provider;
    std::vector<CScript> scripts;
    BOOST_REQUIRE(parsed[0]->Expand(0, descriptor_keys, scripts, provider));
    parsed[0]->ExpandPrivate(0, descriptor_keys, provider);
    BOOST_REQUIRE_EQUAL(scripts.size(), 1U);

    const COutPoint prevout{Txid::FromUint256(uint256{prev_txid_seed}), 0};
    const CAmount input_value{25 * COIN};
    Coin prev_coin{CTxOut{input_value, scripts[0]}, /*nHeight=*/1, /*fCoinBase=*/false};

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(input_value - 1000, scripts[0]);

    std::map<COutPoint, Coin> coins;
    coins.emplace(prevout, prev_coin);

    return {std::move(provider), std::move(prev_coin), std::move(tx), std::move(coins)};
}

bool SignDirectP2MRSpend(DirectP2MRSpendFixture& fixture,
                         bool slhdsa_fips205,
                         std::optional<PQAlgorithm> preferred_pq_signing_algo = std::nullopt)
{
    std::map<int, bilingual_str> input_errors;
    const bool signed_ok = ::SignTransaction(fixture.tx,
                                             &fixture.provider,
                                             fixture.coins,
                                             SIGHASH_DEFAULT,
                                             input_errors,
                                             /*inputs_amount_sum=*/nullptr,
                                             preferred_pq_signing_algo,
                                             slhdsa_fips205);
    return signed_ok && input_errors.empty();
}

bool VerifyDirectP2MRSpend(const CMutableTransaction& tx, const Coin& prev_coin, unsigned int flags, ScriptError* serror_out = nullptr)
{
    const CTransaction tx_const{tx};
    PrecomputedTransactionData txdata;
    txdata.Init(tx_const, {prev_coin.out}, /*force=*/true);
    ScriptError serror = SCRIPT_ERR_OK;
    const bool ok = VerifyScript(tx.vin[0].scriptSig,
                                 prev_coin.out.scriptPubKey,
                                 &tx.vin[0].scriptWitness,
                                 flags,
                                 TransactionSignatureChecker(&tx_const, 0, prev_coin.out.nValue, txdata, MissingDataBehavior::FAIL),
                                 &serror);
    if (serror_out) *serror_out = serror;
    return ok;
}

unsigned char SignedP2MRLeafOpcode(const CMutableTransaction& tx)
{
    BOOST_REQUIRE(tx.vin[0].scriptSig.empty());
    BOOST_REQUIRE_EQUAL(tx.vin[0].scriptWitness.stack.size(), 3U);
    const auto& leaf_script = tx.vin[0].scriptWitness.stack[1];
    BOOST_REQUIRE(!leaf_script.empty());
    return leaf_script.back();
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(pq_wallet_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(generate_wallet_descriptor_p2mr)
{
    const auto seed = MakePQSeed(0x11);
    const WalletDescriptor desc = GeneratePQWalletDescriptor(seed, /*internal=*/false);
    const std::string desc_str = desc.descriptor->ToString();

    BOOST_CHECK_EQUAL(desc.descriptor->GetOutputType(), OutputType::P2MR);
    BOOST_CHECK(desc_str.rfind("mr(", 0) == 0);
    BOOST_CHECK(desc_str.find("pqhd(") != std::string::npos);
    BOOST_CHECK(desc_str.find("pk_slh(") != std::string::npos);
}

BOOST_AUTO_TEST_CASE(create_wallet_p2mr_destination)
{
    const auto wallet = CreateP2MRDescriptorWallet(*this);
    const auto dest = wallet->GetNewDestination(OutputType::P2MR, "");
    BOOST_REQUIRE(dest);
    BOOST_REQUIRE(std::holds_alternative<WitnessV2P2MR>(*dest));

    const std::string addr = EncodeDestination(*dest);
    BOOST_CHECK(addr.rfind(std::string(Params().Bech32HRP()) + "1z", 0) == 0);
}

BOOST_AUTO_TEST_CASE(wallet_creates_p2mr_only_descriptors)
{
    const auto wallet = CreateP2MRDescriptorWallet(*this);
    BOOST_CHECK(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false));
    BOOST_CHECK(wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/true));
    BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::LEGACY, /*internal=*/false));
    BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::P2SH_SEGWIT, /*internal=*/false));
    BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32, /*internal=*/false));
    BOOST_CHECK(!wallet->GetScriptPubKeyMan(OutputType::BECH32M, /*internal=*/false));
}

BOOST_AUTO_TEST_CASE(sign_p2mr_transaction_mldsa)
{
    const auto wallet = CreateP2MRDescriptorWallet(*this);
    const CTxDestination from_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination to_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));

    const COutPoint prevout{Txid::FromUint256(uint256{1}), 0};
    const CAmount input_value{50 * COIN};
    Coin prev_coin{CTxOut{input_value, GetScriptForDestination(from_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(input_value - 1000, GetScriptForDestination(to_dest));

    BOOST_REQUIRE(SignAndCheckP2MRTransaction(wallet, tx, prev_coin));

    BOOST_REQUIRE(tx.vin[0].scriptSig.empty());
    BOOST_REQUIRE_EQUAL(tx.vin[0].scriptWitness.stack.size(), 3U);
    const auto& sig = tx.vin[0].scriptWitness.stack[0];
    const auto& leaf_script = tx.vin[0].scriptWitness.stack[1];
    const auto& control = tx.vin[0].scriptWitness.stack[2];
    BOOST_CHECK(!leaf_script.empty());
    const unsigned char checksig_opcode = leaf_script.back();
    if (checksig_opcode == static_cast<unsigned char>(OP_CHECKSIG_MLDSA)) {
        BOOST_CHECK_EQUAL(sig.size(), MLDSA44_SIGNATURE_SIZE);
        BOOST_CHECK_EQUAL(leaf_script.size(), MLDSA44_PUBKEY_SIZE + 4U);
    } else if (checksig_opcode == static_cast<unsigned char>(OP_CHECKSIG_SLHDSA)) {
        BOOST_CHECK_EQUAL(sig.size(), SLHDSA128S_SIGNATURE_SIZE);
        BOOST_CHECK_EQUAL(leaf_script.size(), SLHDSA128S_PUBKEY_SIZE + 2U);
    } else {
        BOOST_FAIL("unexpected P2MR checksig opcode");
    }
    BOOST_CHECK(!control.empty());
    BOOST_CHECK_EQUAL(control[0], P2MR_LEAF_VERSION);
    BOOST_CHECK_EQUAL(control.size(), 33U);
}

BOOST_AUTO_TEST_CASE(sign_p2mr_transaction_slhdsa_backup)
{
    const auto seed = MakePQSeed(0x21);
    const std::vector<unsigned char> fixed_mldsa = MakePattern(MLDSA44_PUBKEY_SIZE, 0x51);
    const std::string receive_desc = AddChecksum("mr(" + HexStr(fixed_mldsa) + ",pk_slh(" + MakeP2MRKeyPathExpr(seed, /*internal=*/false) + "))");
    const std::string change_desc = AddChecksum("mr(" + HexStr(fixed_mldsa) + ",pk_slh(" + MakeP2MRKeyPathExpr(seed, /*internal=*/true) + "))");
    const auto wallet = CreateP2MRDescriptorWalletFromStrings(*this, receive_desc, change_desc);

    const CTxDestination from_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination to_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const COutPoint prevout{Txid::FromUint256(uint256{2}), 0};
    const CAmount input_value{25 * COIN};
    Coin prev_coin{CTxOut{input_value, GetScriptForDestination(from_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(input_value - 1000, GetScriptForDestination(to_dest));

    BOOST_REQUIRE(SignAndCheckP2MRTransaction(wallet, tx, prev_coin));
    BOOST_REQUIRE_EQUAL(tx.vin[0].scriptWitness.stack.size(), 3U);
    const auto& sig = tx.vin[0].scriptWitness.stack[0];
    const auto& leaf_script = tx.vin[0].scriptWitness.stack[1];
    const auto& control = tx.vin[0].scriptWitness.stack[2];
    BOOST_CHECK_EQUAL(sig.size(), SLHDSA128S_SIGNATURE_SIZE);
    BOOST_CHECK(!leaf_script.empty());
    BOOST_CHECK_EQUAL(leaf_script.back(), static_cast<unsigned char>(OP_CHECKSIG_SLHDSA));
    BOOST_CHECK_EQUAL(leaf_script.size(), SLHDSA128S_PUBKEY_SIZE + 2U);
    BOOST_CHECK_EQUAL(control.size(), 33U);
}

BOOST_AUTO_TEST_CASE(sign_p2mr_slhdsa_uses_matching_c002_signature_mode)
{
    BOOST_CHECK(!((smile2::SmileCTProof::C002_ACTIVATION_HEIGHT - 1) >= smile2::SmileCTProof::C002_ACTIVATION_HEIGHT));
    BOOST_CHECK(123000 >= smile2::SmileCTProof::C002_ACTIVATION_HEIGHT);
    BOOST_CHECK(123001 >= smile2::SmileCTProof::C002_ACTIVATION_HEIGHT);

    const auto seed = MakePQSeed(0x24);
    const std::vector<unsigned char> fixed_mldsa = MakePattern(MLDSA44_PUBKEY_SIZE, 0x64);
    const std::string desc = AddChecksum("mr(" + HexStr(fixed_mldsa) + ",pk_slh(" + MakeP2MRKeyPathExpr(seed, /*internal=*/false) + "))");

    auto legacy_fixture = MakeDirectP2MRSpendFixture(desc, /*prev_txid_seed=*/40);
    BOOST_REQUIRE(SignDirectP2MRSpend(legacy_fixture, /*slhdsa_fips205=*/false));
    BOOST_CHECK_EQUAL(SignedP2MRLeafOpcode(legacy_fixture.tx), static_cast<unsigned char>(OP_CHECKSIG_SLHDSA));
    BOOST_CHECK_EQUAL(legacy_fixture.tx.vin[0].scriptWitness.stack[0].size(), SLHDSA128S_SIGNATURE_SIZE);
    BOOST_CHECK(VerifyDirectP2MRSpend(legacy_fixture.tx, legacy_fixture.prev_coin, STANDARD_SCRIPT_VERIFY_FLAGS));
    BOOST_CHECK(!VerifyDirectP2MRSpend(legacy_fixture.tx, legacy_fixture.prev_coin, SLHDSA_FIPS205_SCRIPT_VERIFY_FLAGS));

    auto fips_fixture = MakeDirectP2MRSpendFixture(desc, /*prev_txid_seed=*/41);
    BOOST_REQUIRE(SignDirectP2MRSpend(fips_fixture, /*slhdsa_fips205=*/true));
    BOOST_CHECK_EQUAL(SignedP2MRLeafOpcode(fips_fixture.tx), static_cast<unsigned char>(OP_CHECKSIG_SLHDSA));
    BOOST_CHECK_EQUAL(fips_fixture.tx.vin[0].scriptWitness.stack[0].size(), SLHDSA128S_SIGNATURE_SIZE);
    BOOST_CHECK(VerifyDirectP2MRSpend(fips_fixture.tx, fips_fixture.prev_coin, SLHDSA_FIPS205_SCRIPT_VERIFY_FLAGS));
    BOOST_CHECK(!VerifyDirectP2MRSpend(fips_fixture.tx, fips_fixture.prev_coin, STANDARD_SCRIPT_VERIFY_FLAGS));

    BOOST_CHECK(!VerifyDirectP2MRSpend(legacy_fixture.tx, legacy_fixture.prev_coin, SLHDSA_FIPS205_SCRIPT_VERIFY_FLAGS));
    BOOST_CHECK(VerifyDirectP2MRSpend(fips_fixture.tx, fips_fixture.prev_coin, SLHDSA_FIPS205_SCRIPT_VERIFY_FLAGS));
}

BOOST_AUTO_TEST_CASE(psbt_sign_p2mr_slhdsa_uses_c002_signature_mode)
{
    const auto seed = MakePQSeed(0x25);
    const std::vector<unsigned char> fixed_mldsa = MakePattern(MLDSA44_PUBKEY_SIZE, 0x65);
    const std::string desc = AddChecksum("mr(" + HexStr(fixed_mldsa) + ",pk_slh(" + MakeP2MRKeyPathExpr(seed, /*internal=*/false) + "))");
    auto fixture = MakeDirectP2MRSpendFixture(desc, /*prev_txid_seed=*/42);

    PartiallySignedTransaction psbt{fixture.tx};
    psbt.inputs.at(0).witness_utxo = fixture.prev_coin.out;
    const PrecomputedTransactionData txdata = PrecomputePSBTData(psbt);

    BOOST_REQUIRE(SignPSBTInput(fixture.provider,
                                psbt,
                                /*index=*/0,
                                &txdata,
                                SIGHASH_DEFAULT,
                                /*out_sigdata=*/nullptr,
                                /*finalize=*/true,
                                /*slhdsa_fips205=*/true));
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, /*input_index=*/0, &txdata, /*slhdsa_fips205=*/true));
    BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, /*input_index=*/0, &txdata, /*slhdsa_fips205=*/false));

    CMutableTransaction extracted;
    BOOST_REQUIRE(FinalizeAndExtractPSBT(psbt, extracted, /*slhdsa_fips205=*/true));
    BOOST_CHECK_EQUAL(SignedP2MRLeafOpcode(extracted), static_cast<unsigned char>(OP_CHECKSIG_SLHDSA));
    BOOST_CHECK(VerifyDirectP2MRSpend(extracted, fixture.prev_coin, SLHDSA_FIPS205_SCRIPT_VERIFY_FLAGS));
    BOOST_CHECK(!VerifyDirectP2MRSpend(extracted, fixture.prev_coin, STANDARD_SCRIPT_VERIFY_FLAGS));
}

BOOST_AUTO_TEST_CASE(sign_p2mr_prefers_mldsa_when_available_and_slhdsa_fallback_when_needed)
{
    const auto dual_seed = MakePQSeed(0x26);
    WalletDescriptor dual_desc = GeneratePQWalletDescriptor(dual_seed, /*internal=*/false);
    std::string dual_desc_str;
    BOOST_REQUIRE(dual_desc.descriptor->ToPrivateString(DUMMY_SIGNING_PROVIDER, dual_desc_str));

    auto dual_fixture = MakeDirectP2MRSpendFixture(dual_desc_str, /*prev_txid_seed=*/43);
    BOOST_REQUIRE(SignDirectP2MRSpend(dual_fixture, /*slhdsa_fips205=*/true, PQAlgorithm::ML_DSA_44));
    BOOST_CHECK_EQUAL(SignedP2MRLeafOpcode(dual_fixture.tx), static_cast<unsigned char>(OP_CHECKSIG_MLDSA));
    BOOST_CHECK_EQUAL(dual_fixture.tx.vin[0].scriptWitness.stack[0].size(), MLDSA44_SIGNATURE_SIZE);
    BOOST_CHECK(VerifyDirectP2MRSpend(dual_fixture.tx, dual_fixture.prev_coin, SLHDSA_FIPS205_SCRIPT_VERIFY_FLAGS));

    const auto slh_seed = MakePQSeed(0x27);
    const std::vector<unsigned char> fixed_mldsa = MakePattern(MLDSA44_PUBKEY_SIZE, 0x67);
    const std::string slh_fallback_desc = AddChecksum("mr(" + HexStr(fixed_mldsa) + ",pk_slh(" + MakeP2MRKeyPathExpr(slh_seed, /*internal=*/false) + "))");
    auto slh_fixture = MakeDirectP2MRSpendFixture(slh_fallback_desc, /*prev_txid_seed=*/44);
    BOOST_REQUIRE(SignDirectP2MRSpend(slh_fixture, /*slhdsa_fips205=*/true, PQAlgorithm::ML_DSA_44));
    BOOST_CHECK_EQUAL(SignedP2MRLeafOpcode(slh_fixture.tx), static_cast<unsigned char>(OP_CHECKSIG_SLHDSA));
    BOOST_CHECK_EQUAL(slh_fixture.tx.vin[0].scriptWitness.stack[0].size(), SLHDSA128S_SIGNATURE_SIZE);
    BOOST_CHECK(VerifyDirectP2MRSpend(slh_fixture.tx, slh_fixture.prev_coin, SLHDSA_FIPS205_SCRIPT_VERIFY_FLAGS));
}

BOOST_AUTO_TEST_CASE(p2mr_metadata_weight_estimator_matches_selected_algorithm)
{
    const auto seed = MakePQSeed(0x28);
    WalletDescriptor wallet_desc = GeneratePQWalletDescriptor(seed, /*internal=*/false);
    std::string desc;
    BOOST_REQUIRE(wallet_desc.descriptor->ToPrivateString(DUMMY_SIGNING_PROVIDER, desc));

    auto ml_fixture = MakeDirectP2MRSpendFixture(desc, /*prev_txid_seed=*/45);
    const auto selected_ml = CalculateSelectedP2MRInputWeight(
        ml_fixture.prev_coin.out.scriptPubKey, ml_fixture.provider, PQAlgorithm::ML_DSA_44);
    const auto selected_slh = CalculateSelectedP2MRInputWeight(
        ml_fixture.prev_coin.out.scriptPubKey, ml_fixture.provider, PQAlgorithm::SLH_DSA_128S);
    const auto maximum = CalculateMaximumP2MRInputWeight(
        ml_fixture.prev_coin.out.scriptPubKey, ml_fixture.provider);
    BOOST_REQUIRE(selected_ml);
    BOOST_REQUIRE(selected_slh);
    BOOST_REQUIRE(maximum);
    BOOST_CHECK_LT(*selected_ml, *selected_slh);
    BOOST_CHECK_GE(*maximum, *selected_slh);

    BOOST_REQUIRE(SignDirectP2MRSpend(
        ml_fixture, /*slhdsa_fips205=*/true, PQAlgorithm::ML_DSA_44));
    BOOST_CHECK_GE(*selected_ml, GetTransactionInputWeight(ml_fixture.tx.vin[0]));

    auto slh_fixture = MakeDirectP2MRSpendFixture(desc, /*prev_txid_seed=*/46);
    BOOST_REQUIRE(SignDirectP2MRSpend(
        slh_fixture, /*slhdsa_fips205=*/true, PQAlgorithm::SLH_DSA_128S));
    BOOST_CHECK_GE(*selected_slh, GetTransactionInputWeight(slh_fixture.tx.vin[0]));

    // Public metadata remains enough for a conservative maximum, but never
    // pretends that a signing path is available.
    HidingSigningProvider public_only{&ml_fixture.provider, /*hide_secret=*/true, /*hide_origin=*/false};
    BOOST_CHECK(!CalculateSelectedP2MRInputWeight(
        ml_fixture.prev_coin.out.scriptPubKey, public_only, PQAlgorithm::ML_DSA_44));
    BOOST_CHECK(CalculateMaximumP2MRInputWeight(
        ml_fixture.prev_coin.out.scriptPubKey, public_only));

    // If the preferred ML key is absent, selection must fall back to the
    // available SLH leaf without underestimating it.
    const auto fallback_seed = MakePQSeed(0x29);
    const std::vector<unsigned char> fixed_mldsa = MakePattern(MLDSA44_PUBKEY_SIZE, 0x69);
    const std::string fallback_desc = AddChecksum(
        "mr(" + HexStr(fixed_mldsa) + ",pk_slh(" +
        MakeP2MRKeyPathExpr(fallback_seed, /*internal=*/false) + "))");
    auto fallback_fixture = MakeDirectP2MRSpendFixture(fallback_desc, /*prev_txid_seed=*/47);
    const auto fallback_weight = CalculateSelectedP2MRInputWeight(
        fallback_fixture.prev_coin.out.scriptPubKey,
        fallback_fixture.provider,
        PQAlgorithm::ML_DSA_44);
    BOOST_REQUIRE(fallback_weight);
    BOOST_CHECK_GE(*fallback_weight, *selected_slh);
}

BOOST_AUTO_TEST_CASE(p2mr_metadata_weight_estimator_is_fail_closed_and_covers_policy_maxima)
{
    std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> slh_keys;
    for (size_t i{0}; i < MAX_PQ_PUBKEYS_PER_MULTISIG; ++i) {
        slh_keys.emplace_back(
            PQAlgorithm::SLH_DSA_128S,
            std::vector<unsigned char>(SLHDSA128S_PUBKEY_SIZE, static_cast<unsigned char>(i + 1)));
    }
    const auto multisig_script = BuildP2MRMultisigCTVScript(
        uint256{}, MAX_PQ_PUBKEYS_PER_MULTISIG, slh_keys);
    BOOST_REQUIRE(!multisig_script.empty());
    auto maximum_fixture = MakeP2MRWeightFixture(
        multisig_script,
        (P2MR_CONTROL_MAX_SIZE - P2MR_CONTROL_BASE_SIZE) / P2MR_CONTROL_NODE_SIZE);

    const auto maximum = CalculateMaximumP2MRInputWeight(
        maximum_fixture.script_pubkey, maximum_fixture.provider);
    BOOST_REQUIRE(maximum);
    BOOST_CHECK_GT(*maximum, 33'000);
    BOOST_CHECK_EQUAL(*maximum, GetMaximumStandardP2MRInputWeight());
    BOOST_CHECK(!HasGenericP2MRSigningPath(
        maximum_fixture.script_pubkey, maximum_fixture.provider));

    // Explicit non-default sighash bytes and empty multisig slots are part of
    // the serialized witness bound. The all-signature case exercises the
    // former; a mixed 2-of-3 leaf exercises the latter.
    CTxIn expected_maximum;
    expected_maximum.scriptWitness.stack.assign(
        MAX_PQ_PUBKEYS_PER_MULTISIG,
        std::vector<unsigned char>(SLHDSA128S_SIGNATURE_SIZE + 1));
    expected_maximum.scriptWitness.stack.push_back(multisig_script);
    expected_maximum.scriptWitness.stack.push_back(maximum_fixture.control);
    BOOST_CHECK_EQUAL(*maximum, GetTransactionInputWeight(expected_maximum));

    const std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>> mixed_keys{
        {PQAlgorithm::ML_DSA_44, MakePattern(MLDSA44_PUBKEY_SIZE, 0x10)},
        {PQAlgorithm::SLH_DSA_128S, MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x20)},
        {PQAlgorithm::ML_DSA_44, MakePattern(MLDSA44_PUBKEY_SIZE, 0x30)},
    };
    const auto mixed_script = BuildP2MRMultisigScript(/*threshold=*/2, mixed_keys);
    auto mixed_fixture = MakeP2MRWeightFixture(mixed_script, /*depth=*/1);
    const auto mixed_maximum = CalculateMaximumP2MRInputWeight(
        mixed_fixture.script_pubkey, mixed_fixture.provider);
    BOOST_REQUIRE(mixed_maximum);
    CTxIn expected_mixed;
    expected_mixed.scriptWitness.stack = {
        std::vector<unsigned char>(SLHDSA128S_SIGNATURE_SIZE + 1),
        std::vector<unsigned char>(MLDSA44_SIGNATURE_SIZE + 1),
        {},
        mixed_script,
        mixed_fixture.control,
    };
    BOOST_CHECK_EQUAL(*mixed_maximum, GetTransactionInputWeight(expected_mixed));

    // Standard CSFS/HTLC message or preimage bounds are 520 bytes; CSFS
    // signatures carry no transaction-sighash suffix.
    const auto csfs_pubkey = MakePattern(SLHDSA128S_PUBKEY_SIZE, 0x40);
    const auto csfs_script = BuildP2MRCSFSScript(PQAlgorithm::SLH_DSA_128S, csfs_pubkey);
    auto csfs_fixture = MakeP2MRWeightFixture(csfs_script, /*depth=*/0);
    const auto csfs_maximum = CalculateMaximumP2MRInputWeight(
        csfs_fixture.script_pubkey, csfs_fixture.provider);
    BOOST_REQUIRE(csfs_maximum);
    CTxIn expected_csfs;
    expected_csfs.scriptWitness.stack = {
        std::vector<unsigned char>(SLHDSA128S_SIGNATURE_SIZE),
        std::vector<unsigned char>(MAX_SCRIPT_ELEMENT_SIZE),
        csfs_script,
        csfs_fixture.control,
    };
    BOOST_CHECK_EQUAL(*csfs_maximum, GetTransactionInputWeight(expected_csfs));
    BOOST_CHECK(!HasGenericP2MRSigningPath(
        csfs_fixture.script_pubkey, csfs_fixture.provider));
    BOOST_CHECK_EQUAL(
        CalculateMaximumSignedInputSize(
            CTxOut{COIN, csfs_fixture.script_pubkey},
            COutPoint{},
            &csfs_fixture.provider,
            /*can_grind_r=*/false,
            /*coin_control=*/nullptr),
        -1);

    const auto htlc_script = BuildP2MRHTLCLeaf(
        std::vector<unsigned char>(20, 0x41), PQAlgorithm::SLH_DSA_128S, csfs_pubkey);
    BOOST_REQUIRE(!htlc_script.empty());
    auto htlc_fixture = MakeP2MRWeightFixture(htlc_script, /*depth=*/0);
    BOOST_CHECK(CalculateMaximumP2MRInputWeight(
        htlc_fixture.script_pubkey, htlc_fixture.provider));
    BOOST_CHECK(!HasGenericP2MRSigningPath(
        htlc_fixture.script_pubkey, htlc_fixture.provider));
    BOOST_CHECK_EQUAL(
        CalculateMaximumSignedInputSize(
            CTxOut{COIN, htlc_fixture.script_pubkey},
            COutPoint{},
            &htlc_fixture.provider,
            /*can_grind_r=*/false,
            /*coin_control=*/nullptr),
        -1);

    // The transaction-bound HTLC claim uses a normal PQ sighash signature and
    // the RPC's exact 32-byte preimage. Metadata can bound its maximum witness,
    // but a provider alone still cannot select the leaf without that preimage.
    const auto htlc_tx_script = BuildP2MRHTLCTxLeaf(
        std::vector<unsigned char>(20, 0x42), PQAlgorithm::SLH_DSA_128S, csfs_pubkey);
    BOOST_REQUIRE(!htlc_tx_script.empty());
    auto htlc_tx_fixture = MakeP2MRWeightFixture(htlc_tx_script, /*depth=*/0);
    const auto htlc_tx_maximum = CalculateMaximumP2MRInputWeight(
        htlc_tx_fixture.script_pubkey, htlc_tx_fixture.provider);
    BOOST_REQUIRE(htlc_tx_maximum);
    CTxIn expected_htlc_tx;
    expected_htlc_tx.scriptWitness.stack = {
        std::vector<unsigned char>(SLHDSA128S_SIGNATURE_SIZE + 1),
        std::vector<unsigned char>(32),
        htlc_tx_script,
        htlc_tx_fixture.control,
    };
    BOOST_CHECK_EQUAL(*htlc_tx_maximum, GetTransactionInputWeight(expected_htlc_tx));
    BOOST_CHECK(!CalculateSelectedP2MRInputWeight(
        htlc_tx_fixture.script_pubkey, htlc_tx_fixture.provider, PQAlgorithm::SLH_DSA_128S));
    BOOST_CHECK(!HasGenericP2MRSigningPath(
        htlc_tx_fixture.script_pubkey, htlc_tx_fixture.provider));
    BOOST_CHECK_EQUAL(
        CalculateMaximumSignedInputSize(
            CTxOut{COIN, htlc_tx_fixture.script_pubkey},
            COutPoint{},
            &htlc_tx_fixture.provider,
            /*can_grind_r=*/false,
            /*coin_control=*/nullptr),
        -1);

    // Missing, malformed, or root-inconsistent provider metadata must never
    // turn an unknown P2MR output into a solvable one.
    FlatSigningProvider empty_provider;
    BOOST_CHECK(!CalculateMaximumP2MRInputWeight(
        maximum_fixture.script_pubkey, empty_provider));

    FlatSigningProvider wrong_version{maximum_fixture.provider};
    auto& wrong_version_spend = wrong_version.p2mr_spends.begin()->second;
    const auto script_it = wrong_version_spend.scripts.begin();
    std::vector<unsigned char> bad_version_control{*script_it->second.begin()};
    wrong_version_spend.scripts.clear();
    bad_version_control[0] = 0x00;
    wrong_version_spend.scripts[multisig_script].insert(bad_version_control);
    BOOST_CHECK(!CalculateMaximumP2MRInputWeight(
        maximum_fixture.script_pubkey, wrong_version));

    FlatSigningProvider wrong_commitment{maximum_fixture.provider};
    auto& wrong_commitment_spend = wrong_commitment.p2mr_spends.begin()->second;
    std::vector<unsigned char> bad_commitment_control{*wrong_commitment_spend.scripts.begin()->second.begin()};
    wrong_commitment_spend.scripts.clear();
    bad_commitment_control.back() ^= 0x01;
    wrong_commitment_spend.scripts[multisig_script].insert(bad_commitment_control);
    BOOST_CHECK(!CalculateMaximumP2MRInputWeight(
        maximum_fixture.script_pubkey, wrong_commitment));
}

BOOST_AUTO_TEST_CASE(p2mr_specialized_leaf_is_not_automatically_selected)
{
    const auto seed = MakePQSeed(0x2a);
    const std::string hash160(40, '4');
    const std::string receive_desc = AddChecksum(
        "mr(htlc(" + hash160 + "," +
        MakeP2MRKeyPathExpr(seed, /*internal=*/false) + "))");
    const std::string change_desc = AddChecksum(
        "mr(htlc(" + hash160 + "," +
        MakeP2MRKeyPathExpr(seed, /*internal=*/true) + "))");
    const auto wallet = CreateP2MRDescriptorWalletFromStrings(
        *this, receive_desc, change_desc);

    const CTxDestination dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    CMutableTransaction funding;
    funding.vout.emplace_back(5 * COIN, GetScriptForDestination(dest));

    LOCK(wallet->cs_wallet);
    BOOST_REQUIRE(wallet->AddToWallet(
        MakeTransactionRef(funding), TxStateInactive{}, /*update_wtx=*/nullptr,
        /*fFlushOnClose=*/false));

    CCoinControl include_unsafe;
    include_unsafe.m_include_unsafe_inputs = true;
    const CoinsResult selectable = *Assert(AvailableCoins(
        *wallet, &include_unsafe, /*feerate=*/std::nullopt));
    BOOST_CHECK_EQUAL(selectable.Size(), 0U);
    BOOST_CHECK_EQUAL(CalculateMaximumSignedInputSize(
        funding.vout[0], wallet.get(), &include_unsafe), -1);
}

BOOST_AUTO_TEST_CASE(p2mr_mixed_tree_requires_an_available_generic_key)
{
    const auto seed = MakePQSeed(0x2b);
    const std::string hash160(40, '5');
    const std::string unavailable_refund_key =
        HexStr(MakePattern(MLDSA44_PUBKEY_SIZE, 0x52));
    const std::string receive_desc = AddChecksum(
        "mr(htlc(" + hash160 + "," +
        MakeP2MRKeyPathExpr(seed, /*internal=*/false) + "),refund(500," +
        unavailable_refund_key + "))");
    const std::string change_desc = AddChecksum(
        "mr(htlc(" + hash160 + "," +
        MakeP2MRKeyPathExpr(seed, /*internal=*/true) + "),refund(500," +
        unavailable_refund_key + "))");
    const auto wallet = CreateP2MRDescriptorWalletFromStrings(
        *this, receive_desc, change_desc);

    const CTxDestination dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    CMutableTransaction funding;
    funding.vout.emplace_back(5 * COIN, GetScriptForDestination(dest));

    LOCK(wallet->cs_wallet);
    BOOST_CHECK((wallet->IsMine(funding.vout[0]) & ISMINE_SPENDABLE) != ISMINE_NO);
    BOOST_REQUIRE(wallet->AddToWallet(
        MakeTransactionRef(funding), TxStateInactive{}, /*update_wtx=*/nullptr,
        /*fFlushOnClose=*/false));

    CCoinControl include_unsafe;
    include_unsafe.m_include_unsafe_inputs = true;
    const CoinsResult selectable = *Assert(AvailableCoins(
        *wallet, &include_unsafe, /*feerate=*/std::nullopt));
    BOOST_CHECK_EQUAL(selectable.Size(), 0U);
    BOOST_CHECK_EQUAL(CalculateMaximumSignedInputSize(
        funding.vout[0], wallet.get(), &include_unsafe), -1);

    // Explicit watch-only funding may use the committed tree's conservative
    // maximum so that a separate signer can later satisfy the transaction.
    include_unsafe.fAllowWatchOnly = true;
    BOOST_CHECK_GT(CalculateMaximumSignedInputSize(
        funding.vout[0], wallet.get(), &include_unsafe), 0);
}

BOOST_AUTO_TEST_CASE(sign_p2mr_transaction_multisig_leaf)
{
    const auto seed = MakePQSeed(0x31);
    const std::string receive_desc = AddChecksum(
        "mr(multi_pq(2,"
        + MakeP2MRKeyPathExprWithBranch(seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(seed, /*branch=*/1, /*internal=*/false) + ",pk_slh("
        + MakeP2MRKeyPathExprWithBranch(seed, /*branch=*/2, /*internal=*/false) + ")))");
    const std::string change_desc = AddChecksum(
        "mr(multi_pq(2,"
        + MakeP2MRKeyPathExprWithBranch(seed, /*branch=*/0, /*internal=*/true) + ","
        + MakeP2MRKeyPathExprWithBranch(seed, /*branch=*/1, /*internal=*/true) + ",pk_slh("
        + MakeP2MRKeyPathExprWithBranch(seed, /*branch=*/2, /*internal=*/true) + ")))");
    const auto wallet = CreateP2MRDescriptorWalletFromStrings(*this, receive_desc, change_desc);

    const CTxDestination from_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination to_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const COutPoint prevout{Txid::FromUint256(uint256{3}), 0};
    const CAmount input_value{30 * COIN};
    Coin prev_coin{CTxOut{input_value, GetScriptForDestination(from_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(input_value - 1200, GetScriptForDestination(to_dest));

    BOOST_REQUIRE(SignAndCheckP2MRTransaction(wallet, tx, prev_coin));
    BOOST_REQUIRE_EQUAL(tx.vin[0].scriptWitness.stack.size(), 5U);

    const auto& sig3 = tx.vin[0].scriptWitness.stack[0];
    const auto& sig2 = tx.vin[0].scriptWitness.stack[1];
    const auto& sig1 = tx.vin[0].scriptWitness.stack[2];
    const auto& leaf_script = tx.vin[0].scriptWitness.stack[3];
    const auto& control = tx.vin[0].scriptWitness.stack[4];
    const size_t non_empty_sigs = (!sig1.empty() ? 1U : 0U) + (!sig2.empty() ? 1U : 0U) + (!sig3.empty() ? 1U : 0U);
    BOOST_CHECK_EQUAL(non_empty_sigs, 2U);
    BOOST_CHECK(!leaf_script.empty());
    BOOST_CHECK(leaf_script.size() > 3U);
    BOOST_CHECK_EQUAL(leaf_script[leaf_script.size() - 1], static_cast<unsigned char>(OP_NUMEQUAL));
    BOOST_CHECK_EQUAL(leaf_script[leaf_script.size() - 2], static_cast<unsigned char>(OP_2));
    BOOST_CHECK_EQUAL(control.size(), 1U);
    BOOST_CHECK_EQUAL(control[0], P2MR_LEAF_VERSION);
}

BOOST_AUTO_TEST_CASE(sign_p2mr_fee_bearing_rebalance_preserves_shielded_bundle)
{
    const auto wallet = CreateP2MRDescriptorWallet(*this);
    const CTxDestination from_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination to_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));

    const COutPoint prevout{Txid::FromUint256(uint256{44}), 0};
    const CAmount input_value{20 * COIN};
    Coin prev_coin{CTxOut{input_value, GetScriptForDestination(from_dest)}, /*nHeight=*/150, /*fCoinBase=*/true};

    auto fixture = test::shielded::BuildV2RebalanceFixture();
    fixture.tx.vin = {CTxIn{prevout}};
    fixture.tx.vout = {CTxOut{input_value - 1000, GetScriptForDestination(to_dest)}};

    std::map<COutPoint, Coin> coins;
    coins.emplace(prevout, prev_coin);
    std::map<int, bilingual_str> input_errors;
    BOOST_REQUIRE(wallet->SignTransaction(fixture.tx, coins, SIGHASH_ALL, input_errors, /*inputs_amount_sum=*/nullptr));
    BOOST_CHECK(input_errors.empty());

    const CTransaction signed_tx{fixture.tx};
    PrecomputedTransactionData txdata;
    txdata.Init(signed_tx, {prev_coin.out}, /*force=*/true);
    ScriptError serror = SCRIPT_ERR_OK;
    BOOST_REQUIRE(VerifyScript(fixture.tx.vin[0].scriptSig,
                               prev_coin.out.scriptPubKey,
                               &fixture.tx.vin[0].scriptWitness,
                               STANDARD_SCRIPT_VERIFY_FLAGS,
                               TransactionSignatureChecker(&signed_tx, 0, prev_coin.out.nValue, txdata, MissingDataBehavior::FAIL),
                               &serror));
    BOOST_CHECK_EQUAL(serror, SCRIPT_ERR_OK);

    DataStream stream;
    stream << TX_WITH_WITNESS(fixture.tx);
    CMutableTransaction decoded;
    stream >> TX_WITH_WITNESS(decoded);

    BOOST_REQUIRE(decoded.HasShieldedBundle());
    BOOST_REQUIRE(decoded.HasWitness());
    BOOST_REQUIRE(decoded.GetShieldedBundle().CheckStructure());

    TxValidationState state;
    BOOST_CHECK(CheckTransaction(CTransaction{decoded}, state));
    BOOST_CHECK(state.IsValid());
}

BOOST_AUTO_TEST_CASE(p2mr_backup_estimator_covers_actual_weight)
{
    const auto seed = MakePQSeed(0x41);
    const std::vector<unsigned char> fixed_mldsa = MakePattern(MLDSA44_PUBKEY_SIZE, 0x61);
    const std::string receive_desc = AddChecksum("mr(" + HexStr(fixed_mldsa) + ",pk_slh(" + MakeP2MRKeyPathExpr(seed, /*internal=*/false) + "))");
    const std::string change_desc = AddChecksum("mr(" + HexStr(fixed_mldsa) + ",pk_slh(" + MakeP2MRKeyPathExpr(seed, /*internal=*/true) + "))");
    const auto wallet = CreateP2MRDescriptorWalletFromStrings(*this, receive_desc, change_desc);

    const CTxDestination from_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination to_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const COutPoint prevout{Txid::FromUint256(uint256{22}), 0};
    const CAmount input_value{25 * COIN};
    Coin prev_coin{CTxOut{input_value, GetScriptForDestination(from_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(input_value - 1500, GetScriptForDestination(to_dest));

    const std::unique_ptr<SigningProvider> provider{wallet->GetSolvingProvider(prev_coin.out.scriptPubKey)};
    BOOST_REQUIRE(provider);
    const int provider_estimate = CalculateMaximumSignedInputSize(
        prev_coin.out, prevout, provider.get(), wallet->CanGrindR(), /*coin_control=*/nullptr);
    BOOST_REQUIRE_GT(provider_estimate, 0);

    const TxSize estimated = CalculateMaximumSignedTxSize(CTransaction{tx}, wallet.get(), std::vector<CTxOut>{prev_coin.out});
    BOOST_REQUIRE(estimated.weight > 0);
    BOOST_REQUIRE(estimated.vsize > 0);

    BOOST_REQUIRE(SignAndCheckP2MRTransaction(wallet, tx, prev_coin));

    const CTransaction tx_signed{tx};
    const int64_t actual_weight = GetTransactionWeight(tx_signed);
    const int64_t actual_vsize = GetVirtualTransactionSize(tx_signed);
    const int64_t actual_input_vsize = GetVirtualTransactionSize(GetTransactionInputWeight(tx.vin[0]), 0, 0);
    BOOST_CHECK_GE(provider_estimate, actual_input_vsize);
    BOOST_CHECK_LT(provider_estimate - actual_input_vsize, 100);
    BOOST_CHECK_GE(estimated.weight, actual_weight);
    BOOST_CHECK_GE(estimated.vsize, actual_vsize);
    BOOST_CHECK_LT(estimated.weight - actual_weight, 5000);
}

BOOST_AUTO_TEST_CASE(p2mr_primary_estimator_covers_actual_weight)
{
    const auto wallet = CreateP2MRDescriptorWallet(*this);
    const CTxDestination from_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination to_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const COutPoint prevout{Txid::FromUint256(uint256{23}), 0};
    const CAmount input_value{50 * COIN};
    Coin prev_coin{CTxOut{input_value, GetScriptForDestination(from_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};

    const auto spkmans = wallet->GetScriptPubKeyMans(prev_coin.out.scriptPubKey);
    BOOST_REQUIRE_EQUAL(spkmans.size(), 1);
    const auto* desc_spkman = dynamic_cast<const DescriptorScriptPubKeyMan*>(*spkmans.begin());
    BOOST_REQUIRE(desc_spkman != nullptr);
    const auto sizing_provider = desc_spkman->GetP2MRSizingProvider(prev_coin.out.scriptPubKey);
    BOOST_REQUIRE(sizing_provider);
    BOOST_CHECK(sizing_provider->pq_keys.empty());
    BOOST_CHECK(!sizing_provider->pq_signing_key_availability.empty());
    BOOST_CHECK(CalculateSelectedP2MRInputWeight(
        prev_coin.out.scriptPubKey, *sizing_provider, PQAlgorithm::ML_DSA_44));

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(input_value - 2000, GetScriptForDestination(to_dest));

    const std::unique_ptr<SigningProvider> provider{wallet->GetSolvingProvider(prev_coin.out.scriptPubKey)};
    BOOST_REQUIRE(provider);
    const int provider_estimate = CalculateMaximumSignedInputSize(
        prev_coin.out, prevout, provider.get(), wallet->CanGrindR(), /*coin_control=*/nullptr);
    BOOST_REQUIRE_GT(provider_estimate, 0);

    const TxSize estimated = CalculateMaximumSignedTxSize(CTransaction{tx}, wallet.get(), std::vector<CTxOut>{prev_coin.out});
    BOOST_REQUIRE(estimated.weight > 0);
    BOOST_REQUIRE(estimated.vsize > 0);

    BOOST_REQUIRE(SignAndCheckP2MRTransaction(wallet, tx, prev_coin));

    const CTransaction tx_signed{tx};
    const int64_t actual_weight = GetTransactionWeight(tx_signed);
    const int64_t actual_vsize = GetVirtualTransactionSize(tx_signed);
    const int64_t actual_input_vsize = GetVirtualTransactionSize(GetTransactionInputWeight(tx.vin[0]), 0, 0);
    BOOST_CHECK_GE(provider_estimate, actual_input_vsize);
    // Provider-only sizing deliberately chooses the larger SLH-DSA leaf when
    // key availability is unknown; the wallet-aware estimator above selects
    // the actual default ML-DSA path.
    BOOST_CHECK_LE(provider_estimate - actual_input_vsize,
                   static_cast<int64_t>(SLHDSA128S_SIGNATURE_SIZE - MLDSA44_SIGNATURE_SIZE + 500));
    BOOST_CHECK_GE(estimated.weight, actual_weight);
    BOOST_CHECK_GE(estimated.vsize, actual_vsize);
    // The estimator intentionally uses a conservative worst-case P2MR input bound.
    BOOST_CHECK_LT(estimated.weight - actual_weight, 5000);
}

BOOST_AUTO_TEST_CASE(p2mr_transaction_weight_calculation)
{
    const auto wallet = CreateP2MRDescriptorWallet(*this);
    const CTxDestination from_dest = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination to_dest_1 = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination to_dest_2 = *Assert(wallet->GetNewDestination(OutputType::P2MR, ""));

    const COutPoint prevout{Txid::FromUint256(uint256{3}), 0};
    const CAmount input_value{50 * COIN};
    const CAmount output_1{25 * COIN};
    const CAmount fee{2000};
    const CAmount output_2{input_value - output_1 - fee};
    Coin prev_coin{CTxOut{input_value, GetScriptForDestination(from_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(output_1, GetScriptForDestination(to_dest_1));
    tx.vout.emplace_back(output_2, GetScriptForDestination(to_dest_2));

    BOOST_REQUIRE(SignAndCheckP2MRTransaction(wallet, tx, prev_coin));
    BOOST_REQUIRE_EQUAL(tx.vin[0].scriptWitness.stack.size(), 3U);

    const CTransaction tx_const{tx};
    const int64_t weight = GetTransactionWeight(tx_const);
    const int64_t total_size = tx_const.GetTotalSize();
    const int64_t sig_size = tx.vin[0].scriptWitness.stack[0].size();
    const int64_t sig_delta = sig_size - MLDSA44_SIGNATURE_SIZE;
    const int64_t expected_weight = 4294 + sig_delta;
    const int64_t expected_total_size = 3883 + sig_delta;

    BOOST_CHECK(weight > 3500);
    BOOST_CHECK(weight < 12000);
    BOOST_CHECK(total_size > 3000);
    BOOST_CHECK(total_size < 11000);
    BOOST_CHECK(std::llabs(weight - expected_weight) < 1500);
    BOOST_CHECK(std::llabs(total_size - expected_total_size) < 1500);
}

BOOST_AUTO_TEST_CASE(wallet_rejects_non_p2mr_address_type)
{
    const auto wallet = CreateP2MRDescriptorWallet(*this);
    const auto bech32_dest = wallet->GetNewDestination(OutputType::BECH32, "");
    BOOST_CHECK(!bech32_dest);
}

BOOST_AUTO_TEST_CASE(watch_only_p2mr_wallet_with_cache_cannot_sign)
{
    const auto seed = MakePQSeed(0x51);
    WalletDescriptor receive = MakeRangedDescriptor(seed, /*internal=*/false);
    WalletDescriptor change = MakeRangedDescriptor(seed, /*internal=*/true);
    const std::string receive_desc_str = receive.descriptor->ToString();
    const std::string change_desc_str = change.descriptor->ToString();

    std::string receive_desc_priv;
    std::string change_desc_priv;
    BOOST_REQUIRE(receive.descriptor->ToPrivateString(DUMMY_SIGNING_PROVIDER, receive_desc_priv));
    BOOST_REQUIRE(change.descriptor->ToPrivateString(DUMMY_SIGNING_PROVIDER, change_desc_priv));

    // Build caches based on a parsed descriptor so key expression indices match what the wallet will use.
    FlatSigningProvider receive_parse_out;
    std::string receive_parse_error;
    auto receive_parsed = Parse(receive_desc_priv, receive_parse_out, receive_parse_error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!receive_parsed.empty(), "receive descriptor parse failed: " + receive_parse_error);
    BOOST_REQUIRE_EQUAL(receive_parsed.size(), 1U);

    FlatSigningProvider change_parse_out;
    std::string change_parse_error;
    auto change_parsed = Parse(change_desc_priv, change_parse_out, change_parse_error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!change_parsed.empty(), "change descriptor parse failed: " + change_parse_error);
    BOOST_REQUIRE_EQUAL(change_parsed.size(), 1U);

    DescriptorCache receive_cache;
    DescriptorCache change_cache;
    for (int pos = 0; pos < P2MR_TEST_RANGE_END; ++pos) {
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts;
        DescriptorCache tmp_cache;
        BOOST_REQUIRE(receive_parsed[0]->Expand(pos, DUMMY_SIGNING_PROVIDER, scripts, out_keys, &tmp_cache));
        receive_cache.MergeAndDiff(tmp_cache);
    }
    for (int pos = 0; pos < P2MR_TEST_RANGE_END; ++pos) {
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts;
        DescriptorCache tmp_cache;
        BOOST_REQUIRE(change_parsed[0]->Expand(pos, DUMMY_SIGNING_PROVIDER, scripts, out_keys, &tmp_cache));
        change_cache.MergeAndDiff(tmp_cache);
    }

    // Sanity: a separately parsed descriptor must be able to expand from the populated cache for each range index.
    FlatSigningProvider receive_parse_again;
    std::string receive_parse_again_err;
    auto receive_parsed_again = Parse(receive_desc_str, receive_parse_again, receive_parse_again_err, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!receive_parsed_again.empty(), "receive descriptor parse failed: " + receive_parse_again_err);
    BOOST_REQUIRE_EQUAL(receive_parsed_again.size(), 1U);
    FlatSigningProvider change_parse_again;
    std::string change_parse_again_err;
    auto change_parsed_again = Parse(change_desc_str, change_parse_again, change_parse_again_err, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!change_parsed_again.empty(), "change descriptor parse failed: " + change_parse_again_err);
    BOOST_REQUIRE_EQUAL(change_parsed_again.size(), 1U);

    for (int pos = 0; pos < P2MR_TEST_RANGE_END; ++pos) {
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts;
        BOOST_REQUIRE(receive_parsed_again[0]->ExpandFromCache(pos, receive_cache, scripts, out_keys));
        BOOST_REQUIRE(!scripts.empty());
    }
    for (int pos = 0; pos < P2MR_TEST_RANGE_END; ++pos) {
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts;
        BOOST_REQUIRE(change_parsed_again[0]->ExpandFromCache(pos, change_cache, scripts, out_keys));
        BOOST_REQUIRE(!scripts.empty());
    }

    // Create a watch-only wallet (no private keys), but seed it with the PQ pubkey caches so it can derive addresses.
    const auto watch_wallet = CreateP2MRDescriptorWalletFromStrings(*this,
                                                                    receive_desc_str,
                                                                    change_desc_str,
                                                                    &receive_cache,
                                                                    &change_cache);
    const CTxDestination from_dest = *Assert(watch_wallet->GetNewDestination(OutputType::P2MR, ""));
    const CTxDestination to_dest = *Assert(watch_wallet->GetNewDestination(OutputType::P2MR, ""));

    const COutPoint prevout{Txid::FromUint256(uint256{123}), 0};
    const CAmount input_value{10 * COIN};
    Coin prev_coin{CTxOut{input_value, GetScriptForDestination(from_dest)}, /*nHeight=*/1, /*fCoinBase=*/false};

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(input_value - 1000, GetScriptForDestination(to_dest));

    std::map<COutPoint, Coin> coins;
    coins.emplace(tx.vin[0].prevout, prev_coin);
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(!watch_wallet->SignTransaction(tx, coins, SIGHASH_DEFAULT, input_errors, /*inputs_amount_sum=*/nullptr));
    BOOST_CHECK(!input_errors.empty());

    const CTransaction tx_const{tx};
    PrecomputedTransactionData txdata;
    txdata.Init(tx_const, {prev_coin.out}, /*force=*/true);
    ScriptError serror = SCRIPT_ERR_OK;
    BOOST_CHECK(!VerifyScript(
        tx.vin[0].scriptSig,
        prev_coin.out.scriptPubKey,
        &tx.vin[0].scriptWitness,
        STANDARD_SCRIPT_VERIFY_FLAGS,
        TransactionSignatureChecker(&tx_const, 0, prev_coin.out.nValue, txdata, MissingDataBehavior::FAIL),
        &serror));
    BOOST_CHECK(serror != SCRIPT_ERR_OK);
}

// ============================================================================
// PQ-native wallet tests (no ECDSA key involved)
// ============================================================================

BOOST_AUTO_TEST_CASE(pq_native_generate_descriptor)
{
    // Test that GeneratePQWalletDescriptor creates a valid PQ-native descriptor
    std::array<unsigned char, 32> pq_seed{};
    for (size_t i = 0; i < 32; ++i) pq_seed[i] = static_cast<unsigned char>(i + 0xA0);

    auto w_desc = GeneratePQWalletDescriptor(pq_seed, /*internal=*/false);
    BOOST_CHECK(w_desc.descriptor);

    // Descriptor string should contain pqhd()
    std::string desc_str = w_desc.descriptor->ToString();
    BOOST_CHECK(desc_str.find("pqhd(") != std::string::npos);
    BOOST_CHECK(desc_str.find("mr(") != std::string::npos);
    BOOST_CHECK(desc_str.find("pk_slh(") != std::string::npos);

    // Seed must NOT appear in public form
    std::string seed_hex = HexStr(pq_seed);
    BOOST_CHECK(desc_str.find(seed_hex) == std::string::npos);

    // Internal descriptor should be different
    auto w_desc_int = GeneratePQWalletDescriptor(pq_seed, /*internal=*/true);
    BOOST_CHECK(w_desc_int.descriptor);
    BOOST_CHECK(w_desc.id != w_desc_int.id);
}

BOOST_AUTO_TEST_CASE(pq_native_descriptor_expansion)
{
    // Test that PQ-native descriptors can expand to produce valid scripts
    std::array<unsigned char, 32> pq_seed{};
    for (size_t i = 0; i < 32; ++i) pq_seed[i] = static_cast<unsigned char>(i + 0xB0);

    auto w_desc = GeneratePQWalletDescriptor(pq_seed, /*internal=*/false);
    BOOST_CHECK(w_desc.descriptor);

    // Expand at position 0
    FlatSigningProvider keys;
    std::vector<CScript> scripts;
    w_desc.descriptor->Expand(0, keys, scripts, keys);
    BOOST_REQUIRE(!scripts.empty());

    // Script should be a valid P2MR output (OP_2 + 32 bytes)
    BOOST_CHECK_EQUAL(scripts[0].size(), 34u); // 1 (OP_2) + 1 (push 32) + 32 (merkle root)

    // Expand at position 1 should produce a different script
    std::vector<CScript> scripts1;
    w_desc.descriptor->Expand(1, keys, scripts1, keys);
    BOOST_REQUIRE(!scripts1.empty());
    BOOST_CHECK(scripts[0] != scripts1[0]);

    // ExpandPrivate should produce PQ keys
    FlatSigningProvider priv_keys;
    w_desc.descriptor->Expand(0, keys, scripts, priv_keys);
    w_desc.descriptor->ExpandPrivate(0, keys, priv_keys);
    BOOST_CHECK(!priv_keys.pq_keys.empty());
}

BOOST_AUTO_TEST_CASE(pq_seed_survives_descriptor_import_roundtrip)
{
    // Verify that PQ seeds persist through the AddWalletDescriptor path
    // (simulating importdescriptors). Previously, the seed embedded in
    // pqhd(hexseed/...) was lost because WalletDescriptor serialization
    // uses the fingerprint-only public form.
    std::array<unsigned char, 32> pq_seed = MakePQSeed(0xC0);

    // Generate descriptor from seed (private form embeds full seed)
    auto w_desc = GeneratePQWalletDescriptor(pq_seed, /*internal=*/false);
    BOOST_REQUIRE(w_desc.descriptor);

    // Verify seed is present in the parsed descriptor
    auto extracted = w_desc.descriptor->ExtractPQSeed();
    BOOST_REQUIRE(extracted.has_value());
    BOOST_CHECK(extracted.value() == pq_seed);

    // Get private descriptor string (should contain full hex seed)
    FlatSigningProvider dummy_provider;
    std::string priv_str;
    BOOST_REQUIRE(w_desc.descriptor->ToPrivateString(dummy_provider, priv_str));
    std::string seed_hex = HexStr(pq_seed);
    BOOST_CHECK_MESSAGE(priv_str.find(seed_hex) != std::string::npos,
                        "Private descriptor string should contain the full hex seed");

    // Simulate import: parse the private string back
    FlatSigningProvider import_keys;
    std::string parse_error;
    auto reparsed = Parse(priv_str, import_keys, parse_error, /*require_checksum=*/false);
    BOOST_REQUIRE_MESSAGE(!reparsed.empty(), "Failed to re-parse private descriptor: " + parse_error);

    // Verify the re-parsed descriptor still has the seed
    auto reparsed_seed = reparsed[0]->ExtractPQSeed();
    BOOST_REQUIRE(reparsed_seed.has_value());
    BOOST_CHECK(reparsed_seed.value() == pq_seed);

    // Create wallet and import via AddWalletDescriptor
    auto wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->m_keypool_size = 2;

        WalletDescriptor import_desc{std::move(reparsed[0]),
                                     static_cast<uint64_t>(GetTime()),
                                     /*range_start=*/0, /*range_end=*/2, /*next_index=*/0};
        auto* spkm = wallet->AddWalletDescriptor(import_desc, import_keys, "", /*internal=*/false);
        BOOST_REQUIRE(spkm != nullptr);

        // Verify the PQ seed was persisted to the database
        WalletBatch batch(wallet->GetDatabase());
        std::vector<unsigned char> db_seed;
        bool have_seed = batch.ReadPQDescriptorSeed(spkm->GetID(), db_seed);
        BOOST_CHECK_MESSAGE(have_seed, "PQ seed should be persisted in database after import");
        if (have_seed) {
            BOOST_CHECK_EQUAL(db_seed.size(), 32u);
            BOOST_CHECK(std::equal(db_seed.begin(), db_seed.end(), pq_seed.begin()));
            memory_cleanse(db_seed.data(), db_seed.size());
        }
    }
}

// =============================================================================
// Cross-descriptor PQ key merge tests
// =============================================================================

// Helper: derive ML-DSA public key from a seed at a given position using a solo
// descriptor.  Returns the raw 1312-byte ML-DSA pubkey.
static std::vector<unsigned char> DerivePQPubkeyAtPos(
    const std::array<unsigned char, 32>& seed, uint32_t branch, int pos)
{
    const std::string key_expr = MakeP2MRKeyPathExprWithBranch(seed, branch, /*internal=*/false);
    const std::string desc_str = AddChecksum("mr(" + key_expr + ",pk_slh(" + key_expr + "))");
    FlatSigningProvider parse_keys;
    std::string error;
    auto parsed = Parse(desc_str, parse_keys, error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), "DerivePQPubkeyAtPos: parse failed: " + error);

    FlatSigningProvider out_keys;
    std::vector<CScript> scripts;
    parsed[0]->Expand(pos, DUMMY_SIGNING_PROVIDER, scripts, out_keys);
    parsed[0]->ExpandPrivate(pos, parse_keys, out_keys);

    for (const auto& [pub, key] : out_keys.pq_keys) {
        if (pub.size() == MLDSA44_PUBKEY_SIZE) return pub;
    }
    BOOST_FAIL("DerivePQPubkeyAtPos: no ML-DSA pubkey found");
    return {};
}

BOOST_AUTO_TEST_CASE(cross_descriptor_pq_key_merge_signs_multisig)
{
    // Scenario: A wallet has a sortedmulti_pq(2,...) multisig descriptor with
    // FIXED inline public keys (no seeds).  Separately, the wallet also holds
    // solo descriptors whose seeds can derive the private keys for 2 of the 3
    // fixed pubkeys.  The cross-descriptor merge in CWallet::SignTransaction
    // should find those private keys and allow signing.

    const auto seed_a = MakePQSeed(0xA1);
    const auto seed_b = MakePQSeed(0xB1);
    const auto seed_c = MakePQSeed(0xC1);

    // Derive the ML-DSA pubkeys at position 0 from each seed (branch 0).
    const auto pubkey_a = DerivePQPubkeyAtPos(seed_a, /*branch=*/0, /*pos=*/0);
    const auto pubkey_b = DerivePQPubkeyAtPos(seed_b, /*branch=*/0, /*pos=*/0);
    const auto pubkey_c = DerivePQPubkeyAtPos(seed_c, /*branch=*/0, /*pos=*/0);

    BOOST_REQUIRE_EQUAL(pubkey_a.size(), MLDSA44_PUBKEY_SIZE);
    BOOST_REQUIRE_EQUAL(pubkey_b.size(), MLDSA44_PUBKEY_SIZE);
    BOOST_REQUIRE_EQUAL(pubkey_c.size(), MLDSA44_PUBKEY_SIZE);

    // Build fixed-pubkey multisig descriptor (no seeds — public only).
    const std::string multisig_desc = AddChecksum(
        "mr(sortedmulti_pq(2," + HexStr(pubkey_a) + "," + HexStr(pubkey_b) + "," + HexStr(pubkey_c) + "))");

    // Expand the multisig descriptor at position 0 to get the scriptPubKey.
    // Fixed-pubkey descriptors are non-ranged, so we expand manually rather
    // than using GetNewDestination().
    CScript multisig_spk;
    {
        FlatSigningProvider keys;
        std::string error;
        auto parsed = Parse(multisig_desc, keys, error, /*require_checksum=*/true);
        BOOST_REQUIRE_MESSAGE(!parsed.empty(), "multisig expand parse failed: " + error);
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts;
        BOOST_REQUIRE(parsed[0]->Expand(0, DUMMY_SIGNING_PROVIDER, scripts, out_keys));
        BOOST_REQUIRE(!scripts.empty());
        multisig_spk = scripts[0];
    }

    // Build the wallet with three descriptors:
    //   1. multisig (non-ranged, no seeds, fixed pubkeys)
    //   2. solo for seed_a (can derive pubkey_a)
    //   3. solo for seed_b (can derive pubkey_b)
    auto wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet->m_keypool_size = P2MR_TEST_RANGE_END;

    // 1. Add multisig descriptor (non-ranged: range_end=0)
    {
        FlatSigningProvider keys;
        std::string error;
        auto parsed = Parse(multisig_desc, keys, error, /*require_checksum=*/true);
        BOOST_REQUIRE_MESSAGE(!parsed.empty(), "multisig parse failed: " + error);
        WalletDescriptor wd{std::move(parsed[0]), static_cast<uint64_t>(GetTime()),
                            /*range_start=*/0, /*range_end=*/0, /*next_index=*/0};
        auto* spkm = wallet->AddWalletDescriptor(wd, keys, "", /*internal=*/false);
        BOOST_REQUIRE(spkm);
    }
    // 2. Solo descriptor for seed_a (provides PQ private key for pubkey_a)
    {
        const std::string key_expr = MakeP2MRKeyPathExprWithBranch(seed_a, /*branch=*/0, /*internal=*/false);
        const std::string solo_desc = AddChecksum("mr(" + key_expr + ",pk_slh(" + key_expr + "))");
        FlatSigningProvider keys;
        std::string error;
        auto parsed = Parse(solo_desc, keys, error, /*require_checksum=*/true);
        BOOST_REQUIRE_MESSAGE(!parsed.empty(), "solo A parse failed: " + error);
        WalletDescriptor wd{std::move(parsed[0]), static_cast<uint64_t>(GetTime()),
                            /*range_start=*/0, /*range_end=*/P2MR_TEST_RANGE_END, /*next_index=*/0};
        wallet->AddWalletDescriptor(wd, keys, "", /*internal=*/false);
    }
    // 3. Solo descriptor for seed_b (provides PQ private key for pubkey_b)
    {
        const std::string key_expr = MakeP2MRKeyPathExprWithBranch(seed_b, /*branch=*/0, /*internal=*/false);
        const std::string solo_desc = AddChecksum("mr(" + key_expr + ",pk_slh(" + key_expr + "))");
        FlatSigningProvider keys;
        std::string error;
        auto parsed = Parse(solo_desc, keys, error, /*require_checksum=*/true);
        BOOST_REQUIRE_MESSAGE(!parsed.empty(), "solo B parse failed: " + error);
        WalletDescriptor wd{std::move(parsed[0]), static_cast<uint64_t>(GetTime()),
                            /*range_start=*/0, /*range_end=*/P2MR_TEST_RANGE_END, /*next_index=*/0};
        wallet->AddWalletDescriptor(wd, keys, "", /*internal=*/false);
    }

    const COutPoint prevout{Txid::FromUint256(uint256{99}), 0};
    const CAmount input_value{20 * COIN};
    Coin prev_coin{CTxOut{input_value, multisig_spk}, /*nHeight=*/1, /*fCoinBase=*/false};

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(input_value - 1500, multisig_spk);

    // Without the cross-descriptor merge, this would fail because the multisig
    // descriptor has no PQ seeds.  With the merge, private keys from the solo
    // descriptors are located and signing succeeds.
    BOOST_REQUIRE(SignAndCheckP2MRTransaction(wallet, tx, prev_coin));

    // Verify the witness has the expected multisig structure (5 stack items:
    // sig3, sig2, sig1, leaf_script, control).
    BOOST_REQUIRE_EQUAL(tx.vin[0].scriptWitness.stack.size(), 5U);
    const auto& sig3 = tx.vin[0].scriptWitness.stack[0];
    const auto& sig2 = tx.vin[0].scriptWitness.stack[1];
    const auto& sig1 = tx.vin[0].scriptWitness.stack[2];
    const size_t non_empty_sigs = (!sig1.empty() ? 1U : 0U) + (!sig2.empty() ? 1U : 0U) + (!sig3.empty() ? 1U : 0U);
    BOOST_CHECK_GE(non_empty_sigs, 2U);
}

BOOST_AUTO_TEST_CASE(cross_descriptor_merge_fails_without_enough_keys)
{
    // Same setup but only 1 solo descriptor (need 2 of 3 for threshold).
    // Signing should fail.
    const auto seed_a = MakePQSeed(0xA2);
    const auto seed_b = MakePQSeed(0xB2);
    const auto seed_c = MakePQSeed(0xC2);

    const auto pubkey_a = DerivePQPubkeyAtPos(seed_a, /*branch=*/0, /*pos=*/0);
    const auto pubkey_b = DerivePQPubkeyAtPos(seed_b, /*branch=*/0, /*pos=*/0);
    const auto pubkey_c = DerivePQPubkeyAtPos(seed_c, /*branch=*/0, /*pos=*/0);

    const std::string multisig_desc = AddChecksum(
        "mr(sortedmulti_pq(2," + HexStr(pubkey_a) + "," + HexStr(pubkey_b) + "," + HexStr(pubkey_c) + "))");

    // Expand multisig descriptor to get the scriptPubKey.
    CScript multisig_spk;
    {
        FlatSigningProvider keys;
        std::string error;
        auto parsed = Parse(multisig_desc, keys, error, /*require_checksum=*/true);
        BOOST_REQUIRE(!parsed.empty());
        FlatSigningProvider out_keys;
        std::vector<CScript> scripts;
        BOOST_REQUIRE(parsed[0]->Expand(0, DUMMY_SIGNING_PROVIDER, scripts, out_keys));
        BOOST_REQUIRE(!scripts.empty());
        multisig_spk = scripts[0];
    }

    auto wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    LOCK(wallet->cs_wallet);
    wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
    wallet->m_keypool_size = P2MR_TEST_RANGE_END;

    // Add multisig (non-ranged)
    {
        FlatSigningProvider keys;
        std::string error;
        auto parsed = Parse(multisig_desc, keys, error, /*require_checksum=*/true);
        BOOST_REQUIRE(!parsed.empty());
        WalletDescriptor wd{std::move(parsed[0]), static_cast<uint64_t>(GetTime()), 0, 0, 0};
        auto* spkm = wallet->AddWalletDescriptor(wd, keys, "", /*internal=*/false);
        BOOST_REQUIRE(spkm);
    }
    // Only add ONE solo descriptor (seed_a)
    {
        const std::string key_expr = MakeP2MRKeyPathExprWithBranch(seed_a, /*branch=*/0, /*internal=*/false);
        const std::string solo_desc = AddChecksum("mr(" + key_expr + ",pk_slh(" + key_expr + "))");
        FlatSigningProvider keys;
        std::string error;
        auto parsed = Parse(solo_desc, keys, error, /*require_checksum=*/true);
        BOOST_REQUIRE(!parsed.empty());
        WalletDescriptor wd{std::move(parsed[0]), static_cast<uint64_t>(GetTime()), 0, P2MR_TEST_RANGE_END, 0};
        wallet->AddWalletDescriptor(wd, keys, "", /*internal=*/false);
    }

    const COutPoint prevout{Txid::FromUint256(uint256{100}), 0};
    const CAmount input_value{15 * COIN};
    Coin prev_coin{CTxOut{input_value, multisig_spk}, 1, false};

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(input_value - 1500, multisig_spk);

    // Should fail: only 1 of 2 required private keys available
    std::map<COutPoint, Coin> coins;
    coins.emplace(tx.vin[0].prevout, prev_coin);
    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(!wallet->SignTransaction(tx, coins, SIGHASH_DEFAULT, input_errors, /*inputs_amount_sum=*/nullptr));
}

BOOST_AUTO_TEST_CASE(extract_pq_seed_returns_nullopt_for_fingerprint_only)
{
    // Fingerprint-only (public) descriptor should NOT have an extractable seed
    std::array<unsigned char, 32> pq_seed = MakePQSeed(0xD0);
    auto w_desc = GeneratePQWalletDescriptor(pq_seed, /*internal=*/false);

    // Public form string (fingerprint only)
    std::string pub_str = w_desc.descriptor->ToString();

    FlatSigningProvider keys;
    std::string error;
    auto parsed = Parse(pub_str, keys, error, /*require_checksum=*/false);
    BOOST_REQUIRE(!parsed.empty());

    auto extracted = parsed[0]->ExtractPQSeed();
    BOOST_CHECK_MESSAGE(!extracted.has_value(),
                        "Public-form descriptor should not yield an extractable PQ seed");
}

// =============================================================================
// Multisig PQ seed persistence tests
// =============================================================================

BOOST_AUTO_TEST_CASE(multisig_pq_seed_persistence_roundtrip)
{
    // A multisig descriptor with pqhd() providers using DIFFERENT seeds
    // must persist ALL seeds and restore them on reload. Previously only
    // one seed was persisted, breaking key derivation for providers that
    // used a different seed.

    const auto seed_a = MakePQSeed(0xE1);
    const auto seed_b = MakePQSeed(0xE2);

    // Build a multi_pq(2,...) descriptor with 2 keys from different seeds
    // and a third SLH-DSA key from seed_a (branch 2).
    const std::string desc_str = AddChecksum(
        "mr(multi_pq(2,"
        + MakeP2MRKeyPathExprWithBranch(seed_a, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(seed_b, /*branch=*/0, /*internal=*/false) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(seed_a, /*branch=*/2, /*internal=*/false) + ")))");

    // Parse the descriptor (with full seeds).
    FlatSigningProvider parse_keys;
    std::string parse_error;
    auto parsed = Parse(desc_str, parse_keys, parse_error, /*require_checksum=*/true);
    BOOST_REQUIRE_MESSAGE(!parsed.empty(), "parse failed: " + parse_error);

    // Verify ExtractAllPQSeeds returns both seeds.
    auto all_seeds = parsed[0]->ExtractAllPQSeeds();
    BOOST_REQUIRE_GE(all_seeds.size(), 2U);

    // Build a wallet, import the descriptor, which persists seeds.
    auto wallet = std::make_shared<CWallet>(m_node.chain.get(), "", CreateMockableWalletDatabase());
    {
        LOCK(wallet->cs_wallet);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->m_keypool_size = P2MR_TEST_RANGE_END;

        WalletDescriptor wd{std::move(parsed[0]), static_cast<uint64_t>(GetTime()),
                            /*range_start=*/0, /*range_end=*/P2MR_TEST_RANGE_END, /*next_index=*/0};
        auto* spkm = wallet->AddWalletDescriptor(wd, parse_keys, "", /*internal=*/false);
        BOOST_REQUIRE(spkm);
        wallet->AddActiveScriptPubKeyMan(spkm->GetID(), OutputType::P2MR, /*internal=*/false);
    }

    // Get an address and expand the descriptor to verify it works.
    CTxDestination dest;
    {
        LOCK(wallet->cs_wallet);
        auto dest_result = wallet->GetNewDestination(OutputType::P2MR, "");
        BOOST_REQUIRE_MESSAGE(dest_result, util::ErrorString(dest_result).original);
        dest = *dest_result;
    }

    // Build a UTXO and sign it — this proves the seeds are available.
    const COutPoint prevout{Txid::FromUint256(uint256{200}), 0};
    const CAmount input_value{10 * COIN};
    Coin prev_coin{CTxOut{input_value, GetScriptForDestination(dest)}, 1, false};

    CMutableTransaction tx;
    tx.vin.emplace_back(prevout);
    tx.vout.emplace_back(input_value - 1000, GetScriptForDestination(dest));
    BOOST_REQUIRE(SignAndCheckP2MRTransaction(wallet, tx, prev_coin));

    // Now verify that the seed map was written to the DB.
    {
        LOCK(wallet->cs_wallet);
        WalletBatch batch(wallet->GetDatabase());

        // Read the seed map.
        auto* spkm = wallet->GetScriptPubKeyMan(OutputType::P2MR, /*internal=*/false);
        BOOST_REQUIRE(spkm);
        std::vector<std::pair<std::array<unsigned char, 4>, std::vector<unsigned char>>> seed_map;
        bool have_map = batch.ReadPQDescriptorSeedMap(spkm->GetID(), seed_map);
        BOOST_CHECK_MESSAGE(have_map, "Seed map should be persisted for multisig descriptor");
        if (have_map) {
            BOOST_CHECK_GE(seed_map.size(), 2U);
            // Verify each seed is 32 bytes.
            for (const auto& [fp, seed_vec] : seed_map) {
                BOOST_CHECK_EQUAL(seed_vec.size(), 32U);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(extract_all_pq_seeds_deduplicates_by_fingerprint)
{
    // When the same seed is used with different branches (common in tests),
    // ExtractAllPQSeeds should return it only once.
    const auto seed = MakePQSeed(0xF1);

    const std::string desc_str = AddChecksum(
        "mr(multi_pq(2,"
        + MakeP2MRKeyPathExprWithBranch(seed, /*branch=*/0, /*internal=*/false) + ","
        + MakeP2MRKeyPathExprWithBranch(seed, /*branch=*/1, /*internal=*/false) + ","
        "pk_slh(" + MakeP2MRKeyPathExprWithBranch(seed, /*branch=*/2, /*internal=*/false) + ")))");

    FlatSigningProvider keys;
    std::string error;
    auto parsed = Parse(desc_str, keys, error, /*require_checksum=*/true);
    BOOST_REQUIRE(!parsed.empty());

    auto all_seeds = parsed[0]->ExtractAllPQSeeds();
    // Same seed used for all 3 keys → should be deduplicated to 1 entry.
    BOOST_CHECK_EQUAL(all_seeds.size(), 1U);
    BOOST_CHECK(all_seeds[0].second == seed);
}

BOOST_AUTO_TEST_SUITE_END()

} // namespace wallet
