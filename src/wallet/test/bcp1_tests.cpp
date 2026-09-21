// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/licenses/mit-license.php.

#include <addresstype.h>
#include <chainparams.h>
#include <coins.h>
#include <common/args.h>
#include <core_io.h>
#include <key_io.h>
#include <policy/policy.h>
#include <pq/pq_keyderivation.h>
#include <pqkey.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <script/interpreter.h>
#include <script/pqm.h>
#include <script/script.h>
#include <script/script_error.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/translation.h>
#include <wallet/bcp1_deposit.h>
#include <wallet/bcp1_package.h>
#include <wallet/bcp1_watchonly.h>
#include <wallet/context.h>
#include <wallet/rpc/bcp1.h>
#include <wallet/signer_provider.h>
#include <wallet/test/util.h>
#include <wallet/test/wallet_test_fixture.h>
#include <wallet/wallet.h>
#include <wallet/walletutil.h>

#include <tinyformat.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <fstream>
#include <iterator>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <variant>
#include <vector>

namespace wallet {
RPCHelpMan dumpprivkey();
RPCHelpMan signrawtransactionwithwallet();
RPCHelpMan signmessage();

namespace {

constexpr unsigned int BCP1_SCRIPT_FLAGS{STANDARD_SCRIPT_VERIFY_FLAGS};

fs::path Bcp1VectorDir()
{
    std::vector<fs::path> candidates;
    const fs::path file_dir = fs::PathFromString(std::string{__FILE__}).parent_path();
    candidates.push_back(file_dir / ".." / ".." / "test" / "data" / "bcp1-vectors");
    fs::path cwd = fs::current_path();
    for (int i = 0; i < 8; ++i) {
        candidates.push_back(cwd / "src" / "test" / "data" / "bcp1-vectors");
        if (!cwd.has_parent_path() || cwd.parent_path() == cwd) break;
        cwd = cwd.parent_path();
    }
    for (const auto& c : candidates) {
        if (fs::exists(c / "manifest.json")) return fs::absolute(c);
    }
    BOOST_FAIL("src/test/data/bcp1-vectors/manifest.json not found");
    return {};
}

UniValue ReadBcp1Json(const std::string& name)
{
    const fs::path path = Bcp1VectorDir() / fs::PathFromString(name);
    std::ifstream in{path};
    BOOST_REQUIRE_MESSAGE(in.good(), "missing vector " + fs::PathToString(path));
    const std::string raw{std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    UniValue v;
    BOOST_REQUIRE_MESSAGE(v.read(raw), "invalid JSON " + name);
    return v;
}

std::array<unsigned char, 32> MasterSeedFromDerivation()
{
    const UniValue der = ReadBcp1Json("derivation.json");
    const auto bytes = ParseHex(der["master_seed_hex"].get_str());
    BOOST_REQUIRE_EQUAL(bytes.size(), 32U);
    std::array<unsigned char, 32> seed{};
    std::copy(bytes.begin(), bytes.end(), seed.begin());
    return seed;
}

uint32_t CoinTypeForParams()
{
    return Params().IsTestChain() ? 1 : 0;
}

std::string DepositPath(uint32_t index)
{
    return strprintf("m/87h/%uh/0h/%u/%u", CoinTypeForParams(), bcp1::BRANCH_DEPOSIT, index);
}

std::string ChangePath(uint32_t index)
{
    return strprintf("m/87h/%uh/0h/%u/%u", CoinTypeForParams(), bcp1::BRANCH_CHANGE, index);
}

std::string P2MRAddressFromMlDsaKey(const CPQKey& key)
{
    const auto leaf = BuildP2MRScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf)});
    return EncodeDestination(WitnessV2P2MR{root});
}

CScript P2MRScriptPubKeyFromMlDsaKey(const CPQKey& key)
{
    const auto leaf = BuildP2MRScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
    const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf)});
    return GetScriptForDestination(WitnessV2P2MR{root});
}

CPQKey DeriveMlDsa(Span<const unsigned char> seed, uint32_t branch, uint32_t index)
{
    auto key = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::ML_DSA_44, CoinTypeForParams(),
                                        /*account=*/0, branch, index);
    BOOST_REQUIRE(key.has_value());
    BOOST_REQUIRE(key->IsValid());
    return *key;
}

std::optional<uint256> IndependentP2MRSighash(const CMutableTransaction& tx_spend,
                                              const CTxOut& prevout,
                                              Span<const unsigned char> leaf_script)
{
    PrecomputedTransactionData txdata;
    txdata.Init(tx_spend, {prevout}, /*force=*/true);
    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;
    execdata.m_tapleaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf_script);
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFFU;
    execdata.m_codeseparator_pos_init = true;
    uint256 sighash;
    if (!SignatureHashSchnorr(sighash, execdata, tx_spend, /*in_pos=*/0, SIGHASH_DEFAULT,
                              SigVersion::P2MR, txdata, MissingDataBehavior::FAIL)) {
        return std::nullopt;
    }
    return sighash;
}

bool VerifyP2MRWitness(const CMutableTransaction& tx, const CTxOut& prevout, const CScriptWitness& witness)
{
    CMutableTransaction spend{tx};
    spend.vin.at(0).scriptWitness = witness;
    const CTransaction tx_const{spend};
    PrecomputedTransactionData txdata;
    txdata.Init(tx_const, {prevout}, /*force=*/true);
    ScriptError serror = SCRIPT_ERR_OK;
    return VerifyScript(spend.vin.at(0).scriptSig, prevout.scriptPubKey, &spend.vin.at(0).scriptWitness,
                        BCP1_SCRIPT_FLAGS,
                        TransactionSignatureChecker(&tx_const, 0, prevout.nValue, txdata, MissingDataBehavior::FAIL),
                        &serror) &&
           serror == SCRIPT_ERR_OK;
}

struct Bcp1Spend {
    CPQKey deposit_key;
    CPQKey change_key;
    std::vector<unsigned char> leaf;
    std::vector<unsigned char> control;
    uint256 merkle_root;
    CScript deposit_spk;
    CScript change_spk;
    CScript withdraw_spk;
    COutPoint prevout;
    CTxOut prev_txout;
    CMutableTransaction unsigned_tx;
    uint256 digest;
    CAmount amount{125000000};
    CAmount withdraw_amount{50000000};
    CAmount change_amount{74900000};
};

Bcp1Spend MakeSpend(Span<const unsigned char> seed)
{
    Bcp1Spend s;
    s.deposit_key = DeriveMlDsa(seed, bcp1::BRANCH_DEPOSIT, /*index=*/0);
    s.change_key = DeriveMlDsa(seed, bcp1::BRANCH_CHANGE, /*index=*/0);
    s.leaf = BuildP2MRScript(PQAlgorithm::ML_DSA_44, s.deposit_key.GetPubKey());
    s.control = {P2MR_LEAF_VERSION};
    const uint256 leaf_hash = ComputeP2MRLeafHash(P2MR_LEAF_VERSION, s.leaf);
    s.merkle_root = ComputeP2MRMerkleRoot({leaf_hash});
    s.deposit_spk = GetScriptForDestination(WitnessV2P2MR{s.merkle_root});
    const auto change_leaf = BuildP2MRScript(PQAlgorithm::ML_DSA_44, s.change_key.GetPubKey());
    const uint256 change_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, change_leaf)});
    s.change_spk = GetScriptForDestination(WitnessV2P2MR{change_root});
    s.withdraw_spk = GetScriptForDestination(WitnessV2P2MR{uint256{0x51}});

    const auto prev_txid = uint256::FromHex("b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1");
    BOOST_REQUIRE(prev_txid);
    s.prevout = COutPoint{Txid::FromUint256(*prev_txid), 0};
    s.prev_txout = CTxOut{s.amount, s.deposit_spk};

    s.unsigned_tx.vin.emplace_back(s.prevout);
    s.unsigned_tx.vout.emplace_back(s.withdraw_amount, s.withdraw_spk);
    s.unsigned_tx.vout.emplace_back(s.change_amount, s.change_spk);

    const auto digest = IndependentP2MRSighash(s.unsigned_tx, s.prev_txout, s.leaf);
    BOOST_REQUIRE(digest);
    s.digest = *digest;
    return s;
}

bcp1::Package PackageFromSpend(const Bcp1Spend& spend)
{
    bcp1::Package pkg;
    std::string err;
    BOOST_REQUIRE_MESSAGE(bcp1::FromUnsignedTx(spend.unsigned_tx, {spend.prev_txout},
                                               Params().GetChainTypeString(), pkg, err),
                          err);
    BOOST_REQUIRE_EQUAL(pkg.inputs.size(), 1U);
    pkg.inputs[0].p2mr = bcp1::P2MRSpend{spend.leaf, spend.control, P2MR_LEAF_VERSION};
    pkg.inputs[0].pubkey = spend.deposit_key.GetPubKey();
    pkg.inputs[0].algo = PQAlgorithm::ML_DSA_44;
    pkg.inputs[0].derivation_path = DepositPath(0);
    if (!pkg.change.empty()) {
        pkg.change[0].derivation_path = ChangePath(0);
    }
    BOOST_REQUIRE_MESSAGE(bcp1::FillCanonicalDigests(pkg, err), err);
    BOOST_REQUIRE(pkg.inputs[0].digest.has_value());
    BOOST_CHECK(*pkg.inputs[0].digest == spend.digest);
    return pkg;
}

void FillVectorAliases(UniValue& json, const Bcp1Spend& spend)
{
    const std::string tx_hex = EncodeHexTx(CTransaction{spend.unsigned_tx});
    json.pushKV("unsigned_tx", tx_hex);
    json.pushKV("unsigned_tx_hex", tx_hex);
    json.pushKV("txid", CTransaction{spend.unsigned_tx}.GetHash().GetHex());
    json.pushKV("network", Params().GetChainTypeString());
    BOOST_REQUIRE(json["inputs"].isArray() && json["inputs"].size() >= 1);
    UniValue in = json["inputs"][0];
    in.pushKV("script_pubkey", HexStr(spend.deposit_spk));
    in.pushKV("scriptPubKey", HexStr(spend.deposit_spk));
    in.pushKV("amount_atoms", spend.amount);
    in.pushKV("leaf_script", HexStr(spend.leaf));
    in.pushKV("pubkey", HexStr(spend.deposit_key.GetPubKey()));
    in.pushKV("path", DepositPath(0));
    in.pushKV("digest", spend.digest.GetHex());
    UniValue p2mr = in.exists("p2mr") && in["p2mr"].isObject() ? in["p2mr"] : UniValue(UniValue::VOBJ);
    p2mr.pushKV("merkle_root", spend.merkle_root.GetHex());
    p2mr.pushKV("leaf_script", HexStr(spend.leaf));
    p2mr.pushKV("leaf_version", static_cast<int>(P2MR_LEAF_VERSION));
    p2mr.pushKV("leaf_hash", ComputeP2MRLeafHash(P2MR_LEAF_VERSION, spend.leaf).GetHex());
    p2mr.pushKV("control_block", HexStr(spend.control));
    in.pushKV("p2mr", p2mr);
    UniValue pubkeys(UniValue::VARR);
    UniValue pk(UniValue::VOBJ);
    pk.pushKV("algo", "ML-DSA-44");
    pk.pushKV("pubkey", HexStr(spend.deposit_key.GetPubKey()));
    pubkeys.push_back(pk);
    in.pushKV("pubkeys", pubkeys);
    UniValue inputs(UniValue::VARR);
    inputs.push_back(in);
    json.pushKV("inputs", inputs);
    if (json.exists("outputs") && json["outputs"].isArray() && json["outputs"].size() >= 2) {
        UniValue outs(UniValue::VARR);
        UniValue withdrawal = json["outputs"][0];
        withdrawal.pushKV("script_pubkey", HexStr(spend.withdraw_spk));
        withdrawal.pushKV("address", EncodeDestination(WitnessV2P2MR{uint256{0x51}}));
        outs.push_back(withdrawal);
        UniValue change = json["outputs"][1];
        change.pushKV("script_pubkey", HexStr(spend.change_spk));
        const uint256 change_root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(
            P2MR_LEAF_VERSION, BuildP2MRScript(PQAlgorithm::ML_DSA_44, spend.change_key.GetPubKey()))});
        change.pushKV("address", EncodeDestination(WitnessV2P2MR{change_root}));
        outs.push_back(change);
        json.pushKV("outputs", outs);
    }
}

std::shared_ptr<CWallet> MakeWatchOnlyDescriptorWallet(const WalletTestingSetup& setup, const std::string& name)
{
    auto wallet = std::make_shared<CWallet>(setup.m_node.chain.get(), name, CreateMockableWalletDatabase());
    {
        LOCK(wallet->cs_wallet);
        wallet->SetMinVersion(FEATURE_LATEST);
        wallet->SetWalletFlag(WALLET_FLAG_DESCRIPTORS);
        wallet->SetWalletFlag(WALLET_FLAG_DISABLE_PRIVATE_KEYS);
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

} // namespace

BOOST_FIXTURE_TEST_SUITE(bcp1_tests, WalletTestingSetup)

BOOST_AUTO_TEST_CASE(vector_manifest_profile_and_sizes)
{
    const UniValue manifest = ReadBcp1Json("manifest.json");
    BOOST_CHECK_EQUAL(manifest["profile"].get_str(), bcp1::PROFILE_ID);
    BOOST_CHECK_EQUAL(manifest["format"].get_str(), bcp1::FORMAT_ID);
    BOOST_CHECK_EQUAL(manifest["version"].getInt<int>(), static_cast<int>(bcp1::PACKAGE_VERSION));
    BOOST_CHECK_EQUAL(manifest["p2mr_leaf_version"].getInt<int>(), static_cast<int>(P2MR_LEAF_VERSION));
    BOOST_CHECK_EQUAL(manifest["sizes"]["mldsa44_pubkey_bytes"].getInt<int>(), static_cast<int>(MLDSA44_PUBKEY_SIZE));
    BOOST_CHECK_EQUAL(manifest["sizes"]["mldsa44_signature_bytes"].getInt<int>(), static_cast<int>(MLDSA44_SIGNATURE_SIZE));
    BOOST_CHECK(!manifest["public_bip32_child_derivation"].get_bool());
    BOOST_CHECK_EQUAL(manifest["public_child_error"].get_str(), SignerProvider::ERR_PUBLIC_CHILD_UNSUPPORTED);
    BOOST_CHECK_EQUAL(manifest["automatic_spend_atoms"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(manifest["derivation"]["branch_deposit"].getInt<int>(), static_cast<int>(bcp1::BRANCH_DEPOSIT));
    BOOST_CHECK_EQUAL(manifest["derivation"]["branch_change"].getInt<int>(), static_cast<int>(bcp1::BRANCH_CHANGE));
}

BOOST_AUTO_TEST_CASE(derive_path_branch_deposit_change)
{
    BOOST_CHECK_EQUAL(bcp1::BRANCH_DEPOSIT, 0U);
    BOOST_CHECK_EQUAL(bcp1::BRANCH_CHANGE, 1U);

    const UniValue der = ReadBcp1Json("derivation.json");
    const UniValue manifest = ReadBcp1Json("manifest.json");
    BOOST_CHECK_EQUAL(der["branch_deposit"].getInt<int>(), 0);
    BOOST_CHECK_EQUAL(der["branch_change"].getInt<int>(), 1);
    BOOST_CHECK(!der["public_bip32_child_derivation"].get_bool());

    const auto seed = MasterSeedFromDerivation();
    const CPQKey deposit0 = DeriveMlDsa(seed, bcp1::BRANCH_DEPOSIT, 0);
    const CPQKey deposit1 = DeriveMlDsa(seed, bcp1::BRANCH_DEPOSIT, 1);
    const CPQKey change0 = DeriveMlDsa(seed, bcp1::BRANCH_CHANGE, 0);
    BOOST_CHECK(deposit0.GetPubKey() != change0.GetPubKey());
    BOOST_CHECK(deposit0.GetPubKey() != deposit1.GetPubKey());
    BOOST_CHECK_EQUAL(deposit0.GetPubKey().size(), MLDSA44_PUBKEY_SIZE);
    BOOST_CHECK_EQUAL(change0.GetPubKey().size(), MLDSA44_PUBKEY_SIZE);

    BOOST_CHECK_EQUAL(der["public_child_error"].get_str(), SignerProvider::ERR_PUBLIC_CHILD_UNSUPPORTED);
    BOOST_CHECK_EQUAL(der["public_child_error"].get_str(), manifest["public_child_error"].get_str());

    const std::string deposit_addr = P2MRAddressFromMlDsaKey(deposit0);
    const std::string change_addr = P2MRAddressFromMlDsaKey(change0);
    BOOST_CHECK(!deposit_addr.empty());
    BOOST_CHECK(!change_addr.empty());
    BOOST_CHECK(deposit_addr != change_addr);

    CTxDestination deposit_dest = DecodeDestination(deposit_addr);
    CTxDestination change_dest = DecodeDestination(change_addr);
    BOOST_REQUIRE(IsValidDestination(deposit_dest));
    BOOST_REQUIRE(IsValidDestination(change_dest));
    BOOST_REQUIRE(std::holds_alternative<WitnessV2P2MR>(deposit_dest));
    BOOST_REQUIRE(std::holds_alternative<WitnessV2P2MR>(change_dest));
    const auto& deposit_p2mr = std::get<WitnessV2P2MR>(deposit_dest);
    const auto& change_p2mr = std::get<WitnessV2P2MR>(change_dest);
    BOOST_CHECK(P2MRScriptPubKeyFromMlDsaKey(deposit0) == GetScriptForDestination(deposit_p2mr));
    BOOST_CHECK(P2MRScriptPubKeyFromMlDsaKey(change0) == GetScriptForDestination(change_p2mr));
    BOOST_CHECK_EQUAL(GetScriptForDestination(deposit_p2mr).size(), 34U);

    if (Params().IsTestChain()) {
        BOOST_CHECK_EQUAL(der["path_deposit_test"].get_str(), DepositPath(0));
        BOOST_CHECK_EQUAL(der["path_change_test"].get_str(), ChangePath(0));
    } else {
        BOOST_CHECK_EQUAL(der["path_deposit_main"].get_str(), DepositPath(0));
        BOOST_CHECK_EQUAL(der["path_change_main"].get_str(), ChangePath(0));
    }

    auto signer = MakeSoftwareSignerForTests(seed);
    BOOST_REQUIRE(signer);
    std::string child_err;
    std::vector<unsigned char> parent_pk;
    BOOST_REQUIRE(signer->GetPublicKey(DepositPath(0), PQAlgorithm::ML_DSA_44, parent_pk, child_err));
    BOOST_CHECK_EQUAL(HexStr(parent_pk), HexStr(deposit0.GetPubKey()));
    std::vector<unsigned char> derived_child;
    BOOST_CHECK(!signer->DerivePublicKey(parent_pk, DepositPath(1), PQAlgorithm::ML_DSA_44, derived_child, child_err));
    BOOST_CHECK_EQUAL(child_err, SignerProvider::ERR_PUBLIC_CHILD_UNSUPPORTED);

    std::vector<uint32_t> path;
    BOOST_REQUIRE(bcp1::ParseDerivationPath(DepositPath(0), path));
    BOOST_REQUIRE_EQUAL(path.size(), 5U);
    BOOST_CHECK_EQUAL(path[0], bcp1::PURPOSE | bcp1::HARDENED);
    BOOST_CHECK_EQUAL(path[1], CoinTypeForParams() | bcp1::HARDENED);
    BOOST_CHECK_EQUAL(path[2], 0U | bcp1::HARDENED);
    BOOST_CHECK_EQUAL(path[3], bcp1::BRANCH_DEPOSIT);
    BOOST_CHECK_EQUAL(path[4], 0U);

    BOOST_REQUIRE(bcp1::ParseDerivationPath(ChangePath(0), path));
    BOOST_CHECK_EQUAL(path[3], bcp1::BRANCH_CHANGE);
}

BOOST_AUTO_TEST_CASE(package_roundtrip)
{
    const auto seed = MasterSeedFromDerivation();
    const Bcp1Spend spend = MakeSpend(seed);
    bcp1::Package pkg = PackageFromSpend(spend);

    std::string err;
    BOOST_REQUIRE_MESSAGE(bcp1::ValidateStructure(pkg, err), err);
    BOOST_CHECK_EQUAL(pkg.profile, bcp1::PROFILE_ID);
    BOOST_CHECK_EQUAL(pkg.format, bcp1::FORMAT_ID);
    BOOST_CHECK_EQUAL(pkg.network, Params().GetChainTypeString());
    BOOST_CHECK_EQUAL(pkg.inputs[0].amount, spend.amount);

    const UniValue encoded = bcp1::Encode(pkg);
    BOOST_REQUIRE(encoded.isObject());
    BOOST_CHECK(!encoded.exists("automatic_spend_atoms"));
    BOOST_CHECK_EQUAL(encoded["format"].get_str(), bcp1::FORMAT_ID);

    bcp1::Package decoded;
    BOOST_REQUIRE_MESSAGE(bcp1::Decode(encoded, decoded, err), err);
    BOOST_CHECK_EQUAL(bcp1::Encode(decoded).write(), encoded.write());
    BOOST_CHECK_EQUAL(decoded.inputs[0].amount, spend.amount);
    BOOST_CHECK_EQUAL(decoded.inputs[0].vout, 0U);

    UniValue vector_json = ReadBcp1Json("unsigned-package.json");
    FillVectorAliases(vector_json, spend);
    bcp1::Package from_vector;
    BOOST_REQUIRE_MESSAGE(bcp1::Decode(vector_json, from_vector, err), err);
    BOOST_REQUIRE_MESSAGE(bcp1::ValidateStructure(from_vector, err), err);
    BOOST_CHECK_EQUAL(from_vector.inputs[0].amount, spend.amount);
}

BOOST_AUTO_TEST_CASE(corrupt_mldsa_signature_rejected)
{
    const UniValue corrupt_v = ReadBcp1Json("negative-corrupt-signature.json");
    BOOST_CHECK_EQUAL(corrupt_v["expect"].get_str(), "reject");

    const auto seed = MasterSeedFromDerivation();
    const Bcp1Spend spend = MakeSpend(seed);
    bcp1::Package pkg = PackageFromSpend(spend);

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(spend.deposit_key.Sign(spend.digest, sig));
    BOOST_REQUIRE_EQUAL(sig.size(), MLDSA44_SIGNATURE_SIZE);

    CScriptWitness good_wit;
    good_wit.stack = {sig, spend.leaf, spend.control};
    BOOST_REQUIRE(VerifyP2MRWitness(spend.unsigned_tx, spend.prev_txout, good_wit));

    std::vector<unsigned char> corrupt = sig;
    corrupt.front() ^= 0x01;
    CScriptWitness bad_wit;
    bad_wit.stack = {corrupt, spend.leaf, spend.control};
    BOOST_CHECK(!VerifyP2MRWitness(spend.unsigned_tx, spend.prev_txout, bad_wit));

    std::string err;
    BOOST_REQUIRE_MESSAGE(bcp1::InsertSignature(pkg, 0, sig, err), err);
    BOOST_REQUIRE_MESSAGE(bcp1::PackageReadyToBroadcast(pkg, err), err);

    const bool inserted_corrupt = bcp1::InsertSignature(pkg, 0, corrupt, err);
    const bool ready_corrupt = bcp1::PackageReadyToBroadcast(pkg, err);
    BOOST_CHECK_MESSAGE(!inserted_corrupt,
                        "InsertSignature must fail closed on a corrupt ML-DSA-44 signature");
    BOOST_CHECK_MESSAGE(!ready_corrupt,
                        "PackageReadyToBroadcast must not accept a corrupt ML-DSA-44 signature");
    if (!inserted_corrupt) {
        BOOST_CHECK(err.find("CORRUPT") != std::string::npos || err == bcp1::ERR_CORRUPT_SIGNATURE);
    }
}

BOOST_AUTO_TEST_CASE(leaf_pubkey_mismatch_rejected)
{
    const auto seed = MasterSeedFromDerivation();
    const Bcp1Spend spend = MakeSpend(seed);
    bcp1::Package pkg = PackageFromSpend(spend);

    std::array<unsigned char, 32> other_seed{};
    other_seed.fill(0x22);
    auto other = pq::DerivePQKeyFromBIP39(other_seed, PQAlgorithm::ML_DSA_44, CoinTypeForParams(),
                                          /*account=*/0, /*branch=*/0, /*index=*/1);
    BOOST_REQUIRE(other && other->IsValid());
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(other->Sign(*pkg.inputs[0].digest, sig));
    std::string err;
    BOOST_CHECK_MESSAGE(!bcp1::InsertSignature(pkg, 0, other->GetPubKey(), sig, err),
                        "InsertSignature must not accept a key that is not in the P2MR leaf");
    BOOST_CHECK(err.find("CORRUPT") != std::string::npos || err == bcp1::ERR_CORRUPT_SIGNATURE);
}

BOOST_AUTO_TEST_CASE(wrong_prevout_rejected)
{
    const UniValue wrong_v = ReadBcp1Json("negative-wrong-prevout.json");
    BOOST_CHECK_EQUAL(wrong_v["expect"].get_str(), "reject");

    const auto seed = MasterSeedFromDerivation();
    const Bcp1Spend spend = MakeSpend(seed);
    bcp1::Package pkg = PackageFromSpend(spend);

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(spend.deposit_key.Sign(spend.digest, sig));
    std::string err;
    BOOST_REQUIRE(bcp1::InsertSignature(pkg, 0, sig, err));
    BOOST_REQUIRE(bcp1::PackageReadyToBroadcast(pkg, err));

    pkg.unsigned_tx.vin[0].prevout.n = 1;
    BOOST_CHECK_MESSAGE(!bcp1::PackageReadyToBroadcast(pkg, err),
                        "PackageReadyToBroadcast must reject a wrong prevout");

    UniValue vector_json = ReadBcp1Json("unsigned-package.json");
    FillVectorAliases(vector_json, spend);
    const UniValue wrong = ReadBcp1Json("negative-wrong-prevout.json");
    {
        UniValue in = vector_json["inputs"][0];
        in.pushKV("txid", wrong["wrong_txid"].get_str());
        if (in.exists("prevout") && in["prevout"].isObject()) {
            UniValue prev = in["prevout"];
            prev.pushKV("txid", wrong["wrong_txid"].get_str());
            in.pushKV("prevout", prev);
        }
        UniValue inputs(UniValue::VARR);
        inputs.push_back(in);
        vector_json.pushKV("inputs", inputs);
    }
    bcp1::Package mutated;
    const bool decoded = bcp1::Decode(vector_json, mutated, err);
    const bool valid = decoded && bcp1::ValidateStructure(mutated, err);
    const bool ready = valid && bcp1::FillCanonicalDigests(mutated, err) &&
                       bcp1::InsertSignature(mutated, 0, sig, err) &&
                       bcp1::PackageReadyToBroadcast(mutated, err);
    BOOST_CHECK_MESSAGE(!ready, "wrong prevout BTXPSBT must not finalize");
}

BOOST_AUTO_TEST_CASE(wrong_amount_rejected)
{
    const UniValue wrong_v = ReadBcp1Json("negative-wrong-amount.json");
    BOOST_CHECK_EQUAL(wrong_v["expect"].get_str(), "reject");

    const auto seed = MasterSeedFromDerivation();
    const Bcp1Spend spend = MakeSpend(seed);
    bcp1::Package pkg = PackageFromSpend(spend);

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(spend.deposit_key.Sign(spend.digest, sig));
    std::string err;
    BOOST_REQUIRE(bcp1::InsertSignature(pkg, 0, sig, err));
    BOOST_REQUIRE(bcp1::PackageReadyToBroadcast(pkg, err));

    const CAmount original = pkg.inputs[0].amount;
    const CAmount wrong_amount = wrong_v["wrong_amount_atoms"].getInt<int64_t>();
    BOOST_CHECK(wrong_amount != original);
    pkg.inputs[0].amount = wrong_amount;
    BOOST_CHECK_MESSAGE(!bcp1::PackageReadyToBroadcast(pkg, err),
                        "PackageReadyToBroadcast must reject a wrong prevout amount");

    CTxOut wrong_out = spend.prev_txout;
    wrong_out.nValue = wrong_amount;
    const auto wrong_digest = IndependentP2MRSighash(spend.unsigned_tx, wrong_out, spend.leaf);
    BOOST_REQUIRE(wrong_digest);
    BOOST_CHECK(*wrong_digest != spend.digest);
    BOOST_CHECK(!spend.deposit_key.GetPubKey().empty());
    CPQPubKey pub{PQAlgorithm::ML_DSA_44, spend.deposit_key.GetPubKey()};
    BOOST_CHECK(!pub.Verify(*wrong_digest, sig));

    UniValue vector_json = ReadBcp1Json("unsigned-package.json");
    FillVectorAliases(vector_json, spend);
    {
        UniValue in = vector_json["inputs"][0];
        in.pushKV("amount_atoms", wrong_amount);
        UniValue inputs(UniValue::VARR);
        inputs.push_back(in);
        vector_json.pushKV("inputs", inputs);
    }
    bcp1::Package mutated;
    const bool decoded = bcp1::Decode(vector_json, mutated, err);
    bool ready = false;
    if (decoded && bcp1::ValidateStructure(mutated, err) && bcp1::FillCanonicalDigests(mutated, err)) {
        ready = bcp1::InsertSignature(mutated, 0, sig, err) && bcp1::PackageReadyToBroadcast(mutated, err);
    }
    BOOST_CHECK_MESSAGE(!ready, "wrong amount_atoms BTXPSBT must not finalize");
}

BOOST_AUTO_TEST_CASE(missing_prevout_or_amount_rejected)
{
    const UniValue missing_v = ReadBcp1Json("negative-missing-amount.json");
    BOOST_CHECK_EQUAL(missing_v["expect"].get_str(), "reject");

    const auto seed = MasterSeedFromDerivation();
    const Bcp1Spend spend = MakeSpend(seed);
    bcp1::Package pkg = PackageFromSpend(spend);
    std::string err;

    pkg.inputs[0].amount = -1;
    BOOST_CHECK(!bcp1::ValidateStructure(pkg, err));
    BOOST_CHECK(err.find("AMOUNT") != std::string::npos || err == bcp1::ERR_MISSING_AMOUNT);

    pkg = PackageFromSpend(spend);
    pkg.inputs[0].script_pub_key = CScript{};
    BOOST_CHECK(!bcp1::ValidateStructure(pkg, err));
    BOOST_CHECK(err.find("PREVOUT") != std::string::npos || err == bcp1::ERR_MISSING_PREVOUT ||
                err == bcp1::ERR_INVALID_STRUCTURE);

    UniValue missing = ReadBcp1Json("unsigned-package.json");
    FillVectorAliases(missing, spend);
    {
        UniValue in = missing["inputs"][0];
        in.pushKV("amount_atoms", UniValue());
        UniValue inputs(UniValue::VARR);
        inputs.push_back(in);
        missing.pushKV("inputs", inputs);
    }
    bcp1::Package decoded;
    const bool ok = bcp1::Decode(missing, decoded, err) && bcp1::ValidateStructure(decoded, err);
    BOOST_CHECK_MESSAGE(!ok, "missing amount_atoms must fail closed");
}

BOOST_AUTO_TEST_CASE(wrong_network_rejected)
{
    const UniValue vector = ReadBcp1Json("negative-wrong-network.json");
    BOOST_CHECK_EQUAL(vector["expect"].get_str(), "reject");

    const auto seed = MasterSeedFromDerivation();
    const Bcp1Spend spend = MakeSpend(seed);
    bcp1::Package pkg = PackageFromSpend(spend);
    const std::string local = Params().GetChainTypeString();
    BOOST_CHECK_EQUAL(pkg.network, local);
    pkg.network = vector["wrong_network"].get_str();
    BOOST_REQUIRE(pkg.network != local);
    const UniValue encoded = bcp1::Encode(pkg);
    BOOST_CHECK_EQUAL(encoded["network"].get_str(), pkg.network);

    auto wallet = MakeWatchOnlyDescriptorWallet(*this, "bcp1-wrong-net");
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);
    UniValue params(UniValue::VARR);
    params.push_back(encoded);
    JSONRPCRequest req = WalletRpc(context, params);
    try {
        const UniValue result = finalizeexternalsign().HandleRequest(req);
        const bool complete = result.exists("complete") && result["complete"].get_bool();
        BOOST_CHECK_MESSAGE(!complete, "finalizeexternalsign must reject a BTXPSBT for another network");
    } catch (const UniValue&) {
    }
    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_CASE(public_bip32_child_unsupported_for_mldsa)
{
    const UniValue vector = ReadBcp1Json("negative-public-child.json");
    BOOST_CHECK(!vector["public_bip32_child_derivation"].get_bool());
    BOOST_CHECK_EQUAL(vector["error"].get_str(), SignerProvider::ERR_PUBLIC_CHILD_UNSUPPORTED);

    const auto seed = MasterSeedFromDerivation();
    auto signer = MakeSoftwareSignerForTests(seed);
    BOOST_REQUIRE(signer);

    const UniValue health = signer->Health();
    BOOST_REQUIRE(health.isObject());
    BOOST_REQUIRE(health.exists("p2mr"));
    BOOST_CHECK(health["p2mr"].get_bool());
    BOOST_REQUIRE(health.exists("pq_algorithms"));

    const std::string path = DepositPath(0);
    std::string err;
    std::vector<unsigned char> parent;
    BOOST_REQUIRE_MESSAGE(signer->GetPublicKey(path, PQAlgorithm::ML_DSA_44, parent, err), err);
    BOOST_CHECK_EQUAL(parent.size(), MLDSA44_PUBKEY_SIZE);

    std::vector<unsigned char> child;
    BOOST_CHECK(!signer->DerivePublicKey(parent, path, PQAlgorithm::ML_DSA_44, child, err));
    BOOST_CHECK_EQUAL(err, SignerProvider::ERR_PUBLIC_CHILD_UNSUPPORTED);
    BOOST_CHECK(child.empty());

    std::string prod_err;
    auto prod_main = MakeSoftwareSigner(ChainType::MAIN, seed, m_args, prod_err);
    BOOST_CHECK_MESSAGE(!prod_main, "in-process software signer must not construct on main");

    auto prod_regtest = MakeSoftwareSigner(ChainType::REGTEST, seed, m_args, prod_err);
    BOOST_CHECK_MESSAGE(!prod_regtest, "software signer requires -bcp1software=1 even on regtest");
}

BOOST_AUTO_TEST_CASE(watchonly_refuses_dumpprivkey_and_wallet_sign)
{
    m_args.ForceSetArg("-exchange-watchonly", "1");
    if (m_node.args) m_node.args->ForceSetArg("-exchange-watchonly", "1");

    auto wallet = MakeWatchOnlyDescriptorWallet(*this, "bcp1-watchonly");
    BOOST_CHECK(ExchangeWatchOnlyActive(*wallet));
    bilingual_str ensure_err;
    BOOST_REQUIRE(EnsureExchangeWatchOnly(*wallet, ensure_err));

    bilingual_str refuse_err;
    BOOST_CHECK(RefusePrivateSign(*wallet, refuse_err));
    BOOST_CHECK(!refuse_err.empty());

    const auto seed = MasterSeedFromDerivation();
    const Bcp1Spend spend = MakeSpend(seed);
    const std::string address = EncodeDestination(WitnessV2P2MR{spend.merkle_root});

    UniValue pool(UniValue::VARR);
    UniValue entry(UniValue::VOBJ);
    entry.pushKV("index", 0);
    entry.pushKV("address", address);
    pool.push_back(entry);
    bilingual_str import_err;
    BOOST_REQUIRE_MESSAGE(ImportDepositPool(*wallet, pool, import_err), import_err.original);

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);

    {
        UniValue params(UniValue::VARR);
        params.push_back(address);
        JSONRPCRequest req = WalletRpc(context, params);
        try {
            const UniValue dumped = dumpprivkey().HandleRequest(req);
            BOOST_FAIL("dumpprivkey must not succeed on a BCP/1 watch-only wallet, got " + dumped.write());
        } catch (const UniValue&) {
        }
    }

    {
        LOCK(wallet->cs_wallet);
        std::map<COutPoint, Coin> coins;
        coins.emplace(spend.prevout, Coin{spend.prev_txout, /*nHeight=*/1, /*fCoinBase=*/false});
        std::map<int, bilingual_str> input_errors;
        CMutableTransaction tx = spend.unsigned_tx;
        const bool signed_ok = wallet->SignTransaction(tx, coins, SIGHASH_DEFAULT, input_errors);
        BOOST_CHECK_MESSAGE(!signed_ok, "watch-only wallet must not sign with wallet keys");
    }

    {
        UniValue params(UniValue::VARR);
        params.push_back(EncodeHexTx(CTransaction{spend.unsigned_tx}));
        JSONRPCRequest req = WalletRpc(context, params);
        try {
            const UniValue result = signrawtransactionwithwallet().HandleRequest(req);
            const bool complete = result.exists("complete") && result["complete"].get_bool();
            BOOST_CHECK_MESSAGE(!complete, "signrawtransactionwithwallet must not complete on watch-only");
        } catch (const UniValue&) {
        }
    }

    {
        UniValue params(UniValue::VARR);
        params.push_back(address);
        params.push_back("bcp1 watch-only must not sign messages in-process");
        JSONRPCRequest req = WalletRpc(context, params);
        bool threw{false};
        bool saw_bcp1_refusal{false};
        try {
            const UniValue signed_msg = signmessage().HandleRequest(req);
            BOOST_FAIL("signmessage must not succeed on a BCP/1 watch-only wallet, got " + signed_msg.write());
        } catch (const UniValue& rpc_err) {
            threw = true;
            saw_bcp1_refusal = rpc_err.write().find("BCP/1 exchange watch-only") != std::string::npos;
        }
        BOOST_CHECK(threw);
        BOOST_CHECK_MESSAGE(saw_bcp1_refusal,
                            "signmessage must refuse with the BCP/1 private-sign message, not a generic key error");
    }

    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_CASE(importdepositpool_watchonly)
{
    auto wallet = MakeWatchOnlyDescriptorWallet(*this, "bcp1-pool");
    BOOST_CHECK(!WalletHasDepositMaterial(*wallet));
    {
        const Bcp1Readiness empty = EvaluateBcp1Readiness(*wallet, gArgs);
        BOOST_CHECK(empty.descriptors_ok);
        BOOST_CHECK(empty.watchonly_ok);
        BOOST_CHECK(!empty.deposits_ok);
        BOOST_CHECK(!empty.signer_ok);
        BOOST_CHECK(!empty.Ready());
    }
    const auto seed = MasterSeedFromDerivation();
    const UniValue spec = ReadBcp1Json("deposit-pool.json");
    BOOST_REQUIRE(spec["entries"].isArray());

    UniValue pool(UniValue::VARR);
    std::string first_address;
    for (size_t i = 0; i < spec["entries"].size(); ++i) {
        const uint32_t index = static_cast<uint32_t>(spec["entries"][i]["index"].getInt<int>());
        BOOST_CHECK_EQUAL(spec["entries"][i]["branch"].getInt<int>(), static_cast<int>(bcp1::BRANCH_DEPOSIT));
        const CPQKey key = DeriveMlDsa(seed, bcp1::BRANCH_DEPOSIT, index);
        const auto leaf = BuildP2MRScript(PQAlgorithm::ML_DSA_44, key.GetPubKey());
        const uint256 root = ComputeP2MRMerkleRoot({ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf)});
        const std::string address = EncodeDestination(WitnessV2P2MR{root});
        if (first_address.empty()) first_address = address;
        UniValue item(UniValue::VOBJ);
        item.pushKV("index", static_cast<int>(index));
        item.pushKV("branch", 0);
        item.pushKV("address", address);
        item.pushKV("pubkey", HexStr(key.GetPubKey()));
        item.pushKV("label", spec["entries"][i]["label"].get_str());
        pool.push_back(item);
    }

    bilingual_str err;
    BOOST_REQUIRE_MESSAGE(ImportDepositPool(*wallet, pool, err), err.original);
    BOOST_CHECK(WalletHasDepositMaterial(*wallet));
    {
        const Bcp1Readiness ready = EvaluateBcp1Readiness(*wallet, gArgs);
        BOOST_CHECK(ready.descriptors_ok);
        BOOST_CHECK(ready.watchonly_ok);
        BOOST_CHECK(ready.deposits_ok);
        BOOST_CHECK(!ready.signer_ok);
        BOOST_CHECK(!ready.pkcs11_live);
        BOOST_CHECK(!ready.kmip_live);
        BOOST_CHECK_EQUAL(ready.Ready(), ready.synced_ok);
    }

    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);

    {
        UniValue params(UniValue::VARR);
        params.push_back(pool);
        JSONRPCRequest req = WalletRpc(context, params);
        try {
            importdepositpool().HandleRequest(req);
        } catch (const UniValue& rpc_err) {
            // Re-import of the same scripts may be rejected; the C++ import above is the lock.
            BOOST_TEST_MESSAGE(rpc_err.write());
        }
    }

    {
        UniValue params(UniValue::VARR);
        params.push_back(0);
        JSONRPCRequest req = WalletRpc(context, params);
        try {
            const UniValue derived = deriveexchangeaddress().HandleRequest(req);
            if (derived.isStr()) {
                BOOST_CHECK_EQUAL(derived.get_str(), first_address);
            } else if (derived.isObject() && derived.exists("address")) {
                BOOST_CHECK_EQUAL(derived["address"].get_str(), first_address);
            }
        } catch (const UniValue& rpc_err) {
            BOOST_TEST_MESSAGE(rpc_err.write());
        }
    }

    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_CASE(finalizeexternalsign_rejects_corrupt_signature)
{
    const auto seed = MasterSeedFromDerivation();
    const Bcp1Spend spend = MakeSpend(seed);
    bcp1::Package pkg = PackageFromSpend(spend);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(spend.deposit_key.Sign(spend.digest, sig));
    std::vector<unsigned char> corrupt = sig;
    corrupt.front() ^= 0x01;

    auto wallet = MakeWatchOnlyDescriptorWallet(*this, "bcp1-finalize");
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);

    UniValue params(UniValue::VARR);
    params.push_back(bcp1::Encode(pkg));
    UniValue sigs(UniValue::VARR);
    UniValue sig_obj(UniValue::VOBJ);
    sig_obj.pushKV("algo", "ML-DSA-44");
    sig_obj.pushKV("pubkey", HexStr(spend.deposit_key.GetPubKey()));
    sig_obj.pushKV("signature", HexStr(corrupt));
    sigs.push_back(sig_obj);
    params.push_back(sigs);
    JSONRPCRequest req = WalletRpc(context, params);
    try {
        const UniValue result = finalizeexternalsign().HandleRequest(req);
        const bool complete = result.exists("complete") && result["complete"].get_bool();
        BOOST_CHECK_MESSAGE(!complete, "finalizeexternalsign must not accept a corrupt ML-DSA signature");
        if (result.exists("hex") && result["hex"].isStr() && !result["hex"].get_str().empty()) {
            CMutableTransaction mtx;
            BOOST_REQUIRE(DecodeHexTx(mtx, result["hex"].get_str()));
            BOOST_CHECK(!VerifyP2MRWitness(mtx, spend.prev_txout, mtx.vin[0].scriptWitness));
        }
    } catch (const UniValue&) {
        // Fail closed.
    }

    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_CASE(structure_rejects_duplicate_noncanonical_p2mr_wrong_change)
{
    const auto seed = MasterSeedFromDerivation();
    const Bcp1Spend spend = MakeSpend(seed);
    std::string err;

    {
        bcp1::Package pkg = PackageFromSpend(spend);
        pkg.inputs.push_back(pkg.inputs[0]);
        pkg.unsigned_tx.vin.push_back(pkg.unsigned_tx.vin[0]);
        BOOST_CHECK(!bcp1::ValidateStructure(pkg, err));
        BOOST_CHECK_EQUAL(err, bcp1::ERR_DUPLICATE_INPUT);
        const UniValue vector = ReadBcp1Json("negative-duplicate-input.json");
        BOOST_CHECK_EQUAL(vector["expect"].get_str(), "reject");
    }

    {
        const UniValue vector = ReadBcp1Json("negative-noncanonical.json");
        BOOST_CHECK_EQUAL(vector["expect"].get_str(), "reject");
        bcp1::Package pkg = PackageFromSpend(spend);
        pkg.sighash = 0x83;
        BOOST_CHECK(!bcp1::ValidateStructure(pkg, err));
        BOOST_CHECK_EQUAL(err, bcp1::ERR_NONCANONICAL);

        std::vector<unsigned char> sig;
        BOOST_REQUIRE(spend.deposit_key.Sign(spend.digest, sig));
        CScriptWitness extra_wit;
        extra_wit.stack = {ParseHex("00"), sig, spend.leaf, spend.control};
        BOOST_CHECK_MESSAGE(!VerifyP2MRWitness(spend.unsigned_tx, spend.prev_txout, extra_wit),
                            "extra witness stack item must not verify");
    }

    {
        const UniValue vector = ReadBcp1Json("negative-invalid-p2mr-branch.json");
        BOOST_CHECK_EQUAL(vector["expect"].get_str(), "reject");
        bcp1::Package pkg = PackageFromSpend(spend);
        BOOST_REQUIRE(pkg.inputs[0].p2mr.has_value());
        pkg.inputs[0].p2mr->control_block[0] = 0xc0;
        BOOST_CHECK(!bcp1::ValidateStructure(pkg, err));
        BOOST_CHECK_EQUAL(err, bcp1::ERR_INVALID_P2MR);

        pkg = PackageFromSpend(spend);
        BOOST_REQUIRE(pkg.inputs[0].p2mr.has_value());
        pkg.inputs[0].p2mr->control_block[0] = 0xc3;
        BOOST_CHECK(!bcp1::ValidateStructure(pkg, err));
        BOOST_CHECK_EQUAL(err, bcp1::ERR_INVALID_P2MR);

        pkg = PackageFromSpend(spend);
        BOOST_REQUIRE(pkg.inputs[0].p2mr.has_value());
        const auto bogus_ctrl =
            ParseHex("c2ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
        BOOST_REQUIRE_EQUAL(bogus_ctrl.size(), 33U);
        pkg.inputs[0].p2mr->control_block = bogus_ctrl;
        BOOST_CHECK(!bcp1::ValidateStructure(pkg, err));
        BOOST_CHECK_EQUAL(err, bcp1::ERR_INVALID_P2MR);
    }

    {
        bcp1::Package pkg = PackageFromSpend(spend);
        bcp1::ChangeOutput wrong;
        wrong.vout = 1;
        wrong.amount = spend.change_amount;
        wrong.script_pub_key = spend.withdraw_spk;
        pkg.change.push_back(wrong);
        BOOST_CHECK(!bcp1::ValidateStructure(pkg, err));
        BOOST_CHECK_EQUAL(err, bcp1::ERR_WRONG_CHANGE);
        const UniValue vector = ReadBcp1Json("negative-wrong-change.json");
        BOOST_CHECK_EQUAL(vector["expect"].get_str(), "reject");
    }

}

BOOST_AUTO_TEST_CASE(negative_spent_input_vector)
{
    const UniValue spent = ReadBcp1Json("negative-spent-input.json");
    BOOST_CHECK_EQUAL(spent["expect"].get_str(), "reject");
    BOOST_CHECK_EQUAL(spent["status"].get_str(), "SPENT");
    BOOST_CHECK(spent["note"].get_str().find("UTXO") != std::string::npos ||
                spent["note"].get_str().find("SPENT") != std::string::npos);

    const auto seed = MasterSeedFromDerivation();
    const Bcp1Spend spend = MakeSpend(seed);
    bcp1::Package pkg = PackageFromSpend(spend);
    std::string err;
    BOOST_REQUIRE_MESSAGE(bcp1::ValidateStructure(pkg, err), err);

    const auto txid = uint256::FromHex(spent["txid"].get_str());
    BOOST_REQUIRE(txid);
    BOOST_CHECK_EQUAL(spend.prevout.hash.ToUint256(), *txid);
    BOOST_CHECK_EQUAL(spend.prevout.n, static_cast<uint32_t>(spent["vout"].getInt<int>()));
}

BOOST_AUTO_TEST_CASE(p2mr_script_digest_and_txid_vectors)
{
    const auto seed = MasterSeedFromDerivation();
    const Bcp1Spend spend = MakeSpend(seed);
    const UniValue script = ReadBcp1Json("p2mr-script.json");
    BOOST_CHECK_EQUAL(script["witness_version"].getInt<int>(), 2);
    BOOST_CHECK_EQUAL(script["leaf_version"].getInt<int>(), static_cast<int>(P2MR_LEAF_VERSION));
    BOOST_CHECK_EQUAL(script["pubkey_size"].getInt<int>(), static_cast<int>(MLDSA44_PUBKEY_SIZE));
    BOOST_CHECK_EQUAL(script["signature_size"].getInt<int>(), static_cast<int>(MLDSA44_SIGNATURE_SIZE));
    BOOST_CHECK_EQUAL(script["script_pubkey_size"].getInt<int>(), 34);
    BOOST_CHECK_EQUAL(HexStr(spend.deposit_spk), HexStr(P2MRScriptPubKeyFromMlDsaKey(spend.deposit_key)));
    BOOST_CHECK_EQUAL(P2MRAddressFromMlDsaKey(spend.deposit_key),
                      EncodeDestination(WitnessV2P2MR{spend.merkle_root}));
    BOOST_CHECK_EQUAL(HexStr(spend.control), script["control_block"].get_str());

    const UniValue digest_v = ReadBcp1Json("signing-digest.json");
    BOOST_CHECK_EQUAL(digest_v["sighash"].get_str(), "DEFAULT");

    std::vector<unsigned char> sig;
    BOOST_REQUIRE(spend.deposit_key.Sign(spend.digest, sig));
    const UniValue sig_v = ReadBcp1Json("mldsa-signature.json");
    BOOST_CHECK(sig_v["synthetic"].get_bool());

    const UniValue txid_v = ReadBcp1Json("txid-inclusion.json");
    BOOST_CHECK(txid_v["p2mr_signatures_in_witness"].get_bool() ||
                txid_v["txid_stable_across_witness"].get_bool() ||
                txid_v.exists("txid_serialization"));
    CMutableTransaction wit_tx = spend.unsigned_tx;
    wit_tx.vin[0].scriptWitness.stack = {sig, spend.leaf, spend.control};
    BOOST_CHECK(CTransaction{wit_tx}.GetHash() == CTransaction{spend.unsigned_tx}.GetHash());
}

BOOST_AUTO_TEST_CASE(kmip_and_pkcs11_fail_closed)
{
    std::string err;
    auto kmip = MakeKmipSigner("kmip://127.0.0.1:5696", err);
    BOOST_REQUIRE(kmip);
    BOOST_CHECK_EQUAL(kmip->Backend(), "kmip");
    std::vector<unsigned char> pubkey;
    BOOST_CHECK(!kmip->GetPublicKey("m/87h/1h/0h/0/0", PQAlgorithm::ML_DSA_44, pubkey, err));
    BOOST_CHECK_EQUAL(err, SignerProvider::ERR_KMIP_LIB_MISSING);
    std::vector<unsigned char> child;
    BOOST_CHECK(!kmip->DerivePublicKey(pubkey, "m/87h/1h/0h/0/1", PQAlgorithm::ML_DSA_44, child, err));
    BOOST_CHECK_EQUAL(err, SignerProvider::ERR_PUBLIC_CHILD_UNSUPPORTED);
    std::vector<unsigned char> signature;
    BOOST_CHECK(!kmip->SignDigest("m/87h/1h/0h/0/0", PQAlgorithm::ML_DSA_44, uint256(), signature, err));
    BOOST_CHECK_EQUAL(err, SignerProvider::ERR_KMIP_UNAVAILABLE);

    auto pkcs = MakePkcs11Signer("/nonexistent/libpkcs11.so", err);
    BOOST_REQUIRE(pkcs);
    BOOST_CHECK_EQUAL(pkcs->Backend(), "pkcs11");
    BOOST_CHECK(!pkcs->GetPublicKey("m/87h/1h/0h/0/0", PQAlgorithm::ML_DSA_44, pubkey, err));

    auto wallet = MakeWatchOnlyDescriptorWallet(*this, "bcp1-readiness-stubs");
    const Bcp1Readiness eval = EvaluateBcp1Readiness(*wallet, gArgs);
    BOOST_CHECK(!eval.pkcs11_live);
    BOOST_CHECK(!eval.kmip_live);
    BOOST_CHECK(!eval.https_live);
    BOOST_CHECK(!eval.signer_ok);
    BOOST_CHECK(!eval.Ready());
    const UniValue health = CommandSignerHealthReport(gArgs);
    BOOST_CHECK_EQUAL(health["pkcs11_live"].get_bool(), false);
    BOOST_CHECK_EQUAL(health["kmip_live"].get_bool(), false);
    BOOST_CHECK_EQUAL(health["https_live"].get_bool(), false);
    BOOST_CHECK_EQUAL(health["available"].get_bool(), false);
}

BOOST_AUTO_TEST_CASE(deposit_events_json_and_zmq_map)
{
    BOOST_CHECK_EQUAL(std::string(Bcp1EventForZmqTopic("hashblock")), "block.connected");
    BOOST_CHECK_EQUAL(std::string(Bcp1EventForZmqTopic("sequence:D")), "block.disconnected");
    BOOST_CHECK_EQUAL(std::string(Bcp1EventForZmqTopic("hashtx")), "transaction.mempool");
    BOOST_CHECK_EQUAL(std::string(Bcp1EventForZmqTopic("hashwallettx-block")), "transaction.confirmed");
    BOOST_CHECK(Bcp1EventForZmqTopic("unknown").empty());

    const auto txid = uint256::FromHex("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    BOOST_REQUIRE(txid);

    DepositStatusResult mempool;
    mempool.status = DepositStatus::MEMPOOL;
    mempool.txid = *txid;
    mempool.vout = 1;
    mempool.address = "btx1zqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq2n9w0h";
    mempool.amount_atoms = 125000000;
    mempool.confirmations = 0;
    const auto first = EventsForDepositTransition(std::nullopt, mempool);
    BOOST_REQUIRE(std::find(first.begin(), first.end(), DepositEventType::DepositDetected) != first.end());
    BOOST_REQUIRE(std::find(first.begin(), first.end(), DepositEventType::UtxoCreated) != first.end());
    BOOST_REQUIRE(std::find(first.begin(), first.end(), DepositEventType::TransactionMempool) != first.end());

    const UniValue detected = EmitDepositEvent(DepositEventType::DepositDetected, mempool);
    BOOST_CHECK_EQUAL(detected["event"].get_str(), "deposit.detected");
    BOOST_CHECK_EQUAL(detected["profile"].get_str(), std::string{BCP1_PROFILE_ID});
    BOOST_CHECK_EQUAL(detected["chain"].get_str(), "BTX");
    BOOST_CHECK_EQUAL(detected["txid"].get_str(), txid->GetHex());
    BOOST_CHECK_EQUAL(detected["vout"].getInt<int>(), 1);
    BOOST_CHECK_EQUAL(detected["amount_atoms"].getInt<int64_t>(), 125000000);
    BOOST_CHECK(!detected.exists("deposit.finalized"));

    DepositStatusResult confirmed = mempool;
    confirmed.status = DepositStatus::CONFIRMED;
    confirmed.confirmations = 7;
    confirmed.block_height = 253184;
    const auto conf_events = EventsForDepositTransition(mempool, confirmed);
    BOOST_REQUIRE(std::find(conf_events.begin(), conf_events.end(), DepositEventType::TransactionConfirmed) != conf_events.end());
    BOOST_REQUIRE(std::find(conf_events.begin(), conf_events.end(), DepositEventType::DepositConfirmationsChanged) != conf_events.end());

    DepositStatusResult reorged = confirmed;
    reorged.status = DepositStatus::REORGED;
    reorged.confirmations = 0;
    const auto reorg_events = EventsForDepositTransition(confirmed, reorged);
    BOOST_REQUIRE(std::find(reorg_events.begin(), reorg_events.end(), DepositEventType::TransactionReorged) != reorg_events.end());

    const UniValue chain_ev = EmitChainEvent(DepositEventType::BlockDisconnected, *txid, 253184);
    BOOST_CHECK_EQUAL(chain_ev["event"].get_str(), "block.disconnected");
    BOOST_CHECK_EQUAL(chain_ev["block_height"].getInt<int>(), 253184);
}

BOOST_AUTO_TEST_CASE(two_leaf_address_mismatch_pool_refused)
{
    const auto seed = MasterSeedFromDerivation();
    const CPQKey ml = DeriveMlDsa(seed, bcp1::BRANCH_DEPOSIT, 0);
    auto slh = pq::DerivePQKeyFromBIP39(seed, PQAlgorithm::SLH_DSA_128S, CoinTypeForParams(),
                                        /*account=*/0, bcp1::BRANCH_DEPOSIT, /*index=*/0);
    BOOST_REQUIRE(slh.has_value());
    const std::string two_leaf = bcp1::EncodeP2MRFromPubkeys(ml.GetPubKey(), slh->GetPubKey());
    const std::string single = bcp1::EncodeP2MRFromPubkeys(ml.GetPubKey(), {});
    BOOST_CHECK(two_leaf != single);
    BOOST_CHECK(!two_leaf.empty());

    auto wallet = MakeWatchOnlyDescriptorWallet(*this, "bcp1-two-leaf");
    UniValue bad(UniValue::VARR);
    UniValue item(UniValue::VOBJ);
    item.pushKV("index", 0);
    item.pushKV("address", two_leaf);
    item.pushKV("pubkey", HexStr(ml.GetPubKey()));
    bad.push_back(item);
    bilingual_str err;
    BOOST_CHECK(!ImportDepositPool(*wallet, bad, err));
    BOOST_CHECK(err.original.find("two-leaf") != std::string::npos ||
                err.original.find("pubkey_slh") != std::string::npos);

    UniValue good(UniValue::VARR);
    UniValue ok_item(UniValue::VOBJ);
    ok_item.pushKV("index", 0);
    ok_item.pushKV("address", two_leaf);
    ok_item.pushKV("pubkey", HexStr(ml.GetPubKey()));
    ok_item.pushKV("pubkey_slh", HexStr(slh->GetPubKey()));
    good.push_back(ok_item);
    UniValue details;
    BOOST_REQUIRE_MESSAGE(ImportDepositPool(*wallet, good, err, details), err.original);
    BOOST_CHECK(details["solvable"].get_bool());
    BOOST_CHECK_EQUAL(details["imported"].getInt<int>(), 1);
}

BOOST_AUTO_TEST_CASE(finalizeexternalsign_accepts_valid_software_signature)
{
    const auto seed = MasterSeedFromDerivation();
    const Bcp1Spend spend = MakeSpend(seed);
    bcp1::Package pkg = PackageFromSpend(spend);
    std::vector<unsigned char> sig;
    BOOST_REQUIRE(spend.deposit_key.Sign(spend.digest, sig));
    BOOST_REQUIRE_EQUAL(sig.size(), MLDSA44_SIGNATURE_SIZE);

    auto wallet = MakeWatchOnlyDescriptorWallet(*this, "bcp1-finalize-good");
    WalletContext context;
    context.args = &m_args;
    context.chain = m_node.chain.get();
    AddWallet(context, wallet);

    UniValue params(UniValue::VARR);
    params.push_back(bcp1::Encode(pkg));
    UniValue sigs(UniValue::VARR);
    UniValue sig_obj(UniValue::VOBJ);
    sig_obj.pushKV("algo", "ML-DSA-44");
    sig_obj.pushKV("pubkey", HexStr(spend.deposit_key.GetPubKey()));
    sig_obj.pushKV("signature", HexStr(sig));
    sigs.push_back(sig_obj);
    params.push_back(sigs);
    JSONRPCRequest req = WalletRpc(context, params);
    const UniValue result = finalizeexternalsign().HandleRequest(req);
    BOOST_REQUIRE(result.isObject());
    BOOST_CHECK(result.exists("complete") && result["complete"].get_bool());
    BOOST_CHECK(result.exists("broadcast") && result["broadcast"].isFalse());
    BOOST_REQUIRE(result.exists("hex") && result["hex"].isStr() && !result["hex"].get_str().empty());
    CMutableTransaction mtx;
    BOOST_REQUIRE(DecodeHexTx(mtx, result["hex"].get_str()));
    BOOST_CHECK(VerifyP2MRWitness(mtx, spend.prev_txout, mtx.vin[0].scriptWitness));

    RemoveWallet(context, wallet, /*load_on_start=*/std::nullopt);
}

BOOST_AUTO_TEST_SUITE_END()
} // namespace wallet
