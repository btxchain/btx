// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <wallet/bcp1_package.h>

#include <addresstype.h>
#include <chainparams.h>
#include <core_io.h>
#include <key_io.h>
#include <psbt.h>
#include <script/interpreter.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>
#include <util/string.h>

#include <algorithm>
#include <cctype>
#include <exception>
#include <limits>
#include <optional>
#include <set>
#include <utility>

namespace wallet {
namespace bcp1 {
namespace {

bool HasAutomaticSpend(const UniValue& v)
{
    if (v.isObject()) {
        if (v.exists("automatic_spend_atoms")) return true;
        for (const auto& k : v.getKeys()) {
            if (HasAutomaticSpend(v[k])) return true;
        }
    } else if (v.isArray()) {
        for (const auto& e : v.getValues()) {
            if (HasAutomaticSpend(e)) return true;
        }
    }
    return false;
}

bool ParseHexBytes(const std::string& hex, std::vector<unsigned char>& out, std::string& error, const char* what)
{
    if (hex.empty()) {
        out.clear();
        return true;
    }
    if (!IsHex(hex)) {
        error = strprintf("invalid %s hex", what);
        return false;
    }
    out = ParseHex(hex);
    return true;
}

bool ParseAmountAtoms(const UniValue& v, CAmount& amt, std::string& error)
{
    if (v.isNull()) {
        error = ERR_MISSING_AMOUNT;
        return false;
    }
    if (v.isNum()) {
        try {
            amt = v.getInt<int64_t>();
        } catch (const std::exception&) {
            error = ERR_MISSING_AMOUNT;
            return false;
        }
    } else if (v.isStr()) {
        if (v.get_str().find('.') != std::string::npos || !ParseInt64(v.get_str(), &amt)) {
            error = ERR_MISSING_AMOUNT;
            return false;
        }
    } else {
        error = ERR_MISSING_AMOUNT;
        return false;
    }
    if (!MoneyRange(amt)) {
        error = ERR_MISSING_AMOUNT;
        return false;
    }
    return true;
}

const UniValue* FindField(const UniValue& obj, std::initializer_list<const char*> names)
{
    for (const char* name : names) {
        if (obj.exists(name) && !obj[name].isNull()) return &obj[name];
    }
    return nullptr;
}

CTxOut PrevoutOf(const Input& in)
{
    return CTxOut{in.amount, in.script_pub_key};
}

std::optional<uint256> ComputeInputDigest(const CMutableTransaction& tx, std::vector<CTxOut> prevouts,
                                          uint32_t in_pos, Span<const unsigned char> leaf_script, uint8_t leaf_version,
                                          uint8_t sighash)
{
    if (in_pos >= tx.vin.size() || prevouts.size() != tx.vin.size()) return std::nullopt;
    PrecomputedTransactionData txdata;
    txdata.Init(tx, std::move(prevouts), /*force=*/true);
    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;
    execdata.m_tapleaf_hash = ComputeP2MRLeafHash(leaf_version, leaf_script);
    execdata.m_tapleaf_hash_init = true;
    execdata.m_codeseparator_pos = 0xFFFFFFFFU;
    execdata.m_codeseparator_pos_init = true;
    uint256 out;
    if (!SignatureHashSchnorr(out, execdata, tx, in_pos, sighash, SigVersion::P2MR, txdata, MissingDataBehavior::FAIL)) {
        return std::nullopt;
    }
    return out;
}

Span<const unsigned char> RawSignature(Span<const unsigned char> sig, PQAlgorithm algo)
{
    const size_t expected = GetPQSignatureSize(algo);
    if (sig.size() == expected + 1) return sig.first(expected);
    return sig;
}

bool VerifyInputSig(const Input& in, const uint256& digest, std::string& error)
{
    if (in.pubkey.empty() || !in.algo) {
        error = ERR_CORRUPT_SIGNATURE;
        return false;
    }
    if (in.signature.empty()) {
        error = ERR_CORRUPT_SIGNATURE;
        return false;
    }
    if (in.pubkey.size() != GetPQPubKeySize(*in.algo)) {
        error = ERR_CORRUPT_SIGNATURE;
        return false;
    }
    const Span<const unsigned char> raw = RawSignature(in.signature, *in.algo);
    if (raw.size() != GetPQSignatureSize(*in.algo)) {
        error = ERR_CORRUPT_SIGNATURE;
        return false;
    }
    const CPQPubKey pk(*in.algo, in.pubkey);
    if (!pk.Verify(digest, raw)) {
        error = ERR_CORRUPT_SIGNATURE;
        return false;
    }
    if (in.p2mr && !in.p2mr->leaf_script.empty()) {
        PQAlgorithm leaf_algo;
        std::vector<unsigned char> leaf_pk;
        if (!ExtractP2MRChecksigPubkey(in.p2mr->leaf_script, leaf_algo, leaf_pk)) {
            error = ERR_CORRUPT_SIGNATURE;
            return false;
        }
        if (leaf_algo != *in.algo || leaf_pk != in.pubkey) {
            error = ERR_CORRUPT_SIGNATURE;
            return false;
        }
    }
    return true;
}

bool ParseScriptField(const UniValue& obj, CScript& out, std::string& error)
{
    const UniValue* field = FindField(obj, {"scriptPubKey", "script_pubkey"});
    if (!field || !field->isStr() || field->get_str().empty()) {
        error = ERR_MISSING_PREVOUT;
        return false;
    }
    std::vector<unsigned char> spk;
    if (!ParseHexBytes(field->get_str(), spk, error, "scriptPubKey")) return false;
    if (spk.empty()) {
        error = ERR_MISSING_PREVOUT;
        return false;
    }
    out = CScript(spk.begin(), spk.end());
    return true;
}

bool ParseP2MRFromInput(const UniValue& iv, Input& inp, std::string& error)
{
    const UniValue* nested = (iv.exists("p2mr") && iv["p2mr"].isObject()) ? &iv["p2mr"] : nullptr;
    const UniValue* leaf_v = FindField(iv, {"leaf_script"});
    if (!leaf_v && nested) leaf_v = FindField(*nested, {"leaf_script"});
    const UniValue* ctrl_v = FindField(iv, {"control_block"});
    if (!ctrl_v && nested) ctrl_v = FindField(*nested, {"control_block"});
    if (!leaf_v && !ctrl_v) return true;
    if (!leaf_v || !ctrl_v) {
        error = ERR_INVALID_STRUCTURE;
        return false;
    }
    P2MRSpend spend;
    if (!ParseHexBytes(leaf_v->get_str(), spend.leaf_script, error, "leaf_script")) return false;
    if (!ParseHexBytes(ctrl_v->get_str(), spend.control_block, error, "control_block")) return false;
    const UniValue* ver = FindField(iv, {"leaf_version"});
    if (!ver && nested) ver = FindField(*nested, {"leaf_version"});
    if (ver && ver->isNum()) {
        const int64_t v = ver->getInt<int64_t>();
        if (v < 0 || v > 0xff) {
            error = ERR_INVALID_STRUCTURE;
            return false;
        }
        spend.leaf_version = static_cast<uint8_t>(v);
    }
    if (!spend.leaf_script.empty() && !spend.control_block.empty()) inp.p2mr = std::move(spend);
    return true;
}

} // namespace

bool ParseAlgo(const std::string& name, PQAlgorithm& algo)
{
    const std::string n = ToLower(name);
    if (n == "ml-dsa-44" || n == "mldsa44" || n == "ml_dsa_44" || n == "ml-dsa" || n == "mldsa") {
        algo = PQAlgorithm::ML_DSA_44;
        return true;
    }
    if (n == "slh-dsa-128s" || n == "slh_dsa_128s" || n == "slhdsa128s" || n == "slh-dsa-shake-128s" ||
        n == "slh_dsa_shake_128s" || n == "slh-dsa" || n == "slhdsa") {
        algo = PQAlgorithm::SLH_DSA_128S;
        return true;
    }
    return false;
}

std::string FormatAlgo(PQAlgorithm algo)
{
    switch (algo) {
    case PQAlgorithm::ML_DSA_44:
        return "ml_dsa_44";
    case PQAlgorithm::SLH_DSA_128S:
        return "slh_dsa_128s";
    }
    return "ml_dsa_44";
}

std::string EncodeP2MRFromPubkeys(Span<const unsigned char> ml_dsa, Span<const unsigned char> slh_dsa)
{
    std::vector<uint256> leaves;
    if (!ml_dsa.empty()) {
        const auto leaf = BuildP2MRScript(PQAlgorithm::ML_DSA_44, ml_dsa);
        leaves.push_back(ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf));
    }
    if (!slh_dsa.empty()) {
        const auto leaf = BuildP2MRScript(PQAlgorithm::SLH_DSA_128S, slh_dsa);
        leaves.push_back(ComputeP2MRLeafHash(P2MR_LEAF_VERSION, leaf));
    }
    if (leaves.empty()) return {};
    return EncodeDestination(WitnessV2P2MR{ComputeP2MRMerkleRoot(leaves)});
}

bool ParseDerivationPath(const std::string& path, std::vector<uint32_t>& out)
{
    out.clear();
    if (path.size() < 3 || (path[0] != 'm' && path[0] != 'M') || path[1] != '/') return false;
    size_t i = 2;
    while (i < path.size()) {
        uint32_t v = 0;
        bool any = false;
        while (i < path.size() && std::isdigit(static_cast<unsigned char>(path[i]))) {
            any = true;
            const uint32_t next = v * 10u + static_cast<uint32_t>(path[i] - '0');
            if (next < v) return false;
            v = next;
            ++i;
        }
        if (!any) return false;
        if (i < path.size() && (path[i] == 'h' || path[i] == 'H' || path[i] == '\'')) {
            v |= HARDENED;
            ++i;
        }
        out.push_back(v);
        if (i == path.size()) break;
        if (path[i] != '/') return false;
        ++i;
    }
    return !out.empty();
}

UniValue Encode(const Package& pkg)
{
    UniValue o(UniValue::VOBJ);
    o.pushKV("format", pkg.format.empty() ? FORMAT_ID : pkg.format);
    o.pushKV("version", static_cast<int>(pkg.version));
    o.pushKV("profile", pkg.profile.empty() ? PROFILE_ID : pkg.profile);
    o.pushKV("chain", pkg.chain.empty() ? CHAIN_ID : pkg.chain);
    o.pushKV("network", pkg.network);
    o.pushKV("sighash", pkg.sighash == SIGHASH_DEFAULT ? "DEFAULT" : strprintf("%u", pkg.sighash));
    o.pushKV("unsigned_tx", EncodeHexTx(CTransaction(pkg.unsigned_tx)));

    UniValue inputs(UniValue::VARR);
    UniValue digests(UniValue::VARR);
    UniValue signatures(UniValue::VARR);
    for (size_t idx = 0; idx < pkg.inputs.size(); ++idx) {
        const Input& in = pkg.inputs[idx];
        UniValue i(UniValue::VOBJ);
        i.pushKV("txid", in.txid.GetHex());
        i.pushKV("vout", static_cast<int>(in.vout));
        i.pushKV("amount_atoms", in.amount);
        i.pushKV("amount", in.amount);
        i.pushKV("scriptPubKey", HexStr(in.script_pub_key));
        if (in.p2mr) {
            UniValue p2mr(UniValue::VOBJ);
            p2mr.pushKV("leaf_script", HexStr(in.p2mr->leaf_script));
            p2mr.pushKV("control_block", HexStr(in.p2mr->control_block));
            p2mr.pushKV("leaf_version", static_cast<int>(in.p2mr->leaf_version));
            i.pushKV("p2mr", p2mr);
            i.pushKV("leaf_script", HexStr(in.p2mr->leaf_script));
            i.pushKV("control_block", HexStr(in.p2mr->control_block));
            i.pushKV("leaf_version", static_cast<int>(in.p2mr->leaf_version));
        }
        if (in.derivation_path) i.pushKV("path", *in.derivation_path);
        if (in.master_fingerprint) i.pushKV("fingerprint", *in.master_fingerprint);
        if (!in.pubkey.empty()) i.pushKV("pubkey", HexStr(in.pubkey));
        if (in.algo) i.pushKV("algo", FormatAlgo(*in.algo));
        if (in.digest) i.pushKV("digest", in.digest->GetHex());
        if (!in.signature.empty()) i.pushKV("signature", HexStr(in.signature));
        inputs.push_back(i);

        if (in.digest) {
            UniValue d(UniValue::VOBJ);
            d.pushKV("index", static_cast<int>(idx));
            d.pushKV("digest", in.digest->GetHex());
            d.pushKV("sighash", pkg.sighash == SIGHASH_DEFAULT ? "DEFAULT" : strprintf("%u", pkg.sighash));
            digests.push_back(std::move(d));
        }
        if (!in.signature.empty()) {
            UniValue s(UniValue::VOBJ);
            s.pushKV("index", static_cast<int>(idx));
            if (!in.pubkey.empty()) s.pushKV("pubkey", HexStr(in.pubkey));
            if (in.algo) s.pushKV("algo", FormatAlgo(*in.algo));
            s.pushKV("signature", HexStr(in.signature));
            signatures.push_back(std::move(s));
        }
    }
    o.pushKV("inputs", std::move(inputs));
    o.pushKV("digests", std::move(digests));
    o.pushKV("signatures", std::move(signatures));

    UniValue change(UniValue::VARR);
    for (const ChangeOutput& c : pkg.change) {
        UniValue cobj(UniValue::VOBJ);
        cobj.pushKV("vout", static_cast<int>(c.vout));
        cobj.pushKV("amount_atoms", c.amount);
        cobj.pushKV("scriptPubKey", HexStr(c.script_pub_key));
        if (c.derivation_path) cobj.pushKV("path", *c.derivation_path);
        change.push_back(std::move(cobj));
    }
    o.pushKV("change", std::move(change));
    return o;
}

bool Decode(const UniValue& in, Package& pkg, std::string& error)
{
    pkg = Package();
    if (!in.isObject()) {
        error = ERR_INVALID_STRUCTURE;
        return false;
    }
    if (HasAutomaticSpend(in)) {
        error = ERR_AUTOMATIC_SPEND_FORBIDDEN;
        return false;
    }

    try {
        if (in.exists("format") && in["format"].isStr() && in["format"].get_str() != FORMAT_ID) {
            error = ERR_INVALID_STRUCTURE;
            return false;
        }
        if (in.exists("version") && in["version"].isNum() &&
            in["version"].getInt<int>() != static_cast<int>(PACKAGE_VERSION)) {
            error = ERR_INVALID_STRUCTURE;
            return false;
        }
        pkg.version = PACKAGE_VERSION;
        pkg.profile = (in.exists("profile") && in["profile"].isStr()) ? in["profile"].get_str() : PROFILE_ID;
        pkg.format = FORMAT_ID;
        pkg.chain = (in.exists("chain") && in["chain"].isStr()) ? in["chain"].get_str() : CHAIN_ID;
        pkg.network = (in.exists("network") && in["network"].isStr()) ? in["network"].get_str() : "";

        if (in.exists("sighash") && !in["sighash"].isNull()) {
            if (in["sighash"].isStr()) {
                const std::string s = in["sighash"].get_str();
                if (s == "DEFAULT" || s == "ALL") {
                    pkg.sighash = SIGHASH_DEFAULT;
                } else if (!ParseUInt8(s, &pkg.sighash)) {
                    error = ERR_INVALID_STRUCTURE;
                    return false;
                }
            } else if (in["sighash"].isNum()) {
                const int64_t n = in["sighash"].getInt<int64_t>();
                if (n < 0 || n > 0xff) {
                    error = ERR_INVALID_STRUCTURE;
                    return false;
                }
                pkg.sighash = static_cast<uint8_t>(n);
            }
        }

        const UniValue* txhex = FindField(in, {"unsigned_tx", "unsigned_tx_hex"});
        if (txhex && txhex->isStr() && !txhex->get_str().empty()) {
            if (!DecodeHexTx(pkg.unsigned_tx, txhex->get_str(), /*try_no_witness=*/true, /*try_witness=*/true)) {
                error = ERR_INVALID_STRUCTURE;
                return false;
            }
        }

        if (!in.exists("inputs") || !in["inputs"].isArray()) {
            error = ERR_INVALID_STRUCTURE;
            return false;
        }
        for (const UniValue& iv : in["inputs"].getValues()) {
            if (!iv.isObject()) {
                error = ERR_INVALID_STRUCTURE;
                return false;
            }
            Input inp;
            const UniValue* txid_v = FindField(iv, {"txid"});
            const UniValue* vout_v = FindField(iv, {"vout"});
            if (iv.exists("prevout") && iv["prevout"].isObject()) {
                if (!txid_v) txid_v = FindField(iv["prevout"], {"txid"});
                if (!vout_v) vout_v = FindField(iv["prevout"], {"vout"});
            }
            if (!txid_v || !vout_v) {
                error = ERR_MISSING_PREVOUT;
                return false;
            }
            const auto txid = Txid::FromHex(txid_v->get_str());
            if (!txid) {
                error = ERR_MISSING_PREVOUT;
                return false;
            }
            inp.txid = *txid;
            const int64_t vout = vout_v->getInt<int64_t>();
            if (vout < 0 || vout > static_cast<int64_t>(std::numeric_limits<uint32_t>::max())) {
                error = ERR_MISSING_PREVOUT;
                return false;
            }
            inp.vout = static_cast<uint32_t>(vout);

            const UniValue* amt = FindField(iv, {"amount_atoms", "amount"});
            if (!amt || !ParseAmountAtoms(*amt, inp.amount, error)) {
                error = ERR_MISSING_AMOUNT;
                return false;
            }
            if (!ParseScriptField(iv, inp.script_pub_key, error)) return false;
            if (!ParseP2MRFromInput(iv, inp, error)) return false;

            const UniValue* path_v = FindField(iv, {"path", "derivation_path"});
            if (path_v && path_v->isStr() && !path_v->get_str().empty()) inp.derivation_path = path_v->get_str();
            const UniValue* fp_v = FindField(iv, {"fingerprint", "master_fingerprint"});
            if (fp_v && fp_v->isStr() && !fp_v->get_str().empty()) inp.master_fingerprint = fp_v->get_str();

            const UniValue* pubkey_v = FindField(iv, {"pubkey"});
            if (!pubkey_v && iv.exists("pubkeys") && iv["pubkeys"].isArray() && !iv["pubkeys"].empty() &&
                iv["pubkeys"][0].isObject()) {
                pubkey_v = FindField(iv["pubkeys"][0], {"pubkey"});
            }
            if (pubkey_v && pubkey_v->isStr() && !pubkey_v->get_str().empty()) {
                if (!ParseHexBytes(pubkey_v->get_str(), inp.pubkey, error, "pubkey")) return false;
            }

            const UniValue* algo_v = FindField(iv, {"algo", "algorithm"});
            if (!algo_v && iv.exists("pubkeys") && iv["pubkeys"].isArray() && !iv["pubkeys"].empty() &&
                iv["pubkeys"][0].isObject()) {
                algo_v = FindField(iv["pubkeys"][0], {"algo", "algorithm"});
            }
            if (algo_v && algo_v->isStr() && !algo_v->get_str().empty()) {
                PQAlgorithm algo{};
                if (!ParseAlgo(algo_v->get_str(), algo)) {
                    error = ERR_INVALID_STRUCTURE;
                    return false;
                }
                inp.algo = algo;
            } else if (!inp.pubkey.empty()) {
                inp.algo = GetPQAlgorithmByPubKeySize(inp.pubkey.size());
            }

            const UniValue* digest_v = FindField(iv, {"digest"});
            if (digest_v && digest_v->isStr() && !digest_v->get_str().empty()) {
                const auto parsed = uint256::FromHex(digest_v->get_str());
                if (!parsed) {
                    error = ERR_WRONG_DIGEST;
                    return false;
                }
                inp.digest = *parsed;
            }
            const UniValue* sig_v = FindField(iv, {"signature"});
            if (sig_v && sig_v->isStr() && !sig_v->get_str().empty()) {
                if (!ParseHexBytes(sig_v->get_str(), inp.signature, error, "signature")) return false;
            }
            pkg.inputs.push_back(std::move(inp));
        }

        if (in.exists("digests") && in["digests"].isArray()) {
            for (const UniValue& d : in["digests"].getValues()) {
                if (!d.isObject() || !d.exists("index") || !d.exists("digest")) continue;
                const int64_t index = d["index"].getInt<int64_t>();
                if (index < 0 || static_cast<size_t>(index) >= pkg.inputs.size()) {
                    error = ERR_INVALID_STRUCTURE;
                    return false;
                }
                const auto parsed = uint256::FromHex(d["digest"].get_str());
                if (!parsed) {
                    error = ERR_WRONG_DIGEST;
                    return false;
                }
                Input& target = pkg.inputs[static_cast<size_t>(index)];
                if (target.digest && *target.digest != *parsed) {
                    error = ERR_WRONG_DIGEST;
                    return false;
                }
                target.digest = *parsed;
            }
        }
        if (in.exists("signatures") && in["signatures"].isArray()) {
            for (const UniValue& s : in["signatures"].getValues()) {
                if (!s.isObject() || !s.exists("index") || !s.exists("signature")) continue;
                const int64_t index = s["index"].getInt<int64_t>();
                if (index < 0 || static_cast<size_t>(index) >= pkg.inputs.size()) {
                    error = ERR_INVALID_STRUCTURE;
                    return false;
                }
                std::vector<unsigned char> sig;
                if (!ParseHexBytes(s["signature"].get_str(), sig, error, "signature")) return false;
                Input& target = pkg.inputs[static_cast<size_t>(index)];
                if (!target.signature.empty() && target.signature != sig) {
                    error = ERR_CORRUPT_SIGNATURE;
                    return false;
                }
                target.signature = std::move(sig);
            }
        }

        if (in.exists("change") && in["change"].isArray()) {
            for (const UniValue& cv : in["change"].getValues()) {
                if (!cv.isObject()) continue;
                const UniValue* spk = FindField(cv, {"scriptPubKey", "script_pubkey"});
                if (!spk) continue;
                ChangeOutput c;
                const UniValue* vout_v = FindField(cv, {"vout", "index"});
                if (vout_v) {
                    const int64_t vout = vout_v->getInt<int64_t>();
                    if (vout >= 0) c.vout = static_cast<uint32_t>(vout);
                }
                const UniValue* amt = FindField(cv, {"amount_atoms", "amount"});
                if (amt) ParseAmountAtoms(*amt, c.amount, error);
                std::vector<unsigned char> raw;
                if (!ParseHexBytes(spk->get_str(), raw, error, "scriptPubKey")) continue;
                c.script_pub_key = CScript(raw.begin(), raw.end());
                const UniValue* path_v = FindField(cv, {"path", "derivation_path"});
                if (path_v && path_v->isStr() && !path_v->get_str().empty()) c.derivation_path = path_v->get_str();
                pkg.change.push_back(std::move(c));
            }
        }
        if (in.exists("outputs") && in["outputs"].isArray() && pkg.change.empty()) {
            for (const UniValue& ov : in["outputs"].getValues()) {
                if (!ov.isObject()) continue;
                const bool is_change = ov.exists("role") && ov["role"].isStr() && ov["role"].get_str() == "change";
                if (!is_change) continue;
                ChangeOutput c;
                const UniValue* vout_v = FindField(ov, {"vout", "index"});
                if (vout_v) {
                    const int64_t vout = vout_v->getInt<int64_t>();
                    if (vout >= 0) c.vout = static_cast<uint32_t>(vout);
                }
                const UniValue* amt = FindField(ov, {"amount_atoms", "amount"});
                if (amt) ParseAmountAtoms(*amt, c.amount, error);
                const UniValue* spk = FindField(ov, {"scriptPubKey", "script_pubkey"});
                if (spk && spk->isStr() && !spk->get_str().empty()) {
                    std::vector<unsigned char> raw;
                    if (ParseHexBytes(spk->get_str(), raw, error, "scriptPubKey")) {
                        c.script_pub_key = CScript(raw.begin(), raw.end());
                    }
                }
                const UniValue* path_v = FindField(ov, {"path", "derivation_path"});
                if (path_v && path_v->isStr() && !path_v->get_str().empty()) c.derivation_path = path_v->get_str();
                pkg.change.push_back(std::move(c));
            }
        }
    } catch (const std::exception& e) {
        error = e.what();
        return false;
    }
    error.clear();
    return true;
}

bool ValidateStructure(const Package& pkg, std::string& error)
{
    if (pkg.format != FORMAT_ID || pkg.version != PACKAGE_VERSION) {
        error = ERR_INVALID_STRUCTURE;
        return false;
    }
    if (pkg.inputs.size() != pkg.unsigned_tx.vin.size() || pkg.inputs.empty()) {
        error = ERR_INVALID_STRUCTURE;
        return false;
    }
    if (pkg.sighash != 0) {
        error = ERR_NONCANONICAL;
        return false;
    }
    std::set<COutPoint> seen_prevouts;
    for (size_t i = 0; i < pkg.inputs.size(); ++i) {
        const Input& in = pkg.inputs[i];
        if (in.amount < 0 || !MoneyRange(in.amount)) {
            error = ERR_MISSING_AMOUNT;
            return false;
        }
        if (in.script_pub_key.empty()) {
            error = ERR_MISSING_PREVOUT;
            return false;
        }
        const CTxIn& vin = pkg.unsigned_tx.vin[i];
        if (vin.prevout.hash != in.txid || vin.prevout.n != in.vout) {
            error = ERR_MISSING_PREVOUT;
            return false;
        }
        if (!seen_prevouts.emplace(in.txid, in.vout).second) {
            error = ERR_DUPLICATE_INPUT;
            return false;
        }
        if (!in.p2mr || in.p2mr->leaf_script.empty() || in.p2mr->control_block.empty()) {
            error = ERR_INVALID_STRUCTURE;
            return false;
        }
        int witness_version = 0;
        std::vector<unsigned char> program;
        if (!in.script_pub_key.IsWitnessProgram(witness_version, program) || witness_version != 2 ||
            program.size() != P2MR_PROGRAM_SIZE) {
            error = ERR_INVALID_P2MR;
            return false;
        }
        if ((in.p2mr->control_block[0] & P2MR_LEAF_MASK) != P2MR_LEAF_VERSION) {
            error = ERR_INVALID_P2MR;
            return false;
        }
        const uint256 leaf_hash =
            ComputeP2MRLeafHash(in.p2mr->control_block[0] & P2MR_LEAF_MASK, in.p2mr->leaf_script);
        if (!VerifyP2MRCommitment(in.p2mr->control_block, program, leaf_hash)) {
            error = ERR_INVALID_P2MR;
            return false;
        }
    }
    for (const ChangeOutput& change : pkg.change) {
        if (change.vout >= pkg.unsigned_tx.vout.size() ||
            change.script_pub_key != pkg.unsigned_tx.vout[change.vout].scriptPubKey) {
            error = ERR_WRONG_CHANGE;
            return false;
        }
    }
    return true;
}

bool FillCanonicalDigests(Package& pkg, std::string& error)
{
    if (!ValidateStructure(pkg, error)) return false;
    std::vector<CTxOut> prevouts;
    prevouts.reserve(pkg.inputs.size());
    for (const Input& in : pkg.inputs) prevouts.push_back(PrevoutOf(in));
    for (size_t i = 0; i < pkg.inputs.size(); ++i) {
        Input& in = pkg.inputs[i];
        const auto digest = ComputeInputDigest(pkg.unsigned_tx, prevouts, static_cast<uint32_t>(i),
                                               in.p2mr->leaf_script, in.p2mr->leaf_version, pkg.sighash);
        if (!digest) {
            error = ERR_WRONG_DIGEST;
            return false;
        }
        if (in.digest && *in.digest != *digest) {
            error = ERR_WRONG_DIGEST;
            return false;
        }
        in.digest = *digest;
        if (!in.algo) in.algo = PQAlgorithm::ML_DSA_44;
    }
    return true;
}

bool InsertSignature(Package& pkg, size_t input_index, Span<const unsigned char> signature, std::string& error)
{
    if (input_index >= pkg.inputs.size()) {
        error = ERR_INVALID_STRUCTURE;
        return false;
    }
    return InsertSignature(pkg, input_index, pkg.inputs[input_index].pubkey, signature, error);
}

bool InsertSignature(Package& pkg, size_t input_index, Span<const unsigned char> pubkey,
                     Span<const unsigned char> signature, std::string& error)
{
    if (input_index >= pkg.inputs.size()) {
        error = ERR_INVALID_STRUCTURE;
        return false;
    }
    if (!ValidateStructure(pkg, error)) return false;
    Input& in = pkg.inputs[input_index];
    if (pubkey.empty()) {
        error = ERR_CORRUPT_SIGNATURE;
        return false;
    }
    in.pubkey.assign(pubkey.begin(), pubkey.end());
    if (!in.algo) {
        const auto inferred = GetPQAlgorithmByPubKeySize(in.pubkey.size());
        if (!inferred) {
            error = ERR_CORRUPT_SIGNATURE;
            return false;
        }
        in.algo = *inferred;
    }
    if (!in.digest && !FillCanonicalDigests(pkg, error)) return false;
    in.signature.assign(signature.begin(), signature.end());
    if (!VerifyInputSig(in, *in.digest, error)) {
        in.signature.clear();
        return false;
    }
    return true;
}

bool PackageReadyToBroadcast(const Package& pkg, std::string& error)
{
    if (!ValidateStructure(pkg, error)) return false;
    if (!pkg.network.empty() && pkg.network != Params().GetChainTypeString()) {
        error = ERR_INVALID_STRUCTURE;
        return false;
    }
    std::vector<CTxOut> prevouts;
    prevouts.reserve(pkg.inputs.size());
    for (const Input& in : pkg.inputs) prevouts.push_back(PrevoutOf(in));
    for (size_t i = 0; i < pkg.inputs.size(); ++i) {
        const Input& in = pkg.inputs[i];
        const auto digest = ComputeInputDigest(pkg.unsigned_tx, prevouts, static_cast<uint32_t>(i),
                                               in.p2mr->leaf_script, in.p2mr->leaf_version, pkg.sighash);
        if (!digest) {
            error = ERR_WRONG_DIGEST;
            return false;
        }
        if (in.digest && *in.digest != *digest) {
            error = ERR_WRONG_DIGEST;
            return false;
        }
        if (!VerifyInputSig(in, *digest, error)) return false;
    }
    return true;
}

bool FromPSBT(const PartiallySignedTransaction& psbt, const std::string& network, Package& pkg, std::string& error)
{
    pkg = Package();
    pkg.network = network;
    if (!psbt.tx) {
        error = ERR_INVALID_STRUCTURE;
        return false;
    }
    pkg.unsigned_tx = *psbt.tx;
    if (psbt.inputs.size() != pkg.unsigned_tx.vin.size()) {
        error = ERR_INVALID_STRUCTURE;
        return false;
    }
    for (size_t i = 0; i < psbt.inputs.size(); ++i) {
        const PSBTInput& pin = psbt.inputs[i];
        Input in;
        in.txid = pkg.unsigned_tx.vin[i].prevout.hash;
        in.vout = pkg.unsigned_tx.vin[i].prevout.n;
        CTxOut utxo;
        if (psbt.GetInputUTXO(utxo, static_cast<int>(i)) && !utxo.IsNull()) {
            in.amount = utxo.nValue;
            in.script_pub_key = utxo.scriptPubKey;
        } else {
            error = ERR_MISSING_PREVOUT;
            return false;
        }
        if (in.amount < 0 || !MoneyRange(in.amount)) {
            error = ERR_MISSING_AMOUNT;
            return false;
        }
        if (!pin.m_p2mr_leaf_script.empty() && !pin.m_p2mr_control_block.empty()) {
            P2MRSpend spend;
            spend.leaf_script = pin.m_p2mr_leaf_script;
            spend.control_block = pin.m_p2mr_control_block;
            spend.leaf_version = pin.m_p2mr_leaf_version;
            in.p2mr = spend;
        }
        if (!pin.m_p2mr_bip32_paths.empty()) {
            in.pubkey = pin.m_p2mr_bip32_paths.begin()->first;
        }
        if (!pin.m_p2mr_pq_sigs.empty()) {
            const auto& first = *pin.m_p2mr_pq_sigs.begin();
            if (in.pubkey.empty()) in.pubkey = first.first.second;
            in.signature = first.second;
        }
        if (!in.pubkey.empty()) {
            if (const auto inferred = GetPQAlgorithmByPubKeySize(in.pubkey.size())) in.algo = *inferred;
        }
        pkg.inputs.push_back(std::move(in));
    }
    for (const Input& in : pkg.inputs) {
        if (!in.p2mr) return true;
    }
    return FillCanonicalDigests(pkg, error);
}

bool FromUnsignedTx(const CMutableTransaction& tx, const std::vector<CTxOut>& prevouts,
                    const std::string& network, Package& pkg, std::string& error)
{
    pkg = Package();
    pkg.network = network;
    pkg.unsigned_tx = tx;
    if (tx.vin.empty() || prevouts.size() != tx.vin.size()) {
        error = ERR_MISSING_PREVOUT;
        return false;
    }
    for (size_t i = 0; i < tx.vin.size(); ++i) {
        if (prevouts[i].IsNull() || prevouts[i].scriptPubKey.empty()) {
            error = ERR_MISSING_PREVOUT;
            return false;
        }
        if (prevouts[i].nValue < 0 || !MoneyRange(prevouts[i].nValue)) {
            error = ERR_MISSING_AMOUNT;
            return false;
        }
        Input in;
        in.txid = tx.vin[i].prevout.hash;
        in.vout = tx.vin[i].prevout.n;
        in.amount = prevouts[i].nValue;
        in.script_pub_key = prevouts[i].scriptPubKey;
        pkg.inputs.push_back(std::move(in));
    }
    error.clear();
    return true;
}

bool ApplyToPSBT(const Package& pkg, PartiallySignedTransaction& psbt, std::string& error)
{
    if (!psbt.tx.has_value()) {
        psbt = PartiallySignedTransaction(pkg.unsigned_tx);
    }
    if (psbt.inputs.size() != pkg.inputs.size()) {
        error = ERR_INVALID_STRUCTURE;
        return false;
    }
    for (size_t i = 0; i < pkg.inputs.size(); ++i) {
        const Input& in = pkg.inputs[i];
        PSBTInput& pin = psbt.inputs[i];
        if (in.p2mr) {
            pin.m_p2mr_leaf_script = in.p2mr->leaf_script;
            pin.m_p2mr_control_block = in.p2mr->control_block;
            pin.m_p2mr_leaf_version = in.p2mr->leaf_version;
            int witness_version = 0;
            std::vector<unsigned char> program;
            if (in.script_pub_key.IsWitnessProgram(witness_version, program) && program.size() == 32) {
                pin.m_p2mr_merkle_root = uint256(Span<const unsigned char>{program.data(), program.size()});
            }
        }
        if (!in.signature.empty() && !in.pubkey.empty() && in.p2mr) {
            const uint256 leaf = ComputeP2MRLeafHash(in.p2mr->leaf_version, in.p2mr->leaf_script);
            pin.m_p2mr_pq_sigs[{leaf, in.pubkey}] = in.signature;
        }
        if (pin.witness_utxo.IsNull() && in.amount >= 0) {
            pin.witness_utxo = CTxOut{in.amount, in.script_pub_key};
        }
    }
    return true;
}

bool TryExtractSignedTx(const Package& pkg, CMutableTransaction& tx, std::string& error)
{
    if (!PackageReadyToBroadcast(pkg, error)) return false;
    tx = pkg.unsigned_tx;
    for (size_t i = 0; i < pkg.inputs.size(); ++i) {
        const Input& in = pkg.inputs[i];
        CScriptWitness wit;
        wit.stack.push_back(in.signature);
        wit.stack.push_back(in.p2mr->leaf_script);
        wit.stack.push_back(in.p2mr->control_block);
        tx.vin[i].scriptWitness = std::move(wit);
        tx.vin[i].scriptSig.clear();
    }
    return true;
}

} // namespace bcp1
} // namespace wallet
