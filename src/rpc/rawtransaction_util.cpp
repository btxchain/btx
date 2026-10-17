// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <rpc/rawtransaction_util.h>

#include <coins.h>
#include <consensus/amount.h>
#include <core_io.h>
#include <key_io.h>
#include <policy/policy.h>
#include <primitives/transaction.h>
#include <rpc/request.h>
#include <rpc/util.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <tinyformat.h>
#include <univalue.h>
#include <util/rbf.h>
#include <util/strencodings.h>
#include <util/translation.h>

#include <optional>

void AddInputs(CMutableTransaction& rawTx, const UniValue& inputs_in, std::optional<bool> rbf)
{
    UniValue inputs;
    if (inputs_in.isNull()) {
        inputs = UniValue::VARR;
    } else {
        inputs = inputs_in.get_array();
    }

    for (unsigned int idx = 0; idx < inputs.size(); idx++) {
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();

        Txid txid = Txid::FromUint256(ParseHashO(o, "txid"));

        const UniValue& vout_v = o.find_value("vout");
        if (!vout_v.isNum())
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, missing vout key");
        int nOutput = vout_v.getInt<int>();
        if (nOutput < 0)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, vout cannot be negative");

        uint32_t nSequence;

        if (rbf.value_or(true)) {
            nSequence = MAX_BIP125_RBF_SEQUENCE; /* CTxIn::SEQUENCE_FINAL - 2 */
        } else if (rawTx.nLockTime) {
            nSequence = CTxIn::MAX_SEQUENCE_NONFINAL; /* CTxIn::SEQUENCE_FINAL - 1 */
        } else {
            nSequence = CTxIn::SEQUENCE_FINAL;
        }

        // set the sequence number if passed in the parameters object
        const UniValue& sequenceObj = o.find_value("sequence");
        if (sequenceObj.isNum()) {
            int64_t seqNr64 = sequenceObj.getInt<int64_t>();
            if (seqNr64 < 0 || seqNr64 > CTxIn::SEQUENCE_FINAL) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, sequence number is out of range");
            } else {
                nSequence = (uint32_t)seqNr64;
            }
        }

        CTxIn in(COutPoint(txid, nOutput), CScript(), nSequence);

        rawTx.vin.push_back(in);
    }
}

UniValue NormalizeOutputs(const UniValue& outputs_in)
{
    if (outputs_in.isNull()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, output argument must be non-null");
    }

    const bool outputs_is_obj = outputs_in.isObject();
    UniValue outputs = outputs_is_obj ? outputs_in.get_obj() : outputs_in.get_array();

    if (!outputs_is_obj) {
        // Translate array of key-value pairs into dict
        UniValue outputs_dict = UniValue(UniValue::VOBJ);
        for (size_t i = 0; i < outputs.size(); ++i) {
            const UniValue& output = outputs[i];
            if (!output.isObject()) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, key-value pair not an object as expected");
            }
            if (output.size() != 1) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, key-value pair must contain exactly one key");
            }
            outputs_dict.pushKVs(output);
        }
        outputs = std::move(outputs_dict);
    }
    return outputs;
}

std::vector<std::pair<CTxDestination, CAmount>> ParseOutputs(const UniValue& outputs)
{
    // Duplicate checking
    std::set<CTxDestination> destinations;
    std::vector<std::pair<CTxDestination, CAmount>> parsed_outputs;
    for (const std::string& name_ : outputs.getKeys()) {
        if (name_ == "data") {
            // BTX is a financial-only chain: OP_RETURN data-carrier outputs are
            // disabled (inscription-elimination plan, Pillar 6). First-party
            // tooling must not be able to mint OP_RETURN data payloads, so the
            // "data" output field is rejected rather than turned into an
            // OP_RETURN scriptPubKey.
            throw JSONRPCError(RPC_INVALID_PARAMETER, "OP_RETURN \"data\" outputs are disabled on BTX (financial-only chain); this output type is not supported");
        } else {
            CTxDestination destination{DecodeDestination(name_)};
            CAmount amount{AmountFromValue(outputs[name_])};
            if (!IsValidDestination(destination)) {
                throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, std::string("Invalid BTX address: ") + name_);
            }

            if (!destinations.insert(destination).second) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, std::string("Invalid parameter, duplicated address: ") + name_);
            }
            parsed_outputs.emplace_back(destination, amount);
        }
    }
    return parsed_outputs;
}

void AddOutputs(CMutableTransaction& rawTx, const UniValue& outputs_in)
{
    UniValue outputs(UniValue::VOBJ);
    outputs = NormalizeOutputs(outputs_in);

    std::vector<std::pair<CTxDestination, CAmount>> parsed_outputs = ParseOutputs(outputs);
    for (const auto& [destination, nAmount] : parsed_outputs) {
        CScript scriptPubKey = GetScriptForDestination(destination);

        CTxOut out(nAmount, scriptPubKey);
        rawTx.vout.push_back(out);
    }
}

CMutableTransaction ConstructTransaction(const UniValue& inputs_in, const UniValue& outputs_in, const UniValue& locktime, std::optional<bool> rbf)
{
    CMutableTransaction rawTx;

    if (!locktime.isNull()) {
        int64_t nLockTime = locktime.getInt<int64_t>();
        if (nLockTime < 0 || nLockTime > LOCKTIME_MAX)
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter, locktime out of range");
        rawTx.nLockTime = nLockTime;
    }

    AddInputs(rawTx, inputs_in, rbf);
    AddOutputs(rawTx, outputs_in);

    if (rbf.has_value() && rbf.value() && rawTx.vin.size() > 0 && !SignalsOptInRBF(CTransaction(rawTx))) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Invalid parameter combination: Sequence number(s) contradict replaceable option");
    }

    return rawTx;
}

/** Pushes a JSON object for script verification or signing errors to vErrorsRet. */
static void TxInErrorToJSON(const CTxIn& txin, UniValue& vErrorsRet, const std::string& strMessage)
{
    UniValue entry(UniValue::VOBJ);
    entry.pushKV("txid", txin.prevout.hash.ToString());
    entry.pushKV("vout", (uint64_t)txin.prevout.n);
    UniValue witness(UniValue::VARR);
    for (unsigned int i = 0; i < txin.scriptWitness.stack.size(); i++) {
        witness.push_back(HexStr(txin.scriptWitness.stack[i]));
    }
    entry.pushKV("witness", std::move(witness));
    entry.pushKV("scriptSig", HexStr(txin.scriptSig));
    entry.pushKV("sequence", (uint64_t)txin.nSequence);
    entry.pushKV("error", strMessage);
    vErrorsRet.push_back(std::move(entry));
}

void ParsePrevouts(const UniValue& prevTxsUnival, FlatSigningProvider* keystore, std::map<COutPoint, Coin>& coins)
{
    if (!prevTxsUnival.isNull()) {
        const UniValue& prevTxs = prevTxsUnival.get_array();
        for (unsigned int idx = 0; idx < prevTxs.size(); ++idx) {
            const UniValue& p = prevTxs[idx];
            if (!p.isObject()) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "expected object with {\"txid'\",\"vout\",\"scriptPubKey\"}");
            }

            const UniValue& prevOut = p.get_obj();

            RPCTypeCheckObj(prevOut,
                {
                    {"txid", UniValueType(UniValue::VSTR)},
                    {"vout", UniValueType(UniValue::VNUM)},
                    {"scriptPubKey", UniValueType(UniValue::VSTR)},
                });

            Txid txid = Txid::FromUint256(ParseHashO(prevOut, "txid"));

            int nOut = prevOut.find_value("vout").getInt<int>();
            if (nOut < 0) {
                throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "vout cannot be negative");
            }

            COutPoint out(txid, nOut);
            std::vector<unsigned char> pkData(ParseHexO(prevOut, "scriptPubKey"));
            CScript scriptPubKey(pkData.begin(), pkData.end());

            {
                auto coin = coins.find(out);
                if (coin != coins.end() && !coin->second.IsSpent() && coin->second.out.scriptPubKey != scriptPubKey) {
                    std::string err("Previous output scriptPubKey mismatch:\n");
                    err = err + ScriptToAsmStr(coin->second.out.scriptPubKey) + "\nvs:\n"+
                        ScriptToAsmStr(scriptPubKey);
                    throw JSONRPCError(RPC_DESERIALIZATION_ERROR, err);
                }
                Coin newcoin;
                newcoin.out.scriptPubKey = scriptPubKey;
                newcoin.out.nValue = MAX_MONEY;
                if (prevOut.exists("amount")) {
                    newcoin.out.nValue = AmountFromValue(prevOut.find_value("amount"));
                }
                newcoin.nHeight = 1;
                coins[out] = std::move(newcoin);
            }

            // if redeemScript and private keys were given, add redeemScript to the keystore so it can be signed
            const bool is_p2sh = scriptPubKey.IsPayToScriptHash();
            const bool is_p2wsh = scriptPubKey.IsPayToWitnessScriptHash();
            if (keystore && (is_p2sh || is_p2wsh)) {
                RPCTypeCheckObj(prevOut,
                    {
                        {"redeemScript", UniValueType(UniValue::VSTR)},
                        {"witnessScript", UniValueType(UniValue::VSTR)},
                    }, true);
                const UniValue& rs{prevOut.find_value("redeemScript")};
                const UniValue& ws{prevOut.find_value("witnessScript")};
                if (rs.isNull() && ws.isNull()) {
                    throw JSONRPCError(RPC_INVALID_PARAMETER, "Missing redeemScript/witnessScript");
                }

                // work from witnessScript when possible
                std::vector<unsigned char> scriptData(!ws.isNull() ? ParseHexV(ws, "witnessScript") : ParseHexV(rs, "redeemScript"));
                CScript script(scriptData.begin(), scriptData.end());
                keystore->scripts.emplace(CScriptID(script), script);
                // Automatically also add the P2WSH wrapped version of the script (to deal with P2SH-P2WSH).
                // This is done for redeemScript only for compatibility, it is encouraged to use the explicit witnessScript field instead.
                CScript witness_output_script{GetScriptForDestination(WitnessV0ScriptHash(script))};
                keystore->scripts.emplace(CScriptID(witness_output_script), witness_output_script);

                if (!ws.isNull() && !rs.isNull()) {
                    // if both witnessScript and redeemScript are provided,
                    // they should either be the same (for backwards compat),
                    // or the redeemScript should be the encoded form of
                    // the witnessScript (ie, for p2sh-p2wsh)
                    if (ws.get_str() != rs.get_str()) {
                        std::vector<unsigned char> redeemScriptData(ParseHexV(rs, "redeemScript"));
                        CScript redeemScript(redeemScriptData.begin(), redeemScriptData.end());
                        if (redeemScript != witness_output_script) {
                            throw JSONRPCError(RPC_INVALID_PARAMETER, "redeemScript does not correspond to witnessScript");
                        }
                    }
                }

                if (is_p2sh) {
                    const CTxDestination p2sh{ScriptHash(script)};
                    const CTxDestination p2sh_p2wsh{ScriptHash(witness_output_script)};
                    if (scriptPubKey == GetScriptForDestination(p2sh)) {
                        // traditional p2sh; arguably an error if
                        // we got here with rs.IsNull(), because
                        // that means the p2sh script was specified
                        // via witnessScript param, but for now
                        // we'll just quietly accept it
                    } else if (scriptPubKey == GetScriptForDestination(p2sh_p2wsh)) {
                        // p2wsh encoded as p2sh; ideally the witness
                        // script was specified in the witnessScript
                        // param, but also support specifying it via
                        // redeemScript param for backwards compat
                        // (in which case ws.IsNull() == true)
                    } else {
                        // otherwise, can't generate scriptPubKey from
                        // either script, so we got unusable parameters
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "redeemScript/witnessScript does not match scriptPubKey");
                    }
                } else if (is_p2wsh) {
                    // plain p2wsh; could throw an error if script
                    // was specified by redeemScript rather than
                    // witnessScript (ie, ws.IsNull() == true), but
                    // accept it for backwards compat
                    const CTxDestination p2wsh{WitnessV0ScriptHash(script)};
                    if (scriptPubKey != GetScriptForDestination(p2wsh)) {
                        throw JSONRPCError(RPC_INVALID_PARAMETER, "redeemScript/witnessScript does not match scriptPubKey");
                    }
                }
            }
        }
    }
}

void SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, const UniValue& hashType, UniValue& result)
{
    int nHashType = ParseSighashString(hashType);

    // Script verification errors
    std::map<int, bilingual_str> input_errors;
    std::optional<CAmount> inputs_amount_sum;

    bool complete = SignTransaction(mtx, keystore, coins, nHashType, input_errors, &inputs_amount_sum);
    SignTransactionResultToJSON(mtx, complete, coins, input_errors, result, inputs_amount_sum);
}

void SignTransactionResultToJSON(CMutableTransaction& mtx, bool complete, const std::map<COutPoint, Coin>& coins, const std::map<int, bilingual_str>& input_errors, UniValue& result, const std::optional<CAmount>& inputs_amount_sum)
{
    // Make errors UniValue
    UniValue vErrors(UniValue::VARR);
    for (const auto& err_pair : input_errors) {
        if (err_pair.second.original == "Missing amount") {
            // This particular error needs to be an exception for some reason
            throw JSONRPCError(RPC_TYPE_ERROR, strprintf("Missing amount for %s", coins.at(mtx.vin.at(err_pair.first).prevout).out.ToString()));
        }
        TxInErrorToJSON(mtx.vin.at(err_pair.first), vErrors, err_pair.second.original);
    }

    CTransaction tx(mtx);
    result.pushKV("hex", EncodeHexTx(tx));
    result.pushKV("complete", complete);
    if (inputs_amount_sum) {
        CAmount inout_amount = *inputs_amount_sum;
        for (const CTxOut& txout : mtx.vout) {
            inout_amount -= txout.nValue;
        }
        result.pushKV("fee", ValueFromAmount(inout_amount));
        result.pushKV("feerate",
            ValueFromAmount(
                CFeeRate(inout_amount, GetVirtualTransactionSize(tx)).GetFeePerK()
            )
        );
    }
    if (!vErrors.empty()) {
        if (result.exists("errors")) {
            vErrors.push_backV(result["errors"].getValues());
        }
        result.pushKV("errors", std::move(vErrors));
    }
}

void AppendTimelockAdjustment(UniValue& result, const P2MRTimelockAdjustment& adjustment)
{
    if (!adjustment.changed) return;
    UniValue obj(UniValue::VOBJ);
    obj.pushKV("txid_before", adjustment.txid_before.GetHex());
    obj.pushKV("txid_after", adjustment.txid_after.GetHex());
    obj.pushKV("locktime_before", static_cast<int64_t>(adjustment.locktime_before));
    obj.pushKV("locktime_after", static_cast<int64_t>(adjustment.locktime_after));
    obj.pushKV("version_before", adjustment.version_before);
    obj.pushKV("version_after", adjustment.version_after);
    UniValue sequences(UniValue::VARR);
    for (const auto& [vin, before, after] : adjustment.sequences) {
        UniValue entry(UniValue::VOBJ);
        entry.pushKV("vin", static_cast<int>(vin));
        entry.pushKV("nsequence_before", static_cast<int64_t>(before));
        entry.pushKV("nsequence_after", static_cast<int64_t>(after));
        sequences.push_back(std::move(entry));
    }
    obj.pushKV("sequences", std::move(sequences));
    result.pushKV("timelock_adjustment", std::move(obj));
}

void ParseP2MRLeafValue(const UniValue& value, std::optional<uint32_t>& index, std::vector<unsigned char>& script)
{
    index.reset();
    script.clear();
    if (value.isNum()) {
        const int leaf = value.getInt<int>();
        if (leaf < 0) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "p2mr_leaf index must be non-negative");
        }
        index = static_cast<uint32_t>(leaf);
        return;
    }
    if (value.isStr()) {
        if (!IsHex(value.get_str())) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "p2mr_leaf script must be hex");
        }
        script = ParseHex(value.get_str());
        if (script.empty()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "p2mr_leaf script is empty");
        }
        return;
    }
    throw JSONRPCError(RPC_INVALID_PARAMETER, "p2mr_leaf must be a leaf index or a leaf script hex");
}

static P2MRLeafSelection LeafSelectionFromOutpoint(const uint256& txid, uint32_t vout, const UniValue& leaf)
{
    P2MRLeafSelection selection;
    selection.txid = txid;
    selection.vout = vout;
    ParseP2MRLeafValue(leaf, selection.index, selection.script);
    return selection;
}

std::vector<P2MRLeafSelection> ParseInputsP2MRLeaves(const UniValue& inputs_in)
{
    std::vector<P2MRLeafSelection> selections;
    if (inputs_in.isNull()) return selections;
    const UniValue inputs = inputs_in.get_array();
    for (unsigned int idx = 0; idx < inputs.size(); ++idx) {
        const UniValue& input = inputs[idx];
        const UniValue& o = input.get_obj();
        if (!o.exists("p2mr_leaf")) continue;
        selections.push_back(LeafSelectionFromOutpoint(ParseHashO(o, "txid"), o["vout"].getInt<uint32_t>(), o["p2mr_leaf"]));
    }
    return selections;
}

std::vector<P2MRLeafSelection> ParseP2MRLeafMap(const UniValue& leaf_map)
{
    std::vector<P2MRLeafSelection> selections;
    if (leaf_map.isNull()) return selections;
    if (!leaf_map.isObject()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "p2mr_leaf must be an object of txid:vout keys");
    }
    for (const std::string& key : leaf_map.getKeys()) {
        const auto colon = key.rfind(':');
        if (colon == std::string::npos || colon == 0 || colon + 1 >= key.size()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "p2mr_leaf key must be txid:vout");
        }
        const auto txid = uint256::FromHex(key.substr(0, colon));
        if (!txid) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "p2mr_leaf key must be txid:vout");
        }
        uint32_t vout{0};
        if (!ParseUInt32(key.substr(colon + 1), &vout)) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "p2mr_leaf key must be txid:vout");
        }
        selections.push_back(LeafSelectionFromOutpoint(*txid, vout, leaf_map[key]));
    }
    return selections;
}
