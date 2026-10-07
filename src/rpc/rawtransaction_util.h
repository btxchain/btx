// Copyright (c) 2017-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_RPC_RAWTRANSACTION_UTIL_H
#define BITCOIN_RPC_RAWTRANSACTION_UTIL_H

#include <addresstype.h>
#include <consensus/amount.h>
#include <psbt.h>
#include <map>
#include <optional>
#include <string>

struct bilingual_str;
struct FlatSigningProvider;
class UniValue;
struct CMutableTransaction;
class Coin;
class COutPoint;
class SigningProvider;

/**
 * Sign a transaction with the given keystore and previous transactions
 *
 * @param  mtx           The transaction to-be-signed
 * @param  keystore      Temporary keystore containing signing keys
 * @param  coins         Map of unspent outputs
 * @param  hashType      The signature hash type
 * @param result         JSON object where signed transaction results accumulate
 */
void SignTransaction(CMutableTransaction& mtx, const SigningProvider* keystore, const std::map<COutPoint, Coin>& coins, const UniValue& hashType, UniValue& result);
void SignTransactionResultToJSON(CMutableTransaction& mtx, bool complete, const std::map<COutPoint, Coin>& coins, const std::map<int, bilingual_str>& input_errors, UniValue& result, const std::optional<CAmount>& inputs_amount_sum);
void AppendTimelockAdjustment(UniValue& result, const P2MRTimelockAdjustment& adjustment);

/** Read one p2mr_leaf value: a non-negative index, or a hex leaf script. */
void ParseP2MRLeafValue(const UniValue& value, std::optional<uint32_t>& index, std::vector<unsigned char>& script);

/** Optional p2mr_leaf field on each input object. Inputs without the field are skipped. */
std::vector<P2MRLeafSelection> ParseInputsP2MRLeaves(const UniValue& inputs);

/** Updater map {"txid:vout": <index or leaf-script hex>}. */
std::vector<P2MRLeafSelection> ParseP2MRLeafMap(const UniValue& leaf_map);

/**
  * Parse a prevtxs UniValue array and get the map of coins from it
  *
  * @param  prevTxsUnival Array of previous txns outputs that tx depends on but may not yet be in the block chain
  * @param  keystore      A pointer to the temporary keystore if there is one
  * @param  coins         Map of unspent outputs - coins in mempool and current chain UTXO set, may be extended by previous txns outputs after call
  */
void ParsePrevouts(const UniValue& prevTxsUnival, FlatSigningProvider* keystore, std::map<COutPoint, Coin>& coins);

/** Normalize univalue-represented inputs and add them to the transaction */
void AddInputs(CMutableTransaction& rawTx, const UniValue& inputs_in, bool rbf);

/** Normalize univalue-represented outputs */
UniValue NormalizeOutputs(const UniValue& outputs_in);

/** Parse normalized outputs into destination, amount tuples */
std::vector<std::pair<CTxDestination, CAmount>> ParseOutputs(const UniValue& outputs);

/** Normalize, parse, and add outputs to the transaction */
void AddOutputs(CMutableTransaction& rawTx, const UniValue& outputs_in);

/** Create a transaction from univalue parameters */
CMutableTransaction ConstructTransaction(const UniValue& inputs_in, const UniValue& outputs_in, const UniValue& locktime, std::optional<bool> rbf);

#endif // BITCOIN_RPC_RAWTRANSACTION_UTIL_H
