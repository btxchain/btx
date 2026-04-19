// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <common/args.h>
#include <rpc/client.h>
#include <tinyformat.h>

#include <set>
#include <stdint.h>
#include <string>
#include <string_view>

class CRPCConvertParam
{
public:
    std::string methodName; //!< method whose params want conversion
    int paramIdx;           //!< 0-based idx of param to convert
    std::string paramName;  //!< parameter name
    bool also_string{false}; //!< The parameter is also a string
};

// clang-format off
/**
 * Specify a (method, idx, name) here if the argument is a non-string RPC
 * argument and needs to be converted from JSON.
 *
 * @note Parameter indexes start from 0.
 */
static const CRPCConvertParam vRPCConvertParams[] =
{
    { "setmocktime", 0, "timestamp" },
    { "mockscheduler", 0, "delta_time" },
    { "utxoupdatepsbt", 1, "descriptors" },
    { "utxoupdatepsbt", 2, "prevtxs" },
    { "generatetoaddress", 0, "nblocks" },
    { "generatetoaddress", 2, "maxtries" },
    { "generatetodescriptor", 0, "num_blocks" },
    { "generatetodescriptor", 2, "maxtries" },
    { "generateblock", 1, "transactions" },
    { "generateblock", 2, "submit" },
    { "getnetworkhashps", 0, "nblocks" },
    { "getnetworkhashps", 1, "height" },
    { "getdifficultyhealth", 0, "window_blocks" },
    { "getmatmulchallengeprofile", 0, "target_solve_time_s" },
    { "getmatmulchallengeprofile", 1, "validation_overhead_s" },
    { "getmatmulchallengeprofile", 2, "propagation_overhead_s" },
    { "getmatmulchallengeprofile", 3, "solver_parallelism" },
    { "getmatmulchallengeprofile", 4, "solver_duty_cycle_pct" },
    { "getmatmulservicechallenge", 3, "target_solve_time_s" },
    { "getmatmulservicechallenge", 4, "expires_in_s" },
    { "getmatmulservicechallenge", 5, "validation_overhead_s" },
    { "getmatmulservicechallenge", 6, "propagation_overhead_s" },
    { "getmatmulservicechallenge", 8, "difficulty_window_blocks" },
    { "getmatmulservicechallenge", 9, "min_solve_time_s" },
    { "getmatmulservicechallenge", 10, "max_solve_time_s" },
    { "getmatmulservicechallenge", 11, "solver_parallelism" },
    { "getmatmulservicechallenge", 12, "solver_duty_cycle_pct" },
    { "getmatmulservicechallengeplan", 1, "objective_value" },
    { "getmatmulservicechallengeplan", 2, "validation_overhead_s" },
    { "getmatmulservicechallengeplan", 3, "propagation_overhead_s" },
    { "getmatmulservicechallengeplan", 5, "difficulty_window_blocks" },
    { "getmatmulservicechallengeplan", 6, "min_solve_time_s" },
    { "getmatmulservicechallengeplan", 7, "max_solve_time_s" },
    { "getmatmulservicechallengeplan", 8, "solver_parallelism" },
    { "getmatmulservicechallengeplan", 9, "solver_duty_cycle_pct" },
    { "getmatmulservicechallengeprofile", 1, "validation_overhead_s" },
    { "getmatmulservicechallengeprofile", 2, "propagation_overhead_s" },
    { "getmatmulservicechallengeprofile", 3, "min_solve_time_s" },
    { "getmatmulservicechallengeprofile", 4, "max_solve_time_s" },
    { "getmatmulservicechallengeprofile", 5, "solve_time_multiplier" },
    { "getmatmulservicechallengeprofile", 7, "difficulty_window_blocks" },
    { "getmatmulservicechallengeprofile", 8, "solver_parallelism" },
    { "getmatmulservicechallengeprofile", 9, "solver_duty_cycle_pct" },
    { "listmatmulservicechallengeprofiles", 0, "validation_overhead_s" },
    { "listmatmulservicechallengeprofiles", 1, "propagation_overhead_s" },
    { "listmatmulservicechallengeprofiles", 2, "min_solve_time_s" },
    { "listmatmulservicechallengeprofiles", 3, "max_solve_time_s" },
    { "listmatmulservicechallengeprofiles", 4, "solve_time_multiplier" },
    { "listmatmulservicechallengeprofiles", 6, "difficulty_window_blocks" },
    { "listmatmulservicechallengeprofiles", 7, "solver_parallelism" },
    { "listmatmulservicechallengeprofiles", 8, "solver_duty_cycle_pct" },
    { "issuematmulservicechallengeprofile", 4, "expires_in_s" },
    { "issuematmulservicechallengeprofile", 5, "validation_overhead_s" },
    { "issuematmulservicechallengeprofile", 6, "propagation_overhead_s" },
    { "issuematmulservicechallengeprofile", 7, "min_solve_time_s" },
    { "issuematmulservicechallengeprofile", 8, "max_solve_time_s" },
    { "issuematmulservicechallengeprofile", 9, "solve_time_multiplier" },
    { "issuematmulservicechallengeprofile", 11, "difficulty_window_blocks" },
    { "issuematmulservicechallengeprofile", 12, "solver_parallelism" },
    { "issuematmulservicechallengeprofile", 13, "solver_duty_cycle_pct" },
    { "solvematmulservicechallenge", 0, "challenge" },
    { "solvematmulservicechallenge", 1, "max_tries" },
    { "solvematmulservicechallenge", 2, "time_budget_ms" },
    { "solvematmulservicechallenge", 3, "solver_threads" },
    { "verifymatmulserviceproof", 0, "challenge" },
    { "verifymatmulserviceproof", 3, "lookup_local_status" },
    { "redeemmatmulserviceproof", 0, "challenge" },
    { "verifymatmulserviceproofs", 0, "proofs" },
    { "verifymatmulserviceproofs", 1, "lookup_local_status" },
    { "redeemmatmulserviceproofs", 0, "proofs" },
    { "sendtoaddress", 1, "amount" },
    { "sendtoaddress", 4, "subtractfeefromamount" },
    { "sendtoaddress", 5 , "replaceable" },
    { "sendtoaddress", 6 , "conf_target" },
    { "sendtoaddress", 8, "avoid_reuse" },
    { "sendtoaddress", 9, "fee_rate"},
    { "sendtoaddress", 10, "verbose"},
    { "setfeerate", 0, "amount" },
    { "settxfee", 0, "amount" },
    { "sethdseed", 0, "newkeypool" },
    { "getreceivedbyaddress", 1, "minconf" },
    { "getreceivedbyaddress", 2, "include_immature_coinbase" },
    { "getreceivedbylabel", 1, "minconf" },
    { "getreceivedbylabel", 2, "include_immature_coinbase" },
    { "listreceivedbyaddress", 0, "minconf" },
    { "listreceivedbyaddress", 1, "include_empty" },
    { "listreceivedbyaddress", 2, "include_watchonly" },
    { "listreceivedbyaddress", 4, "include_immature_coinbase" },
    { "listreceivedbylabel", 0, "minconf" },
    { "listreceivedbylabel", 1, "include_empty" },
    { "listreceivedbylabel", 2, "include_watchonly" },
    { "listreceivedbylabel", 3, "include_immature_coinbase" },
    { "getbalance", 1, "minconf" },
    { "getbalance", 2, "include_watchonly" },
    { "getbalance", 3, "avoid_reuse" },
    { "getblockfrompeer", 1, "peer_id" },
    { "getblockfrompeer", 1, "nodeid" },
    { "getblockhash", 0, "height" },
    { "maxmempool", 0, "megabytes" },
    { "waitforblockheight", 0, "height" },
    { "waitforblockheight", 1, "timeout" },
    { "waitforblock", 1, "timeout" },
    { "waitfornewblock", 0, "timeout" },
    { "listtransactions", 1, "count" },
    { "listtransactions", 2, "skip" },
    { "listtransactions", 3, "include_watchonly" },
    { "walletpassphrase", 1, "timeout" },
    { "getblocktemplate", 0, "template_request" },
    { "listsinceblock", 1, "target_confirmations" },
    { "listsinceblock", 2, "include_watchonly" },
    { "listsinceblock", 3, "include_removed" },
    { "listsinceblock", 4, "include_change" },
    { "sendmany", 1, "amounts" },
    { "sendmany", 2, "minconf" },
    { "sendmany", 4, "subtractfeefrom" },
    { "sendmany", 5 , "replaceable" },
    { "sendmany", 6 , "conf_target" },
    { "sendmany", 8, "fee_rate"},
    { "sendmany", 9, "verbose" },
    { "deriveaddresses", 1, "range" },
    { "deriveaddresses", 2, "options" },
    { "deriveaddresses", 2, "require_checksum" },
    { "deriveaddresses", 2, "allow_op_success" },
    { "getdescriptorinfo", 1, "options" },
    { "getdescriptorinfo", 1, "allow_op_success" },
    { "scanblocks", 1, "scanobjects" },
    { "scanblocks", 2, "start_height" },
    { "scanblocks", 3, "stop_height" },
    { "scanblocks", 5, "options" },
    { "scanblocks", 5, "filter_false_positives" },
    { "getdescriptoractivity", 0, "blockhashes" },
    { "getdescriptoractivity", 1, "scanobjects" },
    { "getdescriptoractivity", 2, "include_mempool" },
    { "sweepprivkeys", 0, "options" },
    { "sweepprivkeys", 0, "privkeys" },
    { "scantxoutset", 1, "scanobjects" },
    { "dumptxoutset", 1, "format" },
    { "dumptxoutset", 2, "format" },
    { "dumptxoutset", 2, "show_header" },
    { "addmultisigaddress", 0, "nrequired" },
    { "addmultisigaddress", 1, "keys" },
    { "addmultisigaddress", 2, "options" },
    { "addmultisigaddress", 2, "sort" },
    { "addpqmultisigaddress", 0, "nrequired" },
    { "addpqmultisigaddress", 1, "keys" },
    { "addpqmultisigaddress", 3, "sort" },
    { "createmultisig", 0, "nrequired" },
    { "createmultisig", 1, "keys" },
    { "createmultisig", 2, "options" },
    { "createmultisig", 2, "sort" },
    { "listunspent", 0, "minconf" },
    { "listunspent", 1, "maxconf" },
    { "listunspent", 2, "addresses" },
    { "listunspent", 3, "include_unsafe" },
    { "listunspent", 4, "query_options" },
    { "listunspent", 4, "minimumAmount" },
    { "listunspent", 4, "maximumAmount" },
    { "listunspent", 4, "maximumCount" },
    { "listunspent", 4, "minimumSumAmount" },
    { "listunspent", 4, "include_immature_coinbase" },
    { "getblock", 1, "verbosity" },
    { "getblock", 1, "verbose" },
    { "getblockheader", 1, "verbose" },
    { "getblocklocations", 1, "nblocks" },
    { "getchaintxstats", 0, "nblocks" },
    { "gettransaction", 1, "include_watchonly" },
    { "gettransaction", 2, "verbose" },
    { "getrawtransaction", 1, "verbosity" },
    { "getrawtransaction", 1, "verbose" },
    { "createrawtransaction", 0, "inputs" },
    { "createrawtransaction", 1, "outputs" },
    { "createrawtransaction", 2, "locktime" },
    { "createrawtransaction", 3, "replaceable" },
    { "decoderawtransaction", 1, "iswitness" },
    { "signrawtransactionwithkey", 1, "privkeys" },
    { "signrawtransactionwithkey", 2, "prevtxs" },
    { "signrawtransactionwithwallet", 1, "prevtxs" },
    { "sendrawtransaction", 1, "maxfeerate" },
    { "sendrawtransaction", 2, "maxburnamount" },
    { "sendrawtransaction", 3, "ignore_rejects" },
    { "testmempoolaccept", 0, "rawtxs" },
    { "testmempoolaccept", 1, "maxfeerate" },
    { "testmempoolaccept", 2, "ignore_rejects" },
    { "submitpackage", 0, "package" },
    { "submitpackage", 1, "maxfeerate" },
    { "submitpackage", 2, "maxburnamount" },
    { "combinerawtransaction", 0, "txs" },
    { "fundrawtransaction", 1, "options" },
    { "fundrawtransaction", 1, "add_inputs"},
    { "fundrawtransaction", 1, "include_unsafe"},
    { "fundrawtransaction", 1, "minconf"},
    { "fundrawtransaction", 1, "maxconf"},
    { "fundrawtransaction", 1, "changePosition"},
    { "fundrawtransaction", 1, "includeWatching"},
    { "fundrawtransaction", 1, "lockUnspents"},
    { "fundrawtransaction", 1, "fee_rate"},
    { "fundrawtransaction", 1, "feeRate"},
    { "fundrawtransaction", 1, "segwit_inputs_only"},
    { "fundrawtransaction", 1, "subtractFeeFromOutputs"},
    { "fundrawtransaction", 1, "input_weights"},
    { "fundrawtransaction", 1, "conf_target"},
    { "fundrawtransaction", 1, "replaceable"},
    { "fundrawtransaction", 1, "solving_data"},
    { "fundrawtransaction", 1, "max_tx_weight"},
    { "fundrawtransaction", 2, "iswitness" },
    { "walletcreatefundedpsbt", 0, "inputs" },
    { "walletcreatefundedpsbt", 1, "outputs" },
    { "walletcreatefundedpsbt", 2, "locktime" },
    { "walletcreatefundedpsbt", 3, "options" },
    { "walletcreatefundedpsbt", 3, "add_inputs"},
    { "walletcreatefundedpsbt", 3, "include_unsafe"},
    { "walletcreatefundedpsbt", 3, "minconf"},
    { "walletcreatefundedpsbt", 3, "maxconf"},
    { "walletcreatefundedpsbt", 3, "changePosition"},
    { "walletcreatefundedpsbt", 3, "includeWatching"},
    { "walletcreatefundedpsbt", 3, "lockUnspents"},
    { "walletcreatefundedpsbt", 3, "fee_rate"},
    { "walletcreatefundedpsbt", 3, "feeRate"},
    { "walletcreatefundedpsbt", 3, "subtractFeeFromOutputs"},
    { "walletcreatefundedpsbt", 3, "conf_target"},
    { "walletcreatefundedpsbt", 3, "replaceable"},
    { "walletcreatefundedpsbt", 3, "solving_data"},
    { "walletcreatefundedpsbt", 3, "max_tx_weight"},
    { "walletcreatefundedpsbt", 4, "bip32derivs" },
    { "walletprocesspsbt", 1, "options" },
    { "walletprocesspsbt", 1, "sign" },
    { "walletprocesspsbt", 1, "bip32derivs" },
    { "walletprocesspsbt", 1, "finalize" },
    { "walletprocesspsbt", 3, "bip32derivs" },
    { "walletprocesspsbt", 4, "finalize" },
    { "descriptorprocesspsbt", 1, "descriptors"},
    { "descriptorprocesspsbt", 2, "options" },
    { "descriptorprocesspsbt", 2, "bip32derivs" },
    { "descriptorprocesspsbt", 2, "finalize" },
    { "descriptorprocesspsbt", 2, "prevtxs" },
    { "descriptorprocesspsbt", 3, "bip32derivs" },
    { "descriptorprocesspsbt", 4, "finalize" },
    { "createpsbt", 0, "inputs" },
    { "createpsbt", 1, "outputs" },
    { "createpsbt", 2, "locktime" },
    { "createpsbt", 3, "replaceable" },
    { "combinepsbt", 0, "txs"},
    { "joinpsbts", 0, "txs"},
    { "finalizepsbt", 1, "extract"},
    { "converttopsbt", 1, "permitsigdata"},
    { "converttopsbt", 2, "iswitness"},
    { "gettxout", 1, "n" },
    { "gettxout", 2, "include_mempool" },
    { "gettxoutproof", 0, "txids" },
    { "gettxoutproof", 2, "options" },
    { "gettxoutproof", 2, "prove_witness" },
    { "verifytxoutproof", 1, "options" },
    { "verifytxoutproof", 1, "verify_witness" },
    { "gettxoutsetinfo", 1, "hash_or_height", /*also_string=*/true },
    { "gettxoutsetinfo", 2, "use_index"},
    { "dumptxoutset", 2, "options" },
    { "dumptxoutset", 2, "rollback", /*also_string=*/true },
    { "lockunspent", 0, "unlock" },
    { "lockunspent", 1, "transactions" },
    { "lockunspent", 2, "persistent" },
    { "send", 0, "outputs" },
    { "send", 1, "conf_target" },
    { "send", 3, "fee_rate"},
    { "send", 4, "options" },
    { "send", 4, "add_inputs"},
    { "send", 4, "include_unsafe"},
    { "send", 4, "minconf"},
    { "send", 4, "maxconf"},
    { "send", 4, "add_to_wallet"},
    { "send", 4, "change_position"},
    { "send", 4, "fee_rate"},
    { "send", 4, "include_watching"},
    { "send", 4, "inputs"},
    { "send", 4, "locktime"},
    { "send", 4, "lock_unspents"},
    { "send", 4, "psbt"},
    { "send", 4, "subtract_fee_from_outputs"},
    { "send", 4, "conf_target"},
    { "send", 4, "replaceable"},
    { "send", 4, "solving_data"},
    { "send", 4, "max_tx_weight"},
    { "sendall", 0, "recipients" },
    { "sendall", 1, "conf_target" },
    { "sendall", 3, "fee_rate"},
    { "sendall", 4, "options" },
    { "sendall", 4, "add_to_wallet"},
    { "sendall", 4, "fee_rate"},
    { "sendall", 4, "include_watching"},
    { "sendall", 4, "preferred_pq_algo"},
    { "sendall", 4, "inputs"},
    { "sendall", 4, "locktime"},
    { "sendall", 4, "lock_unspents"},
    { "sendall", 4, "psbt"},
    { "sendall", 4, "send_max"},
    { "sendall", 4, "minconf"},
    { "sendall", 4, "maxconf"},
    { "sendall", 4, "conf_target"},
    { "sendall", 4, "replaceable"},
    { "sendall", 4, "solving_data"},
    { "sweeptoself", 0, "options" },
    { "sweeptoself", 0, "fee_rate" },
    { "sweeptoself", 0, "minconf" },
    { "sweeptoself", 0, "maxconf" },
    { "sweeptoself", 0, "include_unsafe" },
    { "sweeptoself", 0, "lock_unspents" },
    { "simulaterawtransaction", 0, "rawtxs" },
    { "simulaterawtransaction", 1, "options" },
    { "simulaterawtransaction", 1, "include_watchonly"},
    { "importprivkey", 2, "rescan" },
    { "importaddress", 2, "rescan" },
    { "importaddress", 3, "p2sh" },
    { "importpubkey", 2, "rescan" },
    { "importmempool", 1, "options" },
    { "importmempool", 1, "apply_fee_delta_priority" },
    { "importmempool", 1, "use_current_time" },
    { "importmempool", 1, "apply_unbroadcast_set" },
    { "z_getnewaddress", 0, "account" },
    { "z_getbalance", 0, "minconf" },
    { "z_listunspent", 0, "minconf" },
    { "z_listunspent", 1, "maxconf" },
    { "z_listunspent", 2, "include_watchonly" },
    { "z_sendtoaddress", 1, "amount" },
    { "z_sendtoaddress", 4, "subtractfeefromamount" },
    { "z_sendtoaddress", 5, "fee" },
    { "z_sendtoaddress", 6, "verbose" },
    { "z_sendtoaddress", 7, "conf_target" },
    { "z_sendmany", 0, "amounts" },
    { "z_sendmany", 1, "fee" },
    { "z_sendmany", 2, "subtractfeefromamount" },
    { "z_sendmany", 3, "conf_target" },
    { "z_shieldcoinbase", 1, "fee" },
    { "z_shieldcoinbase", 2, "limit" },
    { "z_shieldcoinbase", 3, "conf_target" },
    { "z_shieldfunds", 0, "amount" },
    { "z_shieldfunds", 2, "fee" },
    { "z_mergenotes", 0, "max_notes" },
    { "z_mergenotes", 1, "fee" },
    { "z_importviewingkey", 3, "rescan" },
    { "z_importviewingkey", 4, "start_height" },
    { "z_gettotalbalance", 0, "minconf" },
    { "z_listreceivedbyaddress", 0, "minconf" },
    { "z_listreceivedbyaddress", 1, "include_watchonly" },
    { "bridge_planin", 2, "amount" },
    { "bridge_planin", 3, "options" },
    { "bridge_planbatchin", 2, "leaves" },
    { "bridge_planbatchin", 3, "options" },
    { "bridge_planout", 3, "amount" },
    { "bridge_planout", 4, "options" },
    { "bridge_planbatchout", 2, "payouts" },
    { "bridge_planbatchout", 3, "options" },
    { "bridge_buildverifierset", 0, "attestors" },
    { "bridge_buildverifierset", 1, "options" },
    { "bridge_buildproofprofile", 0, "profile" },
    { "bridge_buildproofclaim", 1, "options" },
    { "bridge_buildproofadapter", 0, "adapter" },
    { "bridge_buildproofartifact", 1, "artifact" },
    { "bridge_builddataartifact", 1, "artifact" },
    { "bridge_buildaggregateartifactbundle", 1, "bundle" },
    { "bridge_buildaggregatesettlement", 1, "aggregate" },
    { "bridge_buildproofcompressiontarget", 1, "options" },
    { "bridge_buildshieldedstateprofile", 0, "state_profile" },
    { "bridge_buildstateretentionpolicy", 0, "retention_policy" },
    { "bridge_buildproversample", 0, "sample" },
    { "bridge_buildproverprofile", 0, "samples" },
    { "bridge_buildproverbenchmark", 0, "profiles" },
    { "bridge_estimatestategrowth", 1, "options" },
    { "bridge_estimatestateretention", 1, "options" },
    { "bridge_estimatecapacity", 0, "footprint" },
    { "bridge_estimatecapacity", 1, "options" },
    { "bridge_buildproofpolicy", 0, "descriptors" },
    { "bridge_buildproofpolicy", 1, "options" },
    { "bridge_buildbatchstatement", 1, "leaves" },
    { "bridge_buildbatchstatement", 2, "options" },
    { "bridge_signbatchreceipt", 2, "options" },
    { "bridge_buildproofreceipt", 1, "proof_receipt" },
    { "bridge_buildproofanchor", 1, "proof_receipts" },
    { "bridge_buildproofanchor", 2, "options" },
    { "bridge_buildhybridanchor", 1, "receipts" },
    { "bridge_buildhybridanchor", 2, "proof_receipts" },
    { "bridge_buildhybridanchor", 3, "options" },
    { "bridge_buildexternalanchor", 1, "receipts" },
    { "bridge_buildexternalanchor", 2, "options" },
    { "bridge_signbatchauthorization", 2, "authorization" },
    { "bridge_signbatchauthorization", 3, "options" },
    { "bridge_buildbatchcommitment", 1, "leaves" },
    { "bridge_buildbatchcommitment", 2, "options" },
    { "bridge_buildshieldtx", 2, "vout" },
    { "bridge_buildshieldtx", 3, "amount" },
    { "bridge_submitshieldtx", 2, "vout" },
    { "bridge_submitshieldtx", 3, "amount" },
    { "bridge_buildunshieldtx", 2, "vout" },
    { "bridge_buildunshieldtx", 3, "amount" },
    { "bridge_submitunshieldtx", 2, "vout" },
    { "bridge_submitunshieldtx", 3, "amount" },
    { "bridge_buildrefund", 2, "vout" },
    { "bridge_buildrefund", 3, "amount" },
    { "bridge_buildrefund", 5, "fee" },
    { "bridge_buildrefund", 6, "enforce_timeout" },
    { "importmulti", 0, "requests" },
    { "importmulti", 1, "options" },
    { "importmulti", 1, "rescan" },
    { "importdescriptors", 0, "requests" },
    { "importdescriptors", 1, "seeds" },
    { "listdescriptors", 0, "private" },
    { "verifychain", 0, "checklevel" },
    { "verifychain", 1, "nblocks" },
    { "getblockstats", 0, "hash_or_height", /*also_string=*/true },
    { "getblockstats", 1, "stats" },
    { "getblockfileinfo", 0, "file_number" },
    { "setprunelock", 1, "lock_info" },
    { "pruneblockchain", 0, "height" },
    { "keypoolrefill", 0, "newsize" },
    { "getmempoolinfo", 0, "fee_histogram" },
    { "getmempoolinfo", 0, "with_fee_histogram" },
    { "getrawmempool", 0, "verbose" },
    { "getrawmempool", 1, "mempool_sequence" },
    { "getorphantxs", 0, "verbosity" },
    { "estimatesmartfee", 0, "conf_target" },
    { "estimaterawfee", 0, "conf_target" },
    { "estimaterawfee", 1, "threshold" },
    { "prioritisetransaction", 1, "priority_delta" },
    { "prioritisetransaction", 2, "fee_delta" },
    { "setban", 2, "bantime" },
    { "setban", 3, "absolute" },
    { "setnetworkactive", 0, "state" },
    { "setwalletflag", 1, "value" },
    { "getmempoolancestors", 1, "verbose" },
    { "getmempooldescendants", 1, "verbose" },
    { "gettxspendingprevout", 0, "outputs" },
    { "bumpfee", 1, "options" },
    { "bumpfee", 1, "conf_target"},
    { "bumpfee", 1, "fee_rate"},
    { "bumpfee", 1, "replaceable"},
    { "bumpfee", 1, "require_replacable"},
    { "bumpfee", 1, "outputs"},
    { "bumpfee", 1, "original_change_index"},
    { "psbtbumpfee", 1, "options" },
    { "psbtbumpfee", 1, "conf_target"},
    { "psbtbumpfee", 1, "fee_rate"},
    { "psbtbumpfee", 1, "replaceable"},
    { "psbtbumpfee", 1, "require_replacable"},
    { "psbtbumpfee", 1, "outputs"},
    { "psbtbumpfee", 1, "original_change_index"},
    { "logging", 0, "include" },
    { "logging", 1, "exclude" },
    { "disconnectnode", 1, "nodeid" },
    { "upgradewallet", 0, "version" },
    { "gethdkeys", 0, "active_only" },
    { "gethdkeys", 0, "options" },
    { "gethdkeys", 0, "private" },
    { "createwalletdescriptor", 1, "options" },
    { "createwalletdescriptor", 1, "internal" },
    // Echo with conversion (For testing only)
    { "echojson", 0, "arg0" },
    { "echojson", 1, "arg1" },
    { "echojson", 2, "arg2" },
    { "echojson", 3, "arg3" },
    { "echojson", 4, "arg4" },
    { "echojson", 5, "arg5" },
    { "echojson", 6, "arg6" },
    { "echojson", 7, "arg7" },
    { "echojson", 8, "arg8" },
    { "echojson", 9, "arg9" },
    { "rescanblockchain", 0, "start_height"},
    { "rescanblockchain", 1, "stop_height"},
    { "setscriptthreadsenabled", 0, "state"},
    { "createwallet", 1, "disable_private_keys"},
    { "createwallet", 2, "blank"},
    { "createwallet", 4, "avoid_reuse"},
    { "createwallet", 5, "descriptors"},
    { "createwallet", 6, "load_on_startup"},
    { "createwallet", 7, "external_signer"},
    { "restorewallet", 2, "load_on_startup"},
    { "loadwallet", 1, "load_on_startup"},
    { "unloadwallet", 1, "load_on_startup"},
    { "getnodeaddresses", 0, "count"},
    { "addpeeraddress", 1, "port"},
    { "addpeeraddress", 2, "tried"},
    { "sendmsgtopeer", 0, "peer_id" },
    { "stop", 0, "wait" },
    { "addnode", 2, "v2transport" },
    { "addconnection", 2, "v2transport" },
    { "listmempooltransactions", 0, "start_sequence"},
    { "listmempooltransactions", 1, "verbose"},
};
// clang-format on

/** Parse string to UniValue or throw runtime_error if string contains invalid JSON */
static UniValue Parse(std::string_view raw, bool also_string)
{
    UniValue parsed;
    if (!parsed.read(raw)) {
        if (!also_string) throw std::runtime_error(tfm::format("Error parsing JSON: %s", raw));
        return raw;
    }
    return parsed;
}

class CRPCConvertTable
{
private:
    std::map<std::pair<std::string, int>, bool> members;
    std::map<std::pair<std::string, std::string>, bool> membersByName;

public:
    CRPCConvertTable();

    /** Return arg_value as UniValue, and first parse it if it is a non-string parameter */
    UniValue ArgToUniValue(std::string_view arg_value, const std::string& method, int param_idx)
    {
        const auto& it = members.find({method, param_idx});
        if (it != members.end()) {
            return Parse(arg_value, it->second);
        }
        return arg_value;
    }

    /** Return arg_value as UniValue, and first parse it if it is a non-string parameter */
    UniValue ArgToUniValue(std::string_view arg_value, const std::string& method, const std::string& param_name)
    {
        const auto& it = membersByName.find({method, param_name});
        if (it != membersByName.end()) {
            return Parse(arg_value, it->second);
        }
        return arg_value;
    }
};

CRPCConvertTable::CRPCConvertTable()
{
    for (const auto& cp : vRPCConvertParams) {
        members.emplace(std::make_pair(cp.methodName, cp.paramIdx), cp.also_string);
        membersByName.emplace(std::make_pair(cp.methodName, cp.paramName), cp.also_string);
    }
}

static CRPCConvertTable rpcCvtTable;

UniValue RPCConvertValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VARR);

    for (unsigned int idx = 0; idx < strParams.size(); idx++) {
        std::string_view value{strParams[idx]};
        params.push_back(rpcCvtTable.ArgToUniValue(value, strMethod, idx));
    }

    return params;
}

UniValue RPCConvertNamedValues(const std::string &strMethod, const std::vector<std::string> &strParams)
{
    UniValue params(UniValue::VOBJ);
    UniValue positional_args{UniValue::VARR};

    for (std::string_view s: strParams) {
        size_t pos = s.find('=');
        if (pos == std::string::npos) {
            positional_args.push_back(rpcCvtTable.ArgToUniValue(s, strMethod, positional_args.size()));
            continue;
        }

        std::string name{s.substr(0, pos)};
        std::string_view value{s.substr(pos+1)};

        // Intentionally overwrite earlier named values with later ones as a
        // convenience for scripts and command line users that want to merge
        // options.
        params.pushKV(name, rpcCvtTable.ArgToUniValue(value, strMethod, name));
    }

    if (!positional_args.empty()) {
        // Use pushKVEnd instead of pushKV to avoid overwriting an explicit
        // "args" value with an implicit one. Let the RPC server handle the
        // request as given.
        params.pushKVEnd("args", std::move(positional_args));
    }

    return params;
}
