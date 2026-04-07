// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_SCRIPT_PQM_H
#define BITCOIN_SCRIPT_PQM_H

#include <pqkey.h>
#include <script/script.h>
#include <span.h>
#include <uint256.h>

#include <cstddef>
#include <cstdint>
#include <vector>

static constexpr uint8_t P2MR_LEAF_VERSION = 0xc2;
static constexpr uint8_t P2MR_LEAF_MASK = 0xfe;
static constexpr size_t P2MR_PROGRAM_SIZE = 32;
static constexpr size_t P2MR_CONTROL_BASE_SIZE = 1;
static constexpr size_t P2MR_CONTROL_NODE_SIZE = 32;
static constexpr size_t P2MR_CONTROL_MAX_SIZE = 1 + 128 * 32;

uint256 ComputeP2MRLeafHash(uint8_t leaf_version, Span<const unsigned char> script);
uint256 ComputeP2MRBranchHash(const uint256& left, const uint256& right);
uint256 ComputeP2MRMerkleRoot(const std::vector<uint256>& leaf_hashes);

bool VerifyP2MRCommitment(
    Span<const unsigned char> control,
    Span<const unsigned char> program,
    const uint256& leaf_hash);

std::vector<unsigned char> BuildP2MRPubkeyPush(
    PQAlgorithm algo,
    Span<const unsigned char> pubkey);

bool ParseP2MRPubkeyPush(
    Span<const unsigned char> script,
    size_t offset,
    PQAlgorithm algo,
    Span<const unsigned char>& pubkey,
    size_t& consumed);

bool ParseP2MRAnyPubkeyPush(
    Span<const unsigned char> script,
    size_t offset,
    PQAlgorithm& algo,
    Span<const unsigned char>& pubkey,
    size_t& consumed);

opcodetype GetP2MRChecksigOpcode(PQAlgorithm algo);
opcodetype GetP2MRChecksigAddOpcode(PQAlgorithm algo);
bool DecodeP2MRChecksigOpcode(opcodetype opcode, PQAlgorithm& algo, bool& is_checksigadd);

std::vector<unsigned char> BuildP2MRScript(
    PQAlgorithm algo,
    Span<const unsigned char> pubkey);

std::vector<unsigned char> BuildP2MRMultisigScript(
    uint8_t threshold,
    const std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>>& pubkeys);

std::vector<unsigned char> BuildP2MRCTVScript(const uint256& ctv_hash);

std::vector<unsigned char> BuildP2MRMultisigCTVScript(
    const uint256& ctv_hash,
    uint8_t threshold,
    const std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>>& pubkeys);

std::vector<unsigned char> BuildP2MRCLTVMultisigScript(
    int64_t locktime,
    uint8_t threshold,
    const std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>>& pubkeys);

std::vector<unsigned char> BuildP2MRCSVMultisigScript(
    int64_t sequence,
    uint8_t threshold,
    const std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>>& pubkeys);

std::vector<unsigned char> BuildP2MRCSFSScript(
    PQAlgorithm algo,
    Span<const unsigned char> pubkey);

std::vector<unsigned char> BuildP2MRCTVCSFSScript(
    const uint256& ctv_hash,
    PQAlgorithm algo,
    Span<const unsigned char> pubkey);

std::vector<unsigned char> BuildP2MRCTVChecksigScript(
    const uint256& ctv_hash,
    PQAlgorithm algo,
    Span<const unsigned char> pubkey);

std::vector<unsigned char> BuildP2MRDelegationScript(
    PQAlgorithm csfs_algo,
    Span<const unsigned char> csfs_pubkey,
    PQAlgorithm checksig_algo,
    Span<const unsigned char> checksig_pubkey);

std::vector<unsigned char> BuildP2MRHTLCLeaf(
    Span<const unsigned char> preimage_hash160,
    PQAlgorithm oracle_algo,
    Span<const unsigned char> oracle_pubkey);

std::vector<unsigned char> BuildP2MRRefundLeaf(
    int64_t timeout,
    PQAlgorithm sender_algo,
    Span<const unsigned char> sender_pubkey);

std::vector<unsigned char> BuildP2MRAtomicSwapLeaf(
    const uint256& ctv_hash,
    PQAlgorithm spender_algo,
    Span<const unsigned char> spender_pubkey);

#endif // BITCOIN_SCRIPT_PQM_H
