// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/pqm.h>

#include <hash.h>
#include <primitives/transaction.h>
#include <script/script.h>
#include <serialize.h>

#include <algorithm>
#include <limits>
#include <set>

std::vector<unsigned char> BuildP2MRPubkeyPush(PQAlgorithm algo, Span<const unsigned char> pubkey)
{
    const size_t expected_size = GetPQPubKeySize(algo);
    if (expected_size == 0 || pubkey.size() != expected_size) return {};

    std::vector<unsigned char> script;
    if (expected_size <= 75) {
        script.reserve(1 + pubkey.size());
        script.push_back(static_cast<unsigned char>(expected_size));
    } else if (expected_size <= 0xFF) {
        script.reserve(2 + pubkey.size());
        script.push_back(static_cast<unsigned char>(OP_PUSHDATA1));
        script.push_back(static_cast<unsigned char>(expected_size));
    } else if (expected_size <= 0xFFFF) {
        script.reserve(3 + pubkey.size());
        script.push_back(static_cast<unsigned char>(OP_PUSHDATA2));
        script.push_back(static_cast<unsigned char>(expected_size & 0xFF));
        script.push_back(static_cast<unsigned char>((expected_size >> 8) & 0xFF));
    } else {
        return {};
    }

    script.insert(script.end(), pubkey.begin(), pubkey.end());
    return script;
}

bool ParseP2MRPubkeyPush(Span<const unsigned char> script, size_t offset, PQAlgorithm algo, Span<const unsigned char>& pubkey, size_t& consumed)
{
    const size_t expected_size = GetPQPubKeySize(algo);
    if (expected_size == 0) return false;

    if (expected_size <= 75) {
        if (script.size() < offset + 1 + expected_size) return false;
        if (script[offset] != static_cast<unsigned char>(expected_size)) return false;
        pubkey = script.subspan(offset + 1, expected_size);
        consumed = 1 + expected_size;
        return true;
    }

    if (expected_size <= 0xFF) {
        if (script.size() < offset + 2 + expected_size) return false;
        if (script[offset] != OP_PUSHDATA1) return false;
        if (script[offset + 1] != static_cast<unsigned char>(expected_size)) return false;
        pubkey = script.subspan(offset + 2, expected_size);
        consumed = 2 + expected_size;
        return true;
    }

    if (expected_size <= 0xFFFF) {
        if (script.size() < offset + 3 + expected_size) return false;
        if (script[offset] != OP_PUSHDATA2) return false;
        if (script[offset + 1] != static_cast<unsigned char>(expected_size & 0xFF)) return false;
        if (script[offset + 2] != static_cast<unsigned char>((expected_size >> 8) & 0xFF)) return false;
        pubkey = script.subspan(offset + 3, expected_size);
        consumed = 3 + expected_size;
        return true;
    }

    return false;
}

bool ParseP2MRAnyPubkeyPush(Span<const unsigned char> script, size_t offset, PQAlgorithm& algo, Span<const unsigned char>& pubkey, size_t& consumed)
{
    for (const PQAlgorithm candidate : GetSupportedPQAlgorithms()) {
        if (ParseP2MRPubkeyPush(script, offset, candidate, pubkey, consumed)) {
            algo = candidate;
            return true;
        }
    }
    return false;
}

opcodetype GetP2MRChecksigOpcode(PQAlgorithm algo)
{
    switch (algo) {
    case PQAlgorithm::ML_DSA_44:
        return OP_CHECKSIG_MLDSA;
    case PQAlgorithm::SLH_DSA_128S:
        return OP_CHECKSIG_SLHDSA;
    }
    return OP_INVALIDOPCODE;
}

opcodetype GetP2MRChecksigAddOpcode(PQAlgorithm algo)
{
    switch (algo) {
    case PQAlgorithm::ML_DSA_44:
        return OP_CHECKSIGADD_MLDSA;
    case PQAlgorithm::SLH_DSA_128S:
        return OP_CHECKSIGADD_SLHDSA;
    }
    return OP_INVALIDOPCODE;
}

bool DecodeP2MRChecksigOpcode(opcodetype opcode, PQAlgorithm& algo, bool& is_checksigadd)
{
    switch (opcode) {
    case OP_CHECKSIG_MLDSA:
        algo = PQAlgorithm::ML_DSA_44;
        is_checksigadd = false;
        return true;
    case OP_CHECKSIG_SLHDSA:
        algo = PQAlgorithm::SLH_DSA_128S;
        is_checksigadd = false;
        return true;
    case OP_CHECKSIGADD_MLDSA:
        algo = PQAlgorithm::ML_DSA_44;
        is_checksigadd = true;
        return true;
    case OP_CHECKSIGADD_SLHDSA:
        algo = PQAlgorithm::SLH_DSA_128S;
        is_checksigadd = true;
        return true;
    default:
        return false;
    }
}

uint256 ComputeP2MRLeafHash(uint8_t leaf_version, Span<const unsigned char> script)
{
    return (HashWriter{TaggedHash("P2MRLeaf")} << leaf_version << CompactSizeWriter(script.size()) << script).GetSHA256();
}

uint256 ComputeP2MRBranchHash(const uint256& left, const uint256& right)
{
    HashWriter ss_branch{TaggedHash("P2MRBranch")};
    Span<const unsigned char> left_span{left};
    Span<const unsigned char> right_span{right};
    if (std::lexicographical_compare(left_span.begin(), left_span.end(), right_span.begin(), right_span.end())) {
        ss_branch << left_span << right_span;
    } else {
        ss_branch << right_span << left_span;
    }
    return ss_branch.GetSHA256();
}

uint256 ComputeP2MRMerkleRoot(const std::vector<uint256>& leaf_hashes)
{
    if (leaf_hashes.empty()) return uint256::ZERO;
    if (leaf_hashes.size() == 1) return leaf_hashes.front();

    std::vector<uint256> level = leaf_hashes;
    while (level.size() > 1) {
        std::vector<uint256> next;
        next.reserve((level.size() + 1) / 2);
        for (size_t i = 0; i < level.size(); i += 2) {
            if (i + 1 < level.size()) {
                next.push_back(ComputeP2MRBranchHash(level[i], level[i + 1]));
            } else {
                next.push_back(level[i]);
            }
        }
        level = std::move(next);
    }
    return level.front();
}

bool VerifyP2MRCommitment(
    Span<const unsigned char> control,
    Span<const unsigned char> program,
    const uint256& leaf_hash)
{
    if (program.size() != P2MR_PROGRAM_SIZE) return false;
    if (control.size() < P2MR_CONTROL_BASE_SIZE || control.size() > P2MR_CONTROL_MAX_SIZE) return false;
    if (((control.size() - P2MR_CONTROL_BASE_SIZE) % P2MR_CONTROL_NODE_SIZE) != 0) return false;

    uint256 root = leaf_hash;
    const size_t path_len = (control.size() - P2MR_CONTROL_BASE_SIZE) / P2MR_CONTROL_NODE_SIZE;
    for (size_t i = 0; i < path_len; ++i) {
        const auto node_span = control.subspan(
            P2MR_CONTROL_BASE_SIZE + i * P2MR_CONTROL_NODE_SIZE,
            P2MR_CONTROL_NODE_SIZE);
        const uint256 node_hash{node_span};
        root = ComputeP2MRBranchHash(root, node_hash);
    }

    return std::equal(program.begin(), program.end(), root.begin(), root.end());
}

std::vector<unsigned char> BuildP2MRScript(PQAlgorithm algo, Span<const unsigned char> pubkey)
{
    std::vector<unsigned char> script = BuildP2MRPubkeyPush(algo, pubkey);
    if (script.empty()) return {};
    script.push_back(GetP2MRChecksigOpcode(algo));
    return script;
}

std::vector<unsigned char> BuildP2MRMultisigScript(
    uint8_t threshold,
    const std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>>& pubkeys)
{
    if (pubkeys.size() < 2) return {};
    if (threshold < 1 || threshold > pubkeys.size()) return {};
    if (pubkeys.size() > MAX_PQ_PUBKEYS_PER_MULTISIG) return {};

    std::set<std::pair<PQAlgorithm, std::vector<unsigned char>>> unique_pubkeys;
    for (const auto& [algo, pubkey] : pubkeys) {
        if (!unique_pubkeys.emplace(algo, pubkey).second) return {};
    }

    std::vector<unsigned char> script;
    for (size_t i = 0; i < pubkeys.size(); ++i) {
        const auto& [algo, pubkey] = pubkeys[i];
        std::vector<unsigned char> push = BuildP2MRPubkeyPush(algo, pubkey);
        if (push.empty()) return {};
        script.insert(script.end(), push.begin(), push.end());
        if (script.size() > MAX_P2MR_SCRIPT_SIZE) return {};

        if (i == 0) {
            script.push_back(GetP2MRChecksigOpcode(algo));
        } else {
            script.push_back(GetP2MRChecksigAddOpcode(algo));
        }
        if (script.size() > MAX_P2MR_SCRIPT_SIZE) return {};
    }

    CScript threshold_suffix;
    threshold_suffix << static_cast<int64_t>(threshold) << OP_NUMEQUAL;
    script.insert(script.end(), threshold_suffix.begin(), threshold_suffix.end());
    if (script.size() > MAX_P2MR_SCRIPT_SIZE) return {};
    return script;
}

std::vector<unsigned char> BuildP2MRCTVScript(const uint256& ctv_hash)
{
    CScript script;
    script << std::vector<unsigned char>(ctv_hash.begin(), ctv_hash.end()) << OP_CHECKTEMPLATEVERIFY;
    return std::vector<unsigned char>(script.begin(), script.end());
}

std::vector<unsigned char> BuildP2MRMultisigCTVScript(
    const uint256& ctv_hash,
    uint8_t threshold,
    const std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>>& pubkeys)
{
    std::vector<unsigned char> script = BuildP2MRCTVScript(ctv_hash);
    if (script.empty()) return {};
    script.push_back(OP_DROP);

    const std::vector<unsigned char> multisig_script = BuildP2MRMultisigScript(threshold, pubkeys);
    if (multisig_script.empty()) return {};
    script.insert(script.end(), multisig_script.begin(), multisig_script.end());
    if (script.size() > MAX_P2MR_SCRIPT_SIZE) return {};
    return script;
}

std::vector<unsigned char> BuildP2MRCLTVMultisigScript(
    int64_t locktime,
    uint8_t threshold,
    const std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>>& pubkeys)
{
    CScript prefix;
    prefix << locktime << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    std::vector<unsigned char> script(prefix.begin(), prefix.end());

    const std::vector<unsigned char> multisig_script = BuildP2MRMultisigScript(threshold, pubkeys);
    if (multisig_script.empty()) return {};
    script.insert(script.end(), multisig_script.begin(), multisig_script.end());
    if (script.size() > MAX_P2MR_SCRIPT_SIZE) return {};
    return script;
}

std::vector<unsigned char> BuildP2MRCSVMultisigScript(
    int64_t sequence,
    uint8_t threshold,
    const std::vector<std::pair<PQAlgorithm, std::vector<unsigned char>>>& pubkeys)
{
    if (sequence < 1 || sequence > std::numeric_limits<int32_t>::max()) return {};
    if ((static_cast<uint32_t>(sequence) & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0) return {};

    CScript prefix;
    prefix << sequence << OP_CHECKSEQUENCEVERIFY << OP_DROP;
    std::vector<unsigned char> script(prefix.begin(), prefix.end());

    const std::vector<unsigned char> multisig_script = BuildP2MRMultisigScript(threshold, pubkeys);
    if (multisig_script.empty()) return {};
    script.insert(script.end(), multisig_script.begin(), multisig_script.end());
    if (script.size() > MAX_P2MR_SCRIPT_SIZE) return {};
    return script;
}

std::vector<unsigned char> BuildP2MRCSFSScript(PQAlgorithm algo, Span<const unsigned char> pubkey)
{
    std::vector<unsigned char> script = BuildP2MRPubkeyPush(algo, pubkey);
    if (script.empty()) return {};
    script.push_back(OP_CHECKSIGFROMSTACK);
    return script;
}

std::vector<unsigned char> BuildP2MRCTVCSFSScript(const uint256& ctv_hash, PQAlgorithm algo, Span<const unsigned char> pubkey)
{
    std::vector<unsigned char> script = BuildP2MRCTVScript(ctv_hash);
    if (script.empty()) return {};
    script.push_back(OP_DROP);
    const std::vector<unsigned char> csfs_script = BuildP2MRCSFSScript(algo, pubkey);
    if (csfs_script.empty()) return {};
    script.insert(script.end(), csfs_script.begin(), csfs_script.end());
    return script;
}

std::vector<unsigned char> BuildP2MRCTVChecksigScript(const uint256& ctv_hash, PQAlgorithm algo, Span<const unsigned char> pubkey)
{
    std::vector<unsigned char> script = BuildP2MRCTVScript(ctv_hash);
    if (script.empty()) return {};
    script.push_back(OP_DROP);
    const std::vector<unsigned char> checksig_script = BuildP2MRScript(algo, pubkey);
    if (checksig_script.empty()) return {};
    script.insert(script.end(), checksig_script.begin(), checksig_script.end());
    return script;
}

std::vector<unsigned char> BuildP2MRDelegationScript(
    PQAlgorithm csfs_algo,
    Span<const unsigned char> csfs_pubkey,
    PQAlgorithm checksig_algo,
    Span<const unsigned char> checksig_pubkey)
{
    std::vector<unsigned char> script = BuildP2MRCSFSScript(csfs_algo, csfs_pubkey);
    if (script.empty()) return {};
    script.push_back(OP_VERIFY);
    const std::vector<unsigned char> checksig_script = BuildP2MRScript(checksig_algo, checksig_pubkey);
    if (checksig_script.empty()) return {};
    script.insert(script.end(), checksig_script.begin(), checksig_script.end());
    return script;
}

std::vector<unsigned char> BuildP2MRHTLCLeaf(
    Span<const unsigned char> preimage_hash160,
    PQAlgorithm oracle_algo,
    Span<const unsigned char> oracle_pubkey)
{
    if (preimage_hash160.size() != uint160::size()) return {};

    CScript script;
    script << std::vector<unsigned char>(preimage_hash160.begin(), preimage_hash160.end())
           << OP_OVER << OP_HASH160 << OP_EQUALVERIFY;

    const std::vector<unsigned char> oracle_push = BuildP2MRPubkeyPush(oracle_algo, oracle_pubkey);
    if (oracle_push.empty()) return {};
    script.insert(script.end(), oracle_push.begin(), oracle_push.end());
    script << OP_CHECKSIGFROMSTACK << OP_VERIFY << OP_DROP;
    return std::vector<unsigned char>(script.begin(), script.end());
}

std::vector<unsigned char> BuildP2MRRefundLeaf(
    int64_t timeout,
    PQAlgorithm sender_algo,
    Span<const unsigned char> sender_pubkey)
{
    CScript script;
    script << timeout << OP_CHECKLOCKTIMEVERIFY << OP_DROP;
    const std::vector<unsigned char> checksig_script = BuildP2MRScript(sender_algo, sender_pubkey);
    if (checksig_script.empty()) return {};
    script.insert(script.end(), checksig_script.begin(), checksig_script.end());
    return std::vector<unsigned char>(script.begin(), script.end());
}

std::vector<unsigned char> BuildP2MRAtomicSwapLeaf(
    const uint256& ctv_hash,
    PQAlgorithm spender_algo,
    Span<const unsigned char> spender_pubkey)
{
    return BuildP2MRCTVChecksigScript(ctv_hash, spender_algo, spender_pubkey);
}
