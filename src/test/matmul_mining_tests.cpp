// Copyright (c) 2026 The BTX developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <consensus/merkle.h>
#include <common/system.h>
#include <consensus/consensus.h>
#include <interfaces/mining.h>
#include <matmul/matmul_pow.h>
#include <node/miner.h>
#include <pow.h>
#include <rpc/server.h>
#include <streams.h>
#include <test/util/mining.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/strencodings.h>
#include <validation.h>

#include <boost/test/unit_test.hpp>

#include <charconv>
#include <optional>
#include <stdexcept>
#include <string>

namespace {

class MatMulMiningTestingSetup : public TestingSetup {
public:
    static TestOpts BuildOpts()
    {
        TestOpts opts;
        opts.extra_args = {"-test=matmulstrict"};
        return opts;
    }

    MatMulMiningTestingSetup()
        : TestingSetup{ChainType::REGTEST, BuildOpts()}
    {
        m_node.mining = interfaces::MakeMining(m_node);
    }

    UniValue CallRPC(const std::string& method, UniValue params = UniValue{UniValue::VARR})
    {
        JSONRPCRequest request;
        request.context = &m_node;
        request.strMethod = method;
        request.params = std::move(params);
        if (RPCIsInWarmup(nullptr)) SetRPCWarmupFinished();
        try {
            return tableRPC.execute(request);
        } catch (const UniValue& obj_error) {
            throw std::runtime_error{obj_error.find_value("message").get_str()};
        }
    }

    int ActiveHeight() const
    {
        return WITH_LOCK(cs_main, return m_node.chainman->ActiveHeight());
    }

    uint256 ActiveTipHash() const
    {
        return WITH_LOCK(cs_main, return m_node.chainman->ActiveChain().Tip()->GetBlockHash());
    }

    static UniValue GBTParams()
    {
        UniValue rules{UniValue::VARR};
        rules.push_back("segwit");
        UniValue req{UniValue::VOBJ};
        req.pushKV("rules", std::move(rules));
        UniValue params{UniValue::VARR};
        params.push_back(std::move(req));
        return params;
    }

    void SetMiningChainGuard(bool enabled)
    {
        m_node.args->ForceSetArg("-miningchainguard", enabled ? "1" : "0");
    }
};

UniValue GenerateBlockParams(bool submit)
{
    UniValue params{UniValue::VARR};
    params.push_back("raw(51)");
    params.push_back(UniValue{UniValue::VARR});
    params.push_back(submit);
    return params;
}

UniValue GetMatMulServiceChallengeParams(
    const std::string& purpose,
    const std::string& resource,
    const std::string& subject,
    double target_solve_time_s,
    int expires_in_s,
    double validation_overhead_s,
    double propagation_overhead_s,
    const std::string& difficulty_policy = "fixed",
    int difficulty_window_blocks = 24,
    double min_solve_time_s = 0.25,
    double max_solve_time_s = 30.0,
    int solver_parallelism = 1,
    double solver_duty_cycle_pct = 100.0)
{
    UniValue params{UniValue::VARR};
    params.push_back(purpose);
    params.push_back(resource);
    params.push_back(subject);
    params.push_back(target_solve_time_s);
    params.push_back(expires_in_s);
    params.push_back(validation_overhead_s);
    params.push_back(propagation_overhead_s);
    params.push_back(difficulty_policy);
    params.push_back(difficulty_window_blocks);
    params.push_back(min_solve_time_s);
    params.push_back(max_solve_time_s);
    params.push_back(solver_parallelism);
    params.push_back(solver_duty_cycle_pct);
    return params;
}

UniValue GetMatMulServiceChallengeProfileParams(
    const std::string& profile_name,
    double validation_overhead_s,
    double propagation_overhead_s,
    double min_solve_time_s,
    double max_solve_time_s,
    double solve_time_multiplier,
    const std::string& difficulty_policy = "fixed",
    int difficulty_window_blocks = 24,
    int solver_parallelism = 1,
    double solver_duty_cycle_pct = 100.0)
{
    UniValue params{UniValue::VARR};
    params.push_back(profile_name);
    params.push_back(validation_overhead_s);
    params.push_back(propagation_overhead_s);
    params.push_back(min_solve_time_s);
    params.push_back(max_solve_time_s);
    params.push_back(solve_time_multiplier);
    params.push_back(difficulty_policy);
    params.push_back(difficulty_window_blocks);
    params.push_back(solver_parallelism);
    params.push_back(solver_duty_cycle_pct);
    return params;
}

UniValue GetMatMulServiceChallengePlanParams(
    const std::string& objective_mode,
    double objective_value,
    double validation_overhead_s = 0.0,
    double propagation_overhead_s = 0.0,
    const std::string& difficulty_policy = "fixed",
    int difficulty_window_blocks = 24,
    double min_solve_time_s = 0.25,
    double max_solve_time_s = 30.0,
    int solver_parallelism = 1,
    double solver_duty_cycle_pct = 100.0)
{
    UniValue params{UniValue::VARR};
    params.push_back(objective_mode);
    params.push_back(objective_value);
    params.push_back(validation_overhead_s);
    params.push_back(propagation_overhead_s);
    params.push_back(difficulty_policy);
    params.push_back(difficulty_window_blocks);
    params.push_back(min_solve_time_s);
    params.push_back(max_solve_time_s);
    params.push_back(solver_parallelism);
    params.push_back(solver_duty_cycle_pct);
    return params;
}

UniValue ListMatMulServiceChallengeProfilesParams(
    double validation_overhead_s,
    double propagation_overhead_s,
    double min_solve_time_s,
    double max_solve_time_s,
    double solve_time_multiplier,
    const std::string& difficulty_policy = "fixed",
    int difficulty_window_blocks = 24,
    int solver_parallelism = 1,
    double solver_duty_cycle_pct = 100.0)
{
    UniValue params{UniValue::VARR};
    params.push_back(validation_overhead_s);
    params.push_back(propagation_overhead_s);
    params.push_back(min_solve_time_s);
    params.push_back(max_solve_time_s);
    params.push_back(solve_time_multiplier);
    params.push_back(difficulty_policy);
    params.push_back(difficulty_window_blocks);
    params.push_back(solver_parallelism);
    params.push_back(solver_duty_cycle_pct);
    return params;
}

UniValue IssueMatMulServiceChallengeProfileParams(
    const std::string& purpose,
    const std::string& resource,
    const std::string& subject,
    const std::string& profile_name,
    int64_t expires_in_s,
    double validation_overhead_s,
    double propagation_overhead_s,
    double min_solve_time_s,
    double max_solve_time_s,
    double solve_time_multiplier,
    const std::string& difficulty_policy = "fixed",
    int difficulty_window_blocks = 24,
    int solver_parallelism = 1,
    double solver_duty_cycle_pct = 100.0)
{
    UniValue params{UniValue::VARR};
    params.push_back(purpose);
    params.push_back(resource);
    params.push_back(subject);
    params.push_back(profile_name);
    params.push_back(expires_in_s);
    params.push_back(validation_overhead_s);
    params.push_back(propagation_overhead_s);
    params.push_back(min_solve_time_s);
    params.push_back(max_solve_time_s);
    params.push_back(solve_time_multiplier);
    params.push_back(difficulty_policy);
    params.push_back(difficulty_window_blocks);
    params.push_back(solver_parallelism);
    params.push_back(solver_duty_cycle_pct);
    return params;
}

UniValue SolveMatMulServiceChallengeParams(
    const UniValue& challenge,
    uint64_t max_tries,
    std::optional<int64_t> time_budget_ms = std::nullopt,
    std::optional<int> solver_threads = std::nullopt)
{
    UniValue params{UniValue::VARR};
    params.push_back(challenge);
    params.push_back(max_tries);
    if (time_budget_ms.has_value() || solver_threads.has_value()) {
        params.push_back(time_budget_ms.has_value() ? UniValue{*time_budget_ms} : UniValue{UniValue::VNULL});
    }
    if (solver_threads.has_value()) {
        params.push_back(*solver_threads);
    }
    return params;
}

UniValue VerifyMatMulServiceProofParams(
    const UniValue& challenge,
    const std::string& nonce64_hex,
    const std::string& digest_hex,
    std::optional<bool> include_local_registry_status = std::nullopt)
{
    UniValue params{UniValue::VARR};
    params.push_back(challenge);
    params.push_back(nonce64_hex);
    params.push_back(digest_hex);
    if (include_local_registry_status.has_value()) {
        params.push_back(*include_local_registry_status);
    }
    return params;
}

UniValue MatMulServiceProofBatchEntry(
    const UniValue& challenge,
    const std::string& nonce64_hex,
    const std::string& digest_hex)
{
    UniValue entry{UniValue::VOBJ};
    entry.pushKV("challenge", challenge);
    entry.pushKV("nonce64_hex", nonce64_hex);
    entry.pushKV("digest_hex", digest_hex);
    return entry;
}

UniValue MatMulServiceProofBatchParams(
    std::initializer_list<UniValue> entries,
    std::optional<bool> include_local_registry_status = std::nullopt)
{
    UniValue batch{UniValue::VARR};
    for (const auto& entry : entries) {
        batch.push_back(entry);
    }
    UniValue params{UniValue::VARR};
    params.push_back(std::move(batch));
    if (include_local_registry_status.has_value()) {
        params.push_back(*include_local_registry_status);
    }
    return params;
}

std::string FormatNonce64Hex(uint64_t nonce64)
{
    return strprintf("%016x", nonce64);
}

uint32_t ParseBitsHex(const std::string& bits_hex);

uint256 ParseUint256HexChecked(const UniValue& value)
{
    const auto parsed = uint256::FromHex(value.get_str());
    BOOST_REQUIRE(parsed.has_value());
    return *parsed;
}

matmul::PowState PowStateFromServiceChallenge(const UniValue& service_envelope)
{
    const auto challenge = service_envelope.find_value("challenge").get_obj();
    const auto header_context = challenge.find_value("header_context").get_obj();
    const auto matmul = challenge.find_value("matmul").get_obj();

    matmul::PowState state;
    state.version = header_context.find_value("version").getInt<int32_t>();
    state.previous_block_hash = ParseUint256HexChecked(header_context.find_value("previousblockhash"));
    state.merkle_root = ParseUint256HexChecked(header_context.find_value("merkleroot"));
    state.time = static_cast<uint32_t>(header_context.find_value("time").getInt<int64_t>());
    state.bits = ParseBitsHex(header_context.find_value("bits").get_str());
    state.seed_a = ParseUint256HexChecked(matmul.find_value("seed_a"));
    state.seed_b = ParseUint256HexChecked(matmul.find_value("seed_b"));
    state.nonce = header_context.find_value("nonce64_start").getInt<uint64_t>();
    state.matmul_dim = static_cast<uint16_t>(matmul.find_value("n").getInt<int>());
    state.digest.SetNull();
    return state;
}

matmul::PowConfig PowConfigFromServiceChallenge(const UniValue& service_envelope)
{
    const auto challenge = service_envelope.find_value("challenge").get_obj();
    const auto matmul = challenge.find_value("matmul").get_obj();

    return matmul::PowConfig{
        .n = static_cast<uint32_t>(matmul.find_value("n").getInt<int>()),
        .b = static_cast<uint32_t>(matmul.find_value("b").getInt<int>()),
        .r = static_cast<uint32_t>(matmul.find_value("r").getInt<int>()),
        .target = UintToArith256(ParseUint256HexChecked(challenge.find_value("target"))),
    };
}

uint32_t ParseBitsHex(const std::string& bits_hex)
{
    uint32_t out{0};
    const auto result = std::from_chars(bits_hex.data(), bits_hex.data() + bits_hex.size(), out, 16);
    BOOST_REQUIRE(result.ec == std::errc{});
    BOOST_REQUIRE(result.ptr == bits_hex.data() + bits_hex.size());
    return out;
}

void MineBlocksWithSpacing(MatMulMiningTestingSetup& setup, int count, int64_t spacing_s)
{
    BOOST_REQUIRE_GT(count, 0);
    int64_t next_time = WITH_LOCK(cs_main, return setup.m_node.chainman->ActiveChain().Tip()->GetBlockTime());
    for (int i = 0; i < count; ++i) {
        auto block = PrepareBlock(setup.m_node, node::BlockAssembler::Options{});
        next_time += spacing_s;
        block->nTime = static_cast<uint32_t>(next_time);
        const auto mined = MineBlock(setup.m_node, block);
        BOOST_CHECK(!mined.IsNull());
    }
}

struct ResetMockTimeGuard {
    ~ResetMockTimeGuard()
    {
        SetMockTime(0);
    }
};

} // namespace

BOOST_FIXTURE_TEST_SUITE(matmul_mining_tests, MatMulMiningTestingSetup)

// TEST: mining_template_matmul_params
// TEST: rpc_getblocktemplate_matmul
// TEST: rpc_getblocktemplate_block_capacity
BOOST_AUTO_TEST_CASE(getblocktemplate_includes_matmul_params)
{
    SetMiningChainGuard(false);
    const auto tmpl = CallRPC("getblocktemplate", GBTParams()).get_obj();
    const auto& consensus = m_node.chainman->GetConsensus();

    const auto capacity = tmpl.find_value("block_capacity").get_obj();
    BOOST_CHECK_EQUAL(capacity.find_value("max_block_weight").getInt<int64_t>(), static_cast<int64_t>(MAX_BLOCK_WEIGHT));
    BOOST_CHECK_EQUAL(capacity.find_value("max_block_serialized_size").getInt<int64_t>(), static_cast<int64_t>(MAX_BLOCK_SERIALIZED_SIZE));
    BOOST_CHECK_EQUAL(capacity.find_value("max_block_sigops_cost").getInt<int64_t>(), static_cast<int64_t>(MAX_BLOCK_SIGOPS_COST));
    BOOST_CHECK_EQUAL(capacity.find_value("witness_scale_factor").getInt<int>(), WITNESS_SCALE_FACTOR);
    BOOST_CHECK_EQUAL(capacity.find_value("policy_block_max_weight").getInt<int64_t>(), static_cast<int64_t>(node::BlockAssembler::Options{}.nBlockMaxWeight));
    BOOST_CHECK_EQUAL(capacity.find_value("default_block_max_weight").getInt<int64_t>(), static_cast<int64_t>(node::BlockAssembler::Options{}.nBlockMaxWeight));
    BOOST_CHECK_EQUAL(capacity.find_value("max_block_shielded_verify_units").getInt<int64_t>(), static_cast<int64_t>(consensus.nMaxBlockShieldedVerifyCost));
    BOOST_CHECK_EQUAL(capacity.find_value("max_block_shielded_scan_units").getInt<int64_t>(), static_cast<int64_t>(consensus.nMaxBlockShieldedScanUnits));
    BOOST_CHECK_EQUAL(capacity.find_value("max_block_shielded_tree_update_units").getInt<int64_t>(), static_cast<int64_t>(consensus.nMaxBlockShieldedTreeUpdateUnits));
    BOOST_CHECK_EQUAL(capacity.find_value("template_shielded_verify_units").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(capacity.find_value("template_shielded_scan_units").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(capacity.find_value("template_shielded_tree_update_units").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(capacity.find_value("remaining_shielded_verify_units").getInt<int64_t>(), static_cast<int64_t>(consensus.nMaxBlockShieldedVerifyCost));
    BOOST_CHECK_EQUAL(capacity.find_value("remaining_shielded_scan_units").getInt<int64_t>(), static_cast<int64_t>(consensus.nMaxBlockShieldedScanUnits));
    BOOST_CHECK_EQUAL(capacity.find_value("remaining_shielded_tree_update_units").getInt<int64_t>(), static_cast<int64_t>(consensus.nMaxBlockShieldedTreeUpdateUnits));

    const auto matmul = tmpl.find_value("matmul").get_obj();
    BOOST_CHECK_EQUAL(matmul.find_value("n").getInt<int>(), static_cast<int>(consensus.nMatMulDimension));
    BOOST_CHECK_EQUAL(matmul.find_value("b").getInt<int>(), static_cast<int>(consensus.nMatMulTranscriptBlockSize));
    BOOST_CHECK_EQUAL(matmul.find_value("r").getInt<int>(), static_cast<int>(consensus.nMatMulNoiseRank));
    BOOST_CHECK_EQUAL(matmul.find_value("q").getInt<uint64_t>(), static_cast<uint64_t>(consensus.nMatMulFieldModulus));

    BOOST_CHECK_EQUAL(tmpl.find_value("matmul_n").getInt<int>(), static_cast<int>(consensus.nMatMulDimension));
    BOOST_CHECK_EQUAL(tmpl.find_value("matmul_b").getInt<int>(), static_cast<int>(consensus.nMatMulTranscriptBlockSize));
    BOOST_CHECK_EQUAL(tmpl.find_value("matmul_r").getInt<int>(), static_cast<int>(consensus.nMatMulNoiseRank));

    const std::string seed_a = tmpl.find_value("seed_a").get_str();
    const std::string seed_b = tmpl.find_value("seed_b").get_str();
    BOOST_CHECK_EQUAL(seed_a.size(), 64U);
    BOOST_CHECK_EQUAL(seed_b.size(), 64U);
    BOOST_CHECK(seed_a != std::string(64, '0'));
    BOOST_CHECK(seed_b != std::string(64, '0'));
}

BOOST_AUTO_TEST_CASE(getblocktemplate_reports_chain_guard_pause_for_external_miners)
{
    SetMiningChainGuard(true);

    const auto tmpl = CallRPC("getblocktemplate", GBTParams()).get_obj();
    const auto chain_guard = tmpl.find_value("chain_guard").get_obj();

    BOOST_CHECK(chain_guard.find_value("enabled").get_bool());
    BOOST_CHECK(!chain_guard.find_value("healthy").get_bool());
    BOOST_CHECK(chain_guard.find_value("should_pause_mining").get_bool());
    BOOST_CHECK_EQUAL(chain_guard.find_value("recommended_action").get_str(), "catch_up");
    BOOST_CHECK(tmpl.exists("previousblockhash"));
}

// TEST: rpc_getmininginfo_algorithm
// TEST: rpc_getmininginfo_reports_capacity
BOOST_AUTO_TEST_CASE(getmininginfo_reports_matmul_algorithm)
{
    SetMiningChainGuard(false);
    (void)CallRPC("getblocktemplate", GBTParams());
    const auto info = CallRPC("getmininginfo").get_obj();
    const auto& consensus = m_node.chainman->GetConsensus();
    BOOST_CHECK_EQUAL(info.find_value("algorithm").get_str(), "matmul");
    BOOST_CHECK_EQUAL(info.find_value("powalgorithm").get_str(), "matmul");
    BOOST_CHECK_EQUAL(info.find_value("max_block_weight").getInt<int64_t>(), static_cast<int64_t>(MAX_BLOCK_WEIGHT));
    BOOST_CHECK_EQUAL(info.find_value("policy_block_max_weight").getInt<int64_t>(), static_cast<int64_t>(node::BlockAssembler::Options{}.nBlockMaxWeight));
    BOOST_CHECK_EQUAL(info.find_value("max_block_shielded_verify_units").getInt<int64_t>(), static_cast<int64_t>(consensus.nMaxBlockShieldedVerifyCost));
    BOOST_CHECK_EQUAL(info.find_value("max_block_shielded_scan_units").getInt<int64_t>(), static_cast<int64_t>(consensus.nMaxBlockShieldedScanUnits));
    BOOST_CHECK_EQUAL(info.find_value("max_block_shielded_tree_update_units").getInt<int64_t>(), static_cast<int64_t>(consensus.nMaxBlockShieldedTreeUpdateUnits));
    BOOST_CHECK_EQUAL(info.find_value("currentblockshieldedverifyunits").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(info.find_value("currentblockshieldedscanunits").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(info.find_value("currentblockshieldedtreeupdateunits").getInt<int64_t>(), 0);
    BOOST_CHECK_EQUAL(info.find_value("matmul_n").getInt<int>(), static_cast<int>(consensus.nMatMulDimension));
    BOOST_CHECK_EQUAL(info.find_value("matmul_b").getInt<int>(), static_cast<int>(consensus.nMatMulTranscriptBlockSize));
    BOOST_CHECK_EQUAL(info.find_value("matmul_r").getInt<int>(), static_cast<int>(consensus.nMatMulNoiseRank));
}

// TEST: mining_generate_block
// TEST: rpc_getblock_matmul_verbose
// TEST: mining_seeds_in_header
BOOST_AUTO_TEST_CASE(generateblock_mines_valid_matmul_block)
{
    SetMiningChainGuard(false);
    const int old_height = ActiveHeight();
    const auto& consensus = m_node.chainman->GetConsensus();
    const auto generated = CallRPC("generateblock", GenerateBlockParams(/*submit=*/true)).get_obj();
    const std::string hash = generated.find_value("hash").get_str();

    BOOST_CHECK_EQUAL(ActiveHeight(), old_height + 1);
    BOOST_CHECK_EQUAL(hash, ActiveTipHash().GetHex());

    UniValue getblock_params{UniValue::VARR};
    getblock_params.push_back(hash);
    getblock_params.push_back(1);
    const auto block = CallRPC("getblock", std::move(getblock_params)).get_obj();
    BOOST_CHECK_EQUAL(block.find_value("matmul_dim").getInt<int>(), static_cast<int>(consensus.nMatMulDimension));
    BOOST_CHECK_EQUAL(block.find_value("seed_a").get_str().size(), 64U);
    BOOST_CHECK_EQUAL(block.find_value("seed_b").get_str().size(), 64U);
    BOOST_CHECK_EQUAL(block.find_value("matmul_digest").get_str().size(), 64U);

    UniValue header_params{UniValue::VARR};
    header_params.push_back(hash);
    header_params.push_back(true);
    const auto header = CallRPC("getblockheader", std::move(header_params)).get_obj();
    BOOST_CHECK_EQUAL(header.find_value("matmul_dim").getInt<int>(), static_cast<int>(consensus.nMatMulDimension));
    BOOST_CHECK_EQUAL(header.find_value("seed_a").get_str().size(), 64U);
    BOOST_CHECK_EQUAL(header.find_value("seed_b").get_str().size(), 64U);
    BOOST_CHECK_EQUAL(header.find_value("matmul_digest").get_str().size(), 64U);
}

// TEST: submitblock_accepts_valid_matmul_block
BOOST_AUTO_TEST_CASE(submitblock_accepts_valid_matmul_block)
{
    SetMiningChainGuard(false);
    const int old_height = ActiveHeight();
    const auto generated = CallRPC("generateblock", GenerateBlockParams(/*submit=*/false)).get_obj();
    const std::string block_hex = generated.find_value("hex").get_str();

    UniValue submit_params{UniValue::VARR};
    submit_params.push_back(block_hex);
    const UniValue submit_result = CallRPC("submitblock", std::move(submit_params));

    BOOST_CHECK(submit_result.isNull());
    BOOST_CHECK_EQUAL(ActiveHeight(), old_height + 1);
    BOOST_CHECK_EQUAL(generated.find_value("hash").get_str(), ActiveTipHash().GetHex());
}

BOOST_AUTO_TEST_CASE(submitblock_pauses_when_chain_guard_requests_stop)
{
    SetMiningChainGuard(false);
    const int old_height = ActiveHeight();
    const auto generated = CallRPC("generateblock", GenerateBlockParams(/*submit=*/false)).get_obj();
    const std::string block_hex = generated.find_value("hex").get_str();

    SetMiningChainGuard(true);

    UniValue submit_params{UniValue::VARR};
    submit_params.push_back(block_hex);
    const UniValue submit_result = CallRPC("submitblock", std::move(submit_params));

    BOOST_CHECK(submit_result.isStr());
    BOOST_CHECK_EQUAL(submit_result.get_str(), "paused-chain-guard-catch_up");
    BOOST_CHECK_EQUAL(ActiveHeight(), old_height);
}

// TEST: mining_reject_tampered
// TEST: rpc_submitblock_rejects_invalid
BOOST_AUTO_TEST_CASE(submitblock_rejects_tampered_matmul_digest)
{
    SetMiningChainGuard(false);
    const int old_height = ActiveHeight();
    const auto generated = CallRPC("generateblock", GenerateBlockParams(/*submit=*/false)).get_obj();
    std::string bad_hex = generated.find_value("hex").get_str();

    constexpr size_t HEADER_BYTES_BEFORE_MATMUL_DIGEST = 4 + 32 + 32 + 4 + 4 + 8;
    const size_t digest_offset = HEADER_BYTES_BEFORE_MATMUL_DIGEST * 2;
    const size_t digest_len = 64;
    BOOST_REQUIRE(bad_hex.size() >= digest_offset + digest_len);
    bad_hex.replace(digest_offset, digest_len, digest_len, 'f');

    UniValue submit_params{UniValue::VARR};
    submit_params.push_back(bad_hex);
    const UniValue submit_result = CallRPC("submitblock", std::move(submit_params));

    BOOST_CHECK(submit_result.isStr());
    BOOST_CHECK_NE(submit_result.get_str().find("high-hash"), std::string::npos);
    BOOST_CHECK_EQUAL(ActiveHeight(), old_height);
}

// TEST: strict regtest mining emits the Freivalds payload and rejects blocks
// that strip it back out before submission.
BOOST_AUTO_TEST_CASE(submitblock_requires_freivalds_payload_when_consensus_demands_it)
{
    SetMiningChainGuard(false);
    const auto& consensus = m_node.chainman->GetConsensus();
    BOOST_REQUIRE(consensus.fMatMulPOW);
    BOOST_REQUIRE(consensus.fMatMulFreivaldsEnabled);
    BOOST_REQUIRE(consensus.fMatMulRequireProductPayload);

    const int old_height = ActiveHeight();
    const auto generated = CallRPC("generateblock", GenerateBlockParams(/*submit=*/false)).get_obj();
    CBlock block;
    BOOST_REQUIRE(DecodeHexBlkCompat(block, generated.find_value("hex").get_str()));
    BOOST_CHECK(HasMatMulFreivaldsPayload(block));

    block.matrix_c_data.clear();
    DataStream ss{};
    ss << TX_WITH_WITNESS(block);

    UniValue submit_params{UniValue::VARR};
    submit_params.push_back(HexStr(ss));
    const UniValue submit_result = CallRPC("submitblock", std::move(submit_params));

    BOOST_CHECK(submit_result.isStr());
    BOOST_CHECK_EQUAL(submit_result.get_str(), "missing-product-payload");
    BOOST_CHECK_EQUAL(ActiveHeight(), old_height);
}

// TEST: rpc_matmul_service_profile_runtime_observability
BOOST_AUTO_TEST_CASE(matmul_service_profile_reports_measured_runtime_and_network_proxy)
{
    ResetMatMulSolvePipelineStats();
    ResetMatMulDigestCompareStats();
    ResetMatMulSolveRuntimeStats();
    ResetMatMulValidationRuntimeStats();
    ResetReorgProtectionRuntimeStats();
    RecordRejectedReorgDepth(
        /*reorg_depth=*/248,
        /*max_reorg_depth=*/144,
        /*old_tip_height=*/53'086,
        /*fork_height=*/52'838,
        /*candidate_height=*/53'347);

    const auto generated = CallRPC("generateblock", GenerateBlockParams(/*submit=*/true)).get_obj();
    BOOST_CHECK(!generated.find_value("hash").get_str().empty());

    UniValue params{UniValue::VARR};
    params.push_back(1.0);
    params.push_back(0.25);
    params.push_back(0.75);
    const auto profile = CallRPC("getmatmulchallengeprofile", std::move(params)).get_obj();
    const auto service_profile = profile.find_value("service_profile").get_obj();
    const auto runtime = service_profile.find_value("runtime_observability").get_obj();

    const auto solve_runtime = runtime.find_value("solve_runtime").get_obj();
    BOOST_CHECK_GE(solve_runtime.find_value("attempts").getInt<uint64_t>(), 1U);
    BOOST_CHECK_GE(solve_runtime.find_value("solved_attempts").getInt<uint64_t>(), 1U);
    BOOST_CHECK_GE(solve_runtime.find_value("total_elapsed_ms").get_real(), 0.0);
    BOOST_CHECK_GT(solve_runtime.find_value("last_elapsed_ms").get_real(), 0.0);
    BOOST_CHECK_GE(solve_runtime.find_value("max_elapsed_ms").get_real(), solve_runtime.find_value("last_elapsed_ms").get_real());

    const auto& consensus = m_node.chainman->GetConsensus();
    const bool product_digest_active = consensus.IsMatMulProductDigestActive(ActiveHeight());
    const auto validation_runtime = runtime.find_value("validation_runtime").get_obj();
    BOOST_CHECK_GE(validation_runtime.find_value("phase2_checks").getInt<uint64_t>(), 1U);
    BOOST_CHECK_GE(validation_runtime.find_value("freivalds_checks").getInt<uint64_t>(), 1U);
    BOOST_CHECK_GE(validation_runtime.find_value("successful_checks").getInt<uint64_t>(), 1U);
    BOOST_CHECK_GE(validation_runtime.find_value("failed_checks").getInt<uint64_t>(), 0U);
    BOOST_CHECK_GT(validation_runtime.find_value("last_phase2_elapsed_ms").get_real(), 0.0);
    BOOST_CHECK_GT(validation_runtime.find_value("last_freivalds_elapsed_ms").get_real(), 0.0);
    if (product_digest_active) {
        BOOST_CHECK_EQUAL(validation_runtime.find_value("transcript_checks").getInt<uint64_t>(), 0U);
        BOOST_CHECK_EQUAL(validation_runtime.find_value("last_transcript_elapsed_ms").get_real(), 0.0);
    } else {
        BOOST_CHECK_GE(validation_runtime.find_value("transcript_checks").getInt<uint64_t>(), 1U);
        BOOST_CHECK_GT(validation_runtime.find_value("last_transcript_elapsed_ms").get_real(), 0.0);
    }

    const auto propagation_proxy = runtime.find_value("propagation_proxy").get_obj();
    BOOST_CHECK_EQUAL(propagation_proxy.find_value("connected_peers").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(propagation_proxy.find_value("outbound_peers").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(propagation_proxy.find_value("synced_outbound_peers").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(propagation_proxy.find_value("manual_outbound_peers").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(propagation_proxy.find_value("outbound_peers_missing_sync_height").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(propagation_proxy.find_value("outbound_peers_beyond_sync_lag").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(propagation_proxy.find_value("recent_block_announcing_outbound_peers").getInt<int>(), 0);
    BOOST_CHECK(propagation_proxy.find_value("outbound_peer_diagnostics").get_array().empty());
    BOOST_CHECK_EQUAL(
        propagation_proxy.find_value("validated_tip_height").getInt<int>(),
        ActiveHeight());
    BOOST_CHECK_EQUAL(
        propagation_proxy.find_value("best_header_height").getInt<int>(),
        ActiveHeight());
    BOOST_CHECK_EQUAL(propagation_proxy.find_value("header_lag").getInt<int>(), 0);

    const auto reorg_protection = runtime.find_value("reorg_protection").get_obj();
    BOOST_CHECK(!reorg_protection.find_value("enabled").get_bool());
    BOOST_CHECK(!reorg_protection.find_value("active").get_bool());
    BOOST_CHECK_EQUAL(reorg_protection.find_value("start_height").getInt<int>(), -1);
    BOOST_CHECK_EQUAL(reorg_protection.find_value("max_reorg_depth").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(reorg_protection.find_value("rejected_reorgs").getInt<uint64_t>(), 1U);
    BOOST_CHECK_EQUAL(reorg_protection.find_value("deepest_rejected_reorg_depth").getInt<int>(), 248);
    BOOST_CHECK_EQUAL(reorg_protection.find_value("last_rejected_reorg_depth").getInt<int>(), 248);
    BOOST_CHECK_EQUAL(reorg_protection.find_value("last_rejected_max_reorg_depth").getInt<int>(), 144);
    BOOST_CHECK_EQUAL(reorg_protection.find_value("last_rejected_tip_height").getInt<int>(), 53'086);
    BOOST_CHECK_EQUAL(reorg_protection.find_value("last_rejected_fork_height").getInt<int>(), 52'838);
    BOOST_CHECK_EQUAL(reorg_protection.find_value("last_rejected_candidate_height").getInt<int>(), 53'347);
    BOOST_CHECK_GT(reorg_protection.find_value("last_rejected_unix").getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(getmatmulservicechallengeprofile_returns_network_relative_issue_defaults)
{
    const auto profile = CallRPC(
        "getmatmulservicechallengeprofile",
        GetMatMulServiceChallengeProfileParams(
            "balanced",
            0.25,
            0.75,
            0.25,
            30.0,
            1.0,
            "fixed",
            24,
            4,
            25.0)).get_obj();

    BOOST_REQUIRE(profile.find_value("profile").isObject());
    const auto resolved = profile.find_value("profile").get_obj();
    BOOST_CHECK_EQUAL(resolved.find_value("name").get_str(), "balanced");
    BOOST_CHECK_EQUAL(resolved.find_value("difficulty_label").get_str(), "normal");
    BOOST_CHECK_EQUAL(resolved.find_value("effort_tier").getInt<int>(), 2);
    BOOST_CHECK(!resolved.find_value("description").get_str().empty());
    BOOST_CHECK_EQUAL(resolved.find_value("solve_time_multiplier").get_real(), 1.0);
    BOOST_CHECK_EQUAL(resolved.find_value("min_solve_time_s").get_real(), 0.25);
    BOOST_CHECK_EQUAL(resolved.find_value("max_solve_time_s").get_real(), 30.0);
    BOOST_CHECK(!resolved.find_value("clamped").get_bool());

    const double expected_target =
        std::clamp(
            static_cast<double>(m_node.chainman->GetConsensus().nPowTargetSpacing) / 45.0,
            0.25,
            30.0);
    BOOST_CHECK_CLOSE(
        resolved.find_value("recommended_target_solve_time_s").get_real(),
        expected_target,
        0.0001);
    BOOST_CHECK_CLOSE(
        resolved.find_value("resolved_target_solve_time_s").get_real(),
        expected_target,
        0.0001);
    BOOST_CHECK_CLOSE(
        resolved.find_value("estimated_average_node_solve_time_s").get_real(),
        expected_target,
        0.0001);
    BOOST_CHECK_CLOSE(
        resolved.find_value("estimated_average_node_total_time_s").get_real(),
        expected_target + 0.25 + 0.75,
        0.0001);
    BOOST_CHECK_CLOSE(
        resolved.find_value("estimated_average_node_challenges_per_hour").get_real(),
        3600.0 / (expected_target + 1.0),
        0.0001);
    BOOST_REQUIRE(resolved.find_value("operator_capacity").isObject());
    const auto operator_capacity = resolved.find_value("operator_capacity").get_obj();
    BOOST_CHECK_EQUAL(operator_capacity.find_value("estimation_basis").get_str(), "average_node");
    BOOST_CHECK_EQUAL(operator_capacity.find_value("solver_parallelism").getInt<int>(), 4);
    BOOST_CHECK_EQUAL(operator_capacity.find_value("solver_duty_cycle_pct").get_real(), 25.0);
    BOOST_CHECK_CLOSE(operator_capacity.find_value("effective_parallelism").get_real(), 1.0, 0.0001);
    BOOST_CHECK_CLOSE(operator_capacity.find_value("budgeted_solver_seconds_per_hour").get_real(), 3600.0, 0.0001);
    BOOST_CHECK_CLOSE(
        operator_capacity.find_value("estimated_sustained_solves_per_hour").get_real(),
        3600.0 / (expected_target + 1.0),
        0.0001);
    BOOST_CHECK_CLOSE(
        operator_capacity.find_value("estimated_mean_seconds_between_solves").get_real(),
        expected_target + 1.0,
        0.0001);
    BOOST_REQUIRE(resolved.find_value("difficulty_resolution").isObject());
    const auto difficulty_resolution = resolved.find_value("difficulty_resolution").get_obj();
    BOOST_CHECK_EQUAL(difficulty_resolution.find_value("mode").get_str(), "fixed");
    BOOST_CHECK_EQUAL(difficulty_resolution.find_value("window_blocks").getInt<int>(), 24);
    BOOST_CHECK_CLOSE(
        difficulty_resolution.find_value("resolved_solve_time_s").get_real(),
        expected_target,
        0.0001);

    BOOST_REQUIRE(resolved.find_value("issue_defaults").isObject());
    const auto defaults = resolved.find_value("issue_defaults").get_obj();
    BOOST_CHECK_EQUAL(defaults.find_value("rpc").get_str(), "getmatmulservicechallenge");
    BOOST_CHECK_EQUAL(defaults.find_value("profile_name").get_str(), "balanced");
    BOOST_CHECK_EQUAL(defaults.find_value("difficulty_label").get_str(), "normal");
    BOOST_CHECK_CLOSE(
        defaults.find_value("target_solve_time_s").get_real(),
        expected_target,
        0.0001);
    BOOST_CHECK_EQUAL(defaults.find_value("validation_overhead_s").get_real(), 0.25);
    BOOST_CHECK_EQUAL(defaults.find_value("propagation_overhead_s").get_real(), 0.75);
    BOOST_CHECK_EQUAL(defaults.find_value("difficulty_policy").get_str(), "fixed");
    BOOST_CHECK_EQUAL(defaults.find_value("difficulty_window_blocks").getInt<int>(), 24);
    BOOST_CHECK_EQUAL(defaults.find_value("min_solve_time_s").get_real(), 0.25);
    BOOST_CHECK_EQUAL(defaults.find_value("max_solve_time_s").get_real(), 30.0);
    BOOST_CHECK_EQUAL(defaults.find_value("solver_parallelism").getInt<int>(), 4);
    BOOST_CHECK_EQUAL(defaults.find_value("solver_duty_cycle_pct").get_real(), 25.0);

    BOOST_REQUIRE(resolved.find_value("profile_issue_defaults").isObject());
    const auto profile_defaults = resolved.find_value("profile_issue_defaults").get_obj();
    BOOST_CHECK_EQUAL(profile_defaults.find_value("rpc").get_str(), "issuematmulservicechallengeprofile");
    BOOST_CHECK_EQUAL(profile_defaults.find_value("profile_name").get_str(), "balanced");
    BOOST_CHECK_EQUAL(profile_defaults.find_value("difficulty_label").get_str(), "normal");
    BOOST_CHECK_EQUAL(profile_defaults.find_value("solve_time_multiplier").get_real(), 1.0);
    BOOST_CHECK_EQUAL(profile_defaults.find_value("solver_parallelism").getInt<int>(), 4);
    BOOST_CHECK_EQUAL(profile_defaults.find_value("solver_duty_cycle_pct").get_real(), 25.0);

    BOOST_REQUIRE(profile.find_value("challenge_profile").isObject());
    const auto challenge_profile = profile.find_value("challenge_profile").get_obj();
    BOOST_REQUIRE(challenge_profile.find_value("service_profile").isObject());
    const auto service_profile = challenge_profile.find_value("service_profile").get_obj();
    BOOST_CHECK_CLOSE(
        service_profile.find_value("solve_time_target_s").get_real(),
        expected_target,
        0.0001);
    BOOST_CHECK_EQUAL(service_profile.find_value("validation_overhead_s").get_real(), 0.25);
    BOOST_CHECK_EQUAL(service_profile.find_value("propagation_overhead_s").get_real(), 0.75);
    BOOST_REQUIRE(service_profile.find_value("operator_capacity").isObject());
    BOOST_CHECK_EQUAL(
        service_profile.find_value("operator_capacity").get_obj().find_value("solver_parallelism").getInt<int>(),
        4);
    BOOST_CHECK_EQUAL(
        service_profile.find_value("operator_capacity").get_obj().find_value("solver_duty_cycle_pct").get_real(),
        25.0);
    BOOST_REQUIRE(service_profile.find_value("difficulty_resolution").isObject());
    BOOST_CHECK_EQUAL(
        service_profile.find_value("difficulty_resolution").get_obj().find_value("mode").get_str(),
        "fixed");
}

BOOST_AUTO_TEST_CASE(listmatmulservicechallengeprofiles_returns_profile_catalog)
{
    const auto catalog = CallRPC(
        "listmatmulservicechallengeprofiles",
        ListMatMulServiceChallengeProfilesParams(
            0.25,
            0.75,
            0.25,
            30.0,
            1.0,
            "fixed",
            24,
            4,
            25.0)).get_obj();

    BOOST_CHECK_EQUAL(catalog.find_value("default_profile").get_str(), "balanced");
    BOOST_CHECK_EQUAL(catalog.find_value("default_difficulty_label").get_str(), "normal");
    BOOST_REQUIRE(catalog.find_value("profiles").isArray());
    const auto profiles = catalog.find_value("profiles").get_array();
    BOOST_CHECK_EQUAL(profiles.size(), 4U);
    BOOST_CHECK_EQUAL(profiles[0].get_obj().find_value("name").get_str(), "interactive");
    BOOST_CHECK_EQUAL(profiles[0].get_obj().find_value("difficulty_label").get_str(), "easy");
    BOOST_CHECK_EQUAL(profiles[1].get_obj().find_value("name").get_str(), "balanced");
    BOOST_CHECK_EQUAL(profiles[1].get_obj().find_value("difficulty_label").get_str(), "normal");
    BOOST_CHECK_EQUAL(profiles[2].get_obj().find_value("name").get_str(), "strict");
    BOOST_CHECK_EQUAL(profiles[2].get_obj().find_value("difficulty_label").get_str(), "hard");
    BOOST_CHECK_EQUAL(profiles[3].get_obj().find_value("name").get_str(), "background");
    BOOST_CHECK_EQUAL(profiles[3].get_obj().find_value("difficulty_label").get_str(), "idle");
    BOOST_CHECK_EQUAL(
        profiles[1].get_obj().find_value("operator_capacity").get_obj().find_value("solver_parallelism").getInt<int>(),
        4);
    BOOST_CHECK_EQUAL(
        profiles[1].get_obj().find_value("operator_capacity").get_obj().find_value("solver_duty_cycle_pct").get_real(),
        25.0);
}

BOOST_AUTO_TEST_CASE(getmatmulservicechallengeplan_returns_direct_and_profile_defaults)
{
    const auto plan = CallRPC(
        "getmatmulservicechallengeplan",
        GetMatMulServiceChallengePlanParams(
            "solves_per_hour",
            1200.0,
            0.25,
            0.75,
            "fixed",
            24,
            0.25,
            30.0,
            4,
            25.0)).get_obj();

    BOOST_REQUIRE(plan.find_value("objective").isObject());
    const auto objective = plan.find_value("objective").get_obj();
    BOOST_CHECK_EQUAL(objective.find_value("mode").get_str(), "solves_per_hour");
    BOOST_CHECK_CLOSE(objective.find_value("requested_value").get_real(), 1200.0, 0.0001);
    BOOST_CHECK_CLOSE(objective.find_value("requested_total_target_s").get_real(), 3.0, 0.0001);
    BOOST_CHECK_CLOSE(objective.find_value("requested_resolved_solve_time_s").get_real(), 2.0, 0.0001);

    BOOST_REQUIRE(plan.find_value("plan").isObject());
    const auto resolved_plan = plan.find_value("plan").get_obj();
    BOOST_CHECK(resolved_plan.find_value("objective_satisfied").get_bool());
    BOOST_CHECK_CLOSE(resolved_plan.find_value("requested_base_solve_time_s").get_real(), 2.0, 0.0001);
    BOOST_CHECK_CLOSE(resolved_plan.find_value("resolved_target_solve_time_s").get_real(), 2.0, 0.0001);
    BOOST_CHECK_CLOSE(resolved_plan.find_value("resolved_total_target_s").get_real(), 3.0, 0.0001);
    BOOST_REQUIRE(resolved_plan.find_value("difficulty_resolution").isObject());
    BOOST_CHECK_EQUAL(
        resolved_plan.find_value("difficulty_resolution").get_obj().find_value("mode").get_str(),
        "fixed");
    BOOST_REQUIRE(resolved_plan.find_value("operator_capacity").isObject());
    BOOST_CHECK_CLOSE(
        resolved_plan.find_value("operator_capacity").get_obj().find_value("estimated_sustained_solves_per_hour").get_real(),
        1200.0,
        0.0001);
    BOOST_REQUIRE(resolved_plan.find_value("objective_gap").isObject());
    BOOST_CHECK_CLOSE(
        resolved_plan.find_value("objective_gap").get_obj().find_value("headroom_pct").get_real(),
        0.0,
        0.0001);
    BOOST_REQUIRE(resolved_plan.find_value("issue_defaults").isObject());
    const auto issue_defaults = resolved_plan.find_value("issue_defaults").get_obj();
    BOOST_CHECK_EQUAL(issue_defaults.find_value("rpc").get_str(), "getmatmulservicechallenge");
    BOOST_CHECK_CLOSE(issue_defaults.find_value("target_solve_time_s").get_real(), 2.0, 0.0001);
    BOOST_CHECK_CLOSE(issue_defaults.find_value("resolved_target_solve_time_s").get_real(), 2.0, 0.0001);
    BOOST_CHECK_EQUAL(issue_defaults.find_value("solver_parallelism").getInt<int>(), 4);
    BOOST_CHECK_EQUAL(issue_defaults.find_value("solver_duty_cycle_pct").get_real(), 25.0);

    BOOST_REQUIRE(plan.find_value("recommended_profile").isObject());
    const auto recommended_profile = plan.find_value("recommended_profile").get_obj();
    BOOST_CHECK_EQUAL(recommended_profile.find_value("name").get_str(), "balanced");
    BOOST_CHECK_CLOSE(recommended_profile.find_value("solve_time_multiplier").get_real(), 1.0, 0.0001);
    BOOST_CHECK(recommended_profile.find_value("objective_satisfied").get_bool());
    BOOST_CHECK_CLOSE(recommended_profile.find_value("resolved_total_target_s").get_real(), 3.0, 0.0001);
    BOOST_REQUIRE(recommended_profile.find_value("issue_defaults").isObject());
    BOOST_CHECK_CLOSE(
        recommended_profile.find_value("issue_defaults").get_obj().find_value("resolved_target_solve_time_s").get_real(),
        2.0,
        0.0001);
    BOOST_REQUIRE(recommended_profile.find_value("profile_issue_defaults").isObject());
    BOOST_CHECK_CLOSE(
        recommended_profile.find_value("profile_issue_defaults").get_obj().find_value("resolved_target_solve_time_s").get_real(),
        2.0,
        0.0001);

    BOOST_REQUIRE(plan.find_value("candidate_profiles").isArray());
    const auto candidate_profiles = plan.find_value("candidate_profiles").get_array();
    BOOST_CHECK_EQUAL(candidate_profiles.size(), 4U);
    BOOST_CHECK_EQUAL(candidate_profiles[0].get_obj().find_value("name").get_str(), "balanced");

    BOOST_REQUIRE(plan.find_value("challenge_profile").isObject());
    const auto challenge_profile = plan.find_value("challenge_profile").get_obj();
    BOOST_REQUIRE(challenge_profile.find_value("service_profile").isObject());
    BOOST_CHECK_CLOSE(
        challenge_profile.find_value("service_profile").get_obj().find_value("solve_time_target_s").get_real(),
        2.0,
        0.0001);
}

BOOST_AUTO_TEST_CASE(getmatmulservicechallengeplan_inverts_adaptive_window_targets)
{
    MineBlocksWithSpacing(*this, 6, 180);

    const auto plan = CallRPC(
        "getmatmulservicechallengeplan",
        GetMatMulServiceChallengePlanParams(
            "solves_per_hour",
            450.0,
            0.25,
            0.75,
            "adaptive_window",
            4,
            0.25,
            30.0,
            1,
            100.0)).get_obj();

    const auto objective = plan.find_value("objective").get_obj();
    BOOST_CHECK_CLOSE(objective.find_value("requested_total_target_s").get_real(), 8.0, 0.0001);
    BOOST_CHECK_CLOSE(objective.find_value("requested_resolved_solve_time_s").get_real(), 7.0, 0.0001);

    const auto resolved_plan = plan.find_value("plan").get_obj();
    BOOST_CHECK_CLOSE(resolved_plan.find_value("requested_base_solve_time_s").get_real(), 3.5, 0.0001);
    BOOST_CHECK_CLOSE(resolved_plan.find_value("resolved_target_solve_time_s").get_real(), 7.0, 0.0001);
    BOOST_REQUIRE(resolved_plan.find_value("difficulty_resolution").isObject());
    const auto difficulty_resolution = resolved_plan.find_value("difficulty_resolution").get_obj();
    BOOST_CHECK_EQUAL(difficulty_resolution.find_value("mode").get_str(), "adaptive_window");
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("base_solve_time_s").get_real(), 3.5, 0.0001);
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("adjusted_solve_time_s").get_real(), 7.0, 0.0001);
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("resolved_solve_time_s").get_real(), 7.0, 0.0001);
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("interval_scale").get_real(), 2.0, 0.0001);
    BOOST_CHECK_EQUAL(difficulty_resolution.find_value("observed_interval_count").getInt<int>(), 4);
    BOOST_REQUIRE(resolved_plan.find_value("issue_defaults").isObject());
    BOOST_CHECK_CLOSE(
        resolved_plan.find_value("issue_defaults").get_obj().find_value("target_solve_time_s").get_real(),
        3.5,
        0.0001);
    BOOST_CHECK_CLOSE(
        resolved_plan.find_value("issue_defaults").get_obj().find_value("resolved_target_solve_time_s").get_real(),
        7.0,
        0.0001);

    BOOST_REQUIRE(plan.find_value("recommended_profile").isObject());
    const auto recommended_profile = plan.find_value("recommended_profile").get_obj();
    BOOST_CHECK_EQUAL(recommended_profile.find_value("name").get_str(), "strict");
    BOOST_CHECK_CLOSE(recommended_profile.find_value("solve_time_multiplier").get_real(), 0.7, 0.0001);
    BOOST_CHECK_CLOSE(recommended_profile.find_value("resolved_total_target_s").get_real(), 8.0, 0.0001);
    BOOST_CHECK_CLOSE(
        recommended_profile.find_value("objective_gap").get_obj().find_value("headroom_pct").get_real(),
        0.0,
        0.0001);
}

BOOST_AUTO_TEST_CASE(getmatmulservicechallengeplan_clamps_fixed_mode_to_bounds)
{
    const auto plan = CallRPC(
        "getmatmulservicechallengeplan",
        GetMatMulServiceChallengePlanParams(
            "solves_per_hour",
            1200.0,
            0.25,
            0.75,
            "fixed",
            24,
            0.25,
            1.0,
            4,
            25.0)).get_obj();

    const auto objective = plan.find_value("objective").get_obj();
    BOOST_CHECK_CLOSE(objective.find_value("requested_resolved_solve_time_s").get_real(), 2.0, 0.0001);

    BOOST_REQUIRE(plan.find_value("plan").isObject());
    const auto resolved_plan = plan.find_value("plan").get_obj();
    BOOST_CHECK(resolved_plan.find_value("objective_satisfied").get_bool());
    BOOST_CHECK_CLOSE(resolved_plan.find_value("requested_base_solve_time_s").get_real(), 2.0, 0.0001);
    BOOST_CHECK_CLOSE(resolved_plan.find_value("resolved_target_solve_time_s").get_real(), 1.0, 0.0001);
    BOOST_CHECK_CLOSE(resolved_plan.find_value("resolved_total_target_s").get_real(), 2.0, 0.0001);
    BOOST_REQUIRE(resolved_plan.find_value("difficulty_resolution").isObject());
    const auto difficulty_resolution = resolved_plan.find_value("difficulty_resolution").get_obj();
    BOOST_CHECK_EQUAL(difficulty_resolution.find_value("mode").get_str(), "fixed");
    BOOST_CHECK(difficulty_resolution.find_value("clamped").get_bool());
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("adjusted_solve_time_s").get_real(), 2.0, 0.0001);
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("resolved_solve_time_s").get_real(), 1.0, 0.0001);
    BOOST_REQUIRE(resolved_plan.find_value("issue_defaults").isObject());
    const auto issue_defaults = resolved_plan.find_value("issue_defaults").get_obj();
    BOOST_CHECK_CLOSE(issue_defaults.find_value("target_solve_time_s").get_real(), 2.0, 0.0001);
    BOOST_CHECK_CLOSE(issue_defaults.find_value("resolved_target_solve_time_s").get_real(), 1.0, 0.0001);
    BOOST_CHECK_CLOSE(
        resolved_plan.find_value("objective_gap").get_obj().find_value("actual_sustained_solves_per_hour").get_real(),
        1800.0,
        0.0001);
}

BOOST_AUTO_TEST_CASE(getmatmulservicechallengeplan_supports_day_and_spacing_aliases)
{
    const auto per_day = CallRPC(
        "getmatmulservicechallengeplan",
        GetMatMulServiceChallengePlanParams(
            "challenges_per_day",
            28'800.0,
            0.25,
            0.75,
            "fixed",
            24,
            0.25,
            30.0,
            4,
            25.0)).get_obj();

    BOOST_REQUIRE(per_day.find_value("objective").isObject());
    const auto day_objective = per_day.find_value("objective").get_obj();
    BOOST_CHECK_EQUAL(day_objective.find_value("mode").get_str(), "solves_per_day");
    BOOST_CHECK_CLOSE(day_objective.find_value("requested_sustained_solves_per_hour").get_real(), 1200.0, 0.0001);
    BOOST_CHECK_CLOSE(day_objective.find_value("requested_total_target_s").get_real(), 3.0, 0.0001);
    BOOST_CHECK_CLOSE(
        per_day.find_value("plan").get_obj().find_value("resolved_target_solve_time_s").get_real(),
        2.0,
        0.0001);

    const auto spacing = CallRPC(
        "getmatmulservicechallengeplan",
        GetMatMulServiceChallengePlanParams(
            "mean_seconds_between_challenges",
            3.0,
            0.25,
            0.75,
            "fixed",
            24,
            0.25,
            30.0,
            4,
            25.0)).get_obj();

    BOOST_REQUIRE(spacing.find_value("objective").isObject());
    const auto spacing_objective = spacing.find_value("objective").get_obj();
    BOOST_CHECK_EQUAL(spacing_objective.find_value("mode").get_str(), "mean_seconds_between_solves");
    BOOST_CHECK_CLOSE(spacing_objective.find_value("requested_sustained_solves_per_hour").get_real(), 1200.0, 0.0001);
    BOOST_CHECK_CLOSE(spacing_objective.find_value("requested_total_target_s").get_real(), 3.0, 0.0001);
    BOOST_CHECK_CLOSE(
        spacing.find_value("plan").get_obj().find_value("requested_base_solve_time_s").get_real(),
        2.0,
        0.0001);
    BOOST_CHECK_CLOSE(
        spacing.find_value("plan").get_obj().find_value("resolved_target_solve_time_s").get_real(),
        2.0,
        0.0001);
}

BOOST_AUTO_TEST_CASE(getmatmulservicechallengeplan_rejects_bad_inputs)
{
    BOOST_CHECK_EXCEPTION(
        CallRPC(
            "getmatmulservicechallengeplan",
            GetMatMulServiceChallengePlanParams("nope", 1.0)),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string{e.what()}.find("unknown objective_mode") != std::string::npos;
        });

    BOOST_CHECK_EXCEPTION(
        CallRPC(
            "getmatmulservicechallengeplan",
            GetMatMulServiceChallengePlanParams(
                "mean_seconds_between_solves",
                1.0,
                0.75,
                0.50)),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string{e.what()} ==
                "objective_value leaves no positive solve budget after validation_overhead_s and propagation_overhead_s";
        });
}

BOOST_AUTO_TEST_CASE(getmatmulservicechallengeprofile_clamps_and_rejects_bad_inputs)
{
    const auto clamped = CallRPC(
        "getmatmulservicechallengeprofile",
        GetMatMulServiceChallengeProfileParams(
            "background",
            0.0,
            0.0,
            1.0,
            2.0,
            10.0)).get_obj();
    const auto resolved = clamped.find_value("profile").get_obj();
    BOOST_CHECK(resolved.find_value("clamped").get_bool());
    BOOST_CHECK_EQUAL(resolved.find_value("recommended_target_solve_time_s").get_real(), 2.0);

    BOOST_CHECK_EXCEPTION(
        CallRPC(
            "getmatmulservicechallengeprofile",
            GetMatMulServiceChallengeProfileParams(
                "unknown",
                0.0,
                0.0,
                0.25,
                30.0,
                1.0)),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string{e.what()}.find("unknown service challenge profile") != std::string::npos;
        });

    BOOST_CHECK_EXCEPTION(
        CallRPC(
            "getmatmulservicechallengeprofile",
            GetMatMulServiceChallengeProfileParams(
                "balanced",
                0.0,
                0.0,
                2.0,
                1.0,
                1.0)),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string{e.what()} == "max_solve_time_s must be greater than or equal to min_solve_time_s";
        });

    BOOST_CHECK_EXCEPTION(
        CallRPC(
            "getmatmulservicechallengeprofile",
            GetMatMulServiceChallengeProfileParams(
                "balanced",
                0.0,
                0.0,
                0.25,
                30.0,
                1.0,
                "adaptive_window",
                0)),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string{e.what()} == "difficulty_window_blocks must be positive";
        });

    BOOST_CHECK_EXCEPTION(
        CallRPC(
            "getmatmulservicechallengeprofile",
            GetMatMulServiceChallengeProfileParams(
                "balanced",
                0.0,
                0.0,
                0.25,
                30.0,
                1.0,
                "fixed",
                24,
                0,
                100.0)),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string{e.what()} == "solver_parallelism must be positive";
        });

    BOOST_CHECK_EXCEPTION(
        CallRPC(
            "getmatmulservicechallengeprofile",
            GetMatMulServiceChallengeProfileParams(
                "balanced",
                0.0,
                0.0,
                0.25,
                30.0,
                1.0,
                "fixed",
                24,
                1,
                0.0)),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string{e.what()} ==
                "solver_duty_cycle_pct must be greater than 0 and less than or equal to 100";
        });
}

BOOST_AUTO_TEST_CASE(getmatmulservicechallengeprofile_adaptive_window_falls_back_without_observed_intervals)
{
    const auto profile = CallRPC(
        "getmatmulservicechallengeprofile",
        GetMatMulServiceChallengeProfileParams(
            "balanced",
            0.25,
            0.75,
            0.25,
            6.0,
            1.0,
            "adaptive_window",
            24)).get_obj();

    const auto resolved = profile.find_value("profile").get_obj();
    const auto difficulty_resolution = resolved.find_value("difficulty_resolution").get_obj();
    BOOST_CHECK_EQUAL(difficulty_resolution.find_value("mode").get_str(), "adaptive_window");
    BOOST_CHECK_EQUAL(difficulty_resolution.find_value("observed_interval_count").getInt<int>(), 0);
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("observed_mean_interval_s").get_real(), 90.0, 0.0001);
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("interval_scale").get_real(), 1.0, 0.0001);
    BOOST_CHECK(!difficulty_resolution.find_value("clamped").get_bool());
    BOOST_CHECK_CLOSE(
        resolved.find_value("recommended_target_solve_time_s").get_real(),
        resolved.find_value("resolved_target_solve_time_s").get_real(),
        0.0001);
}

BOOST_AUTO_TEST_CASE(getmatmulservicechallenge_adaptive_window_scales_to_anchored_intervals)
{
    MineBlocksWithSpacing(*this, 6, 180);

    const auto service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "adaptive:/v1/messages",
            "user:adaptive@example.com",
            2.0,
            300,
            0.10,
            0.20,
            "adaptive_window",
            4,
            0.25,
            10.0)).get_obj();

    const auto challenge = service.find_value("challenge").get_obj();
    const auto service_profile = challenge.find_value("service_profile").get_obj();
    BOOST_CHECK_CLOSE(service_profile.find_value("solve_time_target_s").get_real(), 4.0, 0.0001);
    BOOST_REQUIRE(service_profile.find_value("difficulty_resolution").isObject());
    const auto difficulty_resolution = service_profile.find_value("difficulty_resolution").get_obj();
    BOOST_CHECK_EQUAL(difficulty_resolution.find_value("mode").get_str(), "adaptive_window");
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("base_solve_time_s").get_real(), 2.0, 0.0001);
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("adjusted_solve_time_s").get_real(), 4.0, 0.0001);
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("resolved_solve_time_s").get_real(), 4.0, 0.0001);
    BOOST_CHECK_EQUAL(difficulty_resolution.find_value("window_blocks").getInt<int>(), 4);
    BOOST_CHECK_EQUAL(difficulty_resolution.find_value("observed_interval_count").getInt<int>(), 4);
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("observed_mean_interval_s").get_real(), 180.0, 0.0001);
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("network_target_s").get_real(), 90.0, 0.0001);
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("interval_scale").get_real(), 2.0, 0.0001);
    BOOST_CHECK(!difficulty_resolution.find_value("clamped").get_bool());
}

BOOST_AUTO_TEST_CASE(getmatmulservicechallenge_adaptive_window_clamps_resolved_target)
{
    MineBlocksWithSpacing(*this, 6, 180);

    const auto service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "adaptive:/v1/clamped",
            "user:clamped@example.com",
            2.0,
            300,
            0.10,
            0.20,
            "adaptive_window",
            4,
            0.25,
            3.0)).get_obj();

    const auto service_profile = service.find_value("challenge").get_obj().find_value("service_profile").get_obj();
    const auto difficulty_resolution = service_profile.find_value("difficulty_resolution").get_obj();
    BOOST_CHECK_CLOSE(service_profile.find_value("solve_time_target_s").get_real(), 3.0, 0.0001);
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("adjusted_solve_time_s").get_real(), 4.0, 0.0001);
    BOOST_CHECK_CLOSE(difficulty_resolution.find_value("resolved_solve_time_s").get_real(), 3.0, 0.0001);
    BOOST_CHECK(difficulty_resolution.find_value("clamped").get_bool());
}

BOOST_AUTO_TEST_CASE(issuematmulservicechallengeprofile_accepts_alias_and_returns_redeemable_challenge)
{
    const auto issued = CallRPC(
        "issuematmulservicechallengeprofile",
        IssueMatMulServiceChallengeProfileParams(
            "rate_limit",
            "profile:/v1/messages",
            "user:profile@example.com",
            "normal",
            300,
            0.0,
            0.0,
            0.001,
            0.001,
            0.0001)).get_obj();

    BOOST_REQUIRE(issued.find_value("profile").isObject());
    const auto profile = issued.find_value("profile").get_obj();
    BOOST_CHECK_EQUAL(profile.find_value("name").get_str(), "balanced");
    BOOST_CHECK_EQUAL(profile.find_value("difficulty_label").get_str(), "normal");
    BOOST_CHECK_CLOSE(profile.find_value("resolved_target_solve_time_s").get_real(), 0.001, 0.0001);

    BOOST_REQUIRE(issued.find_value("service_challenge").isObject());
    const auto service = issued.find_value("service_challenge").get_obj();
    BOOST_CHECK_EQUAL(service.find_value("kind").get_str(), "matmul_service_challenge_v1");
    BOOST_CHECK_CLOSE(
        service.find_value("challenge").get_obj().find_value("service_profile").get_obj().find_value("solve_time_target_s").get_real(),
        0.001,
        0.0001);

    const auto solved = CallRPC(
        "solvematmulservicechallenge",
        SolveMatMulServiceChallengeParams(service, 256)).get_obj();
    BOOST_CHECK(solved.find_value("solved").get_bool());

    const auto redeemed = CallRPC(
        "redeemmatmulserviceproof",
        VerifyMatMulServiceProofParams(
            service,
            solved.find_value("nonce64_hex").get_str(),
            solved.find_value("digest_hex").get_str())).get_obj();
    BOOST_CHECK(redeemed.find_value("valid").get_bool());
    BOOST_CHECK_EQUAL(redeemed.find_value("reason").get_str(), "ok");
}

BOOST_AUTO_TEST_CASE(getmatmulservicechallenge_returns_domain_bound_replay_resistant_template)
{
    const auto first = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "signup:/v1/messages",
            "user:alice@example.com",
            2.0,
            300,
            0.25,
            0.75)).get_obj();
    const auto second = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "signup:/v1/messages",
            "user:alice@example.com",
            2.0,
            300,
            0.25,
            0.75)).get_obj();

    BOOST_CHECK_EQUAL(first.find_value("kind").get_str(), "matmul_service_challenge_v1");
    BOOST_CHECK_NE(first.find_value("challenge_id").get_str(), second.find_value("challenge_id").get_str());

    const auto binding = first.find_value("binding").get_obj();
    BOOST_CHECK_EQUAL(binding.find_value("purpose").get_str(), "rate_limit");
    BOOST_CHECK_EQUAL(binding.find_value("resource").get_str(), "signup:/v1/messages");
    BOOST_CHECK_EQUAL(binding.find_value("subject").get_str(), "user:alice@example.com");
    BOOST_CHECK_EQUAL(binding.find_value("anchor_height").getInt<int>(), ActiveHeight());
    BOOST_CHECK_EQUAL(binding.find_value("anchor_hash").get_str(), ActiveTipHash().GetHex());
    BOOST_CHECK_EQUAL(binding.find_value("challenge_id_rule").get_str(), "sha256(domain || binding_hash || salt || anchor_hash || anchor_height || issued_at || expires_at || target_solve_ms || validation_overhead_ms || propagation_overhead_ms)");
    BOOST_CHECK_EQUAL(binding.find_value("seed_derivation_rule").get_str(), "sha256(challenge_id || anchor_hash || label)");

    const auto first_header = first.find_value("challenge").get_obj().find_value("header_context").get_obj();
    const auto second_header = second.find_value("challenge").get_obj().find_value("header_context").get_obj();
    BOOST_CHECK_EQUAL(first_header.find_value("previousblockhash").get_str(), ActiveTipHash().GetHex());
    BOOST_CHECK_NE(first_header.find_value("merkleroot").get_str(), second_header.find_value("merkleroot").get_str());
    BOOST_CHECK_NE(first_header.find_value("seed_a").get_str(), second_header.find_value("seed_a").get_str());
    BOOST_CHECK_NE(first_header.find_value("seed_b").get_str(), second_header.find_value("seed_b").get_str());

    const auto proof_policy = first.find_value("proof_policy").get_obj();
    BOOST_CHECK(!proof_policy.find_value("sigma_gate_applied").get_bool());
    BOOST_CHECK(proof_policy.find_value("expiration_enforced").get_bool());
    BOOST_CHECK(proof_policy.find_value("challenge_id_required").get_bool());
    BOOST_CHECK_EQUAL(proof_policy.find_value("replay_protection").get_str(), "redeemmatmulserviceproof");
    BOOST_CHECK_EQUAL(proof_policy.find_value("redeem_rpc").get_str(), "redeemmatmulserviceproof");
    BOOST_CHECK_EQUAL(proof_policy.find_value("solve_rpc").get_str(), "solvematmulservicechallenge");
    BOOST_CHECK(proof_policy.find_value("locally_issued_required").get_bool());
    BOOST_CHECK_EQUAL(proof_policy.find_value("issued_challenge_store").get_str(), "local_persistent_file");
    BOOST_CHECK_EQUAL(proof_policy.find_value("issued_challenge_scope").get_str(), "node_local");
    const auto service_profile = first.find_value("challenge").get_obj().find_value("service_profile").get_obj();
    BOOST_REQUIRE(service_profile.find_value("difficulty_resolution").isObject());
    BOOST_CHECK_EQUAL(
        service_profile.find_value("difficulty_resolution").get_obj().find_value("mode").get_str(),
        "fixed");
}

BOOST_AUTO_TEST_CASE(verifymatmulserviceproof_rejects_invalid_digest_and_tampered_target)
{
    const auto service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/comment",
            "user:bob@example.com",
            2.0,
            300,
            0.10,
            0.20)).get_obj();

    const auto invalid_digest = CallRPC(
        "verifymatmulserviceproof",
        VerifyMatMulServiceProofParams(service, "0000000000000000", std::string(64, '0'))).get_obj();
    BOOST_CHECK(!invalid_digest.find_value("valid").get_bool());
    BOOST_CHECK(!invalid_digest.find_value("expired").get_bool());
    BOOST_CHECK_MESSAGE(
        invalid_digest.find_value("reason").get_str() == "invalid_proof",
        invalid_digest.write());
    BOOST_CHECK(invalid_digest.find_value("mismatch_field").isNull());
    BOOST_CHECK(invalid_digest.find_value("issued_by_local_node").get_bool());
    BOOST_CHECK(!invalid_digest.find_value("redeemed").get_bool());
    BOOST_CHECK(invalid_digest.find_value("redeemable").get_bool());
    BOOST_REQUIRE(invalid_digest.find_value("proof").isObject());
    const auto proof = invalid_digest.find_value("proof").get_obj();
    BOOST_CHECK_EQUAL(proof.find_value("nonce64_hex").get_str(), "0000000000000000");
    BOOST_CHECK_EQUAL(proof.find_value("digest").get_str(), std::string(64, '0'));
    BOOST_CHECK(proof.find_value("commitment_valid").get_bool());
    BOOST_CHECK(!proof.find_value("transcript_valid").get_bool());
    BOOST_CHECK(proof.find_value("meets_target").get_bool());

    std::string tampered_service_json = service.write();
    const std::string original_bits =
        service.find_value("challenge").get_obj().find_value("bits").get_str();
    const std::string original_target =
        service.find_value("challenge").get_obj().find_value("target").get_str();
    const std::string tampered_bits{"207fffff"};
    const std::string tampered_target =
        DeriveTarget(ParseBitsHex(tampered_bits), m_node.chainman->GetConsensus().powLimit)->GetHex();
    const auto replace_once = [&](const std::string& needle, const std::string& replacement) {
        const size_t pos = tampered_service_json.find(needle);
        BOOST_REQUIRE(pos != std::string::npos);
        tampered_service_json.replace(pos, needle.size(), replacement);
    };
    replace_once(
        strprintf("\"bits\":\"%s\"", original_bits),
        strprintf("\"bits\":\"%s\"", tampered_bits));
    replace_once(
        strprintf("\"bits\":\"%s\"", original_bits),
        strprintf("\"bits\":\"%s\"", tampered_bits));
    replace_once(
        strprintf("\"target\":\"%s\"", original_target),
        strprintf("\"target\":\"%s\"", tampered_target));
    UniValue tampered_service;
    BOOST_REQUIRE(tampered_service.read(tampered_service_json));

    const auto tampered_verified = CallRPC(
        "verifymatmulserviceproof",
        VerifyMatMulServiceProofParams(
            tampered_service,
            "0000000000000000",
            std::string(64, '0'))).get_obj();
    BOOST_CHECK(!tampered_verified.find_value("valid").get_bool());
    BOOST_CHECK_EQUAL(tampered_verified.find_value("reason").get_str(), "challenge_mismatch");
    BOOST_CHECK_EQUAL(tampered_verified.find_value("mismatch_field").get_str(), "challenge.bits");
}

BOOST_AUTO_TEST_CASE(verifymatmulserviceproof_rejects_tampered_difficulty_resolution)
{
    MineBlocksWithSpacing(*this, 6, 180);
    const auto service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/adaptive",
            "user:adaptive@example.com",
            2.0,
            300,
            0.10,
            0.20,
            "adaptive_window",
            4,
            0.25,
            10.0)).get_obj();

    std::string tampered_service_json = service.write();
    const auto difficulty_resolution = service.find_value("challenge").get_obj()
        .find_value("service_profile").get_obj()
        .find_value("difficulty_resolution").get_obj();
    const std::string original_base =
        util::ToString(difficulty_resolution.find_value("base_solve_time_s").get_real());
    const std::string original_adjusted =
        util::ToString(difficulty_resolution.find_value("adjusted_solve_time_s").get_real());
    const auto replace_once = [&](const std::string& needle, const std::string& replacement) {
        const size_t pos = tampered_service_json.find(needle);
        BOOST_REQUIRE(pos != std::string::npos);
        tampered_service_json.replace(pos, needle.size(), replacement);
    };
    replace_once(
        strprintf("\"base_solve_time_s\":%s", original_base),
        "\"base_solve_time_s\":1.5");
    replace_once(
        strprintf("\"adjusted_solve_time_s\":%s", original_adjusted),
        "\"adjusted_solve_time_s\":3");

    UniValue tampered_service;
    BOOST_REQUIRE(tampered_service.read(tampered_service_json));

    try {
        (void)CallRPC(
            "verifymatmulserviceproof",
            VerifyMatMulServiceProofParams(
                tampered_service,
                "0000000000000000",
                std::string(64, '0')));
        BOOST_FAIL("expected verifymatmulserviceproof to reject the tampered difficulty resolution");
    } catch (const std::runtime_error& e) {
        BOOST_CHECK_EQUAL(
            std::string{e.what()},
            "invalid service challenge: difficulty_resolution does not match the anchored network conditions");
    }
}

BOOST_AUTO_TEST_CASE(verifymatmulserviceproof_rejects_oversized_or_inverted_service_envelopes)
{
    const auto service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/comment",
            "user:oversized@example.com",
            2.0,
            300,
            0.0,
            0.0)).get_obj();

    const auto replace_once = [](std::string& json, const std::string& needle, const std::string& replacement) {
        const size_t pos = json.find(needle);
        BOOST_REQUIRE(pos != std::string::npos);
        json.replace(pos, needle.size(), replacement);
    };

    std::string oversized_json = service.write();
    replace_once(
        oversized_json,
        "\"resource\":\"post:/v1/comment\"",
        strprintf("\"resource\":\"%s\"", std::string(257, 'r')));
    UniValue oversized_service;
    BOOST_REQUIRE(oversized_service.read(oversized_json));

    BOOST_CHECK_EXCEPTION(
        CallRPC(
            "verifymatmulserviceproof",
            VerifyMatMulServiceProofParams(
                oversized_service,
                "0000000000000000",
                std::string(64, '0'))),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string{e.what()} ==
                "invalid service challenge: resource must be at most 256 bytes";
        });

    const int64_t issued_at = service.find_value("issued_at").getInt<int64_t>();
    const int64_t expires_at = service.find_value("expires_at").getInt<int64_t>();
    std::string inverted_expiry_json = service.write();
    replace_once(
        inverted_expiry_json,
        strprintf("\"expires_at\":%d", expires_at),
        strprintf("\"expires_at\":%d", issued_at - 1));
    UniValue inverted_expiry_service;
    BOOST_REQUIRE(inverted_expiry_service.read(inverted_expiry_json));

    BOOST_CHECK_EXCEPTION(
        CallRPC(
            "verifymatmulserviceproof",
            VerifyMatMulServiceProofParams(
                inverted_expiry_service,
                "0000000000000000",
                std::string(64, '0'))),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string{e.what()} ==
                "invalid service challenge: expires_at must be greater than or equal to issued_at";
        });
}

BOOST_AUTO_TEST_CASE(solvematmulservicechallenge_returns_redeemable_proof)
{
    const auto service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/solve",
            "user:solver@example.com",
            0.001,
            300,
            0.0,
            0.0,
            "fixed",
            24,
            0.001,
            0.001)).get_obj();

    const auto solved = CallRPC(
        "solvematmulservicechallenge",
        SolveMatMulServiceChallengeParams(service, 8)).get_obj();
    BOOST_CHECK(solved.find_value("solved").get_bool());
    BOOST_CHECK_EQUAL(solved.find_value("reason").get_str(), "ok");
    BOOST_CHECK_GT(solved.find_value("attempts").getInt<uint64_t>(), 0U);
    BOOST_CHECK_LE(solved.find_value("attempts").getInt<uint64_t>(), 256U);
    BOOST_REQUIRE(solved.find_value("proof").isObject());
    const auto proof = solved.find_value("proof").get_obj();
    BOOST_CHECK_EQUAL(
        proof.find_value("nonce64_hex").get_str(),
        solved.find_value("nonce64_hex").get_str());
    BOOST_CHECK_EQUAL(
        proof.find_value("digest_hex").get_str(),
        solved.find_value("digest_hex").get_str());

    const auto verified = CallRPC(
        "verifymatmulserviceproof",
        VerifyMatMulServiceProofParams(
            service,
            solved.find_value("nonce64_hex").get_str(),
            solved.find_value("digest_hex").get_str())).get_obj();
    BOOST_CHECK(verified.find_value("valid").get_bool());

    const auto redeemed = CallRPC(
        "redeemmatmulserviceproof",
        VerifyMatMulServiceProofParams(
            service,
            solved.find_value("nonce64_hex").get_str(),
            solved.find_value("digest_hex").get_str())).get_obj();
    BOOST_CHECK(redeemed.find_value("valid").get_bool());
    BOOST_CHECK_EQUAL(redeemed.find_value("reason").get_str(), "ok");
}

BOOST_AUTO_TEST_CASE(solvematmulservicechallenge_reports_runtime_controls)
{
    const auto service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/runtime-controls",
            "user:runtime@example.com",
            0.001,
            300,
            0.0,
            0.0,
            "fixed",
            24,
            0.001,
            0.001)).get_obj();

    const auto solved = CallRPC(
        "solvematmulservicechallenge",
        SolveMatMulServiceChallengeParams(service, 256, 1000, 1)).get_obj();
    BOOST_CHECK(solved.find_value("solved").get_bool());
    BOOST_CHECK_EQUAL(solved.find_value("reason").get_str(), "ok");
    BOOST_CHECK_EQUAL(solved.find_value("time_budget_ms").getInt<int64_t>(), 1000);
    BOOST_CHECK_EQUAL(solved.find_value("solver_threads").getInt<int>(), 1);
}

BOOST_AUTO_TEST_CASE(solvematmulservicechallenge_reports_max_tries_exhausted)
{
    const auto service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/exhausted",
            "user:exhausted@example.com",
            600.0,
            300,
            0.0,
            0.0)).get_obj();

    const auto exhausted = CallRPC(
        "solvematmulservicechallenge",
        SolveMatMulServiceChallengeParams(service, 1)).get_obj();
    BOOST_CHECK(!exhausted.find_value("solved").get_bool());
    BOOST_CHECK_EQUAL(exhausted.find_value("reason").get_str(), "max_tries_exhausted");
    BOOST_CHECK_EQUAL(exhausted.find_value("attempts").getInt<uint64_t>(), 1U);
    BOOST_CHECK_EQUAL(exhausted.find_value("remaining_tries").getInt<uint64_t>(), 0U);
    BOOST_CHECK(exhausted.find_value("proof").isNull());
}

BOOST_AUTO_TEST_CASE(solvematmulservicechallenge_rejects_invalid_runtime_controls)
{
    const auto service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/runtime-invalid",
            "user:runtime-invalid@example.com",
            0.001,
            300,
            0.0,
            0.0,
            "fixed",
            24,
            0.001,
            0.001)).get_obj();

    BOOST_CHECK_EXCEPTION(
        CallRPC(
            "solvematmulservicechallenge",
            SolveMatMulServiceChallengeParams(service, 8, -1, 1)),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string{e.what()} == "time_budget_ms must be non-negative";
        });

    BOOST_CHECK_EXCEPTION(
        CallRPC(
            "solvematmulservicechallenge",
            SolveMatMulServiceChallengeParams(service, 8, 0, -1)),
        std::runtime_error,
        [](const std::runtime_error& e) {
            return std::string{e.what()} == "solver_threads must be non-negative";
        });
}

BOOST_AUTO_TEST_CASE(matmulserviceproof_reports_expired_challenges)
{
    const auto service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/expired",
            "user:expired@example.com",
            0.001,
            1,
            0.0,
            0.0)).get_obj();

    const ResetMockTimeGuard guard;
    SetMockTime(service.find_value("expires_at").getInt<int64_t>() + 1);

    const auto verified = CallRPC(
        "verifymatmulserviceproof",
        VerifyMatMulServiceProofParams(service, "0000000000000000", std::string(64, '0'))).get_obj();
    BOOST_CHECK(!verified.find_value("valid").get_bool());
    BOOST_CHECK(verified.find_value("expired").get_bool());
    BOOST_CHECK_EQUAL(verified.find_value("reason").get_str(), "expired");

    const auto redeemed = CallRPC(
        "redeemmatmulserviceproof",
        VerifyMatMulServiceProofParams(service, "0000000000000000", std::string(64, '0'))).get_obj();
    BOOST_CHECK(!redeemed.find_value("valid").get_bool());
    BOOST_CHECK(redeemed.find_value("expired").get_bool());
    BOOST_CHECK_EQUAL(redeemed.find_value("reason").get_str(), "expired");
}

BOOST_AUTO_TEST_CASE(redeemmatmulserviceproof_accepts_valid_local_proof_once)
{
    const auto service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/comment",
            "user:carol@example.com",
            0.001,
            300,
            0.0,
            0.0,
            "fixed",
            24,
            0.001,
            0.001)).get_obj();

    matmul::PowState state = PowStateFromServiceChallenge(service);
    const matmul::PowConfig config = PowConfigFromServiceChallenge(service);
    uint64_t max_tries{256};
    BOOST_REQUIRE(matmul::Solve(state, config, max_tries));

    const auto verified = CallRPC(
        "verifymatmulserviceproof",
        VerifyMatMulServiceProofParams(service, FormatNonce64Hex(state.nonce), state.digest.GetHex())).get_obj();
    BOOST_CHECK(verified.find_value("valid").get_bool());
    BOOST_CHECK(verified.find_value("issued_by_local_node").get_bool());
    BOOST_CHECK(!verified.find_value("redeemed").get_bool());
    BOOST_CHECK(verified.find_value("redeemable").get_bool());

    const auto redeemed = CallRPC(
        "redeemmatmulserviceproof",
        VerifyMatMulServiceProofParams(service, FormatNonce64Hex(state.nonce), state.digest.GetHex())).get_obj();
    BOOST_CHECK(redeemed.find_value("valid").get_bool());
    BOOST_CHECK_EQUAL(redeemed.find_value("reason").get_str(), "ok");
    BOOST_CHECK(redeemed.find_value("issued_by_local_node").get_bool());
    BOOST_CHECK(redeemed.find_value("redeemed").get_bool());
    BOOST_CHECK(!redeemed.find_value("redeemable").get_bool());
    BOOST_CHECK_GT(redeemed.find_value("redeemed_at").getInt<int64_t>(), 0);

    const auto redeemed_again = CallRPC(
        "redeemmatmulserviceproof",
        VerifyMatMulServiceProofParams(service, FormatNonce64Hex(state.nonce), state.digest.GetHex())).get_obj();
    BOOST_CHECK(!redeemed_again.find_value("valid").get_bool());
    BOOST_CHECK_EQUAL(redeemed_again.find_value("reason").get_str(), "already_redeemed");
    BOOST_CHECK(redeemed_again.find_value("issued_by_local_node").get_bool());
    BOOST_CHECK(redeemed_again.find_value("redeemed").get_bool());
    BOOST_CHECK(!redeemed_again.find_value("redeemable").get_bool());
    BOOST_CHECK_GT(redeemed_again.find_value("redeemed_at").getInt<int64_t>(), 0);
}

BOOST_AUTO_TEST_CASE(verifymatmulserviceproof_can_skip_local_registry_lookup)
{
    const auto service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/stateless",
            "user:stateless@example.com",
            0.001,
            300,
            0.0,
            0.0,
            "fixed",
            24,
            0.001,
            0.001)).get_obj();

    matmul::PowState state = PowStateFromServiceChallenge(service);
    const matmul::PowConfig config = PowConfigFromServiceChallenge(service);
    uint64_t max_tries{256};
    BOOST_REQUIRE(matmul::Solve(state, config, max_tries));

    const auto verified = CallRPC(
        "verifymatmulserviceproof",
        VerifyMatMulServiceProofParams(
            service,
            FormatNonce64Hex(state.nonce),
            state.digest.GetHex(),
            false)).get_obj();
    BOOST_CHECK(verified.find_value("valid").get_bool());
    BOOST_CHECK(!verified.find_value("expired").get_bool());
    BOOST_CHECK_EQUAL(verified.find_value("reason").get_str(), "ok");
    BOOST_CHECK(!verified.find_value("local_registry_status_checked").get_bool());
    BOOST_CHECK(verified.find_value("issued_by_local_node").isNull());
    BOOST_CHECK(verified.find_value("redeemed").isNull());
    BOOST_CHECK(verified.find_value("redeemable").isNull());
    BOOST_CHECK(verified.find_value("redeemed_at").isNull());
}

BOOST_AUTO_TEST_CASE(batch_matmulserviceproof_rpcs_summarize_and_preserve_order)
{
    const auto valid_service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/comment",
            "user:dave@example.com",
            0.001,
            300,
            0.0,
            0.0,
            "fixed",
            24,
            0.001,
            0.001)).get_obj();
    matmul::PowState state = PowStateFromServiceChallenge(valid_service);
    const matmul::PowConfig config = PowConfigFromServiceChallenge(valid_service);
    uint64_t max_tries{256};
    BOOST_REQUIRE(matmul::Solve(state, config, max_tries));

    const auto invalid_service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/comment",
            "user:erin@example.com",
            2.0,
            300,
            0.0,
            0.0)).get_obj();

    const auto verify_batch = CallRPC(
        "verifymatmulserviceproofs",
        MatMulServiceProofBatchParams({
            MatMulServiceProofBatchEntry(valid_service, FormatNonce64Hex(state.nonce), state.digest.GetHex()),
            MatMulServiceProofBatchEntry(invalid_service, "0000000000000000", std::string(64, '0')),
        })).get_obj();
    BOOST_CHECK_EQUAL(verify_batch.find_value("count").getInt<int>(), 2);
    BOOST_CHECK_EQUAL(verify_batch.find_value("valid").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(verify_batch.find_value("invalid").getInt<int>(), 1);
    BOOST_REQUIRE(verify_batch.find_value("by_reason").isObject());
    const auto verify_reasons = verify_batch.find_value("by_reason").get_obj();
    BOOST_CHECK_EQUAL(verify_reasons.find_value("ok").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(verify_reasons.find_value("invalid_proof").getInt<int>(), 1);
    BOOST_REQUIRE(verify_batch.find_value("results").isArray());
    const auto& verify_results = verify_batch.find_value("results").get_array();
    BOOST_REQUIRE_EQUAL(verify_results.size(), 2U);
    BOOST_CHECK_EQUAL(verify_results[0].get_obj().find_value("index").getInt<int>(), 0);
    BOOST_CHECK(verify_results[0].get_obj().find_value("valid").get_bool());
    BOOST_CHECK_EQUAL(verify_results[1].get_obj().find_value("index").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(verify_results[1].get_obj().find_value("reason").get_str(), "invalid_proof");

    const auto redeem_batch = CallRPC(
        "redeemmatmulserviceproofs",
        MatMulServiceProofBatchParams({
            MatMulServiceProofBatchEntry(valid_service, FormatNonce64Hex(state.nonce), state.digest.GetHex()),
            MatMulServiceProofBatchEntry(invalid_service, "0000000000000000", std::string(64, '0')),
        })).get_obj();
    BOOST_CHECK_EQUAL(redeem_batch.find_value("count").getInt<int>(), 2);
    BOOST_CHECK_EQUAL(redeem_batch.find_value("valid").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(redeem_batch.find_value("invalid").getInt<int>(), 1);
    BOOST_REQUIRE(redeem_batch.find_value("by_reason").isObject());
    const auto redeem_reasons = redeem_batch.find_value("by_reason").get_obj();
    BOOST_CHECK_EQUAL(redeem_reasons.find_value("ok").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(redeem_reasons.find_value("invalid_proof").getInt<int>(), 1);
    BOOST_REQUIRE(redeem_batch.find_value("results").isArray());
    const auto& redeem_results = redeem_batch.find_value("results").get_array();
    BOOST_REQUIRE_EQUAL(redeem_results.size(), 2U);
    BOOST_CHECK(redeem_results[0].get_obj().find_value("valid").get_bool());
    BOOST_CHECK(redeem_results[0].get_obj().find_value("redeemed").get_bool());
    BOOST_CHECK_EQUAL(redeem_results[1].get_obj().find_value("reason").get_str(), "invalid_proof");

    const auto redeem_again_batch = CallRPC(
        "redeemmatmulserviceproofs",
        MatMulServiceProofBatchParams({
            MatMulServiceProofBatchEntry(valid_service, FormatNonce64Hex(state.nonce), state.digest.GetHex()),
        })).get_obj();
    BOOST_CHECK_EQUAL(redeem_again_batch.find_value("count").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(redeem_again_batch.find_value("valid").getInt<int>(), 0);
    BOOST_CHECK_EQUAL(redeem_again_batch.find_value("invalid").getInt<int>(), 1);
    BOOST_REQUIRE(redeem_again_batch.find_value("by_reason").isObject());
    const auto redeem_again_reasons = redeem_again_batch.find_value("by_reason").get_obj();
    BOOST_CHECK_EQUAL(redeem_again_reasons.find_value("already_redeemed").getInt<int>(), 1);
    BOOST_REQUIRE(redeem_again_batch.find_value("results").isArray());
    const auto& redeem_again_results = redeem_again_batch.find_value("results").get_array();
    BOOST_REQUIRE_EQUAL(redeem_again_results.size(), 1U);
    BOOST_CHECK_EQUAL(redeem_again_results[0].get_obj().find_value("reason").get_str(), "already_redeemed");
}

BOOST_AUTO_TEST_CASE(verifymatmulserviceproofs_can_skip_local_registry_lookup)
{
    const auto valid_service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/stateless-batch-valid",
            "user:stateless-batch-valid@example.com",
            0.001,
            300,
            0.0,
            0.0,
            "fixed",
            24,
            0.001,
            0.001)).get_obj();
    matmul::PowState state = PowStateFromServiceChallenge(valid_service);
    const matmul::PowConfig config = PowConfigFromServiceChallenge(valid_service);
    uint64_t max_tries{256};
    BOOST_REQUIRE(matmul::Solve(state, config, max_tries));

    const auto invalid_service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/stateless-batch-invalid",
            "user:stateless-batch-invalid@example.com",
            2.0,
            300,
            0.0,
            0.0)).get_obj();

    const auto verify_batch = CallRPC(
        "verifymatmulserviceproofs",
        MatMulServiceProofBatchParams({
            MatMulServiceProofBatchEntry(valid_service, FormatNonce64Hex(state.nonce), state.digest.GetHex()),
            MatMulServiceProofBatchEntry(invalid_service, "0000000000000000", std::string(64, '0')),
        }, false)).get_obj();

    BOOST_CHECK_EQUAL(verify_batch.find_value("count").getInt<int>(), 2);
    BOOST_REQUIRE(verify_batch.find_value("results").isArray());
    const auto& results = verify_batch.find_value("results").get_array();
    BOOST_REQUIRE_EQUAL(results.size(), 2U);
    BOOST_CHECK(results[0].get_obj().find_value("valid").get_bool());
    BOOST_CHECK_EQUAL(results[0].get_obj().find_value("reason").get_str(), "ok");
    BOOST_CHECK(!results[0].get_obj().find_value("local_registry_status_checked").get_bool());
    BOOST_CHECK(results[0].get_obj().find_value("issued_by_local_node").isNull());
    BOOST_CHECK(results[0].get_obj().find_value("redeemed").isNull());
    BOOST_CHECK(results[0].get_obj().find_value("redeemable").isNull());
    BOOST_CHECK_EQUAL(results[1].get_obj().find_value("reason").get_str(), "invalid_proof");
    BOOST_CHECK(!results[1].get_obj().find_value("local_registry_status_checked").get_bool());
    BOOST_CHECK(results[1].get_obj().find_value("issued_by_local_node").isNull());
    BOOST_CHECK(results[1].get_obj().find_value("redeemed").isNull());
    BOOST_CHECK(results[1].get_obj().find_value("redeemable").isNull());
}

BOOST_AUTO_TEST_CASE(redeemmatmulserviceproofs_marks_duplicate_entry_already_redeemed_inside_single_batch)
{
    const auto service = CallRPC(
        "getmatmulservicechallenge",
        GetMatMulServiceChallengeParams(
            "rate_limit",
            "post:/v1/comment",
            "user:duplicate@example.com",
            0.001,
            300,
            0.0,
            0.0,
            "fixed",
            24,
            0.001,
            0.001)).get_obj();

    matmul::PowState state = PowStateFromServiceChallenge(service);
    const matmul::PowConfig config = PowConfigFromServiceChallenge(service);
    uint64_t max_tries{256};
    BOOST_REQUIRE(matmul::Solve(state, config, max_tries));

    const auto duplicate_batch = CallRPC(
        "redeemmatmulserviceproofs",
        MatMulServiceProofBatchParams({
            MatMulServiceProofBatchEntry(service, FormatNonce64Hex(state.nonce), state.digest.GetHex()),
            MatMulServiceProofBatchEntry(service, FormatNonce64Hex(state.nonce), state.digest.GetHex()),
        })).get_obj();
    BOOST_CHECK_EQUAL(duplicate_batch.find_value("count").getInt<int>(), 2);
    BOOST_CHECK_EQUAL(duplicate_batch.find_value("valid").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(duplicate_batch.find_value("invalid").getInt<int>(), 1);
    BOOST_REQUIRE(duplicate_batch.find_value("by_reason").isObject());
    const auto reasons = duplicate_batch.find_value("by_reason").get_obj();
    BOOST_CHECK_EQUAL(reasons.find_value("ok").getInt<int>(), 1);
    BOOST_CHECK_EQUAL(reasons.find_value("already_redeemed").getInt<int>(), 1);
    BOOST_REQUIRE(duplicate_batch.find_value("results").isArray());
    const auto& results = duplicate_batch.find_value("results").get_array();
    BOOST_REQUIRE_EQUAL(results.size(), 2U);
    BOOST_CHECK(results[0].get_obj().find_value("valid").get_bool());
    BOOST_CHECK(results[0].get_obj().find_value("redeemed").get_bool());
    BOOST_CHECK_EQUAL(results[1].get_obj().find_value("reason").get_str(), "already_redeemed");
    BOOST_CHECK(results[1].get_obj().find_value("redeemed").get_bool());
    BOOST_CHECK(!results[1].get_obj().find_value("redeemable").get_bool());
}

BOOST_AUTO_TEST_SUITE_END()
