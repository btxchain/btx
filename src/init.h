// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_INIT_H
#define BITCOIN_INIT_H

#include <atomic>
#include <functional>
#include <string>
#include <utility>

class CChainParams;

//! Default value for -daemon option
static constexpr bool DEFAULT_DAEMON = false;
//! Default value for -daemonwait option
static constexpr bool DEFAULT_DAEMONWAIT = false;

class ArgsManager;
namespace interfaces {
struct BlockAndHeaderTipInfo;
}
namespace kernel {
struct Context;
}
namespace node {
struct NodeContext;
} // namespace node

/** Initialize node context shutdown and args variables. */
void InitContext(node::NodeContext& node);
/** Return whether node shutdown was requested. */
bool ShutdownRequested(node::NodeContext& node);

/** Interrupt threads */
void Interrupt(node::NodeContext& node);
void Shutdown(node::NodeContext& node);
//!Initialize the logging infrastructure
void InitLogging(const ArgsManager& args);
//!Parameter interaction: change current parameters depending on various rules
void InitParameterInteraction(ArgsManager& args);

/** Initialize bitcoin core: Basic context setup.
 *  @note This can be done before daemonization. Do not call Shutdown() if this function fails.
 *  @pre Parameters should be parsed and config file should be read.
 */
bool AppInitBasicSetup(const ArgsManager& args, std::atomic<int>& exit_status);
/**
 * Initialization: parameter interaction.
 * @note This can be done before daemonization. Do not call Shutdown() if this function fails.
 * @pre Parameters should be parsed and config file should be read, AppInitBasicSetup should have been called.
 */
bool AppInitParameterInteraction(const ArgsManager& args);

/** Fail closed if RC accelerator resolution or its production canary ran
 * before Unix daemonization. Device runtimes and their process-local caches
 * are not safe to inherit across fork(). */
bool CheckMatMulAcceleratorPreForkInvariant();
/**
 * Initialization sanity checks.
 * @note This can be done before daemonization. Do not call Shutdown() if this function fails.
 * @pre Parameters should be parsed and config file should be read, AppInitParameterInteraction should have been called.
 */
bool AppInitSanityChecks(const kernel::Context& kernel);
/**
 * Lock bitcoin core critical directories.
 * @note This should only be done after daemonization. Do not call Shutdown() if this function fails.
 * @pre Parameters should be parsed and config file should be read, AppInitSanityChecks should have been called.
 */
bool AppInitLockDirectories();
/**
 * Initialize node and wallet interface pointers. Has no prerequisites or side effects besides allocating memory.
 */
bool AppInitInterfaces(node::NodeContext& node);
/**
 * Bitcoin core main initialization.
 * @note This should only be done after daemonization. Call Shutdown() if this function fails.
 * @pre Parameters should be parsed and config file should be read, AppInitLockDirectories should have been called.
 */
bool AppInitMain(node::NodeContext& node, interfaces::BlockAndHeaderTipInfo* tip_info = nullptr);

/**
 * Register all arguments with the ArgsManager
 */
void SetupServerArgs(ArgsManager& argsman, bool can_listen_ipc=false);

/** Validates requirements to run the indexes and spawns each index initial sync thread */
bool StartIndexBackgroundSync(node::NodeContext& node);

/**
 * Resolve the default -matmulrcexecution mode for a chain.
 *
 * Returns "strict-device" on a public chain that carries a finite RC activation
 * height, and "auto-fallback" otherwise. Exposed so the truth table can be
 * pinned by a test: this default decides whether a node will silently accept an
 * unusable CPU ExactReplay path on an activated network, and it is consumed by
 * AppInitParameterInteraction, which the test harnesses execute too.
 */
std::string DefaultMatMulRCExecutionMode(const CChainParams& chainparams);

/** Historically returned true when a production RC consensus node could not
 * verify the first activated block and `-allowunverifiablematmulconsensus`
 * was unset. 0.34.5 never refuses that case: the node starts, warns, withholds
 * NODE_MATMUL_CONSENSUS. Without the flag it stalls at the RC body boundary.
 * With `-allowunverifiablematmulconsensus` catch-up still fully ExactReplays
 * every body (device GEMM if present, otherwise CPU) before ConnectTip.
 * Mining remains fail-closed (canary / self-qualification). The predicate
 * is kept so tests pin the documented degrade path. */
bool RefuseUnverifiableMatMulConsensusStartup(
    const CChainParams& chainparams,
    const std::string& validation_mode,
    bool strict_device_ready,
    bool allow_unverifiable_startup);

/** Result of one cheap runtime-presence re-probe while strict-device
 * validation is unavailable. This deliberately does not run self-
 * qualification or the production-shape golden canary. */
struct MatMulRCRuntimeReprobeResult {
    bool attempted{false};
    bool runtime_candidate_available{false};
    std::string provider;
    std::string reason;
};

/** Invoke a supplied cheap runtime-identity probe at most once, and only while
 * strict-device readiness is unavailable. Exposed to pin the scheduler's
 * fail-closed policy without touching accelerator hardware in unit tests. */
MatMulRCRuntimeReprobeResult RunUnavailableMatMulRCRuntimeReprobe(
    bool strict_device_ready,
    const std::string& provider,
    const std::function<std::pair<bool, std::string>(const std::string&)>& probe);

#endif // BITCOIN_INIT_H
