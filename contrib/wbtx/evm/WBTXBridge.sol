// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {WBTX} from "./WBTX.sol";
import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {AccessControlDefaultAdminRules}
    from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @dev Authorizes a mint statement. `proof` is opaque (ECDSA bundle today; a SNARK tomorrow). The
///      bridge passes the EIP-712 typed digest so the verifier is signature-scheme-agnostic.
interface IAttestationVerifier {
    function verifyMint(bytes32 digest, bytes calldata proof) external view returns (bool);
}

/// @title WBTXBridge — federation lock-and-mint bridge (Model A), hardened.
/// @notice Mints wBTX against an EIP-712 attested, replay-bound BTX lock and burns wBTX to request a
///         BTX release. Hardened per contrib/wbtx/SECURITY.md against the bridge-hack corpus (Ronin,
///         Wormhole, Nomad, Poly, Qubit, Multichain, renBTC):
///           - EIP-712 typed attestation; live `block.chainid` in the domain (no post-fork replay).
///           - Per-deposit outpoint replay guard (one mint per BTX outpoint).
///           - Circuit breaker: rolling-window mint cap + hard supply ceiling.
///           - Guardian veto: mints above `optimisticThreshold` are time-queued and cancelable by a
///             GUARDIAN before execution (tBTC optimistic-minting pattern) — bounds a compromised
///             federation/verifier.
///           - Pause (PAUSER) + role separation via AccessControlDefaultAdminRules (2-step + delay;
///             admin MUST be a Timelock owned by a multisig).
///           - Redeem: uint64 truncation guard, on-chain fulfillment record, and a governance refund
///             path if a redemption cannot be honored (no silently-lost funds).
///           - ReentrancyGuard on mint/execute/redeem/refund.
///         Reference implementation — external audit + invariant fuzzing required before mainnet.
contract WBTXBridge is EIP712, AccessControlDefaultAdminRules, ReentrancyGuard {
    WBTX public immutable wbtx;
    uint256 public immutable bridgeId;
    /// @dev 1 BTX satoshi == SAT_SCALE units of 18-decimal wBTX (the decided standard). Mirrors WBTX.
    uint256 public constant SAT_SCALE = 1e10;

    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE"); // Timelock
    bytes32 public constant GUARDIAN_ROLE   = keccak256("GUARDIAN_ROLE");   // veto/cancel + pause
    bytes32 public constant PAUSER_ROLE     = keccak256("PAUSER_ROLE");
    bytes32 public constant FEDERATION_ROLE = keccak256("FEDERATION_ROLE"); // marks redeems fulfilled

    bytes32 private constant MINT_TYPEHASH =
        keccak256("MintAttestation(bytes32 btxTxid,uint32 vout,address to,uint64 amountSat)");

    IAttestationVerifier public verifier;
    // Granular pause: mint-pause is the critical backing-safety lever; redeem-pause is for BTX-side
    // issues. Keeping them separate avoids halting redemptions when only minting must stop, and vice versa.
    bool public mintPaused;
    bool public redeemPaused;

    // --- circuit breaker (Ronin/Harmony lesson: cap blast radius, don't rely on humans noticing) ---
    uint256 public maxSupplyWbtx;          // hard ceiling on circulating wBTX (0 = unlimited)
    uint64  public windowMintCapSat;       // max sat minted per rolling window (0 = unlimited)
    uint64  public windowDuration;         // window length (seconds)
    uint64  public windowStart;
    uint64  public windowMintedSat;

    // --- guardian veto (tBTC optimistic minting) ---
    uint64  public optimisticThresholdSat; // mints above this are time-queued
    uint64  public guardianDelay;          // queue delay (seconds) during which a GUARDIAN may cancel

    struct QueuedMint { address to; uint64 amountSat; uint64 executeAfter; bool exists; }
    mapping(bytes32 => bool) public minted;        // depositKey => minted (authoritative replay guard)
    mapping(bytes32 => QueuedMint) public queued;  // depositKey => pending mint

    // --- redeem lifecycle (auditable + refundable) ---
    struct Redeem { address from; uint64 amountSat; uint256 amountWbtx; uint64 requestedAt; bool fulfilled; bool refunded; }
    uint256 public redeemNonce;
    mapping(uint256 => Redeem) public redeems;
    uint64 public redeemRefundTimeout;     // after this, an unfulfilled redeem may be governance-refunded

    event MintExecuted(bytes32 indexed depositKey, bytes32 btxTxid, uint32 vout, address indexed to, uint64 amountSat, uint256 amountWbtx);
    event MintQueued(bytes32 indexed depositKey, address indexed to, uint64 amountSat, uint64 executeAfter);
    event MintCancelled(bytes32 indexed depositKey, address indexed by);
    event RedeemRequested(uint256 indexed redeemId, address indexed from, uint64 amountSat, bytes btxDestination, uint256 amountWbtxBurned);
    event RedeemFulfilled(uint256 indexed redeemId, bytes32 btxTxid);
    event RedeemRefunded(uint256 indexed redeemId, address indexed to, uint256 amountWbtx);
    event VerifierUpdated(address indexed previous, address indexed current);
    event MintPausedSet(bool paused, address indexed by);
    event RedeemPausedSet(bool paused, address indexed by);
    event LimitsUpdated(uint256 maxSupplyWbtx, uint64 windowMintCapSat, uint64 windowDuration, uint64 optimisticThresholdSat, uint64 guardianDelay, uint64 redeemRefundTimeout);

    error MintPaused();
    error RedeemPaused();
    error AlreadyMinted();
    error BadAttestation();
    error AmountOverflow();
    error WindowCapExceeded();
    error SupplyCapExceeded();
    error NotQueued();
    error TooEarly();
    error BadDestination();
    error BelowOneSat();
    error UnknownRedeem();
    error RedeemClosed();

    modifier whenMintNotPaused() { if (mintPaused) revert MintPaused(); _; }
    modifier whenRedeemNotPaused() { if (redeemPaused) revert RedeemPaused(); _; }

    constructor(
        WBTX wbtx_,
        IAttestationVerifier verifier_,
        uint256 bridgeId_,
        address admin,          // Timelock-owned multisig
        uint48  adminDelay
    ) EIP712("WBTXBridge", "1") AccessControlDefaultAdminRules(adminDelay, admin) {
        wbtx = wbtx_;
        verifier = verifier_;
        bridgeId = bridgeId_;
        // Sensible-but-conservative defaults; tune via setLimits before launch.
        windowDuration = 1 days;
        redeemRefundTimeout = 7 days;
    }

    // ----------------------------- governance -----------------------------

    function setVerifier(IAttestationVerifier v) external onlyRole(GOVERNANCE_ROLE) {
        emit VerifierUpdated(address(verifier), address(v));
        verifier = v;
    }

    function setLimits(
        uint256 maxSupplyWbtx_, uint64 windowMintCapSat_, uint64 windowDuration_,
        uint64 optimisticThresholdSat_, uint64 guardianDelay_, uint64 redeemRefundTimeout_
    ) external onlyRole(GOVERNANCE_ROLE) {
        maxSupplyWbtx = maxSupplyWbtx_;
        windowMintCapSat = windowMintCapSat_;
        windowDuration = windowDuration_ == 0 ? 1 days : windowDuration_;
        optimisticThresholdSat = optimisticThresholdSat_;
        guardianDelay = guardianDelay_;
        redeemRefundTimeout = redeemRefundTimeout_;
        emit LimitsUpdated(maxSupplyWbtx_, windowMintCapSat_, windowDuration_, optimisticThresholdSat_, guardianDelay_, redeemRefundTimeout_);
    }

    function setMintPaused(bool p) external onlyRole(PAUSER_ROLE) { mintPaused = p; emit MintPausedSet(p, msg.sender); }
    function setRedeemPaused(bool p) external onlyRole(PAUSER_ROLE) { redeemPaused = p; emit RedeemPausedSet(p, msg.sender); }

    // ----------------------------- attestation -----------------------------

    /// @notice EIP-712 typed digest the federation signs. Domain binds {name, version, block.chainid,
    ///         address(this)} (live chainid => no post-fork replay; verifyingContract => no cross-bridge
    ///         replay). The struct binds the exact deposit, recipient, and amount.
    function mintDigest(bytes32 btxTxid, uint32 vout, address to, uint64 amountSat) public view returns (bytes32) {
        return _hashTypedDataV4(keccak256(abi.encode(MINT_TYPEHASH, btxTxid, vout, to, amountSat)));
    }

    function depositKey(bytes32 btxTxid, uint32 vout) public pure returns (bytes32) {
        return keccak256(abi.encode(btxTxid, vout)); // abi.encode (not packed) => collision-safe
    }

    // ----------------------------- mint -----------------------------

    /// @notice Mint wBTX for an attested BTX lock. Small mints execute immediately; mints above
    ///         `optimisticThresholdSat` are time-queued for guardian review. Idempotent per deposit.
    function mint(bytes32 btxTxid, uint32 vout, address to, uint64 amountSat, bytes calldata proof)
        external whenMintNotPaused nonReentrant
    {
        if (to == address(0)) revert BadDestination();
        if (amountSat == 0) revert BelowOneSat();
        bytes32 dk = depositKey(btxTxid, vout);
        if (minted[dk] || queued[dk].exists) revert AlreadyMinted();

        if (!verifier.verifyMint(mintDigest(btxTxid, vout, to, amountSat), proof)) revert BadAttestation();

        _checkAndConsumeLimits(amountSat);

        if (optimisticThresholdSat != 0 && amountSat > optimisticThresholdSat && guardianDelay != 0) {
            uint64 executeAfter = uint64(block.timestamp) + guardianDelay;
            queued[dk] = QueuedMint({to: to, amountSat: amountSat, executeAfter: executeAfter, exists: true});
            emit MintQueued(dk, to, amountSat, executeAfter);
        } else {
            minted[dk] = true;
            _doMint(dk, btxTxid, vout, to, amountSat);
        }
    }

    /// @notice Execute a queued mint after its guardian delay (anyone may call).
    function executeQueuedMint(bytes32 btxTxid, uint32 vout) external whenMintNotPaused nonReentrant {
        bytes32 dk = depositKey(btxTxid, vout);
        QueuedMint memory q = queued[dk];
        if (!q.exists) revert NotQueued();
        if (block.timestamp < q.executeAfter) revert TooEarly();
        delete queued[dk];
        minted[dk] = true;
        _doMint(dk, btxTxid, vout, q.to, q.amountSat);
    }

    /// @notice A GUARDIAN cancels a queued (suspicious) mint within the delay window. The deposit can
    ///         then be re-attested/re-minted only after governance review (the outpoint is freed).
    function cancelQueuedMint(bytes32 btxTxid, uint32 vout) external onlyRole(GUARDIAN_ROLE) {
        bytes32 dk = depositKey(btxTxid, vout);
        if (!queued[dk].exists) revert NotQueued();
        delete queued[dk];
        emit MintCancelled(dk, msg.sender);
    }

    function _doMint(bytes32 dk, bytes32 btxTxid, uint32 vout, address to, uint64 amountSat) private {
        uint256 amountWbtx = uint256(amountSat) * SAT_SCALE;
        if (maxSupplyWbtx != 0 && wbtx.totalSupply() + amountWbtx > maxSupplyWbtx) revert SupplyCapExceeded();
        wbtx.mint(to, amountWbtx);
        emit MintExecuted(dk, btxTxid, vout, to, amountSat, amountWbtx);
    }

    function _checkAndConsumeLimits(uint64 amountSat) private {
        if (windowMintCapSat == 0) return;
        uint64 nowTs = uint64(block.timestamp);
        if (nowTs >= windowStart + windowDuration) { windowStart = nowTs; windowMintedSat = 0; }
        // overflow-safe accumulation
        if (uint256(windowMintedSat) + amountSat > windowMintCapSat) revert WindowCapExceeded();
        windowMintedSat += amountSat;
    }

    // ----------------------------- redeem -----------------------------

    /// @notice Burn wBTX to request a BTX release to `btxDestination`. ROUNDS DOWN to whole satoshi;
    ///         sub-sat dust is burned (accrues to backing surplus). Records an auditable, refundable
    ///         redeem.
    function redeem(uint256 amountWbtx, bytes calldata btxDestination)
        external whenRedeemNotPaused nonReentrant returns (uint256 redeemId)
    {
        if (btxDestination.length == 0 || btxDestination.length > 128) revert BadDestination();
        uint256 sat = amountWbtx / SAT_SCALE;            // round down
        if (sat == 0) revert BelowOneSat();
        if (sat > type(uint64).max) revert AmountOverflow(); // defensive truncation guard
        uint64 amountSat = uint64(sat);

        wbtx.burn(msg.sender, amountWbtx);               // burn FULL amount (dust included)
        redeemId = ++redeemNonce;
        redeems[redeemId] = Redeem({
            from: msg.sender, amountSat: amountSat, amountWbtx: amountWbtx,
            requestedAt: uint64(block.timestamp), fulfilled: false, refunded: false
        });
        emit RedeemRequested(redeemId, msg.sender, amountSat, btxDestination, amountWbtx);
    }

    /// @notice The federation records on-chain that a redeem was released on BTX (auditability).
    function fulfillRedeem(uint256 redeemId, bytes32 btxTxid) external onlyRole(FEDERATION_ROLE) {
        Redeem storage r = redeems[redeemId];
        if (r.from == address(0)) revert UnknownRedeem();
        if (r.fulfilled || r.refunded) revert RedeemClosed();
        r.fulfilled = true;
        emit RedeemFulfilled(redeemId, btxTxid);
    }

    /// @notice If a redeem cannot be honored on BTX (malformed destination, federation failure) and
    ///         the refund timeout has elapsed, governance re-mints wBTX to the original burner so no
    ///         funds are silently lost. (FBTC "safety committee" pattern.)
    function refundRedeem(uint256 redeemId) external onlyRole(GOVERNANCE_ROLE) nonReentrant {
        Redeem storage r = redeems[redeemId];
        if (r.from == address(0)) revert UnknownRedeem();
        if (r.fulfilled || r.refunded) revert RedeemClosed();
        if (block.timestamp < r.requestedAt + redeemRefundTimeout) revert TooEarly();
        r.refunded = true;
        wbtx.mint(r.from, r.amountWbtx);
        emit RedeemRefunded(redeemId, r.from, r.amountWbtx);
    }
}

/// @title ECDSAMultisigVerifier — v1 M-of-N attestation verifier (classical EVM leg).
/// @notice Verifies >= threshold distinct ECDSA signatures from the configured signer set over the
///         bridge's EIP-712 digest, using audited OpenZeppelin `ECDSA` (rejects high-s malleability,
///         bad `v`, and the ecrecover-zero-address case). `proof` = abi.encode(bytes[] signatures),
///         ordered by ASCENDING recovered signer address (cheap distinctness). Signer set is
///         rotatable by governance with proper clearing. UNAUDITED reference.
///
/// SECURITY: this is *classical* security on the EVM leg; the authoritative security is the M-of-N
///           POST-QUANTUM attestation on BTX. Swap this for a zk-attestation verifier (constant-gas
///           SNARK proving M-of-N ML-DSA/SLH-DSA signatures) to make the EVM leg PQ-secure too —
///           the bridge's IAttestationVerifier interface is unchanged. See SECURITY.md / architecture §8.
contract ECDSAMultisigVerifier is IAttestationVerifier, AccessControlDefaultAdminRules {
    using ECDSA for bytes32;

    address[] private _signers;
    mapping(address => bool) public isSigner;
    uint256 public threshold;

    event SignersRotated(address[] signers, uint256 threshold);

    error BadThreshold();
    error DupOrZeroSigner();
    error TooManySigs();
    error NotOrdered();

    constructor(address admin, uint48 adminDelay, address[] memory signers_, uint256 threshold_)
        AccessControlDefaultAdminRules(adminDelay, admin)
    {
        _rotate(signers_, threshold_);
    }

    /// @notice Replace the entire signer set + threshold (governance/Timelock only). Clears the prior
    ///         set first (no stale-signer accumulation — the gap flagged in the v0 reference).
    function rotateSigners(address[] calldata signers_, uint256 threshold_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _rotate(signers_, threshold_);
    }

    function _rotate(address[] memory signers_, uint256 threshold_) private {
        if (threshold_ == 0 || threshold_ > signers_.length) revert BadThreshold();
        for (uint256 i = 0; i < _signers.length; i++) { isSigner[_signers[i]] = false; }
        delete _signers;
        for (uint256 i = 0; i < signers_.length; i++) {
            address s = signers_[i];
            if (s == address(0) || isSigner[s]) revert DupOrZeroSigner();
            isSigner[s] = true;
            _signers.push(s);
        }
        threshold = threshold_;
        emit SignersRotated(signers_, threshold_);
    }

    function signers() external view returns (address[] memory) { return _signers; }

    function verifyMint(bytes32 digest, bytes calldata proof) external view returns (bool) {
        bytes[] memory sigs = abi.decode(proof, (bytes[]));
        if (sigs.length > _signers.length) revert TooManySigs(); // fail fast; bound the loop
        if (sigs.length < threshold) return false;
        address last = address(0);
        uint256 valid = 0;
        for (uint256 i = 0; i < sigs.length; i++) {
            address signer = digest.recover(sigs[i]);   // OZ: rejects high-s, bad v, zero-addr
            if (signer <= last) revert NotOrdered();     // strictly ascending => distinct
            last = signer;
            if (isSigner[signer]) { unchecked { valid++; } }
        }
        return valid >= threshold;
    }
}
