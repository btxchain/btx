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
    /// @dev Code-level minimum finality floor: matches BTX COINBASE_MATURITY (100) and is ~3x the
    ///      observed 34-block reorg; this is not governance-settable.
    uint64 public constant MIN_CONFIRMATIONS = 100;

    bytes32 public constant GOVERNANCE_ROLE = keccak256("GOVERNANCE_ROLE"); // Timelock
    bytes32 public constant GUARDIAN_ROLE   = keccak256("GUARDIAN_ROLE");   // veto/cancel + pause
    bytes32 public constant PAUSER_ROLE     = keccak256("PAUSER_ROLE");
    bytes32 public constant FEDERATION_ROLE = keccak256("FEDERATION_ROLE"); // marks redeems fulfilled
    /// @dev Trust-anchor change delay (L2BEAT Stage-1 style exit window).
    uint64 public constant VERIFIER_DELAY = 7 days;
    /// @dev Shorter delay for clearing a guardian veto on an otherwise honest user deposit.
    uint64 public constant CLEAR_VETO_DELAY = 48 hours;
    /// @dev Governance cannot shrink guardian review to near-zero.
    uint64 public constant MIN_GUARDIAN_DELAY = 6 hours;

    bytes32 private constant MINT_TYPEHASH =
        keccak256("MintAttestation(uint256 bridgeId,bytes32 btxTxid,uint32 vout,bytes32 btxBlockHash,uint64 btxBlockHeight,uint64 attestedHeight,address to,uint64 amountSat,uint64 deadline)");

    IAttestationVerifier public verifier;
    IAttestationVerifier public pendingVerifier;
    uint64 public verifierEta;
    // Granular pause: mint-pause is the critical backing-safety lever; redeem-pause is for BTX-side
    // issues. Keeping them separate avoids halting redemptions when only minting must stop, and vice versa.
    bool public mintPaused;
    bool public redeemPaused;
    bool public limitsConfigured;

    // --- circuit breaker (Ronin/Harmony lesson: cap blast radius, don't rely on humans noticing) ---
    uint256 public maxSupplyWbtx;          // hard ceiling on circulating wBTX (0 = unlimited)
    uint64  public windowMintCapSat;       // max sat minted per rolling window (0 = unlimited)
    uint64  public windowDuration;         // window length (seconds)
    uint64  public availableSat;
    uint64  public lastRefill;

    // --- guardian veto (tBTC optimistic minting) ---
    uint64  public optimisticThresholdSat; // mints above this are time-queued
    uint64  public guardianDelay;          // queue delay (seconds) during which a GUARDIAN may cancel

    struct QueuedMint { address to; uint64 amountSat; uint64 executeAfter; bool exists; }
    mapping(bytes32 => bool) public minted;        // depositKey => minted (authoritative replay guard)
    mapping(bytes32 => QueuedMint) public queued;  // depositKey => pending mint
    mapping(bytes32 => bool) public vetoed;        // depositKey => guardian-vetoed until governance clears
    mapping(bytes32 => uint64) public clearVetoEta;

    // --- redeem lifecycle (auditable + refundable) ---
    struct Redeem { address from; uint64 amountSat; uint256 amountWbtx; uint64 requestedAt; bool fulfilled; bool refunded; }
    uint256 public redeemNonce;
    mapping(uint256 => Redeem) public redeems;
    uint64 public redeemRefundTimeout;     // after this, an unfulfilled redeem may be governance-refunded

    event MintExecuted(bytes32 indexed depositKey, bytes32 btxTxid, uint32 vout, address indexed to, uint64 amountSat, uint256 amountWbtx);
    event MintQueued(bytes32 indexed depositKey, address indexed to, uint64 amountSat, uint64 executeAfter);
    event MintCancelled(bytes32 indexed depositKey, address indexed by);
    event VetoCleared(bytes32 indexed depositKey, address indexed by);
    event RedeemRequested(uint256 indexed redeemId, address indexed from, uint64 amountSat, bytes btxDestination, uint256 amountWbtxBurned);
    event RedeemFulfilled(uint256 indexed redeemId, bytes32 btxTxid);
    event RedeemRefunded(uint256 indexed redeemId, address indexed to, uint256 amountWbtx);
    event VerifierProposed(address indexed pendingVerifier, uint64 verifierEta);
    event VerifierApplied(address indexed previousVerifier, address indexed currentVerifier);
    event PendingVerifierCancelled(address indexed by);
    event ClearVetoProposed(bytes32 indexed depositKey, uint64 executeAfter);
    event MintPausedSet(bool paused, address indexed by);
    event RedeemPausedSet(bool paused, address indexed by);
    event LimitsUpdated(uint256 maxSupplyWbtx, uint64 windowMintCapSat, uint64 windowDuration, uint64 optimisticThresholdSat, uint64 guardianDelay, uint64 redeemRefundTimeout);

    error MintPaused();
    error RedeemPaused();
    error AlreadyMinted();
    error Vetoed();
    error BadAttestation();
    error AmountOverflow();
    error WindowCapExceeded();
    error SupplyCapExceeded();
    error NotConfigured();
    error ZeroBreakerValue();
    error WindowRateZero();
    error NotQueued();
    error TooEarly();
    error AttestationExpired();
    error NotAttested();
    error TooShallow();
    error BadDestination();
    error BelowOneSat();
    error UnknownRedeem();
    error RedeemClosed();
    error VerifierNotContract();
    error VerifierNotReady();
    error ClearVetoNotReady();
    error GuardianDelayTooLow();

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

    function proposeVerifier(IAttestationVerifier v) external onlyRole(GOVERNANCE_ROLE) {
        if (address(v) == address(0) || address(v).code.length == 0) revert VerifierNotContract();
        pendingVerifier = v;
        verifierEta = uint64(block.timestamp) + VERIFIER_DELAY;
        emit VerifierProposed(address(v), verifierEta);
    }

    function applyVerifier() external {
        if (verifierEta == 0 || block.timestamp < verifierEta) revert VerifierNotReady();
        address previous = address(verifier);
        IAttestationVerifier next = pendingVerifier;
        verifier = next;
        pendingVerifier = IAttestationVerifier(address(0));
        verifierEta = 0;
        emit VerifierApplied(previous, address(next));
    }

    function cancelPendingVerifier() external onlyRole(GUARDIAN_ROLE) {
        pendingVerifier = IAttestationVerifier(address(0));
        verifierEta = 0;
        emit PendingVerifierCancelled(msg.sender);
    }

    function setLimits(
        uint256 maxSupplyWbtx_, uint64 windowMintCapSat_, uint64 windowDuration_,
        uint64 optimisticThresholdSat_, uint64 guardianDelay_, uint64 redeemRefundTimeout_
    ) external onlyRole(GOVERNANCE_ROLE) {
        if (
            maxSupplyWbtx_ == 0
                || windowMintCapSat_ == 0
                || windowDuration_ == 0
                || optimisticThresholdSat_ == 0
                || guardianDelay_ == 0
        ) revert ZeroBreakerValue();
        if (guardianDelay_ < MIN_GUARDIAN_DELAY) revert GuardianDelayTooLow();
        if (uint256(windowMintCapSat_) / uint256(windowDuration_) == 0) revert WindowRateZero();
        maxSupplyWbtx = maxSupplyWbtx_;
        windowMintCapSat = windowMintCapSat_;
        windowDuration = windowDuration_;
        optimisticThresholdSat = optimisticThresholdSat_;
        guardianDelay = guardianDelay_;
        redeemRefundTimeout = redeemRefundTimeout_;
        availableSat = windowMintCapSat_;
        lastRefill = uint64(block.timestamp);
        limitsConfigured = true;
        emit LimitsUpdated(maxSupplyWbtx_, windowMintCapSat_, windowDuration_, optimisticThresholdSat_, guardianDelay_, redeemRefundTimeout_);
    }

    function setMintPaused(bool p) external onlyRole(PAUSER_ROLE) { mintPaused = p; emit MintPausedSet(p, msg.sender); }
    function setRedeemPaused(bool p) external onlyRole(PAUSER_ROLE) { redeemPaused = p; emit RedeemPausedSet(p, msg.sender); }

    // ----------------------------- attestation -----------------------------

    /// @notice EIP-712 typed digest the federation signs. Domain binds {name, version, block.chainid,
    ///         address(this)} (live chainid => no post-fork replay; verifyingContract => no cross-bridge
    ///         replay). The struct binds bridge identity, exact deposit and BTX finality view, recipient,
    ///         amount, and attestation expiry.
    function mintDigest(
        uint256 bridgeId_,
        bytes32 btxTxid,
        uint32 vout,
        bytes32 btxBlockHash,
        uint64 btxBlockHeight,
        uint64 attestedHeight,
        address to,
        uint64 amountSat,
        uint64 deadline
    ) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(
                    MINT_TYPEHASH,
                    bridgeId_,
                    btxTxid,
                    vout,
                    btxBlockHash,
                    btxBlockHeight,
                    attestedHeight,
                    to,
                    amountSat,
                    deadline
                )
            )
        );
    }

    function depositKey(bytes32 btxTxid, uint32 vout) public pure returns (bytes32) {
        return keccak256(abi.encode(btxTxid, vout)); // abi.encode (not packed) => collision-safe
    }

    // ----------------------------- mint -----------------------------

    /// @notice Mint wBTX for an attested BTX lock. Small mints execute immediately; mints above
    ///         `optimisticThresholdSat` are time-queued for guardian review. Idempotent per deposit.
    function mint(
        bytes32 btxTxid,
        uint32 vout,
        bytes32 btxBlockHash,
        uint64 btxBlockHeight,
        uint64 attestedHeight,
        address to,
        uint64 amountSat,
        uint64 deadline,
        bytes calldata proof
    ) external whenMintNotPaused nonReentrant {
        if (!limitsConfigured) revert NotConfigured();
        if (to == address(0)) revert BadDestination();
        if (amountSat == 0) revert BelowOneSat();
        if (block.timestamp > deadline) revert AttestationExpired();
        if (attestedHeight < btxBlockHeight) revert NotAttested();
        if (attestedHeight - btxBlockHeight < MIN_CONFIRMATIONS) revert TooShallow();
        bytes32 dk = depositKey(btxTxid, vout);
        if (minted[dk] || queued[dk].exists) revert AlreadyMinted();
        if (vetoed[dk]) revert Vetoed();

        if (
            !verifier.verifyMint(
                mintDigest(
                    bridgeId,
                    btxTxid,
                    vout,
                    btxBlockHash,
                    btxBlockHeight,
                    attestedHeight,
                    to,
                    amountSat,
                    deadline
                ),
                proof
            )
        ) revert BadAttestation();

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

    /// @notice A GUARDIAN cancels a queued (suspicious) mint within the delay window and durably vetoes
    ///         the deposit key until governance clears it.
    function cancelQueuedMint(bytes32 btxTxid, uint32 vout) external onlyRole(GUARDIAN_ROLE) {
        bytes32 dk = depositKey(btxTxid, vout);
        if (!queued[dk].exists) revert NotQueued();
        delete queued[dk];
        vetoed[dk] = true;
        emit MintCancelled(dk, msg.sender);
    }

    /// @notice Governance-only proposal to clear a guardian veto after a short review delay.
    function proposeClearVeto(bytes32 dk) external onlyRole(GOVERNANCE_ROLE) {
        clearVetoEta[dk] = uint64(block.timestamp) + CLEAR_VETO_DELAY;
        emit ClearVetoProposed(dk, clearVetoEta[dk]);
    }

    function applyClearVeto(bytes32 dk) external {
        uint64 eta = clearVetoEta[dk];
        if (eta == 0 || block.timestamp < eta) revert ClearVetoNotReady();
        delete clearVetoEta[dk];
        vetoed[dk] = false;
        emit VetoCleared(dk, msg.sender);
    }

    function _doMint(bytes32 dk, bytes32 btxTxid, uint32 vout, address to, uint64 amountSat) private {
        _checkAndConsumeLimits(amountSat);
        uint256 amountWbtx = uint256(amountSat) * SAT_SCALE;
        if (maxSupplyWbtx != 0 && wbtx.totalSupply() + amountWbtx > maxSupplyWbtx) revert SupplyCapExceeded();
        wbtx.mint(to, amountWbtx);
        emit MintExecuted(dk, btxTxid, vout, to, amountSat, amountWbtx);
    }

    function _checkAndConsumeLimits(uint64 amountSat) private {
        if (windowMintCapSat == 0) return;
        if (uint256(windowMintCapSat) / uint256(windowDuration) == 0) revert WindowRateZero();
        uint64 nowTs = uint64(block.timestamp);
        uint64 elapsed = nowTs - lastRefill;
        uint256 replenished = uint256(elapsed) * uint256(windowMintCapSat) / uint256(windowDuration);
        uint256 available = uint256(availableSat) + replenished;
        if (available > windowMintCapSat) available = windowMintCapSat;
        if (available < amountSat) revert WindowCapExceeded();
        availableSat = uint64(available - amountSat);
        lastRefill = nowTs;
    }

    // ----------------------------- redeem -----------------------------

    /// @notice Burn wBTX to request a BTX release to `btxDestination`. ROUNDS DOWN to whole satoshi;
    ///         sub-sat dust is burned (accrues to backing surplus). Records an auditable, refundable
    ///         redeem.
    function redeem(uint256 amountWbtx, bytes calldata btxDestination)
        external whenRedeemNotPaused nonReentrant returns (uint256 redeemId)
    {
        if (!limitsConfigured) revert NotConfigured();
        if (btxDestination.length == 0 || btxDestination.length > 128) revert BadDestination();
        uint256 sat = amountWbtx / SAT_SCALE;            // round down
        if (sat == 0) revert BelowOneSat();
        if (sat > type(uint64).max) revert AmountOverflow(); // defensive truncation guard
        uint64 amountSat = uint64(sat);

        wbtx.burnFrom(msg.sender, amountWbtx);           // burn FULL amount (dust included)
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

    bytes32 public constant GUARDIAN_ROLE = keccak256("GUARDIAN_ROLE");
    uint64 public constant ROTATION_DELAY = 7 days;

    address[] private _signers;
    address[] private _pendingSigners;
    mapping(address => bool) public isSigner;
    uint256 public threshold;
    uint256 public pendingThreshold;
    uint64 public rotationEta;

    event SignersRotated(address[] signers, uint256 threshold);
    event RotationProposed(address[] signers, uint256 threshold, uint64 rotationEta);
    event PendingRotationCancelled(address indexed by);

    error BadThreshold();
    error DupOrZeroSigner();
    error TooManySigs();
    error NotOrdered();
    error SignersNotAscending();
    error RotationNotReady();

    constructor(address admin, uint48 adminDelay, address[] memory signers_, uint256 threshold_)
        AccessControlDefaultAdminRules(adminDelay, admin)
    {
        _rotate(signers_, threshold_);
        _grantRole(GUARDIAN_ROLE, admin);
    }

    /// @notice Legacy name routed through timelocked rotation flow.
    function rotateSigners(address[] calldata signers_, uint256 threshold_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _proposeRotation(signers_, threshold_);
    }

    /// @notice Propose signer set + threshold replacement, applied after a fixed delay.
    function proposeRotation(address[] calldata signers_, uint256 threshold_) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _proposeRotation(signers_, threshold_);
    }

    function applyRotation() external {
        if (rotationEta == 0 || block.timestamp < rotationEta) revert RotationNotReady();
        uint256 len = _pendingSigners.length;
        address[] memory signers_ = new address[](len);
        for (uint256 i = 0; i < len; i++) {
            signers_[i] = _pendingSigners[i];
        }
        uint256 threshold_ = pendingThreshold;
        delete _pendingSigners;
        pendingThreshold = 0;
        rotationEta = 0;
        _rotate(signers_, threshold_);
    }

    function cancelPendingRotation() external onlyRole(GUARDIAN_ROLE) {
        delete _pendingSigners;
        pendingThreshold = 0;
        rotationEta = 0;
        emit PendingRotationCancelled(msg.sender);
    }

    function pendingSigners() external view returns (address[] memory) {
        return _pendingSigners;
    }

    function _proposeRotation(address[] calldata signers_, uint256 threshold_) private {
        _validateRotation(signers_, threshold_);
        delete _pendingSigners;
        for (uint256 i = 0; i < signers_.length; i++) {
            _pendingSigners.push(signers_[i]);
        }
        pendingThreshold = threshold_;
        rotationEta = uint64(block.timestamp) + ROTATION_DELAY;
        emit RotationProposed(signers_, threshold_, rotationEta);
    }

    function _validateRotation(address[] calldata signers_, uint256 threshold_) private pure {
        if (threshold_ == 0 || threshold_ > signers_.length) revert BadThreshold();
        address prev = address(0);
        for (uint256 i = 0; i < signers_.length; i++) {
            address s = signers_[i];
            if (s == address(0)) revert DupOrZeroSigner();
            if (s <= prev) revert SignersNotAscending();
            prev = s;
        }
    }

    function _rotate(address[] memory signers_, uint256 threshold_) private {
        if (threshold_ == 0 || threshold_ > signers_.length) revert BadThreshold();
        address prev = address(0);
        for (uint256 i = 0; i < _signers.length; i++) { isSigner[_signers[i]] = false; }
        delete _signers;
        for (uint256 i = 0; i < signers_.length; i++) {
            address s = signers_[i];
            if (s == address(0) || isSigner[s]) revert DupOrZeroSigner();
            if (s <= prev) revert SignersNotAscending();
            prev = s;
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
