// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {ERC20Permit} from "@openzeppelin/contracts/token/ERC20/extensions/ERC20Permit.sol";
import {AccessControlDefaultAdminRules}
    from "@openzeppelin/contracts/access/extensions/AccessControlDefaultAdminRules.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/// @dev Optional, governance-installed transfer-compliance hook. Reverts to block a transfer/mint/burn.
///      Unset by default (the token is credibly neutral); only a Timelock can install one.
interface IComplianceHook {
    function check(address from, address to, uint256 amount) external view;
}

/// @title WBTX — wrapped BTX (EVM-native, 18 decimals)
/// @notice Canonical wrapped representation of BTX. Built on audited OpenZeppelin v5.6 with the full
///         best-practice set distilled from WBTC, cbBTC, FBTC, Circle FiatToken/USDC and tBTC
///         (contrib/wbtx/SECURITY.md):
///           - ERC20 + ERC20Permit (EIP-2612) + EIP-3009 (transfer/receiveWithAuthorization,
///             cancelAuthorization) — gasless approvals AND gasless transfers / meta-tx (Circle pattern).
///           - AccessControlDefaultAdminRules (2-step + enforced delay on the root admin) with least-
///             privilege roles; mint/burn restricted to the bridge.
///           - Issuance pause (mint/burn) — the backing-safety lever — WITHOUT a holder transfer-freeze
///             (no censorship lever by default; credibly neutral, WBTC stance).
///           - Optional, governance-gated, default-OFF compliance hook (the Circle/cbBTC blacklist
///             capability, made opt-in so neutrality is the default and any censorship power is
///             explicit + Timelock-only).
///           - rescueERC20 (SafeERC20) recovers foreign tokens; can never touch wBTX.
///         Reference implementation — external audit + invariant fuzzing required before mainnet.
///
/// DECIMALS = 18 (DECIDED). wBTX is positioned as an EVM-native asset (the Binance-Peg BTCB model):
///   uniform 18-dec DeFi math and sub-satoshi granularity on the EVM side. 1 BTX satoshi == 1e10 units.
///   Mints are always whole-satoshi multiples (no sub-sat backing is ever created); sub-sat balances
///   arise only from EVM-side division and are backed in aggregate. Redeem rounds DOWN to whole sat and
///   burns the remainder, so dust accrues to the bridge's backing SURPLUS (solvency-positive). L1
///   redemption of sub-sat amounts requires consolidation — a deliberate, coordinated secondary concern.
///   (The wrapped-BTC norm is 8; 18 is the deliberate EVM-native choice here — see SECURITY.md.)
contract WBTX is ERC20, ERC20Permit, AccessControlDefaultAdminRules {
    using SafeERC20 for IERC20;
    using ECDSA for bytes32;

    bytes32 public constant MINTER_ROLE   = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE   = keccak256("BURNER_ROLE");
    bytes32 public constant PAUSER_ROLE   = keccak256("PAUSER_ROLE");   // fast, low-trust trigger
    bytes32 public constant UNPAUSER_ROLE = keccak256("UNPAUSER_ROLE"); // separate / higher-trust
    bytes32 public constant RESCUER_ROLE  = keccak256("RESCUER_ROLE");

    // EIP-3009 typehashes (Circle FiatToken).
    bytes32 public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
    bytes32 public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH =
        keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)");
    bytes32 public constant CANCEL_AUTHORIZATION_TYPEHASH =
        keccak256("CancelAuthorization(address authorizer,bytes32 nonce)");

    /// @dev EIP-3009 random-nonce authorization state: authorizer => nonce => used/canceled.
    mapping(address => mapping(bytes32 => bool)) public authorizationState;

    /// @dev Pauses mint/burn only (not holder transfers).
    bool public issuancePaused;

    /// @dev Optional compliance hook (address(0) => neutral, no checks). Timelock-only.
    IComplianceHook public complianceHook;

    event IssuancePaused(address indexed by);
    event IssuanceUnpaused(address indexed by);
    event Rescued(address indexed token, address indexed to, uint256 amount);
    event ComplianceHookUpdated(address indexed hook);
    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
    event AuthorizationCanceled(address indexed authorizer, bytes32 indexed nonce);

    error IssuanceIsPaused();
    error CannotRescueSelf();
    error AuthInvalid();
    error AuthNotYetValid();
    error AuthExpired();
    error AuthUsedOrCanceled();
    error CallerMustBePayee();

    /// @param admin      DEFAULT_ADMIN (use a Timelock owned by a multisig). 2-step + `adminDelay`.
    /// @param adminDelay enforced delay (seconds) on DEFAULT_ADMIN transfer (e.g. 2 days).
    constructor(address admin, uint48 adminDelay)
        ERC20("Wrapped BTX", "wBTX")
        ERC20Permit("Wrapped BTX")
        AccessControlDefaultAdminRules(adminDelay, admin)
    {}

    function decimals() public pure override returns (uint8) { return 18; }

    // ---- issuance (bridge only) ----

    modifier whenIssuanceNotPaused() { if (issuancePaused) revert IssuanceIsPaused(); _; }

    function mint(address to, uint256 value) external onlyRole(MINTER_ROLE) whenIssuanceNotPaused {
        _mint(to, value);
    }
    function burn(address from, uint256 value) external onlyRole(BURNER_ROLE) whenIssuanceNotPaused {
        _burn(from, value);
    }

    // ---- pause (asymmetric trust: fast to pause, slow to unpause) ----

    function pauseIssuance() external onlyRole(PAUSER_ROLE) { issuancePaused = true; emit IssuancePaused(msg.sender); }
    function unpauseIssuance() external onlyRole(UNPAUSER_ROLE) { issuancePaused = false; emit IssuanceUnpaused(msg.sender); }

    // ---- optional compliance hook (default OFF) ----

    function setComplianceHook(IComplianceHook hook) external onlyRole(DEFAULT_ADMIN_ROLE) {
        complianceHook = hook;
        emit ComplianceHookUpdated(address(hook));
    }

    /// @dev Single transfer/mint/burn chokepoint; consults the compliance hook iff one is installed.
    function _update(address from, address to, uint256 value) internal override {
        IComplianceHook hook = complianceHook;
        if (address(hook) != address(0)) hook.check(from, to, value);
        super._update(from, to, value);
    }

    // ---- rescue foreign tokens (never wBTX itself) ----

    function rescueERC20(IERC20 token, address to, uint256 amount) external onlyRole(RESCUER_ROLE) {
        if (address(token) == address(this)) revert CannotRescueSelf();
        token.safeTransfer(to, amount);
        emit Rescued(address(token), to, amount);
    }

    // ---- EIP-3009: gasless transfers / meta-transactions (random nonces) ----

    /// @notice Execute a transfer signed by `from` (relayer pays gas). Submittable by anyone.
    function transferWithAuthorization(
        address from, address to, uint256 value, uint256 validAfter, uint256 validBefore,
        bytes32 nonce, uint8 v, bytes32 r, bytes32 s
    ) external {
        _checkWindow(validAfter, validBefore);
        _useAuthorization(from, nonce,
            keccak256(abi.encode(TRANSFER_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)),
            v, r, s);
        _transfer(from, to, value);
    }

    /// @notice Like transferWithAuthorization, but ONLY the payee may submit it (front-run safe).
    function receiveWithAuthorization(
        address from, address to, uint256 value, uint256 validAfter, uint256 validBefore,
        bytes32 nonce, uint8 v, bytes32 r, bytes32 s
    ) external {
        if (to != msg.sender) revert CallerMustBePayee();
        _checkWindow(validAfter, validBefore);
        _useAuthorization(from, nonce,
            keccak256(abi.encode(RECEIVE_WITH_AUTHORIZATION_TYPEHASH, from, to, value, validAfter, validBefore, nonce)),
            v, r, s);
        _transfer(from, to, value);
    }

    /// @notice Cancel an unused authorization nonce (signed by the authorizer).
    function cancelAuthorization(address authorizer, bytes32 nonce, uint8 v, bytes32 r, bytes32 s) external {
        if (authorizationState[authorizer][nonce]) revert AuthUsedOrCanceled();
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(CANCEL_AUTHORIZATION_TYPEHASH, authorizer, nonce)));
        if (digest.recover(v, r, s) != authorizer) revert AuthInvalid();
        authorizationState[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    function _checkWindow(uint256 validAfter, uint256 validBefore) private view {
        if (block.timestamp <= validAfter) revert AuthNotYetValid();
        if (block.timestamp >= validBefore) revert AuthExpired();
    }

    function _useAuthorization(address from, bytes32 nonce, bytes32 structHash, uint8 v, bytes32 r, bytes32 s) private {
        if (authorizationState[from][nonce]) revert AuthUsedOrCanceled();
        if (_hashTypedDataV4(structHash).recover(v, r, s) != from) revert AuthInvalid();
        authorizationState[from][nonce] = true;
        emit AuthorizationUsed(from, nonce);
    }
}
