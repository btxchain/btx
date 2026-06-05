// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title WBTXAtomicSwapHTLC — trustless BTX <-> EVM atomic swaps (bridge Model B), hardened.
/// @notice EVM leg of a hash-timelock atomic swap whose hashlock is byte-compatible with BTX's P2MR
///         HTLC leaf: `OP_HASH160` = RIPEMD160(SHA256(preimage)). Both halves are EVM precompiles, so
///         a single 20-byte hashlock secures both chains against the same 32-byte preimage. Revealing
///         the preimage to claim one leg exposes it on-chain for the counterparty to claim the other.
///
/// Trust model: NONE beyond the two chains' consensus. Hardened per contrib/wbtx/SECURITY.md:
///   - SafeERC20 + balance-delta accounting (tolerates non-standard / fee-on-transfer / rebasing tokens).
///   - Swap id derived IN-CONTRACT from (sender, recipient, token, amount, hashlock, timeout, salt) so
///     it cannot be front-run / squatted by a third party (an attacker's different msg.sender yields a
///     different id).
///   - ReentrancyGuard on claim/refund; checks-effects-interactions throughout.
///   - Enforced min/max timeout bounds (sanity). NOTE: cross-chain timeout *asymmetry* (the slow/first
///     leg must have the strictly longer timeout) cannot be enforced on-chain — the SDK/integrator MUST
///     enforce it; see SECURITY.md §HTLC and contrib/wbtx/README.md.
///   UNAUDITED reference.
contract WBTXAtomicSwapHTLC is ReentrancyGuard {
    using SafeERC20 for IERC20;

    enum State { INVALID, OPEN, CLAIMED, REFUNDED }

    struct Swap {
        address token;
        address sender;
        address recipient;
        uint256 amount;     // actual amount custodied (post-transfer balance delta)
        bytes20 hashlock;   // RIPEMD160(SHA256(preimage))
        uint64  timeout;    // unix seconds; refund allowed at/after this
        State   state;
    }

    /// @dev Sanity bounds (NOT the cross-chain asymmetry rule). Tune per deployment.
    uint64 public constant MIN_TIMEOUT = 30 minutes;
    uint64 public constant MAX_TIMEOUT = 30 days;

    mapping(bytes32 => Swap) public swaps;

    event Opened(bytes32 indexed id, address indexed token, address indexed recipient,
                 address sender, uint256 amount, bytes20 hashlock, uint64 timeout);
    event Claimed(bytes32 indexed id, bytes preimage);
    event Refunded(bytes32 indexed id);

    error IdExists();
    error ZeroAddress();
    error ZeroAmount();
    error BadTimeout();
    error NotOpen();
    error BadPreimage();
    error TooEarly();
    error NotSender();
    error NoValueReceived();

    /// @dev BTX-compatible hashlock: RIPEMD160(SHA256(preimage)) (precompiles 0x02 then 0x03).
    function btxHash160(bytes calldata preimage) public pure returns (bytes20) {
        return ripemd160(abi.encodePacked(sha256(preimage)));
    }

    /// @notice Deterministic, squat-proof swap id. Bound to msg.sender so a third party cannot
    ///         pre-register the same logical swap. `salt` disambiguates a sender's identical swaps.
    function computeId(
        address recipient, address token, uint256 amount, bytes20 hashlock, uint64 timeout, bytes32 salt
    ) public view returns (bytes32) {
        return keccak256(abi.encode(
            block.chainid, address(this), msg.sender, recipient, token, amount, hashlock, timeout, salt
        ));
    }

    /// @notice Lock `amount` of `token` to `recipient`, claimable with the preimage of `hashlock`
    ///         until `timeout`. Caller must `approve` first. Returns the derived swap id.
    function open(
        address recipient, address token, uint256 amount, bytes20 hashlock, uint64 timeout, bytes32 salt
    ) external nonReentrant returns (bytes32 id) {
        if (recipient == address(0) || token == address(0)) revert ZeroAddress();
        if (amount == 0) revert ZeroAmount();
        if (timeout < block.timestamp + MIN_TIMEOUT || timeout > block.timestamp + MAX_TIMEOUT) revert BadTimeout();

        id = computeId(recipient, token, amount, hashlock, timeout, salt);
        if (swaps[id].state != State.INVALID) revert IdExists();

        // Balance-delta accounting: custody EXACTLY what arrived (fee-on-transfer/rebasing safe).
        IERC20 t = IERC20(token);
        uint256 before = t.balanceOf(address(this));
        t.safeTransferFrom(msg.sender, address(this), amount);
        uint256 received = t.balanceOf(address(this)) - before;
        if (received == 0) revert NoValueReceived();

        swaps[id] = Swap({
            token: token, sender: msg.sender, recipient: recipient, amount: received,
            hashlock: hashlock, timeout: timeout, state: State.OPEN
        });
        emit Opened(id, token, recipient, msg.sender, received, hashlock, timeout);
    }

    /// @notice Claim with the preimage; reveals it on-chain for the BTX leg.
    function claim(bytes32 id, bytes calldata preimage) external nonReentrant {
        Swap storage s = swaps[id];
        if (s.state != State.OPEN) revert NotOpen();
        if (btxHash160(preimage) != s.hashlock) revert BadPreimage();
        s.state = State.CLAIMED;                              // effects before interaction
        IERC20(s.token).safeTransfer(s.recipient, s.amount);
        emit Claimed(id, preimage);
    }

    /// @notice Refund to the sender at/after timeout if unclaimed.
    function refund(bytes32 id) external nonReentrant {
        Swap storage s = swaps[id];
        if (s.state != State.OPEN) revert NotOpen();
        if (msg.sender != s.sender) revert NotSender();
        if (block.timestamp < s.timeout) revert TooEarly();
        s.state = State.REFUNDED;
        IERC20(s.token).safeTransfer(s.sender, s.amount);
        emit Refunded(id);
    }
}
