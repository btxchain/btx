// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// @notice Native ETH/ERC-20 bilateral swaps. No administrator, proxy, minting,
/// pooled exchange pricing, upgrade, federation, or arbitrary destination changes.
/// @dev Release gates require compilation, adversarial tests and independent review.
contract SwapNetHTLC {
    enum State { Absent, Locked, Claimed, Refunded }
    struct Swap {
        bytes32 hashlock;
        address token;
        address refundTo;
        address claimTo;
        uint256 amount;
        uint64 refundAt;
        State state;
    }
    mapping(bytes32 => Swap) private swaps;
    mapping(address => mapping(address => uint256)) public credits;
    uint256 private entered;
    uint256 public constant MIN_LOCK = 1 hours;
    uint256 public constant MAX_LOCK = 30 days;

    error Reentrant();
    error InvalidTerms();
    error AlreadyExists();
    error NotLocked();
    error InvalidPreimage();
    error TooLate();
    error TooEarly();
    error TransferFailed();
    error UnsupportedToken();
    error NoCredit();

    event Locked(bytes32 indexed id, bytes32 hashlock, address indexed refundTo,
                 address indexed claimTo, address token, uint256 amount, uint64 refundAt);
    event Claimed(bytes32 indexed id, bytes32 preimage);
    event Refunded(bytes32 indexed id);
    event Withdrawn(address indexed owner, address indexed token, address to, uint256 amount);

    modifier nonReentrant() {
        if (entered != 0) revert Reentrant();
        entered = 1;
        _;
        entered = 0;
    }

    function lockNative(bytes32 salt, bytes32 hashlock, address claimTo, uint64 refundAt)
        external payable nonReentrant returns (bytes32 id)
    {
        id = computeId(msg.sender, salt);
        _create(id, hashlock, claimTo, refundAt, address(0), msg.value);
    }

    function lockToken(bytes32 salt, bytes32 hashlock, address claimTo, uint64 refundAt,
                       address token, uint256 amount) external nonReentrant returns (bytes32 id)
    {
        id = computeId(msg.sender, salt);
        if (token == address(0) || token.code.length == 0) revert UnsupportedToken();
        _create(id, hashlock, claimTo, refundAt, token, amount);
        uint256 beforeBalance = _balance(token, address(this));
        _callToken(token, abi.encodeWithSelector(bytes4(0x23b872dd), msg.sender, address(this), amount));
        uint256 afterBalance = _balance(token, address(this));
        if (afterBalance < beforeBalance || afterBalance - beforeBalance != amount) revert UnsupportedToken();
    }

    /// @dev Sender-scoped storage keys prevent third-party salt squatting.
    function computeId(address funder, bytes32 salt) public view returns (bytes32) {
        return keccak256(abi.encode(block.chainid, address(this), funder, salt));
    }

    function _create(bytes32 id, bytes32 hashlock, address claimTo, uint64 refundAt,
                     address token, uint256 amount) internal
    {
        if (id == bytes32(0) || hashlock == bytes32(0) || claimTo == address(0) ||
            claimTo == address(this) || claimTo == msg.sender || amount == 0 ||
            refundAt < block.timestamp + MIN_LOCK || refundAt > block.timestamp + MAX_LOCK)
            revert InvalidTerms();
        if (swaps[id].state != State.Absent) revert AlreadyExists();
        swaps[id] = Swap(hashlock, token, msg.sender, claimTo, amount, refundAt, State.Locked);
        emit Locked(id, hashlock, msg.sender, claimTo, token, amount, refundAt);
    }

    /// @dev Anyone can relay a valid preimage; the payment beneficiary cannot change.
    function claim(bytes32 id, bytes32 preimage) external nonReentrant {
        Swap storage s = swaps[id];
        if (s.state != State.Locked) revert NotLocked();
        if (block.timestamp >= s.refundAt) revert TooLate();
        if (sha256(abi.encodePacked(preimage)) != s.hashlock) revert InvalidPreimage();
        s.state = State.Claimed;
        credits[s.claimTo][s.token] += s.amount;
        emit Claimed(id, preimage);
    }

    /// @dev Anyone may relay an expired refund; credit always goes to original funder.
    function refund(bytes32 id) external nonReentrant {
        Swap storage s = swaps[id];
        if (s.state != State.Locked) revert NotLocked();
        if (block.timestamp < s.refundAt) revert TooEarly();
        s.state = State.Refunded;
        credits[s.refundTo][s.token] += s.amount;
        emit Refunded(id);
    }

    /// @dev Pull payments prevent a reverting recipient from blocking claim/refund.
    /// Token policies must reject rebasing, transfer-tax, upgradeable/unreviewed assets.
    function withdrawTo(address token, address payable to) external nonReentrant {
        _withdraw(token, to, credits[msg.sender][token]);
    }

    /// @dev Exact-amount withdrawals keep independent concurrent swaps separately
    /// accountable even when they share one receiving account.
    function withdrawAmount(address token, address payable to, uint256 amount)
        external nonReentrant
    {
        _withdraw(token, to, amount);
    }

    function _withdraw(address token, address payable to, uint256 amount) internal {
        if (to == address(0) || to == address(this)) revert InvalidTerms();
        uint256 available = credits[msg.sender][token];
        if (amount == 0 || amount > available) revert NoCredit();
        credits[msg.sender][token] = available - amount;
        if (token == address(0)) {
            (bool ok,) = to.call{value: amount}("");
            if (!ok) revert TransferFailed();
        } else {
            uint256 fromBefore = _balance(token, address(this));
            uint256 toBefore = _balance(token, to);
            _callToken(token, abi.encodeWithSelector(bytes4(0xa9059cbb), to, amount));
            uint256 fromAfter = _balance(token, address(this));
            uint256 toAfter = _balance(token, to);
            if (fromAfter > fromBefore || fromBefore - fromAfter != amount ||
                toAfter < toBefore || toAfter - toBefore != amount) revert UnsupportedToken();
        }
        emit Withdrawn(msg.sender, token, to, amount);
    }

    function getSwap(bytes32 id) external view returns
        (bytes32, address, address, address, uint256, uint64, State)
    {
        Swap storage s = swaps[id];
        return (s.hashlock, s.token, s.refundTo, s.claimTo, s.amount, s.refundAt, s.state);
    }

    function _balance(address token, address who) internal view returns (uint256 value) {
        (bool ok, bytes memory result) = token.staticcall(abi.encodeWithSelector(bytes4(0x70a08231), who));
        if (!ok || result.length != 32) revert UnsupportedToken();
        value = abi.decode(result, (uint256));
    }

    function _callToken(address token, bytes memory data) internal {
        (bool ok, bytes memory result) = token.call(data);
        if (!ok || (result.length != 0 && (result.length != 32 || !abi.decode(result, (bool)))))
            revert TransferFailed();
    }
}
