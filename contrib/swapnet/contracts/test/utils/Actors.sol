// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

import "../../SwapNetHTLC.sol";

/// Rejects every ETH transfer.
contract RevertingReceiver {
    receive() external payable { revert("no ETH"); }
}

/// Tries to re-enter the HTLC from its receive hook, then records the outcome.
contract ReentrantReceiver {
    SwapNetHTLC public immutable h;
    bytes public reentryCall;
    bool public reentryOk;
    bytes public reentryRet;
    constructor(SwapNetHTLC h_) { h = h_; }
    function setCall(bytes calldata c) external { reentryCall = c; }
    function withdraw(address token, uint256 amount) external { h.withdrawAmount(token, payable(address(this)), amount); }
    receive() external payable {
        if (reentryCall.length != 0) {
            (reentryOk, reentryRet) = address(h).call(reentryCall);
        }
    }
}

/// A contract funder that can lock and later withdraw its own refund credit.
contract ContractFunder {
    SwapNetHTLC public immutable h;
    constructor(SwapNetHTLC h_) { h = h_; }
    function lock(bytes32 salt, bytes32 hl, address claimTo, uint64 refundAt) external payable returns (bytes32) {
        return h.lockNative{value: msg.value}(salt, hl, claimTo, refundAt);
    }
    function withdrawTo(address payable to) external { h.withdrawTo(address(0), to); }
}

/// Token hook target that tries every state-changing HTLC entry point during a token transfer.
contract TokenReentrancyProbe {
    SwapNetHTLC public immutable h;
    bytes public call_;
    bool public tried;
    bool public succeeded;
    bytes public ret;
    constructor(SwapNetHTLC h_) { h = h_; }
    function arm(bytes calldata c) external { call_ = c; tried = false; succeeded = false; }
    function onToken() external {
        if (call_.length == 0 || tried) return;
        tried = true;
        (succeeded, ret) = address(h).call(call_);
    }
}
