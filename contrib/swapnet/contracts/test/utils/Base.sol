// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Minimal cheatcode interface so the suite runs offline with no library checkout,
/// like the original SwapNetHTLC.t.sol.
interface Vm {
    struct Log { bytes32[] topics; bytes data; address emitter; }
    function deal(address, uint256) external;
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function warp(uint256) external;
    function chainId(uint256) external;
    function etch(address, bytes calldata) external;
    function load(address, bytes32) external view returns (bytes32);
    function assume(bool) external pure;
    function label(address, string calldata) external;
    function expectRevert(bytes4) external;
    function expectRevert(bytes calldata) external;
    function expectRevert() external;
    function expectEmit(bool, bool, bool, bool, address) external;
    function recordLogs() external;
    function getRecordedLogs() external returns (Log[] memory);
    function snapshotState() external returns (uint256);
    function revertToState(uint256) external returns (bool);
}

abstract contract Base {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));

    function eq(uint256 a, uint256 b, string memory m) internal pure { if (a != b) revert(string.concat(m, ": uint mismatch")); }
    function eq(bytes32 a, bytes32 b, string memory m) internal pure { if (a != b) revert(string.concat(m, ": bytes32 mismatch")); }
    function eq(address a, address b, string memory m) internal pure { if (a != b) revert(string.concat(m, ": address mismatch")); }
    function ok(bool c, string memory m) internal pure { if (!c) revert(m); }

    function bound(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (hi <= lo) return lo;
        return lo + (x % (hi - lo + 1));
    }
}
