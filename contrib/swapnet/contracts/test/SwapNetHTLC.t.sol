// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;
import "../SwapNetHTLC.sol";
interface Vm {
    function deal(address, uint256) external;
    function prank(address) external;
    function warp(uint256) external;
    function expectRevert(bytes4) external;
}
contract SwapNetHTLCTest {
    Vm constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SwapNetHTLC h;
    address constant ALICE = address(0xA11CE);
    address constant BOB = address(0xB0B);
    bytes32 constant SECRET = bytes32(uint256(42));
    bytes32 constant SALT = bytes32(uint256(1));
    bytes32 ID;
    function setUp() public {
        h = new SwapNetHTLC();
        ID = h.computeId(ALICE, SALT);
        vm.deal(ALICE, 10 ether);
    }
    function fund() internal returns (uint64 deadline) {
        deadline = uint64(block.timestamp + 4 hours);
        // Hash before prank. sha256 is a precompile call and would consume prank,
        // so the lock would be recorded for this contract instead of Alice.
        bytes32 hashlock = sha256(abi.encodePacked(SECRET));
        vm.prank(ALICE);
        h.lockNative{value: 1 ether}(SALT, hashlock, BOB, deadline);
    }
    function testClaimPaysFixedRecipient() public {
        fund();
        h.claim(ID, SECRET); // unrelated relayer cannot steal the credit
        require(h.credits(BOB, address(0)) == 1 ether);
        require(h.credits(address(this), address(0)) == 0);
        vm.prank(BOB);
        h.withdrawTo(address(0), payable(BOB));
        require(BOB.balance == 1 ether);
    }
    function testWrongSecret() public {
        fund();
        vm.expectRevert(SwapNetHTLC.InvalidPreimage.selector);
        h.claim(ID, bytes32(uint256(999)));
    }
    function testRefundTooEarly() public {
        fund();
        vm.expectRevert(SwapNetHTLC.TooEarly.selector);
        h.refund(ID);
    }
    function testRefundAndNoDoubleSpend() public {
        uint64 deadline = fund();
        vm.warp(deadline);
        h.refund(ID);
        require(h.credits(ALICE, address(0)) == 1 ether);
        vm.expectRevert(SwapNetHTLC.NotLocked.selector);
        h.claim(ID, SECRET);
    }
    function testNoClaimAtDeadline() public {
        uint64 deadline = fund(); vm.warp(deadline);
        vm.expectRevert(SwapNetHTLC.TooLate.selector); h.claim(ID, SECRET);
    }
    function testDuplicateIdRejected() public {
        uint64 deadline = fund();
        bytes32 hashlock = sha256(abi.encodePacked(SECRET));
        vm.expectRevert(SwapNetHTLC.AlreadyExists.selector);
        vm.prank(ALICE);
        h.lockNative{value: 1 ether}(SALT, hashlock, BOB, deadline);
    }
    function testFuzzSecret(bytes32 preimage) public {
        bytes32 hashlock = sha256(abi.encodePacked(preimage));
        if (hashlock == bytes32(0)) return;
        vm.prank(ALICE);
        h.lockNative{value: 1 ether}(SALT, hashlock, BOB, uint64(block.timestamp+2 hours));
        h.claim(ID, preimage);
        require(h.credits(BOB,address(0)) == 1 ether);
    }
    function testExactWithdrawalPreservesRemainingCredit() public {
        fund(); h.claim(ID, SECRET);
        vm.prank(BOB); h.withdrawAmount(address(0), payable(BOB), 0.4 ether);
        require(BOB.balance == 0.4 ether);
        require(h.credits(BOB, address(0)) == 0.6 ether);
        vm.prank(BOB); h.withdrawAmount(address(0), payable(BOB), 0.6 ether);
        require(BOB.balance == 1 ether);
    }
    function testWithdrawalCannotExceedCredit() public {
        fund(); h.claim(ID, SECRET);
        vm.prank(BOB); vm.expectRevert(SwapNetHTLC.NoCredit.selector);
        h.withdrawAmount(address(0), payable(BOB), 2 ether);
    }
    function testUnrelatedAccountCannotWithdraw() public {
        fund(); h.claim(ID, SECRET);
        vm.prank(ALICE); vm.expectRevert(SwapNetHTLC.NoCredit.selector);
        h.withdrawAmount(address(0), payable(ALICE), 1 ether);
    }
    function testRefundBeneficiaryCannotBeChangedByRelayer() public {
        uint64 deadline=fund();vm.warp(deadline);h.refund(ID);
        require(h.credits(ALICE,address(0))==1 ether);
        require(h.credits(address(this),address(0))==0);
    }
}
