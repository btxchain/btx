// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WBTX, IComplianceHook} from "../evm/WBTX.sol";
import {WBTXBridge, ECDSAMultisigVerifier, IAttestationVerifier} from "../evm/WBTXBridge.sol";
import {WBTXAtomicSwapHTLC} from "../evm/WBTXAtomicSwapHTLC.sol";
import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract WBTXTest is Test {
    WBTX wbtx;
    WBTXBridge bridge;
    ECDSAMultisigVerifier verifier;

    address admin = address(0xA11CE);
    address gov   = address(0x60F);     // governance (timelock stand-in)
    address guardian = address(0x6A7D);
    address federation = address(0xFED);
    address pauser = address(0x9A05E);
    // three federation signers (sorted ascending by address for the proof)
    uint256 pk1 = 0xA11; uint256 pk2 = 0xB22; uint256 pk3 = 0xC33;
    bytes32 constant DEFAULT_BTX_BLOCK_HASH = keccak256("btx-block");
    uint64 constant DEFAULT_BTX_BLOCK_HEIGHT = 1_000_000;
    uint64 constant DEFAULT_ATTESTED_HEIGHT = DEFAULT_BTX_BLOCK_HEIGHT + 150;
    uint256 constant DEFAULT_MAX_SUPPLY_WBTX = type(uint256).max;
    uint64 constant DEFAULT_WINDOW_CAP_SAT = 2_100_000_000_000_000;
    uint64 constant DEFAULT_WINDOW_DURATION = 1 days;
    uint64 constant DEFAULT_OPTIMISTIC_THRESHOLD_SAT = 2_100_000_000_000_000;
    uint64 constant DEFAULT_GUARDIAN_DELAY = 6 hours;
    uint64 constant DEFAULT_REDEEM_REFUND_TIMEOUT = 7 days;
    uint48 constant BRIDGE_ADMIN_DELAY = 1 days;

    function _initialSignersSorted() internal view returns (address[] memory signers) {
        signers = new address[](3);
        signers[0] = vm.addr(pk1);
        signers[1] = vm.addr(pk2);
        signers[2] = vm.addr(pk3);
        for (uint256 i = 1; i < signers.length; i++) {
            address key = signers[i];
            uint256 j = i;
            while (j > 0 && signers[j - 1] > key) {
                signers[j] = signers[j - 1];
                unchecked { --j; }
            }
            signers[j] = key;
        }
    }

    function setUp() public {
        address[] memory signers = _initialSignersSorted();
        verifier = new ECDSAMultisigVerifier(admin, 0, signers, 2); // 2-of-3
        uint256 deployerNonce = vm.getNonce(address(this));
        address predictedBridge = vm.computeCreateAddress(address(this), deployerNonce + 1);
        wbtx = new WBTX(admin, 0, predictedBridge);
        bridge = new WBTXBridge(wbtx, IAttestationVerifier(address(verifier)), 1, admin, BRIDGE_ADMIN_DELAY);

        vm.startPrank(admin);
        wbtx.grantRole(wbtx.PAUSER_ROLE(), pauser);
        wbtx.grantRole(wbtx.UNPAUSER_ROLE(), admin);
        bridge.grantRole(bridge.GOVERNANCE_ROLE(), gov);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), guardian);
        bridge.grantRole(bridge.PAUSER_ROLE(), pauser);
        bridge.grantRole(bridge.FEDERATION_ROLE(), federation);
        verifier.grantRole(verifier.GUARDIAN_ROLE(), guardian);
        vm.stopPrank();

        vm.prank(gov);
        bridge.setLimits(
            DEFAULT_MAX_SUPPLY_WBTX,
            DEFAULT_WINDOW_CAP_SAT,
            DEFAULT_WINDOW_DURATION,
            DEFAULT_OPTIMISTIC_THRESHOLD_SAT,
            DEFAULT_GUARDIAN_DELAY,
            DEFAULT_REDEEM_REFUND_TIMEOUT
        );
    }

    // --- helpers ---

    function _futureDeadline() internal view returns (uint64) {
        return uint64(block.timestamp + 1 days);
    }

    function _proofForDigest(bytes32 digest) internal view returns (bytes memory) {
        // sign with pk1 and pk2, then order by recovered address ascending
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(pk1, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(pk2, digest);
        bytes memory sigA = abi.encodePacked(r1, s1, v1);
        bytes memory sigB = abi.encodePacked(r2, s2, v2);
        bytes[] memory sigs = new bytes[](2);
        if (vm.addr(pk1) < vm.addr(pk2)) {
            sigs[0] = sigA;
            sigs[1] = sigB;
        } else {
            sigs[0] = sigB;
            sigs[1] = sigA;
        }
        return abi.encode(sigs);
    }

    function _attestFor(
        WBTXBridge targetBridge,
        bytes32 txid,
        uint32 vout,
        bytes32 btxBlockHash,
        uint64 btxBlockHeight,
        uint64 attestedHeight,
        address to,
        uint64 amtSat,
        uint64 deadline
    ) internal view returns (bytes memory) {
        bytes32 digest = targetBridge.mintDigest(
            targetBridge.bridgeId(),
            txid,
            vout,
            btxBlockHash,
            btxBlockHeight,
            attestedHeight,
            to,
            amtSat,
            deadline
        );
        return _proofForDigest(digest);
    }

    function _attest(
        bytes32 txid,
        uint32 vout,
        bytes32 btxBlockHash,
        uint64 btxBlockHeight,
        uint64 attestedHeight,
        address to,
        uint64 amtSat,
        uint64 deadline
    ) internal view returns (bytes memory) {
        return _attestFor(bridge, txid, vout, btxBlockHash, btxBlockHeight, attestedHeight, to, amtSat, deadline);
    }

    function _attestFulfill(
        uint256 redeemId,
        bytes32 btxTxid,
        bytes32 destHash,
        uint64 amountSat,
        uint64 btxBlockHeight,
        uint64 attestedHeight,
        uint64 deadline
    ) internal view returns (bytes memory) {
        bytes32 digest = bridge.fulfillDigest(
            bridge.bridgeId(),
            redeemId,
            btxTxid,
            destHash,
            amountSat,
            btxBlockHeight,
            attestedHeight,
            deadline
        );
        return _proofForDigest(digest);
    }

    function _attestNonRelease(
        uint256 redeemId,
        bytes32 destHash,
        uint64 amountSat,
        uint64 asOfBtxHeight,
        uint64 deadline
    ) internal view returns (bytes memory) {
        bytes32 digest = bridge.nonReleaseDigest(
            bridge.bridgeId(),
            redeemId,
            destHash,
            amountSat,
            asOfBtxHeight,
            deadline
        );
        return _proofForDigest(digest);
    }

    // --- mint ---

    function test_MintHappyPath() public {
        bytes32 txid = keccak256("dep1");
        uint64 deadline = _futureDeadline();
        bytes memory proof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 100_000_000, deadline
        ); // 1 BTX
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 100_000_000, deadline, proof
        );
        assertEq(wbtx.balanceOf(address(0xBEEF)), 100_000_000 * 1e10);
        assertEq(wbtx.totalSupply(), 1e18);
    }

    function test_Mint_RevertsWhenTooShallow() public {
        bytes32 txid = keccak256("dep1-shallow");
        uint64 deadline = _futureDeadline();
        uint64 shallowAttestedHeight = DEFAULT_BTX_BLOCK_HEIGHT + 99;
        bytes memory proof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, shallowAttestedHeight, address(0xBEEF), 1_000, deadline
        );
        vm.expectRevert(WBTXBridge.TooShallow.selector);
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, shallowAttestedHeight, address(0xBEEF), 1_000, deadline, proof
        );
    }

    function test_Mint_RevertsWhenExpired() public {
        bytes32 txid = keccak256("dep1-expired");
        uint64 expiredDeadline = uint64(block.timestamp - 1);
        bytes memory proof = _attest(
            txid,
            0,
            DEFAULT_BTX_BLOCK_HASH,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            address(0xBEEF),
            1_000,
            expiredDeadline
        );
        vm.expectRevert(WBTXBridge.AttestationExpired.selector);
        bridge.mint(
            txid,
            0,
            DEFAULT_BTX_BLOCK_HASH,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            address(0xBEEF),
            1_000,
            expiredDeadline,
            proof
        );
    }

    function test_Mint_RevertsWhenNotAttested() public {
        bytes32 txid = keccak256("dep1-not-attested");
        uint64 deadline = _futureDeadline();
        uint64 unattestedHeight = DEFAULT_BTX_BLOCK_HEIGHT - 1;
        bytes memory proof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, unattestedHeight, address(0xBEEF), 1_000, deadline
        );
        vm.expectRevert(WBTXBridge.NotAttested.selector);
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, unattestedHeight, address(0xBEEF), 1_000, deadline, proof
        );
    }

    function test_OutpointReplayRejected() public {
        bytes32 txid = keccak256("dep2");
        uint64 deadline = _futureDeadline();
        bytes memory proof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 1_000, deadline
        );
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 1_000, deadline, proof
        );
        vm.expectRevert(WBTXBridge.AlreadyMinted.selector);
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 1_000, deadline, proof
        );
    }

    function test_EIP712Replay_WrongRecipientRejected() public {
        bytes32 txid = keccak256("dep3");
        uint64 deadline = _futureDeadline();
        bytes memory proof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 1_000, deadline
        ); // signed for 0xBEEF
        vm.expectRevert();
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xDEAD), 1_000, deadline, proof
        ); // try to redirect
    }

    function test_BelowThresholdRejected() public {
        bytes32 txid = keccak256("dep4");
        uint64 deadline = _futureDeadline();
        bytes32 digest = bridge.mintDigest(
            bridge.bridgeId(),
            txid,
            0,
            DEFAULT_BTX_BLOCK_HASH,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            address(0xBEEF),
            1_000,
            deadline
        );
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(pk1, digest);
        bytes[] memory sigs = new bytes[](1);
        sigs[0] = abi.encodePacked(r1, s1, v1);
        vm.expectRevert(WBTXBridge.BadAttestation.selector);
        bridge.mint(
            txid,
            0,
            DEFAULT_BTX_BLOCK_HASH,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            address(0xBEEF),
            1_000,
            deadline,
            abi.encode(sigs)
        ); // 1-of-3 < threshold 2
    }

    // --- circuit breaker + guardian veto ---

    function test_WindowCapEnforced() public {
        vm.prank(gov);
        bridge.setLimits(type(uint256).max, 50_000, 1 hours, 50_000, 6 hours, 7 days); // queue mints > 50k sat
        bytes32 txid = keccak256("dep5");
        uint64 deadline = _futureDeadline();
        bytes memory proof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 60_000, deadline
        );
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 60_000, deadline, proof
        );
        vm.warp(block.timestamp + 7 hours);
        vm.expectRevert(WBTXBridge.WindowCapExceeded.selector);
        bridge.executeQueuedMint(txid, 0);
    }

    function test_GuardianVetoFlow() public {
        vm.prank(gov);
        bridge.setLimits(type(uint256).max, 1_000_000, 1 hours, 100_000, 6 hours, 7 days); // queue mints > 100k sat
        bytes32 txid = keccak256("dep6");
        uint64 deadline = _futureDeadline();
        bytes memory proof = _attest(
            txid, 7, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 500_000, deadline
        );
        bridge.mint(
            txid, 7, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 500_000, deadline, proof
        ); // queued, not minted
        assertEq(wbtx.balanceOf(address(0xBEEF)), 0);
        // too early
        vm.expectRevert(WBTXBridge.TooEarly.selector);
        bridge.executeQueuedMint(txid, 7);
        // guardian cancels
        vm.prank(guardian);
        bridge.cancelQueuedMint(txid, 7);
        vm.warp(block.timestamp + 2 hours);
        vm.expectRevert(WBTXBridge.NotQueued.selector);
        bridge.executeQueuedMint(txid, 7);
        assertEq(wbtx.balanceOf(address(0xBEEF)), 0);              // never minted
    }

    function test_GuardianQueueExecutesAfterDelay() public {
        vm.prank(gov);
        bridge.setLimits(type(uint256).max, 1_000_000, 1 hours, 100_000, 6 hours, 7 days);
        bytes32 txid = keccak256("dep7");
        uint64 deadline = _futureDeadline();
        bytes memory proof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 500_000, deadline
        );
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 500_000, deadline, proof
        );
        vm.warp(block.timestamp + 7 hours);
        bridge.executeQueuedMint(txid, 0);
        assertEq(wbtx.balanceOf(address(0xBEEF)), 500_000 * 1e10);
    }

    function test_ClearVeto_Timelocked() public {
        vm.prank(gov);
        bridge.setLimits(type(uint256).max, 1_000_000, 1 hours, 100_000, 6 hours, 7 days);

        bytes32 txid = keccak256("veto-race");
        uint32 vout = 9;
        uint64 amountSat = 500_000;
        uint64 deadline = _futureDeadline();
        bytes memory proof = _attest(
            txid, vout, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), amountSat, deadline
        );

        bridge.mint(
            txid, vout, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), amountSat, deadline, proof
        );
        vm.prank(guardian);
        bridge.cancelQueuedMint(txid, vout);

        bytes32 dk = bridge.depositKey(txid, vout);
        assertTrue(bridge.vetoed(dk));
        vm.expectRevert(WBTXBridge.Vetoed.selector);
        bridge.mint(
            txid, vout, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), amountSat, deadline, proof
        );

        vm.prank(gov);
        bridge.proposeClearVeto(dk);
        assertTrue(bridge.vetoed(dk));
        vm.expectRevert(WBTXBridge.ClearVetoNotReady.selector);
        bridge.applyClearVeto(dk);
        vm.warp(block.timestamp + bridge.CLEAR_VETO_DELAY());
        bridge.applyClearVeto(dk);
        assertFalse(bridge.vetoed(dk));
    }

    function test_Window_NoBoundaryBurst() public {
        vm.prank(gov);
        bridge.setLimits(type(uint256).max, 1_000, 100, 1_000, 6 hours, 7 days);

        vm.warp(block.timestamp + 99);
        uint64 deadline = _futureDeadline();

        bytes32 txid1 = keccak256("boundary-1");
        bytes memory proof1 = _attest(
            txid1, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 990, deadline
        );
        bridge.mint(
            txid1, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 990, deadline, proof1
        );

        vm.warp(block.timestamp + 1);
        bytes32 txid2 = keccak256("boundary-2");
        bytes memory proof2 = _attest(
            txid2, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 20, deadline
        );
        bridge.mint(
            txid2, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 20, deadline, proof2
        );

        bytes32 txid3 = keccak256("boundary-3");
        bytes memory proof3 = _attest(
            txid3, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 1, deadline
        );
        vm.expectRevert(WBTXBridge.WindowCapExceeded.selector);
        bridge.mint(
            txid3, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 1, deadline, proof3
        );
    }

    function test_Window_QueueReservesNothing() public {
        vm.prank(gov);
        bridge.setLimits(type(uint256).max, 1_000, 100, 500, 6 hours, 7 days);

        uint64 deadline = _futureDeadline();
        bytes32 queuedTxid = keccak256("queue-reserve-1");
        bytes memory queuedProof = _attest(
            queuedTxid, 3, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 900, deadline
        );
        bridge.mint(
            queuedTxid, 3, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 900, deadline, queuedProof
        );
        assertEq(bridge.availableSat(), 1_000);

        vm.prank(guardian);
        bridge.cancelQueuedMint(queuedTxid, 3);
        assertEq(bridge.availableSat(), 1_000);

        bytes32 fullCapTxid = keccak256("queue-reserve-2");
        bytes memory fullCapProof = _attest(
            fullCapTxid, 4, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 1_000, deadline
        );
        bridge.mint(
            fullCapTxid, 4, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 1_000, deadline, fullCapProof
        );
        vm.warp(block.timestamp + 7 hours);
        bridge.executeQueuedMint(fullCapTxid, 4);
        assertEq(wbtx.balanceOf(address(0xBEEF)), 1_000 * 1e10);
        assertEq(bridge.availableSat(), 0);
    }

    function test_Mint_RevertsWhenNotConfigured() public {
        address[] memory signers = _initialSignersSorted();
        ECDSAMultisigVerifier verifier2 = new ECDSAMultisigVerifier(admin, 0, signers, 2);
        uint256 deployerNonce = vm.getNonce(address(this));
        address predictedBridge2 = vm.computeCreateAddress(address(this), deployerNonce + 1);
        WBTX wbtx2 = new WBTX(admin, 0, predictedBridge2);
        WBTXBridge bridge2 = new WBTXBridge(wbtx2, IAttestationVerifier(address(verifier2)), 1, admin, BRIDGE_ADMIN_DELAY);

        vm.startPrank(admin);
        bridge2.grantRole(bridge2.GOVERNANCE_ROLE(), gov);
        vm.stopPrank();

        bytes32 txid = keccak256("dep-not-configured");
        uint64 deadline = _futureDeadline();
        bytes memory proof = _attestFor(
            bridge2, txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 1_000, deadline
        );

        vm.expectRevert(WBTXBridge.NotConfigured.selector);
        bridge2.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 1_000, deadline, proof
        );

        vm.prank(gov);
        vm.expectRevert(WBTXBridge.ZeroBreakerValue.selector);
        bridge2.setLimits(0, 1, 1, 1, 1, 7 days);
    }

    // --- redeem ---

    function test_RedeemRoundDownAndRefund() public {
        bytes32 txid = keccak256("dep8");
        uint64 deadline = _futureDeadline();
        bytes memory proof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 200_000_000, deadline
        ); // mint 2 BTX
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 200_000_000, deadline, proof
        );
        // redeem 1 BTX + 0.5 sat dust -> releases 100000000 sat (rounded down), burns the full amount
        uint256 amt = 100_000_000 * 1e10 + 5e9;
        bytes memory destination = hex"00aabb";
        wbtx.approve(address(bridge), amt);
        uint256 id = bridge.redeem(amt, destination);
        assertEq(wbtx.totalSupply(), 2e18 - amt);                  // full burn incl dust
        (, uint64 sat, , , , bytes32 destHash, , bool fulfilled, ) = bridge.redeems(id);
        assertEq(sat, 100_000_000);                                // rounded down
        assertEq(destHash, keccak256(destination));
        assertEq(fulfilled, false);
        // refund after timeout needs an attested non-release statement.
        vm.warp(block.timestamp + 8 days);
        uint64 asOfBtxHeight = DEFAULT_ATTESTED_HEIGHT + 10;
        uint64 refundDeadline = _futureDeadline();
        bytes memory nonReleaseProof = _attestNonRelease(id, destHash, sat, asOfBtxHeight, refundDeadline);
        vm.prank(gov);
        bridge.refundRedeem(id, asOfBtxHeight, refundDeadline, nonReleaseProof);
        assertEq(wbtx.balanceOf(address(this)), 2e18);             // made whole
    }

    function test_FulfillRedeem_RequiresAttestationAndDepth() public {
        bytes32 txid = keccak256("redeem-fulfill-setup");
        uint64 mintDeadline = _futureDeadline();
        bytes memory mintProof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 200_000_000, mintDeadline
        );
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 200_000_000, mintDeadline, mintProof
        );

        uint256 redeemAmount = 100_000_000 * 1e10;
        bytes memory destination = hex"1122aabb";
        wbtx.approve(address(bridge), redeemAmount);
        uint256 redeemId = bridge.redeem(redeemAmount, destination);
        (, uint64 amountSat, , , , bytes32 destHash, , , ) = bridge.redeems(redeemId);

        bytes32 btxTxid = keccak256("release-txid-1");
        uint64 fulfillDeadline = _futureDeadline();
        uint64 shallowAttestedHeight = DEFAULT_BTX_BLOCK_HEIGHT + 99;
        bytes memory shallowProof = _attestFulfill(
            redeemId,
            btxTxid,
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            shallowAttestedHeight,
            fulfillDeadline
        );
        vm.prank(federation);
        vm.expectRevert(WBTXBridge.TooShallow.selector);
        bridge.fulfillRedeem(
            redeemId,
            btxTxid,
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            shallowAttestedHeight,
            fulfillDeadline,
            shallowProof
        );

        bytes memory forgedProof = _attestFulfill(
            redeemId,
            keccak256("different-release"),
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline
        );
        vm.prank(federation);
        vm.expectRevert(WBTXBridge.BadAttestation.selector);
        bridge.fulfillRedeem(
            redeemId,
            btxTxid,
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline,
            forgedProof
        );

        bytes memory validProof = _attestFulfill(
            redeemId,
            btxTxid,
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline
        );
        vm.prank(federation);
        bridge.fulfillRedeem(
            redeemId,
            btxTxid,
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline,
            validProof
        );
        (, , , , uint64 fulfilledAt, , bytes32 storedTxid, bool fulfilled, ) = bridge.redeems(redeemId);
        assertTrue(fulfilled);
        assertGt(fulfilledAt, 0);
        assertEq(storedTxid, btxTxid);
    }

    function test_Fulfill_RejectsZeroTxid() public {
        bytes32 txid = keccak256("redeem-fulfill-zero-txid");
        uint64 mintDeadline = _futureDeadline();
        bytes memory mintProof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000_000, mintDeadline
        );
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000_000, mintDeadline, mintProof
        );

        uint256 redeemAmount = 10_000 * 1e10;
        bytes memory destination = hex"77aabb";
        wbtx.approve(address(bridge), redeemAmount);
        uint256 redeemId = bridge.redeem(redeemAmount, destination);
        (, uint64 amountSat, , , , bytes32 destHash, , , ) = bridge.redeems(redeemId);

        uint64 fulfillDeadline = _futureDeadline();
        bytes memory proof = _attestFulfill(
            redeemId,
            bytes32(0),
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline
        );

        vm.prank(federation);
        vm.expectRevert(WBTXBridge.BadAttestation.selector);
        bridge.fulfillRedeem(
            redeemId,
            bytes32(0),
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline,
            proof
        );
    }

    function test_Fulfill_RejectsRevoked() public {
        bytes32 txid = keccak256("redeem-fulfill-revoked");
        uint64 mintDeadline = _futureDeadline();
        bytes memory mintProof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000_000, mintDeadline
        );
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000_000, mintDeadline, mintProof
        );

        uint256 redeemAmount = 20_000 * 1e10;
        bytes memory destination = hex"88aabb";
        wbtx.approve(address(bridge), redeemAmount);
        uint256 redeemId = bridge.redeem(redeemAmount, destination);
        (, uint64 amountSat, , , , bytes32 destHash, , , ) = bridge.redeems(redeemId);

        bytes32 releaseTxid = keccak256("release-revoked");
        uint64 fulfillDeadline = _futureDeadline();
        bytes memory fulfillProof = _attestFulfill(
            redeemId,
            releaseTxid,
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline
        );
        vm.prank(federation);
        bridge.fulfillRedeem(
            redeemId,
            releaseTxid,
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline,
            fulfillProof
        );

        vm.prank(guardian);
        bridge.unfulfillRedeem(redeemId);
        assertTrue(bridge.fulfillmentRevoked(redeemId));

        bytes memory refillProof = _attestFulfill(
            redeemId,
            keccak256("release-retry"),
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline
        );
        vm.prank(federation);
        vm.expectRevert(WBTXBridge.FulfillmentPermanentlyRevoked.selector);
        bridge.fulfillRedeem(
            redeemId,
            keccak256("release-retry"),
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline,
            refillProof
        );
    }

    function test_Refund_FulfilledRedeem_WithNonRelease() public {
        bytes32 txid = keccak256("refund-fulfilled-nonrelease");
        uint64 mintDeadline = _futureDeadline();
        bytes memory mintProof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000_000, mintDeadline
        );
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000_000, mintDeadline, mintProof
        );

        uint256 redeemAmount = 50_000_000 * 1e10;
        bytes memory destination = hex"abcd";
        wbtx.approve(address(bridge), redeemAmount);
        uint256 redeemId = bridge.redeem(redeemAmount, destination);
        (, uint64 amountSat, , , , bytes32 destHash, , , ) = bridge.redeems(redeemId);

        bytes32 releaseTxid = keccak256("fulfilled-before-refund");
        uint64 fulfillDeadline = _futureDeadline();
        bytes memory fulfillProof = _attestFulfill(
            redeemId,
            releaseTxid,
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline
        );
        vm.prank(federation);
        bridge.fulfillRedeem(
            redeemId,
            releaseTxid,
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline,
            fulfillProof
        );

        vm.warp(block.timestamp + 8 days);
        uint64 asOfBtxHeight = DEFAULT_ATTESTED_HEIGHT + 15;
        uint64 refundDeadline = _futureDeadline();
        bytes memory nonReleaseProof = _attestNonRelease(redeemId, destHash, amountSat, asOfBtxHeight, refundDeadline);
        vm.prank(gov);
        bridge.refundRedeem(redeemId, asOfBtxHeight, refundDeadline, nonReleaseProof);

        (, , , , uint64 fulfilledAt, , bytes32 storedTxid, bool fulfilled, bool refunded) = bridge.redeems(redeemId);
        assertFalse(fulfilled);
        assertTrue(refunded);
        assertEq(fulfilledAt, 0);
        assertEq(storedTxid, bytes32(0));
        assertFalse(fulfilled && refunded);
        assertEq(wbtx.balanceOf(address(this)), 100_000_000 * 1e10);
    }

    function test_UnfulfillRedeem_ReopensRefund() public {
        bytes32 txid = keccak256("redeem-unfulfill-setup");
        uint64 mintDeadline = _futureDeadline();
        bytes memory mintProof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000_000, mintDeadline
        );
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000_000, mintDeadline, mintProof
        );

        uint256 redeemAmount = 100_000_000 * 1e10;
        bytes memory destination = hex"99aabb";
        wbtx.approve(address(bridge), redeemAmount);
        uint256 redeemId = bridge.redeem(redeemAmount, destination);
        (, uint64 amountSat, , , , bytes32 destHash, , , ) = bridge.redeems(redeemId);

        bytes32 releaseTxid = keccak256("release-txid-2");
        uint64 fulfillDeadline = _futureDeadline();
        bytes memory fulfillProof = _attestFulfill(
            redeemId,
            releaseTxid,
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline
        );
        vm.prank(federation);
        bridge.fulfillRedeem(
            redeemId,
            releaseTxid,
            destHash,
            amountSat,
            DEFAULT_BTX_BLOCK_HEIGHT,
            DEFAULT_ATTESTED_HEIGHT,
            fulfillDeadline,
            fulfillProof
        );

        vm.prank(guardian);
        bridge.unfulfillRedeem(redeemId);
        (, , , , uint64 fulfilledAt, , bytes32 storedTxid, bool fulfilled, ) = bridge.redeems(redeemId);
        assertFalse(fulfilled);
        assertEq(fulfilledAt, 0);
        assertEq(storedTxid, bytes32(0));

        vm.warp(block.timestamp + 8 days);
        uint64 asOfBtxHeight = DEFAULT_ATTESTED_HEIGHT + 20;
        uint64 refundDeadline = _futureDeadline();
        bytes memory nonReleaseProof = _attestNonRelease(redeemId, destHash, amountSat, asOfBtxHeight, refundDeadline);
        vm.prank(gov);
        bridge.refundRedeem(redeemId, asOfBtxHeight, refundDeadline, nonReleaseProof);
        assertEq(wbtx.balanceOf(address(this)), redeemAmount);
    }

    function test_RefundRedeem_RequiresNonReleaseAttestation() public {
        bytes32 txid = keccak256("redeem-non-release-required");
        uint64 mintDeadline = _futureDeadline();
        bytes memory mintProof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000_000, mintDeadline
        );
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000_000, mintDeadline, mintProof
        );

        uint256 redeemAmount = 10_000 * 1e10;
        bytes memory destination = hex"44aabb";
        wbtx.approve(address(bridge), redeemAmount);
        uint256 redeemId = bridge.redeem(redeemAmount, destination);
        (, uint64 amountSat, , , , bytes32 destHash, , , ) = bridge.redeems(redeemId);

        vm.warp(block.timestamp + 8 days);
        uint64 asOfBtxHeight = DEFAULT_ATTESTED_HEIGHT + 5;
        uint64 refundDeadline = _futureDeadline();
        bytes memory forgedProof = _attestNonRelease(redeemId, destHash, amountSat, asOfBtxHeight + 1, refundDeadline);

        vm.prank(gov);
        vm.expectRevert(WBTXBridge.BadAttestation.selector);
        bridge.refundRedeem(redeemId, asOfBtxHeight, refundDeadline, forgedProof);
    }

    function test_RefundRedeem_RoutesThroughSupplyCap() public {
        bytes32 txid = keccak256("redeem-refund-cap-setup");
        uint64 mintDeadline = _futureDeadline();
        bytes memory mintProof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000, mintDeadline
        );
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000, mintDeadline, mintProof
        );

        uint256 redeemAmount = 100_000 * 1e10;
        bytes memory destination = hex"55aabb";
        wbtx.approve(address(bridge), redeemAmount);
        uint256 redeemId = bridge.redeem(redeemAmount, destination);
        (, uint64 amountSat, , , , bytes32 destHash, , , ) = bridge.redeems(redeemId);
        vm.warp(block.timestamp + 8 days);

        uint64 asOfBtxHeight = DEFAULT_ATTESTED_HEIGHT + 7;
        uint64 refundDeadline = _futureDeadline();
        bytes memory nonReleaseProof = _attestNonRelease(redeemId, destHash, amountSat, asOfBtxHeight, refundDeadline);

        vm.prank(gov);
        bridge.setLimits(type(uint256).max, amountSat - 1, 1 days, amountSat - 1, DEFAULT_GUARDIAN_DELAY, 7 days);
        vm.prank(gov);
        vm.expectRevert(WBTXBridge.WindowCapExceeded.selector);
        bridge.refundRedeem(redeemId, asOfBtxHeight, refundDeadline, nonReleaseProof);

        vm.prank(gov);
        bridge.setLimits(redeemAmount - 1, amountSat, 1 days, amountSat, DEFAULT_GUARDIAN_DELAY, 7 days);
        vm.warp(block.timestamp + 1);
        vm.prank(gov);
        vm.expectRevert(WBTXBridge.SupplyCapExceeded.selector);
        bridge.refundRedeem(redeemId, asOfBtxHeight, refundDeadline, nonReleaseProof);

        vm.prank(gov);
        bridge.setLimits(redeemAmount, amountSat, 1 days, amountSat, DEFAULT_GUARDIAN_DELAY, 7 days);
        bytes32 refundKey = keccak256(abi.encodePacked("redeem-refund", redeemId));
        vm.expectEmit(true, true, false, true, address(bridge));
        emit WBTXBridge.MintExecuted(refundKey, bytes32(0), 0, address(this), amountSat, redeemAmount);
        vm.prank(gov);
        bridge.refundRedeem(redeemId, asOfBtxHeight, refundDeadline, nonReleaseProof);
        assertEq(wbtx.balanceOf(address(this)), redeemAmount);
    }

    function test_RefundRedeem_WorksWhileIssuancePaused() public {
        bytes32 txid = keccak256("redeem-refund-paused");
        uint64 mintDeadline = _futureDeadline();
        bytes memory mintProof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000_000, mintDeadline
        );
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 100_000_000, mintDeadline, mintProof
        );

        uint256 redeemAmount = 25_000_000 * 1e10;
        bytes memory destination = hex"66aabb";
        wbtx.approve(address(bridge), redeemAmount);
        uint256 redeemId = bridge.redeem(redeemAmount, destination);
        (, uint64 amountSat, , , , bytes32 destHash, , , ) = bridge.redeems(redeemId);
        vm.warp(block.timestamp + 8 days);

        vm.prank(pauser);
        wbtx.pauseIssuance();

        uint64 asOfBtxHeight = DEFAULT_ATTESTED_HEIGHT + 11;
        uint64 refundDeadline = _futureDeadline();
        bytes memory nonReleaseProof = _attestNonRelease(redeemId, destHash, amountSat, asOfBtxHeight, refundDeadline);
        vm.prank(gov);
        bridge.refundRedeem(redeemId, asOfBtxHeight, refundDeadline, nonReleaseProof);
        assertEq(wbtx.balanceOf(address(this)), 100_000_000 * 1e10);
    }

    // --- token roles / rescue / pause ---

    function test_OnlyBridgeMints() public {
        vm.expectRevert(WBTX.NotBridge.selector);
        wbtx.mint(address(this), 1);

        vm.prank(address(bridge));
        wbtx.mint(address(this), 1);
        assertEq(wbtx.balanceOf(address(this)), 1);
    }

    function test_BurnRequiresAllowance() public {
        address aliceUser = address(0xA71CE);
        address bobUser = address(0xB0B1);
        address spender = address(0xD00D);

        vm.prank(address(bridge));
        wbtx.mint(aliceUser, 10e18);
        vm.prank(address(bridge));
        wbtx.mint(bobUser, 5e18);

        vm.prank(address(bridge));
        vm.expectRevert();
        wbtx.burn(aliceUser, 1e18);

        vm.prank(spender);
        vm.expectRevert();
        wbtx.burnFrom(aliceUser, 1e18);

        vm.prank(aliceUser);
        wbtx.approve(address(bridge), 2e18);
        vm.prank(address(bridge));
        wbtx.burn(aliceUser, 2e18);
        assertEq(wbtx.balanceOf(aliceUser), 8e18);

        vm.prank(aliceUser);
        wbtx.approve(spender, 1e18);
        vm.prank(spender);
        wbtx.burnFrom(aliceUser, 1e18);
        assertEq(wbtx.balanceOf(aliceUser), 7e18);

        vm.prank(address(bridge));
        vm.expectRevert();
        wbtx.burn(bobUser, 1e18);
        assertEq(wbtx.balanceOf(bobUser), 5e18);
    }

    function test_ComplianceHook_ExcludesIssuance() public {
        bytes32 txid1 = keccak256("hook-issuance-1");
        uint64 deadline1 = _futureDeadline();
        bytes memory proof1 = _attest(
            txid1, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 2_000, deadline1
        );
        bridge.mint(
            txid1, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 2_000, deadline1, proof1
        );

        MockRevertingHook badHook = new MockRevertingHook();
        vm.prank(admin);
        wbtx.setComplianceHook(badHook);

        wbtx.transfer(address(0xBEEF), 1_000 * 1e10);

        bytes32 txid2 = keccak256("hook-issuance-2");
        uint64 deadline2 = _futureDeadline();
        bytes memory proof2 = _attest(
            txid2, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 1_000, deadline2
        );
        bridge.mint(
            txid2, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 1_000, deadline2, proof2
        );

        uint256 redeemAmount = 500 * 1e10;
        wbtx.approve(address(bridge), redeemAmount);
        uint256 redeemId = bridge.redeem(redeemAmount, hex"00aabb");
        assertGt(redeemId, 0);
    }

    function test_ComplianceHook_CannotBrick() public {
        vm.prank(address(bridge));
        wbtx.mint(address(this), 5e18);

        MockRevertingHook revertingHook = new MockRevertingHook();
        vm.prank(admin);
        wbtx.setComplianceHook(revertingHook);
        wbtx.transfer(address(0xBEEF), 1e18);
        assertEq(wbtx.balanceOf(address(0xBEEF)), 1e18);

        MockGasBurningHook gasBurningHook = new MockGasBurningHook();
        vm.prank(admin);
        wbtx.setComplianceHook(gasBurningHook);
        wbtx.transfer(address(0xCAFE), 1e18);
        assertEq(wbtx.balanceOf(address(0xCAFE)), 1e18);
    }

    function test_ClearComplianceHook() public {
        MockRevertingHook badHook = new MockRevertingHook();
        vm.prank(admin);
        wbtx.setComplianceHook(badHook);
        assertTrue(address(wbtx.complianceHook()) != address(0));

        vm.prank(pauser);
        wbtx.clearComplianceHook();
        assertEq(address(wbtx.complianceHook()), address(0));
    }

    function test_MintRefund_WorksWhilePaused() public {
        vm.prank(pauser);
        wbtx.pauseIssuance();

        vm.prank(address(bridge));
        wbtx.mintRefund(address(this), 123);
        assertEq(wbtx.balanceOf(address(this)), 123);

        vm.expectRevert(WBTX.NotBridge.selector);
        wbtx.mintRefund(address(this), 1);
    }

    function test_IssuancePauseBlocksMint() public {
        vm.prank(pauser);
        wbtx.pauseIssuance();
        bytes32 txid = keccak256("dep9");
        uint64 deadline = _futureDeadline();
        bytes memory proof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 1_000, deadline
        );
        vm.expectRevert(WBTX.IssuanceIsPaused.selector);
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), 1_000, deadline, proof
        );
    }

    function test_RescueCannotTouchSelf() public {
        bytes32 rescuer = wbtx.RESCUER_ROLE();                      // cache (avoid consuming the prank)
        vm.startPrank(admin);
        wbtx.grantRole(rescuer, admin);
        vm.expectRevert(WBTX.CannotRescueSelf.selector);
        wbtx.rescueERC20(IERC20(address(wbtx)), admin, 0);
        vm.stopPrank();
    }

    function test_VerifierGovernanceGated() public {
        vm.expectRevert();
        bridge.proposeVerifier(IAttestationVerifier(address(verifier)));  // not GOVERNANCE_ROLE
    }

    function test_SetVerifier_Timelocked() public {
        MockVerifier next = new MockVerifier(true);
        vm.prank(gov);
        bridge.proposeVerifier(IAttestationVerifier(address(next)));

        assertEq(address(bridge.verifier()), address(verifier));
        vm.expectRevert(WBTXBridge.VerifierNotReady.selector);
        bridge.applyVerifier();

        vm.warp(block.timestamp + bridge.VERIFIER_DELAY());
        bridge.applyVerifier();
        assertEq(address(bridge.verifier()), address(next));

        vm.prank(gov);
        vm.expectRevert(WBTXBridge.VerifierNotContract.selector);
        bridge.proposeVerifier(IAttestationVerifier(address(0)));

        vm.prank(gov);
        vm.expectRevert(WBTXBridge.VerifierNotContract.selector);
        bridge.proposeVerifier(IAttestationVerifier(address(0xBEEF)));
    }

    function test_CancelPendingVerifier() public {
        MockVerifier next = new MockVerifier(true);
        vm.prank(gov);
        bridge.proposeVerifier(IAttestationVerifier(address(next)));
        vm.prank(guardian);
        bridge.cancelPendingVerifier();

        vm.warp(block.timestamp + bridge.VERIFIER_DELAY());
        vm.expectRevert(WBTXBridge.VerifierNotReady.selector);
        bridge.applyVerifier();
        assertEq(address(bridge.verifier()), address(verifier));
    }

    function test_RotateSigners_Timelocked() public {
        address[] memory nextSigners = new address[](2);
        nextSigners[0] = address(0x1111);
        nextSigners[1] = address(0x2222);

        vm.prank(admin);
        verifier.proposeRotation(nextSigners, 1);
        assertEq(verifier.threshold(), 2);
        vm.expectRevert(ECDSAMultisigVerifier.RotationNotReady.selector);
        verifier.applyRotation();

        vm.warp(block.timestamp + verifier.ROTATION_DELAY());
        verifier.applyRotation();
        assertEq(verifier.threshold(), 1);
        assertTrue(verifier.isSigner(nextSigners[0]));
        assertTrue(verifier.isSigner(nextSigners[1]));
        assertFalse(verifier.isSigner(vm.addr(pk1)));

        address[] memory cancelledSigners = new address[](2);
        cancelledSigners[0] = address(0x3333);
        cancelledSigners[1] = address(0x4444);
        vm.prank(admin);
        verifier.proposeRotation(cancelledSigners, 1);
        vm.prank(guardian);
        verifier.cancelPendingRotation();
        vm.warp(block.timestamp + verifier.ROTATION_DELAY());
        vm.expectRevert(ECDSAMultisigVerifier.RotationNotReady.selector);
        verifier.applyRotation();
    }

    function test_SetLimits_RejectsLowGuardianDelay() public {
        vm.startPrank(gov);
        uint64 tooLowGuardianDelay = bridge.MIN_GUARDIAN_DELAY() - 1;
        vm.expectRevert(WBTXBridge.GuardianDelayTooLow.selector);
        bridge.setLimits(type(uint256).max, 1_000_000, 1 hours, 100_000, tooLowGuardianDelay, 7 days);
        vm.stopPrank();
    }

    function test_SetLimits_RejectsThresholdAboveWindow() public {
        vm.startPrank(gov);
        vm.expectRevert(WBTXBridge.ThresholdAboveWindowCap.selector);
        bridge.setLimits(type(uint256).max, 100_000, 1 hours, 100_001, 6 hours, 7 days);
        vm.stopPrank();
    }

    function test_GranularPause() public {
        bytes32 txid = keccak256("gp");
        uint64 deadline = _futureDeadline();
        bytes memory proof = _attest(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 1_000, deadline
        );
        vm.prank(pauser); bridge.setMintPaused(true);
        vm.expectRevert(WBTXBridge.MintPaused.selector);
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 1_000, deadline, proof
        ); // mint blocked
        vm.prank(gov); bridge.setMintPaused(false);
        bridge.mint(
            txid, 0, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(this), 1_000, deadline, proof
        ); // mint works again
        vm.prank(pauser); bridge.setRedeemPaused(true);
        vm.expectRevert(WBTXBridge.RedeemPaused.selector);
        bridge.redeem(1_000 * 1e10, hex"00aa");                     // redeem blocked independently
    }

    // backing relation: minting `amountSat` yields exactly amountSat*1e10 wBTX (no phantom supply).
    function testFuzz_BackingRelation(uint64 amountSat) public {
        amountSat = uint64(bound(amountSat, 1, 2_100_000_000_000_000)); // up to 21M BTX in sat
        bytes32 txid = keccak256(abi.encode("fuzz", amountSat));
        uint64 deadline = _futureDeadline();
        bytes memory proof = _attest(
            txid, 3, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), amountSat, deadline
        );
        bridge.mint(
            txid, 3, DEFAULT_BTX_BLOCK_HASH, DEFAULT_BTX_BLOCK_HEIGHT, DEFAULT_ATTESTED_HEIGHT, address(0xBEEF), amountSat, deadline, proof
        );
        assertEq(wbtx.totalSupply(), uint256(amountSat) * 1e10);
        assertEq(wbtx.balanceOf(address(0xBEEF)), wbtx.totalSupply());
    }
}

contract MockVerifier is IAttestationVerifier {
    bool public immutable allow;

    constructor(bool allow_) {
        allow = allow_;
    }

    function verifyMint(bytes32, bytes calldata) external view returns (bool) {
        return allow;
    }

    function verifyFulfill(bytes32, bytes calldata) external view returns (bool) {
        return allow;
    }

    function verifyNonRelease(bytes32, bytes calldata) external view returns (bool) {
        return allow;
    }
}

contract MockRevertingHook is IComplianceHook {
    function check(address, address, uint256) external pure {
        revert("hook-revert");
    }
}

contract MockGasBurningHook is IComplianceHook {
    function check(address, address, uint256) external pure {
        while (true) {}
    }
}

contract MockBlockHook is IComplianceHook {
    address public blocked;
    constructor(address b) { blocked = b; }
    function check(address from, address to, uint256) external view {
        require(from != blocked && to != blocked, "blocked");
    }
}

contract WBTXTokenTest is Test {
    WBTX wbtx;
    address admin = address(0xA11CE);
    uint256 alicePk = 0xA11CE5;
    address alice;
    address bob = address(0xB0B);

    function setUp() public {
        alice = vm.addr(alicePk);
        wbtx = new WBTX(admin, 0, admin);
        vm.prank(admin);
        wbtx.mint(alice, 1000e18);
    }

    function _digest(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", wbtx.DOMAIN_SEPARATOR(), structHash));
    }

    function test_EIP3009Transfer_AndReplayRejected() public {
        uint256 vb = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("n1");
        bytes32 sh = keccak256(abi.encode(wbtx.TRANSFER_WITH_AUTHORIZATION_TYPEHASH(), alice, bob, 10e18, uint256(0), vb, nonce));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, _digest(sh));
        wbtx.transferWithAuthorization(alice, bob, 10e18, 0, vb, nonce, v, r, s); // relayer submits
        assertEq(wbtx.balanceOf(bob), 10e18);
        vm.expectRevert(WBTX.AuthUsedOrCanceled.selector);
        wbtx.transferWithAuthorization(alice, bob, 10e18, 0, vb, nonce, v, r, s); // replay
    }

    function test_EIP3009Receive_OnlyPayee() public {
        uint256 vb = block.timestamp + 1 hours;
        bytes32 nonce = keccak256("n2");
        bytes32 sh = keccak256(abi.encode(wbtx.RECEIVE_WITH_AUTHORIZATION_TYPEHASH(), alice, bob, 5e18, uint256(0), vb, nonce));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, _digest(sh));
        vm.expectRevert(WBTX.CallerMustBePayee.selector);
        wbtx.receiveWithAuthorization(alice, bob, 5e18, 0, vb, nonce, v, r, s); // wrong caller (this)
        vm.prank(bob);
        wbtx.receiveWithAuthorization(alice, bob, 5e18, 0, vb, nonce, v, r, s); // payee submits
        assertEq(wbtx.balanceOf(bob), 5e18);
    }

    function test_ComplianceHookFailOpen() public {
        MockBlockHook hook = new MockBlockHook(bob);
        vm.prank(admin);
        wbtx.setComplianceHook(hook);
        vm.prank(alice);
        wbtx.transfer(bob, 1e18);
        assertEq(wbtx.balanceOf(bob), 1e18);
        vm.prank(admin);
        wbtx.setComplianceHook(IComplianceHook(address(0)));
        vm.prank(admin);
        vm.expectRevert(WBTX.BadComplianceHook.selector);
        wbtx.setComplianceHook(IComplianceHook(address(0xBEEF)));
    }

    function test_Permit() public {
        uint256 deadline = block.timestamp + 1 hours;
        bytes32 sh = keccak256(abi.encode(
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"),
            alice, bob, 7e18, wbtx.nonces(alice), deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(alicePk, _digest(sh));
        wbtx.permit(alice, bob, 7e18, deadline, v, r, s);
        assertEq(wbtx.allowance(alice, bob), 7e18);
    }
}

contract HTLCTest is Test {
    WBTXAtomicSwapHTLC htlc;
    WBTX token;
    address admin = address(0xA11CE);
    address alice = address(0xA11);   // funds the swap
    address bob   = address(0xB0B);   // claims with preimage

    function setUp() public {
        htlc = new WBTXAtomicSwapHTLC();
        token = new WBTX(admin, 0, admin);
        vm.prank(admin);
        token.mint(alice, 1000e18);
    }

    function test_HashDomainMatchesBTX() public view {
        // BTX OP_HASH160 of 0x42*32 (verified against a BTX node) == 8739f40e...566981
        bytes memory pre = new bytes(32);
        for (uint i; i < 32; i++) pre[i] = 0x42;
        assertEq(htlc.btxHash160(pre), bytes20(hex"8739f40ec4dbf569dcb38134c6e7310908566981"));
    }

    function test_ClaimWithPreimage() public {
        bytes memory pre = new bytes(32);
        for (uint i; i < 32; i++) pre[i] = 0x42;
        bytes20 h = htlc.btxHash160(pre);
        vm.startPrank(alice);
        token.approve(address(htlc), 100e18);
        bytes32 id = htlc.open(bob, address(token), 100e18, h, uint64(block.timestamp + 7 hours), bytes32("s"));
        vm.stopPrank();
        vm.prank(bob);
        htlc.claim(id, pre);
        assertEq(token.balanceOf(bob), 100e18);
    }

    function test_RefundAfterTimeout() public {
        bytes20 h = bytes20(hex"8739f40ec4dbf569dcb38134c6e7310908566981");
        vm.startPrank(alice);
        token.approve(address(htlc), 100e18);
        bytes32 id = htlc.open(bob, address(token), 100e18, h, uint64(block.timestamp + 7 hours), bytes32("s"));
        vm.stopPrank();
        vm.warp(block.timestamp + 8 hours);
        vm.prank(address(0xCA11AB1E));
        htlc.refund(id);
        assertEq(token.balanceOf(alice), 1000e18);
    }

    function test_ClaimRevertsWhenExpired() public {
        bytes memory pre = new bytes(32);
        for (uint i; i < 32; i++) pre[i] = 0x42;
        bytes20 h = htlc.btxHash160(pre);

        vm.startPrank(alice);
        token.approve(address(htlc), 100e18);
        bytes32 id = htlc.open(bob, address(token), 100e18, h, uint64(block.timestamp + 7 hours), bytes32("s-expired"));
        vm.stopPrank();

        vm.warp(block.timestamp + 8 hours);
        vm.prank(bob);
        vm.expectRevert(WBTXAtomicSwapHTLC.Expired.selector);
        htlc.claim(id, pre);
    }

    function test_RefundAfterTimeoutAllowsThirdParty() public {
        bytes20 h = bytes20(hex"8739f40ec4dbf569dcb38134c6e7310908566981");
        vm.startPrank(alice);
        token.approve(address(htlc), 100e18);
        bytes32 id = htlc.open(bob, address(token), 100e18, h, uint64(block.timestamp + 7 hours), bytes32("s-watchtower"));
        vm.stopPrank();

        vm.warp(block.timestamp + 8 hours);
        address watchtower = address(0xC0FFEE);
        vm.prank(watchtower);
        htlc.refund(id);
        assertEq(token.balanceOf(alice), 1000e18);
        assertEq(token.balanceOf(bob), 0);
    }

    function test_OpenRevertsOnFeeOnTransferUnderfunding() public {
        MockFeeOnTransferToken feeToken = new MockFeeOnTransferToken(100); // 1%
        feeToken.mint(alice, 1000e18);

        bytes memory pre = new bytes(32);
        for (uint i; i < 32; i++) pre[i] = 0x42;
        bytes20 h = htlc.btxHash160(pre);

        vm.startPrank(alice);
        feeToken.approve(address(htlc), 100e18);
        vm.expectRevert(abi.encodeWithSelector(WBTXAtomicSwapHTLC.AmountMismatch.selector, 100e18, 99e18));
        htlc.open(bob, address(feeToken), 100e18, h, uint64(block.timestamp + 7 hours), bytes32("s-fee"));
        vm.stopPrank();
    }
}

contract MockFeeOnTransferToken is ERC20 {
    uint256 public immutable feeBps;

    constructor(uint256 feeBps_) ERC20("Fee Token", "FEE") {
        feeBps = feeBps_;
    }

    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }

    function transfer(address to, uint256 amount) public override returns (bool) {
        address owner = _msgSender();
        uint256 fee = (amount * feeBps) / 10_000;
        uint256 net = amount - fee;
        _transfer(owner, to, net);
        if (fee > 0) _transfer(owner, address(0xDEAD), fee);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) public override returns (bool) {
        _spendAllowance(from, _msgSender(), amount);
        uint256 fee = (amount * feeBps) / 10_000;
        uint256 net = amount - fee;
        _transfer(from, to, net);
        if (fee > 0) _transfer(from, address(0xDEAD), fee);
        return true;
    }
}
