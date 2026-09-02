// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {WBTX} from "../evm/WBTX.sol";
import {WBTXBridge, ECDSAMultisigVerifier, IAttestationVerifier} from "../evm/WBTXBridge.sol";

contract WBTXInvariantHandler is Test {
    struct MintRequest {
        bytes32 txid;
        uint32 vout;
        bytes32 dk;
        uint64 btxBlockHeight;
        uint64 attestedHeight;
        uint64 deadline;
        address to;
        uint64 amountSat;
    }

    WBTX public immutable wbtx;
    WBTXBridge public immutable bridge;

    address public immutable gov;
    address public immutable guardian;
    address public immutable federation;
    address public immutable pauser;
    address public immutable unpauser;

    uint256 public constant SAT_SCALE = 1e10;
    bytes32 internal constant DEFAULT_BTX_BLOCK_HASH = keccak256("invariant-btx-block");
    uint64 internal constant DEFAULT_BTX_BLOCK_HEIGHT = 1_000_000;

    uint256 public ghost_attestedInSat;
    uint256 public ghost_redeemedWbtx;
    uint256 public ghost_refundedSat;
    uint256 public ghost_refundedWbtx;

    uint256 private _depositNonce;
    uint256 private _redeemCursor;

    uint256 private immutable _pk1;
    uint256 private immutable _pk2;
    uint256 private immutable _pk3;
    address private immutable _signer1;
    address private immutable _signer2;
    address private immutable _signer3;

    address[] private _actors;
    bytes32[] private _knownDepositKeys;
    uint256[] private _knownRedeemIds;

    mapping(bytes32 => bool) public ghost_seenDepositKey;
    mapping(bytes32 => uint8) public ghost_mintSuccessCount;
    mapping(bytes32 => bool) public ghost_vetoedByGuardian;
    mapping(uint256 => bool) public ghost_knownRedeem;
    mapping(uint256 => bool) public ghost_refundCounted;

    constructor(
        WBTX wbtx_,
        WBTXBridge bridge_,
        address gov_,
        address guardian_,
        address federation_,
        address pauser_,
        address unpauser_,
        uint256 pk1_,
        uint256 pk2_,
        uint256 pk3_
    ) {
        wbtx = wbtx_;
        bridge = bridge_;
        gov = gov_;
        guardian = guardian_;
        federation = federation_;
        pauser = pauser_;
        unpauser = unpauser_;
        _pk1 = pk1_;
        _pk2 = pk2_;
        _pk3 = pk3_;
        _signer1 = vm.addr(pk1_);
        _signer2 = vm.addr(pk2_);
        _signer3 = vm.addr(pk3_);

        _actors.push(address(0xBEEF));
        _actors.push(address(0xCAFE));
        _actors.push(address(0xD00D));
        _actors.push(address(0xF00D));
    }

    // ---------------- fuzzer-callable actions ----------------

    function mintValid(uint256 seed, uint64 amountSatRaw) external {
        if (bridge.mintPaused() || wbtx.issuancePaused()) return;

        uint64 threshold = bridge.optimisticThresholdSat();
        if (threshold <= 1) return;

        MintRequest memory req = _buildMintRequest(
            seed,
            uint64(bound(amountSatRaw, 1, threshold)),
            "mint",
            10_000,
            2_000,
            1 days
        );
        _mintWithValidAttestation(req);
        _recordMintSuccess(req.dk, req.amountSat);
    }

    function queueThenCancel(uint256 seed, uint64 amountSatRaw) external {
        if (bridge.mintPaused() || wbtx.issuancePaused()) return;

        uint64 threshold = bridge.optimisticThresholdSat();
        uint64 cap = bridge.windowMintCapSat();
        if (cap <= threshold + 1) return;

        uint64 upper = cap > threshold + 500_000 ? threshold + 500_000 : cap;
        if (upper <= threshold) return;
        MintRequest memory req = _buildMintRequest(
            seed,
            uint64(bound(amountSatRaw, threshold + 1, upper)),
            "queue-cancel",
            20_000,
            500,
            2 days
        );
        vm.assume(req.amountSat > threshold);
        _mintWithValidAttestation(req);

        vm.prank(guardian);
        bridge.cancelQueuedMint(req.txid, req.vout);
        ghost_vetoedByGuardian[req.dk] = true;
    }

    function queueThenExecute(uint256 seed, uint64 amountSatRaw, uint32 warpSecondsRaw) external {
        if (bridge.mintPaused() || wbtx.issuancePaused()) return;

        uint64 threshold = bridge.optimisticThresholdSat();
        uint64 cap = bridge.windowMintCapSat();
        if (cap <= threshold + 1) return;

        uint64 upper = cap > threshold + 500_000 ? threshold + 500_000 : cap;
        if (upper <= threshold) return;
        MintRequest memory req = _buildMintRequest(
            seed,
            uint64(bound(amountSatRaw, threshold + 1, upper)),
            "queue-exec",
            20_000,
            700,
            2 days
        );
        vm.assume(req.amountSat > threshold);
        _mintWithValidAttestation(req);

        uint64 minWarp = bridge.guardianDelay() + 1;
        uint64 delta = uint64(bound(warpSecondsRaw, minWarp, minWarp + 2 days));
        vm.warp(block.timestamp + delta);

        bridge.executeQueuedMint(req.txid, req.vout);
        _recordMintSuccess(req.dk, req.amountSat);
    }

    function redeem(uint256 seed, uint256 amountWbtxRaw) external {
        if (wbtx.issuancePaused() || bridge.redeemPaused()) return;

        address actor = _pickActor(seed);
        uint256 bal = wbtx.balanceOf(actor);
        if (bal < SAT_SCALE) return;

        uint256 amount = bound(amountWbtxRaw, SAT_SCALE, bal);
        bytes memory destination = abi.encodePacked(bytes1(0x01), actor, seed);
        vm.assume(destination.length <= 128);

        vm.startPrank(actor);
        wbtx.approve(address(bridge), amount);
        uint256 redeemId = bridge.redeem(amount, destination);
        vm.stopPrank();

        ghost_redeemedWbtx += amount;
        _registerRedeemId(redeemId);
    }

    function fulfill(uint256 redeemSeed, uint256 txSeed) external {
        uint256 redeemId = _pickKnownRedeem(redeemSeed);
        if (redeemId == 0) return;

        (
            address from,
            uint64 amountSat,
            ,
            ,
            ,
            bytes32 destHash,
            ,
            bool fulfilled,
            bool refunded
        ) = bridge.redeems(redeemId);
        if (from == address(0) || fulfilled || refunded) return;

        uint64 btxBlockHeight = DEFAULT_BTX_BLOCK_HEIGHT + uint64(txSeed % 10_000);
        uint64 attestedHeight = btxBlockHeight + bridge.MIN_CONFIRMATIONS() + 120;
        uint64 deadline = uint64(block.timestamp + 1 days);
        bytes32 btxTxid = keccak256(abi.encodePacked("fulfill", redeemId, txSeed));
        bytes memory proof = _attestFulfill(redeemId, btxTxid, destHash, amountSat, btxBlockHeight, attestedHeight, deadline);

        vm.prank(federation);
        bridge.fulfillRedeem(redeemId, btxTxid, destHash, amountSat, btxBlockHeight, attestedHeight, deadline, proof);
    }

    function unfulfill(uint256 redeemSeed) external {
        uint256 redeemId = _pickKnownRedeem(redeemSeed);
        if (redeemId == 0) return;

        (
            address from,
            ,
            ,
            ,
            uint64 fulfilledAt,
            ,
            ,
            bool fulfilled,
            bool refunded
        ) = bridge.redeems(redeemId);
        if (from == address(0) || !fulfilled || refunded) return;

        if (block.timestamp > fulfilledAt + bridge.FULFILL_REVOKE_WINDOW()) return;
        vm.prank(guardian);
        bridge.unfulfillRedeem(redeemId);
    }

    function refund(uint256 redeemSeed, uint32 extraWarpRaw, uint64 asOfSeed) external {
        uint256 redeemId = _pickKnownRedeem(redeemSeed);
        if (redeemId == 0) return;

        (
            address from,
            uint64 amountSat,
            uint256 amountWbtx,
            uint64 requestedAt,
            ,
            bytes32 destHash,
            ,
            bool fulfilled,
            bool refunded
        ) = bridge.redeems(redeemId);
        if (from == address(0) || fulfilled || refunded) return;

        uint64 timeout = bridge.redeemRefundTimeout();
        uint64 readyAt = requestedAt + timeout + 1;
        if (block.timestamp < readyAt) {
            uint64 extra = uint64(bound(extraWarpRaw, 0, 2 days));
            vm.warp(readyAt + extra);
        }

        uint64 asOfBtxHeight = DEFAULT_BTX_BLOCK_HEIGHT + uint64(bound(asOfSeed, 1, 1_000_000));
        uint64 deadline = uint64(block.timestamp + 1 days);
        bytes memory proof = _attestNonRelease(redeemId, destHash, amountSat, asOfBtxHeight, deadline);

        vm.prank(gov);
        bridge.refundRedeem(redeemId, asOfBtxHeight, deadline, proof);

        if (!ghost_refundCounted[redeemId]) {
            ghost_refundedSat += amountSat;
            ghost_refundedWbtx += amountWbtx;
            ghost_refundCounted[redeemId] = true;
        }
    }

    function pauseIssuance() external {
        vm.prank(pauser);
        wbtx.pauseIssuance();
    }

    function unpauseIssuance() external {
        vm.prank(unpauser);
        wbtx.unpauseIssuance();
    }

    function setMintPaused(bool paused) external {
        vm.prank(paused ? pauser : gov);
        bridge.setMintPaused(paused);
    }

    function setRedeemPaused(bool paused) external {
        vm.prank(paused ? pauser : gov);
        bridge.setRedeemPaused(paused);
    }

    function warp(uint32 dtRaw) external {
        uint64 dt = uint64(bound(dtRaw, 1, 3 days));
        vm.warp(block.timestamp + dt);
    }

    // ---------------- invariant introspection ----------------

    function knownDepositKeysLength() external view returns (uint256) {
        return _knownDepositKeys.length;
    }

    function knownDepositKeyAt(uint256 index) external view returns (bytes32) {
        return _knownDepositKeys[index];
    }

    function knownRedeemIdsLength() external view returns (uint256) {
        return _knownRedeemIds.length;
    }

    function knownRedeemIdAt(uint256 index) external view returns (uint256) {
        return _knownRedeemIds[index];
    }

    // ---------------- internal helpers ----------------

    function _buildMintRequest(
        uint256 seed,
        uint64 amountSat,
        bytes32 tag,
        uint64 heightModulus,
        uint64 depthExtra,
        uint64 deadlineOffset
    ) private returns (MintRequest memory req) {
        (req.txid, req.vout, req.dk) = _freshDeposit(seed, tag);
        req.amountSat = amountSat;
        req.btxBlockHeight = DEFAULT_BTX_BLOCK_HEIGHT + uint64(seed % heightModulus);
        req.attestedHeight = req.btxBlockHeight + bridge.MIN_CONFIRMATIONS() + depthExtra;
        req.deadline = uint64(block.timestamp + deadlineOffset);
        req.to = _pickActor(seed);
    }

    function _mintWithValidAttestation(MintRequest memory req) private {
        bytes memory proof = _attestMint(
            req.txid,
            req.vout,
            req.btxBlockHeight,
            req.attestedHeight,
            req.to,
            req.amountSat,
            req.deadline
        );
        bridge.mint(
            req.txid,
            req.vout,
            DEFAULT_BTX_BLOCK_HASH,
            req.btxBlockHeight,
            req.attestedHeight,
            req.to,
            req.amountSat,
            req.deadline,
            proof
        );
    }

    function _registerDeposit(bytes32 dk) private {
        if (!ghost_seenDepositKey[dk]) {
            ghost_seenDepositKey[dk] = true;
            _knownDepositKeys.push(dk);
        }
    }

    function _registerRedeemId(uint256 redeemId) private {
        if (!ghost_knownRedeem[redeemId]) {
            ghost_knownRedeem[redeemId] = true;
            _knownRedeemIds.push(redeemId);
        }
    }

    function _recordMintSuccess(bytes32 dk, uint64 amountSat) private {
        _registerDeposit(dk);
        ghost_mintSuccessCount[dk] += 1;
        ghost_attestedInSat += amountSat;
    }

    function _pickActor(uint256 seed) private view returns (address) {
        return _actors[seed % _actors.length];
    }

    function _pickKnownRedeem(uint256 seed) private returns (uint256) {
        uint256 len = _knownRedeemIds.length;
        if (len == 0) return 0;

        uint256 start = (_redeemCursor + seed) % len;
        for (uint256 i = 0; i < len; i++) {
            uint256 idx = (start + i) % len;
            uint256 id = _knownRedeemIds[idx];
            if (id != 0) {
                _redeemCursor = idx + 1;
                return id;
            }
        }
        return 0;
    }

    function _freshDeposit(uint256 seed, bytes32 tag) private returns (bytes32 txid, uint32 vout, bytes32 dk) {
        _depositNonce++;
        txid = keccak256(abi.encodePacked(tag, seed, _depositNonce, block.timestamp));
        vout = uint32(seed);
        dk = bridge.depositKey(txid, vout);
        (, , , bool queuedExists) = bridge.queued(dk);
        vm.assume(!bridge.minted(dk));
        vm.assume(!queuedExists);
        vm.assume(!bridge.vetoed(dk));
        _registerDeposit(dk);
    }

    function _proofForDigest(bytes32 digest) private view returns (bytes memory) {
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(_pk1, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(_pk2, digest);

        bytes memory sigA = abi.encodePacked(r1, s1, v1);
        bytes memory sigB = abi.encodePacked(r2, s2, v2);
        bytes[] memory sigs = new bytes[](2);

        // Deterministic, sorted 2-of-3 proof using two fixed known signers.
        _storeSortedPair(sigs, _signer1, sigA, _signer2, sigB);
        return abi.encode(sigs);
    }

    function _storeSortedPair(
        bytes[] memory sigs,
        address signerA,
        bytes memory sigA,
        address signerB,
        bytes memory sigB
    ) private pure {
        if (signerA < signerB) {
            sigs[0] = sigA;
            sigs[1] = sigB;
        } else {
            sigs[0] = sigB;
            sigs[1] = sigA;
        }
    }

    function _attestMint(
        bytes32 txid,
        uint32 vout,
        uint64 btxBlockHeight,
        uint64 attestedHeight,
        address to,
        uint64 amountSat,
        uint64 deadline
    ) private view returns (bytes memory) {
        bytes32 digest = bridge.mintDigest(
            bridge.bridgeId(),
            txid,
            vout,
            DEFAULT_BTX_BLOCK_HASH,
            btxBlockHeight,
            attestedHeight,
            to,
            amountSat,
            deadline
        );
        return _proofForDigest(digest);
    }

    function _attestFulfill(
        uint256 redeemId,
        bytes32 btxTxid,
        bytes32 destHash,
        uint64 amountSat,
        uint64 btxBlockHeight,
        uint64 attestedHeight,
        uint64 deadline
    ) private view returns (bytes memory) {
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
    ) private view returns (bytes memory) {
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
}

contract WBTXInvariantTest is Test {
    WBTX internal wbtx;
    WBTXBridge internal bridge;
    ECDSAMultisigVerifier internal verifier;
    WBTXInvariantHandler internal handler;

    address internal constant ADMIN = address(0xA11CE);
    address internal constant GOV = address(0x60F);
    address internal constant GUARDIAN = address(0x6A7D);
    address internal constant FEDERATION = address(0xFED);
    address internal constant PAUSER = address(0x9A05E);

    uint256 internal constant PK1 = 0xA11;
    uint256 internal constant PK2 = 0xB22;
    uint256 internal constant PK3 = 0xC33;
    uint256 internal constant SAT_SCALE = 1e10;

    uint256 internal constant MAX_SUPPLY_WBTX = 5_000_000_000 * SAT_SCALE;
    uint64 internal constant WINDOW_MINT_CAP_SAT = 3_000_000;
    uint64 internal constant WINDOW_DURATION = 1 days;
    uint64 internal constant OPTIMISTIC_THRESHOLD_SAT = 1_000_000;
    uint64 internal constant GUARDIAN_DELAY = 6 hours;
    uint64 internal constant REDEEM_REFUND_TIMEOUT = 7 days;
    uint48 internal constant BRIDGE_ADMIN_DELAY = 1 days;

    /// forge-config: default.invariant.runs = 256
    /// forge-config: default.invariant.depth = 32
    /// forge-config: default.invariant.fail-on-revert = false
    function setUp() public {
        address[] memory signers = _initialSignersSorted();
        verifier = new ECDSAMultisigVerifier(ADMIN, 0, signers, 2);

        uint256 deployerNonce = vm.getNonce(address(this));
        address predictedBridge = vm.computeCreateAddress(address(this), deployerNonce + 1);
        wbtx = new WBTX(ADMIN, 0, predictedBridge);
        bridge = new WBTXBridge(wbtx, IAttestationVerifier(address(verifier)), 1, ADMIN, BRIDGE_ADMIN_DELAY);

        vm.startPrank(ADMIN);
        wbtx.grantRole(wbtx.PAUSER_ROLE(), PAUSER);
        wbtx.grantRole(wbtx.UNPAUSER_ROLE(), ADMIN);
        bridge.grantRole(bridge.GOVERNANCE_ROLE(), GOV);
        bridge.grantRole(bridge.GUARDIAN_ROLE(), GUARDIAN);
        bridge.grantRole(bridge.PAUSER_ROLE(), PAUSER);
        bridge.grantRole(bridge.FEDERATION_ROLE(), FEDERATION);
        verifier.grantRole(verifier.GUARDIAN_ROLE(), GUARDIAN);
        vm.stopPrank();

        vm.prank(GOV);
        bridge.setLimits(
            MAX_SUPPLY_WBTX,
            WINDOW_MINT_CAP_SAT,
            WINDOW_DURATION,
            OPTIMISTIC_THRESHOLD_SAT,
            GUARDIAN_DELAY,
            REDEEM_REFUND_TIMEOUT
        );

        handler = new WBTXInvariantHandler(
            wbtx,
            bridge,
            GOV,
            GUARDIAN,
            FEDERATION,
            PAUSER,
            ADMIN,
            PK1,
            PK2,
            PK3
        );

        targetContract(address(handler));
    }

    function invariant_Solvency() public view {
        uint256 attestedWbtx = handler.ghost_attestedInSat() * SAT_SCALE;
        uint256 redeemedWbtx = handler.ghost_redeemedWbtx();
        uint256 refundedWbtx = handler.ghost_refundedWbtx();
        assertLe(redeemedWbtx, attestedWbtx + refundedWbtx);

        uint256 netBackingWbtx = attestedWbtx + refundedWbtx - redeemedWbtx;
        assertLe(wbtx.totalSupply(), netBackingWbtx);

        // Sat view of the same invariant: supply in satoshis cannot exceed net sat backing.
        uint256 supplySat = wbtx.totalSupply() / SAT_SCALE;
        uint256 netBackingSat = netBackingWbtx / SAT_SCALE;
        assertLe(supplySat, netBackingSat);
    }

    function invariant_SupplyCeiling() public view {
        assertLe(wbtx.totalSupply(), bridge.maxSupplyWbtx());
    }

    function invariant_NoDoubleMintPerDeposit() public view {
        uint256 len = handler.knownDepositKeysLength();
        for (uint256 i = 0; i < len; i++) {
            bytes32 dk = handler.knownDepositKeyAt(i);
            uint8 count = handler.ghost_mintSuccessCount(dk);
            assertLe(uint256(count), 1);
            if (count == 1) {
                assertTrue(bridge.minted(dk));
            }
        }
    }

    function invariant_FulfillRefundMutuallyExclusive() public view {
        uint256 len = handler.knownRedeemIdsLength();
        for (uint256 i = 0; i < len; i++) {
            uint256 redeemId = handler.knownRedeemIdAt(i);
            (, , , , , , , bool fulfilled, bool refunded) = bridge.redeems(redeemId);
            assertFalse(fulfilled && refunded);
        }
    }

    function invariant_BucketNeverExceedsCap() public view {
        assertLe(uint256(bridge.availableSat()), uint256(bridge.windowMintCapSat()));
    }

    function invariant_VetoedNeverMints() public view {
        uint256 len = handler.knownDepositKeysLength();
        for (uint256 i = 0; i < len; i++) {
            bytes32 dk = handler.knownDepositKeyAt(i);
            if (handler.ghost_vetoedByGuardian(dk)) {
                assertFalse(bridge.minted(dk));
            }
        }
    }

    function _initialSignersSorted() internal view returns (address[] memory signers) {
        signers = new address[](3);
        signers[0] = vm.addr(PK1);
        signers[1] = vm.addr(PK2);
        signers[2] = vm.addr(PK3);
        for (uint256 i = 1; i < signers.length; i++) {
            address key = signers[i];
            uint256 j = i;
            while (j > 0 && signers[j - 1] > key) {
                signers[j] = signers[j - 1];
                unchecked {
                    --j;
                }
            }
            signers[j] = key;
        }
    }
}
