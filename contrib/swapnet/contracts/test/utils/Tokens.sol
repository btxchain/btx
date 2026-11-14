// SPDX-License-Identifier: MIT
pragma solidity 0.8.24;

/// Test tokens covering the ERC-20 behaviours the contract must accept or reject.
contract StdToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public totalSupply;

    function mint(address to, uint256 v) external { balanceOf[to] += v; totalSupply += v; }
    function approve(address s, uint256 v) external returns (bool) { allowance[msg.sender][s] = v; return true; }
    function transfer(address to, uint256 v) external virtual returns (bool) { _move(msg.sender, to, v); return true; }
    function transferFrom(address f, address to, uint256 v) external virtual returns (bool) {
        _spend(f, v); _move(f, to, v); return true;
    }
    function _spend(address f, uint256 v) internal {
        uint256 a = allowance[f][msg.sender];
        require(a >= v, "allowance");
        if (a != type(uint256).max) allowance[f][msg.sender] = a - v;
    }
    function _move(address f, address to, uint256 v) internal virtual {
        require(balanceOf[f] >= v, "balance");
        balanceOf[f] -= v; balanceOf[to] += v;
    }
}

/// USDT-style: no return value.
contract NoReturnToken is StdToken {
    function transfer(address to, uint256 v) external override returns (bool) {
        _move(msg.sender, to, v); assembly { return(0, 0) }
    }
    function transferFrom(address f, address to, uint256 v) external override returns (bool) {
        _spend(f, v); _move(f, to, v); assembly { return(0, 0) }
    }
}

/// Returns false instead of reverting, without moving funds.
contract FalseReturnToken is StdToken {
    bool public failTransfer;
    bool public failTransferFrom;
    function setFail(bool t, bool tf) external { failTransfer = t; failTransferFrom = tf; }
    function transfer(address to, uint256 v) external override returns (bool) {
        if (failTransfer) return false; _move(msg.sender, to, v); return true;
    }
    function transferFrom(address f, address to, uint256 v) external override returns (bool) {
        if (failTransferFrom) return false; _spend(f, v); _move(f, to, v); return true;
    }
}

/// Returns a 32-byte word that is not a canonical bool.
contract NonBoolToken is StdToken {
    function transfer(address to, uint256 v) external override returns (bool) {
        _move(msg.sender, to, v); assembly { mstore(0, 2) return(0, 32) }
    }
}

/// Transfer tax that the issuer can switch on after a lock (USDT has such a switch).
contract FeeToken is StdToken {
    uint256 public feeBps;
    address public sink = address(0xFEE);
    function setFee(uint256 bps) external { feeBps = bps; }
    function _move(address f, address to, uint256 v) internal override {
        require(balanceOf[f] >= v, "balance");
        uint256 fee = v * feeBps / 10_000;
        balanceOf[f] -= v; balanceOf[to] += v - fee; balanceOf[sink] += fee;
    }
}

/// Shares-based rebasing token: balanceOf scales with a global index.
contract ElasticToken {
    mapping(address => uint256) internal shares;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public index = 1e18;
    function rebase(uint256 newIndex) external { index = newIndex; }
    function mint(address to, uint256 v) external { shares[to] += v * 1e18 / index; }
    function balanceOf(address a) public view returns (uint256) { return shares[a] * index / 1e18; }
    function approve(address s, uint256 v) external returns (bool) { allowance[msg.sender][s] = v; return true; }
    function transfer(address to, uint256 v) external returns (bool) { _move(msg.sender, to, v); return true; }
    function transferFrom(address f, address to, uint256 v) external returns (bool) {
        require(allowance[f][msg.sender] >= v, "allowance"); allowance[f][msg.sender] -= v; _move(f, to, v); return true;
    }
    function _move(address f, address to, uint256 v) internal {
        uint256 s = (v * 1e18 + index - 1) / index; // round shares up so the sender pays at least v
        require(shares[f] >= s, "balance");
        shares[f] -= s; shares[to] += s;
    }
}

/// Issuer blocklist (USDC/USDT style): transfers to a blocked address revert.
contract BlockToken is StdToken {
    mapping(address => bool) public blocked;
    function setBlocked(address a, bool b) external { blocked[a] = b; }
    function _move(address f, address to, uint256 v) internal override {
        require(!blocked[f] && !blocked[to], "blocked");
        super._move(f, to, v);
    }
}

interface IHook { function onToken() external; }

/// ERC-777-style hook: calls a target during transfer and transferFrom.
contract HookToken is StdToken {
    address public hook;
    function setHook(address h) external { hook = h; }
    function _move(address f, address to, uint256 v) internal override {
        super._move(f, to, v);
        if (hook != address(0)) IHook(hook).onToken();
    }
}

/// balanceOf misbehaves on demand: 0 = normal, 1 = revert, 2 = short return, 3 = long return.
contract BadBalanceToken {
    mapping(address => uint256) internal bal;
    uint256 public mode;
    function setMode(uint256 m) external { mode = m; }
    function mint(address to, uint256 v) external { bal[to] += v; }
    function approve(address, uint256) external pure returns (bool) { return true; }
    function transferFrom(address f, address to, uint256 v) external returns (bool) { bal[f] -= v; bal[to] += v; return true; }
    function transfer(address to, uint256 v) external returns (bool) { bal[msg.sender] -= v; bal[to] += v; return true; }
    function balanceOf(address a) external view returns (uint256) {
        uint256 m = mode;
        if (m == 1) revert("no");
        if (m == 2) assembly { mstore(0, 1) return(0, 16) }
        if (m == 3) assembly { mstore(0, 1) mstore(32, 1) return(0, 64) }
        return bal[a];
    }
}
