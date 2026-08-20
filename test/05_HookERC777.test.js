const { ethers } = require("hardhat");
const { expect } = require("chai");

describe("Variant 5 — Hook-based reentrancy", function () {
  const ATTACKER_SEED = 1n;
  const HONEST_DEPOSIT = 5n;

  async function setup(vaultName) {
    const [deployer, honest] = await ethers.getSigners();

    const Token = await ethers.getContractFactory("HookToken");
    const token = await Token.deploy();
    await token.waitForDeployment();

    const Vault = await ethers.getContractFactory(vaultName);
    const vault = await Vault.deploy(
      await token.getAddress()
    );
    await vault.waitForDeployment();

    // Give the honest user 5 tokens.
    await token.mint(
      honest.address,
      HONEST_DEPOSIT
    );

    // Deploy attacker.
    const Attacker = await ethers.getContractFactory(
      "HookAttacker"
    );

    const attacker = await Attacker.deploy(
      await token.getAddress(),
      await vault.getAddress()
    );
    await attacker.waitForDeployment();

    // Give attacker 1 token.
    await token.mint(
      await attacker.getAddress(),
      ATTACKER_SEED
    );

    // Honest user deposits 5 tokens.
    await token.connect(honest).transfer(
      await vault.getAddress(),
      HONEST_DEPOSIT
    );

    return {
      token,
      vault,
      attacker,
      honest,
    };
  }

  it("DRAINS the VulnerableHookVault through the token hook", async function () {
    const {
      token,
      vault,
      attacker,
      honest,
    } = await setup("VulnerableHookVault");

    // At this point only the honest user has deposited.
    // The attacker still holds its 1 token.
    expect(
      await token.balanceOf(await vault.getAddress())
    ).to.equal(5n);

    expect(
      await token.balanceOf(await attacker.getAddress())
    ).to.equal(1n);

    expect(
      await vault.deposits(honest.address)
    ).to.equal(5n);

    // Start attack.
    //
    // The attacker deposits its 1 token first.
    // Vault balance becomes 6.
    //
    // withdrawAll() then sends the attacker's token back.
    // The token hook re-enters withdrawAll() while the attacker's
    // ledger balance has not yet been cleared.
    await attacker.attack(ATTACKER_SEED);

    // The attacker has drained all tokens from the vault.
    expect(
      await token.balanceOf(await vault.getAddress())
    ).to.equal(0n);

    // All 6 tokens ended up with the attacker.
    expect(
      await token.balanceOf(await attacker.getAddress())
    ).to.equal(6n);

    // The honest user's ledger still says 5 tokens,
    // even though the vault has no tokens left.
    expect(
      await vault.deposits(honest.address)
    ).to.equal(5n);
  });

  it("BLOCKS the hook reentrancy with SafeHookVault", async function () {
    const {
      token,
      vault,
      attacker,
      honest,
    } = await setup("SafeHookVault");

    // Initially the vault contains only the honest user's 5 tokens.
    expect(
      await token.balanceOf(await vault.getAddress())
    ).to.equal(5n);

    expect(
      await token.balanceOf(await attacker.getAddress())
    ).to.equal(1n);

    // The attacker attempts to deposit 1 token and start the attack.
    //
    // SafeHookVault:
    // 1. sets deposits[attacker] = 0
    // 2. performs token transfer
    // 3. token invokes attacker's hook
    // 4. attacker attempts to re-enter withdrawAll()
    // 5. nonReentrant rejects the re-entry
    //
    // The entire transaction therefore reverts.
    await expect(
      attacker.attack(ATTACKER_SEED)
    ).to.be.reverted;

    // Because the transaction reverted, all state is restored.
    expect(
      await token.balanceOf(await vault.getAddress())
    ).to.equal(5n);

    expect(
      await token.balanceOf(await attacker.getAddress())
    ).to.equal(1n);

    expect(
      await vault.deposits(honest.address)
    ).to.equal(5n);

    expect(
      await vault.deposits(await attacker.getAddress())
    ).to.equal(0n);
  });
});