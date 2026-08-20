const { ethers } = require("hardhat");
const { expect } = require("chai");

const eth = (n) => ethers.parseEther(n);

describe("Variant 3 — Cross-contract reentrancy", function () {
  async function setup(vaultName) {
    const Vault = await ethers.getContractFactory(vaultName);
    const vault = await Vault.deploy();
    await vault.waitForDeployment();

    const Reward = await ethers.getContractFactory("RewardPool");
    const reward = await Reward.deploy(await vault.getAddress());
    await reward.waitForDeployment();

    // Fund RewardPool with 2 ETH.
    await ethers.getSigners().then(async ([deployer]) => {
      await deployer.sendTransaction({
        to: await reward.getAddress(),
        value: eth("2"),
      });
    });

    return { vault, reward };
  }

  it("STEALS the bonus from RewardPool during cross-contract reentrancy", async function () {
    const { vault, reward } = await setup("VulnerableRewardVault");

    const Attacker =
      await ethers.getContractFactory("CrossContractAttacker");

    const attacker = await Attacker.deploy(
      await vault.getAddress(),
      await reward.getAddress()
    );

    await attacker.waitForDeployment();

    await attacker.attack({
      value: eth("1"),
    });

    // The attacker received:
    // 1 ETH withdrawal + 0.5 ETH bonus = 1.5 ETH.
    expect(
      await ethers.provider.getBalance(await attacker.getAddress())
    ).to.equal(eth("1.5"));

    // RewardPool should have paid the 0.5 ETH bonus.
    expect(
      await ethers.provider.getBalance(await reward.getAddress())
    ).to.equal(eth("1.5"));

    // Vault has no ETH remaining because the attacker's 1 ETH
    // withdrawal was completed.
    expect(
      await ethers.provider.getBalance(await vault.getAddress())
    ).to.equal(0n);

    // The reward was incorrectly marked as claimed.
    expect(
      await reward.claimed(await attacker.getAddress())
    ).to.equal(true);
  });

  it("BLOCKS the undeserved bonus with SafeRewardVault", async function () {
    const { vault, reward } = await setup("SafeRewardVault");

    const Attacker =
      await ethers.getContractFactory("CrossContractAttacker");

    const attacker = await Attacker.deploy(
      await vault.getAddress(),
      await reward.getAddress()
    );

    await attacker.waitForDeployment();

    await attacker.attack({
      value: eth("1"),
    });

    // Attacker gets only its legitimate 1 ETH withdrawal.
    expect(
      await ethers.provider.getBalance(await attacker.getAddress())
    ).to.equal(eth("1"));

    // RewardPool was not exploited.
    expect(
      await ethers.provider.getBalance(await reward.getAddress())
    ).to.equal(eth("2"));

    // No bonus was claimed.
    expect(
      await reward.claimed(await attacker.getAddress())
    ).to.equal(false);
  });
});
