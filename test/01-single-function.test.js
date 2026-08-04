const { ethers } = require("hardhat");
const { expect } = require("chai");

const eth = (n) => ethers.parseEther(n);
const fmt = (w) => ethers.formatEther(w);

describe("Variant 1 — Single-function reentrancy", () => {
  async function setup(vaultName) {
    const [dep, u1, u2] = await ethers.getSigners();
    const Vault = await ethers.getContractFactory(vaultName);
    const vault = await Vault.deploy();
    await vault.waitForDeployment();
    // two honest users deposit 3 ETH each
    await vault.connect(u1).deposit({ value: eth("3") });
    await vault.connect(u2).deposit({ value: eth("3") });
    return { vault };
  }

  it("DRAINS the VulnerableVault (1 ETH seed -> 7 ETH stolen)", async () => {
    const { vault } = await setup("VulnerableVault");
    const Att = await ethers.getContractFactory("ReentrancyAttacker");
    const att = await Att.deploy(await vault.getAddress());
    await att.waitForDeployment();

    const vaultAddr = await vault.getAddress();
    const attAddr = await att.getAddress();

    console.log("   vault before :", fmt(await ethers.provider.getBalance(vaultAddr)), "ETH");
    await att.attack({ value: eth("1") });
    console.log("   vault after  :", fmt(await ethers.provider.getBalance(vaultAddr)), "ETH");
    console.log("   attacker holds:", fmt(await ethers.provider.getBalance(attAddr)), "ETH");

    expect(await ethers.provider.getBalance(vaultAddr)).to.equal(0n);
    expect(await ethers.provider.getBalance(attAddr)).to.equal(eth("7")); // 6 stolen + 1 seed
  });

  it("BLOCKS the attack on the SafeVault (CEI + nonReentrant)", async () => {
    const { vault } = await setup("SafeVault");
    const Att = await ethers.getContractFactory("ReentrancyAttacker");
    const att = await Att.deploy(await vault.getAddress());
    await att.waitForDeployment();

    await expect(att.attack({ value: eth("1") })).to.be.reverted;
    // honest deposits are untouched
    expect(await ethers.provider.getBalance(await vault.getAddress())).to.equal(eth("6"));
  });
});
