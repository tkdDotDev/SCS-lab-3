const { ethers } = require("hardhat");
const { expect } = require("chai");

const eth = (n) => ethers.parseEther(n);

describe("Variant 2 — Cross-function reentrancy", function () {
  async function setup(bankName) {
    const [deployer, user1, user2] = await ethers.getSigners();

    const Bank = await ethers.getContractFactory(bankName);
    const bank = await Bank.deploy();
    await bank.waitForDeployment();

    // Honest users deposit a total of 5 ETH.
    await bank.connect(user1).deposit({
      value: eth("3"),
    });

    await bank.connect(user2).deposit({
      value: eth("2"),
    });

    return { bank, user1, user2 };
  }

  it("DRAINS the VulnerableBank using cross-function reentrancy", async function () {
    const { bank } = await setup("VulnerableBank");

    const Attacker = await ethers.getContractFactory("CrossFnAttacker");
    const attacker = await Attacker.deploy(await bank.getAddress());
    await attacker.waitForDeployment();

    const Partner = await ethers.getContractFactory("Partner");
    const partner = await Partner.deploy(await bank.getAddress());
    await partner.waitForDeployment();

    await attacker.setPartner(await partner.getAddress());

    // Attacker deposits only 1 ETH.
    await attacker.seedAndAttack({
      value: eth("1"),
    });

    // Attacker's original 1 ETH was withdrawn.
    expect(
      await ethers.provider.getBalance(await attacker.getAddress())
    ).to.equal(eth("1"));

    // The stale balance was transferred to Partner.
    expect(
      await bank.balanceOf(await partner.getAddress())
    ).to.equal(eth("1"));

    // Partner cashes out the duplicated balance.
    await partner.cashOut();

    // Partner receives another 1 ETH.
    expect(
      await ethers.provider.getBalance(await partner.getAddress())
    ).to.equal(eth("1"));

    // Bank originally had 5 ETH + attacker's 1 ETH.
    // Two ETH were extracted from the attacker's single 1 ETH deposit.
    expect(
      await ethers.provider.getBalance(await bank.getAddress())
    ).to.equal(eth("4"));
  });

  it("BLOCKS the double-spend against SafeBank", async function () {
    const { bank } = await setup("SafeBank");

    const Attacker = await ethers.getContractFactory("CrossFnAttacker");
    const attacker = await Attacker.deploy(await bank.getAddress());
    await attacker.waitForDeployment();

    const Partner = await ethers.getContractFactory("Partner");
    const partner = await Partner.deploy(await bank.getAddress());
    await partner.waitForDeployment();

    await attacker.setPartner(await partner.getAddress());

    await attacker.seedAndAttack({
      value: eth("1"),
    });

    // The attacker gets its legitimate 1 ETH back.
    expect(
      await ethers.provider.getBalance(await attacker.getAddress())
    ).to.equal(eth("1"));

    // No balance was transferred to Partner.
    expect(
      await bank.balanceOf(await partner.getAddress())
    ).to.equal(0n);

    // Bank still contains the honest 5 ETH.
    expect(
      await ethers.provider.getBalance(await bank.getAddress())
    ).to.equal(eth("5"));
  });
});
