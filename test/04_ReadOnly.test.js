const { ethers } = require("hardhat");
const { expect } = require("chai");

const eth = (n) => ethers.parseEther(n);

describe("Variant 4 — Read-only reentrancy", function () {
  async function setup(poolName) {
    const Pool = await ethers.getContractFactory(poolName);
    const pool = await Pool.deploy();
    await pool.waitForDeployment();

    const Lender = await ethers.getContractFactory("Lender");
    const lender = await Lender.deploy(await pool.getAddress());
    await lender.waitForDeployment();

    // Fund the lender with 3 ETH.
    const [deployer] = await ethers.getSigners();

    await deployer.sendTransaction({
      to: await lender.getAddress(),
      value: eth("3"),
    });

    const Borrower = await ethers.getContractFactory("Borrower");

    const borrower = await Borrower.deploy(
      await pool.getAddress(),
      await lender.getAddress()
    );

    await borrower.waitForDeployment();

    const Trigger = await ethers.getContractFactory("Trigger");

    const trigger = await Trigger.deploy(
      await pool.getAddress(),
      await borrower.getAddress()
    );

    await trigger.waitForDeployment();

    return {
      pool,
      lender,
      borrower,
      trigger,
    };
  }

  it("INFLATES the read-only price during vulnerable withdrawal", async function () {
    const {
      pool,
      lender,
      borrower,
      trigger,
    } = await setup("VulnerablePool");

    // Borrower owns 1 share.
    await borrower.deposit({
      value: eth("1"),
    });

    // Trigger owns another 1 share.
    await trigger.deposit({
      value: eth("1"),
    });

    // Before the attack:
    // reserve = 2 ETH
    // totalShares = 2 ETH
    // price = 1 ETH per share.
    expect(
      await pool.pricePerShare()
    ).to.equal(ethers.parseEther("1"));

    // Trigger withdraws 1 share.
    // During the callback:
    // totalShares = 1 ETH
    // reserve = still 2 ETH
    //
    // price becomes 2 ETH per share.
    await trigger.attack(
      eth("1"),
      eth("1")
    );

    const capturedPrice = await trigger.capturedPrice();

    expect(capturedPrice).to.equal(
      ethers.parseEther("2")
    );

    // Borrower used 1 ETH worth of shares as collateral,
    // but received 2 ETH because the oracle was inflated.
    expect(
      await lender.debt(await borrower.getAddress())
    ).to.equal(eth("2"));

    expect(
      await ethers.provider.getBalance(
        await borrower.getAddress()
      )
    ).to.equal(eth("2"));
  });

  it("KEEPS the price consistent with SafePool", async function () {
    const {
      pool,
      lender,
      borrower,
      trigger,
    } = await setup("SafePool");

    await borrower.deposit({
      value: eth("1"),
    });

    await trigger.deposit({
      value: eth("1"),
    });

    expect(
      await pool.pricePerShare()
    ).to.equal(ethers.parseEther("1"));

    await trigger.attack(
      eth("1"),
      eth("1")
    );

    // Reserve was updated BEFORE the external callback.
    // Therefore:
    // reserve = 1 ETH
    // totalShares = 1 ETH
    // price = 1 ETH.
    expect(
      await trigger.capturedPrice()
    ).to.equal(ethers.parseEther("1"));

    // Borrower receives only the correct 1 ETH value.
    expect(
      await lender.debt(await borrower.getAddress())
    ).to.equal(eth("1"));

    expect(
      await ethers.provider.getBalance(
        await borrower.getAddress()
      )
    ).to.equal(eth("1"));
  });
});
