# Reentrancy Lab — Unit III / Lecture 1

Each variant ships as **one self-contained `.sol`
file** containing a *vulnerable* contract, an *attacker*, and a *fixed* version,
plus a Hardhat test that (1) proves the exploit drains funds and (2) proves the
fix blocks it.

Because each file is standalone, you can **either** run the Hardhat tests **or**
paste any file straight into **Remix** for a live click-through.

| # | File | Variant | Core fix demonstrated |
|---|------|---------|-----------------------|
| 1 | `contracts/01_SingleFunction.sol` | Single-function (the DAO bug) | Checks-Effects-Interactions + `nonReentrant` |
| 2 | `contracts/02_CrossFunction.sol` | Cross-function | One shared mutex across **all** functions |
| 3 | `contracts/03_CrossContract.sol` | Cross-contract | CEI so a sibling contract reads correct state |
| 4 | `contracts/04_ReadOnly.sol` | Read-only (view oracle) | Consistent state ordering before external calls |
| 5 | `contracts/05_HookERC777.sol` | Hook-based (ERC-777 style) | Treat token transfers as external calls; CEI + guard |

---

## Assignment Task

To complete the unit tests for:

- 02_CrossFunction.sol
- 03_CrossContract.sol
- 04_ReadOnly.sol
- 05_HookERC777.sol

## Run with Hardhat

```bash
npm install            # needs internet for hardhat + toolbox (~1 min)
npx hardhat test       # runs all five demos

# or one at a time:
npm run test:1         # single-function
npm run test:2         # cross-function
npm run test:3         # cross-contract
npm run test:4         # read-only
npm run test:5         # hook / ERC-777
```

Each test prints before/after balances, so the terminal output alone tells the
story on camera. Expected result: every `DRAINS/STEALS/INFLATES` test passes
against the vulnerable contract, and every `BLOCKS/DENIES/KEEPS` test passes
against the fixed one.

> Solidity **0.8.24**. The contracts use a local minimal `ReentrancyGuard` so
> nothing external is imported — in production use
> `@openzeppelin/contracts/utils/ReentrancyGuard.sol`.

---