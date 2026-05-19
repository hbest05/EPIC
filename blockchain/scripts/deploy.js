/**
 * deploy.js — Deploy MessageDigest to Ethereum Sepolia testnet.
 *
 * Usage:
 *   npx hardhat run scripts/deploy.js --network sepolia
 *
 * Prerequisites:
 *   1. Set SEPOLIA_RPC_URL and DEPLOYER_PRIVATE_KEY in .env
 *   2. Fund the deployer wallet with Sepolia ETH (faucet.sepolia.dev)
 *   3. Run `npx hardhat compile` first
 *
 * After deployment:
 *   - Copy the printed contract address into backend/.env as CONTRACT_ADDRESS
 *   - Run `npx hardhat verify --network sepolia <address>` to verify on Etherscan
 */

const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();

  console.log("Deploying MessageDigest contract...");
  console.log("Deployer address:", deployer.address);
  console.log(
    "Deployer balance:",
    ethers.formatEther(await ethers.provider.getBalance(deployer.address)),
    "ETH"
  );

  // Deploy the contract
  const MessageDigest = await ethers.getContractFactory("MessageDigest");
  const contract = await MessageDigest.deploy();
  await contract.waitForDeployment();

  const address = await contract.getAddress();
  console.log("\nMessageDigest deployed to:", address);
  console.log("Transaction hash:         ", contract.deploymentTransaction().hash);
  console.log("\nUpdate backend/.env:");
  console.log(`  CONTRACT_ADDRESS=${address}`);
  console.log("\nVerify on Etherscan:");
  console.log(`  npx hardhat verify --network sepolia ${address}`);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
