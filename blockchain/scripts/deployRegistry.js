/**
 * deployRegistry.js — Deploy MessageDigestRegistry to Ethereum Sepolia testnet.
 *
 * Usage:
 *   npx hardhat compile                 # compile the contract first
 *   node scripts/deployRegistry.js      # deploy using env vars below
 *
 * Required environment variables (set in blockchain/.env or repo-root .env.example):
 *   PRIVATE_KEY  — deployer wallet private key (0x-prefixed, 64 hex chars)
 *   RPC_URL      — Sepolia JSON-RPC endpoint  (e.g. https://rpc2.sepolia.org)
 *
 * Output:
 *   Prints deployed address and tx hash to stdout.
 *   Writes / updates blockchain/deployedAddress.json so digestRecorder.js
 *   can locate the contract without manual copy-paste.
 *
 * Prerequisites:
 *   1. Fund the deployer wallet with Sepolia ETH — https://faucet.sepolia.dev
 *   2. Run `npx hardhat compile` from the blockchain/ directory first.
 */

"use strict";

require("dotenv").config();

const { ethers } = require("ethers");
const fs         = require("fs");
const path       = require("path");

async function main() {
    // -----------------------------------------------------------------------
    // 1. Validate environment
    // -----------------------------------------------------------------------
    const { PRIVATE_KEY, RPC_URL } = process.env;
    if (!PRIVATE_KEY) throw new Error("PRIVATE_KEY is not set in environment");
    if (!RPC_URL)     throw new Error("RPC_URL is not set in environment");

    // -----------------------------------------------------------------------
    // 2. Load compiled artifact (produced by `npx hardhat compile`)
    // -----------------------------------------------------------------------
    const artifactPath = path.join(
        __dirname,
        "../artifacts/contracts/MessageDigestRegistry.sol/MessageDigestRegistry.json"
    );
    if (!fs.existsSync(artifactPath)) {
        throw new Error(
            `Artifact not found at:\n  ${artifactPath}\n` +
            "Run 'npx hardhat compile' from the blockchain/ directory first."
        );
    }
    const artifact = JSON.parse(fs.readFileSync(artifactPath, "utf8"));

    // -----------------------------------------------------------------------
    // 3. Connect to Sepolia
    // -----------------------------------------------------------------------
    const provider = new ethers.JsonRpcProvider(RPC_URL);
    // Wallet holds PRIVATE_KEY — never logged, only used to sign transactions.
    const wallet   = new ethers.Wallet(PRIVATE_KEY, provider);

    console.log("Deployer address :", wallet.address);
    const balance = await provider.getBalance(wallet.address);
    console.log("Deployer balance :", ethers.formatEther(balance), "ETH");

    if (balance === 0n) {
        throw new Error(
            "Deployer wallet has 0 ETH on Sepolia. " +
            "Fund it at https://faucet.sepolia.dev before deploying."
        );
    }

    // -----------------------------------------------------------------------
    // 4. Deploy MessageDigestRegistry
    // -----------------------------------------------------------------------
    console.log("\nDeploying MessageDigestRegistry...");
    const factory  = new ethers.ContractFactory(artifact.abi, artifact.bytecode, wallet);
    const contract = await factory.deploy();

    const deployTx   = contract.deploymentTransaction();
    console.log("Deployment tx hash :", deployTx.hash);
    console.log("Waiting for 1 confirmation...");

    // Wait for 1 block confirmation before treating the deployment as settled.
    const receipt = await deployTx.wait(1);
    const address = await contract.getAddress();

    console.log("\n✓ MessageDigestRegistry deployed");
    console.log("  Contract address :", address);
    console.log("  Block number     :", receipt.blockNumber);
    console.log("  Etherscan        :", `https://sepolia.etherscan.io/tx/${receipt.hash}`);

    // -----------------------------------------------------------------------
    // 5. Persist deployed address to deployedAddress.json
    // -----------------------------------------------------------------------
    // Path is relative to scripts/ → one level up lands in blockchain/.
    const outputPath = path.join(__dirname, "../deployedAddress.json");

    // Merge into an existing file so other contracts' addresses are preserved.
    let existing = {};
    if (fs.existsSync(outputPath)) {
        try {
            existing = JSON.parse(fs.readFileSync(outputPath, "utf8"));
        } catch {
            // Overwrite if the file is malformed.
        }
    }
    existing.MessageDigestRegistry = address;
    fs.writeFileSync(outputPath, JSON.stringify(existing, null, 2) + "\n");

    console.log("\n  Deployed address written to:", outputPath);
    console.log("  Set CONTRACT_ADDRESS in your .env if calling the contract directly.\n");
}

main().catch((err) => {
    console.error("\nDeployment failed:", err.message);
    process.exitCode = 1;
});
