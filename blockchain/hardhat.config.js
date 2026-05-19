/**
 * Hardhat configuration for SecureMsg.
 *
 * Networks configured:
 *   hardhat  — local in-process network (default for testing)
 *   sepolia  — Ethereum Sepolia testnet (target deployment)
 *
 * Required environment variables (set in .env, never commit):
 *   SEPOLIA_RPC_URL  — Infura / Alchemy Sepolia endpoint
 *   DEPLOYER_PRIVATE_KEY — private key of the deploying wallet (0x prefixed)
 *   ETHERSCAN_API_KEY    — for contract verification on Etherscan
 */

require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

const SEPOLIA_RPC_URL = process.env.SEPOLIA_RPC_URL || "";
const DEPLOYER_PRIVATE_KEY = process.env.DEPLOYER_PRIVATE_KEY || "0x" + "0".repeat(64);
const ETHERSCAN_API_KEY = process.env.ETHERSCAN_API_KEY || "";

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.24",
    settings: {
      optimizer: {
        enabled: true,
        runs: 200,
      },
    },
  },
  networks: {
    hardhat: {
      chainId: 31337,
    },
    sepolia: {
      url: SEPOLIA_RPC_URL,
      accounts: DEPLOYER_PRIVATE_KEY ? [DEPLOYER_PRIVATE_KEY] : [],
      chainId: 11155111,
    },
  },
  etherscan: {
    apiKey: ETHERSCAN_API_KEY,
  },
  gasReporter: {
    enabled: process.env.REPORT_GAS === "true",
    currency: "USD",
  },
};
