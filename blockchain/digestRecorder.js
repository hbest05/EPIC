/**
 * digestRecorder.js — UNUSED AT RUNTIME
 *
 * The Python backend now calls the MessageDigestRegistry contract directly
 * via web3.py (see backend/app/services/blockchain_service.py).
 * This file is retained for reference / deploy-time tooling only.
 *
 * Still used by: blockchain/scripts/deployRegistry.js (deploy-time, not runtime).
 *
 * Original description: JS integration layer for MessageDigestRegistry.
 *
 * Exports three functions:
 *   recordConversationDigest(conversationId, conversationText)
 *     → { txHash, blockNumber, recordIndex }
 *
 *   verifyDigest(conversationId, conversationText, recordIndex)
 *     → boolean
 *
 *   getOnChainRecord(recordIndex)
 *     → { digest, timestamp, recorder, conversationId }
 *
 * Configuration (loaded lazily on first call):
 *   CONTRACT_ADDRESS — read from blockchain/deployedAddress.json
 *   ABI              — read from compiled artifact, with fallback to
 *                      blockchain/MessageDigestRegistryABI.json
 *   PRIVATE_KEY      — process.env.PRIVATE_KEY (server wallet, 0x-prefixed)
 *   RPC_URL          — process.env.RPC_URL      (Sepolia JSON-RPC endpoint)
 *
 * Run `npx hardhat compile` and `node scripts/deployRegistry.js` before use.
 */

"use strict";

require("dotenv").config();

const { ethers } = require("ethers");
const fs         = require("fs");
const path       = require("path");

// ---------------------------------------------------------------------------
// Bootstrap — build a singleton contract instance on first call
// ---------------------------------------------------------------------------

/**
 * Resolve ABI from the hardhat artifact (canonical) with a fallback to the
 * standalone ABI JSON shipped with the repo.
 */
function loadAbi() {
    const artifactPath = path.join(
        __dirname,
        "artifacts/contracts/MessageDigestRegistry.sol/MessageDigestRegistry.json"
    );
    if (fs.existsSync(artifactPath)) {
        return JSON.parse(fs.readFileSync(artifactPath, "utf8")).abi;
    }

    const abiPath = path.join(__dirname, "MessageDigestRegistryABI.json");
    if (fs.existsSync(abiPath)) {
        // Fallback: use the standalone ABI file (artifacts not compiled yet)
        return JSON.parse(fs.readFileSync(abiPath, "utf8"));
    }

    throw new Error(
        "ABI not found. Run 'npx hardhat compile' from the blockchain/ directory, " +
        "or ensure MessageDigestRegistryABI.json is present."
    );
}

function loadConfig() {
    const abi = loadAbi();

    // CONTRACT_ADDRESS comes from the deploy script output.
    const addressFile = path.join(__dirname, "deployedAddress.json");
    if (!fs.existsSync(addressFile)) {
        throw new Error(
            "deployedAddress.json not found. " +
            "Run 'node scripts/deployRegistry.js' to deploy the contract first."
        );
    }
    const deployed = JSON.parse(fs.readFileSync(addressFile, "utf8"));
    const contractAddress = deployed.MessageDigestRegistry || process.env.CONTRACT_ADDRESS;
    if (!contractAddress) {
        throw new Error(
            "MessageDigestRegistry address missing in deployedAddress.json " +
            "and CONTRACT_ADDRESS env var is not set."
        );
    }

    const { PRIVATE_KEY, RPC_URL } = process.env;
    if (!PRIVATE_KEY) throw new Error("PRIVATE_KEY is not set in environment");
    if (!RPC_URL)     throw new Error("RPC_URL is not set in environment");

    const provider = new ethers.JsonRpcProvider(RPC_URL);
    // Wallet is used to sign write transactions (recordDigest). Read calls
    // via getRecord/getRecordsByConversation use eth_call and cost no gas.
    const wallet   = new ethers.Wallet(PRIVATE_KEY, provider);
    const contract = new ethers.Contract(contractAddress, abi, wallet);

    return { provider, wallet, contract };
}

// Lazy singleton — initialised on first public API call so that importing the
// module does not throw when env vars are absent (e.g. during test mocking).
let _ctx = null;

function getCtx() {
    if (!_ctx) _ctx = loadConfig();
    return _ctx;
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Hash a conversation segment and record the digest on-chain.
 *
 * The keccak256 hash is computed locally (ethers v6: ethers.keccak256 +
 * ethers.toUtf8Bytes — equivalent to the v5 ethers.utils.* helpers) so the
 * raw text never leaves the calling process.
 *
 * @param {string} conversationId   Off-chain thread identifier (UUID / slug).
 * @param {string} conversationText Raw text of the conversation segment to anchor.
 * @returns {Promise<{txHash: string, blockNumber: number, recordIndex: number|null}>}
 */
async function recordConversationDigest(conversationId, conversationText) {
    try {
        const { contract } = getCtx();

        // Compute keccak256(UTF-8 bytes) — mirrors what a Solidity `keccak256`
        // call would produce over the same input.
        const digest = ethers.keccak256(ethers.toUtf8Bytes(conversationText));

        const tx      = await contract.recordDigest(conversationId, digest);
        const receipt = await tx.wait();

        // Extract recordIndex from the DigestRecorded event rather than
        // relying on the return value, which is not accessible via tx.wait().
        let recordIndex = null;
        for (const log of receipt.logs) {
            try {
                const parsed = contract.interface.parseLog(log);
                if (parsed && parsed.name === "DigestRecorded") {
                    recordIndex = Number(parsed.args.recordIndex);
                    break;
                }
            } catch {
                // Log belongs to a different contract (e.g. ERC-20 transfer) — skip.
            }
        }

        return {
            txHash:      receipt.hash,
            blockNumber: receipt.blockNumber,
            recordIndex,
        };
    } catch (err) {
        throw new Error(`recordConversationDigest failed for "${conversationId}": ${err.message}`);
    }
}

/**
 * Verify that a conversation segment matches its on-chain digest.
 *
 * Recomputes the hash locally and compares it to the stored value at
 * `recordIndex` — no trust in the caller's claimed hash is required.
 *
 * @param {string} conversationId   Off-chain thread identifier (used in error messages).
 * @param {string} conversationText Text to rehash locally.
 * @param {number} recordIndex      Index returned by a prior recordConversationDigest call.
 * @returns {Promise<boolean>}  true if hashes match, false otherwise.
 */
async function verifyDigest(conversationId, conversationText, recordIndex) {
    try {
        const { contract } = getCtx();
        const localDigest  = ethers.keccak256(ethers.toUtf8Bytes(conversationText));

        // getRecord() is a view call — gas-free, no wallet signature needed.
        const [onChainDigest] = await contract.getRecord(recordIndex);

        return localDigest === onChainDigest;
    } catch (err) {
        throw new Error(
            `verifyDigest failed for "${conversationId}" at index ${recordIndex}: ${err.message}`
        );
    }
}

/**
 * Fetch a structured on-chain record by its index.
 *
 * @param {number} recordIndex  0-based index into the contract's `records[]` array.
 * @returns {Promise<{digest: string, timestamp: number, recorder: string, conversationId: string}>}
 */
async function getOnChainRecord(recordIndex) {
    try {
        const { contract } = getCtx();
        const [digest, timestamp, recorder, conversationId] =
            await contract.getRecord(recordIndex);

        return {
            digest,
            // Convert BigInt returned by ethers v6 to a plain JS number.
            timestamp:      Number(timestamp),
            recorder,
            conversationId,
        };
    } catch (err) {
        throw new Error(`getOnChainRecord failed at index ${recordIndex}: ${err.message}`);
    }
}

module.exports = { recordConversationDigest, verifyDigest, getOnChainRecord };
