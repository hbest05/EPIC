/**
 * verifyDigestCli.js — UNUSED AT RUNTIME
 *
 * The Python backend now calls the MessageDigestRegistry contract directly
 * via web3.py (see backend/app/services/blockchain_service.py).
 * This file is retained for reference only and is NOT called by the server.
 *
 * Original purpose: CLI shim for the verify endpoint in the Python backend.
 * Usage (Python passes conversationText on stdin):
 *   echo "<conversationText>" | node verifyDigestCli.js <conversationId> <recordIndex>
 */

"use strict";

require("dotenv").config();

const { ethers }          = require("ethers");
const { getOnChainRecord } = require("./digestRecorder");

async function main() {
    const conversationId = process.argv[2];
    const recordIndex    = parseInt(process.argv[3], 10);

    if (!conversationId || isNaN(recordIndex)) {
        process.stderr.write("Usage: node verifyDigestCli.js <conversationId> <recordIndex>\n");
        process.exit(1);
    }

    // Read conversationText from stdin.
    const chunks = [];
    for await (const chunk of process.stdin) {
        chunks.push(chunk);
    }
    const conversationText = Buffer.concat(chunks).toString("utf8").trim();
    if (!conversationText) {
        process.stderr.write("Error: conversationText is empty (pipe it via stdin)\n");
        process.exit(1);
    }

    // Fetch on-chain record — this is an eth_call (gas-free view call).
    const record = await getOnChainRecord(recordIndex);

    // Recompute the digest locally using the same method as recordConversationDigest.
    const localDigest = ethers.keccak256(ethers.toUtf8Bytes(conversationText));
    const verified    = localDigest === record.digest;

    process.stdout.write(JSON.stringify({
        verified,
        onChainDigest:         record.digest,
        localDigest,
        timestamp:             record.timestamp,   // Unix seconds (Number, not BigInt)
        recorder:              record.recorder,
        onChainConversationId: record.conversationId,
    }) + "\n");
}

main().catch((err) => {
    process.stderr.write(err.message + "\n");
    process.exit(1);
});
