/**
 * recordDigestCli.js — UNUSED AT RUNTIME
 *
 * The Python backend now calls the MessageDigestRegistry contract directly
 * via web3.py (see backend/app/services/blockchain_service.py).
 * This file is retained for reference only and is NOT called by the server.
 *
 * Original purpose: CLI shim called by the Python backend via subprocess.
 * Usage (Python passes conversationText on stdin):
 *   echo "<conversationText>" | node recordDigestCli.js <conversationId>
 */

"use strict";

require("dotenv").config();

const { recordConversationDigest } = require("./digestRecorder");

async function main() {
    const conversationId = process.argv[2];
    if (!conversationId) {
        process.stderr.write("Error: conversationId argument is required\n");
        process.exit(1);
    }

    // Read conversationText from stdin so the Python caller can pipe it safely.
    const chunks = [];
    for await (const chunk of process.stdin) {
        chunks.push(chunk);
    }
    const conversationText = Buffer.concat(chunks).toString("utf8").trim();
    if (!conversationText) {
        process.stderr.write("Error: conversationText is empty (pipe it via stdin)\n");
        process.exit(1);
    }

    const result = await recordConversationDigest(conversationId, conversationText);
    // Output a single JSON line — Python reads it with json.loads().
    process.stdout.write(JSON.stringify(result) + "\n");
}

main().catch((err) => {
    process.stderr.write(err.message + "\n");
    process.exit(1);
});
