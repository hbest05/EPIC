// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/access/Ownable.sol";

/**
 * @title  MessageDigestRegistry
 * @notice Append-only, per-conversation audit registry for SecureMsg.
 *
 * @dev    Records keccak256 digests of conversation segments to a public
 *         array. Each record is tagged with an off-chain conversationId so
 *         any party can retrieve all on-chain entries for a given chat thread
 *         and confirm that a segment existed at a specific block timestamp
 *         without revealing plaintext or ciphertext.
 *
 *         Only the authorised server wallet (the `owner`) may write records.
 *         All reads are free public view calls (gas-free via eth_call).
 *
 *         Design decisions
 *         ────────────────
 *         • Append-only array + mapping: insertion is O(1); per-conversation
 *           lookup is O(n) over the index list, which is acceptable because
 *           getRecordsByConversation() is a view call (gas-free off-chain).
 *         • `string` for conversationId: avoids bytes32 truncation hazard and
 *           keeps the interface self-documenting at the cost of slightly higher
 *           SSTORE gas (dynamic-length storage slot).
 *         • `msg.sender` captured in every record: independent auditors can
 *           verify exactly which wallet submitted each digest.
 *         • No deletion or update functions: immutability is the core security
 *           property; if a digest must be retracted, the off-chain system marks
 *           it invalid without touching the chain.
 */
contract MessageDigestRegistry is Ownable {

    // -----------------------------------------------------------------------
    // Structs
    // -----------------------------------------------------------------------

    struct DigestRecord {
        bytes32 digest;         // keccak256 hash of the conversation segment
        uint256 timestamp;      // block.timestamp at recording — immutable after write
        address recorder;       // msg.sender — proof of which wallet submitted this
        string  conversationId; // off-chain ID used to group records by chat thread
    }

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// @notice All records in insertion order. Index == recordIndex returned by recordDigest().
    DigestRecord[] public records;

    /// @notice Maps each conversationId to its list of record indexes in `records[]`.
    ///         Allows O(1) append and O(n) lookup per thread without full array scans.
    mapping(string => uint256[]) public conversationIndexes;

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    /**
     * @notice Emitted on every successful call to recordDigest().
     * @param recordIndex    Index into `records[]` — stable, never changes.
     * @param conversationId Off-chain thread ID (indexed so log consumers can
     *                       filter by conversation without fetching every event).
     * @param digest         keccak256 digest that was stored.
     * @param timestamp      Block timestamp at the time of recording.
     */
    event DigestRecorded(
        uint256 indexed recordIndex,
        string  indexed conversationId,
        bytes32         digest,
        uint256         timestamp
    );

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    /// @dev Passes msg.sender to OZ Ownable so the deploying wallet becomes
    ///      the sole authorised writer. Ownership can be transferred later if
    ///      the server signing key rotates (see OZ transferOwnership()).
    constructor() Ownable(msg.sender) {}

    // -----------------------------------------------------------------------
    // Write functions (onlyOwner)
    // -----------------------------------------------------------------------

    /**
     * @notice Record a keccak256 digest for a conversation segment on-chain.
     * @dev    Append-only: records are never deleted or overwritten, which is
     *         the core tamper-evidence guarantee. Gas note: one SSTORE for the
     *         DigestRecord slot costs ~22 k gas; the mapping push adds ~5 k.
     *         The Redis worker in redis_service.py batches calls to this
     *         function (one per conversation segment rather than per message)
     *         to amortise the per-tx base cost of ~21 k gas.
     * @param  conversationId Off-chain UUID / slug identifying the chat thread.
     * @param  digest         keccak256(conversationSegment) computed by the backend.
     * @return recordIndex    Index of the newly created record in `records[]`.
     */
    function recordDigest(
        string calldata conversationId,
        bytes32         digest
    ) external onlyOwner returns (uint256 recordIndex) {
        // Array length before push is the 0-based index of the new element.
        recordIndex = records.length;

        records.push(DigestRecord({
            digest:         digest,
            timestamp:      block.timestamp,
            recorder:       msg.sender,       // captures server wallet for accountability
            conversationId: conversationId
        }));

        // Track which indexes belong to this thread for fast per-conversation lookup.
        conversationIndexes[conversationId].push(recordIndex);

        emit DigestRecorded(recordIndex, conversationId, digest, block.timestamp);
    }

    // -----------------------------------------------------------------------
    // View functions — free reads via eth_call, no gas cost when called off-chain
    // -----------------------------------------------------------------------

    /**
     * @notice Fetch a single record by its index.
     * @dev    Reverts with a standard Solidity out-of-bounds panic (0x32) if
     *         `idx` exceeds the current array length — callers should guard
     *         with getRecordCount() if the index is not guaranteed valid.
     * @param  idx           Record index (0-based), as returned by recordDigest().
     * @return digest         Stored keccak256 digest.
     * @return timestamp      Block timestamp when the record was created.
     * @return recorder       Address that submitted the record (the server wallet).
     * @return conversationId Off-chain thread identifier.
     */
    function getRecord(uint256 idx)
        external
        view
        returns (
            bytes32 digest,
            uint256 timestamp,
            address recorder,
            string  memory conversationId
        )
    {
        DigestRecord storage r = records[idx]; // reverts on out-of-bounds — intentional
        return (r.digest, r.timestamp, r.recorder, r.conversationId);
    }

    /**
     * @notice Return all record indexes associated with a given conversationId.
     * @dev    Callers fetch each record individually via getRecord(). Returns an
     *         empty array if no records exist for the given ID — no revert.
     * @param  conversationId Off-chain thread identifier to look up.
     * @return                Array of record indexes into `records[]`.
     */
    function getRecordsByConversation(string calldata conversationId)
        external
        view
        returns (uint256[] memory)
    {
        return conversationIndexes[conversationId];
    }

    /**
     * @notice Return the total number of records stored across all conversations.
     * @dev    Equivalent to `records.length`. Exposed as an explicit function
     *         because some ABI clients cannot read the length of a public
     *         dynamic array without a dedicated getter.
     * @return Total record count.
     */
    function getRecordCount() external view returns (uint256) {
        return records.length;
    }
}
