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

    struct BatchRecord {
        bytes32 digest;          // keccak256 of the sorted JSON batch payload
        uint256 timestamp;       // block.timestamp at recording
        address recorder;        // msg.sender — proof of submitting wallet
        string  conversationId;  // off-chain thread ID
        uint256 messageCount;    // number of messages included in this batch
    }

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    /// @notice All records in insertion order. Index == recordIndex returned by recordDigest().
    DigestRecord[] public records;

    /// @notice Maps each conversationId to its list of record indexes in `records[]`.
    ///         Allows O(1) append and O(n) lookup per thread without full array scans.
    mapping(string => uint256[]) public conversationIndexes;

    /// @notice All batch records in insertion order. Index == batchIndex returned by recordBatch().
    BatchRecord[] public batches;

    /// @notice Maps each conversationId to its list of batch indexes in `batches[]`.
    mapping(string => uint256[]) public conversationBatchIndexes;

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

    /**
     * @notice Emitted on every successful call to recordBatch().
     * @param batchIndex     Index into `batches[]` — stable, never changes.
     * @param conversationId Off-chain thread ID (indexed for log filtering).
     * @param digest         keccak256 of the JSON-encoded batch payload.
     * @param messageCount   Number of messages included in this batch.
     * @param timestamp      Block timestamp at the time of recording.
     */
    event BatchDigestRecorded(
        uint256 indexed batchIndex,
        string  indexed conversationId,
        bytes32         digest,
        uint256         messageCount,
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
     * @param  conversationId Off-chain UUID / slug identifying the chat thread.
     * @param  digest         keccak256(conversationSegment) computed by the backend.
     * @return recordIndex    Index of the newly created record in `records[]`.
     */
    function recordDigest(
        string calldata conversationId,
        bytes32         digest
    ) external onlyOwner returns (uint256 recordIndex) {
        recordIndex = records.length;

        records.push(DigestRecord({
            digest:         digest,
            timestamp:      block.timestamp,
            recorder:       msg.sender,
            conversationId: conversationId
        }));

        conversationIndexes[conversationId].push(recordIndex);

        emit DigestRecorded(recordIndex, conversationId, digest, block.timestamp);
    }

    /**
     * @notice Record a keccak256 digest of a batch of messages on-chain.
     * @dev    One transaction covers up to BATCH_SIZE messages, amortising the
     *         ~21 k base gas cost. The digest is keccak256 of a deterministic
     *         JSON encoding of the batch produced by the Python backend.
     * @param  conversationId Off-chain UUID identifying the chat thread.
     * @param  digest         keccak256(batchJSON) computed by the backend.
     * @param  messageCount   Number of messages included in the batch.
     * @return batchIndex     Index of the newly created batch in `batches[]`.
     */
    function recordBatch(
        string calldata conversationId,
        bytes32         digest,
        uint256         messageCount
    ) external onlyOwner returns (uint256 batchIndex) {
        batchIndex = batches.length;

        batches.push(BatchRecord({
            digest:         digest,
            timestamp:      block.timestamp,
            recorder:       msg.sender,
            conversationId: conversationId,
            messageCount:   messageCount
        }));

        conversationBatchIndexes[conversationId].push(batchIndex);

        emit BatchDigestRecorded(batchIndex, conversationId, digest, messageCount, block.timestamp);
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
        DigestRecord storage r = records[idx];
        return (r.digest, r.timestamp, r.recorder, r.conversationId);
    }

    /**
     * @notice Fetch a single batch record by its index.
     * @param  idx           Batch index (0-based), as returned by recordBatch().
     * @return digest         Stored keccak256 digest of the batch payload.
     * @return timestamp      Block timestamp when the batch was recorded.
     * @return recorder       Address that submitted the batch.
     * @return conversationId Off-chain thread identifier.
     * @return messageCount   Number of messages in the batch.
     */
    function getBatch(uint256 idx)
        external
        view
        returns (
            bytes32 digest,
            uint256 timestamp,
            address recorder,
            string  memory conversationId,
            uint256 messageCount
        )
    {
        BatchRecord storage b = batches[idx];
        return (b.digest, b.timestamp, b.recorder, b.conversationId, b.messageCount);
    }

    /**
     * @notice Return all record indexes associated with a given conversationId.
     * @dev    Returns an empty array if no records exist for the given ID — no revert.
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
     * @return Total record count.
     */
    function getRecordCount() external view returns (uint256) {
        return records.length;
    }

    /**
     * @notice Return the total number of batch records stored.
     * @return Total batch count.
     */
    function getBatchCount() external view returns (uint256) {
        return batches.length;
    }
}
