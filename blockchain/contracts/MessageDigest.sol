// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MessageDigest
 * @notice Immutable audit log for SecureMsg message hashes.
 *
 * @dev The backend writes keccak256(ciphertext) for each message to this
 *      contract. Because Ethereum state is append-only and publicly verifiable,
 *      any party with the ciphertext can independently confirm:
 *        1. A message with that hash existed at a specific block timestamp.
 *        2. The hash has not been altered (tamper-evidence).
 *
 *      The contract stores NO plaintext or ciphertext — only 32-byte hashes.
 *
 * Gas considerations:
 *      The backend batches multiple hashes per transaction (see redis_service.py)
 *      to reduce per-message gas cost. Use storeHashBatch() for this.
 *
 * Access control:
 *      Only the `owner` (the deploying wallet — the backend signing key) may
 *      write hashes. Reads are public.
 *
 * TODO: Consider upgrading to OpenZeppelin's Ownable2Step for safer ownership
 *       transfers before mainnet deployment.
 */

import "@openzeppelin/contracts/access/Ownable.sol";

contract MessageDigest is Ownable {

    // -----------------------------------------------------------------------
    // Events
    // -----------------------------------------------------------------------

    /**
     * @notice Emitted when a message hash is stored.
     * @param messageId  Application-level UUID of the message (bytes32 encoding)
     * @param hash       keccak256 of the message ciphertext
     * @param timestamp  Block timestamp at the time of storage
     */
    event HashStored(bytes32 indexed messageId, bytes32 indexed hash, uint256 timestamp);

    // -----------------------------------------------------------------------
    // Storage
    // -----------------------------------------------------------------------

    struct MessageRecord {
        bytes32 hash;       // keccak256(ciphertext)
        uint256 timestamp;  // block.timestamp when stored
        bool    exists;     // guard against zero-value false positives
    }

    /// @dev messageId (bytes32) => MessageRecord
    mapping(bytes32 => MessageRecord) private _records;

    // -----------------------------------------------------------------------
    // Constructor
    // -----------------------------------------------------------------------

    constructor() Ownable(msg.sender) {}

    // -----------------------------------------------------------------------
    // Write functions (owner only)
    // -----------------------------------------------------------------------

    /**
     * @notice Store a single message hash on-chain.
     * @param messageId  UUID of the message, ABI-encoded as bytes32
     * @param hash       keccak256(ciphertext) computed by the backend
     */
    function storeHash(bytes32 messageId, bytes32 hash) external onlyOwner {
        require(!_records[messageId].exists, "MessageDigest: hash already stored");
        _records[messageId] = MessageRecord({
            hash: hash,
            timestamp: block.timestamp,
            exists: true
        });
        emit HashStored(messageId, hash, block.timestamp);
    }

    /**
     * @notice Batch-store multiple hashes in a single transaction to save gas.
     *         Arrays must be the same length; reverts if any messageId is a duplicate.
     * @param messageIds  Array of message UUIDs
     * @param hashes      Corresponding keccak256 hashes
     *
     * TODO: Implement — iterate and call _storeOne() for each pair.
     */
    function storeHashBatch(
        bytes32[] calldata messageIds,
        bytes32[] calldata hashes
    ) external onlyOwner {
        require(messageIds.length == hashes.length, "MessageDigest: length mismatch");
        // TODO: Loop and store each pair
        revert("MessageDigest: storeHashBatch not implemented yet");
    }

    // -----------------------------------------------------------------------
    // Read functions (public)
    // -----------------------------------------------------------------------

    /**
     * @notice Retrieve the stored record for a message.
     * @param messageId  UUID of the message
     * @return hash       The stored keccak256 hash (bytes32 zero if not found)
     * @return timestamp  Block timestamp when stored
     * @return exists     False if no record has been stored for this messageId
     */
    function getRecord(bytes32 messageId)
        external
        view
        returns (bytes32 hash, uint256 timestamp, bool exists)
    {
        MessageRecord storage r = _records[messageId];
        return (r.hash, r.timestamp, r.exists);
    }

    /**
     * @notice Convenience function — returns true if the supplied hash matches
     *         what is stored on-chain for the given messageId.
     * @param messageId  UUID of the message
     * @param hash       Hash to verify against the stored value
     */
    function verifyHash(bytes32 messageId, bytes32 hash) external view returns (bool) {
        MessageRecord storage r = _records[messageId];
        return r.exists && r.hash == hash;
    }
}
