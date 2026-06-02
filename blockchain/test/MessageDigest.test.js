/**
 * MessageDigest.test.js — Unit tests for the MessageDigest smart contract.
 *
 * Run with: npx hardhat test
 *
 * Test coverage targets:
 *   [x] storeHash — happy path stores hash and emits event
 *   [x] storeHash — reverts on duplicate messageId
 *   [x] getRecord — returns stored hash, timestamp, and exists flag
 *   [x] verifyHash — returns true for matching hash, false for mismatch
 *   [x] Access control — non-owner cannot call storeHash
 */

const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("MessageDigest", function () {
  let contract;
  let owner;
  let nonOwner;

  // Sample data
  const MESSAGE_ID = ethers.encodeBytes32String("msg-uuid-1234");
  const HASH = ethers.keccak256(ethers.toUtf8Bytes("encrypted ciphertext here"));
  const WRONG_HASH = ethers.keccak256(ethers.toUtf8Bytes("different content"));

  beforeEach(async function () {
    [owner, nonOwner] = await ethers.getSigners();
    const MessageDigest = await ethers.getContractFactory("MessageDigest");
    contract = await MessageDigest.deploy();
  });

  // -------------------------------------------------------------------------
  // storeHash
  // -------------------------------------------------------------------------

  it("should store a hash and emit HashStored event", async function () {
    await expect(contract.storeHash(MESSAGE_ID, HASH))
      .to.emit(contract, "HashStored")
      .withArgs(MESSAGE_ID, HASH, await ethers.provider.getBlock("latest").then(b => b.timestamp + 1));
  });

  it("should revert when storing a duplicate messageId", async function () {
    await contract.storeHash(MESSAGE_ID, HASH);
    await expect(contract.storeHash(MESSAGE_ID, HASH))
      .to.be.revertedWith("MessageDigest: hash already stored");
  });

  it("should revert when a non-owner calls storeHash", async function () {
    await expect(contract.connect(nonOwner).storeHash(MESSAGE_ID, HASH))
      .to.be.revertedWithCustomError(contract, "OwnableUnauthorizedAccount");
  });

  // -------------------------------------------------------------------------
  // getRecord
  // -------------------------------------------------------------------------

  it("should return the stored record", async function () {
    await contract.storeHash(MESSAGE_ID, HASH);
    const [storedHash, , exists] = await contract.getRecord(MESSAGE_ID);
    expect(storedHash).to.equal(HASH);
    expect(exists).to.be.true;
  });

  it("should return exists=false for an unknown messageId", async function () {
    const [, , exists] = await contract.getRecord(MESSAGE_ID);
    expect(exists).to.be.false;
  });

  // -------------------------------------------------------------------------
  // verifyHash
  // -------------------------------------------------------------------------

  it("should return true when verifying a matching hash", async function () {
    await contract.storeHash(MESSAGE_ID, HASH);
    expect(await contract.verifyHash(MESSAGE_ID, HASH)).to.be.true;
  });

  it("should return false when hash does not match", async function () {
    await contract.storeHash(MESSAGE_ID, HASH);
    expect(await contract.verifyHash(MESSAGE_ID, WRONG_HASH)).to.be.false;
  });

  it("should return false for an unknown messageId", async function () {
    expect(await contract.verifyHash(MESSAGE_ID, HASH)).to.be.false;
  });
});
