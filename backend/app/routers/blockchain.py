"""
Blockchain router — query on-chain audit trail for messages.

Endpoints:
  GET /api/blockchain/status/{message_id}
      -> Return the blockchain confirmation status and tx hash for a message

  GET /api/blockchain/verify/{message_id}
      -> Re-query the MessageDigest contract on Sepolia to verify the stored hash
         matches what is in the DB (tamper-evidence check)

  POST /api/blockchain/queue/flush  (admin only)
      -> Manually trigger the Redis queue worker to flush pending hashes on-chain
"""

from fastapi import APIRouter, Depends, HTTPException

from app.schemas.message import BlockchainStatusResponse
from app.services import auth_service

router = APIRouter()


@router.get("/status/{message_id}", response_model=BlockchainStatusResponse)
async def blockchain_status(
    message_id: str,
    current_user=Depends(auth_service.get_current_user),
):
    """
    TODO:
    - Lookup Message by ID (check ownership)
    - Return keccak256_hash, blockchain_confirmed, tx_hash
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")


@router.get("/verify/{message_id}")
async def verify_on_chain(
    message_id: str,
    current_user=Depends(auth_service.get_current_user),
):
    """
    TODO:
    - Fetch Message from DB
    - Call web3.py to query MessageDigest.getHash(message_id) on Sepolia
    - Compare returned hash to DB value
    - Return {verified: bool, on_chain_hash: str, db_hash: str}
    """
    raise HTTPException(status_code=501, detail="Not implemented yet")
