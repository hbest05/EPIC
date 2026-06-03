# EPIC — Cover Document

**Group Name:** Alpha and the Cryptmunks (Team 3)  
**Project URL:** https://alpha-and-the-cryptmunks.theburkenator.com/ 
**GitHub Repository:** https://github.com/hbest05/EPIC

---

## Group Members

| Full Name | Student ID |
|---|---|
| Holly Best | [24411566] |
| Matthew Burke | [24416827] |
| Julia Hooper | [24430706] |

---

## Contribution Breakdown

### Holly Best — ~33%

- Signal Protocol ORM models and database layer
- REST API auth and messages endpoints
- CSRF middleware and security headers middleware
- X3DH + Double Ratchet crypto layer for the web client
- Message download, deletion, forwarding endpoints
- Download messages, delete, and forward features in C++ client
- WebSocket message deletion propagation to recipient
- Initial Alembic migration and SQLAlchemy schema

### Matthew Burke — ~33%

- Initial project scaffold
- Python crypto daemon — X3DH + Double Ratchet implementation
- C++ Qt6 desktop client — TLS verifier, crypto daemon IPC, login/register UI
- STL refactor of C++ client — `User`, `Message`, `MessageStore` with STL containers and algorithms
- TOFU key pinning in C++ client
- WebSocket real-time messaging
- Message persistence with local cache, pagination, sent endpoint
- Revoke access — per-message delete-for-recipient with WebSocket notification
- Change password endpoint and Qt UI with session re-encryption
- DoS fix on Double Ratchet skip loops
- Cryptographic design document

### Julia Hooper — ~33%

- Web frontend — full SecureMsg web client including auth flow, messaging UI, styles
- Blockchain verification page — standalone, unauthenticated, hash comparison with pass/fail display
- Public blockchain verify endpoint
- Batch processing for blockchain message records
- Conversation revocation and message forwarding in frontend
- Three-dot message bubble menu with delete, revoke, forward modals
- Key wrapping and unwrapping for at-rest key protection
- Signal Protocol Alembic migrations (IF NOT EXISTS safe, merged divergent heads)
- Docker and deployment fixes
- Rate limiting for authentication endpoints
- Key fingerprint display and clipboard functionality

---
