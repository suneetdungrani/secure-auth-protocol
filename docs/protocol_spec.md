# Authentication Protocol Specification

**Author: Suneet Dungrani**

## Protocol Overview

This document specifies a challenge-response authentication protocol with mutual authentication and forward secrecy. The protocol has been formally verified using TLA+ model checking.

## Protocol Participants

- **Client (C)**: Entity requesting authentication
- **Server (S)**: Authentication server with credential database

## Cryptographic Primitives

- **H()**: Cryptographic hash function (SHA-256)
- **E(k, m)**: Symmetric encryption using key k on message m (AES-256-GCM)
- **MAC(k, m)**: Message authentication code using key k on message m (HMAC-SHA256)
- **DH()**: Diffie-Hellman key exchange

## Protocol Steps

### Phase 1: Initial Handshake
1. C → S: ClientHello(client_id, nonce_c)
2. S → C: ServerHello(server_id, nonce_s, dh_params)

### Phase 2: Key Exchange
3. C → S: ClientKeyExchange(dh_public_c, E(pre_master_secret, client_proof))
4. S → C: ServerKeyExchange(dh_public_s, E(pre_master_secret, server_proof))

### Phase 3: Verification
5. C → S: ClientVerify(MAC(session_key, transcript))
6. S → C: ServerVerify(MAC(session_key, transcript), session_token)

## Security Properties

### 1. Mutual Authentication
- Client authenticates server through server_proof verification
- Server authenticates client through client_proof verification

### 2. Forward Secrecy
- Session keys derived from ephemeral Diffie-Hellman exchange
- Compromise of long-term keys doesn't reveal past sessions

### 3. Replay Protection
- Fresh nonces in each session prevent replay attacks
- Session binding through transcript hashing

### 4. Key Confirmation
- Both parties prove possession of derived session key
- MAC verification ensures key agreement

## Formal Verification Properties

The following properties have been formally verified in TLA+:

### Safety Properties
- **NoUnauthorizedAccess**: Only authenticated clients receive session tokens
- **UniqueSessionKeys**: Each session has a unique key
- **CorrectAuthentication**: Parties authenticate intended counterparts

### Liveness Properties
- **EventualCompletion**: Protocol completes under fair scheduling
- **ProgressGuarantee**: Each step leads to protocol advancement

### Security Invariants
- **KeySecrecy**: Session keys known only to participants
- **NonceUniqueness**: Nonces never repeat across sessions
- **TranscriptIntegrity**: Protocol transcript cannot be tampered

## Threat Model

The protocol defends against:
- Passive eavesdropping
- Active man-in-the-middle attacks
- Replay attacks
- Key compromise impersonation
- Forward secrecy violations

## Implementation Notes

1. All random values must use cryptographically secure generators
2. Constant-time comparisons for MAC verification
3. Proper key derivation using HKDF
4. Session state cleanup after completion or timeout