# Formal Verification of a Security-Critical Authentication Protocol

**Author: Suneet Dungrani**

## Overview

This project demonstrates the formal verification of a custom challenge-response authentication protocol using TLA+ and model checking. Unlike traditional testing approaches that validate behavior for specific inputs, this project mathematically proves the protocol's correctness for all possible execution scenarios.

## Project Structure

```
secure-auth-protocol/
├── src/                    # Python implementation
│   ├── protocol.py        # Core authentication protocol
│   ├── server.py          # Authentication server
│   └── client.py          # Client implementation
├── tla/                   # TLA+ specifications
│   ├── AuthProtocol.tla   # Main protocol specification
│   └── MC.tla             # Model checking configuration
├── scripts/               # Verification scripts
│   └── verify.sh          # Run TLA+ model checker
├── tests/                 # Protocol tests
│   └── test_protocol.py   # Python unit tests
├── docs/                  # Documentation
│   └── protocol_spec.md   # Protocol specification
├── Dockerfile             # Docker environment
└── requirements.txt       # Python dependencies
```

## The Protocol

The verified protocol is a challenge-response authentication system with the following properties:
- Mutual authentication between client and server
- Protection against replay attacks using nonces
- Forward secrecy through session keys
- Formal guarantees of authentication and secrecy

## Formal Verification Approach

1. **Mathematical Model**: The protocol is modeled as a state machine in TLA+
2. **Security Properties**: Defined as temporal logic formulas
3. **Model Checking**: Exhaustive state-space exploration to verify properties
4. **Proof of Correctness**: Mathematical guarantee of protocol security

## Key Security Properties Verified

- **Authentication**: Both parties correctly identify each other
- **Secrecy**: Session keys remain confidential
- **Liveness**: Protocol completes under fair scheduling
- **Safety**: No security violations in any execution path

## Running the Project

### Using Docker (Recommended)

```bash
docker build -t secure-auth-protocol .
docker run -it secure-auth-protocol
```

### Manual Setup

1. Install TLA+ tools (TLC model checker)
2. Install Python dependencies: `pip install -r requirements.txt`
3. Run verification: `./scripts/verify.sh`
4. Run tests: `python -m pytest tests/`

## Technical Stack

- **Formal Methods**: TLA+ for specification and verification
- **Model Checker**: TLC (TLA+ model checker)
- **Implementation**: Python 3.9+
- **Cryptography**: Python cryptography library
- **Containerization**: Docker


## License

This project is licensed under the MIT License.
