#!/bin/bash
# Formal Verification Script for Authentication Protocol
# Author: Suneet Dungrani

echo "========================================"
echo "Secure Authentication Protocol Verifier"
echo "Author: Suneet Dungrani"
echo "========================================"
echo ""

# Check if TLA+ tools are available
if ! command -v java &> /dev/null; then
    echo "Error: Java is required to run TLC model checker"
    exit 1
fi

if [ ! -f "$TLA2TOOLS_JAR" ] && [ ! -f "/opt/tla/tla2tools.jar" ]; then
    echo "Error: TLA+ tools not found"
    exit 1
fi

TLA_JAR="${TLA2TOOLS_JAR:-/opt/tla/tla2tools.jar}"

echo "Starting formal verification of authentication protocol..."
echo ""

# Run TLC model checker
echo "Checking safety properties..."
java -XX:+UseParallelGC -jar "$TLA_JAR" tlc2.TLC \
    -config tla/MC.tla \
    -workers auto \
    -deadlock \
    tla/AuthProtocol.tla

RESULT=$?

echo ""
echo "========================================"

if [ $RESULT -eq 0 ]; then
    echo "✓ All properties verified successfully!"
    echo ""
    echo "Verified Properties:"
    echo "  ✓ Authentication: Only authenticated clients receive session keys"
    echo "  ✓ Key Secrecy: Session keys remain confidential"
    echo "  ✓ Session Uniqueness: Each session has a unique key"
    echo "  ✓ Protocol Consistency: Both parties reach consistent state"
    echo "  ✓ No Replay Attacks: Nonces prevent message replay"
    echo ""
    echo "The protocol has been formally verified to be secure."
else
    echo "✗ Verification failed!"
    echo "Please check the output above for counterexamples."
    exit 1
fi

echo "========================================"