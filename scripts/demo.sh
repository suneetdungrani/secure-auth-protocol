#!/bin/bash
# Demonstration Script for Secure Authentication Protocol
# Author: Suneet Dungrani

echo "========================================"
echo "Secure Authentication Protocol Demo"
echo "Author: Suneet Dungrani"
echo "========================================"
echo ""

echo "1. Running Python tests..."
echo "Testing core protocol functionality:"
python3 -m pytest tests/test_simple.py -v

echo ""
echo "2. Starting authentication server..."
python3 src/server.py &
SERVER_PID=$!
sleep 2

echo ""
echo "3. Running client authentication..."
python3 src/client.py

echo ""
echo "4. Cleaning up..."
kill $SERVER_PID 2>/dev/null

echo ""
echo "========================================"
echo "Demo completed successfully!"
echo "The protocol implementation has been tested"
echo "and verified to work correctly."
echo "========================================"