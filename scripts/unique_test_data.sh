#!/bin/bash
# Generate unique test data for E2E tests

# Generate unique MAC address (using timestamp to make it unique)
UNIQUE_MAC="AA:BB:CC:DD:EE:$(printf '%02x' $((RANDOM % 256)))"
echo "MAC:$UNIQUE_MAC"

# Generate unique IP address
UNIQUE_IP="192.168.$((RANDOM % 100 + 100)).$((RANDOM % 254 + 1))"
echo "IP:$UNIQUE_IP"

# Generate unique name 
UNIQUE_NAME="e2e-test-$(date +%s)"
echo "NAME:$UNIQUE_NAME"