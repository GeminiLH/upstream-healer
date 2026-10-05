#!/usr/bin/env python3
"""
Generate unique identifiers for E2E tests
"""

import random
import time

def generate_unique_mac():
    """Generate a unique MAC address for testing"""
    # Use timestamp and random to make it unique
    timestamp = int(time.time()) % 256
    return f"AA:BB:CC:DD:EE:{timestamp:02x}"

def generate_unique_ip():
    """Generate a unique IP address for testing"""
    # Generate a random IP in the 192.168.x.x range 
    return f"192.168.{random.randint(100, 200)}.{random.randint(1, 254)}"

def generate_unique_name():
    """Generate a unique test name"""
    timestamp = int(time.time())
    return f"e2e-test-{timestamp}"

if __name__ == "__main__":
    print(f"MAC: {generate_unique_mac()}")
    print(f"IP: {generate_unique_ip()}")
    print(f"Name: {generate_unique_name()}")