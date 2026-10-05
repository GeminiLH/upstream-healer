#!/usr/bin/env python3
"""
Helper script to clean up E2E test data from the database.
This is used by E2E tests to ensure clean state before/after testing.
"""

import asyncio
import aiosqlite
from app.config import settings

async def cleanup_e2e_test_data():
    """Remove any test hosts that were created during E2E testing"""
    async with aiosqlite.connect(settings.db_path) as db:
        # Remove hosts with test names or MAC addresses
        await db.execute("DELETE FROM hosts WHERE name LIKE 'e2e-%' OR name LIKE 'test-%'")
        
        # Remove hosts with specific test MAC addresses 
        test_macs = [
            "AA:BB:CC:DD:EE:90",
            "AA:BB:CC:DD:EE:99", 
            "AA:BB:CC:DD:EE:A0",
            "AA:BB:CC:DD:EE:B0"
        ]
        
        for mac in test_macs:
            await db.execute("DELETE FROM hosts WHERE mac_address = ?", (mac,))
            
        # Remove host_state entries for test hosts
        await db.execute("DELETE FROM host_state WHERE host_id IN (SELECT id FROM hosts WHERE name LIKE 'e2e-%' OR name LIKE 'test-%')")
        
        await db.commit()
        print("✅ Cleaned up E2E test data from database")

if __name__ == "__main__":
    asyncio.run(cleanup_e2e_test_data())