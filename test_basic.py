#!/usr/bin/env python3
"""
Basic test script to verify SplitSmart functionality.
"""

from server.server import SplitSmartServer
from client.client import SplitSmartClient

def test_basic():
    print("=" * 80)
    print("Testing SplitSmart Basic Functionality")
    print("=" * 80)
    
    # Initialize server
    print("\n1. Initializing server...")
    server = SplitSmartServer()
    print("✓ Server initialized")
    
    # Register users
    print("\n2. Registering users...")
    alice = SplitSmartClient("alice", server)
    alice.register()
    print("✓ Alice registered")
    
    bob = SplitSmartClient("bob", server)
    bob.register()
    print("✓ Bob registered")
    
    # Login
    print("\n3. Establishing secure sessions...")
    alice.login()
    print("✓ Alice logged in")
    
    bob.login()
    print("✓ Bob logged in")
    
    # Add expenses
    print("\n4. Adding expenses...")
    alice.add_expense("alice", 60.00, "Dinner")
    bob.add_expense("bob", 40.00, "Groceries")
    
    # View ledger
    print("\n5. Viewing ledger...")
    alice.view_ledger()
    
    # View balances
    print("\n6. Viewing balances...")
    alice.view_balances()
    
    print("\n" + "=" * 80)
    print("✓ All tests passed!")
    print("=" * 80)

if __name__ == "__main__":
    test_basic()
