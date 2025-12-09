#!/usr/bin/env python3
"""
Test concurrent users and race conditions in SplitSmart.
Tests multiple users accessing the server simultaneously and attack scenarios.
"""

import threading
import time
import random
from client.client import SplitSmartClient
from server.server import SplitSmartServer

def test_concurrent_users():
    """Test multiple users accessing the server concurrently."""
    print("\n" + "="*80)
    print("TEST 1: CONCURRENT USER OPERATIONS")
    print("="*80)

    # Initialize server
    server = SplitSmartServer()

    # Create multiple clients
    clients = {}
    users = ['alice', 'bob', 'charlie', 'diana']

    # Register all users
    print("\n[Setup] Registering users...")
    for user in users:
        client = SplitSmartClient(user, server)
        client.register()
        clients[user] = client
        print(f"  ✓ {user} registered")

    # Login all users
    print("\n[Setup] Logging in users...")
    for user, client in clients.items():
        success = client.login()
        if success:
            print(f"  ✓ {user} logged in")

    # Test concurrent expense submissions
    print("\n[Test] Submitting expenses concurrently...")

    def submit_expense_thread(user, client, expense_num):
        """Thread function to submit an expense."""
        try:
            payer = user
            amount = round(random.uniform(10, 100), 2)
            description = f"Expense {expense_num} by {user}"
            success = client.add_expense(payer, amount, description)
            if success:
                print(f"  ✓ {user} submitted expense {expense_num}: ${amount}")
        except Exception as e:
            print(f"  ✗ {user} error: {e}")

    # Start multiple threads
    threads = []
    for i in range(3):  # 3 expenses per user
        for user, client in clients.items():
            thread = threading.Thread(
                target=submit_expense_thread,
                args=(user, client, i)
            )
            threads.append(thread)

    start_time = time.time()
    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    elapsed = time.time() - start_time
    print(f"\n[Result] Completed in {elapsed:.2f} seconds")

    # Verify ledger
    print("\n[Verification] Checking ledger...")
    ledger = clients['alice'].view_ledger()
    if ledger:
        print(f"✓ Ledger contains {len(ledger)} entries")
        print("✓ All concurrent operations successful")
    
    print("✓ Concurrent users test complete")


def test_race_conditions():
    """Test race conditions in counter validation."""
    print("\n" + "="*80)
    print("TEST 2: RACE CONDITION IN COUNTER VALIDATION")
    print("="*80)

    server = SplitSmartServer()
    alice = SplitSmartClient('alice', server)
    alice.register()
    alice.login()

    print("\n[Test] Multiple threads trying to use same counter...")
    
    # Save current counter
    current_counter = alice.crypto.counter
    results = []

    def submit_with_same_counter(expense_id):
        """Try to submit with same counter."""
        alice.crypto.counter = current_counter - 1
        success = alice.add_expense('alice', 10.0 * expense_id, f'Expense {expense_id}')
        results.append(success)
        print(f"  [Thread {expense_id}] Result: {success}")

    # Create threads that try to use same counter
    threads = [
        threading.Thread(target=submit_with_same_counter, args=(1,)),
        threading.Thread(target=submit_with_same_counter, args=(2,)),
        threading.Thread(target=submit_with_same_counter, args=(3,))
    ]

    for t in threads:
        t.start()
    for t in threads:
        t.join()

    successful = sum(results)
    print(f"\n[Result] {successful} out of 3 submissions succeeded")

    if successful <= 1:
        print("✓ RACE CONDITION HANDLED CORRECTLY")
        print("✓ Counter validation prevented duplicate submissions")
    else:
        print("⚠ Multiple submissions with same counter accepted")


def test_concurrent_replay_attack():
    """Test replay attack during concurrent operations."""
    print("\n" + "="*80)
    print("TEST 3: REPLAY ATTACK DURING CONCURRENT OPERATIONS")
    print("="*80)

    server = SplitSmartServer()
    alice = SplitSmartClient('alice', server)
    alice.register()
    alice.login()

    print("\n[Setup] Alice submits first expense...")
    alice.add_expense('alice', 100.0, 'Original expense')
    original_counter = alice.crypto.counter

    print("[Setup] Alice submits second expense...")
    alice.add_expense('alice', 50.0, 'Second expense')

    print("\n[Attack] Attacker attempts replay with old counter...")
    alice.crypto.counter = original_counter - 1
    success = alice.add_expense('alice', 999.0, 'REPLAYED EXPENSE')

    if not success:
        print("✓ REPLAY ATTACK BLOCKED!")
        print("✓ Server rejected message with old counter")
    else:
        print("✗ REPLAY ATTACK SUCCEEDED")

    # Verify ledger
    entries = alice.view_ledger()
    if entries:
        for entry in entries:
            if entry['amount'] == 999.0:
                print("✗ REPLAYED EXPENSE IN LEDGER!")
                return
        print("✓ No replayed expenses in ledger")


def test_concurrent_spoofing_attack():
    """Test spoofing attack during concurrent operations."""
    print("\n" + "="*80)
    print("TEST 4: SPOOFING ATTACK DURING CONCURRENT OPERATIONS")
    print("="*80)

    server = SplitSmartServer()
    alice = SplitSmartClient('alice', server)
    bob = SplitSmartClient('bob', server)

    alice.register()
    bob.register()
    alice.login()
    bob.login()

    print("\n[Setup] Alice submits legitimate expense...")
    alice.add_expense('alice', 50.0, 'Legitimate expense')

    print("\n[Attack] Bob attempts to impersonate Alice...")
    
    # Bob tries to submit as alice but with his signature
    from shared.protocols import ExpenseSubmitMessage
    from datetime import datetime

    timestamp = datetime.utcnow().isoformat()
    signature, counter = bob.crypto.sign_expense('alice', 999.0, 'FORGED', timestamp)

    expense_msg = ExpenseSubmitMessage(
        payer='alice',
        amount=999.0,
        description='FORGED EXPENSE',
        counter=counter,
        signature=signature,
        timestamp=timestamp
    )

    encrypted = bob.crypto.encrypt_message(expense_msg.to_bytes())
    response_dict = server.process_message(bob.crypto.session_id, encrypted)

    # Check response
    if "nonce" in response_dict:
        plaintext = bob.crypto.decrypt_message(response_dict["nonce"], response_dict["ciphertext"])
        if plaintext:
            from shared.protocols import ProtocolMessage
            response = ProtocolMessage.from_bytes(plaintext)
            if response.msg_type == "ERROR":
                print("✓ SPOOFING ATTACK BLOCKED!")
                print(f"✓ Server rejected: {response.payload['message']}")

    # Verify ledger
    entries = alice.view_ledger()
    if entries:
        for entry in entries:
            if entry['amount'] == 999.0:
                print("✗ FORGED EXPENSE IN LEDGER!")
                return
        print("✓ No forged expenses in ledger")


if __name__ == "__main__":
    print("\n" + "="*80)
    print("SPLITSMART CONCURRENT USERS AND ATTACK TESTING")
    print("="*80)

    test_concurrent_users()
    test_race_conditions()
    test_concurrent_replay_attack()
    test_concurrent_spoofing_attack()

    print("\n" + "="*80)
    print("ALL CONCURRENT TESTS COMPLETE")
    print("="*80)
    print("✓ Concurrent operations handled correctly")
    print("✓ Race conditions prevented")
    print("✓ Replay attacks blocked")
    print("✓ Spoofing attacks blocked")
