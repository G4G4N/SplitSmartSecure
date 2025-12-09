#!/usr/bin/env python3
"""
SplitSmart CLI - Command-line interface for manual testing and demonstrations.
Run commands directly from terminal without writing Python code.
"""

import sys
import argparse
from client.client import SplitSmartClient
from server.server import SplitSmartServer

# Global server instance
server = None
clients = {}
verbose = False

def init_server():
    """Initialize server if not already initialized."""
    global server
    if server is None:
        server = SplitSmartServer()
        print("[CLI] Server initialized")
    return server

def get_client(user_id):
    """Get or create client for user."""
    if user_id not in clients:
        clients[user_id] = SplitSmartClient(user_id, init_server())
    return clients[user_id]

def cmd_register(args):
    """Register a new user."""
    if verbose:
        print(f"\n[CRYPTO] Generating RSA-2048 key pair for '{args.user}'...")
    
    client = get_client(args.user)
    
    if verbose:
        print(f"[CRYPTO] Public key generated (2048-bit RSA)")
        print(f"[CRYPTO] Private key stored securely in keys/{args.user}_private.pem")
        print(f"[CRYPTO] Sending public key to server...")
    
    success = client.register()
    
    if success:
        print(f"✓ User '{args.user}' registered successfully")
        if verbose:
            print(f"[CRYPTO] Server stored public key for signature verification")
            print(f"[CRYPTO] Counter initialized to 0 for replay protection")
    else:
        print(f"✗ User '{args.user}' already exists")

def cmd_login(args):
    """Login user (establish secure session)."""
    if verbose:
        print(f"\n[CRYPTO] Starting Signed Diffie-Hellman key exchange...")
        print(f"[CRYPTO] Client generates ephemeral DH key pair (2048-bit)")
        print(f"[CRYPTO] Client signs DH public key with RSA private key")
        print(f"[CRYPTO] Sending ClientHello with DH public key + signature")
    
    client = get_client(args.user)
    success = client.login()
    
    if success:
        print(f"✓ User '{args.user}' logged in")
        print(f"  Session ID: {client.crypto.session_id}")
        if verbose:
            print(f"[CRYPTO] Server verified client signature with public key")
            print(f"[CRYPTO] Server generated ephemeral DH key pair")
            print(f"[CRYPTO] Server signed DH public key with server private key")
            print(f"[CRYPTO] Client verified server signature")
            print(f"[CRYPTO] Both computed shared secret via DH")
            print(f"[CRYPTO] Session key derived: K_session = HKDF-SHA256(shared_secret)")
            print(f"[CRYPTO] Session key: 256-bit AES key for encryption")
            print(f"[CRYPTO] ✓ Secure channel established with mutual authentication")
    else:
        print(f"✗ Login failed for '{args.user}'")

def cmd_add_expense(args):
    """Add an expense."""
    client = get_client(args.user)
    if not client.crypto.has_session():
        print(f"✗ User '{args.user}' not logged in. Run: cli.py login {args.user}")
        return
    
    if verbose:
        print(f"\n[CRYPTO] Creating expense record...")
        print(f"[CRYPTO] Counter incremented: {client.crypto.counter} → {client.crypto.counter + 1}")
        print(f"[CRYPTO] Signing expense with RSA-PSS (user's private key)")
        print(f"[CRYPTO] Signature algorithm: RSA-PSS with SHA-256")
        print(f"[CRYPTO] Encrypting message with AES-256-GCM")
        print(f"[CRYPTO] Generating random 96-bit nonce")
        print(f"[CRYPTO] Computing authentication tag (128-bit)")
    
    success = client.add_expense(args.payer, args.amount, args.description)
    
    if success:
        print(f"✓ Expense added: {args.payer} paid ${args.amount} for '{args.description}'")
        if verbose:
            print(f"[CRYPTO] Server decrypted message with session key")
            print(f"[CRYPTO] Server verified authentication tag (integrity check)")
            print(f"[CRYPTO] Server verified user signature (authentication)")
            print(f"[CRYPTO] Server checked counter (replay protection)")
            print(f"[CRYPTO] Computing hash: H = SHA256(prev_hash || entry_data)")
            print(f"[CRYPTO] Entry added to hash chain")
            print(f"[CRYPTO] Server generated cryptographic receipt")
            print(f"[CRYPTO] Receipt signed with server's private key")
    else:
        print(f"✗ Failed to add expense")

def cmd_view_ledger(args):
    """View the ledger."""
    client = get_client(args.user)
    if not client.crypto.has_session():
        print(f"✗ User '{args.user}' not logged in. Run: cli.py login {args.user}")
        return
    
    client.view_ledger()

def cmd_view_balances(args):
    """View balances."""
    client = get_client(args.user)
    if not client.crypto.has_session():
        print(f"✗ User '{args.user}' not logged in. Run: cli.py login {args.user}")
        return
    
    client.view_balances()

def cmd_list_users(args):
    """List all registered users."""
    init_server()
    users = server.list_users()
    print(f"\nRegistered users ({len(users)}):")
    for user in users:
        print(f"  - {user}")

def cmd_verify_ledger(args):
    """Verify ledger integrity."""
    init_server()
    
    if verbose:
        print(f"\n[CRYPTO] Verifying hash chain integrity...")
        print(f"[CRYPTO] Starting with genesis hash")
        entries = server.ledger.get_all_entries()
        print(f"[CRYPTO] Recomputing hashes for {len(entries)} entries")
        print(f"[CRYPTO] For each entry: H_n = SHA256(H_(n-1) || entry_data)")
    
    is_valid, msg = server.ledger.verify_chain_integrity()
    
    if is_valid:
        entries = server.ledger.get_all_entries()
        print(f"✓ Ledger integrity verified ({len(entries)} entries)")
        if verbose:
            print(f"[CRYPTO] All computed hashes match stored hashes")
            print(f"[CRYPTO] No tampering detected")
            print(f"[CRYPTO] Hash chain is valid")
    else:
        print(f"✗ Ledger integrity violation: {msg}")
        if verbose:
            print(f"[CRYPTO] Hash mismatch detected!")
            print(f"[CRYPTO] Database has been tampered with")

def cmd_show_counter(args):
    """Show user's counter."""
    init_server()
    client = get_client(args.user)
    server_counter = server.storage.get_user_counter(args.user)
    print(f"\nCounter for '{args.user}':")
    print(f"  Client counter: {client.crypto.counter}")
    print(f"  Server counter: {server_counter}")

def cmd_demo_quick(args):
    """Run quick demo with 3 users and expenses."""
    print("\n=== QUICK DEMO ===\n")
    
    # Register users
    print("1. Registering users...")
    for user in ['alice', 'bob', 'charlie']:
        client = get_client(user)
        client.register()
        print(f"   ✓ {user} registered")
    
    # Login users
    print("\n2. Logging in users...")
    for user in ['alice', 'bob', 'charlie']:
        client = get_client(user)
        client.login()
        print(f"   ✓ {user} logged in")
    
    # Add expenses
    print("\n3. Adding expenses...")
    expenses = [
        ('alice', 'alice', 60.00, 'Dinner at restaurant'),
        ('bob', 'bob', 45.50, 'Groceries'),
        ('charlie', 'charlie', 30.00, 'Movie tickets'),
        ('alice', 'alice', 15.00, 'Taxi ride'),
    ]
    
    for user, payer, amount, desc in expenses:
        client = get_client(user)
        client.add_expense(payer, amount, desc)
        print(f"   ✓ {payer} paid ${amount} for '{desc}'")
    
    # View ledger
    print("\n4. Viewing ledger...")
    get_client('alice').view_ledger()
    
    # View balances
    print("\n5. Viewing balances...")
    get_client('alice').view_balances()
    
    print("\n✓ Quick demo complete!")

def cmd_demo_attacks(args):
    """Show attack defense summary."""
    print("\n=== ATTACK DEFENSE SUMMARY ===\n")
    
    attacks = [
        ("Eavesdropping", "AES-256-GCM encryption", "Messages encrypted, ciphertext unintelligible"),
        ("Modification", "GCM authentication tag", "Modified messages rejected, tag verification fails"),
        ("Spoofing", "RSA-PSS signatures", "Forged signatures rejected, identity verified"),
        ("Replay", "Monotonic counters", "Old messages rejected, counter must increase"),
        ("Tampering", "SHA-256 hash chain", "Database changes detected, chain breaks"),
    ]
    
    for i, (attack, defense, result) in enumerate(attacks, 1):
        print(f"{i}. {attack} Attack")
        print(f"   Defense: {defense}")
        print(f"   Result: {result}")
        print()
    
    # Verify current ledger
    init_server()
    is_valid, msg = server.ledger.verify_chain_integrity()
    entries = server.ledger.get_all_entries()
    
    print(f"Current Status:")
    print(f"  Ledger entries: {len(entries)}")
    print(f"  Integrity: {'✓ Valid' if is_valid else '✗ Broken'}")
    print(f"  Users: {len(server.list_users())}")

def cmd_reset(args):
    """Reset the application (clear database and keys)."""
    import os
    import shutil
    
    if not args.confirm:
        print("⚠️  This will delete all data and keys!")
        print("   Run with --confirm to proceed: cli.py reset --confirm")
        return
    
    # Remove database
    if os.path.exists('data/splitsmart.db'):
        os.remove('data/splitsmart.db')
        print("✓ Database deleted")
    
    # Remove keys
    if os.path.exists('keys'):
        for file in os.listdir('keys'):
            if file.endswith('.pem'):
                os.remove(os.path.join('keys', file))
        print("✓ Keys deleted")
    
    print("✓ Reset complete. Restart CLI to begin fresh.")

def main():
    global verbose
    
    parser = argparse.ArgumentParser(
        description='SplitSmart CLI - Cryptographic Expense Splitting',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Register and login
  python cli.py register alice
  python cli.py login alice
  
  # Add expenses
  python cli.py add alice alice 50.00 "Dinner"
  python cli.py add bob bob 30.00 "Movie tickets"
  
  # View data
  python cli.py ledger alice
  python cli.py balances alice
  python cli.py users
  
  # Check security
  python cli.py verify
  python cli.py counter alice
  
  # Show crypto operations (verbose mode)
  python cli.py --verbose register alice
  python cli.py -v login alice
  python cli.py -v add alice alice 50.00 "Dinner"
  
  # Quick demos
  python cli.py demo
  python cli.py attacks
  
  # Reset
  python cli.py reset --confirm
        """
    )
    
    # Add verbose flag
    parser.add_argument('-v', '--verbose', action='store_true',
                       help='Show cryptographic operations in detail')
    
    subparsers = parser.add_subparsers(dest='command', help='Command to execute')
    
    # Register command
    parser_register = subparsers.add_parser('register', help='Register a new user')
    parser_register.add_argument('user', help='Username')
    parser_register.set_defaults(func=cmd_register)
    
    # Login command
    parser_login = subparsers.add_parser('login', help='Login user (establish secure session)')
    parser_login.add_argument('user', help='Username')
    parser_login.set_defaults(func=cmd_login)
    
    # Add expense command
    parser_add = subparsers.add_parser('add', help='Add an expense')
    parser_add.add_argument('user', help='User submitting the expense')
    parser_add.add_argument('payer', help='Who paid')
    parser_add.add_argument('amount', type=float, help='Amount paid')
    parser_add.add_argument('description', help='Expense description')
    parser_add.set_defaults(func=cmd_add_expense)
    
    # View ledger command
    parser_ledger = subparsers.add_parser('ledger', help='View the ledger')
    parser_ledger.add_argument('user', help='Username')
    parser_ledger.set_defaults(func=cmd_view_ledger)
    
    # View balances command
    parser_balances = subparsers.add_parser('balances', help='View balances')
    parser_balances.add_argument('user', help='Username')
    parser_balances.set_defaults(func=cmd_view_balances)
    
    # List users command
    parser_users = subparsers.add_parser('users', help='List all registered users')
    parser_users.set_defaults(func=cmd_list_users)
    
    # Verify ledger command
    parser_verify = subparsers.add_parser('verify', help='Verify ledger integrity')
    parser_verify.set_defaults(func=cmd_verify_ledger)
    
    # Show counter command
    parser_counter = subparsers.add_parser('counter', help='Show user counter')
    parser_counter.add_argument('user', help='Username')
    parser_counter.set_defaults(func=cmd_show_counter)
    
    # Quick demo command
    parser_demo = subparsers.add_parser('demo', help='Run quick demo')
    parser_demo.set_defaults(func=cmd_demo_quick)
    
    # Attacks demo command
    parser_attacks = subparsers.add_parser('attacks', help='Show attack defense summary')
    parser_attacks.set_defaults(func=cmd_demo_attacks)
    
    # Reset command
    parser_reset = subparsers.add_parser('reset', help='Reset application (delete all data)')
    parser_reset.add_argument('--confirm', action='store_true', help='Confirm reset')
    parser_reset.set_defaults(func=cmd_reset)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Set verbose mode
    verbose = args.verbose
    
    if not args.command:
        parser.print_help()
        return
    
    # Execute command
    try:
        args.func(args)
    except Exception as e:
        print(f"✗ Error: {e}")
        if verbose:
            import traceback
            traceback.print_exc()

if __name__ == '__main__':
    main()
