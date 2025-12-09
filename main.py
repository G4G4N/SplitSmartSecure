#!/usr/bin/env python3
"""
SplitSmart - Cryptographic Expense Splitting Application
Main demo script showcasing the secure expense tracking system.
"""

import sys
from colorama import init, Fore, Style

from server.server import SplitSmartServer
from client.client import SplitSmartClient

# Initialize colorama for colored output
init(autoreset=True)


def print_header(text):
    """Print a colored header."""
    print(f"\n{Fore.CYAN}{'=' * 80}")
    print(f"{Fore.CYAN}{text:^80}")
    print(f"{Fore.CYAN}{'=' * 80}{Style.RESET_ALL}\n")


def print_success(text):
    """Print success message."""
    print(f"{Fore.GREEN}✓ {text}{Style.RESET_ALL}")


def print_error(text):
    """Print error message."""
    print(f"{Fore.RED}✗ {text}{Style.RESET_ALL}")


def print_info(text):
    """Print info message."""
    print(f"{Fore.YELLOW}ℹ {text}{Style.RESET_ALL}")


def demo_basic_functionality():
    """Demonstrate basic functionality of SplitSmart."""
    
    print_header("SplitSmart - Secure Expense Splitting Demo")
    
    # Initialize server
    print_info("Initializing server...")
    server = SplitSmartServer()
    print_success("Server initialized")
    
    # Create users
    users = ["alice", "bob", "charlie"]
    clients = {}
    
    print_header("Phase 1: User Registration")
    
    for user in users:
        print(f"\n{Fore.MAGENTA}Registering {user}...{Style.RESET_ALL}")
        client = SplitSmartClient(user, server)
        client.register()
        clients[user] = client
        print_success(f"{user} registered")
    
    print_header("Phase 2: Secure Session Establishment")
    
    for user in users:
        print(f"\n{Fore.MAGENTA}{user} logging in...{Style.RESET_ALL}")
        success = clients[user].login()
        if success:
            print_success(f"{user} established secure session")
        else:
            print_error(f"{user} failed to login")
            return
    
    print_header("Phase 3: Recording Expenses")
    
    # Alice pays for dinner
    print(f"\n{Fore.MAGENTA}Alice pays for dinner...{Style.RESET_ALL}")
    clients["alice"].add_expense("alice", 60.00, "Dinner at restaurant")
    
    # Bob pays for groceries
    print(f"\n{Fore.MAGENTA}Bob pays for groceries...{Style.RESET_ALL}")
    clients["bob"].add_expense("bob", 45.50, "Grocery shopping")
    
    # Charlie pays for movie tickets
    print(f"\n{Fore.MAGENTA}Charlie pays for movie tickets...{Style.RESET_ALL}")
    clients["charlie"].add_expense("charlie", 30.00, "Movie tickets")
    
    # Alice pays for coffee
    print(f"\n{Fore.MAGENTA}Alice pays for coffee...{Style.RESET_ALL}")
    clients["alice"].add_expense("alice", 15.75, "Coffee shop")
    
    print_header("Phase 4: Viewing Blockchain Ledger")
    
    print(f"\n{Fore.MAGENTA}Alice viewing blockchain ledger...{Style.RESET_ALL}")
    clients["alice"].view_ledger()
    
    # Show blockchain info
    print(f"\n{Fore.MAGENTA}Blockchain Information:{Style.RESET_ALL}")
    blockchain_info = server.ledger.get_blockchain_info()
    print(f"  Total Blocks: {blockchain_info['total_blocks']}")
    print(f"  Chain Length: {blockchain_info['chain_length']}")
    print(f"  Chain Valid: {'✓ Yes' if blockchain_info['is_valid'] else '✗ No'}")
    print(f"  Genesis Hash: {blockchain_info['genesis_hash'][:32]}...")
    if blockchain_info['latest_block_hash']:
        print(f"  Latest Block Hash: {blockchain_info['latest_block_hash'][:32]}...")
    
    # Show block details
    entries = server.ledger.get_all_entries()
    if entries:
        print(f"\n{Fore.MAGENTA}Block Details:{Style.RESET_ALL}")
        for entry in entries[-3:]:  # Show last 3 blocks
            block_height = entry.get('block_height', entry.get('id', 0))
            block_hash = entry.get('block_hash', entry.get('entry_hash', ''))
            print(f"  Block #{block_height}: {entry['payer']} paid ${entry['amount']:.2f}")
            print(f"    Hash: {block_hash[:32]}...")
            if entry.get('prev_hash'):
                print(f"    Prev Hash: {entry['prev_hash'][:32]}...")
    
    print_header("Phase 5: Calculating Balances")
    
    print(f"\n{Fore.MAGENTA}Bob viewing balances...{Style.RESET_ALL}")
    clients["bob"].view_balances()
    
    print_header("Demo Complete")
    print_success("All operations completed successfully!")
    print_info("The blockchain ledger is cryptographically secured with:")
    print("  • Multiple encryption algorithms (AES-256-GCM, ChaCha20-Poly1305, AES-CBC-HMAC)")
    print("  • Digital signatures (RSA-PSS)")
    print("  • Blockchain hash chain for tamper evidence")
    print("  • Merkle roots for efficient verification")
    print("  • Replay protection via monotonic counters")
    print("  • Authenticated key exchange (Signed Diffie-Hellman)")
    print("  • Three-layer cryptographic architecture")


def demo_attack_scenarios():
    """Demonstrate attack scenarios and defenses."""
    
    print_header("SplitSmart - Attack Demonstration")
    
    print_info("This demo will show how SplitSmart defends against:")
    print("  1. Eavesdropping attacks")
    print("  2. Message modification attacks")
    print("  3. Spoofing attacks")
    print("  4. Replay attacks")
    print("  5. Ledger tampering")
    
    print("\n" + Fore.YELLOW + "Note: Detailed attack demos are in the demos/ directory" + Style.RESET_ALL)
    print(Fore.YELLOW + "Run them individually to see each attack and defense in action." + Style.RESET_ALL)


def interactive_mode():
    """Interactive CLI mode."""
    
    print_header("SplitSmart - Interactive Mode")
    
    # Initialize server
    server = SplitSmartServer()
    clients = {}
    current_user = None
    
    print_info("Server initialized. Type 'help' for available commands.")
    
    while True:
        try:
            if current_user:
                prompt = f"{Fore.GREEN}{current_user}>{Style.RESET_ALL} "
            else:
                prompt = f"{Fore.YELLOW}guest>{Style.RESET_ALL} "
            
            command = input(prompt).strip().split()
            
            if not command:
                continue
            
            cmd = command[0].lower()
            
            if cmd == "help":
                print("\nAvailable commands:")
                print("  register <username>           - Register a new user")
                print("  login <username>              - Login as user")
                print("  add <payer> <amount> <desc>   - Add expense")
                print("  ledger                        - View ledger")
                print("  balances                      - View balances")
                print("  users                         - List registered users")
                print("  logout                        - Logout current user")
                print("  exit                          - Exit program")
                print()
            
            elif cmd == "register":
                if len(command) < 2:
                    print_error("Usage: register <username>")
                    continue
                username = command[1]
                client = SplitSmartClient(username, server)
                client.register()
                clients[username] = client
            
            elif cmd == "login":
                if len(command) < 2:
                    print_error("Usage: login <username>")
                    continue
                username = command[1]
                if username not in clients:
                    client = SplitSmartClient(username, server)
                    clients[username] = client
                if clients[username].login():
                    current_user = username
                    print_success(f"Logged in as {username}")
            
            elif cmd == "add":
                if not current_user:
                    print_error("Please login first")
                    continue
                if len(command) < 4:
                    print_error("Usage: add <payer> <amount> <description>")
                    continue
                payer = command[1]
                try:
                    amount = float(command[2])
                    description = " ".join(command[3:])
                    clients[current_user].add_expense(payer, amount, description)
                except ValueError:
                    print_error("Invalid amount")
            
            elif cmd == "ledger":
                if not current_user:
                    print_error("Please login first")
                    continue
                clients[current_user].view_ledger()
            
            elif cmd == "balances":
                if not current_user:
                    print_error("Please login first")
                    continue
                clients[current_user].view_balances()
            
            elif cmd == "users":
                users = server.list_users()
                print(f"\nRegistered users: {', '.join(users) if users else 'None'}")
            
            elif cmd == "logout":
                if current_user:
                    print_success(f"Logged out {current_user}")
                    current_user = None
                else:
                    print_error("Not logged in")
            
            elif cmd == "exit":
                print_info("Goodbye!")
                break
            
            else:
                print_error(f"Unknown command: {cmd}. Type 'help' for available commands.")
        
        except KeyboardInterrupt:
            print("\n" + Fore.YELLOW + "Use 'exit' to quit" + Style.RESET_ALL)
        except Exception as e:
            print_error(f"Error: {e}")


def main():
    """Main entry point."""
    
    if len(sys.argv) > 1:
        mode = sys.argv[1].lower()
        
        if mode == "demo":
            demo_basic_functionality()
        elif mode == "attacks":
            demo_attack_scenarios()
        elif mode == "interactive":
            interactive_mode()
        else:
            print(f"Unknown mode: {mode}")
            print("Usage: python main.py [demo|attacks|interactive]")
    else:
        # Default to demo mode
        demo_basic_functionality()


if __name__ == "__main__":
    main()
