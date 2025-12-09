#!/usr/bin/env python3
"""
Run all attack demonstrations sequentially
"""

import sys
import os

# Add current directory to path
sys.path.insert(0, '.')

def print_separator():
    print("\n" + "=" * 80)
    print("=" * 80 + "\n")

def main():
    print("=" * 80)
    print("SplitSmart - Complete Attack Demonstration Suite".center(80))
    print("=" * 80)
    
    demos = [
        ("Eavesdropping Attack", "demos/demo_eavesdropping.py"),
        ("Modification Attack", "demos/demo_modification.py"),
        ("Spoofing Attack", "demos/demo_spoofing.py"),
        ("Replay Attack", "demos/demo_replay.py"),
        ("Ledger Tampering", "demos/demo_tampering.py"),
    ]
    
    for i, (name, path) in enumerate(demos, 1):
        print(f"\n{'=' * 80}")
        print(f"Demo {i}/{len(demos)}: {name}".center(80))
        print(f"{'=' * 80}\n")
        
        try:
            with open(path, 'r') as f:
                code = f.read()
            exec(code)
            print(f"\n✓ {name} completed successfully")
        except Exception as e:
            print(f"\n✗ {name} failed: {e}")
            import traceback
            traceback.print_exc()
        
        print_separator()
    
    print("=" * 80)
    print("All Demonstrations Complete".center(80))
    print("=" * 80)

if __name__ == "__main__":
    main()
