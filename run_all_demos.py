#!/usr/bin/env python3
"""
Run all attack demonstrations sequentially
"""

import sys
import os
import importlib.util
import time
import sqlite3
from shared.constants import DB_FILE

# Add current directory to path
sys.path.insert(0, '.')

def print_separator():
    print("\n" + "=" * 80)
    print("=" * 80 + "\n")

def cleanup_database_connections():
    """Ensure all database connections are closed."""
    try:
        # Try to close any lingering connections
        conn = sqlite3.connect(DB_FILE, timeout=1.0)
        conn.close()
        # Small delay to allow cleanup
        time.sleep(0.1)
    except:
        pass

def run_demo_module(module_path, demo_function_name):
    """Load and run a demo module function."""
    spec = importlib.util.spec_from_file_location("demo_module", module_path)
    if spec is None or spec.loader is None:
        raise ImportError(f"Could not load module from {module_path}")
    
    module = importlib.util.module_from_spec(spec)
    # Execute the module to define its functions
    spec.loader.exec_module(module)
    
    # Get and call the demo function
    demo_func = getattr(module, demo_function_name, None)
    if demo_func is None:
        raise AttributeError(f"Function {demo_function_name} not found in {module_path}")
    
    demo_func()

def main():
    print("=" * 80)
    print("SplitSmart - Complete Attack Demonstration Suite".center(80))
    print("=" * 80)
    
    demos = [
        ("Eavesdropping Attack", "demos/demo_eavesdropping.py", "demo_eavesdropping"),
        ("Modification Attack", "demos/demo_modification.py", "demo_modification"),
        ("Spoofing Attack", "demos/demo_spoofing.py", "demo_spoofing"),
        ("Replay Attack", "demos/demo_replay.py", "demo_replay"),
        ("Ledger Tampering", "demos/demo_tampering.py", "demo_tampering"),
    ]
    
    for i, (name, path, func_name) in enumerate(demos, 1):
        print(f"\n{'=' * 80}")
        print(f"Demo {i}/{len(demos)}: {name}".center(80))
        print(f"{'=' * 80}\n")
        
        try:
            run_demo_module(path, func_name)
            print(f"\n✓ {name} completed successfully")
        except Exception as e:
            print(f"\n✗ {name} failed: {e}")
            import traceback
            traceback.print_exc()
        
        # Cleanup database connections between demos
        cleanup_database_connections()
        
        print_separator()
    
    print("=" * 80)
    print("All Demonstrations Complete".center(80))
    print("=" * 80)

if __name__ == "__main__":
    main()
