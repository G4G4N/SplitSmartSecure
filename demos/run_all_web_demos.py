#!/usr/bin/env python3
"""
Run all web UI demos sequentially.
"""

import sys
import os
import time
# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from demos.web_demo_eavesdropping import WebEavesdroppingDemo
from demos.web_demo_modification import WebModificationDemo
from demos.web_demo_analytics import WebAnalyticsDemo
from demos.web_demo_tampering import WebTamperingDemo

def print_header(text):
    print("\n" + "=" * 80)
    print(f"{text:^80}")
    print("=" * 80 + "\n")

def run_all_web_demos():
    """Run all web UI demos."""
    print_header("SplitSmart Web UI Attack Demonstrations")
    
    demos = [
        ("Eavesdropping Attack", WebEavesdroppingDemo),
        ("Modification Attack", WebModificationDemo),
        ("Analytics Dashboard", WebAnalyticsDemo),
        ("Tampering Detection", WebTamperingDemo),
    ]
    
    results = []
    
    for name, demo_class in demos:
        print_header(f"Running: {name}")
        try:
            demo = demo_class()
            success = demo.run_demo()
            results.append((name, success))
            
            if success:
                print(f"\n✓ {name} completed successfully")
            else:
                print(f"\n✗ {name} failed")
            
            # Wait between demos
            print("\nWaiting 3 seconds before next demo...")
            time.sleep(3)
            
        except Exception as e:
            print(f"\n✗ {name} error: {e}")
            results.append((name, False))
            import traceback
            traceback.print_exc()
    
    # Summary
    print_header("Demo Summary")
    
    for name, success in results:
        status = "✓ PASSED" if success else "✗ FAILED"
        print(f"{status:12} - {name}")
    
    total = len(results)
    passed = sum(1 for _, success in results if success)
    
    print(f"\nTotal: {total} demos")
    print(f"Passed: {passed}")
    print(f"Failed: {total - passed}")
    
    if passed == total:
        print("\n✓ All web UI demos passed!")
        return 0
    else:
        print(f"\n✗ {total - passed} demo(s) failed")
        return 1

if __name__ == "__main__":
    sys.exit(run_all_web_demos())

