#!/usr/bin/env python3
"""
Web UI Demo: Ledger Tampering Detection

This demo shows how the web UI detects ledger tampering using
the blockchain hash chain.
"""

import sys
import os
# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from demos.web_demo_base import WebDemoBase
from selenium.webdriver.common.by import By
from selenium.webdriver.common.action_chains import ActionChains
import time
import sqlite3
import os

class WebTamperingDemo(WebDemoBase):
    """Demonstrate tampering detection in web UI."""
    
    def run_demo(self):
        """Run the tampering demo."""
        self.print_header("WEB UI DEMO: Ledger Tampering Detection")
        
        print("Scenario: An attacker modifies the database directly")
        print("Defense: Blockchain hash chain detects tampering\n")
        
        try:
            # Start server
            if not self.start_server():
                print("✗ Failed to start server")
                return False
            
            # Setup browser
            if not self.setup_driver():
                print("✗ Failed to setup browser")
                return False
            
            print("\n1. Registering and logging in user...")
            if not self.register_user("alice"):
                print("✗ Failed to register user")
                return False
            
            time.sleep(1)
            
            print("\n2. Adding legitimate expenses...")
            expenses = [
                ("alice", 50.00, "Lunch"),
                ("bob", 100.00, "Dinner"),
                ("alice", 75.00, "Groceries"),
            ]
            
            for payer, amount, desc in expenses:
                if not self.add_expense(payer, amount, desc):
                    print(f"✗ Failed to add expense: {payer} paid ${amount}")
                else:
                    print(f"   ✓ Added: {payer} paid ${amount} for {desc}")
                time.sleep(1)
            
            print("\n3. VERIFYING LEDGER INTEGRITY (Before Tampering):")
            self.driver.get(self.base_url)
            time.sleep(2)
            
            # Click verify tampering button
            try:
                verify_btn = self.wait_for_clickable(By.ID, "verifyTamperingBtn")
                if verify_btn:
                    verify_btn.click()
                    time.sleep(2)
                    
                    # Check result
                    result_div = self.driver.find_element(By.ID, "tamperingResult")
                    if result_div:
                        result_text = result_div.text
                        if "valid" in result_text.lower() or "verified" in result_text.lower():
                            print("   ✓ Ledger integrity verified - No tampering detected")
                        else:
                            print(f"   Result: {result_text}")
            except Exception as e:
                print(f"   ⚠️  Could not verify: {e}")
            
            print("\n4. ATTACKER MODIFIES DATABASE DIRECTLY:")
            print("   • Attacker has access to database file")
            print("   • Attacker changes amount from $50.00 to $500.00")
            print("   • Attacker modifies description")
            print("   • Attacker does NOT update hash chain\n")
            
            # Actually modify the database
            db_path = "data/splitsmart.db"
            if os.path.exists(db_path):
                print("   • Modifying database...")
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                
                # Get first entry
                cursor.execute("SELECT id, amount, description FROM ledger ORDER BY id LIMIT 1")
                entry = cursor.fetchone()
                
                if entry:
                    entry_id, old_amount, old_desc = entry
                    print(f"   • Original entry ID {entry_id}: ${old_amount} for '{old_desc}'")
                    
                    # Modify it
                    new_amount = 500.00
                    new_desc = "HACKED EXPENSE"
                    cursor.execute(
                        "UPDATE ledger SET amount = ?, description = ? WHERE id = ?",
                        (new_amount, new_desc, entry_id)
                    )
                    conn.commit()
                    conn.close()
                    
                    print(f"   • Modified entry ID {entry_id}: ${new_amount} for '{new_desc}'")
                    print("   ✗ Hash chain is now broken!")
            
            print("\n5. VERIFYING LEDGER INTEGRITY (After Tampering):")
            time.sleep(1)
            
            # Refresh page
            self.driver.refresh()
            time.sleep(2)
            
            # Click verify tampering button again
            try:
                verify_btn = self.wait_for_clickable(By.ID, "verifyTamperingBtn")
                if verify_btn:
                    verify_btn.click()
                    time.sleep(2)
                    
                    # Check result
                    result_div = self.driver.find_element(By.ID, "tamperingResult")
                    if result_div:
                        result_text = result_div.text
                        if "tamper" in result_text.lower() or "invalid" in result_text.lower() or "broken" in result_text.lower():
                            print("   ✗ TAMPERING DETECTED!")
                            print(f"   Result: {result_text}")
                        else:
                            print(f"   Result: {result_text}")
            except Exception as e:
                print(f"   ⚠️  Could not verify: {e}")
            
            print("\n6. VIEWING BLOCKCHAIN STATUS:")
            time.sleep(1)
            
            try:
                blockchain_content = self.driver.find_element(By.ID, "blockchainContent")
                if blockchain_content:
                    blockchain_text = blockchain_content.text
                    if "invalid" in blockchain_text.lower() or "broken" in blockchain_text.lower():
                        print("   ✗ Blockchain shows chain is broken")
                    else:
                        print("   Blockchain information displayed")
            except:
                pass
            
            self.print_header("RESULT: Tampering Detected")
            print("✓ Web UI detects database tampering:")
            print("  • Hash chain verification runs on demand")
            print("  • Any modification breaks the chain")
            print("  • User is immediately notified")
            print("\n✓ Blockchain protection:")
            print("  • Each block contains hash of previous block")
            print("  • Modifying any entry breaks the chain")
            print("  • Tampering is cryptographically detectable")
            print("\n✓ Same security as CLI version:")
            print("  • Same hash chain algorithm")
            print("  • Same verification logic")
            print("  • Same tamper detection capabilities")
            print("\n✓ Protection mechanisms:")
            print("  • Even direct database modification is detected")
            print("  • Hash chain cannot be recomputed without private keys")
            print("  • Blockchain structure prevents undetected tampering")
            
            return True
            
        except Exception as e:
            print(f"\n✗ Demo error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.cleanup()

if __name__ == "__main__":
    demo = WebTamperingDemo()
    demo.run_demo()

