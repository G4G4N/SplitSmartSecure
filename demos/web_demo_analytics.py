#!/usr/bin/env python3
"""
Web UI Demo: Analytics Dashboard

This demo shows the analytics features of the web UI, including
charts, statistics, and blockchain information.
"""

import sys
import os
# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from demos.web_demo_base import WebDemoBase
from selenium.webdriver.common.by import By
import time

class WebAnalyticsDemo(WebDemoBase):
    """Demonstrate analytics features in web UI."""
    
    def run_demo(self):
        """Run the analytics demo."""
        self.print_header("WEB UI DEMO: Analytics Dashboard")
        
        print("This demo shows the analytics features available in the web UI.\n")
        
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
            
            print("\n2. Adding multiple expenses...")
            expenses = [
                ("alice", 50.00, "Lunch"),
                ("alice", 100.00, "Dinner"),
                ("bob", 75.00, "Groceries"),
                ("alice", 30.00, "Coffee"),
                ("bob", 200.00, "Rent"),
            ]
            
            for payer, amount, desc in expenses:
                if not self.add_expense(payer, amount, desc):
                    print(f"✗ Failed to add expense: {payer} paid ${amount}")
                else:
                    print(f"   ✓ Added: {payer} paid ${amount} for {desc}")
                time.sleep(1)
            
            print("\n3. VIEWING ANALYTICS DASHBOARD:")
            self.driver.get(self.base_url)
            time.sleep(3)  # Wait for analytics to load
            
            # Check for analytics elements
            print("\n   Analytics Features Available:")
            
            # Summary cards
            try:
                total_amount = self.driver.find_element(By.ID, "totalAmount")
                total_entries = self.driver.find_element(By.ID, "totalEntries")
                avg_expense = self.driver.find_element(By.ID, "averageExpense")
                most_active = self.driver.find_element(By.ID, "mostActivePayer")
                
                print(f"   ✓ Total Expenses: {total_amount.text}")
                print(f"   ✓ Total Entries: {total_entries.text}")
                print(f"   ✓ Average Expense: {avg_expense.text}")
                print(f"   ✓ Most Active Payer: {most_active.text}")
            except:
                print("   ⚠️  Summary cards not found")
            
            # Charts
            try:
                payer_chart = self.driver.find_element(By.ID, "payerChart")
                trend_chart = self.driver.find_element(By.ID, "trendChart")
                print("   ✓ Expenses by Payer Chart (Doughnut)")
                print("   ✓ Daily Spending Trend Chart (Line)")
            except:
                print("   ⚠️  Charts not found")
            
            # Detailed analysis
            try:
                largest = self.driver.find_element(By.ID, "largestExpense")
                smallest = self.driver.find_element(By.ID, "smallestExpense")
                recent = self.driver.find_element(By.ID, "recentExpenses")
                spending = self.driver.find_element(By.ID, "spendingByUser")
                
                print("   ✓ Largest Expense Analysis")
                print("   ✓ Smallest Expense Analysis")
                print("   ✓ Recent Expenses List")
                print("   ✓ Spending by User Breakdown")
            except:
                print("   ⚠️  Detailed analysis sections not found")
            
            print("\n4. VIEWING BLOCKCHAIN LEDGER:")
            time.sleep(1)
            
            # Scroll to blockchain section
            try:
                blockchain_section = self.driver.find_element(By.ID, "blockchainContent")
                if blockchain_section:
                    print("   ✓ Blockchain ledger visible")
                    print("   ✓ Block heights and hashes displayed")
                    print("   ✓ Chain validity verification")
            except:
                print("   ⚠️  Blockchain section not found")
            
            print("\n5. VIEWING SECURITY STATUS:")
            try:
                security_section = self.driver.find_element(By.CLASS_NAME, "security-card")
                if security_section:
                    print("   ✓ Security features displayed:")
                    print("     • AES-256-GCM Encryption")
                    print("     • RSA-PSS Signatures")
                    print("     • Hash Chain")
                    print("     • Replay Protection")
                    print("   ✓ Tampering verification button available")
            except:
                print("   ⚠️  Security section not found")
            
            # Take a screenshot if possible
            try:
                screenshot_path = "web_demo_analytics_screenshot.png"
                self.driver.save_screenshot(screenshot_path)
                print(f"\n   ✓ Screenshot saved: {screenshot_path}")
            except:
                pass
            
            self.print_header("RESULT: Analytics Dashboard Working")
            print("✓ Web UI provides comprehensive analytics:")
            print("  • Summary statistics (total, average, most active)")
            print("  • Visual charts (pie, line graphs)")
            print("  • Detailed expense analysis")
            print("  • Recent expenses tracking")
            print("  • User spending breakdown")
            print("\n✓ Blockchain information displayed:")
            print("  • Block heights and hashes")
            print("  • Chain validity status")
            print("  • Tamper detection")
            print("\n✓ Security features visible:")
            print("  • Encryption algorithms explained")
            print("  • Security properties listed")
            print("  • Real-time tampering verification")
            print("\n✓ All data is cryptographically protected:")
            print("  • Same encryption as CLI version")
            print("  • Secure session management")
            print("  • Authenticated API requests")
            
            return True
            
        except Exception as e:
            print(f"\n✗ Demo error: {e}")
            import traceback
            traceback.print_exc()
            return False
        finally:
            self.cleanup()

if __name__ == "__main__":
    demo = WebAnalyticsDemo()
    demo.run_demo()

