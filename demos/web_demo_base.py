#!/usr/bin/env python3
"""
Base class for web UI demos.
Provides common functionality for browser automation demos.
"""

import time
import threading
import subprocess
import sys
import os
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, NoSuchElementException

class WebDemoBase:
    """Base class for web UI demonstrations."""
    
    def __init__(self, port=5000):
        """
        Initialize web demo base.
        
        Args:
            port: Port for Flask server
        """
        self.port = port
        self.server_process = None
        self.driver = None
        self.base_url = f"http://localhost:{port}"
        
    def print_header(self, text):
        """Print formatted header."""
        print("\n" + "=" * 80)
        print(f"{text:^80}")
        print("=" * 80 + "\n")
    
    def start_server(self):
        """Start Flask server in background."""
        print(f"[Web Demo] Starting Flask server on port {self.port}...")
        
        # Start server in subprocess
        env = os.environ.copy()
        env['FLASK_DEBUG'] = 'False'
        env['PORT'] = str(self.port)
        
        self.server_process = subprocess.Popen(
            [sys.executable, 'web_app.py'],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env
        )
        
        # Wait for server to start
        import requests
        max_attempts = 30
        for i in range(max_attempts):
            try:
                response = requests.get(self.base_url, timeout=1)
                if response.status_code == 200:
                    print(f"[Web Demo] Server started successfully")
                    time.sleep(1)  # Give it a moment to fully initialize
                    return True
            except:
                time.sleep(0.5)
        
        print("[Web Demo] Failed to start server")
        return False
    
    def stop_server(self):
        """Stop Flask server."""
        if self.server_process:
            print("[Web Demo] Stopping Flask server...")
            self.server_process.terminate()
            try:
                self.server_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.server_process.kill()
            print("[Web Demo] Server stopped")
    
    def setup_driver(self):
        """Setup Selenium WebDriver."""
        print("[Web Demo] Setting up browser...")
        
        chrome_options = Options()
        chrome_options.add_argument('--headless')  # Run in headless mode
        chrome_options.add_argument('--no-sandbox')
        chrome_options.add_argument('--disable-dev-shm-usage')
        chrome_options.add_argument('--disable-gpu')
        chrome_options.add_argument('--window-size=1920,1080')
        
        # Enable logging for network requests
        chrome_options.set_capability('goog:loggingPrefs', {'performance': 'ALL'})
        
        try:
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
            self.driver.implicitly_wait(5)
            print("[Web Demo] Browser ready")
            return True
        except Exception as e:
            print(f"[Web Demo] Failed to setup browser: {e}")
            print("[Web Demo] Make sure Chrome is installed")
            return False
    
    def teardown_driver(self):
        """Close browser."""
        if self.driver:
            print("[Web Demo] Closing browser...")
            self.driver.quit()
            print("[Web Demo] Browser closed")
    
    def wait_for_element(self, by, value, timeout=10):
        """Wait for element to be present."""
        try:
            element = WebDriverWait(self.driver, timeout).until(
                EC.presence_of_element_located((by, value))
            )
            return element
        except TimeoutException:
            return None
    
    def wait_for_clickable(self, by, value, timeout=10):
        """Wait for element to be clickable."""
        try:
            element = WebDriverWait(self.driver, timeout).until(
                EC.element_to_be_clickable((by, value))
            )
            return element
        except TimeoutException:
            return None
    
    def register_user(self, username, password="testpass123"):
        """Register a new user via web UI."""
        print(f"[Web Demo] Registering user: {username}")
        
        # Navigate to page
        self.driver.get(self.base_url)
        time.sleep(1)
        
        # Click Register tab
        register_tab = self.wait_for_clickable(By.XPATH, "//button[contains(text(), 'Register')]")
        if register_tab:
            register_tab.click()
            time.sleep(0.5)
        
        # Fill registration form
        username_input = self.wait_for_element(By.ID, "registerUsername")
        password_input = self.wait_for_element(By.ID, "registerPassword")
        confirm_input = self.wait_for_element(By.ID, "registerPasswordConfirm")
        
        if username_input and password_input and confirm_input:
            username_input.clear()
            username_input.send_keys(username)
            password_input.clear()
            password_input.send_keys(password)
            confirm_input.clear()
            confirm_input.send_keys(password)
            
            # Submit form
            submit_btn = self.wait_for_clickable(By.XPATH, "//form[@id='registerForm']//button[@type='submit']")
            if submit_btn:
                submit_btn.click()
                time.sleep(2)  # Wait for registration and auto-login
                return True
        
        return False
    
    def login_user(self, username, password="testpass123"):
        """Login user via web UI."""
        print(f"[Web Demo] Logging in user: {username}")
        
        # Navigate to page
        self.driver.get(self.base_url)
        time.sleep(1)
        
        # Make sure we're on login tab
        login_tab = self.wait_for_clickable(By.XPATH, "//button[contains(text(), 'Login')]")
        if login_tab:
            login_tab.click()
            time.sleep(0.5)
        
        # Fill login form
        username_input = self.wait_for_element(By.ID, "loginUsername")
        password_input = self.wait_for_element(By.ID, "loginPassword")
        
        if username_input and password_input:
            username_input.clear()
            username_input.send_keys(username)
            password_input.clear()
            password_input.send_keys(password)
            
            # Submit form
            submit_btn = self.wait_for_clickable(By.XPATH, "//form[@id='loginForm']//button[@type='submit']")
            if submit_btn:
                submit_btn.click()
                time.sleep(2)  # Wait for login
                return True
        
        return False
    
    def add_expense(self, payer, amount, description):
        """Add expense via web UI."""
        print(f"[Web Demo] Adding expense: {payer} paid ${amount} for {description}")
        
        # Make sure we're on the dashboard
        self.driver.get(self.base_url)
        time.sleep(2)  # Wait for page to load
        
        # Wait for dashboard to be visible
        try:
            WebDriverWait(self.driver, 10).until(
                EC.presence_of_element_located((By.ID, "expenseForm"))
            )
        except:
            print("[Web Demo] Warning: Expense form not found, user may not be logged in")
            return False
        
        # Fill expense form
        payer_input = self.wait_for_element(By.ID, "payer")
        amount_input = self.wait_for_element(By.ID, "amount")
        desc_input = self.wait_for_element(By.ID, "description")
        
        if payer_input and amount_input and desc_input:
            try:
                payer_input.clear()
                payer_input.send_keys(payer)
                amount_input.clear()
                amount_input.send_keys(str(amount))
                desc_input.clear()
                desc_input.send_keys(description)
                
                # Submit form
                submit_btn = self.wait_for_clickable(By.XPATH, "//form[@id='expenseForm']//button[@type='submit']")
                if submit_btn:
                    submit_btn.click()
                    time.sleep(3)  # Wait for submission
                    return True
            except Exception as e:
                print(f"[Web Demo] Error adding expense: {e}")
                return False
        
        return False
    
    def get_network_logs(self):
        """Get network request logs from browser."""
        logs = self.driver.get_log('performance')
        network_logs = []
        for log in logs:
            message = log.get('message', '')
            if 'Network' in message or 'Request' in message or 'Response' in message:
                network_logs.append(log)
        return network_logs
    
    def get_page_source_snippet(self, max_length=500):
        """Get snippet of page source."""
        source = self.driver.page_source
        return source[:max_length] + "..." if len(source) > max_length else source
    
    def cleanup(self):
        """Cleanup resources."""
        self.teardown_driver()
        self.stop_server()
    
    def run_demo(self):
        """Run the demo (to be implemented by subclasses)."""
        raise NotImplementedError("Subclasses must implement run_demo()")

