#!/usr/bin/env python3
"""
Usage: python3 scanner.py --gui     # For graphical interface
       python3 scanner.py --cli -u http://example.com   # Command line mode
"""

import requests
from bs4 import BeautifulSoup
import argparse
import sys
import re
import tkinter as tk
from tkinter import messagebox
import threading

class VulnerabilityScanner:
    def __init__(self, target):
        self.target = target.rstrip('/')
        
    def check_xss(self):
        payloads = ['<script>alert(1)</script>', '"><svg onload=alert(1)>']
        vulnerable_url = None
        
        for payload in payloads:
            try:
                response = requests.get(f"{self.target}?q={payload}")
                
                if payload.lower() in response.text.lower():
                    vulnerable_url = response.url
                    break
                    
            except Exception as e:
                print(f"[-] Error checking XSS: {e}")
                
        return vulnerable_url
    
    def check_sql_injection(self):
        tests = ["'", "\"", "--", ";"]
        vulnerable_endpoint = None
        
        for param in ["id", "user_id", "product"]:
            for test in tests:
                try:
                    url = f"{self.target}/{param}=" + test
                    response = requests.get(url)
                    
                    if "sql syntax" in str(response.content).lower() or \
                       "mysql_fetch_array()" in str(response.content).lower():
                        vulnerable_endpoint = url
                        break
                        
                except Exception as e:
                    print(f"[-] Error checking SQLi: {e}")
                    
        return vulnerable_endpoint
    
    def scan(self):
        results = {
            "target": self.target,
            "xss_vulnerable": False,
            "sqli_vulnerable": False,
            "vulnerabilities": []
        }
        
        xss_check = self.check_xss()
        if xss_check:
            results["xss_vulnerable"] = True
            results["vulnerabilities"].append({
                "type": "XSS",
                "url": xss_check
            })
            
        sqli_check = self.check_sql_injection()
        if sqli_check:
            results["sqli_vulnerable"] = True
            results["vulnerabilities"].append({
                "type": "SQL Injection",
                "url": sqli_check
            })
            
        return results

class ScanApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Vulnerability Scanner")
        
        self.entry_label = tk.Label(root, text="Target URL:")
        self.entry_label.pack(pady=5)
        
        self.url_entry = tk.Entry(root, width=50)
        self.url_entry.pack(pady=5)
        
        self.scan_button = tk.Button(root, text="Scan", command=self.start_scan)
        self.scan_button.pack(pady=10)
        
        self.result_text = tk.Text(root, height=10, width=60)
        self.result_text.pack(pady=5)
        
        self.status_label = tk.Label(root, text="")
        self.status_label.pack(pady=5)
    
    def start_scan(self):
        self.scan_button.config(state=tk.DISABLED)
        self.status_label.config(text="Scanning...")
        self.root.update()
        
        target = self.url_entry.get().strip()
        if not re.match(r'https?://', target):
            self.status_label.config(text="")
            self.scan_button.config(state=tk.NORMAL)
            messagebox.showerror("Error", "Please enter a valid URL")
            return
            
        thread = threading.Thread(
            target=self.perform_scan,
            args=(target,)
        )
        thread.start()
    
    def perform_scan(self, target):
        try:
            scanner = VulnerabilityScanner(target)
            results = scanner.scan()
            
            result_output = ""
            if results["vulnerabilities"]:
                result_output += "VULNERABILITIES FOUND:\n"
                for vuln in results["vulnerabilities"]:
                    result_output += f"- {vuln['type']} at: {vuln['url']}\n"
            else:
                result_output = "No obvious vulnerabilities detected"
                
            self.root.after(0, self.update_results, result_output)
            
        except Exception as e:
            self.root.after(0, self.handle_error, str(e))
    
    def update_results(self, output):
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, output)
        self.status_label.config(text="Scan complete")
        self.scan_button.config(state=tk.NORMAL)
    
    def handle_error(self, error_msg):
        self.status_label.config(text="Error during scan")
        self.scan_button.config(state=tk.NORMAL)
        messagebox.showerror("Error", f"Scan failed: {error_msg}")

def cli_mode(args):
    target = args.url.strip()
    
    if not re.match(r'https?://', target):
        print("[-] Invalid URL")
        return
        
    print(f"[+] Starting scan against {target}")
    
    scanner = VulnerabilityScanner(target)
    results = scanner.scan()
    
    print("\n[+] Scan Results:")
    print(f"Target: {results['target']}")
    
    if results["vulnerabilities"]:
        print("[!] VULNERABILITIES FOUND:")
        for vuln in results["vulnerabilities"]:
            print(f"- {vuln['type']} at: {vuln['url']}")
    else:
        print("[+] No obvious vulnerabilities detected")

def main():
    parser = argparse.ArgumentParser(description='Vulnerability Scanner')
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--cli', action='store_true', help="Run in CLI mode")
    group.add_argument('--gui', action='store_true', help="Run in GUI mode")
    
    parser.add_argument('-u', '--url', help="Target URL (for CLI mode)")
    
    args = parser.parse_args()
    
    if args.cli:
        if not args.url:
            parser.error("--cli mode requires --url parameter")
        cli_mode(args)
    
    elif args.gui:
        try:
            root = tk.Tk()
            app = ScanApp(root)
            root.mainloop()
        except Exception as e:
            print(f"GUI initialization error: {e}")
            print("Running in CLI mode instead")
            parser.print_help()

if __name__ == "__main__":
    main()
