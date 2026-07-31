import os 
import re 
import sys 
import subprocess 
from pathlib import Path 
 
IOCS = { 
    "domains": ["trykuro.app"], 
    "ips": ["216.150.1.193"], 
    "processes": ["splunkd.exe"], 
    "registry": ["kuro"], 
    "folders": ["kuro", "splunkd"], 
} 
 
class IOCScanner: 
    def __init__(self): 
        self.found = [] 
 
    def scan_processes(self): 
        try: 
            result = subprocess.run(['tasklist'], capture_output=True, text=True) 
            for process in IOCS['processes']: 
                if process.lower() in result.stdout.lower(): 
                    self.found.append(f"Process: {process}") 
                    print(f"[!] Found malicious process: {process}") 
        except Exception as e: 
            print(f"[!] Error scanning processes: {e}") 
 
    def scan_registry(self): 
        try: 
            for key in IOCS['registry']: 
                cmd = f'reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v {key} 
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True) 
                if result.returncode == 0: 
                    self.found.append(f"Registry: {key}") 
                    print(f"[!] Found malicious registry: {key}") 
        except Exception as e: 
            print(f"[!] Error scanning registry: {e}") 
 
    def scan_folders(self): 
        for folder in IOCS['folders']: 
            paths = [ 
                f"C:\\Users\\{os.getlogin()}\\AppData\\Roaming\\{folder}", 
                f"C:\\Users\\{os.getlogin()}\\AppData\\Local\\{folder}", 
                f"C:\\ProgramData\\{folder}", 
            ] 
            for path in paths: 
                if os.path.exists(path): 
                    self.found.append(f"Folder: {path}") 
                    print(f"[!] Found malicious folder: {path}") 
 
    def generate_report(self): 
        print("\n" + "="*50) 
        print("IOC SCAN REPORT") 
        print("="*50) 
        if self.found: 
            for item in self.found: 
                print(f"  - {item}") 
            print(f"\n[!] Total indicators found: {len(self.found)}") 
            print("[!] System may be compromised!") 
        else: 
            print("[+] No indicators found. System appears clean.") 
        return self.found 
 
    def run(self): 
        print("[*] Starting IOC scan...") 
        self.scan_processes() 
        self.scan_registry() 
        self.scan_folders() 
        return self.generate_report() 
 
if __name__ == "__main__": 
    scanner = IOCScanner() 
    scanner.run() 
