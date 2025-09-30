#!/usr/bin/env python3
"""
Nuclear Defender Disable - COMPLETE SHUTDOWN
WARNING: COMPLETELY DISABLES WINDOWS DEFENDER
"""

import subprocess
import os
import time

def nuclear_defender_disable():
    """Completely disable Windows Defender via multiple methods"""
    
    print(" NUCLEAR DEFENDER DISABLE ")
    print("WARNING: This will COMPLETELY disable Windows Defender!")
    
    response = input("Are you ABSOLUTELY sure? (YES/no): ")
    if response.lower() != 'yes':
        return
    
    methods = [
        # Method 1: Group Policy registry keys
        ('Registry Disable', [
            'reg', 'add', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender', 
            '/v', 'DisableAntiSpyware', '/t', 'REG_DWORD', '/d', '1', '/f'
        ]),
        
        # Method 2: Real-time protection
        ('Real-time Disable', [
            'reg', 'add', 'HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender\\Real-Time Protection',
            '/v', 'DisableRealtimeMonitoring', '/t', 'REG_DWORD', '/d', '1', '/f'
        ]),
        
        # Method 3: Stop services
        ('Stop Services', ['net', 'stop', 'WinDefend']),
        ('Stop NIS', ['net', 'stop', 'WdNisSvc']),
        
        # Method 4: Disable services
        ('Disable Services', ['sc', 'config', 'WinDefend', 'start=', 'disabled']),
        ('Disable NIS', ['sc', 'config', 'WdNisSvc', 'start=', 'disabled']),
        
        # Method 5: Tamper protection
        ('Disable Tamper Protection', [
            'reg', 'add', 'HKLM\\SOFTWARE\\Microsoft\\Windows Defender\\Features',
            '/v', 'TamperProtection', '/t', 'REG_DWORD', '/d', '0', '/f'
        ]),
    ]
    
    print("\n[*] Executing nuclear disable sequence...")
    
    for method_name, command in methods:
        print(f"[*] {method_name}...")
        try:
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                print(f"    Success")
            else:
                print(f" Failed: {result.stderr}")
        except Exception as e:
            print(f"    Error: {e}")
        
        time.sleep(1)
    
    print("\n[!] NUCLEAR DISABLE COMPLETE")
    print("[!] Windows Defender should be completely disabled")
    print("[!] SYSTEM RESTART REQUIRED FOR SOME CHANGES")
    print("[!] Re-enable via: reg delete HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender /f")

if __name__ == "__main__":
    nuclear_defender_disable()
