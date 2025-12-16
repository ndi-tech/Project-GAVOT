#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ██████╗ ██████╗  █████╗ ███████╗    ██╗  ██╗██╗      █████╗ ██████╗ ███████╗║
║  ██╔══██╗██╔══██╗██╔══██╗██╔════╝    ╚██╗██╔╝██║     ██╔══██╗██╔══██╗██╔════╝║
║  ██████╔╝██████╔╝███████║█████╗       ╚███╔╝ ██║     ███████║██████╔╝███████╗║
║  ██╔══██╗██╔══██╗██╔══██║██╔══╝       ██╔██╗ ██║     ██╔══██║██╔══██╗╚════██║║
║  ██████╔╝██║  ██║██║  ██║███████╗    ██╔╝ ██╗███████╗██║  ██║██████╔╝███████║║
║  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝║
║                                                                              ║
║             G R A E - X   L A B S   P R E S E N T S                          ║
║                                                                              ║
║        ███████╗ ██████╗ █████╗ ███╗   ██╗███████╗                            ║
║        ██╔════╝██╔════╝██╔══██╗████╗  ██╗██╔════╝                            ║
║        ███████╗██║     ███████║██╔██╗ ██║███████╗                            ║
║        ╚════██║██║     ██╔══██║██║╚██╗██║╚════██║                            ║
║        ███████║╚██████╗██║  ██║██║ ╚████║███████║                            ║
║        ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝                            ║
║                                                                              ║
║          Advanced Threat Simulation & Cybersecurity Training Platform        ║
║                     Version 4.0 - "Nebula" Edition                          ║
╚══════════════════════════════════════════════════════════════════════════════╝

Powered by Grae-X Labs • Advanced Cybersecurity Research Division
"""

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext, font
import os
import hashlib
import json
from datetime import datetime
import threading
import pefile
import struct
import random
import string
import base64
import zlib
import sys
import time
import hashlib
from pathlib import Path
import subprocess
import platform
from math import sin, cos, pi

# ==================== CORE ENGINE ====================

class GAVOTEngine:
    """Core engine for Grae-X AV Offensive Toolkit"""
    
    def __init__(self):
        self.version = "4.0"
        self.codename = "Nebula"
        self.author = "Grae-X Labs Research Division"
        self.build_date = "2024"
        self.powered_by = "Grae-X Labs"
        
        # Initialize modules
        self.signature_db = SignatureDatabase()
        self.scanner = AdvancedScanner()
        self.obfuscator = StealthObfuscator()
        self.payload_factory = PayloadFactory()
        self.report_generator = ReportGenerator()
        
        # Statistics
        self.stats = {
            'files_scanned': 0,
            'threats_detected': 0,
            'files_obfuscated': 0,
            'payloads_generated': 0,
            'sessions': 0,
            'training_score': 100
        }
    
    def get_banner(self):
        """Return ASCII banner"""
        banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║  ██████╗ ██████╗  █████╗ ███████╗    ██╗  ██╗██╗      █████╗ ██████╗ ███████╗║
║  ██╔══██╗██╔══██╗██╔══██╗██╔════╝    ╚██╗██╔╝██║     ██╔══██╗██╔══██╗██╔════╝║
║  ██████╔╝██████╔╝███████║█████╗       ╚███╔╝ ██║     ███████║██████╔╝███████╗║
║  ██╔══██╗██╔══██╗██╔══██║██╔══╝       ██╔██╗ ██║     ██╔══██║██╔══██╗╚════██║║
║  ██████╔╝██║  ██║██║  ██║███████╗    ██╔╝ ██╗███████╗██║  ██║██████╔╝███████║║
║  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝    ╚═╝  ╚═╝╚══════╝╚═╝  ╚═╝╚═════╝ ╚══════╝║
║                                                                              ║
║             G R A E - X   L A B S   P R E S E N T S                          ║
║                                                                              ║
║        GAVOT v{self.version} - "{self.codename}" Edition                            ║
║        Advanced Threat Simulation Platform                                   ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        return banner

class SignatureDatabase:
    """Advanced signature database with YARA-like capabilities"""
    
    def __init__(self):
        self.signatures = {}
        self.yara_rules = {}
        self.heuristics = {}
        self.load_defaults()
    
    def load_defaults(self):
        """Load default signatures and rules"""
        # Malware hashes
        self.signatures = {
            'EICAR-Test-File': '44d88612fea8a8f36de82e1278abb02f',
            'Trojan.Win32.Agent': 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3',
            'Ransomware.CryptoLocker': 'da39a3ee5e6b4b0d3255bfef95601890afd80709',
            'Backdoor.Meterpreter': '5d41402abc4b2a76b9719d911017c592',
            'Worm.Stuxnet': 'e99a18c428cb38d5f260853678922e03',
            'Virus.Win32.Nimda': '25d55ad283aa400af464c76d713c07ad',
        }
        
        # YARA-like rules
        self.yara_rules = {
            'suspicious_strings': ['FormatC:', 'VirtualAlloc', 'CreateRemoteThread', 'ProcessHollowing'],
            'packer_signatures': ['UPX0', 'UPX1', 'ASPack', 'Themida', 'VMProtect'],
            'malicious_ips': ['192.168.1.100', '10.0.0.1'],
            'crypto_miners': ['xmrig', 'cpuminer', 'NiceHash'],
        }
    
    def add_custom_signature(self, name, pattern, rule_type='hash'):
        """Add custom signature"""
        if rule_type == 'hash':
            self.signatures[name] = pattern
        elif rule_type == 'yara':
            self.yara_rules[name] = pattern.split(',')
        return True
    
    def scan_with_yara(self, content):
        """Simple YARA-like scanning"""
        matches = []
        for rule_name, patterns in self.yara_rules.items():
            for pattern in patterns:
                if pattern.encode() in content:
                    matches.append(f"{rule_name}:{pattern}")
        return matches

class AdvancedScanner:
    """Advanced scanning engine with multiple detection methods"""
    
    def __init__(self):
        self.signature_db = SignatureDatabase()
        self.scan_results = []
        self.scan_history = []
    
    def multi_hash_scan(self, file_path):
        """Calculate multiple hashes for comprehensive detection"""
        hashes = {}
        algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        
        for algo in algorithms:
            try:
                hash_obj = hashlib.new(algo)
                with open(file_path, 'rb') as f:
                    for chunk in iter(lambda: f.read(4096), b''):
                        hash_obj.update(chunk)
                hashes[algo] = hash_obj.hexdigest()
            except:
                hashes[algo] = None
        
        return hashes
    
    def advanced_scan(self, file_path):
        """Advanced file scanning with multiple techniques"""
        results = {
            'file': file_path,
            'timestamp': datetime.now().isoformat(),
            'hashes': {},
            'signature_matches': [],
            'yara_matches': [],
            'entropy': 0,
            'file_type': 'unknown',
            'verdict': 'CLEAN',
            'threat_level': 0
        }
        
        try:
            # Read file content
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Calculate hashes
            results['hashes'] = self.multi_hash_scan(file_path)
            
            # Check signatures
            threat_score = 0
            for name, sig_hash in self.signature_db.signatures.items():
                if results['hashes'].get('md5') == sig_hash:
                    results['signature_matches'].append(name)
                    threat_score += 50
            
            # YARA-like scanning
            results['yara_matches'] = self.signature_db.scan_with_yara(content)
            threat_score += len(results['yara_matches']) * 10
            
            # Calculate entropy
            if content:
                entropy = self.calculate_entropy(content)
                results['entropy'] = entropy
                if entropy > 7.5:
                    results['heuristic_flags'] = ['High entropy - possible packed/encrypted content']
                    threat_score += 20
            
            # File type detection
            if content[:2] == b'MZ':
                results['file_type'] = 'PE/EXE (Windows)'
            elif content[:4] == b'\x7fELF':
                results['file_type'] = 'ELF (Linux)'
            elif b'#!/' in content[:100]:
                results['file_type'] = 'Script'
            elif b'%PDF' in content[:5]:
                results['file_type'] = 'PDF Document'
            
            # Determine threat level
            results['threat_level'] = min(100, threat_score)
            
            # Determine verdict based on threat level
            if results['signature_matches']:
                results['verdict'] = 'MALICIOUS'
            elif threat_score > 30:
                results['verdict'] = 'SUSPICIOUS'
            elif threat_score > 10:
                results['verdict'] = 'LOW_RISK'
            else:
                results['verdict'] = 'CLEAN'
            
            self.scan_results.append(results)
            return results
            
        except Exception as e:
            results['error'] = str(e)
            results['verdict'] = 'ERROR'
            return results
    
    def calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        entropy = 0
        for x in range(256):
            p_x = data.count(bytes([x])) / len(data)
            if p_x > 0:
                entropy += - p_x * (p_x.bit_length() - 1)
        
        return entropy

class StealthObfuscator:
    """Advanced obfuscation techniques for AV evasion"""
    
    def __init__(self):
        self.techniques = {
            'polymorphic': '🧬 Polymorphic Mutation',
            'packer': '📦 Executable Packer', 
            'string_obf': '🔤 String Obfuscation',
            'junk_code': '🗑️ Junk Code Injection',
            'pe_header': '⚙️ PE Header Modification',
            'xor_encrypt': '🔒 XOR Encryption',
            'dead_code': '💀 Dead Code Insertion',
            'api_obf': '🔗 API Call Obfuscation'
        }
        
    def polymorphic_mutation(self, file_path, output_path):
        """Advanced polymorphic code mutation"""
        try:
            with open(file_path, 'rb') as f:
                content = bytearray(f.read())
            
            mutations = []
            
            # Multiple mutation techniques
            for _ in range(random.randint(5, 20)):
                pos = random.randint(0, len(content))
                junk = os.urandom(random.randint(10, 100))
                content[pos:pos] = junk
                mutations.append(f"Added {len(junk)} bytes junk at position {pos}")
            
            # XOR mutate some bytes
            for i in range(0, min(len(content), 1000), random.randint(10, 100)):
                content[i] ^= random.randint(1, 255)
            
            # Add polymorphic dead code
            dead_code_patterns = [
                b'\x90' * random.randint(5, 50),  # NOP sled
                b'\x50\x58' * random.randint(3, 10),  # PUSH EAX, POP EAX
                b'\x31\xC0' * random.randint(2, 8),  # XOR EAX, EAX
            ]
            
            for pattern in dead_code_patterns:
                pos = random.randint(0, len(content))
                content[pos:pos] = pattern
            
            # Modify PE headers if present
            if content[:2] == b'MZ':
                if len(content) > 0x40:
                    # Randomize some PE header fields
                    content[0x3C:0x40] = struct.pack('<I', random.randint(0x80, 0x200))
                    # Change timestamp
                    content[0x8:0xC] = struct.pack('<I', int(time.time()))
            
            with open(output_path, 'wb') as f:
                f.write(content)
            
            return True, f"Applied {len(mutations)} mutations:\n" + "\n".join(mutations[:5])
            
        except Exception as e:
            return False, f"Mutation failed: {str(e)}"

class PayloadFactory:
    """Advanced payload generator for testing"""
    
    def __init__(self):
        self.payload_templates = {
            'eicar': '🛡️ EICAR Test File',
            'trojan': '🐴 Trojan Simulator',
            'ransomware': '🔒 Ransomware Simulator', 
            'backdoor': '🚪 Backdoor Simulator',
            'keylogger': '⌨️ Keylogger Simulator',
            'rootkit': '👑 Rootkit Simulator',
            'worm': '🐛 Worm Simulator',
            'adware': '📢 Adware Simulator',
            'apt': '🎯 APT Simulation',
            'botnet': '🤖 Botnet Node'
        }
    
    def generate_advanced_payload(self, payload_type, output_dir):
        """Generate advanced test payloads"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if payload_type == 'eicar':
            return self.generate_eicar(output_dir, timestamp)
        elif payload_type == 'trojan':
            return self.generate_trojan(output_dir, timestamp)
        elif payload_type == 'ransomware':
            return self.generate_ransomware(output_dir, timestamp)
        elif payload_type == 'apt':
            return self.generate_apt_simulation(output_dir, timestamp)
        else:
            return self.generate_generic(payload_type, output_dir, timestamp)
    
    def generate_eicar(self, output_dir, timestamp):
        """Generate EICAR test file"""
        eicar_string = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
        filename = f"GRAEX_EICAR_{timestamp}.com"
        filepath = os.path.join(output_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(eicar_string)
        
        return filepath, "EICAR Test File", "Standard AV test payload for training"
    
    def generate_apt_simulation(self, output_dir, timestamp):
        """Generate APT (Advanced Persistent Threat) simulation"""
        filename = f"GRAEX_APT_Simulation_{timestamp}.py"
        filepath = os.path.join(output_dir, filename)
        
        content = '''#!/usr/bin/env python3
# GRAE-X LABS - APT SIMULATION FILE
# FOR EDUCATIONAL PURPOSES ONLY - NOT MALICIOUS

import os
import sys
import json
from datetime import datetime

class APTSimulation:
    """Advanced Persistent Threat Simulation"""
    
    def __init__(self):
        self.team = "GRAE-X Red Team"
        self.objective = "Training Simulation"
    
    def simulate_tactic(self, tactic):
        """Simulate a specific APT tactic"""
        print(f"[SIM] Executing tactic: {tactic}")
        return f"Tactic {tactic} simulated successfully"
    
    def generate_report(self):
        """Generate training report"""
        report = {
            "team": self.team,
            "timestamp": datetime.now().isoformat(),
            "exercise": "APT Simulation",
            "score": random.randint(85, 100),
            "findings": [
                "Security awareness improved by 45%",
                "Detection capabilities enhanced",
                "Response time reduced by 30%"
            ]
        }
        return json.dumps(report, indent=2)

if __name__ == "__main__":
    print("="*60)
    print("GRAE-X LABS - ADVANCED PERSISTENT THREAT SIMULATION")
    print("="*60)
    print("\\n🔐 THIS IS A TRAINING EXERCISE\\n")
    
    apt = APTSimulation()
    print("📋 Simulating APT Tactics...")
    print("✅ SIMULATION COMPLETE")
    print("="*60)
    print("\\n💡 Key Takeaways:")
    print("• APTs use multiple stages and techniques")
    print("• Defense requires layered security")
    print("• Continuous monitoring is essential")
    print("\\n🔒 Stay Secure - GRAE-X Labs")
'''
        
        with open(filepath, 'w') as f:
            f.write(content)
        
        return filepath, "APT Simulator", "Advanced Persistent Threat simulation"

class ReportGenerator:
    """Generate professional reports with Grae-X Labs branding"""
    
    @staticmethod
    def generate_html_report(scan_results, filename="graex_report.html"):
        """Generate HTML report with Grae-X branding"""
        total_files = len(scan_results)
        malicious = sum(1 for r in scan_results if r.get('verdict') == 'MALICIOUS')
        suspicious = sum(1 for r in scan_results if r.get('verdict') == 'SUSPICIOUS')
        clean = sum(1 for r in scan_results if r.get('verdict') == 'CLEAN')
        
        html = f'''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GRAE-X Labs Security Report</title>
    <style>
        :root {{
            --graex-blue: #00f3ff;
            --graex-purple: #bc8cff;
            --graex-green: #00ff9d;
            --graex-red: #ff2a6d;
            --graex-dark: #0a0e17;
            --graex-darker: #050913;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', 'Roboto', sans-serif;
            background: linear-gradient(135deg, var(--graex-darker), var(--graex-dark));
            color: white;
            min-height: 100vh;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: rgba(10, 14, 23, 0.9);
            border-radius: 20px;
            border: 1px solid rgba(0, 243, 255, 0.1);
            box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
            overflow: hidden;
        }}
        
        .header {{
            background: linear-gradient(90deg, 
                rgba(0, 243, 255, 0.1) 0%,
                rgba(188, 140, 255, 0.1) 100%);
            padding: 40px;
            text-align: center;
            position: relative;
            overflow: hidden;
        }}
        
        .logo {{
            font-size: 48px;
            font-weight: bold;
            background: linear-gradient(45deg, var(--graex-blue), var(--graex-purple));
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
        }}
        
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            padding: 30px;
        }}
        
        .stat-card {{
            background: rgba(255, 255, 255, 0.05);
            border-radius: 15px;
            padding: 25px;
            text-align: center;
            border: 1px solid rgba(255, 255, 255, 0.1);
        }}
        
        .stat-value {{
            font-size: 42px;
            font-weight: bold;
            margin: 15px 0;
        }}
        
        .malicious {{ color: var(--graex-red); }}
        .suspicious {{ color: var(--graex-purple); }}
        .clean {{ color: var(--graex-green); }}
        
        .scan-results {{
            padding: 30px;
        }}
        
        .result-card {{
            background: rgba(255, 255, 255, 0.03);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 4px solid var(--graex-blue);
        }}
        
        .result-card.malicious {{
            border-left-color: var(--graex-red);
        }}
        
        .result-card.suspicious {{
            border-left-color: var(--graex-purple);
        }}
        
        .result-card.clean {{
            border-left-color: var(--graex-green);
        }}
        
        .verdict-badge {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
            margin-right: 10px;
        }}
        
        .badge-malicious {{ background: var(--graex-red); }}
        .badge-suspicious {{ background: var(--graex-purple); }}
        .badge-clean {{ background: var(--graex-green); }}
        
        .threat-meter {{
            height: 8px;
            background: rgba(255, 255, 255, 0.1);
            border-radius: 4px;
            margin: 10px 0;
            overflow: hidden;
        }}
        
        .threat-level {{
            height: 100%;
            background: linear-gradient(90deg, var(--graex-green), var(--graex-red));
            border-radius: 4px;
        }}
        
        .footer {{
            text-align: center;
            padding: 30px;
            color: rgba(255, 255, 255, 0.5);
            font-size: 14px;
            border-top: 1px solid rgba(255, 255, 255, 0.1);
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">GRAE-X LABS</div>
            <div>Advanced Security Analysis Report</div>
            <div style="color: rgba(255, 255, 255, 0.7);">
                Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            </div>
        </div>
        
        <div class="stats-grid">
            <div class="stat-card">
                <div>Total Files Scanned</div>
                <div class="stat-value">{total_files}</div>
                <div>📊 Analysis Complete</div>
            </div>
            <div class="stat-card">
                <div>Malicious Detections</div>
                <div class="stat-value malicious">{malicious}</div>
                <div>🚨 Immediate Action Required</div>
            </div>
            <div class="stat-card">
                <div>Suspicious Files</div>
                <div class="stat-value suspicious">{suspicious}</div>
                <div>⚠️ Further Investigation Needed</div>
            </div>
            <div class="stat-card">
                <div>Clean Files</div>
                <div class="stat-value clean">{clean}</div>
                <div>✅ No Threats Detected</div>
            </div>
        </div>
        
        <div class="scan-results">
            <h2 style="margin-bottom: 25px; color: var(--graex-blue);">Detailed Scan Results</h2>
'''
        
        # Add detailed results
        for i, result in enumerate(scan_results):
            verdict = result.get('verdict', 'UNKNOWN').lower()
            threat_level = result.get('threat_level', 0)
            entropy = result.get('entropy', 0)
            file_name = os.path.basename(result.get('file', 'Unknown'))
            file_type = result.get('file_type', 'Unknown')
            
            badge_class = f'badge-{verdict}' if verdict in ['malicious', 'suspicious', 'clean'] else 'badge-suspicious'
            card_class = verdict if verdict in ['malicious', 'suspicious', 'clean'] else 'suspicious'
            
            matches = result.get('signature_matches', []) + result.get('yara_matches', [])
            match_text = ' | '.join(matches[:2]) if matches else 'No signature matches'
            
            html += f'''
            <div class="result-card {card_class}">
                <div style="display: flex; justify-content: space-between; align-items: start;">
                    <div>
                        <h3 style="margin-bottom: 10px;">{file_name}</h3>
                        <span class="verdict-badge {badge_class}">{result.get('verdict', 'UNKNOWN')}</span>
                        <span style="color: rgba(255, 255, 255, 0.7);">Type: {file_type}</span>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 12px; color: rgba(255, 255, 255, 0.5);">
                            Threat Level
                        </div>
                        <div style="font-size: 24px; font-weight: bold; color: {'var(--graex-red)' if threat_level > 50 else 'var(--graex-purple)' if threat_level > 20 else 'var(--graex-green)'}">
                            {threat_level}%
                        </div>
                    </div>
                </div>
                
                <div class="threat-meter">
                    <div class="threat-level" style="width: {threat_level}%"></div>
                </div>
                
                <div style="margin-top: 15px; color: rgba(255, 255, 255, 0.7);">
                    <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                        <span>📊 Entropy: <strong>{entropy:.2f}</strong></span>
                        <span>🔍 Matches: <strong>{len(matches)}</strong></span>
                    </div>
                    <div style="font-size: 12px; margin-top: 10px; color: rgba(255, 255, 255, 0.5);">
                        {match_text}
                    </div>
                </div>
            </div>
            '''
        
        html += '''
        </div>
        
        <div class="footer">
            <div style="margin-bottom: 15px;">
                <div style="color: var(--graex-blue); font-weight: bold; margin-bottom: 5px;">
                    GRAE-X LABS - SECURITY DIVISION
                </div>
                <div style="color: rgba(255, 255, 255, 0.7);">
                    Advanced Threat Intelligence & Cybersecurity Training
                </div>
            </div>
            <div style="font-size: 12px; color: rgba(255, 255, 255, 0.5);">
                This report is generated for educational and training purposes.<br>
                All simulated threats are part of authorized security testing.
            </div>
        </div>
    </div>
    
    <script>
        // Animate threat meters
        document.addEventListener('DOMContentLoaded', function() {
            const meters = document.querySelectorAll('.threat-level');
            meters.forEach(meter => {
                const targetWidth = meter.style.width;
                meter.style.width = '0%';
                setTimeout(() => {
                    meter.style.transition = 'width 1.5s ease-in-out';
                    meter.style.width = targetWidth;
                }, 300);
            });
        });
    </script>
</body>
</html>
'''
        
        with open(filename, 'w') as f:
            f.write(html)
        
        return filename

# ==================== VISUALLY STUNNING GUI ====================

class GAVOTGUI:
    """Visually stunning futuristic UI for GAVOT - Powered by Grae-X Labs"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("GRAE-X LABS | GAVOT v4.0 - Nebula Edition")
        self.root.geometry("1400x900")
        
        # Initialize engine
        self.engine = GAVOTEngine()
        self.engine.stats['sessions'] += 1
        
        # Create test directory FIRST
        self.test_dir = os.path.join(os.getcwd(), "GRAEX_TestFiles")
        if not os.path.exists(self.test_dir):
            os.makedirs(self.test_dir)
        
        print(f"📁 Test directory created: {self.test_dir}")
        
        # ULTRA MODERN COLOR SCHEME - Grae-X Labs Theme
        self.colors = {
            'bg_primary': '#050913',  # Deep Space
            'bg_secondary': '#0a0e17',  # Space Blue
            'bg_light': '#1a1f2e',  # Brighter Space
            'text_primary': '#ffffff',  # Pure White
            'text_secondary': '#b0b7c3',  # Light Gray
            'accent_cyan': '#00f3ff',  # Neon Cyan (Grae-X Blue)
            'accent_blue': '#4d7cfe',  # Electric Blue
            'accent_green': '#00ff9d',  # Neon Green
            'accent_red': '#ff2a6d',  # Pink Red
            'accent_yellow': '#ffd166',  # Gold Yellow
            'accent_purple': '#bc8cff',  # Electric Purple
            'accent_orange': '#ff9e00',  # Orange
            'border': '#2a2f3c',  # Dark Border
            'panel_dark': '#0a0e17',  # For panels
            'panel_medium': '#1a1f2e',  # Medium panels
            'panel_light': '#2a2f3c',  # Light panels
        }
        
        # Configure root window
        self.root.configure(bg=self.colors['bg_primary'])
        
        # Load modern fonts
        self.setup_fonts()
        
        # Create main container
        self.setup_main_layout()
        
        # Display Grae-X Labs intro
        self.show_graex_intro()
    
    def setup_fonts(self):
        """Configure modern cyber fonts"""
        try:
            self.font_title = ('Segoe UI', 24, 'bold')
            self.font_subtitle = ('Segoe UI', 12, 'bold')
            self.font_normal = ('Segoe UI', 10)
            self.font_mono = ('Consolas', 9)
            self.font_digital = ('Consolas', 10, 'bold')
        except:
            self.font_title = ('Arial', 24, 'bold')
            self.font_subtitle = ('Arial', 12, 'bold')
            self.font_normal = ('Arial', 10)
            self.font_mono = ('Courier New', 9)
            self.font_digital = ('Courier New', 10, 'bold')
    
    def setup_main_layout(self):
        """Setup main application layout"""
        # Create main container
        self.main_container = tk.Frame(self.root, bg=self.colors['bg_primary'])
        self.main_container.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Top bar with Grae-X Labs branding
        self.top_bar = tk.Frame(self.main_container,
                               bg=self.colors['panel_dark'],
                               height=70)
        self.top_bar.pack(fill=tk.X, pady=(0, 20))
        self.top_bar.pack_propagate(False)
        
        # Grae-X Labs logo and title
        logo_frame = tk.Frame(self.top_bar, bg=self.colors['panel_dark'])
        logo_frame.pack(side=tk.LEFT, padx=30)
        
        self.logo_label = tk.Label(logo_frame,
                                 text="GRAE-X LABS",
                                 font=('Segoe UI', 24, 'bold'),
                                 fg=self.colors['accent_cyan'],
                                 bg=self.colors['panel_dark'])
        self.logo_label.pack(side=tk.LEFT)
        
        version_badge = tk.Label(logo_frame,
                               text=" v4.0 NEBULA",
                               font=('Segoe UI', 10, 'bold'),
                               fg=self.colors['accent_purple'],
                               bg=self.colors['panel_medium'],
                               padx=10,
                               pady=2)
        version_badge.pack(side=tk.LEFT, padx=(10, 0))
        
        # Main content area
        content_frame = tk.Frame(self.main_container,
                                bg=self.colors['bg_primary'])
        content_frame.pack(fill=tk.BOTH, expand=True)
        
        # Create notebook with custom style
        self.create_custom_notebook(content_frame)
        
        # Status bar
        self.create_status_bar()
    
    def create_custom_notebook(self, parent):
        """Create custom styled notebook"""
        # Create custom style
        self.style = ttk.Style()
        self.style.theme_create('graex', parent='alt', settings={
            'TNotebook': {
                'configure': {
                    'background': self.colors['bg_primary'],
                    'borderwidth': 0,
                    'tabmargins': [0, 5, 0, 0]
                }
            },
            'TNotebook.Tab': {
                'configure': {
                    'background': self.colors['panel_medium'],
                    'foreground': self.colors['text_secondary'],
                    'padding': [25, 10],
                    'borderwidth': 0,
                    'focuscolor': 'none',
                    'font': self.font_subtitle
                },
                'map': {
                    'background': [('selected', self.colors['accent_blue'])],
                    'foreground': [('selected', 'white')],
                    'expand': [('selected', [1, 1, 1, 0])]
                }
            }
        })
        self.style.theme_use('graex')
        
        # Create notebook
        self.notebook = ttk.Notebook(parent, style='TNotebook')
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Store tab indices for navigation
        self.tab_index = {}
        
        # Create all tabs
        self.create_dashboard_tab()
        self.create_scanner_tab()
        self.create_obfuscator_tab()
        self.create_payload_tab()
        self.create_database_tab()
        self.create_reports_tab()
    
    def create_status_bar(self):
        """Create status bar"""
        status_frame = tk.Frame(self.main_container,
                               bg=self.colors['panel_dark'],
                               height=50)
        status_frame.pack(fill=tk.X, side=tk.BOTTOM, pady=(20, 0))
        status_frame.pack_propagate(False)
        
        # Left side: System status
        left_frame = tk.Frame(status_frame, bg=self.colors['panel_dark'])
        left_frame.pack(side=tk.LEFT, padx=30, fill=tk.Y)
        
        self.system_status = tk.Label(left_frame,
                                    text="⚡ SYSTEM READY",
                                    font=self.font_subtitle,
                                    fg=self.colors['accent_green'],
                                    bg=self.colors['panel_dark'])
        self.system_status.pack(side=tk.LEFT)
        
        # Right side: Stats
        right_frame = tk.Frame(status_frame, bg=self.colors['panel_dark'])
        right_frame.pack(side=tk.RIGHT, padx=30, fill=tk.Y)
        
        self.stats_label = tk.Label(right_frame,
                                  text=f"Session #{self.engine.stats['sessions']} • Training Score: {self.engine.stats['training_score']}",
                                  font=self.font_normal,
                                  fg=self.colors['text_secondary'],
                                  bg=self.colors['panel_dark'])
        self.stats_label.pack(side=tk.RIGHT)
    
    def show_graex_intro(self):
        """Display Grae-X Labs introduction"""
        intro_text = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    WELCOME TO GRAE-X LABS                                    ║
║                                                                              ║
║        GAVOT v{self.engine.version} - "{self.engine.codename}" Edition                          ║
║        Advanced Threat Simulation & Cybersecurity Training Platform          ║
║                                                                              ║
║        📁 Test Directory: {self.test_dir}                                     ║
║        🔒 Session: #{self.engine.stats['sessions']}                                                      ║
║        ⚡ Status: Ready for Cyber Operations                                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        
        print("\n" + intro_text)
        self.log_activity("Grae-X Labs GAVOT v4.0 initialized")
        self.log_activity(f"Test directory: {self.test_dir}")
        self.log_activity("System ready for cybersecurity training")
        
        # Update status
        self.update_status("🚀 GRAE-X LABS GAVOT v4.0 Ready - Advanced Cyber Training Platform")
    
    def create_dashboard_tab(self):
        """Create dashboard tab"""
        dashboard = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(dashboard, text="📊 DASHBOARD")
        self.tab_index['dashboard'] = 0
        
        # Dashboard content
        content_frame = tk.Frame(dashboard, bg=self.colors['bg_primary'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=30)
        
        # Welcome header
        header_frame = tk.Frame(content_frame, bg=self.colors['bg_primary'])
        header_frame.pack(fill=tk.X, pady=(0, 40))
        
        welcome_label = tk.Label(header_frame,
                               text="GRAE-X CYBERSECURITY PLATFORM",
                               font=('Segoe UI', 28, 'bold'),
                               fg=self.colors['accent_cyan'],
                               bg=self.colors['bg_primary'])
        welcome_label.pack()
        
        subtitle = tk.Label(header_frame,
                          text="Advanced Threat Intelligence & Training System",
                          font=('Segoe UI', 12),
                          fg=self.colors['text_secondary'],
                          bg=self.colors['bg_primary'])
        subtitle.pack(pady=(10, 0))
        
        # Stats grid
        stats_frame = tk.Frame(content_frame, bg=self.colors['bg_primary'])
        stats_frame.pack(fill=tk.X, pady=(0, 40))
        
        stats_data = [
            ("📈", "Files Scanned", self.engine.stats['files_scanned'], self.colors['accent_blue']),
            ("🔴", "Threats Detected", self.engine.stats['threats_detected'], self.colors['accent_red']),
            ("🎭", "Files Obfuscated", self.engine.stats['files_obfuscated'], self.colors['accent_purple']),
            ("⚡", "Payloads Generated", self.engine.stats['payloads_generated'], self.colors['accent_green'])
        ]
        
        for i, (icon, label, value, color) in enumerate(stats_data):
            card = self.create_stat_card(stats_frame, icon, label, value, color)
            card.grid(row=0, column=i, padx=15, pady=10, sticky='nsew')
            stats_frame.columnconfigure(i, weight=1)
        
        # Quick actions
        actions_frame = tk.Frame(content_frame, bg=self.colors['bg_primary'])
        actions_frame.pack(fill=tk.X, pady=(0, 40))
        
        tk.Label(actions_frame,
                text="⚡ QUICK ACTIONS",
                font=self.font_subtitle,
                fg=self.colors['text_primary'],
                bg=self.colors['bg_primary']).pack(anchor=tk.W, pady=(0, 20))
        
        actions = [
            ("🔍 Test Scanner", self.quick_scan_test),
            ("⚡ Generate EICAR", self.quick_generate_test),
            ("🎭 Try Obfuscation", self.quick_obfuscate_test),
            ("📊 View Reports", self.quick_report)
        ]
        
        actions_row = tk.Frame(actions_frame, bg=self.colors['bg_primary'])
        actions_row.pack()
        
        for i, (text, command) in enumerate(actions):
            btn = tk.Button(actions_row,
                          text=text,
                          command=command,
                          bg=self.colors['panel_medium'],
                          fg=self.colors['text_primary'],
                          font=self.font_normal,
                          relief=tk.FLAT,
                          padx=25,
                          pady=12,
                          cursor='hand2')
            btn.grid(row=0, column=i, padx=10, pady=5)
        
        # Activity log
        log_frame = tk.LabelFrame(content_frame,
                                text=" Recent Activity ",
                                bg=self.colors['panel_dark'],
                                fg=self.colors['accent_cyan'],
                                font=self.font_subtitle,
                                relief=tk.FLAT)
        log_frame.pack(fill=tk.BOTH, expand=True, pady=(20, 0))
        
        self.activity_text = scrolledtext.ScrolledText(log_frame,
                                                     height=10,
                                                     bg=self.colors['panel_light'],
                                                     fg=self.colors['text_primary'],
                                                     font=self.font_mono,
                                                     insertbackground=self.colors['accent_cyan'])
        self.activity_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Configure tags for different message types
        self.activity_text.tag_config('success', foreground=self.colors['accent_green'])
        self.activity_text.tag_config('warning', foreground=self.colors['accent_yellow'])
        self.activity_text.tag_config('error', foreground=self.colors['accent_red'])
        self.activity_text.tag_config('info', foreground=self.colors['accent_cyan'])
    
    def create_stat_card(self, parent, icon, label, value, color):
        """Create stat card"""
        card = tk.Frame(parent,
                       bg=self.colors['panel_dark'],
                       relief=tk.FLAT,
                       bd=0)
        
        # Card content
        content_frame = tk.Frame(card, bg=self.colors['panel_dark'])
        content_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Icon
        tk.Label(content_frame,
                text=icon,
                font=('Segoe UI', 24),
                fg=color,
                bg=self.colors['panel_dark']).pack()
        
        # Value
        tk.Label(content_frame,
                text=str(value),
                font=('Segoe UI', 28, 'bold'),
                fg=color,
                bg=self.colors['panel_dark']).pack(pady=(10, 5))
        
        # Label
        tk.Label(content_frame,
                text=label,
                font=self.font_normal,
                fg=self.colors['text_secondary'],
                bg=self.colors['panel_dark']).pack()
        
        # Bottom accent line
        line = tk.Frame(card,
                       bg=color,
                       height=3)
        line.pack(fill=tk.X)
        
        return card
    
    def create_scanner_tab(self):
        """Create scanner tab"""
        scanner = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(scanner, text="🔍 SCANNER")
        self.tab_index['scanner'] = 1
        
        # Header
        header = tk.Frame(scanner, bg=self.colors['bg_primary'])
        header.pack(fill=tk.X, padx=30, pady=30)
        
        tk.Label(header,
                text="ADVANCED MALWARE SCANNER",
                font=('Segoe UI', 20, 'bold'),
                fg=self.colors['accent_cyan'],
                bg=self.colors['bg_primary']).pack()
        
        tk.Label(header,
                text="Multi-engine threat detection system",
                font=self.font_normal,
                fg=self.colors['text_secondary'],
                bg=self.colors['bg_primary']).pack(pady=(10, 0))
        
        # Main content
        content = tk.Frame(scanner, bg=self.colors['bg_primary'])
        content.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 30))
        
        # Left panel - File selection
        left_panel = tk.Frame(content, bg=self.colors['panel_dark'])
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))
        
        tk.Label(left_panel,
                text="📁 FILE SELECTION",
                font=self.font_subtitle,
                fg=self.colors['accent_cyan'],
                bg=self.colors['panel_dark']).pack(anchor=tk.W, padx=20, pady=20)
        
        # File path entry
        file_frame = tk.Frame(left_panel, bg=self.colors['panel_dark'])
        file_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.scan_file_path = tk.StringVar()
        
        entry = tk.Entry(file_frame,
                        textvariable=self.scan_file_path,
                        bg=self.colors['panel_light'],
                        fg=self.colors['text_primary'],
                        font=self.font_mono,
                        insertbackground=self.colors['accent_cyan'],
                        relief=tk.FLAT)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        browse_btn = tk.Button(file_frame,
                              text="📁 Browse",
                              command=self.browse_scan_file,
                              bg=self.colors['accent_blue'],
                              fg='white',
                              font=self.font_normal,
                              relief=tk.FLAT,
                              padx=20,
                              cursor='hand2')
        browse_btn.pack(side=tk.RIGHT)
        
        # Quick test buttons
        tk.Label(left_panel,
                text="⚡ QUICK TESTS",
                font=self.font_subtitle,
                fg=self.colors['text_secondary'],
                bg=self.colors['panel_dark']).pack(anchor=tk.W, padx=20, pady=(30, 10))
        
        quick_frame = tk.Frame(left_panel, bg=self.colors['panel_dark'])
        quick_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        test_files = [
            ("🛡️", "EICAR Test"),
            ("📄", "Clean File"),
            ("🔢", "Random Data")
        ]
        
        for icon, name in test_files:
            btn = tk.Button(quick_frame,
                          text=f"{icon} {name}",
                          command=lambda n=name: self.create_test_file(n),
                          bg=self.colors['panel_medium'],
                          fg=self.colors['text_primary'],
                          relief=tk.FLAT,
                          font=self.font_normal,
                          padx=15)
            btn.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        
        # Scan button
        scan_btn = tk.Button(left_panel,
                           text="🚀 LAUNCH ADVANCED SCAN",
                           command=self.start_scan,
                           bg=self.colors['accent_green'],
                           fg='white',
                           font=('Segoe UI', 14, 'bold'),
                           padx=40,
                           pady=15,
                           relief=tk.FLAT,
                           cursor='hand2')
        scan_btn.pack(pady=30)
        
        # Right panel - Results
        right_panel = tk.Frame(content, bg=self.colors['panel_dark'])
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        tk.Label(right_panel,
                text="📊 SCAN RESULTS",
                font=self.font_subtitle,
                fg=self.colors['accent_cyan'],
                bg=self.colors['panel_dark']).pack(anchor=tk.W, padx=20, pady=20)
        
        # Results notebook
        results_notebook = ttk.Notebook(right_panel)
        results_notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Summary tab
        summary_tab = tk.Frame(results_notebook, bg=self.colors['panel_dark'])
        results_notebook.add(summary_tab, text="Summary")
        
        self.summary_text = scrolledtext.ScrolledText(summary_tab,
                                                    height=20,
                                                    bg=self.colors['panel_light'],
                                                    fg=self.colors['text_primary'],
                                                    font=self.font_mono,
                                                    insertbackground=self.colors['accent_cyan'])
        self.summary_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Details tab
        details_tab = tk.Frame(results_notebook, bg=self.colors['panel_dark'])
        results_notebook.add(details_tab, text="Details")
        
        columns = ('File', 'Verdict', 'Threat', 'Type', 'Entropy')
        self.results_tree = ttk.Treeview(details_tab, columns=columns, show='headings', height=15)
        
        # Configure columns
        col_widths = {'File': 200, 'Verdict': 100, 'Threat': 80, 'Type': 150, 'Entropy': 80}
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=col_widths.get(col, 100))
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(details_tab, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=scrollbar.set)
        
        self.results_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Configure tags for colors
        self.results_tree.tag_configure('malicious', foreground=self.colors['accent_red'])
        self.results_tree.tag_configure('suspicious', foreground=self.colors['accent_yellow'])
        self.results_tree.tag_configure('clean', foreground=self.colors['accent_green'])
        self.results_tree.tag_configure('low_risk', foreground=self.colors['accent_blue'])
    
    def create_obfuscator_tab(self):
        """Create obfuscator tab"""
        obfuscator = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(obfuscator, text="🎭 OBFUSCATOR")
        self.tab_index['obfuscator'] = 2
        
        # Header
        header = tk.Frame(obfuscator, bg=self.colors['bg_primary'])
        header.pack(fill=tk.X, padx=30, pady=30)
        
        tk.Label(header,
                text="ADVANCED OBFUSCATION ENGINE",
                font=('Segoe UI', 20, 'bold'),
                fg=self.colors['accent_purple'],
                bg=self.colors['bg_primary']).pack()
        
        tk.Label(header,
                text="File obfuscation and AV evasion techniques",
                font=self.font_normal,
                fg=self.colors['text_secondary'],
                bg=self.colors['bg_primary']).pack(pady=(10, 0))
        
        # Main content
        content = tk.Frame(obfuscator, bg=self.colors['bg_primary'])
        content.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 30))
        
        # Left panel - Techniques
        left_panel = tk.Frame(content, bg=self.colors['panel_dark'])
        left_panel.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 15))
        
        tk.Label(left_panel,
                text="🔧 OBFUSCATION TECHNIQUES",
                font=self.font_subtitle,
                fg=self.colors['accent_purple'],
                bg=self.colors['panel_dark']).pack(anchor=tk.W, padx=20, pady=20)
        
        # Techniques list
        techniques_frame = tk.Frame(left_panel, bg=self.colors['panel_dark'])
        techniques_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)
        
        self.tech_vars = {}
        techniques = [
            ("🧬", "Polymorphic Mutation", "Advanced code mutation"),
            ("📦", "Executable Packer", "Compress and pack executables"),
            ("🔤", "String Obfuscation", "Hide suspicious strings"),
            ("🗑️", "Junk Code Injection", "Add random bytes"),
            ("⚙️", "PE Header Modification", "Alter executable headers"),
            ("🔒", "XOR Encryption", "Simple encryption layer")
        ]
        
        for icon, name, desc in techniques:
            var = tk.BooleanVar()
            self.tech_vars[name] = var
            
            frame = tk.Frame(techniques_frame, bg=self.colors['panel_medium'])
            frame.pack(fill=tk.X, pady=5, padx=5)
            
            cb = tk.Checkbutton(frame,
                              text="",
                              variable=var,
                              bg=self.colors['panel_medium'],
                              fg=self.colors['text_primary'],
                              selectcolor=self.colors['accent_purple'])
            cb.pack(side=tk.LEFT, padx=15)
            
            tk.Label(frame,
                    text=f"{icon} {name}",
                    font=self.font_normal,
                    fg=self.colors['text_primary'],
                    bg=self.colors['panel_medium']).pack(side=tk.LEFT, padx=(0, 20))
            
            tk.Label(frame,
                    text=desc,
                    font=('Segoe UI', 8),
                    fg=self.colors['text_secondary'],
                    bg=self.colors['panel_medium']).pack(side=tk.RIGHT, padx=15)
        
        # Right panel - File operations
        right_panel = tk.Frame(content, bg=self.colors['panel_dark'])
        right_panel.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        tk.Label(right_panel,
                text="📁 FILE OPERATIONS",
                font=self.font_subtitle,
                fg=self.colors['accent_purple'],
                bg=self.colors['panel_dark']).pack(anchor=tk.W, padx=20, pady=20)
        
        # Input file
        tk.Label(right_panel,
                text="Input File:",
                font=self.font_normal,
                fg=self.colors['text_primary'],
                bg=self.colors['panel_dark']).pack(anchor=tk.W, padx=20, pady=(0, 10))
        
        input_frame = tk.Frame(right_panel, bg=self.colors['panel_dark'])
        input_frame.pack(fill=tk.X, padx=20, pady=(0, 20))
        
        self.obf_input = tk.StringVar()
        entry = tk.Entry(input_frame,
                        textvariable=self.obf_input,
                        bg=self.colors['panel_light'],
                        fg=self.colors['text_primary'],
                        font=self.font_mono,
                        insertbackground=self.colors['accent_purple'])
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        tk.Button(input_frame,
                 text="Browse",
                 command=lambda: self.browse_file(self.obf_input),
                 bg=self.colors['accent_blue'],
                 fg='white',
                 relief=tk.FLAT).pack(side=tk.RIGHT)
        
        # Output file
        tk.Label(right_panel,
                text="Output File:",
                font=self.font_normal,
                fg=self.colors['text_primary'],
                bg=self.colors['panel_dark']).pack(anchor=tk.W, padx=20, pady=(0, 10))
        
        output_frame = tk.Frame(right_panel, bg=self.colors['panel_dark'])
        output_frame.pack(fill=tk.X, padx=20, pady=(0, 30))
        
        self.obf_output = tk.StringVar()
        entry = tk.Entry(output_frame,
                        textvariable=self.obf_output,
                        bg=self.colors['panel_light'],
                        fg=self.colors['text_primary'],
                        font=self.font_mono,
                        insertbackground=self.colors['accent_purple'])
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        
        tk.Button(output_frame,
                 text="Save As",
                 command=lambda: self.save_file_as(self.obf_output),
                 bg=self.colors['accent_blue'],
                 fg='white',
                 relief=tk.FLAT).pack(side=tk.RIGHT)
        
        # Obfuscate button
        obf_btn = tk.Button(right_panel,
                          text="⚡ EXECUTE OBFUSCATION",
                          command=self.perform_obfuscation,
                          bg=self.colors['accent_purple'],
                          fg='white',
                          font=('Segoe UI', 14, 'bold'),
                          pady=15,
                          relief=tk.FLAT,
                          cursor='hand2')
        obf_btn.pack(pady=20, fill=tk.X, padx=20)
        
        # Results area
        results_frame = tk.Frame(right_panel, bg=self.colors['panel_dark'])
        results_frame.pack(fill=tk.BOTH, expand=True, pady=(20, 0))
        
        tk.Label(results_frame,
                text="📋 RESULTS LOG",
                font=self.font_subtitle,
                fg=self.colors['accent_purple'],
                bg=self.colors['panel_dark']).pack(anchor=tk.W, padx=5, pady=(0, 10))
        
        self.obf_results = scrolledtext.ScrolledText(results_frame,
                                                   height=10,
                                                   bg=self.colors['panel_light'],
                                                   fg=self.colors['text_primary'],
                                                   font=self.font_mono,
                                                   insertbackground=self.colors['accent_purple'])
        self.obf_results.pack(fill=tk.BOTH, expand=True)
    
    def create_payload_tab(self):
        """Create payload generator tab"""
        payload = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(payload, text="⚡ PAYLOADS")
        self.tab_index['payload'] = 3
        
        # Header
        header = tk.Frame(payload, bg=self.colors['bg_primary'])
        header.pack(fill=tk.X, padx=30, pady=30)
        
        tk.Label(header,
                text="ADVANCED PAYLOAD GENERATOR",
                font=('Segoe UI', 20, 'bold'),
                fg=self.colors['accent_green'],
                bg=self.colors['bg_primary']).pack()
        
        tk.Label(header,
                text="Create safe training payloads for cybersecurity exercises",
                font=self.font_normal,
                fg=self.colors['text_secondary'],
                bg=self.colors['bg_primary']).pack(pady=(10, 0))
        
        # Payload grid
        content = tk.Frame(payload, bg=self.colors['bg_primary'])
        content.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 30))
        
        payloads = [
            ("🛡️", "EICAR", self.generate_eicar),
            ("🐴", "Trojan", lambda: self.generate_payload('trojan')),
            ("🔒", "Ransomware", lambda: self.generate_payload('ransomware')),
            ("🚪", "Backdoor", lambda: self.generate_payload('backdoor')),
            ("⌨️", "Keylogger", lambda: self.generate_payload('keylogger')),
            ("👑", "Rootkit", lambda: self.generate_payload('rootkit')),
            ("🐛", "Worm", lambda: self.generate_payload('worm')),
            ("📢", "Adware", lambda: self.generate_payload('adware'))
        ]
        
        for i, (icon, name, command) in enumerate(payloads):
            row, col = divmod(i, 4)
            
            card = self.create_payload_card(content, icon, name, command)
            card.grid(row=row, column=col, padx=10, pady=10, sticky='nsew')
            
            content.columnconfigure(col, weight=1)
            content.rowconfigure(row, weight=1)
    
    def create_payload_card(self, parent, icon, name, command):
        """Create payload card"""
        card = tk.Frame(parent,
                       bg=self.colors['panel_dark'],
                       relief=tk.FLAT,
                       bd=0)
        
        # Card content
        content = tk.Frame(card, bg=self.colors['panel_dark'])
        content.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Icon
        tk.Label(content,
                text=icon,
                font=('Segoe UI', 32),
                fg=self.colors['accent_green'],
                bg=self.colors['panel_dark']).pack(pady=(0, 10))
        
        # Name
        tk.Label(content,
                text=name,
                font=('Segoe UI', 14, 'bold'),
                fg=self.colors['text_primary'],
                bg=self.colors['panel_dark']).pack()
        
        # Generate button
        gen_btn = tk.Button(content,
                          text="GENERATE",
                          command=command,
                          bg=self.colors['panel_medium'],
                          fg=self.colors['text_primary'],
                          relief=tk.FLAT,
                          padx=20,
                          cursor='hand2')
        gen_btn.pack(pady=(15, 5))
        
        return card
    
    def create_database_tab(self):
        """Create signature database tab"""
        database = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(database, text="📊 DATABASE")
        self.tab_index['database'] = 4
        
        # Header
        header = tk.Frame(database, bg=self.colors['bg_primary'])
        header.pack(fill=tk.X, padx=30, pady=30)
        
        tk.Label(header,
                text="THREAT SIGNATURE DATABASE",
                font=('Segoe UI', 20, 'bold'),
                fg=self.colors['accent_yellow'],
                bg=self.colors['bg_primary']).pack()
        
        count = len(self.engine.signature_db.signatures) + len(self.engine.signature_db.yara_rules)
        tk.Label(header,
                text=f"{count} Threat Signatures | Real-time Updates",
                font=self.font_normal,
                fg=self.colors['text_secondary'],
                bg=self.colors['bg_primary']).pack(pady=(10, 0))
        
        # Main content
        content = tk.Frame(database, bg=self.colors['bg_primary'])
        content.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 30))
        
        # Database view
        db_frame = tk.Frame(content, bg=self.colors['panel_dark'])
        db_frame.pack(fill=tk.BOTH, expand=True)
        
        # Treeview
        columns = ('Name', 'Type', 'Signature', 'Severity')
        self.db_tree = ttk.Treeview(db_frame, columns=columns, show='headings', height=20)
        
        # Configure columns
        col_widths = {'Name': 200, 'Type': 100, 'Signature': 300, 'Severity': 100}
        for col in columns:
            self.db_tree.heading(col, text=col)
            self.db_tree.column(col, width=col_widths.get(col, 100))
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(db_frame, orient=tk.VERTICAL, command=self.db_tree.yview)
        self.db_tree.configure(yscrollcommand=scrollbar.set)
        
        self.db_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Controls
        controls = tk.Frame(content, bg=self.colors['bg_primary'])
        controls.pack(fill=tk.X, pady=(20, 0))
        
        tk.Button(controls,
                 text="🔄 Refresh",
                 command=self.refresh_database,
                 bg=self.colors['accent_blue'],
                 fg='white',
                 relief=tk.FLAT).pack(side=tk.LEFT, padx=5)
        
        tk.Button(controls,
                 text="➕ Add Signature",
                 command=self.add_signature_dialog,
                 bg=self.colors['accent_green'],
                 fg='white',
                 relief=tk.FLAT).pack(side=tk.LEFT, padx=5)
        
        tk.Button(controls,
                 text="✖️ Remove",
                 command=self.remove_signature,
                 bg=self.colors['accent_red'],
                 fg='white',
                 relief=tk.FLAT).pack(side=tk.LEFT, padx=5)
        
        # Load initial data
        self.refresh_database()
    
    def create_reports_tab(self):
        """Create reports tab"""
        reports = tk.Frame(self.notebook, bg=self.colors['bg_primary'])
        self.notebook.add(reports, text="📈 REPORTS")
        self.tab_index['reports'] = 5
        
        # Header
        header = tk.Frame(reports, bg=self.colors['bg_primary'])
        header.pack(fill=tk.X, padx=30, pady=30)
        
        tk.Label(header,
                text="PROFESSIONAL SECURITY REPORTING",
                font=('Segoe UI', 20, 'bold'),
                fg=self.colors['accent_cyan'],
                bg=self.colors['bg_primary']).pack()
        
        tk.Label(header,
                text="Generate detailed security assessment reports",
                font=self.font_normal,
                fg=self.colors['text_secondary'],
                bg=self.colors['bg_primary']).pack(pady=(10, 0))
        
        # Main content
        content = tk.Frame(reports, bg=self.colors['bg_primary'])
        content.pack(fill=tk.BOTH, expand=True, padx=30, pady=(0, 30))
        
        # Report controls
        controls = tk.Frame(content, bg=self.colors['panel_dark'])
        controls.pack(fill=tk.X, pady=(0, 20))
        
        tk.Button(controls,
                 text="📊 GENERATE HTML REPORT",
                 command=self.generate_html_report,
                 bg=self.colors['accent_blue'],
                 fg='white',
                 font=('Segoe UI', 14, 'bold'),
                 pady=15,
                 relief=tk.FLAT,
                 cursor='hand2').pack(pady=20, padx=20)
        
        # Report preview
        preview_frame = tk.Frame(content, bg=self.colors['panel_dark'])
        preview_frame.pack(fill=tk.BOTH, expand=True)
        
        tk.Label(preview_frame,
                text="📋 REPORT PREVIEW",
                font=self.font_subtitle,
                fg=self.colors['accent_cyan'],
                bg=self.colors['panel_dark']).pack(anchor=tk.W, padx=20, pady=20)
        
        self.report_text = scrolledtext.ScrolledText(preview_frame,
                                                   height=20,
                                                   bg=self.colors['panel_light'],
                                                   fg=self.colors['text_primary'],
                                                   font=self.font_mono,
                                                   insertbackground=self.colors['accent_cyan'])
        self.report_text.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        # Add sample report
        self.report_text.insert(1.0, "GRAE-X LABS SECURITY REPORTING SYSTEM\n")
        self.report_text.insert(tk.END, "="*50 + "\n\n")
        self.report_text.insert(tk.END, "Ready to generate professional security reports.\n\n")
    
    # ============ UTILITY METHODS ============
    
    def update_status(self, message):
        """Update status bar"""
        self.system_status.config(text=message)
        self.root.update_idletasks()
    
    def log_activity(self, message, msg_type='info'):
        """Log activity to dashboard with color coding"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if msg_type == 'success':
            tag = 'success'
            prefix = "✅"
        elif msg_type == 'warning':
            tag = 'warning'
            prefix = "⚠️"
        elif msg_type == 'error':
            tag = 'error'
            prefix = "❌"
        else:
            tag = 'info'
            prefix = "ℹ️"
        
        log_entry = f"[{timestamp}] {prefix} {message}\n"
        
        # Insert with appropriate tag
        self.activity_text.insert(tk.END, log_entry, (tag,))
        self.activity_text.see(tk.END)
    
    # ============ FILE BROWSING METHODS ============
    
    def browse_scan_file(self):
        """Browse for ANY file to scan"""
        filename = filedialog.askopenfilename(
            title="Select ANY file to scan",
            initialdir=self.test_dir,
            filetypes=[("All files", "*.*")]
        )
        
        if filename:
            self.scan_file_path.set(filename)
            self.summary_text.delete(1.0, tk.END)
            self.summary_text.insert(1.0, f"📄 File selected: {filename}\n\n")
            self.summary_text.insert(tk.END, "Click '🚀 LAUNCH ADVANCED SCAN' to analyze this file.")
            self.log_activity(f"File selected for scanning: {os.path.basename(filename)}")
    
    def browse_file(self, var):
        """Browse for file"""
        filename = filedialog.askopenfilename(title="Select file")
        if filename:
            var.set(filename)
    
    def save_file_as(self, var):
        """Save file as"""
        filename = filedialog.asksaveasfilename(
            title="Save file as",
            defaultextension=".exe",
            initialdir=self.test_dir
        )
        if filename:
            var.set(filename)
    
    # ============ TEST FILE METHODS ============
    
    def create_test_file(self, file_type):
        """Create a test file for quick scanning"""
        filename = ""
        
        if file_type == "EICAR Test":
            eicar_string = r'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
            filename = os.path.join(self.test_dir, "GRAEX_EICAR_Test.com")
            with open(filename, 'w') as f:
                f.write(eicar_string)
            self.log_activity("Created EICAR test file", 'success')
            
        elif file_type == "Clean File":
            filename = os.path.join(self.test_dir, "GRAEX_Clean_Test.txt")
            with open(filename, 'w') as f:
                f.write("GRAE-X LABS CLEAN TEST FILE\n")
                f.write("="*40 + "\n")
                f.write("This file contains no malicious content.\n")
                f.write("Created for cybersecurity training purposes.\n")
                f.write("Timestamp: " + datetime.now().isoformat() + "\n")
            self.log_activity("Created clean test file", 'info')
            
        elif file_type == "Random Data":
            filename = os.path.join(self.test_dir, "GRAEX_Random_Data.bin")
            with open(filename, 'wb') as f:
                f.write(os.urandom(2048))
            self.log_activity("Created random binary file", 'info')
        
        if filename:
            self.scan_file_path.set(filename)
            self.summary_text.delete(1.0, tk.END)
            self.summary_text.insert(1.0, f"✅ {file_type} created successfully!\n\n")
            self.summary_text.insert(tk.END, f"📁 Path: {filename}\n\n")
            self.summary_text.insert(tk.END, "Click '🚀 LAUNCH ADVANCED SCAN' to analyze this file.")
            self.update_status(f"Created {file_type}")
    
    # ============ SCANNER METHODS ============
    
    def start_scan(self):
        """Start scanning the selected file"""
        file_path = self.scan_file_path.get()
        
        if not file_path or not os.path.exists(file_path):
            messagebox.showwarning("Warning", "Please select a valid file first!")
            return
        
        # Clear previous results
        self.summary_text.delete(1.0, tk.END)
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        self.summary_text.insert(1.0, f"🔍 Scanning: {os.path.basename(file_path)}\n")
        self.summary_text.insert(tk.END, "="*60 + "\n\n")
        self.summary_text.insert(tk.END, "⚡ Starting advanced analysis... Please wait.\n")
        
        self.update_status(f"Scanning {os.path.basename(file_path)}...")
        self.log_activity(f"Started advanced scan: {file_path}", 'info')
        
        # Start scan in thread
        thread = threading.Thread(target=self.perform_scan, args=(file_path,))
        thread.daemon = True
        thread.start()
    
    def perform_scan(self, file_path):
        """Perform the scan in background thread"""
        try:
            # Perform advanced scan
            result = self.engine.scanner.advanced_scan(file_path)
            
            # Update stats
            self.engine.stats['files_scanned'] += 1
            if result['verdict'] == 'MALICIOUS':
                self.engine.stats['threats_detected'] += 1
                self.engine.stats['training_score'] += 10
            
            # Update GUI in main thread
            self.root.after(0, self.display_scan_results, result)
            
        except Exception as e:
            self.root.after(0, self.display_scan_error, str(e))
    
    def display_scan_results(self, result):
        """Display scan results in GUI"""
        self.summary_text.delete(1.0, tk.END)
        
        # Build beautiful summary
        verdict = result['verdict']
        threat_level = result.get('threat_level', 0)
        entropy = result.get('entropy', 0)
        
        if verdict == 'MALICIOUS':
            verdict_color = self.colors['accent_red']
            verdict_icon = "🚨"
            verdict_text = "MALICIOUS - Immediate Action Required"
        elif verdict == 'SUSPICIOUS':
            verdict_color = self.colors['accent_yellow']
            verdict_icon = "⚠️"
            verdict_text = "SUSPICIOUS - Further Investigation Needed"
        elif verdict == 'LOW_RISK':
            verdict_color = self.colors['accent_blue']
            verdict_icon = "🔵"
            verdict_text = "LOW RISK - Monitor Closely"
        else:
            verdict_color = self.colors['accent_green']
            verdict_icon = "✅"
            verdict_text = "CLEAN - No Threats Detected"
        
        summary = f"""
{verdict_icon} GRAE-X LABS SCAN RESULTS {verdict_icon}

📁 File: {os.path.basename(result['file'])}
📅 Scan Time: {result['timestamp']}
🔍 Verdict: {verdict_text}
📊 File Type: {result.get('file_type', 'Unknown')}
🧮 Entropy: {entropy:.2f}
🎯 Threat Level: {threat_level}%

THREAT ANALYSIS:
"""
        
        # Add threat meter
        meter_width = 40
        filled = int((threat_level / 100) * meter_width)
        meter = "█" * filled + "░" * (meter_width - filled)
        summary += f"\nThreat Meter: [{meter}] {threat_level}%\n"
        
        # Add hashes
        summary += f"\nFILE HASHES:\n"
        
        for algo, hash_val in result.get('hashes', {}).items():
            if hash_val:
                summary += f"{algo.upper()}: {hash_val[:32]}...\n"
        
        # Add signature matches
        if result.get('signature_matches'):
            summary += f"\n⚠️  SIGNATURE MATCHES:\n"
            for match in result['signature_matches']:
                summary += f"   • {match}\n"
        
        # Add YARA matches
        if result.get('yara_matches'):
            summary += f"\n🔍 YARA RULE MATCHES:\n"
            for match in result['yara_matches'][:3]:
                summary += f"   • {match}\n"
        
        # Add recommendations
        summary += f"\nRECOMMENDATIONS:\n"
        
        if verdict == 'MALICIOUS':
            summary += "1. 🚨 ISOLATE file immediately\n"
            summary += "2. 🔒 Run full system scan\n"
            summary += "3. 📊 Review security logs\n"
            summary += "4. 🛡️ Update security definitions\n"
        elif verdict == 'SUSPICIOUS':
            summary += "1. 🔍 Analyze in sandbox environment\n"
            summary += "2. 📝 Review file behavior logs\n"
            summary += "3. 🎯 Monitor for suspicious activity\n"
            summary += "4. 📊 Consider additional scanning\n"
        else:
            summary += "1. ✅ File appears safe\n"
            summary += "2. 🔄 Continue regular monitoring\n"
            summary += "3. 📚 Document for future reference\n"
        
        self.summary_text.insert(1.0, summary)
        
        # Add to treeview
        file_name = os.path.basename(result['file'])
        matches = result.get('signature_matches', []) + result.get('yara_matches', [])
        match_text = ', '.join(matches[:2]) if matches else 'None'
        
        # Determine tag for color
        tag = result['verdict'].lower()
        
        self.results_tree.insert('', tk.END, values=(
            file_name,
            result['verdict'],
            f"{threat_level}%",
            result.get('file_type', 'Unknown'),
            f"{entropy:.2f}"
        ), tags=(tag,))
        
        self.update_status(f"Scan complete: {verdict}")
        self.log_activity(f"Scan completed: {file_name} - {verdict}", 
                         'error' if verdict == 'MALICIOUS' else 'warning' if verdict == 'SUSPICIOUS' else 'success')
        
        # Update training score
        if verdict != 'CLEAN':
            self.engine.stats['training_score'] += 5
            self.stats_label.config(text=f"Session #{self.engine.stats['sessions']} • Training Score: {self.engine.stats['training_score']}")
    
    def display_scan_error(self, error_msg):
        """Display scan error"""
        self.summary_text.delete(1.0, tk.END)
        self.summary_text.insert(1.0, f"❌ SCAN ERROR\n{'='*40}\n\n")
        self.summary_text.insert(tk.END, f"Error: {error_msg}\n\n")
        self.summary_text.insert(tk.END, "Troubleshooting Steps:\n")
        self.summary_text.insert(tk.END, "• Verify file is not in use by another program\n")
        self.summary_text.insert(tk.END, "• Check file permissions\n")
        self.summary_text.insert(tk.END, "• Ensure file is not corrupted\n")
        self.summary_text.insert(tk.END, "• Try running as administrator\n")
        
        self.update_status("Scan failed - check file permissions")
        self.log_activity(f"Scan error: {error_msg}", 'error')
    
    # ============ OBFUSCATOR METHODS ============
    
    def perform_obfuscation(self):
        """Perform file obfuscation"""
        input_file = self.obf_input.get()
        output_file = self.obf_output.get()
        
        if not input_file or not os.path.exists(input_file):
            messagebox.showerror("Error", "Please select a valid input file!")
            return
        
        if not output_file:
            messagebox.showerror("Error", "Please specify output file path!")
            return
        
        # Get selected techniques
        selected_techs = [name for name, var in self.tech_vars.items() if var.get()]
        
        if not selected_techs:
            messagebox.showwarning("Warning", "Please select at least one obfuscation technique!")
            return
        
        self.obf_results.delete(1.0, tk.END)
        self.obf_results.insert(1.0, "⚡ Starting advanced obfuscation...\n")
        self.obf_results.insert(tk.END, f"Selected techniques: {', '.join(selected_techs)}\n\n")
        self.update_status("Obfuscating file with selected techniques...")
        self.log_activity(f"Starting obfuscation: {os.path.basename(input_file)}", 'info')
        
        # Run in thread
        thread = threading.Thread(target=self._run_obfuscation, 
                                 args=(input_file, output_file, selected_techs))
        thread.daemon = True
        thread.start()
    
    def _run_obfuscation(self, input_file, output_file, techniques):
        """Run obfuscation in background thread"""
        try:
            # Calculate original hash and size
            with open(input_file, 'rb') as f:
                original_content = f.read()
            original_hash = hashlib.md5(original_content).hexdigest()
            original_size = len(original_content)
            
            # Apply first selected technique
            tech_name = techniques[0]
            
            # For simulation, just copy with marker
            with open(output_file, 'wb') as f:
                f.write(original_content + b"\n// GRAE-X OBFUSCATED - " + tech_name.encode() + b"\n")
            
            success = True
            message = f"Simulated {tech_name} applied\nFile marked as obfuscated"
            
            if success:
                # Calculate new hash
                with open(output_file, 'rb') as f:
                    new_content = f.read()
                new_hash = hashlib.md5(new_content).hexdigest()
                new_size = len(new_content)
                
                result_text = f"""
✅ OBFUSCATION SUCCESSFUL

Technique: {tech_name}
{message}

TRANSFORMATION STATS:

Original File:
  Size: {original_size:,} bytes
  MD5: {original_hash[:16]}...

Obfuscated File:
  Size: {new_size:,} bytes
  MD5: {new_hash[:16]}...

🔍 RESULT: {'✅ Signature CHANGED!' if original_hash != new_hash else '⚠️  Signature UNCHANGED'}

📁 Output saved to: {output_file}
"""
                
                # Update stats
                self.engine.stats['files_obfuscated'] += 1
                self.engine.stats['training_score'] += 15
                self.log_activity(f"Obfuscated: {os.path.basename(input_file)} → {os.path.basename(output_file)}", 'success')
                
            else:
                result_text = f"❌ OBFUSCATION FAILED\n\nError: {message}"
                self.log_activity(f"Obfuscation failed: {message}", 'error')
            
            # Update GUI
            self.root.after(0, self._display_obfuscation_result, result_text, success)
            
        except Exception as e:
            self.root.after(0, self._display_obfuscation_result, f"❌ ERROR: {str(e)}", False)
    
    def _display_obfuscation_result(self, message, success):
        """Display obfuscation result"""
        self.obf_results.delete(1.0, tk.END)
        self.obf_results.insert(1.0, message)
        
        if success:
            self.update_status("Obfuscation successful! Training score +15")
            self.stats_label.config(text=f"Session #{self.engine.stats['sessions']} • Training Score: {self.engine.stats['training_score']}")
        else:
            self.update_status("Obfuscation failed")
    
    # ============ PAYLOAD METHODS ============
    
    def generate_eicar(self):
        """Generate EICAR test file"""
        self.generate_payload('eicar')
    
    def generate_payload(self, payload_type):
        """Generate payload"""
        output_dir = self.test_dir
        
        if not os.path.exists(output_dir):
            try:
                os.makedirs(output_dir)
            except:
                messagebox.showerror("Error", f"Cannot create directory: {output_dir}")
                return
        
        self.update_status(f"Generating {payload_type} payload...")
        
        try:
            # Generate payload
            filepath, name, description = self.engine.payload_factory.generate_advanced_payload(payload_type, output_dir)
            
            # Update status
            self.update_status(f"Generated {payload_type} payload")
            self.log_activity(f"Generated payload: {os.path.basename(filepath)}", 'success')
            
            # Auto-select in scanner if it's EICAR
            if payload_type == 'eicar':
                self.scan_file_path.set(filepath)
                self.summary_text.delete(1.0, tk.END)
                self.summary_text.insert(1.0, f"✅ EICAR test file generated!\n\n")
                self.summary_text.insert(tk.END, f"Path: {filepath}\n\n")
                self.summary_text.insert(tk.END, "Click '🚀 LAUNCH ADVANCED SCAN' to test detection.")
            
            # Show success message with Grae-X branding
            messagebox.showinfo("Success", 
                              f"✅ {name} generated successfully!\n\n"
                              f"📍 Location: {filepath}\n\n"
                              f"📝 Purpose: {description}\n\n"
                              f"🔒 This is a simulated payload for educational purposes only.\n"
                              f"Powered by Grae-X Labs Cybersecurity Training")
            
            # Update stats
            self.engine.stats['payloads_generated'] += 1
            self.engine.stats['training_score'] += 20
            self.stats_label.config(text=f"Session #{self.engine.stats['sessions']} • Training Score: {self.engine.stats['training_score']}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate payload:\n{str(e)}")
            self.update_status("Payload generation failed")
            self.log_activity(f"Payload generation failed: {str(e)}", 'error')
    
    # ============ DATABASE METHODS ============
    
    def refresh_database(self):
        """Refresh signature database display"""
        # Clear tree
        for item in self.db_tree.get_children():
            self.db_tree.delete(item)
        
        # Add signatures
        for name, sig in self.engine.signature_db.signatures.items():
            severity = "High" if "EICAR" in name else "Medium" if "Trojan" in name else "Low"
            self.db_tree.insert('', tk.END, values=(name, 'Hash', sig[:32] + '...', severity))
        
        # Add YARA rules
        for name, patterns in self.engine.signature_db.yara_rules.items():
            pattern_text = ', '.join(patterns[:2])
            if len(patterns) > 2:
                pattern_text += f"... (+{len(patterns)-2} more)"
            self.db_tree.insert('', tk.END, values=(name, 'YARA', pattern_text, 'Medium'))
        
        self.log_activity("Refreshed threat database", 'info')
    
    def add_signature_dialog(self):
        """Open dialog to add signature"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Add Threat Signature")
        dialog.geometry("500x400")
        dialog.configure(bg=self.colors['bg_primary'])
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Center dialog
        dialog.update_idletasks()
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (500 // 2)
        y = self.root.winfo_y() + (self.root.winfo_height() // 2) - (400 // 2)
        dialog.geometry(f"+{x}+{y}")
        
        # Dialog content
        tk.Label(dialog,
                text="➕ ADD NEW SIGNATURE",
                bg=self.colors['bg_primary'],
                fg=self.colors['accent_cyan'],
                font=self.font_subtitle).pack(pady=20)
        
        # Form fields
        fields = [
            ("Signature Name:", tk.StringVar()),
            ("Signature Type:", tk.StringVar(value='hash')),
            ("Pattern/Hash:", tk.StringVar()),
            ("Severity:", tk.StringVar(value='Medium'))
        ]
        
        for label, var in fields:
            frame = tk.Frame(dialog, bg=self.colors['bg_primary'])
            frame.pack(fill=tk.X, padx=50, pady=5)
            
            tk.Label(frame,
                    text=label,
                    bg=self.colors['bg_primary'],
                    fg=self.colors['text_primary']).pack(side=tk.LEFT)
            
            if label == "Signature Type:":
                tk.Radiobutton(frame,
                             text="Hash",
                             variable=var,
                             value='hash',
                             bg=self.colors['bg_primary'],
                             fg=self.colors['text_primary']).pack(side=tk.LEFT, padx=10)
                tk.Radiobutton(frame,
                             text="YARA",
                             variable=var,
                             value='yara',
                             bg=self.colors['bg_primary'],
                             fg=self.colors['text_primary']).pack(side=tk.LEFT)
            elif label == "Severity:":
                severity_frame = tk.Frame(frame, bg=self.colors['bg_primary'])
                severity_frame.pack(side=tk.RIGHT)
                for sev in ['Low', 'Medium', 'High']:
                    tk.Radiobutton(severity_frame,
                                 text=sev,
                                 variable=var,
                                 value=sev,
                                 bg=self.colors['bg_primary'],
                                 fg=self.colors['text_primary']).pack(side=tk.LEFT, padx=5)
            else:
                tk.Entry(frame,
                        textvariable=var,
                        bg=self.colors['panel_light'],
                        fg=self.colors['text_primary'],
                        width=40).pack(side=tk.RIGHT)
        
        # Buttons
        btn_frame = tk.Frame(dialog, bg=self.colors['bg_primary'])
        btn_frame.pack(pady=30)
        
        tk.Button(btn_frame,
                 text="Add Signature",
                 command=lambda: self.add_signature(
                     fields[0][1].get(),
                     fields[2][1].get(),
                     fields[1][1].get(),
                     dialog
                 ),
                 bg=self.colors['accent_green'],
                 fg='white',
                 padx=30).pack(side=tk.LEFT, padx=10)
        
        tk.Button(btn_frame,
                 text="Cancel",
                 command=dialog.destroy,
                 bg=self.colors['accent_red'],
                 fg='white',
                 padx=30).pack(side=tk.RIGHT, padx=10)
    
    def add_signature(self, name, pattern, sig_type, dialog):
        """Add signature to database"""
        if not name or not pattern:
            messagebox.showerror("Error", "Please fill in all fields!")
            return
        
        if sig_type == 'hash':
            self.engine.signature_db.add_custom_signature(name, pattern, 'hash')
        else:
            self.engine.signature_db.add_custom_signature(name, pattern, 'yara')
        
        self.refresh_database()
        self.log_activity(f"Added signature: {name}", 'success')
        dialog.destroy()
        messagebox.showinfo("Success", f"Signature '{name}' added successfully!")
    
    def remove_signature(self):
        """Remove selected signature"""
        selection = self.db_tree.selection()
        if not selection:
            messagebox.showwarning("Warning", "Please select a signature to remove!")
            return
        
        item = selection[0]
        name = self.db_tree.item(item)['values'][0]
        
        if messagebox.askyesno("Confirm", f"Remove signature '{name}'?"):
            # Remove from appropriate dictionary
            if name in self.engine.signature_db.signatures:
                del self.engine.signature_db.signatures[name]
            elif name in self.engine.signature_db.yara_rules:
                del self.engine.signature_db.yara_rules[name]
            
            self.refresh_database()
            self.log_activity(f"Removed signature: {name}", 'warning')
    
    # ============ REPORT METHODS ============
    
    def generate_html_report(self):
        """Generate HTML report with Grae-X branding"""
        if not self.engine.scanner.scan_results:
            messagebox.showwarning("Warning", 
                                 "No scan results to report!\n\n"
                                 "Please run some scans first to generate a report.")
            return
        
        filename = filedialog.asksaveasfilename(
            title="Save GRAE-X Security Report",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialdir=self.test_dir,
            initialfile=f"GRAEX_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        )
        
        if filename:
            try:
                report_file = self.engine.report_generator.generate_html_report(
                    self.engine.scanner.scan_results,
                    filename
                )
                
                self.report_text.delete(1.0, tk.END)
                report_msg = f"""
✅ GRAE-X SECURITY REPORT GENERATED

📁 Report saved to: {report_file}

📊 Report Contents:
• Executive summary with threat overview
• Detailed scan results with threat levels
• File hash comparisons
• Entropy analysis
• Security recommendations

🎯 Training Value:
• Professional reporting format
• Real-world security documentation
• Executive communication practice
• Technical analysis skills

🔒 Security Note:
All simulated threats are part of authorized
cybersecurity training exercises.

📈 Total scans in report: {len(self.engine.scanner.scan_results)}
"""
                
                self.report_text.insert(1.0, report_msg)
                self.update_status("Professional HTML report generated")
                self.log_activity(f"Generated report: {os.path.basename(report_file)}", 'success')
                
                # Update training score
                self.engine.stats['training_score'] += 25
                self.stats_label.config(text=f"Session #{self.engine.stats['sessions']} • Training Score: {self.engine.stats['training_score']}")
                
                # Try to open the report
                try:
                    if platform.system() == 'Windows':
                        os.startfile(report_file)
                    elif platform.system() == 'Darwin':  # macOS
                        subprocess.run(['open', report_file])
                    else:  # Linux
                        subprocess.run(['xdg-open', report_file])
                except:
                    pass  # Ignore if can't open
                    
            except Exception as e:
                messagebox.showerror("Error", f"Failed to generate report:\n{str(e)}")
                self.log_activity(f"Report generation failed: {str(e)}", 'error')
    
    # ============ QUICK ACTION METHODS ============
    
    def quick_scan_test(self):
        """Quick scan test action"""
        try:
            self.notebook.select(self.tab_index['scanner'])
        except:
            messagebox.showerror("Error", "Scanner tab not available")
            return
        
        # Create and select EICAR file
        self.create_test_file("EICAR Test")
        messagebox.showinfo("Quick Test", 
                          "🎯 EICAR test file created and selected!\n\n"
                          "Click '🚀 LAUNCH ADVANCED SCAN' to test detection.\n\n"
                          "Expected result: MALICIOUS - EICAR-Test-File")
    
    def quick_generate_test(self):
        """Quick generate test action"""
        try:
            self.notebook.select(self.tab_index['payload'])
        except:
            messagebox.showerror("Error", "Payloads tab not available")
            return
        self.generate_eicar()
    
    def quick_obfuscate_test(self):
        """Quick obfuscate test action"""
        try:
            self.notebook.select(self.tab_index['obfuscator'])
        except:
            messagebox.showerror("Error", "Obfuscator tab not available")
            return
        
        # Create a test file if none exists
        test_file = os.path.join(self.test_dir, "test_to_obfuscate.txt")
        if not os.path.exists(test_file):
            with open(test_file, 'w') as f:
                f.write("GRAE-X LABS OBFUSCATION TEST FILE\n")
                f.write("="*40 + "\n")
                f.write("This file is for obfuscation testing.\n")
        
        self.obf_input.set(test_file)
        self.obf_output.set(os.path.join(self.test_dir, "graex_obfuscated_test.txt"))
        
        messagebox.showinfo("Quick Obfuscate", 
                          "🎭 Test file selected for obfuscation!\n\n"
                          "Select a technique and click '⚡ EXECUTE OBFUSCATION'.\n\n"
                          "Training score +15 on successful obfuscation")
    
    def quick_report(self):
        """Quick report action"""
        try:
            self.notebook.select(self.tab_index['reports'])
        except:
            messagebox.showerror("Error", "Reports tab not available")
            return
            
        if self.engine.scanner.scan_results:
            self.generate_html_report()
        else:
            messagebox.showinfo("No Data", 
                              "📊 No scan data available yet.\n\n"
                              "Please run some scans first to generate a report.")

# ==================== MAIN APPLICATION ====================

def main():
    """Main application entry point with Grae-X Labs branding"""
    try:
        # Check for pefile dependency
        try:
            import pefile
        except ImportError:
            print("Installing required dependencies...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "pefile"])
            import pefile
        
        # Create main window
        root = tk.Tk()
        
        # Set window properties
        root.title("GRAE-X LABS | GAVOT v4.0 - Nebula Edition")
        
        # Create application
        app = GAVOTGUI(root)
        
        # Center window
        root.update_idletasks()
        width = root.winfo_width()
        height = root.winfo_height()
        x = (root.winfo_screenwidth() // 2) - (width // 2)
        y = (root.winfo_screenheight() // 2) - (height // 2)
        root.geometry(f'{width}x{height}+{x}+{y}')
        
        # Make window resizable
        root.minsize(1200, 800)
        
        # Print welcome message
        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║                    GRAE-X LABS PRESENTS                                      ║
║                                                                              ║
║        ██████╗  █████╗ ██╗   ██╗ ███████╗    ██╗  ██╗                       ║
║        ██╔════╝ ██╔══██╗██║   ██║ ██╔════╝    ╚██╗██╔╝                       ║
║        ██║  ███╗███████║██║   ██║ █████╗       ╚███╔╝                        ║
║        ██║   ██║██╔══██║██║   ██║ ██╔══╝       ██╔██╗                        ║
║        ╚██████╔╝██║  ██║╚██████╔╝ ███████╗    ██╔╝ ██╗                       ║
║         ╚═════╝ ╚═╝  ╚═╝ ╚═════╝  ╚══════╝    ╚═╝  ╚═╝                       ║
║                                                                              ║
║            GAVOT v4.0 - "Nebula" Edition                                     ║
║            Advanced Threat Simulation Platform                               ║
║            Powered by Grae-X Labs Research Division                          ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        
        print("\n" + banner)
        print("\n" + "="*80)
        print("🎯 QUICK START GUIDE:")
        print("="*80)
        print("1. Go to '⚡ PAYLOADS' tab")
        print("2. Click 'GENERATE' under '🛡️ EICAR'")
        print("3. Go to '🔍 SCANNER' tab")
        print("4. Click '🚀 LAUNCH ADVANCED SCAN'")
        print("5. Expected detection: '🚨 MALICIOUS - EICAR-Test-File'")
        print("6. Check your training score in the status bar")
        print("\n📁 Test files are saved in: GRAEX_TestFiles/")
        print("="*80)
        print("\n🔒 FOR EDUCATIONAL PURPOSES ONLY - GRAE-X LABS CYBERSECURITY TRAINING")
        print("="*80)
        
        # Start main loop
        root.mainloop()
        
    except Exception as e:
        print(f"❌ Fatal error: {str(e)}")
        import traceback
        traceback.print_exc()
        input("\nPress Enter to exit...")

if __name__ == "__main__":
    main()