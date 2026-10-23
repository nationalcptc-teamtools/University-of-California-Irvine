"""
Dalfox Scanner Module
"""

import os
import json
from .base_scanner import BaseScanner

class DalfoxScanner(BaseScanner):
    """Dalfox XSS vulnerability scanner"""
    
    def __init__(self):
        super().__init__('dalfox', timeout=300)
    
    def run(self, request_file, output_dir, result_queue):
        """Run Dalfox scan"""
        output_file = os.path.join(output_dir, 'dalfox_results.json')
        
        cmd = [
            'dalfox',
            'file', request_file,
            '--output', output_file,
            '--format', 'json',
            '--mining-dict',
            '--skip-bav',
            '--worker', '10',
        ]
        
        def check_vulns(stdout, stderr):
            vuln_count = 0
            if os.path.exists(output_file):
                try:
                    with open(output_file, 'r') as f:
                        results = json.load(f)
                        vuln_count = len(results) if results else 0
                except:
                    pass
            
            vuln_found = vuln_count > 0
            return vuln_found, {
                'vuln_count': vuln_count,
                'output_file': output_file if vuln_count > 0 else None
            }
        
        result = self.execute_command(cmd, output_dir, check_vulns)
        result_queue.put(result)