"""
SQLMap Scanner Module
"""

import os
from .base_scanner import BaseScanner

class SQLMapScanner(BaseScanner):
    """SQLMap vulnerability scanner"""
    
    def __init__(self):
        super().__init__('sqlmap', timeout=600)
    
    def run(self, request_file, output_dir, result_queue, level=1, risk=1, threads=5):
        """Run SQLMap scan"""
        sqlmap_output = os.path.join(output_dir, 'sqlmap_output')
        os.makedirs(sqlmap_output, exist_ok=True)
        
        cmd = [
            'sqlmap',
            '-r', request_file,
            '--batch',
            '--level', str(level),
            '--risk', str(risk),
            '--threads', str(threads),
            '--output-dir', sqlmap_output,
            '--random-agent',
            '--technique=BEUSTQ',
        ]
        
        def check_vulns(stdout, stderr):
            vuln_found = 'parameter' in stdout.lower() and 'vulnerable' in stdout.lower()
            no_vuln = 'all tested parameters do not appear to be injectable' in stdout.lower()
            return vuln_found, {'no_vuln': no_vuln}
        
        result = self.execute_command(cmd, output_dir, check_vulns)
        result_queue.put(result)