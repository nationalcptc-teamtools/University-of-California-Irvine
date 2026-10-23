"""
Base Scanner Class
"""

import subprocess
import time
import os
from queue import Queue

class BaseScanner:
    """Base class for all vulnerability scanners"""
    
    def __init__(self, name, timeout=600):
        self.name = name
        self.timeout = timeout
    
    def log_output(self, output_dir, command, stdout, stderr, returncode):
        """Log tool output to file"""
       
        log_file = os.path.join(output_dir, f"{self.name}.log")
        
        with open(log_file, 'w') as f:
            f.write(f"{'='*80}\n")
            f.write(f"  SCAN LOG - {self.name.upper()}\n")
            f.write(f"{'='*80}\n\n")
            f.write(f"Tool:         {self.name}\n")
            f.write(f"Command:      {' '.join(command)}\n")
            f.write(f"Return Code:  {returncode}\n\n")
            f.write(f"{'='*80}\n")
            f.write("STDOUT:\n")
            f.write(f"{'='*80}\n\n")
            f.write(stdout)
            f.write(f"\n\n{'='*80}\n")
            f.write("STDERR:\n")
            f.write(f"{'='*80}\n\n")
            f.write(stderr)
            f.write(f"\n{'='*80}\n")
        
        return log_file
    
    def run(self, request_file, output_dir, result_queue, **kwargs):
        """Override this in subclasses"""
        raise NotImplementedError("Subclasses must implement run()")
    
    def execute_command(self, cmd, output_dir, check_vuln_func=None):
        """Execute command and handle results"""
        try:
            start_time = time.time()
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
            elapsed = time.time() - start_time
            
            log_file = self.log_output(output_dir, cmd, result.stdout, result.stderr, result.returncode)
            
            vuln_found = False
            vuln_data = {}
            
            if check_vuln_func:
                vuln_found, vuln_data = check_vuln_func(result.stdout, result.stderr)
            
            return {
                'tool': self.name,
                'success': True,
                'elapsed': elapsed,
                'log_file': log_file,
                'vuln_found': vuln_found,
                'returncode': result.returncode,
                **vuln_data
            }
            
        except subprocess.TimeoutExpired:
            return {
                'tool': self.name,
                'success': False,
                'error': f'Timeout after {self.timeout}s',
                'returncode': 1
            }
        except Exception as e:
            return {
                'tool': self.name,
                'success': False,
                'error': str(e),
                'returncode': 1
            }
                           