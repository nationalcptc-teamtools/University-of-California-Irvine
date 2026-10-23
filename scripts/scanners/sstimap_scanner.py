"""
SSTImap Scanner Module
"""
import os
from .base_scanner import BaseScanner

class SSTImapScanner(BaseScanner):
    """SSTImap vulnerability scanner"""
    
    def __init__(self):
        super().__init__('sstimap', timeout=300)
    
    def run(self, request_file, output_dir, result_queue):
        """Run SSTImap scan"""
        # Path to venv python and script
        tools_dir = os.path.expanduser('~/cptc_tools')
        venv_python = os.path.join(tools_dir, 'SSTImap', 'venv', 'bin', 'python')
        sstimap_script = os.path.join(tools_dir, 'SSTImap', 'sstimap.py')
        
        # Extract URL from request file
        url = self._extract_url_from_request(request_file)
        
        if not url:
            result = {
                'tool': self.name,
                'success': False,
                'error': 'Could not extract URL from request file',
                'elapsed': 0,
                'log_file': None
            }
            result_queue.put(result)
            return
        
        cmd = [
            venv_python,
            sstimap_script,
            '-u', url,
            '--os-cmd', 'id',
        ]
         
        def check_vulns(stdout, stderr):
            # Look for the confirmation message
            vuln_found = (
                'confirmed injection' in stdout.lower() or 
                'injection point:' in stdout.lower() or
                'sstimap identified' in stdout.lower()
            )
            no_vuln = (
                'not injectable' in stdout.lower() or 
                'tested parameters appear to be not injectable' in stdout.lower()
            )
            return vuln_found, {'no_vuln': no_vuln}
                
        result = self.execute_command(cmd, output_dir, check_vulns)
        result_queue.put(result)
    
    def _extract_url_from_request(self, request_file):
        """Extract URL from HTTP request file and add injection markers"""
        try:
            with open(request_file, 'r') as f:
                lines = f.readlines()
                if len(lines) < 2:
                    return None
                
                # Parse first line: GET /path?param=value HTTP/1.1
                request_line = lines[0].strip().split()
                if len(request_line) < 2:
                    return None
                
                method = request_line[0]
                path = request_line[1]
                
                # Parse Host header
                host = None
                for line in lines[1:]:
                    if line.lower().startswith('host:'):
                        host = line.split(':', 1)[1].strip()
                        break
                
                if not host:
                    return None
                
                # Determine protocol (default to http)
                protocol = 'https' if ':443' in host else 'http'
                
                # Clean up host (remove port if it's default)
                host = host.replace(':80', '').replace(':443', '')
                
                # Construct URL and add injection markers
                url = f"{protocol}://{host}{path}"
                
                # Add * marker to all parameter values for testing
                if '?' in url:
                    # Split URL and query string
                    base_url, query = url.split('?', 1)
                    params = query.split('&')
                    marked_params = []
                    
                    for param in params:
                        if '=' in param:
                            key, value = param.split('=', 1)
                            # Add marker after the value
                            marked_params.append(f"{key}={value}*")
                        else:
                            marked_params.append(param)
                    
                    url = f"{base_url}?{'&'.join(marked_params)}"
                
                return url
                
        except Exception as e:
            print(f"Error parsing request file: {e}")
            return None
                        