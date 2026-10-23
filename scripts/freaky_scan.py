#!/usr/bin/env python3
"""
CPTC Globals Automation Scanner
Modular vulnerability scanner with async execution
"""

import argparse
import sys
import os
from datetime import datetime
import threading
from queue import Queue

# Import scanners
from scanners import SQLMapScanner, SSTImapScanner, DalfoxScanner

class Colors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'

def print_banner():
    banner = f"""
{Colors.HEADER}{Colors.BOLD}
╔═══════════════════════════════════════════════════╗
║     CPTC Globals - Automated Vuln Scanner         ║
║  SQLi | SSTI | XSS | NoSQLi Detection             ║
║           ASYNC MODE - Lightning Fast ⚡          ║
╚═══════════════════════════════════════════════════╝
{Colors.ENDC}
    """
    print(banner)

def print_results(results, output_dir, total_elapsed):
    """Print scan results summary"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'='*60}")
    print(f"SCAN COMPLETE - RESULTS")
    print(f"{'='*60}{Colors.ENDC}\n")
    
    for tool_name in ['sqlmap', 'sstimap', 'dalfox']:
        if tool_name not in results:
            continue
            
        result = results[tool_name]
        
        if result['success']:
            status = f"{Colors.OKGREEN}✓{Colors.ENDC}"
            print(f"{status} {Colors.BOLD}{tool_name.upper()}{Colors.ENDC} - Completed in {result['elapsed']:.2f}s")
            print(f"   Log: {result['log_file']}")
            
            # Print vulnerability status
            if result.get('vuln_found'):
                if tool_name == 'dalfox' and 'vuln_count' in result:
                    print(f"   {Colors.FAIL}⚠ FOUND {result['vuln_count']} XSS VULNERABILITIES!{Colors.ENDC}")
                    if result.get('output_file'):
                        print(f"   Details: {result['output_file']}")
                else:
                    print(f"   {Colors.FAIL}⚠ POTENTIAL VULNERABILITY FOUND!{Colors.ENDC}")
            elif result.get('no_vuln'):
                print(f"   {Colors.OKGREEN}✓ No vulnerabilities detected{Colors.ENDC}")
            else:
                print(f"   {Colors.OKCYAN}ℹ Check log for details{Colors.ENDC}")
        else:
            status = f"{Colors.FAIL}✗{Colors.ENDC}"
            print(f"{status} {Colors.BOLD}{tool_name.upper()}{Colors.ENDC} - {result.get('error', 'Failed')}")
        
        print()
    
    print(f"{Colors.HEADER}{Colors.BOLD}{'='*60}{Colors.ENDC}")
    print(f"Output directory: {output_dir}")
    print(f"Total time: {total_elapsed:.2f}s (parallel execution)")
    print(f"\n{Colors.OKGREEN}[+] All logs saved to {output_dir}{Colors.ENDC}\n")

def main():
    parser = argparse.ArgumentParser(
        description='CPTC Automated Vulnerability Scanner (ASYNC)',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s -r request.txt
  %(prog)s -r request.txt --all
  %(prog)s -r request.txt --sqli --xss
  %(prog)s -r request.txt --level 3 --risk 2
  %(prog)s -r request.txt -o ./results
        '''
    )
    
    parser.add_argument('-r', '--request', required=True, help='HTTP request file')
    parser.add_argument('-o', '--output', default='./scan_results', help='Output directory (default: ./scan_results)')
    
    # Test selection
    parser.add_argument('--all', action='store_true', help='Run all tests (default)')
    parser.add_argument('--sqli', action='store_true', help='Run SQL injection tests')
    parser.add_argument('--ssti', action='store_true', help='Run SSTI tests')
    parser.add_argument('--xss', action='store_true', help='Run XSS tests')
    
    # SQLMap specific options
    parser.add_argument('--level', type=int, default=1, choices=[1,2,3,4,5], 
                       help='SQLMap level (1-5, default: 1)')
    parser.add_argument('--risk', type=int, default=1, choices=[1,2,3],
                       help='SQLMap risk (1-3, default: 1)')
    parser.add_argument('--threads', type=int, default=5,
                       help='Number of threads (default: 5)')
    
    args = parser.parse_args()
    
    print_banner()
    
    # Check if request file exists
    if not os.path.isfile(args.request):
        print(f"{Colors.FAIL}[-] Request file not found: {args.request}{Colors.ENDC}")
        sys.exit(1)
    
    # Create output directory with timestamp
    timestamp = datetime.now().strftime("%H:%M:%S")
    output_dir = os.path.join(args.output, f"scan_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    print(f"{Colors.OKGREEN}[+] Output directory: {output_dir}{Colors.ENDC}")
    
    # Determine which tests to run
    run_all = args.all or not (args.sqli or args.ssti or args.xss)
    
    # Initialize scanners
    scanners_to_run = []
    
    if run_all or args.sqli:
        scanner = SQLMapScanner()
        kwargs = {'level': args.level, 'risk': args.risk, 'threads': args.threads}
        scanners_to_run.append((scanner, kwargs))
    
    if run_all or args.ssti:
        scanner = SSTImapScanner()
        scanners_to_run.append((scanner, {}))
    
    if run_all or args.xss:
        scanner = DalfoxScanner()
        scanners_to_run.append((scanner, {}))
    
    # Queue for collecting results
    result_queue = Queue()
    threads = []
    
    import time
    start_total = time.time()
    
    print(f"\n{Colors.HEADER}{Colors.BOLD}[*] Launching tools asynchronously...{Colors.ENDC}\n")
    
    # Launch threads
    for scanner, kwargs in scanners_to_run:
        print(f"{Colors.OKBLUE}[*] Starting {scanner.name} in background...{Colors.ENDC}")
        t = threading.Thread(target=scanner.run, args=(args.request, output_dir, result_queue), kwargs=kwargs)
        t.start()
        threads.append(t)
    
    print(f"\n{Colors.OKGREEN}[+] All tools are running in background!{Colors.ENDC}")
    print(f"{Colors.OKCYAN}[*] Waiting for results... (this may take several minutes){Colors.ENDC}\n")
    
    # Wait for all threads to complete
    for thread in threads:
        thread.join()
    
    total_elapsed = time.time() - start_total
    
    # Collect results
    results = {}
    while not result_queue.empty():
        result = result_queue.get()
        results[result['tool']] = result
    
    # Print results
    print_results(results, output_dir, total_elapsed)

if __name__ == '__main__':
    main()
