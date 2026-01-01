#!/usr/bin/env python3
"""
NCFuzz - Netcat Connection Fuzzer
Fuzzes netcat connections with payloads from a wordlist
"""

import argparse
import socket
import sys
import time
from pathlib import Path


def parse_target(target_str):
    """Parse ip:port string into host and port"""
    try:
        if ':' not in target_str:
            raise ValueError("Target must be in format ip:port")
        
        host, port = target_str.rsplit(':', 1)
        port = int(port)
        
        if port < 1 or port > 65535:
            raise ValueError("Port must be between 1 and 65535")
        
        return host, port
    except ValueError as e:
        print(f"Error: Invalid target format - {e}")
        sys.exit(1)


def connect_to_target(host, port, timeout=5):
    """Establish connection to target"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((host, port))
        return sock
    except socket.error as e:
        print(f"Error: Failed to connect to {host}:{port} - {e}")
        sys.exit(1)


def send_data(sock, data):
    """Send data to socket"""
    try:
        if data:
            sock.sendall(data.encode('utf-8'))
    except socket.error as e:
        print(f"Warning: Failed to send data - {e}")


def receive_output(sock, timeout=2):
    """Receive output from socket with timeout"""
    try:
        sock.settimeout(timeout)
        output = b''
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                output += chunk
            except socket.timeout:
                break
        return output.decode('utf-8', errors='ignore')
    except socket.error:
        return ""


def wait_and_print_response(sock, wait_after=0.3, must_wait=True):
    """Wait for at least one response, then wait additional time and print all responses
    
    Args:
        sock: Socket to receive from
        wait_after: Additional time to wait after first response (seconds)
        must_wait: If True, always wait the full period even if no initial response
    """
    all_responses = b''
    got_initial_response = False
    
    # First, wait for at least one response with a timeout
    initial_timeout = 2.0
    sock.settimeout(initial_timeout)
    
    try:
        chunk = sock.recv(4096)
        if chunk:
            all_responses += chunk
            got_initial_response = True
    except socket.timeout:
        pass
    except socket.error:
        pass
    
    # Wait additional time for more data
    if got_initial_response or must_wait:
        # Wait the additional period and collect all responses
        end_time = time.time() + wait_after
        sock.settimeout(0.1)  # Short timeout for checking
        
        while time.time() < end_time:
            try:
                chunk = sock.recv(4096)
                if chunk:
                    all_responses += chunk
                else:
                    break
            except socket.timeout:
                # Continue checking until end_time
                continue
            except socket.error:
                break
    
    # Print the response if we got one
    if all_responses:
        response_text = all_responses.decode('utf-8', errors='ignore')
        print(f"[RESPONSE] {response_text}", end='')
    
    return all_responses.decode('utf-8', errors='ignore')


def parse_quoted_values(data_string):
    """Parse single-quoted values from a string like 'val1', 'val2', 'val3'"""
    if not data_string:
        return []
    
    values = []
    i = 0
    while i < len(data_string):
        # Skip whitespace and commas
        while i < len(data_string) and (data_string[i].isspace() or data_string[i] == ','):
            i += 1
        
        if i >= len(data_string):
            break
        
        # Look for opening single quote
        if data_string[i] == "'":
            i += 1  # Skip opening quote
            value = ""
            # Read until closing quote
            while i < len(data_string) and data_string[i] != "'":
                # Handle escaped quotes
                if data_string[i] == '\\' and i + 1 < len(data_string) and data_string[i + 1] == "'":
                    value += "'"
                    i += 2
                else:
                    value += data_string[i]
                    i += 1
            
            if i < len(data_string) and data_string[i] == "'":
                values.append(value)
                i += 1  # Skip closing quote
        else:
            # If no quote, treat as single value (backward compatibility)
            # Find the next comma or end
            end = i
            while end < len(data_string) and data_string[end] != ',':
                end += 1
            value = data_string[i:end].strip()
            if value:
                values.append(value)
            i = end
    
    return values


def send_sequential_inputs(sock, inputs, delay=0.2):
    """Send multiple inputs sequentially, waiting for and receiving responses after each"""
    if not inputs:
        return
    
    for i, input_data in enumerate(inputs):
        send_data(sock, input_data)
        # Wait for at least one response, then wait additional time and print all responses
        wait_and_print_response(sock, wait_after=0.3)


def fuzz_connection(host, port, wordlist_path, payload_template, initial_data=None, 
                   repeat_data=None, reconnect=False):
    """Main fuzzing function"""
    
    # Validate wordlist file
    if not Path(wordlist_path).exists():
        print(f"Error: Wordlist file not found: {wordlist_path}")
        sys.exit(1)
    
    # Validate payload template
    if '{FUZZ}' not in payload_template:
        print("Error: Payload template must contain {FUZZ} placeholder")
        sys.exit(1)
    
    # Read wordlist
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            wordlist = [line.strip() for line in f if line.strip()]
    except IOError as e:
        print(f"Error: Cannot read wordlist file - {e}")
        sys.exit(1)
    
    if not wordlist:
        print("Error: Wordlist is empty")
        sys.exit(1)
    
    # Parse initial data - support single-quoted sequential inputs
    initial_inputs = []
    if initial_data:
        initial_inputs = parse_quoted_values(initial_data)
    
    # Parse repeat data - support single-quoted sequential inputs
    repeat_inputs = []
    if repeat_data:
        repeat_inputs = parse_quoted_values(repeat_data)
    
    print(f"[*] Starting fuzzing against {host}:{port}")
    print(f"[*] Wordlist: {wordlist_path} ({len(wordlist)} entries)")
    print(f"[*] Payload template: {payload_template}")
    print(f"[*] Connection mode: {'Reconnect per attempt' if reconnect else 'Persistent connection'}")
    if initial_inputs:
        print(f"[*] Initial inputs: {len(initial_inputs)} sequential input(s)")
    if repeat_inputs and not reconnect:
        print(f"[*] Repeat inputs: {len(repeat_inputs)} sequential input(s)")
    # print(file=sys.stderr)
    
    if reconnect:
        # Mode 1: Reconnect for each attempt
        for i, fuzz_value in enumerate(wordlist, 1):
            # Create payload by replacing {FUZZ}
            payload = payload_template.replace('{FUZZ}', fuzz_value)
            
            try:
                # Connect to target
                sock = connect_to_target(host, port)
                
                # Send initial data sequentially if specified
                if initial_inputs:
                    send_sequential_inputs(sock, initial_inputs)
                    # Response already received by send_sequential_inputs
                
                # Send payload
                print(f"[PAYLOAD] {payload}")
                send_data(sock, payload)
                
                # Wait for and print response, then capture as output
                output = wait_and_print_response(sock, wait_after=0.3)
                
                # Print output to stdout
                print(output)
                sys.stdout.flush()
                
                # Close connection
                sock.close()
                
                # Small delay before next attempt
                if i < len(wordlist):
                    time.sleep(0.1)
                
            except KeyboardInterrupt:
                print("\n[*] Fuzzing interrupted by user")
                break
            except Exception as e:
                error_msg = f"Error processing payload '{payload}': {e}"
                print(f"ERROR: {error_msg}")
                continue
    else:
        # Mode 2: Persistent connection
        sock = None
        try:
            # Connect once at the start
            sock = connect_to_target(host, port)
            
            # Send initial setup once
            if initial_inputs:
                send_sequential_inputs(sock, initial_inputs)
                # Response already received by send_sequential_inputs
            
            # Process each payload
            for i, fuzz_value in enumerate(wordlist, 1):
                # Create payload by replacing {FUZZ}
                payload = payload_template.replace('{FUZZ}', fuzz_value)
                
                try:
                    # Send repeat values before payload (except for first payload)
                    if repeat_inputs and i > 1:
                        send_sequential_inputs(sock, repeat_inputs)
                        # Ensure final response from repeat inputs is fully received
                        # Additional wait to ensure server has fully processed and is ready
                        wait_and_print_response(sock, wait_after=0.3, must_wait=True)
                    
                    # Send payload
                    print(f"[PAYLOAD] {payload}")
                    send_data(sock, payload)
                    
                    # Wait for and print response, then capture as output
                    output = wait_and_print_response(sock, wait_after=0.3)
                    
                    # Print output to stdout
                    # print(output)
                    sys.stdout.flush()
                    
                    # Small delay before next attempt
                    if i < len(wordlist):
                        time.sleep(0.1)
                    
                except KeyboardInterrupt:
                    print("\n[*] Fuzzing interrupted by user")
                    break
                except Exception as e:
                    error_msg = f"Error processing payload '{payload}': {e}"
                    print(f"ERROR: {error_msg}")
                    # Try to continue with next payload
                    continue
            
            # Close connection at the end
            if sock:
                sock.close()
                
        except KeyboardInterrupt:
            print("\n[*] Fuzzing interrupted by user")
            if sock:
                sock.close()
        except Exception as e:
            print(f"Error: Connection failed - {e}")
            if sock:
                sock.close()
            sys.exit(1)
    
    print(f"\n[*] Fuzzing complete")


def main():
    parser = argparse.ArgumentParser(
        description='NCFuzz - Netcat Connection Fuzzer',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s 192.168.1.100:8080 -w wordlist.txt -p "GET /{FUZZ} HTTP/1.1\\r\\nHost: example.com\\r\\n\\r\\n"
  %(prog)s 10.0.0.1:9999 -w payloads.txt -p "FUZZ"
  %(prog)s localhost:4444 -w fuzz.txt -p "test{FUZZ}end" -s "'INIT'" -r "'SEPARATOR'"
  %(prog)s 192.168.1.100:9999 -w wordlist.txt -p "{FUZZ}" -s "'2', '2'"
  %(prog)s 192.168.1.100:9999 -w wordlist.txt -p "{FUZZ}" -s "'2', '2'" -r "'reset', 'menu'"
  %(prog)s 192.168.1.100:9999 -w wordlist.txt -p "{FUZZ}" --reconnect -s "'2', '2'"
        '''
    )
    
    parser.add_argument('target', help='Target in format ip:port (required)')
    parser.add_argument('-w', '--wordlist', required=True, help='Wordlist file (required)')
    parser.add_argument('-p', '--payload', required=True, 
                       help='Payload template with {FUZZ} placeholder (required)')
    parser.add_argument('-s', '--initial', 
                       help='Initial data to send before fuzzing. Use single-quoted values for sequential inputs (e.g., \'2\', \'2\' to send "2" twice with response waiting)')
    parser.add_argument('-r', '--repeat', 
                       help='Data to send between each fuzz attempt (persistent connection only). Use single-quoted values for sequential inputs (e.g., \'reset\', \'menu\' to send multiple commands). Cannot be used with --reconnect.')
    parser.add_argument('--reconnect', action='store_true',
                       help='Reconnect for each fuzz attempt (default: persistent connection). Cannot be used with --repeat.')
    
    args = parser.parse_args()
    
    # Validate flags - --repeat cannot be used with --reconnect
    if args.reconnect and args.repeat:
        print("Error: --repeat cannot be used with --reconnect flag")
        print("When using --reconnect, each attempt reconnects fresh, so repeat data is not needed.")
        sys.exit(1)
    
    # Parse target
    host, port = parse_target(args.target)
    
    # Run fuzzing
    fuzz_connection(
        host=host,
        port=port,
        wordlist_path=args.wordlist,
        payload_template=args.payload,
        initial_data=args.initial,
        repeat_data=args.repeat,
        reconnect=args.reconnect
    )


if __name__ == '__main__':
    main()
