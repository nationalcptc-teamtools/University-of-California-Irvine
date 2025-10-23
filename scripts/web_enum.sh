#!/bin/bash

# Web Enumeration Script using ffuf
# Usage: ./web_enum.sh <target> or ./web_enum.sh -f <file>
# -v to specify vhosts wordlist -d to specify directory wordlist
# Example: ./web_enum.sh example.com -v vhosts.txt
# Example: ./web_enum.sh -f targets.txt -v vhosts.txt -d directories.txt

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables to store user-specified wordlists
USER_VHOST_WORDLIST=""
USER_DIR_WORDLIST=""

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if ffuf is installed
check_dependencies() {
    if ! command -v ffuf &> /dev/null; then
        print_error "ffuf is not installed. Please install it first."
        print_status "Install with: go install github.com/ffuf/ffuf@latest"
        exit 1
    fi
    
    # Validate user-specified wordlists if provided
    if [ -n "$USER_VHOST_WORDLIST" ]; then
        if [ ! -f "$USER_VHOST_WORDLIST" ]; then
            print_error "VHOST wordlist not found at $USER_VHOST_WORDLIST"
            exit 1
        fi
        print_status "Using vhost wordlist: $USER_VHOST_WORDLIST"
    else
        print_warning "No vhost wordlist specified - vhost fuzzing will be skipped"
    fi
    
    if [ -n "$USER_DIR_WORDLIST" ]; then
        if [ ! -f "$USER_DIR_WORDLIST" ]; then
            print_error "Directory wordlist not found at $USER_DIR_WORDLIST"
            exit 1
        fi
        print_status "Using directory wordlist: $USER_DIR_WORDLIST"
    else
        print_warning "No directory wordlist specified - directory fuzzing will be skipped"
    fi
}

# Function to create output directory for a target
create_output_dir() {
    local target="$1"
    local clean_target=$(echo "$target" | sed 's/[^a-zA-Z0-9.-]/_/g')
    local output_dir="ffuf_results_${clean_target}_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$output_dir"
    echo "$output_dir"
}

# Function to run vhost fuzzing
fuzz_vhosts() {
    local target="$1"
    local output_dir="$2"
    
    if [ -z "$USER_VHOST_WORDLIST" ]; then
        print_warning "Skipping vhost fuzzing - no wordlist specified"
        return
    fi
    
    print_status "Starting vhost fuzzing for $target"
    
    ffuf -w "$USER_VHOST_WORDLIST" -u "http://$target" -H "Host: FUZZ.$target" -ic > "$output_dir/vhost_results.txt" &
    
    local vhost_pid=$!
    echo $vhost_pid > "$output_dir/vhost.pid"
    print_success "VHOST fuzzing started (PID: $vhost_pid)"
}

# Function to run directory fuzzing
fuzz_directories() {
    local target="$1"
    local output_dir="$2"
    
    if [ -z "$USER_DIR_WORDLIST" ]; then
        print_warning "Skipping directory fuzzing - no wordlist specified"
        return
    fi
    
    print_status "Starting directory fuzzing for $target"
    
    ffuf -w "$USER_DIR_WORDLIST" -u "http://$target/FUZZ" -ic > "$output_dir/dir_results.txt" &
    
    local dir_pid=$!
    echo $dir_pid > "$output_dir/dir.pid"
    print_success "Directory fuzzing started (PID: $dir_pid)"
}


# Function to wait for all processes and generate summary
wait_and_summarize() {
    local output_dir="$1"
    local target="$2"
    
    print_status "Waiting for all fuzzing processes to complete for $target..."
    
    # Wait for all background processes
    wait
    
    # Generate summary
    print_status "Generating summary for $target..."
    
    echo "=== FUZZING SUMMARY FOR $target ===" > "$output_dir/summary.txt"
    echo "Generated on: $(date)" >> "$output_dir/summary.txt"
    echo "" >> "$output_dir/summary.txt"
    
    # Count results
    if [ -f "$output_dir/vhost_results.txt" ]; then
        local vhost_count=$(wc -l < "$output_dir/vhost_results.txt" 2>/dev/null || echo "0")
        echo "VHOST Results: $vhost_count" >> "$output_dir/summary.txt"
    fi
    
    if [ -f "$output_dir/dir_results.txt" ]; then
        local dir_count=$(wc -l < "$output_dir/dir_results.txt" 2>/dev/null || echo "0")
        echo "Directory Results: $dir_count" >> "$output_dir/summary.txt"
    fi
    
    
    print_success "Fuzzing completed for $target. Results saved in: $output_dir"
    print_status "Summary: $output_dir/summary.txt"
}

# Function to process a single target
process_target() {
    local target="$1"
    
    print_status "Processing target: $target"
    
    # Create output directory
    local output_dir=$(create_output_dir "$target")
    print_status "Created output directory: $output_dir"
    
    # Start fuzzing in parallel
    fuzz_vhosts "$target" "$output_dir"
    fuzz_directories "$target" "$output_dir"
    
    # Wait for completion and generate summary
    wait_and_summarize "$output_dir" "$target"
}

# Function to show usage
show_usage() {
    echo "Usage: $0 <target> | $0 -f <file> | $0 -h"
    echo "       $0 -v <vhost_wordlist> -d <dir_wordlist> <target>"
    echo ""
    echo "Options:"
    echo "  <target>     Single IP address or hostname to fuzz"
    echo "  -f <file>    File containing targets (one per line)"
    echo "  -v <file>    Vhost wordlist file (required for vhost fuzzing)"
    echo "  -d <file>    Directory wordlist file (required for directory fuzzing)"
    echo "  -h, --help   Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0 -v vhosts.txt -d dirs.txt example.com"
    echo "  $0 -d dirs.txt 192.168.1.100"
    echo "  $0 -v vhosts.txt -f targets.txt"
    echo "  $0 -h"
    echo ""
    echo "Note: At least one wordlist (-v or -d) must be specified for fuzzing to occur"
    echo ""
    echo "Output:"
    echo "  Results are saved in timestamped directories (ffuf_results_<target>_<timestamp>)"
    echo "  Each directory contains text results and a summary.txt file"
}

# Main script logic
main() {
    # Parse arguments
    if [ $# -eq 0 ]; then
        show_usage
        exit 1
    fi
    
    # Check for help flag
    if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
        show_usage
        exit 0
    fi
    
    # Parse command line arguments
    local target=""
    local file=""
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            -f)
                if [ $# -lt 2 ]; then
                    print_error "File option requires a filename"
                    show_usage
                    exit 1
                fi
                file="$2"
                if [ ! -f "$file" ]; then
                    print_error "File $file does not exist"
                    exit 1
                fi
                shift 2
                ;;
            -v)
                if [ $# -lt 2 ]; then
                    print_error "Vhost wordlist option requires a filename"
                    show_usage
                    exit 1
                fi
                USER_VHOST_WORDLIST="$2"
                shift 2
                ;;
            -d)
                if [ $# -lt 2 ]; then
                    print_error "Directory wordlist option requires a filename"
                    show_usage
                    exit 1
                fi
                USER_DIR_WORDLIST="$2"
                shift 2
                ;;
            -h|--help)
                show_usage
                exit 0
                ;;
            -*)
                print_error "Invalid flag: $1"
                echo ""
                show_usage
                exit 1
                ;;
            *)
                # This is a target
                if [ -z "$target" ]; then
                    target="$1"
                else
                    print_error "Multiple targets specified. Use -f for multiple targets."
                    show_usage
                    exit 1
                fi
                shift
                ;;
        esac
    done
    
    # Check dependencies
    check_dependencies
    
    # Ensure at least one wordlist is provided
    if [ -z "$USER_VHOST_WORDLIST" ] && [ -z "$USER_DIR_WORDLIST" ]; then
        print_error "At least one wordlist must be specified (-v for vhost or -d for directory)"
        echo ""
        show_usage
        exit 1
    fi
    
    # Process targets
    if [ -n "$file" ]; then
        # Process targets from file
        print_status "Processing targets from file: $file"
        
        while IFS= read -r line_target; do
            # Skip empty lines and comments
            if [[ -n "$line_target" && ! "$line_target" =~ ^[[:space:]]*# ]]; then
                process_target "$line_target"
                echo "" # Add spacing between targets
            fi
        done < "$file"
        
    elif [ -n "$target" ]; then
        # Process single target
        process_target "$target"
    else
        print_error "No target specified"
        show_usage
        exit 1
    fi
    
    print_success "All fuzzing operations completed!"
}

# Run main function
main "$@"
