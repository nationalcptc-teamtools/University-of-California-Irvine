#!/bin/bash
# CPTC Auto Scanner - Tool Installation Script

set -e  # Exit on error

echo "╔═══════════════════════════════════════════════════╗"
echo "║  Installing CPTC Auto Scanner Dependencies        ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check for sudo/root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${YELLOW}[!] This script may require sudo for some operations${NC}"
fi

# Create tools directory
TOOLS_DIR="$HOME/cptc_tools"
mkdir -p "$TOOLS_DIR"
cd "$TOOLS_DIR"

echo -e "\n${YELLOW}[*] Installing SQLMap...${NC}"
if [ ! -d "sqlmap" ]; then
    git clone --depth 1 https://github.com/sqlmapproject/sqlmap.git
    chmod +x sqlmap/sqlmap.py
    sudo ln -sf "$TOOLS_DIR/sqlmap/sqlmap.py" /usr/local/bin/sqlmap
    echo -e "${GREEN}[+] SQLMap installed${NC}"
else
    echo -e "${GREEN}[+] SQLMap already installed${NC}"
fi

echo -e "\n${YELLOW}[*] Installing SSTImap...${NC}"
if [ ! -d "SSTImap" ]; then
    git clone https://github.com/vladko312/SSTImap.git
    cd SSTImap
    # Use virtual environment to avoid conflicts
    python3 -m venv venv
    source venv/bin/activate
    pip3 install -r requirements.txt
    deactivate
    # Create wrapper script
    cat > "$TOOLS_DIR/sstimap_wrapper.sh" << 'EOF'
#!/bin/bash
source "$HOME/cptc_tools/SSTImap/venv/bin/activate"
python "$HOME/cptc_tools/SSTImap/sstimap.py" "$@"
deactivate
EOF
    chmod +x "$TOOLS_DIR/sstimap_wrapper.sh"
    sudo ln -sf "$TOOLS_DIR/sstimap_wrapper.sh" /usr/local/bin/sstimap.py
    cd ..
    echo -e "${GREEN}[+] SSTImap installed${NC}"
else
    echo -e "${GREEN}[+] SSTImap already installed${NC}"
fi

echo -e "\n${YELLOW}[*] Installing Dalfox...${NC}"
if ! command -v dalfox &> /dev/null; then
    echo -e "${YELLOW}[*] Downloading Dalfox binary...${NC}"
    wget -q "https://github.com/hahwul/dalfox/releases/download/v2.12.0/dalfox-linux-amd64.tar.gz" -O dalfox.tar.gz
    tar -xzf dalfox.tar.gz
    chmod +x dalfox-linux-amd64
    sudo mv dalfox-linux-amd64 /usr/local/bin/dalfox
    rm -f dalfox.tar.gz LICENSE.txt README.md
    echo -e "${GREEN}[+] Dalfox binary installed${NC}"
else
    echo -e "${GREEN}[+] Dalfox already installed${NC}"
fi

echo -e "\n${YELLOW}[*] Installing NoSQLMap...${NC}"
if [ ! -d "NoSQLMap" ]; then
    git clone https://github.com/codingo/NoSQLMap.git
    cd NoSQLMap
    # Check if requirements.txt exists
    if [ -f "requirements.txt" ]; then
        # Use virtual environment
        python3 -m venv venv
        source venv/bin/activate
        pip3 install -r requirements.txt
        deactivate
        # Create wrapper script
        cat > "$TOOLS_DIR/nosqlmap_wrapper.sh" << 'EOF'
#!/bin/bash
source "$HOME/cptc_tools/NoSQLMap/venv/bin/activate"
python "$HOME/cptc_tools/NoSQLMap/nosqlmap.py" "$@"
deactivate
EOF
        chmod +x "$TOOLS_DIR/nosqlmap_wrapper.sh"
        sudo ln -sf "$TOOLS_DIR/nosqlmap_wrapper.sh" /usr/local/bin/nosqlmap
    else
        echo -e "${YELLOW}[!] No requirements.txt found, installing without dependencies${NC}"
        chmod +x nosqlmap.py
        sudo ln -sf "$TOOLS_DIR/NoSQLMap/nosqlmap.py" /usr/local/bin/nosqlmap
    fi
    cd ..
    echo -e "${GREEN}[+] NoSQLMap installed${NC}"
else
    echo -e "${GREEN}[+] NoSQLMap already installed${NC}"
fi

echo -e "\n${YELLOW}[*] Setting up scanner script...${NC}"
if [ -f "$HOME/cptc_auto_scanner.py" ]; then
    chmod +x "$HOME/cptc_auto_scanner.py"
    echo -e "${GREEN}[+] Scanner script configured${NC}"
else
    echo -e "${YELLOW}[!] cptc_auto_scanner.py not found in home directory${NC}"
fi

echo -e "\n${GREEN}╔═══════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║           Installation Complete!                  ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════╝${NC}"

echo -e "\n${YELLOW}[*] Verifying installations...${NC}"
echo -e "${YELLOW}Checking SQLMap...${NC}"
sqlmap --version 2>/dev/null && echo -e "${GREEN}✓ SQLMap OK${NC}" || echo -e "${RED}✗ SQLMap NOT FOUND${NC}"

echo -e "${YELLOW}Checking SSTImap...${NC}"
sstimap.py --help 2>/dev/null | head -1 && echo -e "${GREEN}✓ SSTImap OK${NC}" || echo -e "${RED}✗ SSTImap NOT FOUND${NC}"

echo -e "${YELLOW}Checking Dalfox...${NC}"
dalfox version 2>/dev/null && echo -e "${GREEN}✓ Dalfox OK${NC}" || echo -e "${RED}✗ Dalfox NOT FOUND${NC}"

echo -e "${YELLOW}Checking NoSQLMap...${NC}"
nosqlmap --help 2>/dev/null | head -1 && echo -e "${GREEN}✓ NoSQLMap OK${NC}" || echo -e "${RED}✗ NoSQLMap NOT FOUND${NC}"

echo -e "\n${GREEN}[+] Run your scanner with:${NC}"
echo -e "    ${YELLOW}python3 ~/cptc_auto_scanner.py -r request.txt${NC}"
echo -e "\n${GREEN}[+] Tools installed in: $TOOLS_DIR${NC}"
