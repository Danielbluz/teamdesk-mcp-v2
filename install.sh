#!/bin/bash
# TeamDesk MCP Server - Linux/Mac Installer

set -e

echo "=========================================="
echo "  TeamDesk MCP Server - Installer"
echo "=========================================="
echo

# Check Python
if ! command -v python3 &> /dev/null; then
    echo "ERROR: Python 3 not found. Install Python 3.10+"
    exit 1
fi

# Create directory
MCP_DIR="$HOME/.claude/mcp-teamdesk"
mkdir -p "$MCP_DIR"

# Copy server
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "$SCRIPT_DIR/server.py" "$MCP_DIR/server.py"
cp "$SCRIPT_DIR/requirements.txt" "$MCP_DIR/requirements.txt"

# Create venv and install deps
echo "Installing dependencies..."
python3 -m venv "$MCP_DIR/venv"
"$MCP_DIR/venv/bin/pip" install -q -r "$MCP_DIR/requirements.txt"

# Create .env if not exists
if [ ! -f "$MCP_DIR/.env" ]; then
    echo
    echo "=========================================="
    echo "  Configuration"
    echo "=========================================="
    echo
    read -p "TeamDesk API Token: " TD_TOKEN
    read -p "TeamDesk Database ID: " TD_DBID
    cat > "$MCP_DIR/.env" << EOF
TEAMDESK_TOKEN=$TD_TOKEN
TEAMDESK_DATABASE_ID=$TD_DBID
EOF
    chmod 600 "$MCP_DIR/.env"
    echo
    echo ".env created at $MCP_DIR/.env"
else
    echo ".env already exists, skipping configuration."
fi

echo
echo "=========================================="
echo "  Installation Complete!"
echo "=========================================="
echo
echo "Server installed at: $MCP_DIR"
echo
echo "Add to your Claude Desktop config:"
echo
echo "  \"teamdesk\": {"
echo "    \"command\": \"$MCP_DIR/venv/bin/python\","
echo "    \"args\": [\"$MCP_DIR/server.py\"],"
echo "    \"env\": {"
echo "      \"TEAMDESK_TOKEN\": \"your_token\","
echo "      \"TEAMDESK_DATABASE_ID\": \"your_db_id\""
echo "    }"
echo "  }"
echo
