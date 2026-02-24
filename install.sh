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
echo "[1/7] Python: $(python3 --version)"
echo

# Determine paths
MCP_DIR="$HOME/.claude/mcp-teamdesk"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Claude Desktop config path (Mac vs Linux)
if [[ "$OSTYPE" == "darwin"* ]]; then
    CLAUDE_CONFIG="$HOME/Library/Application Support/Claude/claude_desktop_config.json"
else
    CLAUDE_CONFIG="${XDG_CONFIG_HOME:-$HOME/.config}/Claude/claude_desktop_config.json"
fi

# 2. Get credentials
echo "[2/7] TeamDesk Configuration"
echo
echo "  You need two things from your TeamDesk admin:"
echo "  - API Token (32-char hex string from Setup > Integration > REST API)"
echo "  - Database ID (number from TeamDesk URL: teamdesk.net/secure/db/XXXXX)"
echo

read -p "  API Token: " TD_TOKEN
if [ -z "$TD_TOKEN" ]; then
    echo "ERROR: Token cannot be empty."
    exit 1
fi
echo "  Token: ${TD_TOKEN:0:8}..."

read -p "  Database ID: " TD_DBID
if [ -z "$TD_DBID" ]; then
    echo "ERROR: Database ID cannot be empty."
    exit 1
fi
echo "  Database ID: $TD_DBID"
echo

# 3. Create directory
echo "[3/7] Creating project folder..."
mkdir -p "$MCP_DIR"
echo "  $MCP_DIR"
echo

# 4. Copy files
echo "[4/7] Copying files..."
cp "$SCRIPT_DIR/server.py" "$MCP_DIR/server.py"
cp "$SCRIPT_DIR/requirements.txt" "$MCP_DIR/requirements.txt"
echo "  server.py + requirements.txt copied."
echo

# 5. Create venv and install deps
echo "[5/7] Installing dependencies..."
python3 -m venv "$MCP_DIR/venv"
"$MCP_DIR/venv/bin/pip" install -q -r "$MCP_DIR/requirements.txt"
echo "  Dependencies installed."
echo

# 6. Validate token
echo "[6/7] Validating token with TeamDesk API..."
VALIDATE_RESULT=$("$MCP_DIR/venv/bin/python" -c "
import urllib.request, json, sys
token, db_id = sys.argv[1], sys.argv[2]
try:
    req = urllib.request.Request(
        f'https://www.teamdesk.net/secure/api/v2/{db_id}/describe.json',
        headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        d = json.loads(r.read())
        t = [x['recordName'] for x in d.get('tables', [])]
        print(f'  OK: {len(t)} tables found')
except urllib.error.HTTPError as e:
    if e.code == 401:
        print('  ERROR: Invalid token or no access to this database')
    elif e.code == 404:
        print('  ERROR: Database ID not found')
    else:
        print(f'  ERROR: HTTP {e.code}')
    sys.exit(1)
except Exception as e:
    print(f'  WARNING: {e}')
    sys.exit(1)
" "$TD_TOKEN" "$TD_DBID" 2>&1) || true
echo "$VALIDATE_RESULT"
echo

# 7. Configure Claude Desktop
echo "[7/7] Configuring Claude Desktop..."
PYTHON_PATH="$MCP_DIR/venv/bin/python"
SERVER_PATH="$MCP_DIR/server.py"

"$MCP_DIR/venv/bin/python" -c "
import json, os, sys, shutil

config_path = sys.argv[1]
python_path = sys.argv[2]
server_path = sys.argv[3]
token = sys.argv[4]
db_id = sys.argv[5]

config = {}
if os.path.exists(config_path):
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = json.load(f)
    except Exception:
        shutil.copy2(config_path, config_path + '.bak')
        print('  WARNING: Corrupt config. Backup saved as .bak')

if 'mcpServers' not in config:
    config['mcpServers'] = {}

action = 'updating' if 'teamdesk' in config['mcpServers'] else 'adding'
print(f'  {action} teamdesk in config.')

config['mcpServers']['teamdesk'] = {
    'command': python_path,
    'args': [server_path],
    'env': {
        'TEAMDESK_API_TOKEN': token,
        'TEAMDESK_DATABASE_ID': db_id
    }
}

os.makedirs(os.path.dirname(config_path), exist_ok=True)
with open(config_path, 'w', encoding='utf-8') as f:
    json.dump(config, f, indent=2, ensure_ascii=False)
print('  Config saved: ' + config_path)
" "$CLAUDE_CONFIG" "$PYTHON_PATH" "$SERVER_PATH" "$TD_TOKEN" "$TD_DBID"

# Also create .env as backup
cat > "$MCP_DIR/.env" << EOF
TEAMDESK_API_TOKEN=$TD_TOKEN
TEAMDESK_DATABASE_ID=$TD_DBID
EOF
chmod 600 "$MCP_DIR/.env"

echo
echo "=========================================="
echo "  Installation complete!"
echo "=========================================="
echo
echo "Next steps:"
echo "  1. Close Claude Desktop completely"
echo "  2. Open Claude Desktop again"
echo "  3. Click the tools icon (hammer)"
echo "  4. Verify 'teamdesk' appears in the list"
echo
echo "Project folder: $MCP_DIR"
echo "Claude config:  $CLAUDE_CONFIG"
echo
