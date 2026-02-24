@echo off
chcp 65001 >nul
title TeamDesk MCP Server - Windows Installer

echo ============================================
echo   TeamDesk MCP Server - Installer
echo ============================================
echo.

:: Installer directory (where this .bat is located)
set "SCRIPT_DIR=%~dp0"
set "INSTALL_DIR=%USERPROFILE%\mcp-teamdesk"
set "CLAUDE_CONFIG_DIR=%APPDATA%\Claude"
set "CLAUDE_CONFIG=%CLAUDE_CONFIG_DIR%\claude_desktop_config.json"

:: ---- Generate temp Python scripts ----
:: (avoids issues with python -c multi-line in batch)

set "PY_VALIDATE=%TEMP%\td_validate.py"
> "%PY_VALIDATE%" (
echo import urllib.request, json, sys
echo token = sys.argv[1]
echo db_id = sys.argv[2]
echo try:
echo     req = urllib.request.Request(
echo         f'https://www.teamdesk.net/secure/api/v2/{db_id}/describe.json',
echo         headers={'Authorization': f'Bearer {token}', 'Content-Type': 'application/json'}
echo     ^)
echo     with urllib.request.urlopen(req, timeout=30^) as r:
echo         d = json.loads(r.read(^)^)
echo         t = [x['recordName'] for x in d.get('tables', []^)]
echo         print(f'    OK: {len(t^)} tables found'^)
echo except urllib.error.HTTPError as e:
echo     if e.code == 401:
echo         print('    ERROR: Invalid token or no access to this database'^)
echo     elif e.code == 404:
echo         print('    ERROR: Database ID not found'^)
echo     else:
echo         print(f'    ERROR: HTTP {e.code}'^)
echo     sys.exit(1^)
echo except Exception as e:
echo     print(f'    WARNING: {e}'^)
echo     sys.exit(1^)
)

set "PY_CONFIG=%TEMP%\td_config.py"
> "%PY_CONFIG%" (
echo import json, os, sys, shutil
echo config_path = sys.argv[1]
echo server_path = sys.argv[2]
echo token = sys.argv[3]
echo db_id = sys.argv[4]
echo config = {}
echo if os.path.exists(config_path^):
echo     try:
echo         with open(config_path, 'r', encoding='utf-8'^) as f:
echo             config = json.load(f^)
echo     except Exception:
echo         shutil.copy2(config_path, config_path + '.bak'^)
echo         print('    WARNING: Corrupt config. Backup saved as .bak'^)
echo if 'mcpServers' not in config:
echo     config['mcpServers'] = {}
echo action = 'updating' if 'teamdesk' in config['mcpServers'] else 'adding'
echo print(f'    {action} teamdesk in config.'^)
echo config['mcpServers']['teamdesk'] = {
echo     'command': 'python',
echo     'args': [server_path],
echo     'env': {
echo         'TEAMDESK_API_TOKEN': token,
echo         'TEAMDESK_DATABASE_ID': db_id
echo     }
echo }
echo os.makedirs(os.path.dirname(config_path^), exist_ok=True^)
echo with open(config_path, 'w', encoding='utf-8'^) as f:
echo     json.dump(config, f, indent=2, ensure_ascii=False^)
echo print('    Config saved: ' + config_path^)
)

:: ---- Start installation ----

:: 1. Check Python
echo [1/7] Checking Python...
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: Python not found. Install Python 3.10+ from https://python.org
    echo Make sure to check "Add Python to PATH" during installation.
    pause
    exit /b 1
)
for /f "tokens=*" %%v in ('python --version') do echo    %%v
echo.

:: 2. Get TeamDesk credentials
echo [2/7] TeamDesk Configuration
echo.
echo    You need two things from your TeamDesk admin:
echo    - API Token (32-char hex string from Setup ^> Integration ^> REST API)
echo    - Database ID (number from TeamDesk URL: teamdesk.net/secure/db/XXXXX)
echo.

:: Check for existing config
set "SAVED_TOKEN="
set "SAVED_DBID="
if exist "%CLAUDE_CONFIG%" (
    python -c "import json,sys; c=json.load(open(sys.argv[1],encoding='utf-8')); e=c.get('mcpServers',{}).get('teamdesk',{}).get('env',{}); print(e.get('TEAMDESK_API_TOKEN',''))" "%CLAUDE_CONFIG%" > "%TEMP%\td_saved_token.txt" 2>nul
    set /p SAVED_TOKEN=<"%TEMP%\td_saved_token.txt"
    del "%TEMP%\td_saved_token.txt" 2>nul

    python -c "import json,sys; c=json.load(open(sys.argv[1],encoding='utf-8')); e=c.get('mcpServers',{}).get('teamdesk',{}).get('env',{}); print(e.get('TEAMDESK_DATABASE_ID',''))" "%CLAUDE_CONFIG%" > "%TEMP%\td_saved_dbid.txt" 2>nul
    set /p SAVED_DBID=<"%TEMP%\td_saved_dbid.txt"
    del "%TEMP%\td_saved_dbid.txt" 2>nul
)

:: Token
if not "%SAVED_TOKEN%"=="" (
    echo    Existing token found: %SAVED_TOKEN:~0,8%...
    set /p "CHANGE_TOKEN=    Keep this token? (Y/n): "
)

if /i "%CHANGE_TOKEN%"=="n" (
    set /p "TD_TOKEN=    New API Token: "
) else if not "%SAVED_TOKEN%"=="" (
    set "TD_TOKEN=%SAVED_TOKEN%"
) else (
    set /p "TD_TOKEN=    API Token: "
)

if "%TD_TOKEN%"=="" (
    echo ERROR: Token cannot be empty.
    pause
    exit /b 1
)
echo    Token: %TD_TOKEN:~0,8%...

:: Database ID
if not "%SAVED_DBID%"=="" (
    echo    Existing Database ID: %SAVED_DBID%
    set /p "CHANGE_DBID=    Keep this Database ID? (Y/n): "
)

if /i "%CHANGE_DBID%"=="n" (
    set /p "TD_DBID=    New Database ID: "
) else if not "%SAVED_DBID%"=="" (
    set "TD_DBID=%SAVED_DBID%"
) else (
    set /p "TD_DBID=    Database ID: "
)

if "%TD_DBID%"=="" (
    echo ERROR: Database ID cannot be empty.
    pause
    exit /b 1
)
echo    Database ID: %TD_DBID%
echo.

:: 3. Create project folder
echo [3/7] Creating project folder...
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    echo    Created: %INSTALL_DIR%
) else (
    echo    Already exists: %INSTALL_DIR%
)
echo.

:: 4. Copy files
echo [4/7] Copying files...

if exist "%SCRIPT_DIR%server.py" (
    copy /Y "%SCRIPT_DIR%server.py" "%INSTALL_DIR%\server.py" >nul
    echo    server.py copied.
) else if exist "%INSTALL_DIR%\server.py" (
    echo    server.py already in destination.
) else (
    echo ERROR: server.py not found.
    echo    Place server.py in the same folder as this .bat and try again.
    pause
    exit /b 1
)

if exist "%SCRIPT_DIR%requirements.txt" (
    copy /Y "%SCRIPT_DIR%requirements.txt" "%INSTALL_DIR%\requirements.txt" >nul
    echo    requirements.txt copied.
) else if exist "%INSTALL_DIR%\requirements.txt" (
    echo    requirements.txt already in destination.
) else (
    echo ERROR: requirements.txt not found.
    pause
    exit /b 1
)
echo.

:: 5. Install dependencies
echo [5/7] Installing dependencies...
pip install -r "%INSTALL_DIR%\requirements.txt" --quiet 2>nul
if %errorlevel% neq 0 (
    echo    Trying with --user...
    pip install -r "%INSTALL_DIR%\requirements.txt" --quiet --user 2>nul
    if %errorlevel% neq 0 (
        echo ERROR: Failed to install dependencies.
        pause
        exit /b 1
    )
)
echo    Dependencies installed.
echo.

:: 6. Validate token with TeamDesk API
echo [6/7] Validating token with TeamDesk API...
python "%PY_VALIDATE%" "%TD_TOKEN%" "%TD_DBID%"
if %errorlevel% neq 0 (
    echo    Installation will continue anyway.
    echo    If the MCP doesn't work, verify your token and database ID.
)
echo.

:: 7. Configure Claude Desktop
echo [7/7] Configuring Claude Desktop...
python "%PY_CONFIG%" "%CLAUDE_CONFIG%" "%INSTALL_DIR%\server.py" "%TD_TOKEN%" "%TD_DBID%"
if %errorlevel% neq 0 (
    echo ERROR: Failed to configure Claude Desktop.
    echo    Try configuring manually:
    echo    File: %CLAUDE_CONFIG%
    pause
    exit /b 1
)

:: Clean up temp files
del "%PY_VALIDATE%" 2>nul
del "%PY_CONFIG%" 2>nul
echo.

echo ============================================
echo   Installation complete!
echo ============================================
echo.
echo Next steps:
echo   1. Close Claude Desktop completely (check system tray)
echo   2. Open Claude Desktop again
echo   3. Click the tools icon (hammer)
echo   4. Verify "teamdesk" appears in the list
echo.
echo If MCP seems slow, check logs at:
echo   Claude Desktop ^> Ctrl+Shift+I ^> Console
echo   Filter by "[TeamDesk MCP]" to see response times.
echo.
echo Project folder: %INSTALL_DIR%
echo Claude config:  %CLAUDE_CONFIG%
echo.
pause
