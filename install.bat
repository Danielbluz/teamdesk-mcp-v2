@echo off
REM TeamDesk MCP Server - Windows Installer
REM Installs and configures the TeamDesk MCP server for Claude Desktop/Code

echo ==========================================
echo   TeamDesk MCP Server - Installer
echo ==========================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.10+ from python.org
    pause
    exit /b 1
)

REM Create directory
set MCP_DIR=%USERPROFILE%\.claude\mcp-teamdesk
if not exist "%MCP_DIR%" mkdir "%MCP_DIR%"

REM Copy server
copy /y "%~dp0server.py" "%MCP_DIR%\server.py" >nul
copy /y "%~dp0requirements.txt" "%MCP_DIR%\requirements.txt" >nul
copy /y "%~dp0.env.example" "%MCP_DIR%\.env.example" >nul

REM Create venv and install deps
echo Installing dependencies...
python -m venv "%MCP_DIR%\venv"
"%MCP_DIR%\venv\Scripts\pip" install -q -r "%MCP_DIR%\requirements.txt"

REM Create .env if not exists
if not exist "%MCP_DIR%\.env" (
    echo.
    echo ==========================================
    echo   Configuration
    echo ==========================================
    echo.
    set /p TD_DBID="TeamDesk Database ID: "
    set /p TD_TOKEN="TeamDesk API Token: "
    (
        echo TEAMDESK_DATABASE_ID=%TD_DBID%
        echo TEAMDESK_API_TOKEN=%TD_TOKEN%
    ) > "%MCP_DIR%\.env"
    echo.
    echo .env created at %MCP_DIR%\.env
) else (
    echo .env already exists, skipping configuration.
)

echo.
echo ==========================================
echo   Installation Complete!
echo ==========================================
echo.
echo Server installed at: %MCP_DIR%
echo.
echo Add to your Claude Desktop config (claude_desktop_config.json):
echo.
echo   "teamdesk": {
echo     "command": "%MCP_DIR:\=\\%\\venv\\Scripts\\python",
echo     "args": ["%MCP_DIR:\=\\%\\server.py"]
echo   }
echo.
pause
