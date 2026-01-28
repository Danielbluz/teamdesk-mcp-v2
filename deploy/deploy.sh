#!/bin/bash
# =============================================================================
# TeamDesk MCP Server v2 - Script de Deploy
# Servidor: srv1083726.hstgr.cloud (72.61.219.5)
# Executar no Terminal da Hostinger
# =============================================================================

set -e

echo "=========================================="
echo "  TeamDesk MCP Server v2 - Deploy"
echo "=========================================="

# Variáveis
APP_DIR="/opt/mcp-teamdesk"
BACKUP_DIR="/opt/mcp-teamdesk-v1-backup-$(date +%Y%m%d-%H%M%S)"
SERVICE_NAME="mcp-teamdesk"
VENV_DIR="$APP_DIR/venv"

# 1. Backup do V1
echo ""
echo "[1/7] Criando backup do V1..."
if [ -d "$APP_DIR" ]; then
    sudo cp -r "$APP_DIR" "$BACKUP_DIR"
    echo "  Backup criado em: $BACKUP_DIR"
else
    echo "  Nenhuma instalação anterior encontrada."
fi

# 2. Parar o serviço V1
echo ""
echo "[2/7] Parando serviço atual..."
sudo systemctl stop $SERVICE_NAME 2>/dev/null || echo "  Serviço não estava rodando."

# 3. Preparar diretório
echo ""
echo "[3/7] Preparando diretório..."
sudo mkdir -p "$APP_DIR/src"

# 4. Criar/atualizar venv
echo ""
echo "[4/7] Configurando ambiente Python..."
if [ ! -d "$VENV_DIR" ]; then
    sudo python3 -m venv "$VENV_DIR"
    echo "  Venv criado."
else
    echo "  Venv existente encontrado."
fi

# 5. Instalar dependências
echo ""
echo "[5/7] Instalando dependências..."
sudo "$VENV_DIR/bin/pip" install --upgrade pip
sudo "$VENV_DIR/bin/pip" install httpx mcp python-dotenv pydantic starlette uvicorn

# 6. Verificar se server.py foi copiado
echo ""
echo "[6/7] Verificando arquivos..."
if [ ! -f "$APP_DIR/src/server.py" ]; then
    echo ""
    echo "  ATENÇÃO: O arquivo src/server.py precisa ser copiado manualmente."
    echo "  Use o comando abaixo no terminal para colar o conteúdo:"
    echo ""
    echo "    sudo nano $APP_DIR/src/server.py"
    echo ""
    echo "  Ou use o comando cat com heredoc (será fornecido separadamente)."
    echo ""
else
    echo "  server.py encontrado."
fi

if [ ! -f "$APP_DIR/src/__init__.py" ]; then
    sudo touch "$APP_DIR/src/__init__.py"
fi

# 7. Verificar .env
echo ""
echo "[7/7] Verificando configuração..."
if [ ! -f "$APP_DIR/.env" ]; then
    echo ""
    echo "  ATENÇÃO: O arquivo .env precisa ser criado."
    echo "  Use: sudo nano $APP_DIR/.env"
    echo ""
else
    echo "  .env encontrado."
fi

echo ""
echo "=========================================="
echo "  Deploy preparado!"
echo "=========================================="
echo ""
echo "Próximos passos:"
echo "  1. Copiar src/server.py para $APP_DIR/src/"
echo "  2. Criar/verificar $APP_DIR/.env"
echo "  3. Atualizar o serviço systemd:"
echo "     sudo cp /tmp/mcp-teamdesk.service /etc/systemd/system/"
echo "     sudo systemctl daemon-reload"
echo "  4. Iniciar o serviço:"
echo "     sudo systemctl start $SERVICE_NAME"
echo "  5. Verificar logs:"
echo "     sudo journalctl -u $SERVICE_NAME -f --no-pager"
echo ""
