# Guia de Deploy - TeamDesk MCP Server v2

## Pré-requisitos
- Acesso ao Terminal da Hostinger (VPS srv1083726.hstgr.cloud)
- Token master do TeamDesk (seu token admin)
- DNS de `mcp.forgreen.com.br` apontando para 72.61.219.5

---

## Etapa 1: Backup e Preparação

Colar no Terminal da Hostinger:

```bash
# Backup do V1
sudo cp -r /opt/mcp-teamdesk /opt/mcp-teamdesk-v1-backup

# Parar V1
sudo systemctl stop mcp-teamdesk

# Preparar diretório V2
sudo mkdir -p /opt/mcp-teamdesk/src
sudo touch /opt/mcp-teamdesk/src/__init__.py
```

---

## Etapa 2: Copiar o Código

O arquivo `src/server.py` precisa ser copiado para `/opt/mcp-teamdesk/src/server.py`.

Opção A - Nano (mais simples):
```bash
sudo nano /opt/mcp-teamdesk/src/server.py
# Colar todo o conteúdo de src/server.py
# Ctrl+O para salvar, Ctrl+X para sair
```

Opção B - Cat com heredoc (alternativa):
```bash
# Usar o arquivo server-heredoc.sh fornecido separadamente
```

---

## Etapa 3: Configurar .env

```bash
sudo tee /opt/mcp-teamdesk/.env > /dev/null << 'EOF'
TEAMDESK_DATABASE_ID=101885
TEAMDESK_MASTER_TOKEN=AF8EA3994E6843A39A6D3269CBD69473
TEAMDESK_API_KEYS_TABLE=API-Keys
MCP_HOST=0.0.0.0
MCP_PORT=8080
MCP_RATE_LIMIT=100
MCP_CACHE_TTL=300
MCP_API_KEY_CACHE_TTL=60
MCP_MAX_PAYLOAD_SIZE=1048576
MCP_CORS_ORIGINS=*
EOF

# Proteger o arquivo
sudo chmod 600 /opt/mcp-teamdesk/.env
```

---

## Etapa 4: Instalar Dependências

```bash
# Criar venv (se não existir)
cd /opt/mcp-teamdesk
sudo python3 -m venv venv 2>/dev/null || true

# Instalar dependências
sudo /opt/mcp-teamdesk/venv/bin/pip install --upgrade pip
sudo /opt/mcp-teamdesk/venv/bin/pip install httpx mcp python-dotenv pydantic starlette uvicorn
```

---

## Etapa 5: Atualizar Serviço Systemd

```bash
sudo tee /etc/systemd/system/mcp-teamdesk.service > /dev/null << 'EOF'
[Unit]
Description=TeamDesk MCP Server v2
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/mcp-teamdesk
Environment=PATH=/opt/mcp-teamdesk/venv/bin:/usr/local/bin:/usr/bin:/bin
EnvironmentFile=/opt/mcp-teamdesk/.env
ExecStart=/opt/mcp-teamdesk/venv/bin/python -m uvicorn src.server:app --host 0.0.0.0 --port 8080
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
```

---

## Etapa 6: Iniciar e Verificar

```bash
# Iniciar serviço
sudo systemctl start mcp-teamdesk
sudo systemctl enable mcp-teamdesk

# Verificar status
sudo systemctl status mcp-teamdesk

# Ver logs em tempo real
sudo journalctl -u mcp-teamdesk -f --no-pager -n 50
```

---

## Etapa 7: Testar

```bash
# Health check (deve retornar JSON com status: healthy)
curl http://localhost:8080/health

# Listar ferramentas
curl http://localhost:8080/tools

# Testar com API Key (substitua pela sua key da tabela API-Keys)
curl -X POST http://localhost:8080/tools/call \
  -H "Content-Type: application/json" \
  -H "X-API-Key: sua-api-key-aqui" \
  -d '{"name": "list_tables", "arguments": {}}'

# Testar acesso externo (do seu PC local)
curl http://72.61.219.5:8080/health
```

---

## Etapa 8: Configurar Nginx + SSL (após DNS propagar)

```bash
# Instalar Nginx e Certbot (se não instalados)
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx

# Criar config Nginx
sudo tee /etc/nginx/sites-available/mcp-teamdesk > /dev/null << 'NGINXEOF'
server {
    listen 80;
    server_name mcp.forgreen.com.br;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # SSE support
        proxy_buffering off;
        proxy_cache off;
        proxy_read_timeout 86400s;
        proxy_send_timeout 86400s;
    }
}
NGINXEOF

# Ativar site
sudo ln -sf /etc/nginx/sites-available/mcp-teamdesk /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl reload nginx

# Obter certificado SSL
sudo certbot --nginx -d mcp.forgreen.com.br

# Certbot vai:
# 1. Verificar que o DNS aponta para este servidor
# 2. Gerar o certificado
# 3. Atualizar a config Nginx automaticamente para HTTPS
# 4. Configurar redirect HTTP -> HTTPS
```

---

## Etapa 9: Abrir Porta no Firewall (se necessário)

```bash
# Verificar firewall
sudo ufw status

# Abrir portas necessárias
sudo ufw allow 80/tcp    # HTTP (Nginx)
sudo ufw allow 443/tcp   # HTTPS (Nginx)
# Nota: 8080 NÃO precisa ser aberto externamente (Nginx faz proxy interno)
```

---

## Configuração do Claude Desktop

Após o SSL estar funcionando, adicionar ao `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "teamdesk": {
      "url": "https://mcp.forgreen.com.br/sse",
      "headers": {
        "X-API-Key": "sua-api-key-aqui"
      }
    }
  }
}
```

Se usar sem SSL temporariamente (HTTP direto):

```json
{
  "mcpServers": {
    "teamdesk": {
      "url": "http://72.61.219.5:8080/sse",
      "headers": {
        "X-API-Key": "sua-api-key-aqui"
      }
    }
  }
}
```

---

## Troubleshooting

### Serviço não inicia
```bash
sudo journalctl -u mcp-teamdesk -n 100 --no-pager
```

### Testar manualmente
```bash
cd /opt/mcp-teamdesk
source venv/bin/activate
python -m uvicorn src.server:app --host 0.0.0.0 --port 8080
```

### Verificar porta em uso
```bash
sudo ss -tulpn | grep 8080
```

### DNS não propagou
```bash
nslookup mcp.forgreen.com.br 8.8.8.8
dig mcp.forgreen.com.br
```

### Reverter para V1
```bash
sudo systemctl stop mcp-teamdesk
sudo rm -rf /opt/mcp-teamdesk
sudo cp -r /opt/mcp-teamdesk-v1-backup /opt/mcp-teamdesk
sudo systemctl start mcp-teamdesk
```
