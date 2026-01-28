# Teamdesk MCP Server v2

Servidor MCP (Model Context Protocol) para integração com Teamdesk.

## Instalação

```bash
# Criar ambiente virtual
python -m venv venv

# Ativar ambiente virtual
# Windows:
venv\Scripts\activate
# Linux/Mac:
source venv/bin/activate

# Instalar dependências
pip install -r requirements.txt
```

## Configuração

Crie um arquivo `.env` na raiz do projeto:

```env
TEAMDESK_API_KEY=sua_api_key
TEAMDESK_DATABASE_ID=seu_database_id
```

## Uso

```bash
python src/server.py
```

## Estrutura do Projeto

```
teamdesk-mcp-v2/
├── src/
│   ├── __init__.py
│   └── server.py
├── tests/
│   └── __init__.py
├── .env.example
├── .gitignore
├── README.md
└── requirements.txt
```
