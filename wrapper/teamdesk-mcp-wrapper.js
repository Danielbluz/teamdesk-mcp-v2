#!/usr/bin/env node
/**
 * TeamDesk MCP Wrapper v2
 * Wrapper local para Claude Desktop que traduz protocolo MCP padrão (stdio)
 * para chamadas HTTP REST ao servidor TeamDesk MCP v2
 */

const readline = require('readline');
const https = require('https');
const http = require('http');

// Configuração - será lida das variáveis de ambiente ou argumentos
const SERVER_URL = process.env.TEAMDESK_MCP_URL || 'http://72.61.219.5:8080';
const API_KEY = process.env.TEAMDESK_API_KEY || process.argv[2] || '';

// Parse da URL do servidor
const serverUrl = new URL(SERVER_URL);
const httpModule = serverUrl.protocol === 'https:' ? https : http;

// Buffer para entrada
let inputBuffer = '';

// Interface readline para stdin
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout,
    terminal: false
});

// Log para stderr (não interfere com stdout do MCP)
function log(...args) {
    console.error('[TeamDesk MCP Wrapper]', ...args);
}

// Envia resposta JSON-RPC para stdout
function sendResponse(response) {
    const json = JSON.stringify(response);
    process.stdout.write(json + '\n');
}

// Envia erro JSON-RPC
function sendError(id, code, message) {
    sendResponse({
        jsonrpc: '2.0',
        id: id,
        error: { code, message }
    });
}

// Faz requisição HTTP ao servidor
async function httpRequest(method, path, body = null) {
    return new Promise((resolve, reject) => {
        const options = {
            hostname: serverUrl.hostname,
            port: serverUrl.port || (serverUrl.protocol === 'https:' ? 443 : 80),
            path: path,
            method: method,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                'X-API-Key': API_KEY
            }
        };

        const req = httpModule.request(options, (res) => {
            let data = '';
            res.on('data', chunk => data += chunk);
            res.on('end', () => {
                try {
                    resolve({
                        status: res.statusCode,
                        data: data ? JSON.parse(data) : {}
                    });
                } catch (e) {
                    resolve({
                        status: res.statusCode,
                        data: { raw: data }
                    });
                }
            });
        });

        req.on('error', reject);
        req.setTimeout(60000, () => {
            req.destroy();
            reject(new Error('Timeout'));
        });

        if (body) {
            req.write(JSON.stringify(body));
        }
        req.end();
    });
}

// Lista de ferramentas (cacheada)
let toolsCache = null;

async function getTools() {
    if (toolsCache) return toolsCache;

    try {
        const response = await httpRequest('GET', '/tools');
        if (response.status === 200 && response.data.tools) {
            toolsCache = response.data.tools;
            return toolsCache;
        }
    } catch (e) {
        log('Erro ao obter ferramentas:', e.message);
    }

    // Fallback: lista hardcoded
    return [
        { name: 'list_tables', description: 'Lista todas as tabelas disponíveis no banco TeamDesk', inputSchema: { type: 'object', properties: {}, required: [] } },
        { name: 'describe_table', description: 'Descreve a estrutura de uma tabela', inputSchema: { type: 'object', properties: { table: { type: 'string' } }, required: ['table'] } },
        { name: 'get_records', description: 'Obtém registros de uma tabela com filtros opcionais', inputSchema: { type: 'object', properties: { table: { type: 'string' }, filter: { type: 'string' }, columns: { type: 'array' }, top: { type: 'integer' }, skip: { type: 'integer' } }, required: ['table'] } },
        { name: 'get_record', description: 'Obtém um registro específico pelo ID', inputSchema: { type: 'object', properties: { table: { type: 'string' }, record_id: { type: 'integer' } }, required: ['table', 'record_id'] } },
        { name: 'create_record', description: 'Cria um novo registro na tabela', inputSchema: { type: 'object', properties: { table: { type: 'string' }, data: { type: 'object' } }, required: ['table', 'data'] } },
        { name: 'update_record', description: 'Atualiza um registro existente', inputSchema: { type: 'object', properties: { table: { type: 'string' }, record_id: { type: 'integer' }, data: { type: 'object' } }, required: ['table', 'record_id', 'data'] } },
        { name: 'delete_record', description: 'Remove um registro da tabela', inputSchema: { type: 'object', properties: { table: { type: 'string' }, record_id: { type: 'integer' } }, required: ['table', 'record_id'] } },
        { name: 'select_query', description: 'Executa uma query SELECT personalizada', inputSchema: { type: 'object', properties: { query: { type: 'string' } }, required: ['query'] } },
        { name: 'upsert_records', description: 'Cria ou atualiza registros em lote', inputSchema: { type: 'object', properties: { table: { type: 'string' }, match_column: { type: 'string' }, records: { type: 'array' } }, required: ['table', 'match_column', 'records'] } },
        { name: 'select_from_view', description: 'Consulta dados de uma view', inputSchema: { type: 'object', properties: { table: { type: 'string' }, view: { type: 'string' }, top: { type: 'integer' } }, required: ['table', 'view'] } },
        { name: 'get_attachment_url', description: 'Gera URL para download de anexo', inputSchema: { type: 'object', properties: { field_id: { type: 'string' }, guid: { type: 'string' } }, required: ['field_id', 'guid'] } }
    ];
}

// Processa mensagem JSON-RPC
async function processMessage(message) {
    let request;
    try {
        request = JSON.parse(message);
    } catch (e) {
        sendError(null, -32700, 'Parse error');
        return;
    }

    const { id, method, params } = request;

    // Verificar se tem API Key configurada
    if (!API_KEY && method !== 'initialize') {
        sendError(id, -32000, 'API Key não configurada. Defina TEAMDESK_API_KEY ou passe como argumento.');
        return;
    }

    try {
        switch (method) {
            case 'initialize':
                sendResponse({
                    jsonrpc: '2.0',
                    id: id,
                    result: {
                        protocolVersion: '2024-11-05',
                        capabilities: {
                            tools: {}
                        },
                        serverInfo: {
                            name: 'teamdesk-mcp-server',
                            version: '2.0.0'
                        }
                    }
                });
                break;

            case 'notifications/initialized':
                // Notificação, não precisa resposta
                break;

            case 'tools/list':
                const tools = await getTools();
                sendResponse({
                    jsonrpc: '2.0',
                    id: id,
                    result: {
                        tools: tools.map(t => ({
                            name: t.name,
                            description: t.description,
                            inputSchema: t.inputSchema
                        }))
                    }
                });
                break;

            case 'tools/call':
                const toolName = params?.name;
                const toolArgs = params?.arguments || {};

                if (!toolName) {
                    sendError(id, -32602, 'Nome da ferramenta é obrigatório');
                    return;
                }

                try {
                    const response = await httpRequest('POST', '/tools/call', {
                        name: toolName,
                        arguments: toolArgs
                    });

                    if (response.status === 200) {
                        sendResponse({
                            jsonrpc: '2.0',
                            id: id,
                            result: {
                                content: [{
                                    type: 'text',
                                    text: JSON.stringify(response.data.result, null, 2)
                                }]
                            }
                        });
                    } else {
                        sendResponse({
                            jsonrpc: '2.0',
                            id: id,
                            result: {
                                content: [{
                                    type: 'text',
                                    text: `Erro ${response.status}: ${JSON.stringify(response.data)}`
                                }],
                                isError: true
                            }
                        });
                    }
                } catch (e) {
                    sendResponse({
                        jsonrpc: '2.0',
                        id: id,
                        result: {
                            content: [{
                                type: 'text',
                                text: `Erro de conexão: ${e.message}`
                            }],
                            isError: true
                        }
                    });
                }
                break;

            case 'ping':
                sendResponse({
                    jsonrpc: '2.0',
                    id: id,
                    result: {}
                });
                break;

            default:
                sendError(id, -32601, `Método não suportado: ${method}`);
        }
    } catch (e) {
        log('Erro processando mensagem:', e);
        sendError(id, -32603, e.message);
    }
}

// Processa linha de entrada
rl.on('line', (line) => {
    if (line.trim()) {
        processMessage(line.trim());
    }
});

rl.on('close', () => {
    process.exit(0);
});

// Log inicial
log('Wrapper iniciado');
log('Servidor:', SERVER_URL);
log('API Key:', API_KEY ? '***' + API_KEY.slice(-4) : 'NÃO CONFIGURADA');
