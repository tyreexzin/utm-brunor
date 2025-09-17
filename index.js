// --- DEPENDÊNCIAS ---
const { TelegramClient } = require('telegram');
const { StringSession } = require('telegram/sessions');
const { NewMessage } = require('telegram/events');
const input = require('input');
const moment = require('moment');
const axios = require('axios');
const express = require('express');
const { Pool } = require('pg');
require('dotenv').config();
const cors = require('cors');
const crypto = require('crypto');

// --- CONFIGURAÇÃO DO EXPRESS ---
const app = express();

app.use(cors({
    origin: '*',
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE',
    credentials: true,
    optionsSuccessStatus: 204
}));
app.use(express.json());

// --- VARIÁVEIS DE AMBIENTE E CONSTANTES ---
const TELEGRAM_SESSION = process.env.TELEGRAM_SESSION;
const DATABASE_URL = process.env.DATABASE_URL;
const PORT = process.env.PORT;
const API_KEY = process.env.API_KEY;
const PUSHINPAY_API_TOKEN = process.env.PUSHINPAY_API_TOKEN;

// Variáveis do Facebook
const FACEBOOK_PIXEL_ID_1 = process.env.FACEBOOK_PIXEL_ID_1;
const FACEBOOK_API_TOKEN_1 = process.env.FACEBOOK_API_TOKEN_1;
const FACEBOOK_PIXEL_ID_2 = process.env.FACEBOOK_PIXEL_ID_2;
const FACEBOOK_API_TOKEN_2 = process.env.FACEBOOK_API_TOKEN_2;

// [NOVO] Variáveis de Ambiente para a API do Google Ads
const GOOGLE_ADS_DEVELOPER_TOKEN = process.env.GOOGLE_ADS_DEVELOPER_TOKEN;
const GOOGLE_ADS_LOGIN_CUSTOMER_ID = process.env.GOOGLE_ADS_LOGIN_CUSTOMER_ID; // ID da sua conta de administrador (MCC), se usar uma
const GOOGLE_ADS_CUSTOMER_ID = process.env.GOOGLE_ADS_CUSTOMER_ID; // ID da sua conta de anúncios (sem os hifens)
const GOOGLE_ADS_CONVERSION_ACTION_ID = process.env.GOOGLE_ADS_CONVERSION_ACTION_ID; // ID numérico da Ação de Conversão

// Constantes do Telegram
const apiId = 21418810;
const apiHash = 'c9b5e116e5be50dbb4f352ee26bb7cd9';
const stringSession = new StringSession(TELEGRAM_SESSION || '');
const CHAT_ID = BigInt(-1003052806563);

// --- CONFIGURAÇÃO DO BANCO DE DADOS POSTGRESQL ---
const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: true }
});

pool.on('connect', () => {
    console.log('✅ PostgreSQL conectado!');
});

pool.on('error', (err) => {
    console.error('❌ Erro inesperado no pool do PostgreSQL:', err);
    process.exit(1);
});

// --- FUNÇÃO AUXILIAR PARA CRIPTOGRAFIA ---
function hashData(data) {
    if (!data) {
        return null;
    }
    const cleanedData = String(data).replace(/[^0-9]/g, '');
    const hash = crypto.createHash('sha256').update(cleanedData.toLowerCase().trim()).digest('hex');
    return hash;
}

// --- FUNÇÕES DO BANCO DE DADOS ---
async function setupDatabase() {
    console.log('🔄 Iniciando configuração do banco de dados...');
    const client = await pool.connect();
    try {
        const sqlVendas = `
            CREATE TABLE IF NOT EXISTS vendas (
                id SERIAL PRIMARY KEY, 
                chave TEXT UNIQUE NOT NULL, 
                hash TEXT UNIQUE NOT NULL, 
                valor REAL NOT NULL, 
                utm_source TEXT, 
                utm_medium TEXT, 
                utm_campaign TEXT, 
                utm_content TEXT, 
                utm_term TEXT, 
                order_id TEXT, 
                transaction_id TEXT, 
                ip TEXT, 
                user_agent TEXT, 
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, 
                facebook_purchase_sent BOOLEAN DEFAULT FALSE,
                keyword TEXT,
                device TEXT,
                network TEXT
            );
        `;
        await client.query(sqlVendas);
        console.log('✅ Tabela "vendas" verificada.');

        const sqlFrontendUtms = `
            CREATE TABLE IF NOT EXISTS frontend_utms (
                id SERIAL PRIMARY KEY, 
                unique_click_id TEXT UNIQUE NOT NULL, 
                timestamp_ms BIGINT NOT NULL, 
                valor REAL, 
                gclid TEXT, -- Coluna para o Google Click ID
                fbclid TEXT, 
                fbc TEXT, 
                fbp TEXT, 
                utm_source TEXT, 
                utm_medium TEXT, 
                utm_campaign TEXT, 
                utm_content TEXT, 
                utm_term TEXT, 
                keyword TEXT,
                device TEXT,
                network TEXT,
                ip TEXT, 
                user_agent TEXT, 
                received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await client.query(sqlFrontendUtms);
        console.log('✅ Tabela "frontend_utms" verificada.');

        const sqlTelegramUsers = `
            CREATE TABLE IF NOT EXISTS telegram_users (
                telegram_user_id TEXT PRIMARY KEY, 
                unique_click_id TEXT, 
                last_activity TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP, 
                created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
            );
        `;
        await client.query(sqlTelegramUsers);
        console.log('✅ Tabela "telegram_users" verificada.');

    } catch (err) {
        console.error('❌ Erro ao configurar tabelas no PostgreSQL:', err.message);
        process.exit(1);
    } finally {
        client.release();
    }
}

function gerarChaveUnica({ transaction_id }) {
    return `chave-${transaction_id}`;
}

function gerarHash({ transaction_id }) {
    return `hash-${transaction_id}`;
}

async function salvarVenda(venda) {
    console.log('💾 Tentando salvar venda no banco (PostgreSQL)...');
    const sql = `
        INSERT INTO vendas (
            chave, hash, valor, utm_source, utm_medium, utm_campaign, utm_content, utm_term, 
            order_id, transaction_id, ip, user_agent, facebook_purchase_sent,
            keyword, device, network
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16) 
        ON CONFLICT (hash) DO NOTHING;
    `;
    const valores = [
        venda.chave, venda.hash, venda.valor,
        venda.utm_source, venda.utm_medium, venda.utm_campaign, venda.utm_content, venda.utm_term,
        venda.orderId, venda.transaction_id,
        venda.ip, venda.userAgent,
        venda.facebook_purchase_sent,
        venda.keyword, venda.device, venda.network
    ];
    try {
        const res = await pool.query(sql, valores);
        if (res.rowCount > 0) {
            console.log('✅ Venda salva no PostgreSQL!');
        } else {
            console.log('🔁 Venda já existia no PostgreSQL, ignorando inserção (hash duplicado).');
        }
    } catch (err) {
        console.error('❌ Erro ao salvar venda no DB (PostgreSQL):', err.message);
    }
}

async function vendaExiste(hash) {
    console.log(`🔎 Verificando se venda com hash ${hash} existe no PostgreSQL...`);
    const sql = 'SELECT COUNT(*) AS total FROM vendas WHERE hash = $1';
    try {
        const res = await pool.query(sql, [hash]);
        return res.rows[0].total > 0;
    } catch (err) {
        console.error('❌ Erro ao verificar venda existente (PostgreSQL):', err.message);
        return false;
    }
}

async function saveUserClickAssociation(telegramUserId, uniqueClickId) {
    const sql = `
        INSERT INTO telegram_users (telegram_user_id, unique_click_id, last_activity) 
        VALUES ($1, $2, NOW()) 
        ON CONFLICT (telegram_user_id) DO UPDATE SET 
            unique_click_id = EXCLUDED.unique_click_id, 
            last_activity = NOW();
    `;
    try {
        await pool.query(sql, [telegramUserId, uniqueClickId]);
        console.log(`✅ Associação user_id(${telegramUserId}) -> click_id(${uniqueClickId}) salva no DB.`);
    } catch (err) {
        console.error('❌ Erro ao salvar associação user_id-click_id no DB:', err.message);
    }
}

async function salvarFrontendUtms(data) {
    console.log('💾 Tentando salvar UTMs do frontend no banco (PostgreSQL)...');
    const sql = `
        INSERT INTO frontend_utms (
            unique_click_id, timestamp_ms, valor, gclid, fbclid, fbc, fbp, 
            utm_source, utm_medium, utm_campaign, utm_content, utm_term, 
            keyword, device, network, ip, user_agent
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17);
    `;
    const valores = [
        data.unique_click_id, data.timestamp, data.valor,
        data.gclid || null,
        data.fbclid || null, data.fbc || null, data.fbp || null,
        data.utm_source || null, data.utm_medium || null, data.utm_campaign || null,
        data.utm_content || null, data.utm_term || null,
        data.keyword || null, data.device || null, data.network || null,
        data.ip || null, data.user_agent || null
    ];
    try {
        await pool.query(sql, valores);
        console.log('✅ UTMs do frontend salvas no PostgreSQL!');
    } catch (err) {
        console.error('❌ Erro ao salvar UTMs do frontend no DB (PostgreSQL):', err.message);
    }
}

async function buscarUtmsPorUniqueClickId(uniqueClickId) {
    console.log(`🔎 Buscando UTMs do frontend por unique_click_id: ${uniqueClickId}...`);
    const sql = 'SELECT * FROM frontend_utms WHERE unique_click_id = $1 ORDER BY received_at DESC LIMIT 1';
    try {
        const res = await pool.query(sql, [uniqueClickId]);
        if (res.rows.length > 0) {
            console.log(`✅ UTMs encontradas para unique_click_id ${uniqueClickId}.`);
            return res.rows[0];
        } else {
            console.log(`🔎 Nenhuma UTM do frontend encontrada para unique_click_id ${uniqueClickId}.`);
            return null;
        }
    } catch (err) {
        console.error('❌ Erro ao buscar UTMs por unique_click_id (PostgreSQL):', err.message);
        return null;
    }
}

async function limparFrontendUtmsAntigos() {
    console.log('🧹 Iniciando limpeza de UTMs antigos...');
    const cutoffTime = moment().subtract(24, 'hours').valueOf();
    const sql = `DELETE FROM frontend_utms WHERE timestamp_ms < $1`;
    try {
        const res = await pool.query(sql, [cutoffTime]);
        if (res.rowCount > 0) {
            console.log(`🧹 Limpeza de UTMs antigos: ${res.rowCount || 0} registros removidos.`);
        }
    } catch (err) {
        console.error('❌ Erro ao limpar UTMs antigos:', err.message);
    }
}

// --- FUNÇÕES DE API EXTERNAS ---

async function enviarEventoParaFacebook(pixelId, apiToken, payload, transaction_id) {
    if (!pixelId || !apiToken) {
        console.log(`⚠️  [BOT] Pixel ID ou API Token não configurado para o Facebook. Envio ignorado.`);
        return false;
    }
    console.log(`➡️  [BOT] Enviando evento 'Purchase' (ID: ${transaction_id}) para o Pixel do Facebook ${pixelId}...`);
    try {
        await axios.post(
            `https://graph.facebook.com/v20.0/${pixelId}/events?access_token=${apiToken}`,
            payload
        );
        console.log(`✅ [BOT] Evento enviado com sucesso para o Pixel do Facebook ${pixelId}.`);
        return true;
    } catch (err) {
        console.error(`❌ [BOT] Erro ao enviar para o Pixel do Facebook ${pixelId}:`, err.response?.data?.error || err.message);
        return false;
    }
}

async function enviarConversaoParaGoogleAds(gclid, valor, transaction_id) {
    if (!gclid) {
        console.log('⚠️ [BOT] Sem GCLID para esta venda. Conversão do Google não será enviada.');
        return false;
    }
    if (!GOOGLE_ADS_DEVELOPER_TOKEN || !GOOGLE_ADS_CUSTOMER_ID || !GOOGLE_ADS_CONVERSION_ACTION_ID) {
        console.error('❌ [BOT] Variáveis de ambiente do Google Ads não configuradas. Verifique .env');
        return false;
    }

    console.log(`➡️  [BOT] Enviando conversão para o Google Ads (GCLID: ${gclid})`);

    const url = `https://googleads.googleapis.com/v17/customers/${GOOGLE_ADS_CUSTOMER_ID}/conversionUploads:uploadClickConversions`;

    const payload = {
        conversions: [{
            gclid: gclid,
            conversionAction: `customers/${GOOGLE_ADS_CUSTOMER_ID}/conversionActions/${GOOGLE_ADS_CONVERSION_ACTION_ID}`,
            conversionDateTime: moment().format('YYYY-MM-DD HH:mm:ssZ'),
            conversionValue: valor,
            currencyCode: 'BRL',
            orderId: transaction_id
        }],
        partialFailure: true,
    };

    const headers = {
        'Authorization': `Bearer ${GOOGLE_ADS_DEVELOPER_TOKEN}`, // A API usa o Developer Token como Bearer Token para autenticação
        'Content-Type': 'application/json',
        'developer-token': GOOGLE_ADS_DEVELOPER_TOKEN, // O token também é passado aqui
    };

    if (GOOGLE_ADS_LOGIN_CUSTOMER_ID) {
        headers['login-customer-id'] = GOOGLE_ADS_LOGIN_CUSTOMER_ID;
    }

    try {
        const response = await axios.post(url, payload, { headers });
        if (response.data.partialFailureError) {
            console.error(`❌ [BOT] Erro parcial ao enviar conversão para Google Ads:`, response.data.partialFailureError.details);
            return false;
        }
        const result = response.data.results[0];
        console.log(`✅ [BOT] Conversão enviada com sucesso para o Google Ads.`);
        return true;
    } catch (err) {
        console.error('❌ [BOT] Erro fatal ao enviar conversão para Google Ads:', err.response?.data?.error?.details[0] || err.message);
        return false;
    }
}


// --- ENDPOINTS HTTP ---
app.post('/frontend-utm-data', (req, res) => {
    console.log('🚀 [BACKEND] Dados do frontend recebidos:', req.body);
    if (!req.body.unique_click_id || !req.body.timestamp) {
        return res.status(400).send('unique_click_id e Timestamp são obrigatórios.');
    }
    salvarFrontendUtms(req.body);
    res.status(200).send('Dados recebidos com sucesso!');
});

app.get('/ping', (req, res) => {
    console.log(`💚 [PING] Recebida requisição /ping às ${moment().format('HH:mm:ss')}. Serviço está ativo.`);
    res.status(200).send('Pong!');
});


// --- INICIALIZAÇÃO E LÓGICA PRINCIPAL ---
app.listen(PORT || 3000, () => {
    console.log(`🌐 Servidor HTTP Express escutando na porta ${PORT || 3000}.`);

    const PING_INTERVALO_MINUTOS = 14;
    const PING_INTERVALO_MS = PING_INTERVALO_MINUTOS * 60 * 1000;

    const selfPing = async () => {
        const url = process.env.RENDER_EXTERNAL_URL;
        if (url) {
            try {
                await axios.get(`${url}/ping`);
            } catch (err) {
                console.error(`❌ Erro no auto-ping às ${moment().format('HH:mm:ss')}:`, err.message);
            }
        }
    };

    (async () => {
        await setupDatabase();

        setInterval(limparFrontendUtmsAntigos, 60 * 60 * 1000);
        console.log('🧹 Limpeza de UTMs antigos agendada para cada 1 hora.');

        if (process.env.RENDER_EXTERNAL_URL) {
            setInterval(selfPing, PING_INTERVALO_MS);
            console.log(`🔁 Auto-ping configurado para cada ${PING_INTERVALO_MINUTOS} minuto(s).`);
        }

        if (!TELEGRAM_SESSION) {
            return console.error("❌ ERRO FATAL: TELEGRAM_SESSION não definida.");
        }

        console.log('Iniciando userbot...');
        const client = new TelegramClient(new StringSession(TELEGRAM_SESSION), parseInt(apiId), apiHash, { connectionRetries: 5 });

        try {
            await client.start({
                phoneNumber: async () => input.text('Digite seu número com DDI: '),
                password: async () => input.text('Senha 2FA (se tiver): '),
                phoneCode: async () => input.text('Código do Telegram: '),
                onError: (err) => console.log('Erro login:', err),
            });
            console.log('✅ Userbot conectado!');
            const sessionString = client.session.save();
            if (sessionString !== TELEGRAM_SESSION) {
                console.log('🔑 Nova StringSession:', sessionString);
            }
        } catch (error) {
            console.error('❌ Falha ao iniciar o userbot:', error.message);
            process.exit(1);
        }

        client.addEventHandler(async (event) => {
            const message = event.message;
            if (!message || !message.message || message.chatId.toString() !== CHAT_ID.toString()) {
                return;
            }

            let texto = message.message.replace(/\r/g, '').trim();
            if (texto.startsWith('/start ')) {
                const startPayload = decodeURIComponent(texto.substring('/start '.length).trim());
                await saveUserClickAssociation(message.senderId.toString(), startPayload);
                return;
            }

            const idMatch = texto.match(/ID\s+Transa(?:ç|c)[aã]o\s+Gateway[:：]?\s*([\w-]+)/i);
            const valorLiquidoMatch = texto.match(/Valor\s+L[ií]quido[:：]?\s*R?\$?\s*([\d.,]+)/i);

            if (!idMatch || !valorLiquidoMatch) {
                return;
            }

            try {
                const transaction_id = idMatch[1].trim();
                const hash = gerarHash({ transaction_id });

                if (await vendaExiste(hash)) {
                    console.log(`🔁 Venda com hash ${hash} já registrada. Ignorando.`);
                    return;
                }

                console.log(`\n⚡ Nova venda detectada! Processando ID: ${transaction_id}`);

                const nomeCompletoRegex = /Nome\s+Completo[:：]?\s*(.+)/i;
                const emailRegex = /E-mail[:：]?\s*(\S+@\S+\.\S+)/i;
                const codigoVendaRegex = /Código\s+de\s+Venda[:：]?\s*(.+)/i;
                const plataformaPagamentoRegex = /Plataforma\s+Pagamento[:：]?\s*(.+)/i;
                const metodoPagamentoRegex = /M[ée]todo\s+Pagamento[:：]?\s*(.+)/i;

                const nomeMatch = texto.match(nomeCompletoRegex);
                const emailMatch = texto.match(emailRegex);
                const codigoVendaMatch = texto.match(codigoVendaRegex);

                let nomeDaMensagem = "Cliente Desconhecido";
                if (nomeMatch && nomeMatch[1]) {
                    nomeDaMensagem = nomeMatch[1].trim().split('|')[0];
                }
                let emailDaMensagem = null;
                if (emailMatch && emailMatch[1]) {
                    emailDaMensagem = emailMatch[1].trim();
                }
                let valorDaMensagem = 0;
                if (valorLiquidoMatch && valorLiquidoMatch[1]) {
                    valorDaMensagem = parseFloat(valorLiquidoMatch[1].replace(/\./g, '').replace(',', '.'));
                }
                let codigoVendaDaMensagem = null;
                if (codigoVendaMatch && codigoVendaMatch[1]) {
                    codigoVendaDaMensagem = codigoVendaMatch[1].trim();
                }

                let dadosDaApi = null;
                if (PUSHINPAY_API_TOKEN) {
                    console.log(`🔎 Consultando API da Pushinpay para a transação ${transaction_id}...`);
                    try {
                        const response = await axios.get(`https://api.pushinpay.com.br/api/transactions/${transaction_id}`, {
                            headers: { 'Authorization': `Bearer ${PUSHINPAY_API_TOKEN}`, 'Accept': 'application/json' }
                        });
                        dadosDaApi = response.data;
                        console.log('✅ Dados da API Pushinpay obtidos com sucesso!');
                    } catch (apiError) {
                        console.warn(`⚠️  Não foi possível consultar a API da Pushinpay. Prosseguindo com dados da mensagem.`);
                    }
                }

                const finalCustomerName = dadosDaApi?.payer_name || nomeDaMensagem;
                const finalCustomerEmail = emailDaMensagem;
                const finalCustomerDocument = dadosDaApi?.payer_national_registration || null;
                const finalValor = valorDaMensagem;

                console.log(`  -> Valor Líquido: R$ ${finalValor.toFixed(2)} | Nome Final: ${finalCustomerName}`);

                let matchedFrontendUtms = null;
                if (codigoVendaDaMensagem) {
                    matchedFrontendUtms = await buscarUtmsPorUniqueClickId(codigoVendaDaMensagem);
                }
                if (matchedFrontendUtms) {
                    console.log(`✅ [BOT] UTMs e dados do frontend para ${transaction_id} atribuídos!`);
                }

                // --- Envio para UTMify ---
                if (API_KEY) {
                    let trackingParams = {
                        utm_source: null,
                        utm_medium: null,
                        utm_campaign: null,
                        utm_content: null,
                        utm_term: null,
                    };

                    if (matchedFrontendUtms) {
                        trackingParams.utm_source = matchedFrontendUtms.utm_source || null;
                        trackingParams.utm_medium = matchedFrontendUtms.utm_medium || null;
                        trackingParams.utm_campaign = matchedFrontendUtms.utm_campaign || null;
                        trackingParams.utm_content = matchedFrontendUtms.utm_content || null;
                        trackingParams.utm_term = matchedFrontendUtms.utm_term || null;
                    } else {
                        console.log(`⚠️ [BOT] Nenhuma UTM correspondente encontrada.`);
                    }

                    const platform = (texto.match(plataformaPagamentoRegex) || [])[1]?.trim() || 'UnknownPlatform';
                    const paymentMethod = (texto.match(metodoPagamentoRegex) || [])[1]?.trim().toLowerCase().replace(' ', '_') || 'unknown';
                    const agoraUtc = moment.utc().format('YYYY-MM-DD HH:mm:ss');

                    const utmifyPayload = {
                        orderId: transaction_id,
                        platform: platform,
                        paymentMethod: paymentMethod,
                        status: 'paid',
                        createdAt: agoraUtc,
                        approvedDate: agoraUtc,
                        customer: {
                            name: finalCustomerName,
                            email: finalCustomerEmail || "naoinformado@utmify.com",
                            phone: null,
                            document: finalCustomerDocument,
                            ip: matchedFrontendUtms?.ip || '0.0.0.0'
                        },
                        products: [{
                            id: 'acesso-vip-bundle', name: 'Acesso VIP', planId: '', planName: '',
                            quantity: 1, priceInCents: Math.round(finalValor * 100)
                        }],
                        trackingParameters: trackingParams,
                        commission: {
                            totalPriceInCents: Math.round(finalValor * 100), gatewayFeeInCents: 0,
                            userCommissionInCents: Math.round(finalValor * 100), currency: 'BRL'
                        },
                        isTest: false
                    };

                    try {
                        const res = await axios.post('https://api.utmify.com.br/api-credentials/orders', utmifyPayload, { headers: { 'x-api-token': API_KEY } });
                        console.log('📬 [BOT] Resposta da UTMify:', res.status, res.data);
                    } catch (err) {
                        console.error('❌ [BOT] Erro ao enviar para UTMify:', err.response?.data || err.message);
                    }
                }

                // --- Envio para Facebook CAPI ---
                const nomeCompleto = finalCustomerName.toLowerCase().split(' ');
                const userData = {
                    fn: [hashData(nomeCompleto[0])],
                    ln: [hashData(nomeCompleto.length > 1 ? nomeCompleto.slice(1).join(' ') : null)],
                    external_id: [hashData(finalCustomerDocument)],
                    client_ip_address: matchedFrontendUtms?.ip,
                    client_user_agent: matchedFrontendUtms?.user_agent,
                    fbc: matchedFrontendUtms?.fbc,
                    fbp: matchedFrontendUtms?.fbp,
                };
                Object.keys(userData).forEach(key => (!userData[key] || (Array.isArray(userData[key]) && !userData[key][0])) && delete userData[key]);

                const customData = {
                    value: finalValor,
                    currency: 'BRL',
                    g_keyword: matchedFrontendUtms?.keyword,
                    g_device: matchedFrontendUtms?.device,
                    g_network: matchedFrontendUtms?.network,
                };
                Object.keys(customData).forEach(key => (customData[key] === undefined || customData[key] === null) && delete customData[key]);

                const facebookPayload = {
                    data: [{
                        event_name: 'Purchase',
                        event_time: Math.floor(Date.now() / 1000),
                        event_id: transaction_id,
                        action_source: 'website',
                        user_data: userData,
                        custom_data: customData
                    }]
                };

                const envioPixel1 = await enviarEventoParaFacebook(FACEBOOK_PIXEL_ID_1, FACEBOOK_API_TOKEN_1, facebookPayload, transaction_id);
                const envioPixel2 = await enviarEventoParaFacebook(FACEBOOK_PIXEL_ID_2, FACEBOOK_API_TOKEN_2, facebookPayload, transaction_id);
                const facebook_purchase_sent = envioPixel1 || envioPixel2;

                // --- Envio para Google Ads API ---
                if (matchedFrontendUtms) {
                    await enviarConversaoParaGoogleAds(matchedFrontendUtms.gclid, finalValor, transaction_id);
                }

                // --- Salvamento Final no Banco ---
                await salvarVenda({
                    chave: gerarChaveUnica({ transaction_id }),
                    hash: gerarHash({ transaction_id }),
                    valor: finalValor,
                    utm_source: matchedFrontendUtms?.utm_source,
                    utm_medium: matchedFrontendUtms?.utm_medium,
                    utm_campaign: matchedFrontendUtms?.utm_campaign,
                    utm_content: matchedFrontendUtms?.utm_content,
                    utm_term: matchedFrontendUtms?.utm_term,
                    orderId: transaction_id,
                    transaction_id: transaction_id,
                    ip: matchedFrontendUtms?.ip,
                    userAgent: matchedFrontendUtms?.user_agent,
                    facebook_purchase_sent: facebook_purchase_sent,
                    keyword: matchedFrontendUtms?.keyword,
                    device: matchedFrontendUtms?.device,
                    network: matchedFrontendUtms?.network
                });

            } catch (err) {
                console.error('❌ [BOT] Erro geral ao processar mensagem:', err.message);
            }
        });
    })();
});