const {
    default: makeWASocket,
    useMultiFileAuthState,
    DisconnectReason,
    fetchLatestBaileysVersion,
    delay,
    downloadMediaMessage
} = require('@whiskeysockets/baileys');
const pino = require('pino');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const fs = require('fs');

const nomeSessao = process.argv[2];
const promptSistema = process.argv[3];
const ignoredIdentifiersArg = process.argv[4] || '[]';
const phoneNumberArg = process.argv[5]; 

const modeloGemini = 'gemini-flash-latest';

if (!nomeSessao || !promptSistema) {
    console.error('❌ Uso correto: node index.js "nome-sessao" "Você é um vendedor..." \'[{"type":"name","value":"Joao"}]\' [numero-telefone]');
    process.exit(1);
}

let ignoredIdentifiers = [];
try {
    ignoredIdentifiers = JSON.parse(ignoredIdentifiersArg);
} catch (e) {
    console.error('❌ Erro ao interpretar a lista de ignorados:', e);
}

if (ignoredIdentifiers.length > 0) {
    console.log(`🚫 Ignorando ${ignoredIdentifiers.length} identificador(es).`);
}

const API_KEYS_STRING = process.env.API_KEYS_GEMINI;
if (!API_KEYS_STRING || !API_KEYS_STRING.trim()) {
    console.error('❌ ERRO: Nenhuma chave API do Gemini foi fornecida.');
    process.exit(1);
}

const API_KEYS = API_KEYS_STRING.split('\n').map(key => key.trim()).filter(Boolean);
if (API_KEYS.length === 0) {
    console.error('❌ ERRO: O formato das chaves API é inválido.');
    process.exit(1);
}

let currentApiKeyIndex = 0;
let genAI = new GoogleGenerativeAI(API_KEYS[currentApiKeyIndex]);
let model = genAI.getGenerativeModel({ model: modeloGemini });

console.log(`🔑 ${API_KEYS.length} Chave(s) API carregada(s).`);

const logger = pino({ level: 'silent' });
const historicoConversa = {};
const MAX_HISTORICO_POR_USUARIO = 20;

function switchToNextApiKey() {
    currentApiKeyIndex = (currentApiKeyIndex + 1) % API_KEYS.length;
    const newKey = API_KEYS[currentApiKeyIndex];
    console.warn(`[API Switch] Trocando para chave #${currentApiKeyIndex}.`);
    genAI = new GoogleGenerativeAI(newKey);
    model = genAI.getGenerativeModel({ model: modeloGemini });
}

async function processarComGemini(jid, input, isAudio = false) {
    for (let attempt = 0; attempt < API_KEYS.length; attempt++) {
        try {
            if (!historicoConversa[jid]) { historicoConversa[jid] = []; }

            let parts;
            if (isAudio) {
                parts = [{ inlineData: { mimeType: "audio/ogg", data: input } }, { text: "Responda a este áudio." }];
                if (attempt === 0) historicoConversa[jid].push({ role: "user", parts: [{ text: "[ÁUDIO]" }] });
            } else {
                parts = [{ text: input }];
                if (attempt === 0) historicoConversa[jid].push({ role: "user", parts: [{ text: input }] });
            }

            const chatHistory = [
                { role: "user", parts: [{ text: `System Instruction:\n${promptSistema}` }] },
                { role: "model", parts: [{ text: "Entendido! Seguirei essas instruções." }] },
                ...historicoConversa[jid].slice(0, -1)
            ];

            let resposta = "";
            const lastUserMessage = historicoConversa[jid][historicoConversa[jid].length - 1];

            if (isAudio) {
                const promptCompleto = [...chatHistory, lastUserMessage];
                const result = await model.generateContent({ contents: promptCompleto });
                resposta = result.response.text().trim();
            } else {
                const chat = model.startChat({ history: chatHistory });
                const result = await chat.sendMessage(input);
                resposta = result.response.text().trim();
            }

            historicoConversa[jid].push({ role: "model", parts: [{ text: resposta }] });
            if (historicoConversa[jid].length > MAX_HISTORICO_POR_USUARIO) {
                historicoConversa[jid] = historicoConversa[jid].slice(-MAX_HISTORICO_POR_USUARIO);
            }
            return resposta;

        } catch (err) {
            const errorMessage = err.toString();
            if (errorMessage.includes('429') || errorMessage.toLowerCase().includes('quota') || errorMessage.includes('403')) {
                switchToNextApiKey();
            } else {
                console.error(`[ERRO GEMINI] ${jid}:`, err?.message || err);
                historicoConversa[jid].pop();
                return "";
            }
        }
    }
    historicoConversa[jid].pop();
    return "Estou sobrecarregado no momento, tente novamente em alguns segundos.";
}

async function ligarBot() {
    console.log(`🚀 Bot iniciado → ${nomeSessao}`);
    const authPath = `./auth_sessions/auth_${nomeSessao}`;
    const { state, saveCreds } = await useMultiFileAuthState(authPath);
    const { version } = await fetchLatestBaileysVersion();

    const sock = makeWASocket({
        version, 
        logger, 
        printQRInTerminal: false, 
        auth: state,
        syncFullHistory: false, 
        markOnlineOnConnect: true,
        generateHighQualityLinkPreview: true,
        browser: ["Ubuntu", "Chrome", "20.0.04"], 
        getMessage: async () => ({ conversation: 'hello' })
    });

    if (phoneNumberArg && !sock.authState.creds.me) {
        console.log(`[${nomeSessao}] Solicitando código de pareamento para: ${phoneNumberArg}`);
        setTimeout(async () => {
            try {
                const code = await sock.requestPairingCode(phoneNumberArg);
                console.log(`PAIRING_CODE:${code}`);
            } catch (err) {
                console.error('Erro ao solicitar pairing code:', err);
            }
        }, 3000);
    }

    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect, qr } = update;

        if (qr && !phoneNumberArg) {
            console.log(`QR_CODE:${qr}`);
        }

        if (connection === 'close') {
            const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
            const statusCode = lastDisconnect?.error?.output?.statusCode;

            if (statusCode === DisconnectReason.loggedOut || statusCode === 401) {
                console.log(`[${nomeSessao}] Sessão desconectada. Aguardando painel recriar.`);
                if (fs.existsSync(authPath)) {
                    try { fs.rmSync(authPath, { recursive: true, force: true }); } catch (e) { }
                }
                process.exit(0);
            } else if (shouldReconnect) {
                console.log(`[${nomeSessao}] Reconectando em 5s...`);
                setTimeout(ligarBot, 5000);
            } else {
                console.log(`[${nomeSessao}] Conexão encerrada.`);
                process.exit();
            }
        }

        if (connection === 'open') {
            console.log(`✅ ${nomeSessao.toUpperCase()} ONLINE!`);
        }
    });

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('messages.upsert', async ({ messages, type }) => {
        if (type !== 'notify') return;
        const msg = messages[0];
        if (!msg.message || msg.key.fromMe) return;
        if (msg.key.remoteJid === 'status@broadcast') return;

        const jid = msg.key.remoteJid;
        const pushName = msg.pushName || '';
        const senderNumber = jid.split('@')[0];

        let isIgnored = false;
        for (const identifier of ignoredIdentifiers) {
            if (identifier.type === 'name') {
                if (pushName && pushName.toLowerCase() === identifier.value.toLowerCase()) {
                    isIgnored = true;
                    break;
                }
            } else if (identifier.type === 'number') {
                if (senderNumber.endsWith(identifier.value)) {
                    isIgnored = true;
                    break;
                }
            }
        }

        if (isIgnored) {
            console.log(`[${nomeSessao}] Mensagem de ${pushName || senderNumber} ignorada.`);
            return;
        }

        let texto = '';
        let isAudio = false;
        let audioBase64 = null;

        if (msg.message.audioMessage) {
            try {
                const buffer = await downloadMediaMessage(msg, 'buffer', {}, { logger, reuploadRequest: sock.updateMediaMessage });
                audioBase64 = buffer.toString('base64');
                isAudio = true;
                texto = "[Áudio]";
            } catch (err) { return; }
        } else {
            texto = msg.message.conversation || msg.message.extendedTextMessage?.text || msg.message.imageMessage?.caption || msg.message.videoMessage?.caption || '';
        }

        if (!texto.trim()) return;

        console.log(`[${nomeSessao}] ${pushName || senderNumber} diz: ${texto.substring(0, 20)}...`);

        await sock.sendPresenceUpdate('composing', jid);
        await delay(1000 + Math.random() * 2000);
        const resposta = await processarComGemini(jid, isAudio ? audioBase64 : texto, isAudio);

        if (resposta && resposta.trim()) {
            await sock.sendMessage(jid, { text: resposta });
        }

        await sock.sendPresenceUpdate('available', jid);
    });
}

ligarBot().catch(err => { console.error("Erro fatal:", err); process.exit(1); });
