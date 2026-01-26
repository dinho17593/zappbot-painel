const {
    default: makeWASocket,
    useMultiFileAuthState,
    DisconnectReason,
    fetchLatestBaileysVersion,
    delay,
    downloadMediaMessage,
    makeCacheableSignalKeyStore
} = require('@whiskeysockets/baileys');
const pino = require('pino');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const fs = require('fs');
const io = require('socket.io-client');

const nomeSessao = process.argv[2];
const promptSistema = process.argv[3];
const ignoredIdentifiersArg = process.argv[4] || '[]';
let phoneNumberArg = (process.argv[5] && process.argv[5] !== 'null') ? process.argv[5] : null;
const authorizedGroupsArg = process.argv[6] || '[]';
const botType = process.argv[7] || 'individual';

// Limpeza crítica do número de telefone para evitar erros do Baileys
if (phoneNumberArg) {
    phoneNumberArg = phoneNumberArg.replace(/[^0-9]/g, '');
}

const modeloGemini = 'gemini-flash-latest';

const socket = io('http://localhost:3000');

socket.on('connect', () => {
    console.log(`[${nomeSessao}] Conectado ao servidor principal via Socket.IO.`);
});
socket.on('disconnect', () => {
    console.log(`[${nomeSessao}] Desconectado do servidor principal.`);
});

const TEMPO_PAUSA_MS = 5 * 60 * 1000;
const pausados = {};

if (!nomeSessao || !promptSistema) {
    console.error('❌ Uso: node index.js "nome" "prompt" \'[ignored]\' [phone] \'[groups]\' [type]');
    process.exit(1);
}

let ignoredIdentifiers = [];
try {
    ignoredIdentifiers = JSON.parse(ignoredIdentifiersArg);
} catch (e) {
    console.error('❌ Erro ao interpretar a lista de ignorados:', e);
}

let authorizedGroups = {};
try {
    const groupsArray = JSON.parse(authorizedGroupsArg);
    groupsArray.forEach(group => {
        authorizedGroups[group.groupId] = group.expiresAt ? new Date(group.expiresAt) : null;
    });
    if (botType === 'group') {
        console.log(`[${nomeSessao}] Modo Grupo Ativo. Grupos autorizados: ${groupsArray.length}`);
    }
} catch (e) {
    console.error('❌ Erro ao interpretar a lista de grupos autorizados:', e);
}

const API_KEYS_STRING = process.env.API_KEYS_GEMINI;
if (!API_KEYS_STRING || !API_KEYS_STRING.trim()) {
    console.error('❌ ERRO: Nenhuma chave API do Gemini foi fornecida no .env');
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
    console.warn(`[API Switch] Trocando para chave #${currentApiKeyIndex + 1}.`);
    genAI = new GoogleGenerativeAI(newKey);
    model = genAI.getGenerativeModel({ model: modeloGemini });
}

async function processarComGemini(jid, input, isAudio = false) {
    for (let attempt = 0; attempt < API_KEYS.length; attempt++) {
        try {
            if (!historicoConversa[jid]) { historicoConversa[jid] = []; }

            const chatHistory = [
                { role: "user", parts: [{ text: `System Instruction:\n${promptSistema}` }] },
                { role: "model", parts: [{ text: "Entendido! Seguirei essas instruções." }] },
                ...historicoConversa[jid]
            ];

            let resposta = "";

            if (isAudio) {
                const parts = [
                    { inlineData: { mimeType: "audio/ogg", data: input } },
                    { text: "Responda a este áudio seguindo as instruções do sistema." }
                ];
                
                const result = await model.generateContent({
                    contents: [
                        { role: "user", parts: [{ text: `System: ${promptSistema}` }] },
                        { role: "user", parts: parts }
                    ]
                });
                resposta = result.response.text().trim();
                historicoConversa[jid].push({ role: "user", parts: [{ text: "[Áudio enviado pelo usuário]" }] });

            } else {
                const chat = model.startChat({ history: chatHistory });
                const result = await chat.sendMessage(input);
                resposta = result.response.text().trim();
                historicoConversa[jid].push({ role: "user", parts: [{ text: input }] });
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
                return "";
            }
        }
    }
    return "Estou sobrecarregado no momento, tente novamente em alguns segundos.";
}

async function ligarBot() {
    console.log(`🚀 Bot iniciado → ${nomeSessao} (Tipo: ${botType})`);
    const authPath = `./auth_sessions/auth_${nomeSessao}`;
    const { state, saveCreds } = await useMultiFileAuthState(authPath);
    const { version } = await fetchLatestBaileysVersion();

    const sock = makeWASocket({
        version,
        logger,
        auth: {
            creds: state.creds,
            keys: makeCacheableSignalKeyStore(state.keys, logger),
        },
        syncFullHistory: false,
        markOnlineOnConnect: true,
        generateHighQualityLinkPreview: true,
        browser: ["Ubuntu", "Chrome", "20.0.04"], 
        getMessage: async () => ({ conversation: 'hello' })
    });

    // Lógica de Pareamento por Código
    if (phoneNumberArg && !sock.authState.creds.me && !sock.authState.creds.registered) {
        console.log(`[${nomeSessao}] Solicitando código de pareamento para: ${phoneNumberArg}`);
        
        setTimeout(async () => {
            try {
                const code = await sock.requestPairingCode(phoneNumberArg);
                console.log(`PAIRING_CODE:${code}`);
            } catch (err) {
                console.error('Erro ao solicitar pairing code:', err);
                console.log(`ERRO: Verifique se o número ${phoneNumberArg} está correto.`);
            }
        }, 3000);
    }

    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect, qr } = update;

        if (qr) {
            console.log(`QR_CODE:${qr}`);
        }

        if (connection === 'close') {
            const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
            const statusCode = lastDisconnect?.error?.output?.statusCode;

            if (statusCode === DisconnectReason.loggedOut || statusCode === 401) {
                console.log(`[${nomeSessao}] Sessão desconectada (Logout).`);
                if (fs.existsSync(authPath)) {
                    try { fs.rmSync(authPath, { recursive: true, force: true }); } catch (e) { }
                }
                process.exit(0);
            } else if (shouldReconnect) {
                console.log(`[${nomeSessao}] Conexão caiu. Reconectando em 5s...`);
                setTimeout(ligarBot, 5000);
            } else {
                console.log(`[${nomeSessao}] Conexão encerrada.`);
                process.exit(0);
            }
        }

        if (connection === 'open') {
            console.log(`✅ ${nomeSessao.toUpperCase()} ONLINE!`);
            console.log('ONLINE!');
        }
    });

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('messages.upsert', async ({ messages, type }) => {
        if (type !== 'notify') return;
        const msg = messages[0];

        if (!msg.message) return;
        if (msg.key.remoteJid === 'status@broadcast') return;

        const jid = msg.key.remoteJid;
        const isGroup = jid.endsWith('@g.us');

        let texto = msg.message.conversation || 
                    msg.message.extendedTextMessage?.text || 
                    msg.message.imageMessage?.caption || 
                    msg.message.videoMessage?.caption || '';
        
        let isAudio = false;
        let audioBase64 = null;

        if (msg.message.audioMessage) {
            try {
                const buffer = await downloadMediaMessage(msg, 'buffer', {}, { logger, reuploadRequest: sock.updateMediaMessage });
                audioBase64 = buffer.toString('base64');
                isAudio = true;
                texto = "[Áudio]";
            } catch (err) { return; }
        }

        if (!texto.trim() && !isAudio) return;

        const activationLinkPattern = 'zappbot.shop/ativar?token=';
        if (isGroup && (texto.includes(activationLinkPattern) || (msg.message.extendedTextMessage?.text || '').includes(activationLinkPattern))) {
            try {
                const fullText = msg.message.extendedTextMessage?.text || texto;
                const urlRegex = /(https?:\/\/[^\s]+)/g;
                const foundUrls = fullText.match(urlRegex);

                if (foundUrls) {
                    for (const urlStr of foundUrls) {
                        if (urlStr.includes(activationLinkPattern)) {
                            const urlObj = new URL(urlStr);
                            const token = urlObj.searchParams.get('token');

                            if (token) {
                                const groupMetadata = await sock.groupMetadata(jid);
                                const groupName = groupMetadata.subject;

                                console.log(`[${nomeSessao}] Link de ativação detectado no grupo '${groupName}' (${jid}).`);

                                socket.emit('group-activation-request', {
                                    groupId: jid,
                                    groupName: groupName,
                                    activationToken: token,
                                    botSessionName: nomeSessao
                                });
                                
                                await sock.sendMessage(jid, { text: '🔄 Verificando ativação...' });
                                return; 
                            }
                        }
                    }
                }
            } catch (e) {
                console.error(`[${nomeSessao}] Erro ao processar link de ativação:`, e);
            }
        }

        if (botType === 'group') {
            if (!isGroup) return;
            if (!authorizedGroups[jid]) return;
            const expiresAt = authorizedGroups[jid];
            if (expiresAt && new Date() > expiresAt) return;
        } else {
            if (isGroup) return;
        }

        if (msg.key.fromMe) {
            console.log(`[${nomeSessao}] 🛑 Intervenção humana detectada. Pausando ${jid} por 5 min.`);
            pausados[jid] = Date.now() + TEMPO_PAUSA_MS;
            return;
        }
        if (pausados[jid] && Date.now() < pausados[jid]) {
            console.log(`[${nomeSessao}] ⏸️ Bot em pausa para ${jid} (Intervenção Humana).`);
            return;
        }

        const pushName = msg.pushName || '';
        const senderNumber = jid.split('@')[0];

        let isIgnored = false;
        for (const identifier of ignoredIdentifiers) {
            if (identifier.type === 'name' && pushName && pushName.toLowerCase() === identifier.value.toLowerCase()) {
                isIgnored = true;
                break;
            } else if (identifier.type === 'number' && senderNumber.endsWith(identifier.value)) {
                isIgnored = true;
                break;
            }
        }

        if (isIgnored) {
            console.log(`[${nomeSessao}] Mensagem de ${pushName || senderNumber} ignorada (Lista Negra).`);
            return;
        }

        console.log(`[${nomeSessao}] ${pushName || senderNumber} diz: ${isAudio ? '[Áudio]' : texto.substring(0, 20)}...`);

        await sock.sendPresenceUpdate('composing', jid);
        await delay(1000 + Math.random() * 1500);

        const resposta = await processarComGemini(jid, isAudio ? audioBase64 : texto, isAudio);

        if (resposta && resposta.trim()) {
            await sock.sendMessage(jid, { text: resposta });
        }

        await sock.sendPresenceUpdate('available', jid);
    });
}

ligarBot().catch(err => { console.error("Erro fatal:", err); process.exit(1); });
