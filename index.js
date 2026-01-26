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

// --- CONFIGURAÇÃO DE ARGUMENTOS ---
const nomeSessao = process.argv[2];
const promptSistema = process.argv[3];
const ignoredIdentifiersArg = process.argv[4] || '[]';
let phoneNumberArg = (process.argv[5] && process.argv[5] !== 'null') ? process.argv[5] : null;
const authorizedGroupsArg = process.argv[6] || '[]';
const botType = process.argv[7] || 'individual'; // 'individual' ou 'group'

// Limpeza do número de telefone
if (phoneNumberArg) {
    phoneNumberArg = phoneNumberArg.replace(/[^0-9]/g, '');
}

const modeloGemini = 'gemini-flash-latest';
const socket = io('http://localhost:3000'); // Ajuste a porta se necessário

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

// --- PARSING DE LISTAS ---
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

// --- CONFIGURAÇÃO GEMINI ---
const API_KEYS_STRING = process.env.API_KEYS_GEMINI;
if (!API_KEYS_STRING || !API_KEYS_STRING.trim()) {
    console.error('❌ ERRO: Nenhuma chave API do Gemini foi fornecida no .env');
    process.exit(1);
}

const API_KEYS = API_KEYS_STRING.split('\n').map(key => key.trim()).filter(Boolean);
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

// --- PROCESSAMENTO IA ---
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
    return "Estou processando muitas mensagens no momento.";
}

// --- INICIALIZAÇÃO DO BOT ---
async function ligarBot() {
    console.log(`🚀 Bot iniciado → ${nomeSessao} (Tipo: ${botType})`);
    const authPath = `./auth_sessions/auth_${nomeSessao}`;
    const { state, saveCreds } = await useMultiFileAuthState(authPath);
    const { version } = await fetchLatestBaileysVersion();

    const sock = makeWASocket({
        version,
        logger,
        printQRInTerminal: !phoneNumberArg, 
        auth: {
            creds: state.creds,
            keys: makeCacheableSignalKeyStore(state.keys, logger),
        },
        syncFullHistory: false,
        markOnlineOnConnect: true,
        generateHighQualityLinkPreview: true,
        browser: ["ZappBot", "Chrome", "1.0.0"], 
        getMessage: async () => ({ conversation: 'hello' })
    });

    // --- OUVINTE DE RESULTADO DE ATIVAÇÃO (NOVO) ---
    // Remove qualquer ouvinte anterior para evitar duplicidade
    socket.off('group-activation-result');
    
    socket.on('group-activation-result', async (data) => {
        // Verifica se a resposta é para este bot e se tem ID do grupo
        if (data.botSessionName === nomeSessao && data.groupId) {
            
            if (data.success) {
                console.log(`[${nomeSessao}] ✅ Ativação confirmada para o grupo ${data.groupId}`);
                
                // 1. Atualiza a memória local do bot para ele começar a responder imediatamente
                authorizedGroups[data.groupId] = new Date(data.expiresAt);

                // 2. Envia a mensagem de confirmação
                await sock.sendMessage(data.groupId, { text: '✅ Grupo ativado com sucesso!' });
                
                // 3. Pequeno delay e envia a mensagem de boas-vindas
                await delay(1500);
                await sock.sendMessage(data.groupId, { text: 'Olá, obrigado por me adicionar ao grupo! Espero ser muito útil!' });

            } else {
                // Caso o servidor recuse (token inválido, etc)
                console.log(`[${nomeSessao}] ❌ Falha na ativação: ${data.message}`);
                await sock.sendMessage(data.groupId, { text: `❌ Não foi possível ativar: ${data.message}` });
            }
        }
    });

    // Pareamento por Código
    if (phoneNumberArg && !sock.authState.creds.me && !sock.authState.creds.registered) {
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

        // --- TRATAMENTO DE TEXTO E MÍDIA ---
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

        // --- DETECÇÃO DE LINK DE ATIVAÇÃO ---
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
                                console.log(`[${nomeSessao}] Link de ativação detectado.`);
                                
                                // Envia solicitação ao servidor
                                socket.emit('group-activation-request', {
                                    groupId: jid,
                                    groupName: groupMetadata.subject,
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
                console.error(`[${nomeSessao}] Erro link ativação:`, e);
            }
        }

        // --- VALIDAÇÃO DE TIPO DE BOT (INDIVIDUAL VS GRUPO) ---
        if (botType === 'group') {
            if (!isGroup) return; 
            if (!authorizedGroups[jid]) return; 

            const expiresAt = authorizedGroups[jid];
            if (expiresAt && new Date() > expiresAt) {
                return;
            }
        } else {
            if (isGroup) return; 
        }

        // --- CORREÇÃO DA LÓGICA DE PAUSA/INTERVENÇÃO ---
        if (msg.key.fromMe) {
            // Se for bot INDIVIDUAL, pausamos na intervenção
            if (botType !== 'group') {
                console.log(`[${nomeSessao}] 🛑 Intervenção humana detectada. Pausando ${jid} por 5 min.`);
                pausados[jid] = Date.now() + TEMPO_PAUSA_MS;
            }
            // Se for bot de GRUPO, apenas ignoramos para não responder a si mesmo
            return;
        }

        if (pausados[jid] && Date.now() < pausados[jid]) {
            console.log(`[${nomeSessao}] ⏸️ Bot em pausa para ${jid} (Intervenção Humana).`);
            return;
        }

        // --- VERIFICAÇÃO DE IGNORE LIST ---
        const pushName = msg.pushName || '';
        const senderNumber = (msg.key.participant || msg.key.remoteJid).split('@')[0];

        let isIgnored = false;
        for (const identifier of ignoredIdentifiers) {
            if (identifier.type === 'name' && pushName && pushName.toLowerCase() === identifier.value.toLowerCase()) {
                isIgnored = true; break;
            } else if (identifier.type === 'number' && senderNumber.endsWith(identifier.value)) {
                isIgnored = true; break;
            }
        }

        if (isIgnored) {
            console.log(`[${nomeSessao}] Ignorado: ${pushName || senderNumber}`);
            return;
        }

        console.log(`[${nomeSessao}] MSG de ${pushName || senderNumber}: ${isAudio ? '[Áudio]' : texto.substring(0, 30)}...`);

        // --- ENVIO DA RESPOSTA ---
        // --- ENVIO DA RESPOSTA ---
        try {
            // 1. Marca a mensagem como lida (para forçar a atualização de status no WhatsApp)
            await sock.readMessages([msg.key]);

            // 2. Sempre mostra "Digitando...", pois a resposta será texto
            await sock.sendPresenceUpdate('composing', jid);

            // 3. Delay para simular o tempo de digitação humana
            await delay(3000 + Math.random() * 3000);

            const resposta = await processarComGemini(jid, isAudio ? audioBase64 : texto, isAudio);

            if (resposta && resposta.trim()) {
                await sock.sendMessage(jid, { text: resposta }, { quoted: msg });
            }
        } catch (error) {
            console.error(`[${nomeSessao}] Erro ao enviar mensagem:`, error);
        } finally {
            // 4. Para de digitar
            await sock.sendPresenceUpdate('available', jid);
        }
    });
}

ligarBot().catch(err => { console.error("Erro fatal:", err); process.exit(1); });

