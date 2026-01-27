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
const botType = process.argv[7] || 'individual'; 

if (phoneNumberArg) {
    phoneNumberArg = phoneNumberArg.replace(/[^0-9]/g, '');
}

const modeloGemini = 'gemini-flash-latest';
const socket = io('http://localhost:3000');

socket.on('connect', () => {
    console.log(`[${nomeSessao}] Conectado ao servidor via Socket.IO.`);
});
socket.on('disconnect', () => {
    console.log(`[${nomeSessao}] Desconectado do servidor.`);
});

const TEMPO_PAUSA_MS = 5 * 60 * 1000;
const pausados = {};

// --- PARSING DE LISTAS E CONFIGS ---
let ignoredIdentifiers = [];
try { ignoredIdentifiers = JSON.parse(ignoredIdentifiersArg); } catch (e) {}

let authorizedGroups = {};
try {
    const groupsArray = JSON.parse(authorizedGroupsArg);
    groupsArray.forEach(group => {
        authorizedGroups[group.groupId] = {
            expiresAt: group.expiresAt ? new Date(group.expiresAt) : null,
            antiLink: group.antiLink === true // Carrega a config de Anti-Link
        };
    });
    if (botType === 'group') {
        console.log(`[${nomeSessao}] Modo Grupo Ativo. Grupos: ${groupsArray.length}`);
    }
} catch (e) {
    console.error('❌ Erro ao ler grupos:', e);
}

// --- GEMINI SETUP ---
const API_KEYS_STRING = process.env.API_KEYS_GEMINI;
if (!API_KEYS_STRING) process.exit(1);
const API_KEYS = API_KEYS_STRING.split('\n').map(k => k.trim()).filter(Boolean);
let currentApiKeyIndex = 0;
let genAI = new GoogleGenerativeAI(API_KEYS[currentApiKeyIndex]);
let model = genAI.getGenerativeModel({ model: modeloGemini });

const logger = pino({ level: 'silent' });
const historicoConversa = {};
const MAX_HISTORICO_POR_USUARIO = 20;

function switchToNextApiKey() {
    currentApiKeyIndex = (currentApiKeyIndex + 1) % API_KEYS.length;
    genAI = new GoogleGenerativeAI(API_KEYS[currentApiKeyIndex]);
    model = genAI.getGenerativeModel({ model: modeloGemini });
}

// --- PROCESSAMENTO IA ---
async function processarComGemini(jid, input, isAudio = false) {
    for (let attempt = 0; attempt < API_KEYS.length; attempt++) {
        try {
            if (!historicoConversa[jid]) historicoConversa[jid] = [];
            const chatHistory = [
                { role: "user", parts: [{ text: `System Instruction:\n${promptSistema}` }] },
                { role: "model", parts: [{ text: "Entendido." }] },
                ...historicoConversa[jid]
            ];

            let resposta = "";
            if (isAudio) {
                const parts = [{ inlineData: { mimeType: "audio/ogg", data: input } }, { text: "Responda a este áudio." }];
                const result = await model.generateContent({
                    contents: [{ role: "user", parts: [{ text: `System: ${promptSistema}` }] }, { role: "user", parts: parts }]
                });
                resposta = result.response.text().trim();
                historicoConversa[jid].push({ role: "user", parts: [{ text: "[Áudio]" }] });
            } else {
                const chat = model.startChat({ history: chatHistory });
                const result = await chat.sendMessage(input);
                resposta = result.response.text().trim();
                historicoConversa[jid].push({ role: "user", parts: [{ text: input }] });
            }

            historicoConversa[jid].push({ role: "model", parts: [{ text: resposta }] });
            if (historicoConversa[jid].length > MAX_HISTORICO_POR_USUARIO) historicoConversa[jid] = historicoConversa[jid].slice(-MAX_HISTORICO_POR_USUARIO);
            return resposta;

        } catch (err) {
            if (err.toString().includes('429')) switchToNextApiKey();
            else return "";
        }
    }
    return "Estou sobrecarregado.";
}

// --- FUNÇÕES DE ADMINISTRAÇÃO ---
async function isGroupAdmin(sock, jid, participant) {
    try {
        const metadata = await sock.groupMetadata(jid);
        const admin = metadata.participants.find(p => p.id === participant && (p.admin === 'admin' || p.admin === 'superadmin'));
        return !!admin;
    } catch { return false; }
}

async function isBotAdmin(sock, jid) {
    try {
        const myself = sock.user.id.split(':')[0] + '@s.whatsapp.net';
        return await isGroupAdmin(sock, jid, myself);
    } catch { return false; }
}

async function ligarBot() {
    console.log(`🚀 Iniciando ${nomeSessao}...`);
    const authPath = `./auth_sessions/auth_${nomeSessao}`;
    const { state, saveCreds } = await useMultiFileAuthState(authPath);
    const { version } = await fetchLatestBaileysVersion();

    const sock = makeWASocket({
        version, logger, printQRInTerminal: !phoneNumberArg,
        auth: { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, logger) },
        syncFullHistory: false, markOnlineOnConnect: true,
        generateHighQualityLinkPreview: true, browser: ["ZappBot", "Chrome", "1.0.0"]
    });

    socket.on('group-activation-result', async (data) => {
        if (data.botSessionName === nomeSessao && data.groupId) {
            if (data.success) {
                authorizedGroups[data.groupId] = { expiresAt: new Date(data.expiresAt), antiLink: false };
                await sock.sendMessage(data.groupId, { text: '✅ Grupo ativado e pronto para uso!' });
            } else {
                await sock.sendMessage(data.groupId, { text: `❌ Falha: ${data.message}` });
            }
        }
    });

    if (phoneNumberArg && !sock.authState.creds.me && !sock.authState.creds.registered) {
        setTimeout(async () => {
            try { console.log(`PAIRING_CODE:${await sock.requestPairingCode(phoneNumberArg)}`); } catch {}
        }, 3000);
    }

    sock.ev.on('connection.update', (update) => {
        const { connection, lastDisconnect, qr } = update;
        if (qr && !phoneNumberArg) console.log(`QR_CODE:${qr}`);
        if (connection === 'close') {
            const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
            if (shouldReconnect) setTimeout(ligarBot, 5000);
            else process.exit(0);
        }
        if (connection === 'open') console.log('ONLINE!');
    });

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('messages.upsert', async ({ messages, type }) => {
        if (type !== 'notify') return;
        const msg = messages[0];
        if (!msg.message || msg.key.remoteJid === 'status@broadcast') return;

        const jid = msg.key.remoteJid;
        const isGroup = jid.endsWith('@g.us');
        const sender = msg.key.participant || jid;

        // Validação de Grupo e Validade
        if (botType === 'group') {
            if (!isGroup || !authorizedGroups[jid]) return;
            if (authorizedGroups[jid].expiresAt && new Date() > authorizedGroups[jid].expiresAt) return;
        } else if (isGroup) return;

        // Parsing de Texto
        let texto = msg.message.conversation || msg.message.extendedTextMessage?.text || 
                    msg.message.imageMessage?.caption || msg.message.videoMessage?.caption || '';
        let isAudio = !!msg.message.audioMessage;
        
        // Link de Ativação
        if (isGroup && texto.includes('zappbot.shop/ativar?token=')) {
            const token = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
            if (token) {
                const meta = await sock.groupMetadata(jid);
                socket.emit('group-activation-request', { groupId: jid, groupName: meta.subject, activationToken: token, botSessionName: nomeSessao });
                return;
            }
        }

        // --- SISTEMA DE ADMINISTRAÇÃO E ANTILINK ---
        if (isGroup && botType === 'group') {
            
            // 1. Anti-Link
            if (authorizedGroups[jid].antiLink) {
                const linkRegex = /(https?:\/\/[^\s]+)|(www\.[^\s]+)|(wa\.me\/[^\s]+)/gi;
                if (linkRegex.test(texto)) {
                    const botIsAdm = await isBotAdmin(sock, jid);
                    const senderIsAdm = await isGroupAdmin(sock, jid, sender);

                    if (botIsAdm && !senderIsAdm) {
                        // Apagar mensagem
                        await sock.sendMessage(jid, { delete: msg.key });
                        // Banir usuário (opcional, aqui só remove)
                        await sock.groupParticipantsUpdate(jid, [sender], 'remove');
                        await sock.sendMessage(jid, { text: '🚫 *Anti-Link:* Links não são permitidos aqui.' });
                        return; // Para processamento aqui
                    }
                }
            }

            // 2. Comandos de Administração (!comando)
            if (texto.startsWith('!') || texto.startsWith('/') || texto.startsWith('.')) {
                const args = texto.slice(1).trim().split(/ +/);
                const comando = args.shift().toLowerCase();
                const senderIsAdm = await isGroupAdmin(sock, jid, sender);
                const botIsAdm = await isBotAdmin(sock, jid);

                // Comandos que exigem que quem mandou seja ADM
                if (senderIsAdm) {
                    let targetUser = msg.message.extendedTextMessage?.contextInfo?.participant || 
                                     (args[0] ? args[0].replace('@', '').replace(/[^0-9]/g, '') + '@s.whatsapp.net' : null);

                    switch (comando) {
                        case 'ban':
                        case 'banir':
                        case 'kick':
                            if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM para banir.' }, { quoted: msg });
                            if (!targetUser) return sock.sendMessage(jid, { text: '❌ Marque alguém ou responda a mensagem.' }, { quoted: msg });
                            await sock.groupParticipantsUpdate(jid, [targetUser], 'remove');
                            await sock.sendMessage(jid, { text: '✅ Usuário removido.' });
                            return;

                        case 'promover':
                        case 'admin':
                            if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                            if (!targetUser) return sock.sendMessage(jid, { text: '❌ Marque alguém.' }, { quoted: msg });
                            await sock.groupParticipantsUpdate(jid, [targetUser], 'promote');
                            await sock.sendMessage(jid, { text: '✅ Usuário promovido a ADM.' });
                            return;

                        case 'rebaixar':
                            if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                            if (!targetUser) return sock.sendMessage(jid, { text: '❌ Marque alguém.' }, { quoted: msg });
                            await sock.groupParticipantsUpdate(jid, [targetUser], 'demote');
                            await sock.sendMessage(jid, { text: '✅ ADM removido.' });
                            return;

                        case 'fechar':
                            if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                            await sock.groupSettingUpdate(jid, 'announcement');
                            await sock.sendMessage(jid, { text: '🔒 Grupo fechado para administradores.' });
                            return;

                        case 'abrir':
                            if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                            await sock.groupSettingUpdate(jid, 'not_announcement');
                            await sock.sendMessage(jid, { text: '🔓 Grupo aberto para todos.' });
                            return;
                        
                        case 'todos':
                        case 'everyone':
                            if (!botIsAdm) return; // Evita spam se bot não for adm
                            const groupMeta = await sock.groupMetadata(jid);
                            const mentions = groupMeta.participants.map(p => p.id);
                            await sock.sendMessage(jid, { text: '📢 *Atenção todos!*', mentions: mentions });
                            return;

                        case 'antilink':
                            if (!args[0]) return sock.sendMessage(jid, { text: 'Use: !antilink on ou !antilink off' });
                            const novoEstado = args[0].toLowerCase() === 'on';
                            authorizedGroups[jid].antiLink = novoEstado;
                            
                            // Envia para o servidor salvar no JSON
                            socket.emit('update-group-settings', { 
                                groupId: jid, 
                                settings: { antiLink: novoEstado } 
                            });

                            await sock.sendMessage(jid, { text: `🛡️ Anti-Link agora está: *${novoEstado ? 'LIGADO' : 'DESLIGADO'}*` });
                            return;
                    }
                }
            }
        }

        // --- LÓGICA DE IA (Gemini) ---
        // Se chegou aqui, não é link proibido nem comando administrativo
        if (msg.key.fromMe) return; 

        // Pausa manual
        if (pausados[jid] && Date.now() < pausados[jid]) return;

        // Ignore List
        if (ignoredIdentifiers.some(i => (i.type === 'number' && sender.includes(i.value)) || (i.type === 'name' && msg.pushName?.toLowerCase() === i.value.toLowerCase()))) return;

        try {
            await sock.readMessages([msg.key]);
            await sock.sendPresenceUpdate('composing', jid);
            await delay(2000);
            
            let audioBuffer = null;
            if (isAudio) audioBuffer = (await downloadMediaMessage(msg, 'buffer', {}, { logger, reuploadRequest: sock.updateMediaMessage })).toString('base64');

            const resposta = await processarComGemini(jid, isAudio ? audioBuffer : texto, isAudio);
            if (resposta) await sock.sendMessage(jid, { text: resposta }, { quoted: msg });

        } catch (e) { console.error('Erro msg:', e); }
    });
}

ligarBot().catch(err => { console.error("Erro fatal:", err); process.exit(1); });
