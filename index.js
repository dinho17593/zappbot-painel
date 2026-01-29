const {
    default: makeWASocket,
    useMultiFileAuthState,
    DisconnectReason,
    fetchLatestBaileysVersion,
    delay,
    downloadMediaMessage,
    makeCacheableSignalKeyStore,
    jidNormalizedUser
} = require('@whiskeysockets/baileys');
const { Telegraf } = require('telegraf');
const pino = require('pino');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const fs = require('fs');
const io = require('socket.io-client');
const axios = require('axios');

// --- CONFIGURAÇÃO DE ARGUMENTOS ---
const nomeSessao = process.argv[2];
const promptSistemaGlobal = process.argv[3]; // Renomeado para Global
const ignoredIdentifiersArg = process.argv[4] || '[]';
let phoneNumberArg = (process.argv[5] && process.argv[5] !== 'null') ? process.argv[5] : null;
const authorizedGroupsArg = process.argv[6] || '[]';
const botType = process.argv[7] || 'individual'; 

// NOVOS ARGUMENTOS
const botNameGlobal = process.argv[8] || ''; // Renomeado para Global
const silenceTimeMinutesGlobal = parseInt(process.argv[9] || '0'); // Renomeado para Global
const platform = process.argv[10] || 'whatsapp';
const telegramToken = process.argv[11] || '';

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

// Listener para atualização em tempo real das configurações de grupo
socket.on('group-settings-changed', (data) => {
    if (data.botSessionName === nomeSessao && data.groupId) {
        console.log(`[${nomeSessao}] Atualizando configurações locais para o grupo ${data.groupId}`);
        authorizedGroups[data.groupId] = {
            ...authorizedGroups[data.groupId],
            ...data.settings,
            expiresAt: data.settings.expiresAt ? new Date(data.settings.expiresAt) : null
        };
    }
});

const TEMPO_PAUSA_MS = 5 * 60 * 1000;
const pausados = {};
const lastResponseTimes = {};

// --- PARSING DE LISTAS E CONFIGS ---
let ignoredIdentifiers = [];
try { ignoredIdentifiers = JSON.parse(ignoredIdentifiersArg); } catch (e) {}

let authorizedGroups = {};
try {
    const groupsArray = JSON.parse(authorizedGroupsArg);
    groupsArray.forEach(group => {
        authorizedGroups[group.groupId] = {
            expiresAt: group.expiresAt ? new Date(group.expiresAt) : null,
            antiLink: group.antiLink === true,
            prompt: group.prompt || '',
            silenceTime: group.silenceTime !== undefined ? parseInt(group.silenceTime) : 0,
            botName: group.botName || '',
            isPaused: group.isPaused === true
        };
    });
    if (botType === 'group') {
        console.log(`[${nomeSessao}] Modo Grupo Ativo. Grupos Autorizados: ${groupsArray.length}`);
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
async function processarComGemini(jid, input, isAudio = false, promptEspecifico = null) {
    for (let attempt = 0; attempt < API_KEYS.length; attempt++) {
        try {
            if (!historicoConversa[jid]) historicoConversa[jid] = [];
            
            const promptFinal = promptEspecifico || promptSistemaGlobal;

            const chatHistory = [
                { role: "user", parts: [{ text: `System Instruction:\n${promptFinal}` }] },
                { role: "model", parts: [{ text: "Entendido." }] },
                ...historicoConversa[jid]
            ];

            let resposta = "";
            if (isAudio) {
                const parts = [{ inlineData: { mimeType: "audio/ogg", data: input } }, { text: "Responda a este áudio." }];
                const result = await model.generateContent({
                    contents: [{ role: "user", parts: [{ text: `System: ${promptFinal}` }] }, { role: "user", parts: parts }]
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

// --- FUNÇÕES DE ADMINISTRAÇÃO WHATSAPP ---

function areJidsSameUser(jid1, jid2) {
    if (!jid1 || !jid2) return false;
    const n1 = jidNormalizedUser(jid1);
    const n2 = jidNormalizedUser(jid2);
    if (n1 === n2) return true;
    const num1 = n1.split('@')[0].replace(/\D/g, '');
    const num2 = n2.split('@')[0].replace(/\D/g, '');
    if (num1 === num2) return true;
    if (num1.startsWith('55') && num2.startsWith('55')) {
        const body1 = num1.slice(2);
        const body2 = num2.slice(2);
        if (body1.slice(0, 2) === body2.slice(0, 2) && body1.slice(-8) === body2.slice(-8)) return true;
    }
    return false;
}

async function isGroupAdminWA(sock, jid, participant) {
    try {
        const metadata = await sock.groupMetadata(jid);
        const admin = metadata.participants.find(p => {
            return areJidsSameUser(p.id, participant) && (p.admin === 'admin' || p.admin === 'superadmin');
        });
        return !!admin;
    } catch (e) { return false; }
}

async function isBotAdminWA(sock, jid) {
    try {
        const me = sock.user || sock.authState.creds.me;
        if (!me) return false;

        const myJid = jidNormalizedUser(me.id);
        const myLid = me.lid ? jidNormalizedUser(me.lid) : null;
        const metadata = await sock.groupMetadata(jid);
        
        const amIAdmin = metadata.participants.find(p => {
            if (p.admin !== 'admin' && p.admin !== 'superadmin') return false;
            const pJid = jidNormalizedUser(p.id);
            if (pJid === myJid) return true;
            if (myLid && pJid === myLid) return true;
            if (areJidsSameUser(pJid, myJid)) return true;
            return false;
        });

        return !!amIAdmin;
    } catch (e) { return false; }
}

// --- INICIALIZAÇÃO DO BOT ---

if (platform === 'telegram') {
    // ==================================================================================
    // LÓGICA TELEGRAM
    // ==================================================================================
    if (!telegramToken) {
        console.error('❌ Token do Telegram não fornecido.');
        process.exit(1);
    }

    const bot = new Telegraf(telegramToken);

    (async () => {
        try {
            const commands = [
                { command: 'id', description: 'Mostrar ID do Chat' }
            ];

            if (botType === 'group') {
                commands.push(
                    { command: 'ban', description: 'Banir usuário (responda a msg)' },
                    { command: 'kick', description: 'Expulsar usuário' },
                    { command: 'mute', description: 'Mutar usuário' },
                    { command: 'unmute', description: 'Desmutar usuário' },
                    { command: 'promover', description: 'Promover a Admin' },
                    { command: 'rebaixar', description: 'Remover Admin' },
                    { command: 'antilink', description: 'Configurar Anti-Link (on/off)' },
                    { command: 'todos', description: 'Chamar todos os membros' }
                );
            }

            await bot.telegram.setMyCommands(commands);
            console.log(`[${nomeSessao}] Comandos do Telegram registrados.`);

            await bot.launch({ dropPendingUpdates: true });
            
            console.log('\nONLINE!'); 
            console.log(`[${nomeSessao}] Telegram Bot iniciado.`);
            
            socket.emit('bot-online', { sessionName: nomeSessao });

        } catch (err) {
            console.error('Erro ao iniciar Telegram:', err);
            process.exit(1);
        }
    })();

    socket.on('group-activation-result', async (data) => {
        if (data.botSessionName === nomeSessao && data.groupId) {
            if (data.success) {
                authorizedGroups[data.groupId] = { expiresAt: new Date(data.expiresAt), antiLink: false, prompt: '', silenceTime: 0, botName: '', isPaused: false };
                try {
                    await bot.telegram.sendMessage(data.groupId, '✅ Grupo ativado e pronto para uso!');
                } catch (e) { console.error('Erro ao enviar msg Telegram:', e); }
            } else {
                try {
                    await bot.telegram.sendMessage(data.groupId, `❌ Falha: ${data.message}`);
                } catch (e) {}
            }
        }
    });

    bot.command('id', (ctx) => {
        ctx.reply(`ID deste chat: \`${ctx.chat.id}\``, { parse_mode: 'Markdown' });
    });

    bot.on('message', async (ctx) => {
        const chat = ctx.chat;
        const chatId = chat.id.toString();
        const isGroup = chat.type === 'group' || chat.type === 'supergroup';
        const user = ctx.from;
        const userId = user.id.toString();
        
        let texto = ctx.message.text || ctx.message.caption || '';
        let isAudio = !!(ctx.message.voice || ctx.message.audio);

        if (isGroup && texto.includes('zappbot.shop/ativar?token=')) {
            console.log(`[${nomeSessao}] Link de ativação detectado no grupo ${chatId}`);
            const token = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
            if (token) {
                socket.emit('group-activation-request', { 
                    groupId: chatId, 
                    groupName: chat.title, 
                    activationToken: token, 
                    botSessionName: nomeSessao 
                });
                return; 
            }
        }

        let groupConfig = null;
        if (botType === 'group') {
            if (!isGroup || !authorizedGroups[chatId]) return;
            if (authorizedGroups[chatId].expiresAt && new Date() > authorizedGroups[chatId].expiresAt) return;
            groupConfig = authorizedGroups[chatId];
            if (groupConfig.isPaused) return; // Bot pausado neste grupo
        } else if (isGroup) {
            return;
        }

        if (isGroup && botType === 'group') {
            if (authorizedGroups[chatId].antiLink) {
                const linkRegex = /(https?:\/\/[^\s]+)|(www\.[^\s]+)|(t\.me\/[^\s]+)/gi;
                if (linkRegex.test(texto)) {
                    try {
                        const member = await ctx.getChatMember(userId);
                        const senderIsAdm = member.status === 'administrator' || member.status === 'creator';
                        
                        if (!senderIsAdm) {
                            await ctx.deleteMessage();
                            await ctx.kickChatMember(userId);
                            await ctx.reply('🚫 *Anti-Link:* Links não são permitidos aqui.', { parse_mode: 'Markdown' });
                            return;
                        }
                    } catch (e) { console.error('Erro antilink telegram:', e); }
                }
            }

            if (texto.startsWith('!') || texto.startsWith('/') || texto.startsWith('.')) {
                const args = texto.trim().split(/ +/);
                let rawCmd = args.shift().toLowerCase();
                
                if (rawCmd.startsWith('/') || rawCmd.startsWith('!') || rawCmd.startsWith('.')) {
                    rawCmd = rawCmd.substring(1);
                }
                
                const comando = rawCmd.split('@')[0];

                try {
                    const member = await ctx.getChatMember(userId);
                    const senderIsAdm = member.status === 'administrator' || member.status === 'creator';

                    if (senderIsAdm) {
                        const replyTo = ctx.message.reply_to_message;
                        const targetUser = replyTo ? replyTo.from : null;

                        switch (comando) {
                            case 'ban':
                            case 'banir':
                            case 'kick':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja banir.');
                                await ctx.kickChatMember(targetUser.id);
                                await ctx.reply('✅ Usuário removido.');
                                return;

                            case 'mute':
                            case 'mutar':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja mutar.');
                                await ctx.restrictChatMember(targetUser.id, { can_send_messages: false });
                                await ctx.reply('✅ Usuário mutado.');
                                return;

                            case 'unmute':
                            case 'desmutar':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja desmutar.');
                                await ctx.restrictChatMember(targetUser.id, { can_send_messages: true, can_send_media_messages: true, can_send_other_messages: true });
                                await ctx.reply('✅ Usuário desmutado.');
                                return;

                            case 'promover':
                            case 'admin':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja promover.');
                                await ctx.promoteChatMember(targetUser.id, { can_change_info: true, can_delete_messages: true, can_invite_users: true, can_restrict_members: true, can_pin_messages: true, can_promote_members: false });
                                await ctx.reply('✅ Usuário promovido a ADM.');
                                return;

                            case 'rebaixar':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja rebaixar.');
                                await ctx.promoteChatMember(targetUser.id, { can_change_info: false, can_delete_messages: false, can_invite_users: false, can_restrict_members: false, can_pin_messages: false, can_promote_members: false });
                                await ctx.reply('✅ ADM removido.');
                                return;
                            
                            case 'todos':
                            case 'everyone':
                                await ctx.reply('📢 *Atenção todos!*', { parse_mode: 'Markdown' });
                                return;

                            case 'antilink':
                                if (!args[0]) return ctx.reply('Use: /antilink on ou /antilink off');
                                const novoEstado = args[0].toLowerCase() === 'on';
                                authorizedGroups[chatId].antiLink = novoEstado;
                                
                                socket.emit('update-group-settings', { 
                                    groupId: chatId, 
                                    settings: { antiLink: novoEstado } 
                                });

                                await ctx.reply(`🛡️ Anti-Link agora está: *${novoEstado ? 'LIGADO' : 'DESLIGADO'}*`, { parse_mode: 'Markdown' });
                                return;
                        }
                    }
                } catch (e) { console.error('Erro comando telegram:', e); }
            }
        }

        if (user.is_bot) return;
        if (ignoredIdentifiers.some(i => (i.type === 'name' && (user.first_name + ' ' + (user.last_name || '')).toLowerCase() === i.value.toLowerCase()))) return;

        let shouldRespond = true;
        const isReplyToBot = ctx.message.reply_to_message && ctx.message.reply_to_message.from.id === ctx.botInfo.id;
        const isMentioned = texto.includes(`@${ctx.botInfo.username}`);
        
        // Determinar nome do bot (Grupo ou Global)
        const botName = (groupConfig && groupConfig.botName) ? groupConfig.botName : botNameGlobal;
        const isNameCalled = botName && texto.toLowerCase().includes(botName.toLowerCase());

        // Determinar tempo de silêncio (Grupo ou Global)
        const silenceTime = (groupConfig && groupConfig.silenceTime !== undefined) ? groupConfig.silenceTime : silenceTimeMinutesGlobal;

        if (silenceTime > 0) {
            const lastTime = lastResponseTimes[chatId] || 0;
            const timeDiffMinutes = (Date.now() - lastTime) / (1000 * 60);

            if (!isMentioned && !isReplyToBot && !isNameCalled) {
                if (timeDiffMinutes < silenceTime) {
                    shouldRespond = false;
                }
            }
        }

        if (!shouldRespond) return;

        try {
            await ctx.sendChatAction('typing');
            
            let audioBuffer = null;
            if (isAudio) {
                const fileId = ctx.message.voice ? ctx.message.voice.file_id : ctx.message.audio.file_id;
                const fileLink = await ctx.telegram.getFileLink(fileId);
                const response = await axios.get(fileLink.href, { responseType: 'arraybuffer' });
                audioBuffer = Buffer.from(response.data).toString('base64');
            }

            // Usar prompt do grupo se existir, senão global
            const promptToUse = (groupConfig && groupConfig.prompt) ? groupConfig.prompt : promptSistemaGlobal;

            const resposta = await processarComGemini(chatId, isAudio ? audioBuffer : texto, isAudio, promptToUse);
            if (resposta) {
                await ctx.reply(resposta, { reply_to_message_id: ctx.message.message_id });
                lastResponseTimes[chatId] = Date.now();
            }

        } catch (e) { console.error('Erro msg Telegram:', e); }
    });

    process.once('SIGINT', () => { bot.stop('SIGINT'); process.exit(0); });
    process.once('SIGTERM', () => { bot.stop('SIGTERM'); process.exit(0); });

} else {
    // ==================================================================================
    // LÓGICA WHATSAPP (BAILEYS)
    // ==================================================================================
    async function ligarBot() {
        console.log(`🚀 Iniciando ${nomeSessao} (WhatsApp)...`);
        const authPath = `./auth_sessions/auth_${nomeSessao}`;
        const { state, saveCreds } = await useMultiFileAuthState(authPath);
        const { version } = await fetchLatestBaileysVersion();

        const sock = makeWASocket({
            version, 
            logger, 
            printQRInTerminal: !phoneNumberArg,
            auth: { creds: state.creds, keys: makeCacheableSignalKeyStore(state.keys, logger) },
            syncFullHistory: false, 
            markOnlineOnConnect: true,
            generateHighQualityLinkPreview: true, 
            browser: ["Ubuntu", "Chrome", "20.0.04"]
        });

        socket.off('group-activation-result');
        
        socket.on('group-activation-result', async (data) => {
            if (data.botSessionName === nomeSessao && data.groupId) {
                if (data.success) {
                    authorizedGroups[data.groupId] = { expiresAt: new Date(data.expiresAt), antiLink: false, prompt: '', silenceTime: 0, botName: '', isPaused: false };
                    await sock.sendMessage(data.groupId, { text: '✅ Grupo ativado e pronto para uso!' });
                } else {
                    await sock.sendMessage(data.groupId, { text: `❌ Falha: ${data.message}` });
                }
            }
        });

        if (phoneNumberArg && !sock.authState.creds.registered) {
            console.log(`[${nomeSessao}] Aguardando socket estabilizar para solicitar código...`);
            setTimeout(async () => {
                try {
                    console.log(`[${nomeSessao}] Solicitando código para: ${phoneNumberArg}`);
                    const code = await sock.requestPairingCode(phoneNumberArg);
                    console.log(`PAIRING_CODE:${code}`);
                } catch (err) {
                    console.error(`[${nomeSessao}] Erro ao solicitar código:`, err);
                }
            }, 4000);
        }

        sock.ev.on('connection.update', (update) => {
            const { connection, lastDisconnect, qr } = update;
            if (qr && !phoneNumberArg) console.log(`QR_CODE:${qr}`);
            
            if (connection === 'close') {
                const shouldReconnect = lastDisconnect?.error?.output?.statusCode !== DisconnectReason.loggedOut;
                if (shouldReconnect) setTimeout(ligarBot, 5000);
                else process.exit(0);
            }
            if (connection === 'open') {
                console.log('\nONLINE!'); 
                socket.emit('bot-online', { sessionName: nomeSessao });
            }
        });

        sock.ev.on('creds.update', saveCreds);

        sock.ev.on('messages.upsert', async ({ messages, type }) => {
            if (type !== 'notify') return;
            const msg = messages[0];
            if (!msg.message || msg.key.remoteJid === 'status@broadcast') return;

            const jid = msg.key.remoteJid;
            const isGroup = jid.endsWith('@g.us');
            const sender = msg.key.participant || jid;

            let texto = msg.message.conversation || msg.message.extendedTextMessage?.text || 
                        msg.message.imageMessage?.caption || msg.message.videoMessage?.caption || '';
            let isAudio = !!msg.message.audioMessage;

            if (isGroup && texto.includes('zappbot.shop/ativar?token=')) {
                console.log(`[${nomeSessao}] Link de ativação detectado no grupo ${jid}`);
                const token = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
                if (token) {
                    const meta = await sock.groupMetadata(jid);
                    socket.emit('group-activation-request', { 
                        groupId: jid, 
                        groupName: meta.subject, 
                        activationToken: token, 
                        botSessionName: nomeSessao 
                    });
                    return; 
                }
            }

            let groupConfig = null;
            if (botType === 'group') {
                if (!isGroup || !authorizedGroups[jid]) return;
                if (authorizedGroups[jid].expiresAt && new Date() > authorizedGroups[jid].expiresAt) return;
                groupConfig = authorizedGroups[jid];
                if (groupConfig.isPaused) return; // Bot pausado neste grupo
            } else if (isGroup) {
                return;
            }

            if (isGroup && botType === 'group') {
                
                if (authorizedGroups[jid].antiLink) {
                    const linkRegex = /(https?:\/\/[^\s]+)|(www\.[^\s]+)|(wa\.me\/[^\s]+)/gi;
                    if (linkRegex.test(texto)) {
                        const botIsAdm = await isBotAdminWA(sock, jid);
                        const senderIsAdm = await isGroupAdminWA(sock, jid, sender);

                        if (botIsAdm && !senderIsAdm) {
                            await sock.sendMessage(jid, { delete: msg.key });
                            await sock.groupParticipantsUpdate(jid, [sender], 'remove');
                            await sock.sendMessage(jid, { text: '🚫 *Anti-Link:* Links não são permitidos aqui.' });
                            return; 
                        }
                    }
                }

                if (texto.startsWith('!') || texto.startsWith('/') || texto.startsWith('.')) {
                    const args = texto.slice(1).trim().split(/ +/);
                    const comando = args.shift().toLowerCase();
                    const senderIsAdm = await isGroupAdminWA(sock, jid, sender);
                    const botIsAdm = await isBotAdminWA(sock, jid);

                    if (senderIsAdm) {
                        let targetUser = null;

                        // 1. Verifica se há menções reais (@Nome clicável)
                        const mentions = msg.message.extendedTextMessage?.contextInfo?.mentionedJid;
                        if (mentions && mentions.length > 0) {
                            targetUser = mentions[0];
                        } 
                        // 2. Verifica se é resposta a uma mensagem
                        else if (msg.message.extendedTextMessage?.contextInfo?.participant) {
                            targetUser = msg.message.extendedTextMessage.contextInfo.participant;
                        }
                        // 3. Tenta pegar do texto (apenas se for número direto)
                        else if (args[0]) {
                            const potentialNum = args[0].replace(/[^0-9]/g, '');
                            if (potentialNum.length >= 10) { 
                                targetUser = potentialNum + '@s.whatsapp.net';
                            }
                        }

                        switch (comando) {
                            case 'ban':
                            case 'banir':
                            case 'kick':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM para banir.' }, { quoted: msg });
                                if (!targetUser) return sock.sendMessage(jid, { text: '❌ Marque alguém (@Nome) ou responda a mensagem.' }, { quoted: msg });
                                await sock.groupParticipantsUpdate(jid, [targetUser], 'remove');
                                await sock.sendMessage(jid, { text: '✅ Usuário removido.' });
                                return;

                            case 'promover':
                            case 'admin':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!targetUser) return sock.sendMessage(jid, { text: '❌ Marque alguém (@Nome) ou responda a mensagem.' }, { quoted: msg });
                                await sock.groupParticipantsUpdate(jid, [targetUser], 'promote');
                                await sock.sendMessage(jid, { text: '✅ Usuário promovido a ADM.' });
                                return;

                            case 'rebaixar':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!targetUser) return sock.sendMessage(jid, { text: '❌ Marque alguém (@Nome) ou responda a mensagem.' }, { quoted: msg });
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
                                if (!botIsAdm) return; 
                                const groupMeta = await sock.groupMetadata(jid);
                                const mentions = groupMeta.participants.map(p => p.id);
                                await sock.sendMessage(jid, { text: '📢 *Atenção todos!*', mentions: mentions });
                                return;

                            case 'antilink':
                                if (!args[0]) return sock.sendMessage(jid, { text: 'Use: !antilink on ou !antilink off' });
                                const novoEstado = args[0].toLowerCase() === 'on';
                                authorizedGroups[jid].antiLink = novoEstado;
                                
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

            if (msg.key.fromMe) return; 
            if (pausados[jid] && Date.now() < pausados[jid]) return;
            if (ignoredIdentifiers.some(i => (i.type === 'number' && sender.includes(i.value)) || (i.type === 'name' && msg.pushName?.toLowerCase() === i.value.toLowerCase()))) return;

            let shouldRespond = true;
            const myId = sock.user?.id || sock.authState.creds.me?.id;
            
            // Verifica menção ou resposta
            const isMentioned = msg.message.extendedTextMessage?.contextInfo?.mentionedJid?.some(m => areJidsSameUser(m, myId));
            const isQuoted = msg.message.extendedTextMessage?.contextInfo?.participant && areJidsSameUser(msg.message.extendedTextMessage.contextInfo.participant, myId);
            
            // Determinar nome do bot (Grupo ou Global)
            const botName = (groupConfig && groupConfig.botName) ? groupConfig.botName : botNameGlobal;
            const isNameCalled = botName && texto.toLowerCase().includes(botName.toLowerCase());

            // Determinar tempo de silêncio (Grupo ou Global)
            const silenceTime = (groupConfig && groupConfig.silenceTime !== undefined) ? groupConfig.silenceTime : silenceTimeMinutesGlobal;

            if (silenceTime > 0) {
                const lastTime = lastResponseTimes[jid] || 0;
                const timeDiffMinutes = (Date.now() - lastTime) / (1000 * 60);

                if (!isMentioned && !isQuoted && !isNameCalled) {
                    if (timeDiffMinutes < silenceTime) {
                        shouldRespond = false;
                    }
                }
            }

            if (!shouldRespond) return;

            try {
                await sock.readMessages([msg.key]);
                await sock.sendPresenceUpdate('composing', jid);
                await delay(2000);
                
                let audioBuffer = null;
                if (isAudio) audioBuffer = (await downloadMediaMessage(msg, 'buffer', {}, { logger, reuploadRequest: sock.updateMediaMessage })).toString('base64');

                // Usar prompt do grupo se existir, senão global
                const promptToUse = (groupConfig && groupConfig.prompt) ? groupConfig.prompt : promptSistemaGlobal;

                const resposta = await processarComGemini(jid, isAudio ? audioBuffer : texto, isAudio, promptToUse);
                if (resposta) {
                    await sock.sendMessage(jid, { text: resposta }, { quoted: msg });
                    lastResponseTimes[jid] = Date.now();
                }

            } catch (e) { console.error('Erro msg:', e); }
        });
    }

    ligarBot().catch(err => { console.error("Erro fatal:", err); process.exit(1); });
}

