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
const { GoogleGenerativeAI, HarmCategory, HarmBlockThreshold } = require('@google/generative-ai');
const fs = require('fs');
const io = require('socket.io-client');
const axios = require('axios');

const nomeSessao = process.argv[2];

const promptSistemaGlobal = Buffer.from(process.argv[3] || '', 'base64').toString('utf-8');
const ignoredIdentifiersArg = Buffer.from(process.argv[4] || 'W10=', 'base64').toString('utf-8'); 
let phoneNumberArg = (process.argv[5] && process.argv[5] !== 'null') ? process.argv[5] : null;
const authorizedGroupsArg = Buffer.from(process.argv[6] || 'W10=', 'base64').toString('utf-8'); 

const botType = process.argv[7] || 'individual'; 
const botNameGlobal = process.argv[8] || ''; 
const silenceTimeMinutesGlobal = parseInt(process.argv[9] || '0'); 
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

// ESCUTA PARA REMOÇÃO IMEDIATA DO GRUPO DA MEMÓRIA
socket.on('group-removed', (data) => {
    if (data.botSessionName === nomeSessao && data.groupId) {
        console.log(`[${nomeSessao}] ⚠️ ALERTA: Grupo ${data.groupId} removido do painel. Parando respostas imediatamente.`);
        delete authorizedGroups[data.groupId];
    }
});

const pausados = {};
const lastResponseTimes = {};

let ignoredIdentifiers = [];
try { ignoredIdentifiers = JSON.parse(ignoredIdentifiersArg); } catch (e) { console.error("Erro parse ignored:", e); }

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
} catch (e) {
    console.error('❌ Erro ao ler grupos:', e);
}

const API_KEYS_STRING = process.env.API_KEYS_GEMINI;
if (!API_KEYS_STRING) {
    console.error("❌ ERRO FATAL: Nenhuma API KEY do Gemini encontrada nas variáveis de ambiente.");
    process.exit(1);
}

const API_KEYS = API_KEYS_STRING.split('\n').map(k => k.trim()).filter(Boolean);
console.log(`[DEBUG] Total de API Keys carregadas: ${API_KEYS.length}`);

let currentApiKeyIndex = 0;

const safetySettings = [
    { category: HarmCategory.HARM_CATEGORY_HARASSMENT, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_HATE_SPEECH, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_SEXUALLY_EXPLICIT, threshold: HarmBlockThreshold.BLOCK_NONE },
    { category: HarmCategory.HARM_CATEGORY_DANGEROUS_CONTENT, threshold: HarmBlockThreshold.BLOCK_NONE },
];

let genAI = new GoogleGenerativeAI(API_KEYS[currentApiKeyIndex]);
let model = genAI.getGenerativeModel({ model: modeloGemini, safetySettings });

const logger = pino({ level: 'error' }); 

const historicoConversa = {};
const MAX_HISTORICO_POR_USUARIO = 20;

function switchToNextApiKey() {
    currentApiKeyIndex = (currentApiKeyIndex + 1) % API_KEYS.length;
    console.log(`[${nomeSessao}] 🔄 Trocando API Key para index: ${currentApiKeyIndex}`);
    genAI = new GoogleGenerativeAI(API_KEYS[currentApiKeyIndex]);
    model = genAI.getGenerativeModel({ model: modeloGemini, safetySettings });
}

async function processarComGemini(jid, input, isAudio = false, promptEspecifico = null) {
    console.log(`[DEBUG IA] Iniciando processamento para ${jid}. Input: "${input.substring(0, 20)}..."`);
    
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
            
            console.log(`[DEBUG IA] Tentativa ${attempt + 1} usando chave index ${currentApiKeyIndex}`);

            if (isAudio) {
                const parts = [{ inlineData: { mimeType: "audio/ogg", data: input } }, { text: "Responda a este áudio." }];
                const result = await model.generateContent({
                    contents: [{ role: "user", parts: [{ text: `System: ${promptFinal}` }] }, { role: "user", parts: parts }]
                });
                resposta = result.response.text().trim();
                historicoConversa[jid].push({ role: "user", parts: [{ text: "[Áudio]" }] });
            } else {
                const chat = model.startChat({ history: chatHistory });
                
                const timeoutPromise = new Promise((_, reject) => setTimeout(() => reject(new Error("Timeout Gemini")), 15000));
                const apiPromise = chat.sendMessage(input);
                
                const result = await Promise.race([apiPromise, timeoutPromise]);
                
                if (!result || !result.response) {
                    throw new Error("Resposta da API veio vazia ou nula.");
                }
                
                resposta = result.response.text();
                if (!resposta) resposta = ""; 
                resposta = resposta.trim();
                
                historicoConversa[jid].push({ role: "user", parts: [{ text: input }] });
            }

            console.log(`[DEBUG IA] Resposta gerada: "${resposta.substring(0, 20)}..."`);

            historicoConversa[jid].push({ role: "model", parts: [{ text: resposta }] });
            if (historicoConversa[jid].length > MAX_HISTORICO_POR_USUARIO) historicoConversa[jid] = historicoConversa[jid].slice(-MAX_HISTORICO_POR_USUARIO);
            
            return resposta;

        } catch (err) {
            const errorMsg = err.toString();
            console.error(`[DEBUG IA] Erro na tentativa ${attempt}:`, errorMsg);
            
            if (errorMsg.includes('429') || errorMsg.includes('fetch failed') || errorMsg.includes('Timeout')) {
                switchToNextApiKey();
            } else {
                console.error(`[DEBUG IA] Erro não recuperável: ${errorMsg}`);
                return ""; 
            }
        }
    }
    console.error("[DEBUG IA] Todas as chaves falharam.");
    return "";
}

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

if (platform === 'telegram') {
    if (!telegramToken) { console.error('❌ Token do Telegram não fornecido.'); process.exit(1); }
    const bot = new Telegraf(telegramToken);
    (async () => {
        try {
            await bot.launch({ dropPendingUpdates: true });
            console.log('\nONLINE!'); 
            socket.emit('bot-online', { sessionName: nomeSessao });
        } catch (err) { console.error('Erro Telegram:', err); process.exit(1); }
    })();
    
    bot.on('message', async (ctx) => {
        const texto = ctx.message.text || '';
        if(!texto) return;
        const resposta = await processarComGemini(ctx.chat.id.toString(), texto);
        if(resposta) ctx.reply(resposta);
    });

} else {
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
                const msg = data.success ? '✅ Grupo ativado!' : `❌ Falha: ${data.message}`;
                await sock.sendMessage(data.groupId, { text: msg });
                if(data.success) {
                    authorizedGroups[data.groupId] = { expiresAt: new Date(data.expiresAt), antiLink: false, prompt: '', silenceTime: 0, botName: '', isPaused: false };
                }
            }
        });

        if (phoneNumberArg && !sock.authState.creds.registered) {
            setTimeout(async () => {
                try {
                    const code = await sock.requestPairingCode(phoneNumberArg);
                    console.log(`PAIRING_CODE:${code}`);
                } catch (err) { console.error(`Erro Pairing Code:`, err); }
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

            if (isGroup && texto.includes('/ativar?token=')) {
                const token = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
                if (token) {
                    const meta = await sock.groupMetadata(jid);
                    socket.emit('group-activation-request', { groupId: jid, groupName: meta.subject, activationToken: token, botSessionName: nomeSessao });
                    return; 
                }
            }

            let groupConfig = null;
            if (botType === 'group') {
                // VERIFICAÇÃO CRÍTICA DE SEGURANÇA
                // Se o bot é de grupo, mas o grupo não está na memória (removido), aborta.
                if (!isGroup || !authorizedGroups[jid]) {
                    // Ignora silenciosamente. O grupo foi removido ou não está autorizado.
                    return;
                }
                
                if (authorizedGroups[jid].expiresAt && new Date() > authorizedGroups[jid].expiresAt) return;
                groupConfig = authorizedGroups[jid];
                if (groupConfig.isPaused) return;
            } else if (isGroup) {
                return;
            }

            if (msg.key.fromMe) return; 
            if (pausados[jid] && Date.now() < pausados[jid]) return;
            if (ignoredIdentifiers.some(i => (i.type === 'number' && sender.includes(i.value)) || (i.type === 'name' && msg.pushName?.toLowerCase() === i.value.toLowerCase()))) return;

            let shouldRespond = true;
            const myId = sock.user?.id || sock.authState.creds.me?.id;
            const isMentioned = msg.message.extendedTextMessage?.contextInfo?.mentionedJid?.some(m => areJidsSameUser(m, myId));
            const isQuoted = msg.message.extendedTextMessage?.contextInfo?.participant && areJidsSameUser(msg.message.extendedTextMessage.contextInfo.participant, myId);
            const botName = (groupConfig && groupConfig.botName) ? groupConfig.botName : botNameGlobal;
            const isNameCalled = botName && texto.toLowerCase().includes(botName.toLowerCase());
            const silenceTime = (groupConfig && groupConfig.silenceTime !== undefined) ? groupConfig.silenceTime : silenceTimeMinutesGlobal;

            if (silenceTime > 0) {
                const lastTime = lastResponseTimes[jid] || 0;
                const timeDiffMinutes = (Date.now() - lastTime) / (1000 * 60);
                if (!isMentioned && !isQuoted && !isNameCalled) {
                    if (timeDiffMinutes < silenceTime) shouldRespond = false;
                }
            }

            if (!shouldRespond) return;

            try {
                console.log(`[DEBUG] Mensagem recebida de ${jid}. Enviando 'composing'...`);
                await sock.readMessages([msg.key]);
                await sock.sendPresenceUpdate('composing', jid);
                
                await delay(1000); 
                
                let audioBuffer = null;
                if (isAudio) {
                    console.log(`[DEBUG] Baixando áudio...`);
                    audioBuffer = (await downloadMediaMessage(msg, 'buffer', {}, { logger, reuploadRequest: sock.updateMediaMessage })).toString('base64');
                }

                const promptToUse = (groupConfig && groupConfig.prompt) ? groupConfig.prompt : promptSistemaGlobal;

                console.log(`[DEBUG] Chamando Gemini...`);
                const resposta = await processarComGemini(jid, isAudio ? audioBuffer : texto, isAudio, promptToUse);
                
                console.log(`[DEBUG] Resposta recebida da função: "${resposta ? resposta.substring(0, 10) + '...' : 'VAZIA'}"`);

                if (resposta && resposta.trim().length > 0) {
                    console.log(`[DEBUG] Enviando mensagem para o WhatsApp...`);
                    await sock.sendMessage(jid, { text: resposta }, { quoted: msg });
                    lastResponseTimes[jid] = Date.now();
                    console.log(`[DEBUG] Mensagem enviada com sucesso.`);
                } else {
                    console.log(`[DEBUG] Resposta vazia, nada enviado.`);
                }
                
                await sock.sendPresenceUpdate('paused', jid);

            } catch (e) { 
                console.error('[ERRO CRÍTICO NO LOOP]:', e); 
                await sock.sendPresenceUpdate('paused', jid);
            }
        });
    }

    ligarBot().catch(err => { console.error("Erro fatal:", err); process.exit(1); });
}

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

