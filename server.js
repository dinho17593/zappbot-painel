const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const FileStore = require('session-file-store')(session);
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { MercadoPagoConfig, Payment } = require('mercadopago');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const BASE_DIR = __dirname;
const BOTS_DB_PATH = path.join(BASE_DIR, 'bots.json');
const USERS_DB_PATH = path.join(BASE_DIR, 'users.json');
const SETTINGS_DB_PATH = path.join(BASE_DIR, 'settings.json');
const GROUPS_DB_PATH = path.join(BASE_DIR, 'groups.json');
const AUTH_SESSIONS_DIR = path.join(BASE_DIR, 'auth_sessions');
const SESSION_FILES_DIR = path.join(BASE_DIR, 'sessions');
const BOT_SCRIPT_PATH = path.join(BASE_DIR, 'index.js');

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID ? process.env.GOOGLE_CLIENT_ID.trim() : null;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET ? process.env.GOOGLE_CLIENT_SECRET.trim() : null;
const CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "https://zappbot.shop/auth/google/callback";
const SESSION_SECRET = process.env.SESSION_SECRET || 'sua-chave-secreta-muito-forte-e-diferente';

const activationTokens = {};

app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(SESSION_SECRET));

app.use(express.static(BASE_DIR));

const sessionMiddleware = session({
    store: new FileStore({ path: SESSION_FILES_DIR, logFn: function () { } }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false,
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
});

app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

io.engine.use(sessionMiddleware);

if (!fs.existsSync(AUTH_SESSIONS_DIR)) fs.mkdirSync(AUTH_SESSIONS_DIR, { recursive: true });
if (!fs.existsSync(SESSION_FILES_DIR)) fs.mkdirSync(SESSION_FILES_DIR, { recursive: true });

const readDB = (filePath) => fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, 'utf-8')) : {};
const writeDB = (filePath, data) => fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');

if (!fs.existsSync(GROUPS_DB_PATH)) writeDB(GROUPS_DB_PATH, {});

function ensureFirstUserIsAdmin() {
    try {
        const users = readDB(USERS_DB_PATH);
        const userKeys = Object.keys(users);

        if (userKeys.length > 0) {
            const hasAdmin = userKeys.some(key => users[key].isAdmin === true);
            if (!hasAdmin) {
                const firstUser = userKeys[0];
                console.log(`[SISTEMA] Nenhum admin encontrado. Promovendo o primeiro usuário (${firstUser}) a Admin.`);
                users[firstUser].isAdmin = true;
                users[firstUser].botLimit = 999999;
                writeDB(USERS_DB_PATH, users);
            }
        }
    } catch (e) {
        console.error("Erro ao verificar admins:", e);
    }
}
ensureFirstUserIsAdmin();

if (!fs.existsSync(SETTINGS_DB_PATH)) {
    writeDB(SETTINGS_DB_PATH, {
        mpAccessToken: "", priceMonthly: "29.90", priceQuarterly: "79.90",
        priceSemiannual: "149.90", priceYearly: "289.90",
        priceResell5: "100.00", priceResell10: "180.00", priceResell20: "300.00", priceResell30: "400.00"
    });
}

function addUserLog(username, message) {
    try {
        const users = readDB(USERS_DB_PATH);
        if (users[username]) {
            if (!users[username].log) users[username].log = [];
            users[username].log.push(`[${new Date().toLocaleString('pt-BR')}] ${message}`);
            writeDB(USERS_DB_PATH, users);
        }
    } catch (e) { }
}

function getClientIp(req) {
    return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

let activeBots = {};

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: CALLBACK_URL,
        passReqToCallback: true,
        proxy: true
    },
        async (req, accessToken, refreshToken, profile, done) => {
            try {
                const users = readDB(USERS_DB_PATH);
                const userIp = getClientIp(req);
                const username = profile.emails[0].value.toLowerCase();

                if (users[username]) {
                    return done(null, users[username]);
                }

                const deviceUsed = req.signedCookies['zapp_device_used'] === 'true';
                const isAdmin = Object.keys(users).length === 0;
                const trialUsed = (!isAdmin && deviceUsed) ? true : false;

                const newUser = {
                    username,
                    password: null,
                    googleId: profile.id,
                    displayName: profile.displayName,
                    createdAt: new Date(),
                    isAdmin,
                    botLimit: isAdmin ? 999999 : 1,
                    log: [],
                    trialUsed: trialUsed,
                    trialExpiresAt: null,
                    salvagedTime: null
                };

                users[username] = newUser;
                writeDB(USERS_DB_PATH, users);
                addUserLog(username, `Conta Google criada. IP: ${userIp} | DeviceUsed: ${deviceUsed}`);
                return done(null, newUser);
            } catch (err) { return done(err, null); }
        }));

    passport.serializeUser((user, done) => done(null, user.username));

    passport.deserializeUser((username, done) => {
        const u = readDB(USERS_DB_PATH)[username.toLowerCase()];
        done(u ? null : new Error("Not found"), u);
    });
}

app.post('/api/generate-activation-link', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Não autorizado. Faça login para continuar.' });
    }

    const token = crypto.randomUUID();
    const ownerEmail = req.session.user.username.toLowerCase();
    const expiresAt = Date.now() + 15 * 60 * 1000; 

    activationTokens[token] = { ownerEmail, expiresAt };

    Object.keys(activationTokens).forEach(t => {
        if (activationTokens[t].expiresAt < Date.now()) {
            delete activationTokens[t];
        }
    });

    const activationLink = `https://zappbot.shop/ativar?token=${token}`;
    res.json({ activationLink });
});

app.post('/api/create-payment', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Não autorizado' });
    const settings = readDB(SETTINGS_DB_PATH);
    const { sessionName, planType, groupId } = req.body;
    if (!settings.mpAccessToken) return res.status(500).json({ error: 'Erro config pagamento.' });

    let amount = 0, desc = '', extRef = '';

    if (planType && planType.startsWith('resell_')) {
        if (planType === 'resell_5') amount = parseFloat(settings.priceResell5);
        if (planType === 'resell_10') amount = parseFloat(settings.priceResell10);
        if (planType === 'resell_20') amount = parseFloat(settings.priceResell20);
        if (planType === 'resell_30') amount = parseFloat(settings.priceResell30);
        desc = `Upgrade: ${planType}`; extRef = `user|${req.session.user.username}|${planType}`;
    } else if (groupId) {
        if (planType === 'monthly') amount = parseFloat(settings.priceMonthly);
        if (planType === 'quarterly') amount = parseFloat(settings.priceQuarterly);
        if (planType === 'semiannual') amount = parseFloat(settings.priceSemiannual);
        if (planType === 'yearly') amount = parseFloat(settings.priceYearly);
        desc = `Ativação Grupo: ${groupId}`; extRef = `group|${groupId}|${planType}`;
    } else {
        if (planType === 'monthly') amount = parseFloat(settings.priceMonthly);
        if (planType === 'quarterly') amount = parseFloat(settings.priceQuarterly);
        if (planType === 'semiannual') amount = parseFloat(settings.priceSemiannual);
        if (planType === 'yearly') amount = parseFloat(settings.priceYearly);
        desc = `Renova: ${sessionName}`; extRef = `bot|${sessionName}|${planType}`;
    }

    try {
        const payment = new Payment(new MercadoPagoConfig({ accessToken: settings.mpAccessToken }));
        const result = await payment.create({ body: { transaction_amount: amount, description: desc, payment_method_id: 'pix', payer: { email: req.session.user.username }, external_reference: extRef, notification_url: 'https://zappbot.shop/webhook/mercadopago' } });
        res.json({ qr_code: result.point_of_interaction.transaction_data.qr_code, qr_code_base64: result.point_of_interaction.transaction_data.qr_code_base64, ticket_url: result.point_of_interaction.transaction_data.ticket_url, amount: amount.toFixed(2).replace('.', ',') });
    } catch (e) { res.status(500).json({ error: 'Erro Pix' }); }
});

app.post('/webhook/mercadopago', async (req, res) => {
    const { data, type } = req.body;
    if (type === 'payment') {
        try {
            const settings = readDB(SETTINGS_DB_PATH);
            const payment = new Payment(new MercadoPagoConfig({ accessToken: settings.mpAccessToken }));
            const paymentData = await payment.get({ id: data.id });

            if (paymentData.status === 'approved') {
                const parts = (paymentData.external_reference || '').split('|');
                const paymentType = parts[0];
                const referenceId = parts[1];
                const plan = parts[2];

                if (paymentType === 'user') {
                    const users = readDB(USERS_DB_PATH);
                    if (users[referenceId]) {
                        users[referenceId].botLimit = parseInt(plan.split('_')[1]);
                        users[referenceId].trialUsed = true;
                        users[referenceId].trialExpiresAt = "PAID_USER";
                        writeDB(USERS_DB_PATH, users);
                        io.to(referenceId.toLowerCase()).emit('update-limit', users[referenceId].botLimit);
                    }
                } else if (paymentType === 'bot') {
                    const bots = readDB(BOTS_DB_PATH);
                    const bot = bots[referenceId];
                    if (bot) {
                        const now = new Date();
                        const currentExpire = new Date(bot.trialExpiresAt);
                        let days = 30;
                        if (plan === 'quarterly') days = 90;
                        if (plan === 'semiannual') days = 180;
                        if (plan === 'yearly') days = 365;
                        let baseDate = (!isNaN(currentExpire) && currentExpire > now) ? currentExpire : now;
                        baseDate.setDate(baseDate.getDate() + days);
                        bot.trialExpiresAt = baseDate.toISOString();
                        bot.isTrial = false;
                        if (!bot.activated) bot.activated = true;
                        writeDB(BOTS_DB_PATH, bots);
                        io.emit('bot-updated', bot);
                        io.emit('payment-success', { sessionName: referenceId });
                    }
                } else if (paymentType === 'group') {
                    const groups = readDB(GROUPS_DB_PATH);
                    const group = groups[referenceId];
                    if (group) {
                        const now = new Date();
                        const currentExpire = group.expiresAt ? new Date(group.expiresAt) : now;
                        let days = 30;
                        if (plan === 'quarterly') days = 90;
                        if (plan === 'semiannual') days = 180;
                        if (plan === 'yearly') days = 365;
                        let baseDate = (currentExpire > now) ? currentExpire : now;
                        baseDate.setDate(baseDate.getDate() + days);
                        
                        group.status = 'active';
                        group.expiresAt = baseDate.toISOString();
                        writeDB(GROUPS_DB_PATH, groups);

                        io.to(group.owner.toLowerCase()).emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === group.owner));
                        io.to(group.owner.toLowerCase()).emit('feedback', { success: true, message: `Grupo "${group.groupName}" ativado com sucesso!` });

                        const botSessionName = group.managedByBot;
                        if (activeBots[botSessionName]) {
                            console.log(`[PAGAMENTO GRUPO] Reiniciando bot agregador: ${botSessionName}`);
                            activeBots[botSessionName].process.kill('SIGINT');
                            setTimeout(() => {
                                const bots = readDB(BOTS_DB_PATH);
                                if (bots[botSessionName]) {
                                    startBotProcess(bots[botSessionName]);
                                }
                            }, 2000);
                        }
                    }
                }
            }
        } catch (e) { console.error("Webhook Error:", e); }
    }
    res.sendStatus(200);
});

app.get('/', (req, res) => {
    res.sendFile(path.join(BASE_DIR, 'index.html'));
});

app.post('/register', async (req, res) => {
    let users = readDB(USERS_DB_PATH);
    const username = req.body.username.toLowerCase().trim();
    const password = req.body.password;

    if (users[username]) return res.status(400).json({ message: "Este usuário já está cadastrado." });

    const deviceUsed = req.signedCookies['zapp_device_used'] === 'true';
    const isAdmin = Object.keys(users).length === 0;
    const trialUsed = (!isAdmin && deviceUsed) ? true : false;

    users[username] = {
        username, password: await bcrypt.hash(password, 10), createdAt: new Date(), isAdmin,
        botLimit: isAdmin ? 999999 : 1, log: [],
        trialUsed: trialUsed,
        trialExpiresAt: null,
        salvagedTime: null
    };

    writeDB(USERS_DB_PATH, users);

    res.cookie('zapp_device_used', 'true', {
        maxAge: 3650 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        signed: true
    });

    res.status(201).json({ message: "OK" });
});

app.post('/login', async (req, res) => {
    const username = req.body.username.toLowerCase().trim();
    const u = readDB(USERS_DB_PATH)[username];

    if (!u || !u.password || !await bcrypt.compare(req.body.password, u.password)) {
        return res.status(401).json({ message: "Usuário ou senha incorretos." });
    }
    req.session.user = { username: u.username, isAdmin: !!u.isAdmin };
    res.status(200).json({ message: "OK" });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', (req, res, next) => {
    if (req.isAuthenticated()) return res.redirect('/');

    passport.authenticate('google', (err, user, info) => {
        if (err) {
            console.error("Erro Google Auth:", err);
            const msg = err.message || "Erro desconhecido";
            return res.redirect(`/?error=${encodeURIComponent(msg)}`);
        }

        if (!user) {
            return res.redirect('/');
        }

        req.logIn(user, (err) => {
            if (err) {
                console.error("Erro login session:", err);
                return res.redirect(`/?error=${encodeURIComponent(err.message)}`);
            }

            res.cookie('zapp_device_used', 'true', {
                maxAge: 3650 * 24 * 60 * 60 * 1000,
                httpOnly: true,
                signed: true
            });

            req.session.user = { username: user.username, isAdmin: !!user.isAdmin };
            return res.redirect('/');
        });
    })(req, res, next);
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

app.get('/check-session', (req, res) => {
    if (req.session.user) {
        const u = readDB(USERS_DB_PATH)[req.session.user.username.toLowerCase()];
        if (u) {
            req.session.user.isAdmin = u.isAdmin;
            res.json({ loggedIn: true, user: { ...req.session.user, botLimit: u.botLimit || 1 } });
        } else {
            req.session.destroy();
            res.status(401).json({ loggedIn: false });
        }
    } else res.status(401).json({ loggedIn: false });
});

io.use((socket, next) => {
    const sessionUser = socket.request.session.user || (socket.request.session.passport?.user);

    if (sessionUser) {
        const username = (typeof sessionUser === 'object' ? sessionUser.username : sessionUser).toLowerCase();
        const dbUser = readDB(USERS_DB_PATH)[username];

        if (dbUser) {
            socket.request.session.user = {
                username: dbUser.username,
                isAdmin: dbUser.isAdmin
            };
            next();
        } else {
            next(new Error('User not found in DB'));
        }
    } else {
        next();
    }
});

io.on('connection', (socket) => {
    const user = socket.request.session.user;
    
    // --- OUVINTE PARA ATUALIZAR CONFIGURAÇÕES DE GRUPO VIA BOT ---
    socket.on('update-group-settings', (data) => {
        // data: { groupId, settings: { antiLink: true/false } }
        const groups = readDB(GROUPS_DB_PATH);
        if (groups[data.groupId]) {
            // Atualiza as configurações mesclando
            groups[data.groupId] = { ...groups[data.groupId], ...data.settings };
            writeDB(GROUPS_DB_PATH, groups);
            console.log(`[CONFIG] Grupo ${data.groupId} atualizado:`, data.settings);
        }
    });

    if (user) {
        socket.join(user.username.toLowerCase());
        const uData = readDB(USERS_DB_PATH)[user.username];
        socket.emit('session-info', { username: user.username, isAdmin: user.isAdmin, botLimit: uData?.botLimit || 1 });

        socket.on('get-public-prices', () => {
            const s = readDB(SETTINGS_DB_PATH);
            socket.emit('public-prices', { monthly: s.priceMonthly, quarterly: s.priceQuarterly, semiannual: s.priceSemiannual, yearly: s.priceYearly, resell5: s.priceResell5, resell10: s.priceResell10, resell20: s.priceResell20, resell30: s.priceResell30 });
        });

        if (user.isAdmin) {
            socket.on('admin-settings', (s) => socket.emit('admin-settings', readDB(SETTINGS_DB_PATH)));
            socket.on('save-settings', (ns) => { writeDB(SETTINGS_DB_PATH, ns); socket.emit('feedback', { success: true, message: 'Salvo' }); io.emit('public-prices', ns); });

            socket.on('admin-set-days', ({ sessionName, days }) => {
                const bots = readDB(BOTS_DB_PATH);
                const bot = bots[sessionName];

                if (bot) {
                    const d = parseInt(days);
                    const now = new Date();
                    const newDate = new Date(now);
                    newDate.setDate(newDate.getDate() + d);
                    newDate.setMinutes(newDate.getMinutes() - 10);
                    bot.trialExpiresAt = newDate.toISOString();
                    bot.activated = true;
                    bot.isTrial = false;
                    writeDB(BOTS_DB_PATH, bots);
                    io.emit('bot-updated', bot);
                }
            });

            socket.on('admin-set-group-days', ({ groupId, days }) => {
                const groups = readDB(GROUPS_DB_PATH);
                const group = groups[groupId];

                if (group) {
                    const d = parseInt(days);
                    const now = new Date();
                    const baseDate = new Date(now);
                    baseDate.setDate(baseDate.getDate() + d);
                    baseDate.setMinutes(baseDate.getMinutes() - 10);
                    group.expiresAt = baseDate.toISOString();
                    group.status = 'active'; 

                    writeDB(GROUPS_DB_PATH, groups);
                    io.to(group.owner.toLowerCase()).emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === group.owner));
                    socket.emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === group.owner));
                    socket.emit('feedback', { success: true, message: 'Dias do grupo definidos com sucesso.' });

                    const botSessionName = group.managedByBot;
                    if (activeBots[botSessionName]) {
                        console.log(`[ADMIN GROUP DAYS] Reiniciando bot ${botSessionName} para aplicar novos dias.`);
                        activeBots[botSessionName].process.kill('SIGINT');
                        delete activeBots[botSessionName];
                        setTimeout(() => {
                            const currentBots = readDB(BOTS_DB_PATH);
                            if (currentBots[botSessionName]) {
                                startBotProcess(currentBots[botSessionName]);
                            }
                        }, 1000);
                    }
                }
            });

            socket.on('admin-get-users', () => socket.emit('admin-users-list', Object.values(readDB(USERS_DB_PATH)).map(({ password, ...r }) => r)));
            socket.on('admin-delete-user', ({ username }) => {
                const users = readDB(USERS_DB_PATH);
                delete users[username];
                writeDB(USERS_DB_PATH, users);
                socket.emit('admin-users-list', Object.values(users).map(({ password, ...r }) => r));
            });
            socket.on('admin-get-bots-for-user', ({ username }) => socket.emit('initial-bots-list', Object.values(readDB(BOTS_DB_PATH)).filter(b => b.owner === username)));
        }

        socket.on('get-my-bots', () => {
            socket.emit('initial-bots-list', Object.values(readDB(BOTS_DB_PATH)).filter(b => b.owner === user.username));
        });

        socket.on('get-my-groups', () => {
            socket.emit('initial-groups-list', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === user.username));
        });

        socket.on('delete-group', ({ groupId }) => {
            const groups = readDB(GROUPS_DB_PATH);
            const group = groups[groupId];
            if (!group) return socket.emit('feedback', { success: false, message: 'Grupo não encontrado.' });
            const bots = readDB(BOTS_DB_PATH);
            const bot = bots[group.managedByBot];
            const isBotOwner = bot && bot.owner === user.username;
            const isGroupOwner = group.owner === user.username;
            if (!user.isAdmin && !isBotOwner && !isGroupOwner) {
                return socket.emit('feedback', { success: false, message: 'Permissão negada.' });
            }
            const botSessionName = group.managedByBot;
            delete groups[groupId];
            writeDB(GROUPS_DB_PATH, groups);
            socket.emit('group-list-updated', Object.values(groups).filter(g => g.owner === user.username));
            socket.emit('feedback', { success: true, message: 'Grupo removido com sucesso.' });
            if (activeBots[botSessionName]) {
                console.log(`[DELETE GROUP] Reiniciando bot ${botSessionName} para aplicar remoção do grupo.`);
                activeBots[botSessionName].process.kill('SIGINT');
                delete activeBots[botSessionName];
                setTimeout(() => {
                    const currentBots = readDB(BOTS_DB_PATH);
                    if (currentBots[botSessionName]) {
                        startBotProcess(currentBots[botSessionName]);
                    }
                }, 1000);
            }
        });

        socket.on('create-bot', (d) => {
            const bots = readDB(BOTS_DB_PATH);
            let users = readDB(USERS_DB_PATH);
            const owner = (user.isAdmin && d.owner) ? d.owner : user.username;
            const ownerData = users[owner];
            if (bots[d.sessionName]) return socket.emit('feedback', { success: false, message: 'Nome de robô já em uso.' });
            if (d.botType !== 'group' && Object.values(bots).filter(b => b.owner === owner && b.botType !== 'group').length >= (ownerData.botLimit || 1) && !ownerData.isAdmin) {
                return socket.emit('feedback', { success: false, error: 'limit_reached' });
            }
            const now = new Date();
            let trialEndDate = new Date(0);
            let isTrial = false;
            let feedbackMessage = 'Robô criado. Realize o pagamento para ativar.';
            if (d.botType !== 'group') {
                if (ownerData.salvagedTime && new Date(ownerData.salvagedTime.expiresAt) > now) {
                    trialEndDate = new Date(ownerData.salvagedTime.expiresAt);
                    isTrial = ownerData.salvagedTime.isTrial;
                    ownerData.salvagedTime = null;
                    users[owner] = ownerData;
                    writeDB(USERS_DB_PATH, users);
                    feedbackMessage = 'Bot criado utilizando o tempo restante do anterior.';
                } else {
                    if (ownerData.isAdmin || !ownerData.trialUsed) {
                        trialEndDate = new Date(now);
                        trialEndDate.setHours(trialEndDate.getHours() + 24);
                        isTrial = true;
                        feedbackMessage = 'Robô criado e iniciando (Teste Grátis)...';
                    }
                }
            } else {
                trialEndDate = new Date(now);
                trialEndDate.setFullYear(trialEndDate.getFullYear() + 10);
                isTrial = false;
                feedbackMessage = 'Bot Agregador de Grupos criado com sucesso!';
            }
            const newBot = { sessionName: d.sessionName, prompt: d.prompt, status: 'Offline', owner, activated: false, isTrial: isTrial, createdAt: now.toISOString(), trialExpiresAt: trialEndDate.toISOString(), ignoredIdentifiers: [], botType: d.botType || 'individual' };
            bots[d.sessionName] = newBot;
            writeDB(BOTS_DB_PATH, bots);
            io.emit('bot-updated', newBot);
            const canStart = new Date(newBot.trialExpiresAt) > new Date();
            if (canStart) {
                startBotProcess(newBot);
            }
            socket.emit('feedback', { success: true, message: feedbackMessage });
        });

        socket.on('start-bot', ({ sessionName, phoneNumber }) => {
            const bots = readDB(BOTS_DB_PATH);
            const bot = bots[sessionName];
            if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;
            if (new Date(bot.trialExpiresAt) < new Date()) {
                return socket.emit('feedback', { success: false, message: 'Robô expirado. Renove para ligar.' });
            }
            if (activeBots[sessionName]) return socket.emit('feedback', { success: false, message: 'O robô já está rodando.' });
            startBotProcess(bot, phoneNumber);
            socket.emit('feedback', { success: true, message: 'Iniciando o robô...' });
        });

        socket.on('stop-bot', ({ sessionName }) => {
            if (activeBots[sessionName]) { activeBots[sessionName].process.kill('SIGINT'); delete activeBots[sessionName]; }
            updateBotStatus(sessionName, 'Offline');
            socket.emit('feedback', { success: true, message: 'Robô parado.' });
        });

        socket.on('delete-bot', ({ sessionName }) => {
            let bots = readDB(BOTS_DB_PATH);
            let users = readDB(USERS_DB_PATH);
            const botToDelete = bots[sessionName];
            if (!botToDelete || (!user.isAdmin && botToDelete.owner !== user.username)) return;
            if (botToDelete.botType !== 'group') {
                const owner = users[botToDelete.owner];
                const expirationDate = new Date(botToDelete.trialExpiresAt);
                if (owner && expirationDate > new Date()) {
                    owner.salvagedTime = { expiresAt: botToDelete.trialExpiresAt, isTrial: botToDelete.isTrial };
                    users[botToDelete.owner] = owner;
                    writeDB(USERS_DB_PATH, users);
                    socket.emit('feedback', { success: true, message: 'Bot excluído. O tempo restante foi salvo para o próximo bot que você criar.' });
                } else {
                    socket.emit('feedback', { success: true, message: 'Bot excluído.' });
                }
            } else {
                 socket.emit('feedback', { success: true, message: 'Bot Agregador excluído.' });
            }
            if (activeBots[sessionName]) {
                activeBots[sessionName].process.kill('SIGINT');
                delete activeBots[sessionName];
            }
            delete bots[sessionName];
            writeDB(BOTS_DB_PATH, bots);
            if (fs.existsSync(path.join(AUTH_SESSIONS_DIR, `auth_${sessionName}`))) {
                fs.rmSync(path.join(AUTH_SESSIONS_DIR, `auth_${sessionName}`), { recursive: true, force: true });
            }
            io.emit('bot-deleted', { sessionName });
        });

        socket.on('update-bot', (d) => {
            const bots = readDB(BOTS_DB_PATH);
            const bot = bots[d.sessionName];
            if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;
            if (bot) {
                bot.prompt = d.newPrompt;
                if (d.botType !== undefined) bot.botType = d.botType;
                writeDB(BOTS_DB_PATH, bots);
                io.emit('bot-updated', bot);
                if (activeBots[d.sessionName]) {
                    try { activeBots[d.sessionName].process.kill('SIGINT'); } catch (e) { console.error(`Erro ao parar ${d.sessionName} para update:`, e); }
                    delete activeBots[d.sessionName];
                    socket.emit('feedback', { success: true, message: 'Configurações salvas. Reiniciando o robô...' });
                    setTimeout(() => { startBotProcess(bot); }, 1000);
                } else {
                    socket.emit('feedback', { success: true, message: 'Configurações salvas com sucesso.' });
                }
            }
        });

        socket.on('update-ignored-identifiers', ({ sessionName, ignoredIdentifiers }) => {
            const bots = readDB(BOTS_DB_PATH);
            const bot = bots[sessionName];
            if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;
            bot.ignoredIdentifiers = ignoredIdentifiers;
            writeDB(BOTS_DB_PATH, bots);
            io.emit('bot-updated', bot);
            socket.emit('feedback', { success: true, message: 'Lista de ignorados salva. Reiniciando o bot...' });
            if (activeBots[sessionName]) {
                activeBots[sessionName].process.kill('SIGINT');
                setTimeout(() => startBotProcess(bot), 1000);
            }
        });
    }

    // --- MANIPULADOR DE ATIVAÇÃO DE GRUPO ---
    socket.on('group-activation-request', ({ groupId, groupName, activationToken, botSessionName }) => {
        console.log(`[SERVIDOR] Recebido 'group-activation-request' do bot ${botSessionName}.`);
        
        const tokenData = activationTokens[activationToken];

        if (!tokenData || tokenData.expiresAt < Date.now()) {
            console.error(`[SERVIDOR] Token inválido ou expirado.`);
            // Envia feedback de FALHA para o bot
            io.emit('group-activation-result', { 
                success: false, 
                groupId, 
                botSessionName, 
                message: 'Link de ativação expirado ou inválido.' 
            });
            return;
        }
        
        const { ownerEmail } = tokenData;
        delete activationTokens[activationToken]; 

        const users = readDB(USERS_DB_PATH);
        const groups = readDB(GROUPS_DB_PATH);

        if (!users[ownerEmail]) {
            io.emit('group-activation-result', { success: false, groupId, botSessionName, message: 'Usuário do token não encontrado.' });
            return;
        }
        if (groups[groupId]) {
            io.to(ownerEmail.toLowerCase()).emit('feedback', { success: false, message: `O grupo "${groupName}" já está cadastrado.` });
            io.emit('group-activation-result', { success: false, groupId, botSessionName, message: 'Grupo já cadastrado no painel.' });
            return;
        }

        // CRIAÇÃO DO GRUPO COM 24H DE TESTE PARA QUE O BOT FUNCIONE IMEDIATAMENTE
        const now = new Date();
        const trialExpire = new Date(now.getTime() + 24 * 60 * 60 * 1000); // +24 Horas

        const newGroup = {
            groupId: groupId,
            groupName: groupName,
            owner: ownerEmail,
            managedByBot: botSessionName,
            status: "active", // Define como ativo para o trial funcionar
            antiLink: false, // Padrão Anti-Link desativado
            createdAt: now.toISOString(),
            expiresAt: trialExpire.toISOString()
        };

        groups[groupId] = newGroup;
        writeDB(GROUPS_DB_PATH, groups);
        console.log(`[SERVIDOR] Grupo '${groupName}' ativado (Trial 24h). Dono: ${ownerEmail}.`);

        // 1. Notifica o Painel do Usuário
        io.to(ownerEmail.toLowerCase()).emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === ownerEmail));
        io.to(ownerEmail.toLowerCase()).emit('feedback', { success: true, message: `Grupo "${groupName}" ativado com sucesso!` });

        // 2. Notifica o Bot (index.js) para mandar as boas-vindas
        io.emit('group-activation-result', { 
            success: true, 
            groupId: groupId, 
            botSessionName: botSessionName,
            expiresAt: newGroup.expiresAt,
            message: 'Grupo ativado.'
        });
    });
});

function startBotProcess(bot, phoneNumber = null) {
    const env = { ...process.env, API_KEYS_GEMINI: process.env.API_KEYS_GEMINI };
    const ignoredIdentifiersArg = JSON.stringify(bot.ignoredIdentifiers || []);
    
    const phoneArg = phoneNumber ? phoneNumber : 'null';

    const args = [
        BOT_SCRIPT_PATH,
        bot.sessionName,
        bot.prompt,
        ignoredIdentifiersArg,
        phoneArg,
    ];

    let authorizedGroupsArg = '[]';
    if (bot.botType === 'group') {
        const allGroups = readDB(GROUPS_DB_PATH);
        // PASSANDO TAMBÉM A CONFIGURAÇÃO ANTILINK
        const authorizedGroups = Object.values(allGroups)
            .filter(g => g.managedByBot === bot.sessionName && g.status === 'active')
            .map(g => ({ groupId: g.groupId, expiresAt: g.expiresAt, antiLink: g.antiLink }));
        authorizedGroupsArg = JSON.stringify(authorizedGroups);
    }
    
    args.push(authorizedGroupsArg);
    args.push(bot.botType || 'individual');

    const p = spawn('node', args, { env, stdio: ['pipe', 'pipe', 'pipe'] });

    activeBots[bot.sessionName] = { process: p };
    updateBotStatus(bot.sessionName, 'Iniciando...');

    p.stdout.on('data', (d) => {
        const msg = d.toString().trim();

        if (msg.startsWith('QR_CODE:')) {
            updateBotStatus(bot.sessionName, 'Aguardando QR Code', { qr: msg.replace('QR_CODE:', '') });
        } else if (msg.startsWith('PAIRING_CODE:')) {
            updateBotStatus(bot.sessionName, 'Aguardando QR Code', { qr: msg });
        } else if (msg.includes('ONLINE!')) {
            updateBotStatus(bot.sessionName, 'Online', { setActivated: true });
        }
        io.emit('log-message', { sessionName: bot.sessionName, message: msg });
    });
    p.stderr.on('data', (d) => io.emit('log-message', { sessionName: bot.sessionName, message: `ERRO: ${d}` }));
    p.on('close', () => {
        delete activeBots[bot.sessionName];
        updateBotStatus(bot.sessionName, 'Offline');
    });
}


function updateBotStatus(name, status, options = {}) {
    const bots = readDB(BOTS_DB_PATH);
    const bot = bots[name];
    if (bot) {
        bot.status = status;

        if (options.qr !== undefined) {
            bot.qr = options.qr;
const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcrypt');
const FileStore = require('session-file-store')(session);
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { MercadoPagoConfig, Payment } = require('mercadopago');
const crypto = require('crypto');
const archiver = require('archiver');
const AdmZip = require('adm-zip');
const multer = require('multer');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

const BASE_DIR = __dirname;
const BOTS_DB_PATH = path.join(BASE_DIR, 'bots.json');
const USERS_DB_PATH = path.join(BASE_DIR, 'users.json');
const SETTINGS_DB_PATH = path.join(BASE_DIR, 'settings.json');
const GROUPS_DB_PATH = path.join(BASE_DIR, 'groups.json');
const AUTH_SESSIONS_DIR = path.join(BASE_DIR, 'auth_sessions');
const SESSION_FILES_DIR = path.join(BASE_DIR, 'sessions');
const BOT_SCRIPT_PATH = path.join(BASE_DIR, 'index.js');

if (!fs.existsSync('uploads')) fs.mkdirSync('uploads');

const upload = multer({ dest: 'uploads/' });

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID ? process.env.GOOGLE_CLIENT_ID.trim() : null;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET ? process.env.GOOGLE_CLIENT_SECRET.trim() : null;
const CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "https://zappbot.shop/auth/google/callback";
const SESSION_SECRET = process.env.SESSION_SECRET || 'sua-chave-secreta-muito-forte-e-diferente';

const activationTokens = {};

app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(SESSION_SECRET));

app.use(express.static(BASE_DIR));

const sessionMiddleware = session({
    store: new FileStore({ path: SESSION_FILES_DIR, logFn: function () { } }),
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: true,
    cookie: {
        secure: false,
        maxAge: 1000 * 60 * 60 * 24 * 7
    }
});

app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

io.engine.use(sessionMiddleware);

if (!fs.existsSync(AUTH_SESSIONS_DIR)) fs.mkdirSync(AUTH_SESSIONS_DIR, { recursive: true });
if (!fs.existsSync(SESSION_FILES_DIR)) fs.mkdirSync(SESSION_FILES_DIR, { recursive: true });

const readDB = (filePath) => fs.existsSync(filePath) ? JSON.parse(fs.readFileSync(filePath, 'utf-8')) : {};
const writeDB = (filePath, data) => fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf-8');

if (!fs.existsSync(GROUPS_DB_PATH)) writeDB(GROUPS_DB_PATH, {});

function ensureFirstUserIsAdmin() {
    try {
        const users = readDB(USERS_DB_PATH);
        const userKeys = Object.keys(users);

        if (userKeys.length > 0) {
            const hasAdmin = userKeys.some(key => users[key].isAdmin === true);
            if (!hasAdmin) {
                const firstUser = userKeys[0];
                console.log(`[SISTEMA] Nenhum admin encontrado. Promovendo o primeiro usuário (${firstUser}) a Admin.`);
                users[firstUser].isAdmin = true;
                users[firstUser].botLimit = 999999;
                writeDB(USERS_DB_PATH, users);
            }
        }
    } catch (e) {
        console.error("Erro ao verificar admins:", e);
    }
}
ensureFirstUserIsAdmin();

const defaultSettings = {
    mpAccessToken: "", 
    priceMonthly: "29.90", 
    priceQuarterly: "79.90",
    priceSemiannual: "149.90", 
    priceYearly: "289.90",
    priceResell5: "100.00", 
    priceResell10: "180.00", 
    priceResell20: "300.00", 
    priceResell30: "400.00"
};

let currentSettings = {};
if (fs.existsSync(SETTINGS_DB_PATH)) {
    try {
        currentSettings = readDB(SETTINGS_DB_PATH);
    } catch (e) {
        console.error("Erro ao ler settings.json, recriando...", e);
        currentSettings = {};
    }
}

let settingsUpdated = false;
for (const key in defaultSettings) {
    if (!currentSettings[key]) {
        currentSettings[key] = defaultSettings[key];
        settingsUpdated = true;
    }
}

if (settingsUpdated || !fs.existsSync(SETTINGS_DB_PATH)) {
    console.log("[SISTEMA] Configurações/Preços restaurados para o padrão.");
    writeDB(SETTINGS_DB_PATH, currentSettings);
}

function addUserLog(username, message) {
    try {
        const users = readDB(USERS_DB_PATH);
        if (users[username]) {
            if (!users[username].log) users[username].log = [];
            users[username].log.push(`[${new Date().toLocaleString('pt-BR')}] ${message}`);
            writeDB(USERS_DB_PATH, users);
        }
    } catch (e) { }
}

function getClientIp(req) {
    return (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
}

let activeBots = {};

if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
        clientID: GOOGLE_CLIENT_ID,
        clientSecret: GOOGLE_CLIENT_SECRET,
        callbackURL: CALLBACK_URL,
        passReqToCallback: true,
        proxy: true
    },
        async (req, accessToken, refreshToken, profile, done) => {
            try {
                const users = readDB(USERS_DB_PATH);
                const userIp = getClientIp(req);
                const username = profile.emails[0].value.toLowerCase();

                if (users[username]) {
                    return done(null, users[username]);
                }

                const deviceUsed = req.signedCookies['zapp_device_used'] === 'true';
                const isAdmin = Object.keys(users).length === 0;
                const trialUsed = (!isAdmin && deviceUsed) ? true : false;

                const newUser = {
                    username,
                    password: null,
                    googleId: profile.id,
                    displayName: profile.displayName,
                    createdAt: new Date(),
                    isAdmin,
                    botLimit: isAdmin ? 999999 : 1,
                    log: [],
                    trialUsed: trialUsed,
                    trialExpiresAt: null,
                    salvagedTime: null
                };

                users[username] = newUser;
                writeDB(USERS_DB_PATH, users);
                addUserLog(username, `Conta Google criada. IP: ${userIp} | DeviceUsed: ${deviceUsed}`);
                return done(null, newUser);
            } catch (err) { return done(err, null); }
        }));

    passport.serializeUser((user, done) => done(null, user.username));

    passport.deserializeUser((username, done) => {
        try {
            const users = readDB(USERS_DB_PATH);
            const u = users[username.toLowerCase()];
            if (u) {
                done(null, u);
            } else {
                done(null, false);
            }
        } catch (err) {
            done(err, null);
        }
    });
}

app.get('/api/admin/backup', (req, res) => {
    if (!req.session.user || !req.session.user.isAdmin) return res.status(403).send('Acesso negado');

    const archive = archiver('zip', { zlib: { level: 9 } });
    const fileName = `backup_zappbot_${new Date().toISOString().split('T')[0]}.zip`;

    res.attachment(fileName);

    archive.on('error', (err) => {
        res.status(500).send({ error: err.message });
    });

    archive.pipe(res);

    if (fs.existsSync(USERS_DB_PATH)) archive.file(USERS_DB_PATH, { name: 'users.json' });
    if (fs.existsSync(BOTS_DB_PATH)) archive.file(BOTS_DB_PATH, { name: 'bots.json' });
    if (fs.existsSync(GROUPS_DB_PATH)) archive.file(GROUPS_DB_PATH, { name: 'groups.json' });
    if (fs.existsSync(SETTINGS_DB_PATH)) archive.file(SETTINGS_DB_PATH, { name: 'settings.json' });

    archive.finalize();
});

app.post('/api/admin/restore', upload.single('backupFile'), (req, res) => {
    if (!req.session.user || !req.session.user.isAdmin) return res.status(403).json({ error: 'Acesso negado' });
    if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });

    try {
        const zip = new AdmZip(req.file.path);
        zip.extractAllTo(BASE_DIR, true);
        fs.unlinkSync(req.file.path);

        console.log('[BACKUP] Restauração concluída. Reiniciando bots...');
        
        Object.keys(activeBots).forEach(sessionName => {
            if (activeBots[sessionName]) {
                activeBots[sessionName].process.kill('SIGINT');
                delete activeBots[sessionName];
            }
        });

        setTimeout(() => {
            restartActiveBots();
        }, 2000);

        res.json({ success: true, message: 'Backup restaurado com sucesso! O sistema foi atualizado.' });
    } catch (error) {
        console.error('Erro na restauração:', error);
        res.status(500).json({ error: 'Falha ao processar o arquivo ZIP.' });
    }
});

app.post('/api/generate-activation-link', (req, res) => {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Não autorizado. Faça login para continuar.' });
    }

    const token = crypto.randomUUID();
    const ownerEmail = req.session.user.username.toLowerCase();
    const expiresAt = Date.now() + 15 * 60 * 1000; 

    activationTokens[token] = { ownerEmail, expiresAt };

    Object.keys(activationTokens).forEach(t => {
        if (activationTokens[t].expiresAt < Date.now()) {
            delete activationTokens[t];
        }
    });

    const activationLink = `https://zappbot.shop/ativar?token=${token}`;
    res.json({ activationLink });
});

app.post('/api/create-payment', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Não autorizado' });
    const settings = readDB(SETTINGS_DB_PATH);
    const { sessionName, planType, groupId } = req.body;
    
    if (!settings.mpAccessToken) {
        console.error("Erro: Token do Mercado Pago não configurado.");
        return res.status(500).json({ error: 'Configuração de pagamento incompleta no painel.' });
    }

    let amount = 0, desc = '', extRef = '';

    if (planType && planType.startsWith('resell_')) {
        if (planType === 'resell_5') amount = parseFloat(settings.priceResell5);
        if (planType === 'resell_10') amount = parseFloat(settings.priceResell10);
        if (planType === 'resell_20') amount = parseFloat(settings.priceResell20);
        if (planType === 'resell_30') amount = parseFloat(settings.priceResell30);
        desc = `Upgrade: ${planType}`; extRef = `user|${req.session.user.username}|${planType}`;
    } else if (groupId) {
        if (planType === 'monthly') amount = parseFloat(settings.priceMonthly);
        if (planType === 'quarterly') amount = parseFloat(settings.priceQuarterly);
        if (planType === 'semiannual') amount = parseFloat(settings.priceSemiannual);
        if (planType === 'yearly') amount = parseFloat(settings.priceYearly);
        desc = `Ativação Grupo: ${groupId}`; extRef = `group|${groupId}|${planType}`;
    } else {
        if (planType === 'monthly') amount = parseFloat(settings.priceMonthly);
        if (planType === 'quarterly') amount = parseFloat(settings.priceQuarterly);
        if (planType === 'semiannual') amount = parseFloat(settings.priceSemiannual);
        if (planType === 'yearly') amount = parseFloat(settings.priceYearly);
        desc = `Renova: ${sessionName}`; extRef = `bot|${sessionName}|${planType}`;
    }

    const uniqueId = Date.now().toString().slice(-6);
    const randomPart = Math.floor(Math.random() * 10000);
    const payerEmail = `pagador_${uniqueId}_${randomPart}@temp.com`;

    try {
        const client = new MercadoPagoConfig({ accessToken: settings.mpAccessToken });
        const payment = new Payment(client);
        
        const request = {
            body: {
                transaction_amount: Number(amount),
                description: desc,
                payment_method_id: 'pix',
                payer: { 
                    email: payerEmail,
                    first_name: "Cliente",
                    last_name: "Pagador"
                },
                external_reference: extRef,
                notification_url: 'https://zappbot.shop/webhook/mercadopago'
            }
        };

        const result = await payment.create(request);
        
        res.json({ 
            qr_code: result.point_of_interaction.transaction_data.qr_code, 
            qr_code_base64: result.point_of_interaction.transaction_data.qr_code_base64, 
            ticket_url: result.point_of_interaction.transaction_data.ticket_url, 
            amount: amount.toFixed(2).replace('.', ',') 
        });
    } catch (e) { 
        console.error("Erro ao criar Pix (Mercado Pago):", JSON.stringify(e, null, 2));
        
        if (e.status === 403) {
            return res.status(403).json({ 
                error: 'Pagamento recusado pelo Mercado Pago (Política de Segurança). Tente novamente em alguns instantes ou verifique se sua conta MP está ativa.' 
            });
        }
        
        res.status(500).json({ error: 'Erro ao gerar Pix. Verifique o console do servidor.' }); 
    }
});

app.post('/webhook/mercadopago', async (req, res) => {
    const { data, type } = req.body;
    
    res.sendStatus(200);

    if (type === 'payment') {
        try {
            const settings = readDB(SETTINGS_DB_PATH);
            if (!settings.mpAccessToken) return;

            const client = new MercadoPagoConfig({ accessToken: settings.mpAccessToken });
            const payment = new Payment(client);
            
            const paymentData = await payment.get({ id: data.id });

            if (paymentData && paymentData.status === 'approved') {
                const parts = (paymentData.external_reference || '').split('|');
                const paymentType = parts[0];
                const referenceId = parts[1];
                const plan = parts[2];

                if (paymentType === 'user') {
                    const users = readDB(USERS_DB_PATH);
                    if (users[referenceId]) {
                        users[referenceId].botLimit = parseInt(plan.split('_')[1]);
                        users[referenceId].trialUsed = true;
                        users[referenceId].trialExpiresAt = "PAID_USER";
                        writeDB(USERS_DB_PATH, users);
                        io.to(referenceId.toLowerCase()).emit('update-limit', users[referenceId].botLimit);
                    }
                } else if (paymentType === 'bot') {
                    const bots = readDB(BOTS_DB_PATH);
                    const bot = bots[referenceId];
                    if (bot) {
                        const now = new Date();
                        const currentExpire = new Date(bot.trialExpiresAt);
                        let days = 30;
                        if (plan === 'quarterly') days = 90;
                        if (plan === 'semiannual') days = 180;
                        if (plan === 'yearly') days = 365;
                        let baseDate = (!isNaN(currentExpire) && currentExpire > now) ? currentExpire : now;
                        baseDate.setDate(baseDate.getDate() + days);
                        bot.trialExpiresAt = baseDate.toISOString();
                        bot.isTrial = false;
                        if (!bot.activated) bot.activated = true;
                        writeDB(BOTS_DB_PATH, bots);
                        io.emit('bot-updated', bot);
                        io.emit('payment-success', { sessionName: referenceId });
                    }
                } else if (paymentType === 'group') {
                    const groups = readDB(GROUPS_DB_PATH);
                    const group = groups[referenceId];
                    if (group) {
                        const now = new Date();
                        const currentExpire = group.expiresAt ? new Date(group.expiresAt) : now;
                        let days = 30;
                        if (plan === 'quarterly') days = 90;
                        if (plan === 'semiannual') days = 180;
                        if (plan === 'yearly') days = 365;
                        let baseDate = (currentExpire > now) ? currentExpire : now;
                        baseDate.setDate(baseDate.getDate() + days);
                        
                        group.status = 'active';
                        group.expiresAt = baseDate.toISOString();
                        writeDB(GROUPS_DB_PATH, groups);

                        io.to(group.owner.toLowerCase()).emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === group.owner));
                        io.to(group.owner.toLowerCase()).emit('feedback', { success: true, message: `Grupo "${group.groupName}" ativado com sucesso!` });

                        const botSessionName = group.managedByBot;
                        if (activeBots[botSessionName]) {
                            console.log(`[PAGAMENTO GRUPO] Reiniciando bot agregador: ${botSessionName}`);
                            activeBots[botSessionName].process.kill('SIGINT');
                            setTimeout(() => {
                                const bots = readDB(BOTS_DB_PATH);
                                if (bots[botSessionName]) {
                                    startBotProcess(bots[botSessionName]);
                                }
                            }, 2000);
                        }
                    }
                }
            }
        } catch (e) { console.error("Webhook Error:", e); }
    }
});

app.get('/', (req, res) => {
    res.sendFile(path.join(BASE_DIR, 'index.html'));
});

app.post('/register', async (req, res) => {
    let users = readDB(USERS_DB_PATH);
    const username = req.body.username.toLowerCase().trim();
    const password = req.body.password;

    if (users[username]) return res.status(400).json({ message: "Este usuário já está cadastrado." });

    const deviceUsed = req.signedCookies['zapp_device_used'] === 'true';
    const isAdmin = Object.keys(users).length === 0;
    const trialUsed = (!isAdmin && deviceUsed) ? true : false;

    users[username] = {
        username, password: await bcrypt.hash(password, 10), createdAt: new Date(), isAdmin,
        botLimit: isAdmin ? 999999 : 1, log: [],
        trialUsed: trialUsed,
        trialExpiresAt: null,
        salvagedTime: null
    };

    writeDB(USERS_DB_PATH, users);

    res.cookie('zapp_device_used', 'true', {
        maxAge: 3650 * 24 * 60 * 60 * 1000,
        httpOnly: true,
        signed: true
    });

    res.status(201).json({ message: "OK" });
});

app.post('/login', async (req, res) => {
    const username = req.body.username.toLowerCase().trim();
    const u = readDB(USERS_DB_PATH)[username];

    if (!u || !u.password || !await bcrypt.compare(req.body.password, u.password)) {
        return res.status(401).json({ message: "Usuário ou senha incorretos." });
    }
    req.session.user = { username: u.username, isAdmin: !!u.isAdmin };
    res.status(200).json({ message: "OK" });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback', (req, res, next) => {
    if (req.isAuthenticated()) return res.redirect('/');

    passport.authenticate('google', (err, user, info) => {
        if (err) {
            console.error("Erro Google Auth:", err);
            const msg = err.message || "Erro desconhecido";
            return res.redirect(`/?error=${encodeURIComponent(msg)}`);
        }

        if (!user) {
            return res.redirect('/');
        }

        req.logIn(user, (err) => {
            if (err) {
                console.error("Erro login session:", err);
                return res.redirect(`/?error=${encodeURIComponent(err.message)}`);
            }

            res.cookie('zapp_device_used', 'true', {
                maxAge: 3650 * 24 * 60 * 60 * 1000,
                httpOnly: true,
                signed: true
            });

            req.session.user = { username: user.username, isAdmin: !!user.isAdmin };
            return res.redirect('/');
        });
    })(req, res, next);
});

app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

app.get('/check-session', (req, res) => {
    if (req.session.user) {
        const u = readDB(USERS_DB_PATH)[req.session.user.username.toLowerCase()];
        if (u) {
            req.session.user.isAdmin = u.isAdmin;
            res.json({ loggedIn: true, user: { ...req.session.user, botLimit: u.botLimit || 1 } });
        } else {
            req.session.destroy();
            res.status(401).json({ loggedIn: false });
        }
    } else res.status(401).json({ loggedIn: false });
});

io.use((socket, next) => {
    const sessionUser = socket.request.session.user || (socket.request.session.passport?.user);

    if (sessionUser) {
        const username = (typeof sessionUser === 'object' ? sessionUser.username : sessionUser).toLowerCase();
        const dbUser = readDB(USERS_DB_PATH)[username];

        if (dbUser) {
            socket.request.session.user = {
                username: dbUser.username,
                isAdmin: dbUser.isAdmin
            };
            next();
        } else {
            next(new Error('User not found in DB'));
        }
    } else {
        next();
    }
});

io.on('connection', (socket) => {
    const user = socket.request.session.user;
    
    socket.on('bot-online', ({ sessionName }) => {
        console.log(`[SOCKET] Bot ${sessionName} reportou ONLINE via socket.`);
        updateBotStatus(sessionName, 'Online', { setActivated: true });
    });

    socket.on('update-group-settings', (data) => {
        const groups = readDB(GROUPS_DB_PATH);
        if (groups[data.groupId]) {
            groups[data.groupId] = { ...groups[data.groupId], ...data.settings };
            writeDB(GROUPS_DB_PATH, groups);
            console.log(`[CONFIG] Grupo ${data.groupId} atualizado:`, data.settings);
            
            // Notificar o frontend do dono
            io.to(groups[data.groupId].owner.toLowerCase()).emit('group-list-updated', Object.values(groups).filter(g => g.owner === groups[data.groupId].owner));
            
            // Notificar o processo do bot em tempo real
            const botSessionName = groups[data.groupId].managedByBot;
            io.emit('group-settings-changed', {
                botSessionName: botSessionName,
                groupId: data.groupId,
                settings: groups[data.groupId]
            });
        }
    });

    if (user) {
        socket.join(user.username.toLowerCase());
        const uData = readDB(USERS_DB_PATH)[user.username];
        socket.emit('session-info', { username: user.username, isAdmin: user.isAdmin, botLimit: uData?.botLimit || 1 });

        socket.on('get-public-prices', () => {
            const s = readDB(SETTINGS_DB_PATH);
            socket.emit('public-prices', { monthly: s.priceMonthly, quarterly: s.priceQuarterly, semiannual: s.priceSemiannual, yearly: s.priceYearly, resell5: s.priceResell5, resell10: s.priceResell10, resell20: s.priceResell20, resell30: s.priceResell30 });
        });

        if (user.isAdmin) {
            socket.on('admin-settings', (s) => socket.emit('admin-settings', readDB(SETTINGS_DB_PATH)));
            socket.on('save-settings', (ns) => { writeDB(SETTINGS_DB_PATH, ns); socket.emit('feedback', { success: true, message: 'Salvo' }); io.emit('public-prices', ns); });

            socket.on('admin-set-days', ({ sessionName, days }) => {
                const bots = readDB(BOTS_DB_PATH);
                const bot = bots[sessionName];

                if (bot) {
                    const d = parseInt(days);
                    const now = new Date();
                    const newDate = new Date(now);
                    newDate.setDate(newDate.getDate() + d);
                    newDate.setMinutes(newDate.getMinutes() - 10);
                    bot.trialExpiresAt = newDate.toISOString();
                    bot.activated = true;
                    bot.isTrial = false;
                    writeDB(BOTS_DB_PATH, bots);
                    io.emit('bot-updated', bot);
                }
            });

            socket.on('admin-set-group-days', ({ groupId, days }) => {
                const groups = readDB(GROUPS_DB_PATH);
                const group = groups[groupId];

                if (group) {
                    const d = parseInt(days);
                    const now = new Date();
                    const baseDate = new Date(now);
                    baseDate.setDate(baseDate.getDate() + d);
                    baseDate.setMinutes(baseDate.getMinutes() - 10);
                    group.expiresAt = baseDate.toISOString();
                    group.status = 'active'; 

                    writeDB(GROUPS_DB_PATH, groups);
                    io.to(group.owner.toLowerCase()).emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === group.owner));
                    socket.emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === group.owner));
                    socket.emit('feedback', { success: true, message: 'Dias do grupo definidos com sucesso.' });

                    const botSessionName = group.managedByBot;
                    if (activeBots[botSessionName]) {
                        console.log(`[ADMIN GROUP DAYS] Reiniciando bot ${botSessionName} para aplicar novos dias.`);
                        activeBots[botSessionName].process.kill('SIGINT');
                        delete activeBots[botSessionName];
                        setTimeout(() => {
                            const currentBots = readDB(BOTS_DB_PATH);
                            if (currentBots[botSessionName]) {
                                startBotProcess(currentBots[botSessionName]);
                            }
                        }, 1000);
                    }
                }
            });

            socket.on('admin-get-users', () => socket.emit('admin-users-list', Object.values(readDB(USERS_DB_PATH)).map(({ password, ...r }) => r)));
            socket.on('admin-delete-user', ({ username }) => {
                const users = readDB(USERS_DB_PATH);
                delete users[username];
                writeDB(USERS_DB_PATH, users);
                socket.emit('admin-users-list', Object.values(users).map(({ password, ...r }) => r));
            });
            socket.on('admin-get-bots-for-user', ({ username }) => socket.emit('initial-bots-list', Object.values(readDB(BOTS_DB_PATH)).filter(b => b.owner === username)));
        }

        socket.on('get-my-bots', () => {
            socket.emit('initial-bots-list', Object.values(readDB(BOTS_DB_PATH)).filter(b => b.owner === user.username));
        });

        socket.on('get-my-groups', () => {
            socket.emit('initial-groups-list', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === user.username));
        });

        socket.on('delete-group', ({ groupId }) => {
            const groups = readDB(GROUPS_DB_PATH);
            const group = groups[groupId];
            if (!group) return socket.emit('feedback', { success: false, message: 'Grupo não encontrado.' });
            const bots = readDB(BOTS_DB_PATH);
            const bot = bots[group.managedByBot];
            const isBotOwner = bot && bot.owner === user.username;
            const isGroupOwner = group.owner === user.username;
            if (!user.isAdmin && !isBotOwner && !isGroupOwner) {
                return socket.emit('feedback', { success: false, message: 'Permissão negada.' });
            }
            const botSessionName = group.managedByBot;
            delete groups[groupId];
            writeDB(GROUPS_DB_PATH, groups);
            socket.emit('group-list-updated', Object.values(groups).filter(g => g.owner === user.username));
            socket.emit('feedback', { success: true, message: 'Grupo removido com sucesso.' });
            if (activeBots[botSessionName]) {
                console.log(`[DELETE GROUP] Reiniciando bot ${botSessionName} para aplicar remoção do grupo.`);
                activeBots[botSessionName].process.kill('SIGINT');
                delete activeBots[botSessionName];
                setTimeout(() => {
                    const currentBots = readDB(BOTS_DB_PATH);
                    if (currentBots[botSessionName]) {
                        startBotProcess(currentBots[botSessionName]);
                    }
                }, 1000);
            }
        });

        socket.on('create-bot', (d) => {
            try {
                const bots = readDB(BOTS_DB_PATH);
                let users = readDB(USERS_DB_PATH);
                const owner = (user.isAdmin && d.owner) ? d.owner : user.username;
                const ownerData = users[owner];

                if (!ownerData) {
                    return socket.emit('feedback', { success: false, message: 'Erro: Usuário proprietário não encontrado. Faça login novamente.' });
                }

                if (bots[d.sessionName]) return socket.emit('feedback', { success: false, message: 'Nome de robô já em uso.' });
                
                if (d.botType !== 'group' && Object.values(bots).filter(b => b.owner === owner && b.botType !== 'group').length >= (ownerData.botLimit || 1) && !ownerData.isAdmin) {
                    return socket.emit('feedback', { success: false, error: 'limit_reached' });
                }

                const now = new Date();
                let trialEndDate = new Date(0);
                let isTrial = false;
                let feedbackMessage = 'Robô criado. Realize o pagamento para ativar.';
                
                if (d.botType !== 'group') {
                    if (ownerData.salvagedTime && new Date(ownerData.salvagedTime.expiresAt) > now) {
                        trialEndDate = new Date(ownerData.salvagedTime.expiresAt);
                        isTrial = ownerData.salvagedTime.isTrial;
                        ownerData.salvagedTime = null;
                        users[owner] = ownerData;
                        writeDB(USERS_DB_PATH, users);
                        feedbackMessage = 'Bot criado utilizando o tempo restante do anterior.';
                    } else {
                        if (ownerData.isAdmin || !ownerData.trialUsed) {
                            trialEndDate = new Date(now);
                            trialEndDate.setHours(trialEndDate.getHours() + 24);
                            isTrial = true;
                            feedbackMessage = 'Robô criado e iniciando (Teste Grátis)...';
                        }
                    }
                } else {
                    trialEndDate = new Date(now);
                    trialEndDate.setFullYear(trialEndDate.getFullYear() + 10);
                    isTrial = false;
                    feedbackMessage = 'Bot Agregador de Grupos criado com sucesso!';
                }
                
                const newBot = { 
                    sessionName: d.sessionName, 
                    prompt: d.prompt, 
                    status: 'Offline', 
                    owner, 
                    activated: false, 
                    isTrial: isTrial, 
                    createdAt: now.toISOString(), 
                    trialExpiresAt: trialEndDate.toISOString(), 
                    ignoredIdentifiers: [], 
                    botType: d.botType || 'individual',
                    botName: d.botName || '',
                    silenceTime: d.silenceTime || 0,
                    platform: d.platform || 'whatsapp',
                    token: d.token || ''
                };

                bots[d.sessionName] = newBot;
                writeDB(BOTS_DB_PATH, bots);
                io.emit('bot-updated', newBot);
                
                const canStart = new Date(newBot.trialExpiresAt) > new Date();
                if (canStart) {
                    startBotProcess(newBot);
                }
                socket.emit('feedback', { success: true, message: feedbackMessage });
            } catch (err) {
                console.error("Erro ao criar bot:", err);
                socket.emit('feedback', { success: false, message: 'Erro interno ao criar robô.' });
            }
        });

        socket.on('start-bot', ({ sessionName, phoneNumber }) => {
            const bots = readDB(BOTS_DB_PATH);
            const bot = bots[sessionName];
            if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;
            if (new Date(bot.trialExpiresAt) < new Date()) {
                return socket.emit('feedback', { success: false, message: 'Robô expirado. Renove para ligar.' });
            }
            if (activeBots[sessionName]) return socket.emit('feedback', { success: false, message: 'O robô já está rodando.' });
            
            let cleanPhone = phoneNumber ? phoneNumber.replace(/\D/g, '') : null;
            
            startBotProcess(bot, cleanPhone);
            socket.emit('feedback', { success: true, message: 'Iniciando o robô...' });
        });

        socket.on('stop-bot', ({ sessionName }) => {
            if (activeBots[sessionName]) { 
                try {
                    activeBots[sessionName].process.kill('SIGINT'); 
                } catch(e) {
                    console.error("Erro ao matar processo:", e);
                }
                delete activeBots[sessionName]; 
            }
            updateBotStatus(sessionName, 'Offline');
            socket.emit('feedback', { success: true, message: 'Robô parado.' });
        });

        socket.on('delete-bot', ({ sessionName }) => {
            let bots = readDB(BOTS_DB_PATH);
            let users = readDB(USERS_DB_PATH);
            const botToDelete = bots[sessionName];
            if (!botToDelete || (!user.isAdmin && botToDelete.owner !== user.username)) return;
            if (botToDelete.botType !== 'group') {
                const owner = users[botToDelete.owner];
                const expirationDate = new Date(botToDelete.trialExpiresAt);
                if (owner && expirationDate > new Date()) {
                    owner.salvagedTime = { expiresAt: botToDelete.trialExpiresAt, isTrial: botToDelete.isTrial };
                    users[botToDelete.owner] = owner;
                    writeDB(USERS_DB_PATH, users);
                    socket.emit('feedback', { success: true, message: 'Bot excluído. O tempo restante foi salvo para o próximo bot que você criar.' });
                } else {
                    socket.emit('feedback', { success: true, message: 'Bot excluído.' });
                }
            } else {
                 socket.emit('feedback', { success: true, message: 'Bot Agregador excluído.' });
            }
            if (activeBots[sessionName]) {
                activeBots[sessionName].process.kill('SIGINT');
                delete activeBots[sessionName];
            }
            delete bots[sessionName];
            writeDB(BOTS_DB_PATH, bots);
            if (fs.existsSync(path.join(AUTH_SESSIONS_DIR, `auth_${sessionName}`))) {
                fs.rmSync(path.join(AUTH_SESSIONS_DIR, `auth_${sessionName}`), { recursive: true, force: true });
            }
            io.emit('bot-deleted', { sessionName });
        });

        socket.on('update-bot', (d) => {
            const bots = readDB(BOTS_DB_PATH);
            const bot = bots[d.sessionName];
            if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;
            if (bot) {
                bot.prompt = d.newPrompt;
                if (d.botType !== undefined) bot.botType = d.botType;
                
                bot.botName = d.botName;
                bot.silenceTime = d.silenceTime;

                writeDB(BOTS_DB_PATH, bots);
                io.emit('bot-updated', bot);
                if (activeBots[d.sessionName]) {
                    try { activeBots[d.sessionName].process.kill('SIGINT'); } catch (e) { console.error(`Erro ao parar ${d.sessionName} para update:`, e); }
                    delete activeBots[d.sessionName];
                    socket.emit('feedback', { success: true, message: 'Configurações salvas. Reiniciando o robô...' });
                    setTimeout(() => { startBotProcess(bot); }, 1000);
                } else {
                    socket.emit('feedback', { success: true, message: 'Configurações salvas com sucesso.' });
                }
            }
        });

        socket.on('update-ignored-identifiers', ({ sessionName, ignoredIdentifiers }) => {
            const bots = readDB(BOTS_DB_PATH);
            const bot = bots[sessionName];
            if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;
            bot.ignoredIdentifiers = ignoredIdentifiers;
            writeDB(BOTS_DB_PATH, bots);
            io.emit('bot-updated', bot);
            socket.emit('feedback', { success: true, message: 'Lista de ignorados salva. Reiniciando o bot...' });
            if (activeBots[sessionName]) {
                activeBots[sessionName].process.kill('SIGINT');
                setTimeout(() => startBotProcess(bot), 1000);
            }
        });
    }

    socket.on('group-activation-request', ({ groupId, groupName, activationToken, botSessionName }) => {
        console.log(`[SERVIDOR] Recebido 'group-activation-request' do bot ${botSessionName}.`);
        
        const tokenData = activationTokens[activationToken];

        if (!tokenData || tokenData.expiresAt < Date.now()) {
            console.error(`[SERVIDOR] Token inválido ou expirado.`);
            io.emit('group-activation-result', { 
                success: false, 
                groupId, 
                botSessionName, 
                message: 'Link de ativação expirado ou inválido.' 
            });
            return;
        }
        
        const { ownerEmail } = tokenData;
        delete activationTokens[activationToken]; 

        const users = readDB(USERS_DB_PATH);
        const groups = readDB(GROUPS_DB_PATH);

        if (!users[ownerEmail]) {
            io.emit('group-activation-result', { success: false, groupId, botSessionName, message: 'Usuário do token não encontrado.' });
            return;
        }
        if (groups[groupId]) {
            io.to(ownerEmail.toLowerCase()).emit('feedback', { success: false, message: `O grupo "${groupName}" já está cadastrado.` });
            io.emit('group-activation-result', { success: false, groupId, botSessionName, message: 'Grupo já cadastrado no painel.' });
            return;
        }

        const now = new Date();
        const trialExpire = new Date(now.getTime() + 24 * 60 * 60 * 1000); 

        const newGroup = {
            groupId: groupId,
            groupName: groupName,
            owner: ownerEmail,
            managedByBot: botSessionName,
            status: "active", 
            antiLink: false, 
            createdAt: now.toISOString(),
            expiresAt: trialExpire.toISOString(),
            prompt: "",
            silenceTime: 0,
            botName: "",
            isPaused: false
        };

        groups[groupId] = newGroup;
        writeDB(GROUPS_DB_PATH, groups);
        console.log(`[SERVIDOR] Grupo '${groupName}' ativado (Trial 24h). Dono: ${ownerEmail}.`);

        io.to(ownerEmail.toLowerCase()).emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH)).filter(g => g.owner === ownerEmail));
        io.to(ownerEmail.toLowerCase()).emit('feedback', { success: true, message: `Grupo "${groupName}" ativado! Verifique o card do robô.` });

        io.emit('group-activation-result', { 
            success: true, 
            groupId: groupId, 
            botSessionName: botSessionName,
            expiresAt: newGroup.expiresAt,
            message: 'Grupo ativado.'
        });
    });
});

function startBotProcess(bot, phoneNumber = null) {
    if (activeBots[bot.sessionName]) return; 

    const env = { ...process.env, API_KEYS_GEMINI: process.env.API_KEYS_GEMINI };
    const ignoredIdentifiersArg = JSON.stringify(bot.ignoredIdentifiers || []);
    
    const phoneArg = phoneNumber ? phoneNumber : 'null';

    const args = [
        BOT_SCRIPT_PATH,
        bot.sessionName,
        bot.prompt,
        ignoredIdentifiersArg,
        phoneArg,
    ];

    let authorizedGroupsArg = '[]';
    if (bot.botType === 'group') {
        const allGroups = readDB(GROUPS_DB_PATH);
        const authorizedGroups = Object.values(allGroups)
            .filter(g => g.managedByBot === bot.sessionName && g.status === 'active')
            .map(g => ({ 
                groupId: g.groupId, 
                expiresAt: g.expiresAt, 
                antiLink: g.antiLink,
                prompt: g.prompt,
                silenceTime: g.silenceTime,
                botName: g.botName,
                isPaused: g.isPaused
            }));
        authorizedGroupsArg = JSON.stringify(authorizedGroups);
    }
    
    args.push(authorizedGroupsArg);
    args.push(bot.botType || 'individual');
    
    args.push(bot.botName || '');
    args.push(bot.silenceTime || '0');
    
    args.push(bot.platform || 'whatsapp');
    args.push(bot.token || '');

    const p = spawn('node', args, { env, stdio: ['pipe', 'pipe', 'pipe'] });

    activeBots[bot.sessionName] = { process: p };
    updateBotStatus(bot.sessionName, 'Iniciando...');

    p.stdout.on('data', (d) => {
        const msg = d.toString().trim();

        if (msg.startsWith('QR_CODE:')) {
            updateBotStatus(bot.sessionName, 'Aguardando QR Code', { qr: msg.replace('QR_CODE:', '') });
        } else if (msg.startsWith('PAIRING_CODE:')) {
            updateBotStatus(bot.sessionName, 'Aguardando QR Code', { qr: msg });
        } else if (msg.includes('ONLINE!')) {
            updateBotStatus(bot.sessionName, 'Online', { setActivated: true });
        }
        io.emit('log-message', { sessionName: bot.sessionName, message: msg });
    });
    p.stderr.on('data', (d) => io.emit('log-message', { sessionName: bot.sessionName, message: `ERRO: ${d}` }));
    
    p.on('close', (code) => {
        console.log(`[PROCESS] ${bot.sessionName} fechou com código ${code}`);
        delete activeBots[bot.sessionName];
        updateBotStatus(bot.sessionName, 'Offline');
    });
}


function updateBotStatus(name, status, options = {}) {
    const bots = readDB(BOTS_DB_PATH);
    const bot = bots[name];
    if (bot) {
        bot.status = status;

        if (options.qr !== undefined) {
            bot.qr = options.qr;
        } else if (status !== 'Aguardando QR Code') {
            bot.qr = null;
        }

        if (options.setActivated && !bot.activated) {
            bot.activated = true;

            const users = readDB(USERS_DB_PATH);
            const ownerData = users[bot.owner];
            if (ownerData && !ownerData.isAdmin && bot.isTrial && !ownerData.trialUsed) {
                ownerData.trialUsed = true;
                writeDB(USERS_DB_PATH, users);
            }
        }

        writeDB(BOTS_DB_PATH, bots);
        io.emit('bot-updated', bot);
    }
}

function restartActiveBots() {
    const bots = readDB(BOTS_DB_PATH);
    console.log('[SISTEMA] Verificando bots para reiniciar...');

    Object.values(bots).forEach(bot => {
        if (bot.status === 'Online' || bot.status.includes('Iniciando') || bot.status.includes('Aguardando')) {
            const now = new Date();
            const expires = new Date(bot.trialExpiresAt);

            if (expires > now) {
                console.log(`[RESTART] Reiniciando bot: ${bot.sessionName}`);
                startBotProcess(bot);
            } else {
                console.log(`[RESTART] Bot ${bot.sessionName} expirou, não será reiniciado.`);
                bot.status = 'Offline';
            }
        }
    });
    writeDB(BOTS_DB_PATH, bots);
}

server.listen(3000, () => {
    console.log('Painel ON: http://localhost:3000');
    restartActiveBots();
});

