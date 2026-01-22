const express = require('express');
const http = require('http');
const { Server } = require('socket.io');
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');
const session = require('express-session');
const bcrypt = require('bcrypt');
const FileStore = require('session-file-store')(session);
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { MercadoPagoConfig, Payment } = require('mercadopago');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// --- CONFIGURAÇÃO E BANCOS DE DADOS ---
const BOTS_DB_PATH = './bots.json';
const USERS_DB_PATH = './users.json';
const IPS_DB_PATH = './ips.json';
const SETTINGS_DB_PATH = './settings.json';
const AUTH_SESSIONS_DIR = path.join(__dirname, 'auth_sessions');
const SESSION_FILES_DIR = path.join(__dirname, 'sessions');

const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
const CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "https://zappbot.shop/auth/google/callback";

app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

const sessionMiddleware = session({
    store: new FileStore({ path: SESSION_FILES_DIR, logFn: function () { } }),
    secret: 'sua-chave-secreta-muito-forte-e-diferente',
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 1000 * 60 * 60 * 24 * 7 }
});

app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

io.engine.use(sessionMiddleware);

// --- INICIALIZAÇÃO DE ARQUIVOS ---
if (!fs.existsSync(AUTH_SESSIONS_DIR)) fs.mkdirSync(AUTH_SESSIONS_DIR, { recursive: true });
if (!fs.existsSync(SESSION_FILES_DIR)) fs.mkdirSync(SESSION_FILES_DIR, { recursive: true });

const readDB = (path) => fs.existsSync(path) ? JSON.parse(fs.readFileSync(path, 'utf-8')) : {};
const writeDB = (path, data) => fs.writeFileSync(path, JSON.stringify(data, null, 2), 'utf-8');

if (!fs.existsSync(SETTINGS_DB_PATH)) {
    writeDB(SETTINGS_DB_PATH, {
        mpAccessToken: "", priceMonthly: "29.90", priceQuarterly: "79.90",
        priceSemiannual: "149.90", priceYearly: "289.90",
        priceResell5: "100.00", priceResell10: "180.00", priceResell20: "300.00", priceResell30: "400.00"
    });
}
if (!fs.existsSync(IPS_DB_PATH)) writeDB(IPS_DB_PATH, {});

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

// --- GOOGLE AUTH ---
if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({ clientID: GOOGLE_CLIENT_ID, clientSecret: GOOGLE_CLIENT_SECRET, callbackURL: CALLBACK_URL, passReqToCallback: true },
        async (req, accessToken, refreshToken, profile, done) => {
            try {
                const users = readDB(USERS_DB_PATH);
                const ips = readDB(IPS_DB_PATH);
                const userIp = getClientIp(req);
                const username = profile.emails[0].value;

                if (users[username]) return done(null, users[username]);

                if (ips[userIp]) {
                    return done(null, false, { message: "Você já criou uma conta neste dispositivo/rede." });
                }

                const isAdmin = Object.keys(users).length === 0;
                const newUser = {
                    username, password: null, googleId: profile.id, displayName: profile.displayName,
                    createdAt: new Date(), isAdmin, botLimit: isAdmin ? 999 : 1, log: [],
                    trialUsed: false, trialExpiresAt: null
                };

                users[username] = newUser;
                ips[userIp] = username;

                writeDB(USERS_DB_PATH, users);
                writeDB(IPS_DB_PATH, ips);
                addUserLog(username, `Conta Google criada. IP: ${userIp}`);
                return done(null, newUser);
            } catch (err) { return done(err, null); }
        }));
    passport.serializeUser((user, done) => done(null, user.username));
    passport.deserializeUser((username, done) => { const u = readDB(USERS_DB_PATH)[username]; done(u ? null : new Error("Not found"), u); });
}

// --- PAGAMENTO ---
app.post('/api/create-payment', async (req, res) => {
    if (!req.session.user) return res.status(401).json({ error: 'Não autorizado' });
    const settings = readDB(SETTINGS_DB_PATH);
    const { sessionName, planType } = req.body;
    if (!settings.mpAccessToken) return res.status(500).json({ error: 'Erro config pagamento.' });

    let amount = 0, desc = '', extRef = '';

    if (planType && planType.startsWith('resell_')) {
        if (planType === 'resell_5') amount = parseFloat(settings.priceResell5);
        if (planType === 'resell_10') amount = parseFloat(settings.priceResell10);
        if (planType === 'resell_20') amount = parseFloat(settings.priceResell20);
        if (planType === 'resell_30') amount = parseFloat(settings.priceResell30);
        desc = `Upgrade: ${planType}`; extRef = `${req.session.user.username}|${planType}`;
    } else {
        if (planType === 'monthly') amount = parseFloat(settings.priceMonthly);
        if (planType === 'quarterly') amount = parseFloat(settings.priceQuarterly);
        if (planType === 'semiannual') amount = parseFloat(settings.priceSemiannual);
        if (planType === 'yearly') amount = parseFloat(settings.priceYearly);
        desc = `Renova: ${sessionName}`; extRef = `${sessionName}|${planType}`;
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
                const ref1 = parts[0], ref2 = parts[1];
                const users = readDB(USERS_DB_PATH);

                if (ref2.startsWith('resell_')) {
                    if (users[ref1]) {
                        users[ref1].botLimit = parseInt(ref2.split('_')[1]);
                        users[ref1].trialUsed = true;
                        users[ref1].trialExpiresAt = "PAID_USER";
                        writeDB(USERS_DB_PATH, users);
                        const sockets = await io.fetchSockets();
                        sockets.forEach(s => { if (s.request.session.user?.username === ref1) s.emit('update-limit', users[ref1].botLimit); });
                    }
                } else {
                    const bots = readDB(BOTS_DB_PATH);
                    const bot = bots[ref1];
                    if (bot && users[bot.owner]) {
                        const owner = users[bot.owner];
                        const now = new Date();
                        const currentExpire = new Date(bot.trialExpiresAt);
                        
                        let days = 30;
                        if (ref2 === 'quarterly') days = 90;
                        if (ref2 === 'semiannual') days = 180;
                        if (ref2 === 'yearly') days = 365;

                        let baseDate = (!isNaN(currentExpire) && currentExpire > now) ? currentExpire : now;
                        baseDate.setDate(baseDate.getDate() + days);

                        bot.trialExpiresAt = baseDate.toISOString();
                        bot.isTrial = false;
                        if (!bot.activated) bot.activated = true;

                        writeDB(BOTS_DB_PATH, bots);
                        
                        io.emit('bot-updated', bot);
                        io.emit('payment-success', { sessionName: ref1 });
                    }
                }
            }
        } catch (e) { /* Silencia erros de webhook */ }
    }
    res.sendStatus(200);
});

// --- ROTAS PADRÃO ---
app.get('/', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.post('/register', async (req, res) => {
    let users = readDB(USERS_DB_PATH);
    let ips = readDB(IPS_DB_PATH);
    const { username, password } = req.body;
    const userIp = getClientIp(req);

    if (users[username]) return res.status(400).json({ message: "Usuário já existe." });
    if (ips[userIp]) return res.status(403).json({ message: "Limite de contas atingido para este IP." });

    const isAdmin = Object.keys(users).length === 0;
    users[username] = {
        username, password: await bcrypt.hash(password, 10), createdAt: new Date(), isAdmin,
        botLimit: isAdmin ? 999 : 1, log: [], trialUsed: false, trialExpiresAt: null
    };

    if (!isAdmin) ips[userIp] = username;

    writeDB(USERS_DB_PATH, users);
    writeDB(IPS_DB_PATH, ips);
    res.status(201).json({ message: "OK" });
});

app.post('/login', async (req, res) => {
    const u = readDB(USERS_DB_PATH)[req.body.username];
    if (!u || !await bcrypt.compare(req.body.password, u.password)) return res.status(401).json({ message: "Credenciais inválidas" });
    req.session.user = { username: u.username, isAdmin: !!u.isAdmin }; res.status(200).json({ message: "OK" });
});

app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback', passport.authenticate('google', { failureRedirect: '/' }), (req, res) => { req.session.user = { username: req.user.username, isAdmin: !!req.user.isAdmin }; res.redirect('/'); });
app.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));
app.get('/check-session', (req, res) => {
    if (req.session.user) {
        const u = readDB(USERS_DB_PATH)[req.session.user.username];
        res.json({ loggedIn: true, user: { ...req.session.user, botLimit: u ? (u.botLimit || 1) : 1 } });
    } else res.status(401).json({ loggedIn: false });
});

io.use((socket, next) => {
    const u = socket.request.session.user || (socket.request.session.passport?.user);
    if (u) { socket.request.session.user = { username: u.username || u, isAdmin: readDB(USERS_DB_PATH)[u.username || u]?.isAdmin }; next(); }
    else next(new Error('Auth error'));
});

// --- SOCKET ---
io.on('connection', (socket) => {
    const user = socket.request.session.user;
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
                const now = new Date();
                let base = new Date(bot.trialExpiresAt);

                if (isNaN(base) || base < now) base = now;
                
                base.setDate(base.getDate() + parseInt(days));

                bot.trialExpiresAt = base.toISOString();
                bot.activated = true;
                bot.isTrial = false;

                writeDB(BOTS_DB_PATH, bots);
                io.emit('bot-updated', bot);
            }
        });

        socket.on('admin-get-users', () => socket.emit('admin-users-list', Object.values(readDB(USERS_DB_PATH)).map(({ password, ...r }) => r)));
        socket.on('admin-delete-user', ({ username }) => {
            const users = readDB(USERS_DB_PATH);
            const ips = readDB(IPS_DB_PATH);
            for (let ip in ips) { if (ips[ip] === username) delete ips[ip]; }
            delete users[username];
            writeDB(USERS_DB_PATH, users);
            writeDB(IPS_DB_PATH, ips);
            socket.emit('admin-users-list', Object.values(users).map(({ password, ...r }) => r));
        });
        socket.on('admin-get-bots-for-user', ({ username }) => socket.emit('initial-bots-list', Object.values(readDB(BOTS_DB_PATH)).filter(b => b.owner === username)));
    }

    socket.on('get-my-bots', () => { if (!user.isAdmin) socket.emit('initial-bots-list', Object.values(readDB(BOTS_DB_PATH)).filter(b => b.owner === user.username)); });

    socket.on('create-bot', (d) => {
        const bots = readDB(BOTS_DB_PATH);
        const users = readDB(USERS_DB_PATH);
        const owner = (user.isAdmin && d.owner) ? d.owner : user.username;
        const ownerData = users[owner];

        if (bots[d.sessionName]) return socket.emit('feedback', { success: false, message: 'Nome de robô já em uso.' });

        if (Object.values(bots).filter(b => b.owner === owner).length >= (ownerData.botLimit || 1) && !ownerData.isAdmin) {
            return socket.emit('feedback', { success: false, error: 'limit_reached' });
        }
        
        const now = new Date();
        let trialEndDate = new Date(now);
        let isTrial = false;

        if (ownerData.isAdmin || !ownerData.trialUsed) {
            trialEndDate.setHours(trialEndDate.getHours() + 24);
            isTrial = true;
            if(!ownerData.isAdmin) {
                 ownerData.trialUsed = true;
                 users[owner] = ownerData;
                 writeDB(USERS_DB_PATH, users);
            }
        } else {
            trialEndDate = new Date(0); // Expired
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
            ignoredIdentifiers: []
        };

        bots[d.sessionName] = newBot;
        writeDB(BOTS_DB_PATH, bots);
        io.emit('bot-updated', newBot);

        const canStart = new Date(newBot.trialExpiresAt) > new Date();
        if (canStart) {
            startBotProcess(newBot);
            socket.emit('feedback', { success: true, message: 'Robô criado e iniciando...' });
        } else {
            socket.emit('feedback', { success: true, message: 'Robô criado, mas seu período de teste expirou. Renove para usar.' });
        }
    });

    socket.on('start-bot', ({ sessionName }) => {
        const bots = readDB(BOTS_DB_PATH);
        const bot = bots[sessionName];
        if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;

        if (new Date(bot.trialExpiresAt) < new Date()) {
            return socket.emit('feedback', { success: false, message: 'Robô expirado. Renove para ligar.' });
        }

        if (activeBots[sessionName]) return socket.emit('feedback', { success: false, message: 'O robô já está rodando.' });

        startBotProcess(bot);
        socket.emit('feedback', { success: true, message: 'Iniciando o robô...' });
    });

    socket.on('stop-bot', ({ sessionName }) => {
        if (activeBots[sessionName]) { activeBots[sessionName].process.kill('SIGINT'); delete activeBots[sessionName]; }
        updateBotStatus(sessionName, 'Offline');
        socket.emit('feedback', { success: true, message: 'Robô parado.' });
    });

    socket.on('delete-bot', ({ sessionName }) => {
        const bots = readDB(BOTS_DB_PATH);
        if (activeBots[sessionName]) { activeBots[sessionName].process.kill('SIGINT'); delete activeBots[sessionName]; }
        delete bots[sessionName];
        writeDB(BOTS_DB_PATH, bots);
        if (fs.existsSync(path.join(AUTH_SESSIONS_DIR, `auth_${sessionName}`))) fs.rmSync(path.join(AUTH_SESSIONS_DIR, `auth_${sessionName}`), { recursive: true });
        io.emit('bot-deleted', { sessionName });
    });

    socket.on('update-bot', (d) => {
        const bots = readDB(BOTS_DB_PATH);
        if (bots[d.sessionName]) {
            bots[d.sessionName].prompt = d.newPrompt;
            writeDB(BOTS_DB_PATH, bots);
            io.emit('bot-updated', bots[d.sessionName]);
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
});


function startBotProcess(bot) {
    const env = { ...process.env, API_KEYS_GEMINI: process.env.API_KEYS_GEMINI };
    const ignoredIdentifiersArg = JSON.stringify(bot.ignoredIdentifiers || []);
    const p = spawn('node', ['index.js', bot.sessionName, bot.prompt, ignoredIdentifiersArg], { env, stdio: ['pipe', 'pipe', 'pipe'] });

    activeBots[bot.sessionName] = { process: p };
    updateBotStatus(bot.sessionName, 'Iniciando...');

    p.stdout.on('data', (d) => {
        const msg = d.toString().trim();

        if (msg.startsWith('QR_CODE:')) {
            updateBotStatus(bot.sessionName, 'Aguardando QR Code', msg.replace('QR_CODE:', ''));
        } else if (msg.includes('ONLINE!')) {
            const bots = readDB(BOTS_DB_PATH);
            const currentBot = bots[bot.sessionName];

            if (!currentBot.activated) {
                currentBot.activated = true;
                writeDB(BOTS_DB_PATH, bots);
                io.emit('bot-updated', currentBot);
            }
            updateBotStatus(bot.sessionName, 'Online');
        }
        io.emit('log-message', { sessionName: bot.sessionName, message: msg });
    });
    p.stderr.on('data', (d) => io.emit('log-message', { sessionName: bot.sessionName, message: `ERRO: ${d}` }));
    p.on('close', () => {
        delete activeBots[bot.sessionName];
        updateBotStatus(bot.sessionName, 'Offline');
    });
}


function updateBotStatus(name, status, qr = null) {
    const bots = readDB(BOTS_DB_PATH);
    if (bots[name]) {
        bots[name].status = status;
        if (qr) bots[name].qr = qr;
        writeDB(BOTS_DB_PATH, bots);
        io.emit('bot-updated', bots[name]);
    }
}

server.listen(3000, () => console.log('Painel ON: http://localhost:3000'));
