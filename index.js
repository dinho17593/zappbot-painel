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
const CALLBACK_URL = process.env.GOOGLE_CALLBACK_URL || "/auth/google/callback";
const SESSION_SECRET = process.env.SESSION_SECRET || 'sua-chave-secreta-muito-forte-e-diferente';

const activationTokens = {};

app.set('trust proxy', true);
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(SESSION_SECRET));

// Desativa cache para arquivos estáticos sensíveis, se houver
app.use(express.static(BASE_DIR, {
    etag: false,
    lastModified: false,
    setHeaders: (res, path) => {
        if (path.endsWith('.html')) {
            res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
        }
    }
}));

const sessionMiddleware = session({
    store: new FileStore({ 
        path: SESSION_FILES_DIR, 
        logFn: function () { },
        retries: 1,
        ttl: 86400 * 7
    }),
    name: 'zappbot.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false,
        httpOnly: true,
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
    appName: "zappbot",
    mpAccessToken: "", 
    supportNumber: "5524999842338",
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

app.get('/manifest.json', (req, res) => {
    const settings = readDB(SETTINGS_DB_PATH);
    const appName = settings.appName || 'zappbot';
    
    res.json({
        "name": appName,
        "short_name": appName,
        "start_url": "/",
        "display": "standalone",
        "background_color": "#09090b",
        "theme_color": "#121214",
        "orientation": "portrait",
        "icons": [
            {
                "src": "/icon-192x192.png",
                "sizes": "192x192",
                "type": "image/png",
                "purpose": "any maskable"
            },
            {
                "src": "/icon-512x512.png",
                "sizes": "512x512",
                "type": "image/png",
                "purpose": "any maskable"
            }
        ]
    });
});

app.post('/api/admin/upload-icons', upload.fields([{ name: 'iconSmall' }, { name: 'iconLarge' }]), (req, res) => {
    if (!req.session.user || !req.session.user.isAdmin) {
        return res.status(403).json({ success: false, message: 'Acesso negado.' });
    }

    try {
        if (req.files['iconSmall']) {
            const tempPath = req.files['iconSmall'][0].path;
            const targetPath = path.join(BASE_DIR, 'icon-192x192.png');
            if(fs.existsSync(path.join(BASE_DIR, 'icon-192×192.png'))) fs.unlinkSync(path.join(BASE_DIR, 'icon-192×192.png'));
            if(fs.existsSync(targetPath)) fs.unlinkSync(targetPath);
            fs.renameSync(tempPath, targetPath);
        }

        if (req.files['iconLarge']) {
            const tempPath = req.files['iconLarge'][0].path;
            const targetPath = path.join(BASE_DIR, 'icon-512x512.png');
            if(fs.existsSync(path.join(BASE_DIR, 'icon-512×512.png'))) fs.unlinkSync(path.join(BASE_DIR, 'icon-512×512.png'));
            if(fs.existsSync(targetPath)) fs.unlinkSync(targetPath);
            fs.renameSync(tempPath, targetPath);
        }

        res.json({ success: true, message: 'Ícones atualizados com sucesso! A página será recarregada.' });
    } catch (error) {
        console.error('Erro upload icones:', error);
        res.status(500).json({ success: false, message: 'Erro ao processar imagens.' });
    }
});

app.get('/api/admin/backup', (req, res) => {
    // Removida a verificação de isAdmin para permitir backup para todos
    if (!req.session.user) return res.status(401).send('Acesso negado');

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
    // Removida a verificação de isAdmin para permitir restauração para todos
    if (!req.session.user) return res.status(401).json({ error: 'Acesso negado' });
    if (!req.file) return res.status(400).json({ error: 'Nenhum arquivo enviado' });

    try {
        const zip = new AdmZip(req.file.path);
        zip.extractAllTo(BASE_DIR, true);
        fs.unlinkSync(req.file.path);

        console.log('[BACKUP] Restauração concluída. Reiniciando bots...');
        
        Object.keys(activeBots).forEach(sessionName => {
            if (activeBots[sessionName]) {
                activeBots[sessionName].intentionalStop = true; 
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
    
    const activationLink = `https://${req.get('host')}/ativar?token=${token}`;
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
                notification_url: `https://${req.get('host')}/webhook/mercadopago`
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
                            activeBots[botSessionName].intentionalStop = true;
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

// Rota de Logout corrigida para limpar cookies e destruir sessão
app.get('/logout', (req, res) => {
    req.session.destroy((err) => {
        res.clearCookie('zappbot.sid'); // Limpa o cookie da sessão
        res.redirect('/');
    });
});

// Rota de verificação de sessão com Cache-Control agressivo
app.get('/check-session', (req, res) => {
    // Impede que o navegador faça cache desta resposta
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
    res.set('Pragma', 'no-cache');
    res.set('Expires', '0');
    res.set('Surrogate-Control', 'no-store');

    if (req.session.user) {
        const users = readDB(USERS_DB_PATH);
        const u = users[req.session.user.username.toLowerCase()];
        
        if (u) {
            req.session.user.isAdmin = u.isAdmin;
            res.json({ loggedIn: true, user: { ...req.session.user, botLimit: u.botLimit || 1 } });
        } else {
            // Usuário na sessão não existe mais no DB (Sessão Zumbi)
            req.session.destroy();
            res.clearCookie('zappbot.sid');
            res.status(401).json({ loggedIn: false });
        }
    } else {
        res.status(401).json({ loggedIn: false });
    }
});

// Middleware do Socket.IO corrigido para rejeitar conexões inválidas
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
            // Usuário não encontrado no DB, rejeita conexão
            next(new Error('Authentication error'));
        }
    } else {
        next();
    }
});

io.on('connection', (socket) => {
    const user = socket.request.session.user;
    
    socket.on('get-public-prices', () => {
        const s = readDB(SETTINGS_DB_PATH);
        socket.emit('public-prices', { 
            appName: s.appName || 'zappbot',
            supportNumber: s.supportNumber,
            priceMonthly: s.priceMonthly, 
            priceQuarterly: s.priceQuarterly, 
            priceSemiannual: s.priceSemiannual, 
            priceYearly: s.priceYearly, 
            priceResell5: s.priceResell5, 
            priceResell10: s.priceResell10, 
            priceResell20: s.priceResell20, 
            priceResell30: s.priceResell30 
        });
    });

    socket.on('bot-online', ({ sessionName }) => {
        updateBotStatus(sessionName, 'Online', { setActivated: true });
    });

    socket.on('bot-identified', ({ sessionName, publicName }) => {
        const bots = readDB(BOTS_DB_PATH);
        if (bots[sessionName]) {
            bots[sessionName].publicName = publicName;
            writeDB(BOTS_DB_PATH, bots);
            io.emit('bot-updated', bots[sessionName]);
        }
    });

    socket.on('update-group-settings', (data) => {
        const groups = readDB(GROUPS_DB_PATH);
        if (groups[data.groupId]) {
            groups[data.groupId] = { ...groups[data.groupId], ...data.settings };
            writeDB(GROUPS_DB_PATH, groups);
            
            io.to(groups[data.groupId].owner.toLowerCase()).emit('group-list-updated', Object.values(groups).filter(g => g.owner === groups[data.groupId].owner));
            
            const botSessionName = groups[data.groupId].managedByBot;
            io.emit('group-settings-changed', {
                botSessionName: botSessionName,
                groupId: data.groupId,
                settings: groups[data.groupId]
            });
        }
    });

    // EVENTO ADICIONADO: Atualização interna vinda do processo do bot (sem sessão de admin)
    socket.on('bot-update-ignored', ({ sessionName, type, value }) => {
        const bots = readDB(BOTS_DB_PATH);
        const bot = bots[sessionName];
        if (bot) {
            if (!bot.ignoredIdentifiers) bot.ignoredIdentifiers = [];
            
            // Verifica duplicidade
            const exists = bot.ignoredIdentifiers.some(i => i.type === type && i.value.toLowerCase() === value.toLowerCase());
            
            if (!exists) {
                bot.ignoredIdentifiers.push({ type, value });
                writeDB(BOTS_DB_PATH, bots);
                
                // Notifica o frontend
                io.emit('bot-updated', bot);
                
                // Retorna confirmação para o próprio bot atualizar sua memória local, caso não tenha sido ele que enviou
                // (embora o bot já tenha atualizado localmente antes de emitir, é bom garantir sync)
                // io.emit('ignored-list-updated', { sessionName, ignoredIdentifiers: bot.ignoredIdentifiers });
            }
        }
    });

    socket.on('group-activation-request', ({ groupId, groupName, activationToken, botSessionName }) => {
        const tokenData = activationTokens[activationToken];

        if (!tokenData || tokenData.expiresAt < Date.now()) {
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

    if (user) {
        socket.join(user.username.toLowerCase());
        const uData = readDB(USERS_DB_PATH)[user.username];
        socket.emit('session-info', { username: user.username, isAdmin: user.isAdmin, botLimit: uData?.botLimit || 1 });

        if (user.isAdmin) {
            socket.on('admin-settings', (s) => socket.emit('admin-settings', readDB(SETTINGS_DB_PATH)));
            socket.on('save-settings', (ns) => { 
                writeDB(SETTINGS_DB_PATH, ns); 
                socket.emit('feedback', { success: true, message: 'Salvo' }); 
                io.emit('public-prices', { 
                    appName: ns.appName,
                    supportNumber: ns.supportNumber,
                    priceMonthly: ns.priceMonthly, 
                    priceQuarterly: ns.priceQuarterly, 
                    priceSemiannual: ns.priceSemiannual, 
                    priceYearly: ns.priceYearly, 
                    priceResell5: ns.priceResell5, 
                    priceResell10: ns.priceResell10, 
                    priceResell20: ns.priceResell20, 
                    priceResell30: ns.priceResell30 
                }); 
            });

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
                    socket.emit('feedback', { success: true, message: 'Dias definidos.' });

                    const botSessionName = group.managedByBot;
                    if (activeBots[botSessionName]) {
                        activeBots[botSessionName].intentionalStop = true;
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
            
            io.emit('group-removed', { botSessionName, groupId });

            socket.emit('group-list-updated', Object.values(groups).filter(g => g.owner === user.username));
            socket.emit('feedback', { success: true, message: 'Grupo removido.' });
            
            if (activeBots[botSessionName]) {
                activeBots[botSessionName].intentionalStop = true;
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
                    return socket.emit('feedback', { success: false, message: 'Dono não encontrado.' });
                }

                if (bots[d.sessionName]) return socket.emit('feedback', { success: false, message: 'Nome em uso.' });
                
                if (d.botType !== 'group' && Object.values(bots).filter(b => b.owner === owner && b.botType !== 'group').length >= (ownerData.botLimit || 1) && !ownerData.isAdmin) {
                    return socket.emit('feedback', { success: false, error: 'limit_reached' });
                }

                const now = new Date();
                let trialEndDate = new Date(0);
                let isTrial = false;
                let feedbackMessage = 'Criado. Pague para ativar.';
                
                if (d.botType !== 'group') {
                    if (ownerData.salvagedTime && new Date(ownerData.salvagedTime.expiresAt) > now) {
                        trialEndDate = new Date(ownerData.salvagedTime.expiresAt);
                        isTrial = ownerData.salvagedTime.isTrial;
                        ownerData.salvagedTime = null;
                        users[owner] = ownerData;
                        writeDB(USERS_DB_PATH, users);
                        feedbackMessage = 'Restaurado tempo anterior.';
                    } else {
                        if (ownerData.isAdmin || !ownerData.trialUsed) {
                            trialEndDate = new Date(now);
                            trialEndDate.setHours(trialEndDate.getHours() + 24);
                            isTrial = true;
                            feedbackMessage = 'Criado (Teste Grátis).';
                        }
                    }
                } else {
                    trialEndDate = new Date(now);
                    trialEndDate.setFullYear(trialEndDate.getFullYear() + 10);
                    isTrial = false;
                    feedbackMessage = 'Agregador criado!';
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
                    token: d.token || '', 
                    notificationNumber: '', 
                    publicName: '' 
                };

                bots[d.sessionName] = newBot;
                writeDB(BOTS_DB_PATH, bots);
                io.emit('bot-updated', newBot);
                
                if (new Date(newBot.trialExpiresAt) > new Date()) {
                    startBotProcess(newBot);
                }
                socket.emit('feedback', { success: true, message: feedbackMessage });
            } catch (err) {
                console.error("Erro criar bot:", err);
                socket.emit('feedback', { success: false, message: 'Erro interno.' });
            }
        });

        socket.on('start-bot', ({ sessionName, phoneNumber }) => {
            const bots = readDB(BOTS_DB_PATH);
            const bot = bots[sessionName];
            if (!bot || (!user.isAdmin && bot.owner !== user.username)) return;
            if (new Date(bot.trialExpiresAt) < new Date()) {
                return socket.emit('feedback', { success: false, message: 'Expirado.' });
            }
            if (activeBots[sessionName]) return socket.emit('feedback', { success: false, message: 'Já rodando.' });
            
            let cleanPhone = phoneNumber ? phoneNumber.replace(/\D/g, '') : null;
            
            startBotProcess(bot, cleanPhone);
            socket.emit('feedback', { success: true, message: 'Iniciando...' });
        });

        socket.on('stop-bot', ({ sessionName }) => {
            if (activeBots[sessionName]) { 
                try {
                    activeBots[sessionName].intentionalStop = true; 
                    activeBots[sessionName].process.kill('SIGINT'); 
                } catch(e) {}
                delete activeBots[sessionName]; 
            }
            updateBotStatus(sessionName, 'Offline');
            socket.emit('feedback', { success: true, message: 'Parado.' });
        });

        socket.on('delete-bot', ({ sessionName }) => {
            let bots = readDB(BOTS_DB_PATH);
            let users = readDB(USERS_DB_PATH);
            const botToDelete = bots[sessionName];
            if (!botToDelete || (!user.isAdmin && botToDelete.owner !== user.username)) return;
            
            if (botToDelete.botType === 'group') {
                let groups = readDB(GROUPS_DB_PATH);
                let groupsChanged = false;
                
                Object.keys(groups).forEach(groupId => {
                    if (groups[groupId].managedByBot === sessionName) {
                        delete groups[groupId];
                        groupsChanged = true;
                    }
                });

                if (groupsChanged) {
                    writeDB(GROUPS_DB_PATH, groups);
                    io.emit('group-list-updated', Object.values(readDB(GROUPS_DB_PATH)));
                }
            }

            if (botToDelete.botType !== 'group') {
                const owner = users[botToDelete.owner];
                if (owner && new Date(botToDelete.trialExpiresAt) > new Date()) {
                    owner.salvagedTime = { expiresAt: botToDelete.trialExpiresAt, isTrial: botToDelete.isTrial };
                    users[botToDelete.owner] = owner;
                    writeDB(USERS_DB_PATH, users);
                }
            }
            
            if (activeBots[sessionName]) {
                activeBots[sessionName].intentionalStop = true;
                activeBots[sessionName].process.kill('SIGINT');
                delete activeBots[sessionName];
            }

            delete bots[sessionName];
            writeDB(BOTS_DB_PATH, bots);

            const authPath = path.join(AUTH_SESSIONS_DIR, `auth_${sessionName}`);
            if (fs.existsSync(authPath)) {
                fs.rmSync(authPath, { recursive: true, force: true });
            }

            io.emit('bot-deleted', { sessionName });
            socket.emit('feedback', { success: true, message: 'Excluído.' });
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
                bot.notificationNumber = d.notificationNumber;

                writeDB(BOTS_DB_PATH, bots);
                io.emit('bot-updated', bot);
                if (activeBots[d.sessionName]) {
                    try { 
                        activeBots[d.sessionName].intentionalStop = true;
                        activeBots[d.sessionName].process.kill('SIGINT'); 
                    } catch (e) {}
                    delete activeBots[d.sessionName];
                    socket.emit('feedback', { success: true, message: 'Salvo. Reiniciando...' });
                    setTimeout(() => { startBotProcess(bot); }, 1000);
                } else {
                    socket.emit('feedback', { success: true, message: 'Salvo.' });
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
            socket.emit('feedback', { success: true, message: 'Ignorados salvos. Reiniciando...' });
            if (activeBots[sessionName]) {
                activeBots[sessionName].intentionalStop = true;
                activeBots[sessionName].process.kill('SIGINT');
                setTimeout(() => startBotProcess(bot), 1000);
            }
        });
    }
});

function startBotProcess(bot, phoneNumber = null) {
    if (activeBots[bot.sessionName]) return; 

    const env = { ...process.env, API_KEYS_GEMINI: process.env.API_KEYS_GEMINI };
    
    const promptBase64 = Buffer.from(bot.prompt || '').toString('base64');
    const ignoredBase64 = Buffer.from(JSON.stringify(bot.ignoredIdentifiers || [])).toString('base64');
    const phoneArg = phoneNumber ? phoneNumber : 'null';

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
    const groupsBase64 = Buffer.from(authorizedGroupsArg).toString('base64');
    
    const args = [
        BOT_SCRIPT_PATH,
        bot.sessionName,
        promptBase64, 
        ignoredBase64, 
        phoneArg,
        groupsBase64, 
        bot.botType || 'individual',
        bot.botName || '',
        (bot.silenceTime || '0').toString(),
        bot.platform || 'whatsapp',
        bot.token || '',
        bot.notificationNumber || ''
    ];

    const p = spawn('node', args, { env, stdio: ['pipe', 'pipe', 'pipe'] });

    activeBots[bot.sessionName] = { process: p, intentionalStop: false };
    updateBotStatus(bot.sessionName, 'Iniciando...');

    p.stdout.on('data', (d) => {
        const msg = d.toString().trim();

        if (msg.startsWith('QR_CODE:')) {
            updateBotStatus(bot.sessionName, 'Aguardando QR Code', { qr: msg.replace('QR_CODE:', '') });
        } else if (msg.startsWith('PAIRING_CODE:')) {
            updateBotStatus(bot.sessionName, 'Aguardando QR Code', { qr: msg });
        } else if (msg.includes('ONLINE!') || msg.includes('Conectado ao servidor via Socket.IO')) {
            updateBotStatus(bot.sessionName, 'Online', { setActivated: true });
        }
        io.emit('log-message', { sessionName: bot.sessionName, message: msg });
    });
    p.stderr.on('data', (d) => io.emit('log-message', { sessionName: bot.sessionName, message: `ERRO: ${d}` }));
    
    p.on('close', (code) => {
        if (activeBots[bot.sessionName]?.intentionalStop) {
            updateBotStatus(bot.sessionName, 'Offline');
        }
        delete activeBots[bot.sessionName];
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
    Object.values(bots).forEach(bot => {
        if (bot.status === 'Online' || bot.status.includes('Iniciando') || bot.status.includes('Aguardando')) {
            const now = new Date();
            const expires = new Date(bot.trialExpiresAt);

            if (expires > now) {
                startBotProcess(bot);
            } else {
                bot.status = 'Offline';
            }
        }
    });
    writeDB(BOTS_DB_PATH, bots);
}

const gracefulShutdown = () => {
    Object.keys(activeBots).forEach(sessionName => {
        if (activeBots[sessionName]) {
            try {
                activeBots[sessionName].process.kill('SIGINT');
            } catch (e) { }
        }
    });
    process.exit(0);
};

process.on('SIGTERM', gracefulShutdown);
process.on('SIGINT', gracefulShutdown);

server.listen(3000, () => {
    console.log('Painel ON: http://localhost:3000');
    restartActiveBots();
});
}
const msgRetryCounterCache = new SimpleCache();

// =================================================================================
// CONFIGURAÇÃO E ARGUMENTOS
// =================================================================================

const nomeSessao = process.argv[2];
const promptSistemaGlobal = Buffer.from(process.argv[3] || '', 'base64').toString('utf-8');
const ignoredIdentifiersArg = Buffer.from(process.argv[4] || 'W10=', 'base64').toString('utf-8'); 
let phoneNumberArg = (process.argv[5] && process.argv[5] !== 'null') ? process.argv[5] : null;
const authorizedGroupsArg = Buffer.from(process.argv[6] || 'W10=', 'base64').toString('utf-8'); 

// --- CORREÇÃO CRÍTICA: Limpeza do botType para garantir comparação exata ---
let rawBotType = process.argv[7] || 'individual';
const botType = rawBotType.trim().toLowerCase().replace(/[^a-z]/g, ''); 
// Agora botType será sempre apenas letras minúsculas, sem espaços.

const botNameGlobal = process.argv[8] || ''; 
const silenceTimeMinutesGlobal = parseInt(process.argv[9] || '0'); 
const platform = process.argv[10] || 'whatsapp';
const telegramToken = process.argv[11] || '';
const notificationNumber = process.argv[12] || '';

if (phoneNumberArg) {
    phoneNumberArg = phoneNumberArg.replace(/[^0-9]/g, '');
}

const modeloGemini = 'gemini-flash-latest'; 

// =================================================================================
// CONEXÃO SOCKET.IO
// =================================================================================

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

socket.on('ignored-list-updated', (data) => {
    if (data.sessionName === nomeSessao) {
        ignoredIdentifiers = data.ignoredIdentifiers;
        console.log(`[${nomeSessao}] Lista de ignorados atualizada via servidor.`);
    }
});

// =================================================================================
// VARIÁVEIS DE ESTADO E AUXILIARES
// =================================================================================

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
            isPaused: group.isPaused === true,
            welcomeMessage: group.welcomeMessage || null // Nova propriedade
        };
    });
} catch (e) {
    console.error('❌ Erro ao ler grupos:', e);
}

// Helper para formatar mensagem de boas-vindas
function formatWelcomeMessage(template, userName, groupName) {
    if (!template) return '';
    return template
        .replace(/#nome/gi, userName)
        .replace(/#user/gi, userName)
        .replace(/#grupo/gi, groupName);
}

// =================================================================================
// CONFIGURAÇÃO GEMINI (IA)
// =================================================================================

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

// =================================================================================
// FUNÇÕES AUXILIARES (ADMINISTRAÇÃO)
// =================================================================================

function areJidsSameUser(jid1, jid2) {
    if (!jid1 || !jid2) return false;
    return jidNormalizedUser(jid1) === jidNormalizedUser(jid2);
}

async function isGroupAdminWA(sock, jid, participant) {
    try {
        const metadata = await sock.groupMetadata(jid);
        const admin = metadata.participants.find(p => {
            return areJidsSameUser(p.id, participant) && (p.admin === 'admin' || p.admin === 'superadmin');
        });
        return !!admin;
    } catch (e) { 
        return false; 
    }
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
            if (myLid && pJid === myLid) return true;
            if (pJid === myJid) return true;
            return false;
        });

        return !!amIAdmin;
    } catch (e) { return false; }
}

// =================================================================================
// LÓGICA TELEGRAM
// =================================================================================
if (platform === 'telegram') {
    if (!telegramToken) { console.error('❌ Token do Telegram não fornecido.'); process.exit(1); }
    const bot = new Telegraf(telegramToken);
    
    (async () => {
        try {
            // Registrar comandos no Telegram
            const commands = [
                { command: 'id', description: 'Mostrar ID do Chat' },
                { command: 'menu', description: 'Mostrar todos os comandos' },
                { command: 'ping', description: 'Verificar status' },
                { command: 'stop', description: 'Pausar bot (ex: /stop10)' },
                { command: 'stopsempre', description: 'Ignorar usuário atual' }
            ];

            if (botType === 'group') {
                commands.push(
                    { command: 'ban', description: 'Banir usuário' },
                    { command: 'kick', description: 'Expulsar usuário' },
                    { command: 'mute', description: 'Mutar usuário' },
                    { command: 'unmute', description: 'Desmutar usuário' },
                    { command: 'promover', description: 'Promover a Admin' },
                    { command: 'rebaixar', description: 'Remover Admin' },
                    { command: 'antilink', description: 'Configurar Anti-Link' },
                    { command: 'boasvindas', description: 'Configurar mensagem de entrada' },
                    { command: 'todos', description: 'Chamar todos' },
                    { command: 'apagar', description: 'Apagar mensagem respondida' },
                    { command: 'fixar', description: 'Fixar mensagem' },
                    { command: 'desfixar', description: 'Desfixar mensagem' },
                    { command: 'titulo', description: 'Alterar título do grupo' },
                    { command: 'descricao', description: 'Alterar descrição' },
                    { command: 'link', description: 'Pegar link do grupo' },
                    { command: 'reset', description: 'Reiniciar memória da IA' }
                );
            }

            await bot.telegram.setMyCommands(commands);
            console.log(`[${nomeSessao}] Comandos do Telegram registrados.`);

            await bot.launch({ dropPendingUpdates: true });
            console.log('\nONLINE!'); 
            socket.emit('bot-online', { sessionName: nomeSessao });
        } catch (err) { console.error('Erro Telegram:', err); process.exit(1); }
    })();

    // Listener para confirmação de ativação de grupo (Telegram)
    socket.off('group-activation-result');
    socket.on('group-activation-result', async (data) => {
        if (data.botSessionName === nomeSessao && data.groupId) {
            const msg = data.success ? '✅ Grupo ativado com sucesso!' : `❌ Falha: ${data.message}`;
            try {
                await bot.telegram.sendMessage(data.groupId, msg);
                if(data.success) {
                    authorizedGroups[data.groupId] = { 
                        expiresAt: new Date(data.expiresAt), 
                        antiLink: false, 
                        prompt: '', 
                        silenceTime: 0, 
                        botName: '', 
                        isPaused: false,
                        welcomeMessage: null
                    };
                }
            } catch (e) { console.error('Erro ao enviar msg Telegram:', e); }
        }
    });

    // =================================================================================
    // 👋 BOAS-VINDAS NO TELEGRAM
    // =================================================================================
    bot.on('new_chat_members', async (ctx) => {
        // --- TRAVA DE SEGURANÇA ABSOLUTA ---
        // Se o bot não for explicitamente do tipo 'group', ele PARA aqui.
        if (botType !== 'group') return;

        try {
            const chatId = ctx.chat.id.toString();
            
            if (!authorizedGroups[chatId]) return;
            if (authorizedGroups[chatId].expiresAt && new Date() > authorizedGroups[chatId].expiresAt) return;
            if (authorizedGroups[chatId].isPaused) return;

            // Verificar configuração de mensagem personalizada
            const customWelcome = authorizedGroups[chatId]?.welcomeMessage;
            if (customWelcome === 'off') return; // Desativado pelo admin

            const newMembers = ctx.message.new_chat_members;
            const groupName = ctx.chat.title || 'Grupo';

            for (const member of newMembers) {
                if (member.is_bot) continue; 
                const name = member.first_name || 'Novo Membro';
                
                let textToSend = '';
                if (customWelcome) {
                    textToSend = formatWelcomeMessage(customWelcome, name, groupName);
                } else {
                    textToSend = `👋 Olá, *${name}*! Seja bem-vindo(a) ao *${groupName}*!`;
                }
                
                await ctx.reply(textToSend, { parse_mode: 'Markdown' });
            }
        } catch (e) {
            console.error(`[${nomeSessao}] Erro ao enviar boas-vindas no Telegram:`, e);
        }
    });
    
    bot.command('id', (ctx) => {
        ctx.reply(`ID deste chat: \`${ctx.chat.id}\``, { parse_mode: 'Markdown' });
    });

    bot.on('message', async (ctx) => {
        const texto = ctx.message.text || ctx.message.caption || '';
        if(!texto && !ctx.message.voice && !ctx.message.audio) return;

        const chatId = ctx.chat.id.toString();
        const isGroup = ctx.chat.type === 'group' || ctx.chat.type === 'supergroup';
        const senderName = ctx.from.first_name || 'User';
        const userId = ctx.from.id.toString();
        const isAudio = !!(ctx.message.voice || ctx.message.audio);

        // --- COMANDO !stopsempre (Ignorar Permanente) ---
        if (texto.match(/^[\/!]stopsempre$/i)) {
            let nameToIgnore = null;
            let canExecute = false;

            if (isGroup) {
                const member = await ctx.getChatMember(userId);
                if (member.status === 'administrator' || member.status === 'creator') {
                     if (ctx.message.reply_to_message) {
                         nameToIgnore = ctx.message.reply_to_message.from.first_name;
                         canExecute = true;
                     }
                }
            } else {
                nameToIgnore = ctx.chat.first_name;
                canExecute = true;
            }
            
            if (canExecute && nameToIgnore) {
                if (!ignoredIdentifiers.some(i => i.type === 'name' && i.value.toLowerCase() === nameToIgnore.toLowerCase())) {
                    ignoredIdentifiers.push({ type: 'name', value: nameToIgnore });
                    socket.emit('bot-update-ignored', { sessionName: nomeSessao, type: 'name', value: nameToIgnore });
                    console.log(`[${nomeSessao}] 🚫 Usuário ${nameToIgnore} ignorado permanentemente.`);
                }
                try { await ctx.deleteMessage(); } catch(e) {}
                return;
            }
        }

        // --- COMANDO !stop (Manual Pause Temporário) ---
        const stopMatch = texto.match(/^[\/!]stop(\d*)$/i);
        if (stopMatch) {
            let isAuth = true;
            if (isGroup) {
                const member = await ctx.getChatMember(userId);
                isAuth = member.status === 'administrator' || member.status === 'creator';
            }
            if (isAuth) {
                const minutos = stopMatch[1] ? parseInt(stopMatch[1]) : 10;
                pausados[chatId] = Date.now() + (minutos * 60 * 1000);
                try { await ctx.deleteMessage(); } catch(e) {}
                return;
            }
        }

        // --- VERIFICAÇÃO DE PAUSA ---
        if (pausados[chatId] && Date.now() < pausados[chatId]) return;

        // 1. Verificar Link de Ativação
        if (isGroup && texto.includes('/ativar?token=')) {
            const token = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
            if (token) {
                console.log(`[${nomeSessao}] Link de ativação detectado no grupo Telegram ${chatId}`);
                const groupTitle = ctx.chat.title || 'Grupo Telegram';
                socket.emit('group-activation-request', { 
                    groupId: chatId, 
                    groupName: groupTitle, 
                    activationToken: token, 
                    botSessionName: nomeSessao 
                });
                return; 
            }
        }

        // 2. Lógica de Autorização de Grupo
        let groupConfig = null;
        if (botType === 'group') {
            if (!isGroup || !authorizedGroups[chatId]) return;
            if (authorizedGroups[chatId].expiresAt && new Date() > authorizedGroups[chatId].expiresAt) return;
            groupConfig = authorizedGroups[chatId];
            if (groupConfig.isPaused) return;
        } else if (isGroup) {
            return;
        }

        // 3. Lógica de Administração (Anti-Link e Comandos)
        if (isGroup && botType === 'group') {
            // --- ANTI-LINK ---
            if (groupConfig && groupConfig.antiLink) {
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

            // --- COMANDOS ADMIN ---
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

                    // Comandos Públicos
                    if (comando === 'ping') {
                        const start = Date.now();
                        const msg = await ctx.reply('🏓 Pong!');
                        const end = Date.now();
                        await ctx.telegram.editMessageText(chatId, msg.message_id, null, `🏓 Pong! Latência: ${end - start}ms`);
                        return;
                    }

                    if (comando === 'menu' || comando === 'ajuda') {
                        let menu = `🤖 *MENU DE COMANDOS*\n\n`;
                        menu += `👤 *Públicos:*\n`;
                        menu += `/menu - Exibe esta lista detalhada de comandos.\n`;
                        menu += `/ping - Verifica se o bot está online e a latência.\n`;
                        menu += `/stop - Pausa o bot por 10 minutos (interrompe respostas da IA).\n`;
                        menu += `/stopsempre - Faz o bot ignorar você ou o usuário respondido permanentemente.\n`;
                        menu += `/id - Ver ID do chat.\n`;

                        if (senderIsAdm) {
                            menu += `\n👮 *Administração (Apenas Admins):*\n`;
                            menu += `/ban (responda) - Bane o usuário da mensagem respondida.\n`;
                            menu += `/kick (responda) - Remove (expulsa) o usuário.\n`;
                            menu += `/mute (responda) - Impede o usuário de enviar mensagens.\n`;
                            menu += `/unmute (responda) - Permite que o usuário fale novamente.\n`;
                            menu += `/promover (responda) - Torna o usuário administrador.\n`;
                            menu += `/rebaixar (responda) - Remove o admin do usuário.\n`;
                            menu += `/boasvindas <texto> - Configura mensagem (use #nome, #grupo) ou 'off'.\n`;
                            menu += `/apagar (responda) - Apaga a mensagem respondida e o comando.\n`;
                            menu += `/fixar (responda) - Fixa a mensagem no topo do grupo.\n`;
                            menu += `/desfixar - Desfixa a mensagem.\n`;
                            menu += `/todos - Marca todos os membros do grupo.\n`;
                            menu += `/titulo <nome> - Altera o título do grupo.\n`;
                            menu += `/descricao <texto> - Altera a descrição do grupo.\n`;
                            menu += `/link - Gera/Exibe o link de convite do grupo.\n`;
                            menu += `/antilink <on/off> - Ativa ou desativa a remoção automática de links.\n`;
                            menu += `/reset - Limpa a memória de conversa da IA neste chat.\n`;
                        }
                        await ctx.reply(menu, { parse_mode: 'Markdown' });
                        return;
                    }

                    // Comandos de Admin
                    if (senderIsAdm) {
                        const replyTo = ctx.message.reply_to_message;
                        const targetUser = replyTo ? replyTo.from : null;

                        switch (comando) {
                            case 'ban':
                            case 'banir':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja banir.');
                                await ctx.kickChatMember(targetUser.id);
                                await ctx.reply('✅ Usuário banido.');
                                return;

                            case 'kick':
                            case 'expulsar':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja expulsar.');
                                await ctx.unbanChatMember(targetUser.id); // Kick no telegram é ban + unban
                                await ctx.reply('✅ Usuário expulso.');
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
                                await ctx.promoteChatMember(targetUser.id, { can_change_info: true, can_delete_messages: true, can_invite_users: true, can_restrict_members: true, can_pin_messages: true });
                                await ctx.reply('✅ Usuário promovido a ADM.');
                                return;

                            case 'rebaixar':
                                if (!targetUser) return ctx.reply('❌ Responda a mensagem de quem deseja rebaixar.');
                                await ctx.promoteChatMember(targetUser.id, { can_change_info: false, can_delete_messages: false, can_invite_users: false, can_restrict_members: false, can_pin_messages: false });
                                await ctx.reply('✅ ADM removido.');
                                return;
                            
                            case 'todos':
                            case 'everyone':
                                await ctx.reply('📢 *Atenção todos!*', { parse_mode: 'Markdown' });
                                return;

                            case 'apagar':
                            case 'del':
                                if (!replyTo) return ctx.reply('❌ Responda a mensagem que deseja apagar.');
                                await ctx.deleteMessage(replyTo.message_id);
                                await ctx.deleteMessage(); // Apaga o comando também
                                return;

                            case 'fixar':
                            case 'pin':
                                if (!replyTo) return ctx.reply('❌ Responda a mensagem que deseja fixar.');
                                await ctx.pinChatMessage(replyTo.message_id);
                                return;

                            case 'desfixar':
                            case 'unpin':
                                await ctx.unpinChatMessage();
                                await ctx.reply('✅ Mensagem desfixada.');
                                return;

                            case 'titulo':
                                if (!args.length) return ctx.reply('❌ Digite o novo título.');
                                await ctx.setChatTitle(args.join(' '));
                                await ctx.reply('✅ Título alterado.');
                                return;

                            case 'descricao':
                                if (!args.length) return ctx.reply('❌ Digite a nova descrição.');
                                await ctx.setChatDescription(args.join(' '));
                                await ctx.reply('✅ Descrição alterada.');
                                return;

                            case 'link':
                                const invite = await ctx.exportChatInviteLink();
                                await ctx.reply(`🔗 Link do grupo: ${invite}`);
                                return;

                            case 'reset':
                                historicoConversa[chatId] = [];
                                await ctx.reply('🧠 Memória da IA reiniciada para este grupo.');
                                return;

                            case 'antilink':
                                if (!args[0]) return ctx.reply('Use: /antilink on ou /antilink off');
                                const novoEstado = args[0].toLowerCase() === 'on';
                                authorizedGroups[chatId].antiLink = novoEstado;
                                socket.emit('update-group-settings', { groupId: chatId, settings: { antiLink: novoEstado } });
                                await ctx.reply(`🛡️ Anti-Link agora está: *${novoEstado ? 'LIGADO' : 'DESLIGADO'}*`, { parse_mode: 'Markdown' });
                                return;

                            case 'boasvindas':
                                if (!args.length) return ctx.reply('❌ Digite a mensagem ou "off". Ex: /boasvindas Olá #nome!');
                                const novaMsg = args.join(' ');
                                const valueToSave = novaMsg.toLowerCase() === 'off' ? 'off' : novaMsg;
                                authorizedGroups[chatId].welcomeMessage = valueToSave;
                                socket.emit('update-group-settings', { groupId: chatId, settings: { welcomeMessage: valueToSave } });
                                if (valueToSave === 'off') await ctx.reply('🔕 Mensagem de boas-vindas desativada.');
                                else await ctx.reply('✅ Mensagem de boas-vindas configurada.');
                                return;
                        }
                    }
                } catch (e) { console.error('Erro comando telegram:', e); }
            }
        }

        // 4. Verificação de Ignorados (Nome)
        if (ignoredIdentifiers.some(i => i.type === 'name' && senderName.toLowerCase() === i.value.toLowerCase())) return;

        // 5. Lógica de Silêncio e Chamada por Nome
        let shouldRespond = true;
        const botName = (groupConfig && groupConfig.botName) ? groupConfig.botName : botNameGlobal;
        const isNameCalled = botName && texto.toLowerCase().includes(botName.toLowerCase());
        const silenceTime = (groupConfig && groupConfig.silenceTime !== undefined) ? groupConfig.silenceTime : silenceTimeMinutesGlobal;

        if (silenceTime > 0) {
            const lastTime = lastResponseTimes[chatId] || 0;
            const timeDiffMinutes = (Date.now() - lastTime) / (1000 * 60);
            if (!isNameCalled && timeDiffMinutes < silenceTime) shouldRespond = false;
        }

        if (!shouldRespond) return;

        // 6. Processamento IA
        try {
            ctx.sendChatAction('typing'); 
            let audioBuffer = null;
            if (isAudio) {
                const fileId = ctx.message.voice ? ctx.message.voice.file_id : ctx.message.audio.file_id;
                const fileLink = await ctx.telegram.getFileLink(fileId);
                const response = await axios.get(fileLink.href, { responseType: 'arraybuffer' });
                audioBuffer = Buffer.from(response.data).toString('base64');
            }

            const promptToUse = (groupConfig && groupConfig.prompt) ? groupConfig.prompt : promptSistemaGlobal;
            const resposta = await processarComGemini(chatId, isAudio ? audioBuffer : texto, isAudio, promptToUse);
            
            if(resposta && resposta.trim().length > 0) {
                await ctx.reply(resposta, { reply_to_message_id: ctx.message.message_id });
                lastResponseTimes[chatId] = Date.now();
            }
        } catch (e) {
            console.error("Erro ao responder no Telegram:", e);
        }
    });
    
    bot.catch((err, ctx) => {
        console.log(`Erro Telegram para ${ctx.updateType}`, err);
    });

    process.once('SIGINT', () => { bot.stop('SIGINT'); process.exit(0); });
    process.once('SIGTERM', () => { bot.stop('SIGTERM'); process.exit(0); });

} else {
    // =================================================================================
    // LÓGICA WHATSAPP
    // =================================================================================
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
                    authorizedGroups[data.groupId] = { 
                        expiresAt: new Date(data.expiresAt), 
                        antiLink: false, 
                        prompt: '', 
                        silenceTime: 0, 
                        botName: '', 
                        isPaused: false,
                        welcomeMessage: null
                    };
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

        // =================================================================================
        // 👋 BOAS-VINDAS NO WHATSAPP
        // =================================================================================
        sock.ev.on('group-participants.update', async (update) => {
            // --- TRAVA DE SEGURANÇA ABSOLUTA ---
            // Se o bot não for explicitamente do tipo 'group', ele PARA aqui.
            if (botType !== 'group') return;

            try {
                const { id, participants, action } = update;
                if (action === 'add') {
                    
                    if (!authorizedGroups[id]) return;
                    if (authorizedGroups[id].expiresAt && new Date() > authorizedGroups[id].expiresAt) return;
                    if (authorizedGroups[id].isPaused) return;

                    const customWelcome = authorizedGroups[id]?.welcomeMessage;
                    if (customWelcome === 'off') return;

                    // Tentar obter metadados do grupo para pegar o nome
                    let groupName = "Grupo";
                    try {
                        const metadata = await sock.groupMetadata(id);
                        groupName = metadata.subject;
                    } catch (e) {
                        console.error(`[${nomeSessao}] Falha ao obter nome do grupo para boas-vindas.`, e);
                    }

                    let text = '';
                    if (customWelcome) {
                         // Como participants é um array, vamos pegar o primeiro JID para o nome (caso seja 1 pessoa)
                         // ou deixar genérico se forem vários, mas o mention funciona no WhatsApp.
                         // O #nome será substituído mas a menção @user será feita pelo mentions array.
                         text = formatWelcomeMessage(customWelcome, '', groupName); 
                    } else {
                        text = `👋 Olá! Seja bem-vindo(a) ao grupo *${groupName}*!`;
                    }
                    
                    await sock.sendMessage(id, { 
                        text: text, 
                        mentions: participants 
                    });
                }
            } catch (e) {
                console.error(`[${nomeSessao}] Erro ao enviar boas-vindas no WhatsApp:`, e);
            }
        });

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

            // --- 1. COMANDO !stopsempre (Ignorar Permanente) ---
            if (texto.toLowerCase() === '!stopsempre') {
                let valueToIgnore = null;
                let typeToIgnore = 'number';

                if (msg.key.fromMe) {
                    if (isGroup) {
                         const context = msg.message?.extendedTextMessage?.contextInfo;
                         if (context?.participant) {
                             const pJid = jidNormalizedUser(context.participant);
                             valueToIgnore = pJid.split('@')[0];
                         }
                    } else {
                        const target = jidNormalizedUser(jid);
                        valueToIgnore = target.split('@')[0];
                    }
                } else {
                    const target = jidNormalizedUser(sender);
                    valueToIgnore = target.split('@')[0];
                }
                
                if (valueToIgnore) {
                    const exists = ignoredIdentifiers.some(i => i.type === 'number' && i.value === valueToIgnore);
                    
                    if (!exists) {
                        ignoredIdentifiers.push({ type: 'number', value: valueToIgnore });
                        socket.emit('bot-update-ignored', { sessionName: nomeSessao, type: 'number', value: valueToIgnore });
                        console.log(`[${nomeSessao}] 🚫 Número ${valueToIgnore} adicionado à lista de ignorados.`);
                    }
                    
                    try {
                        const key = { remoteJid: jid, fromMe: msg.key.fromMe, id: msg.key.id, participant: msg.key.participant };
                        await sock.sendMessage(jid, { delete: key });
                    } catch (e) {}
                }
                return; // Interrompe fluxo
            }

            // --- 2. COMANDO !stop (Pausa Temporária) ---
            const stopMatch = texto.match(/^!stop(\d*)$/i);
            if (stopMatch) {
                let isAuth = false;
                if (msg.key.fromMe) isAuth = true;
                else if (isGroup) isAuth = await isGroupAdminWA(sock, jid, sender);
                else if (!isGroup && !msg.key.fromMe) isAuth = true; 

                if (isAuth) {
                    const minutos = stopMatch[1] ? parseInt(stopMatch[1]) : 10;
                    const duracaoMs = minutos * 60 * 1000;
                    pausados[jid] = Date.now() + duracaoMs;

                    console.log(`[${nomeSessao}] 🔇 Pausado manualmente por ${minutos} min em ${jid}.`);

                    try {
                        const key = { remoteJid: jid, fromMe: msg.key.fromMe, id: msg.key.id, participant: msg.key.participant };
                        await sock.sendMessage(jid, { delete: key });
                    } catch (e) {}
                    return; 
                }
            }

            // --- 3. AUTO-SILÊNCIO AO RESPONDER ---
            if (msg.key.fromMe) {
                if (silenceTimeMinutesGlobal > 0) {
                    const autoSilenceMs = silenceTimeMinutesGlobal * 60 * 1000;
                    pausados[jid] = Date.now() + autoSilenceMs;
                    console.log(`[${nomeSessao}] 🔇 Auto-silêncio ativado por ${silenceTimeMinutesGlobal} min em ${jid} (intervenção humana).`);
                }
                return;
            }

            // --- VERIFICAÇÃO DE ATIVAÇÃO ---
            if (isGroup && texto.includes('/ativar?token=')) {
                const token = texto.match(/token=([a-zA-Z0-9-]+)/)?.[1];
                if (token) {
                    console.log(`[${nomeSessao}] Link de ativação detectado no grupo ${jid}`);
                    const meta = await sock.groupMetadata(jid);
                    socket.emit('group-activation-request', { groupId: jid, groupName: meta.subject, activationToken: token, botSessionName: nomeSessao });
                    return; 
                }
            }

            let groupConfig = null;
            if (botType === 'group') {
                if (!isGroup || !authorizedGroups[jid]) return;
                if (authorizedGroups[jid].expiresAt && new Date() > authorizedGroups[jid].expiresAt) return;
                groupConfig = authorizedGroups[jid];
                if (groupConfig.isPaused) return;
            } else if (isGroup) {
                return;
            }

            // --- LÓGICA DE ADMINISTRAÇÃO (WHATSAPP) ---
            if (isGroup && botType === 'group') {
                
                // 1. Anti-Link
                if (groupConfig && groupConfig.antiLink) {
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

                // 2. Comandos Admin
                if (texto.startsWith('!') || texto.startsWith('/') || texto.startsWith('.')) {
                    const args = texto.slice(1).trim().split(/ +/);
                    const comando = args.shift().toLowerCase();
                    const senderIsAdm = await isGroupAdminWA(sock, jid, sender);
                    const botIsAdm = await isBotAdminWA(sock, jid);

                    // Comandos Públicos
                    if (comando === 'ping') {
                        const start = Date.now();
                        await sock.sendMessage(jid, { text: `🏓 Pong! Latência: ${start - (msg.messageTimestamp * 1000)}ms` }, { quoted: msg });
                        return;
                    }

                    if (comando === 'menu' || comando === 'ajuda') {
                        let menu = `🤖 *MENU DE COMANDOS*\n\n`;
                        menu += `👤 *Públicos:*\n`;
                        menu += `!menu - Exibe esta lista detalhada de comandos.\n`;
                        menu += `!ping - Verifica se o bot está online e a latência.\n`;
                        menu += `!stop - Pausa a IA por 10 minutos.\n`;
                        menu += `!stopsempre - Ignora o usuário/grupo permanentemente.\n`;

                        if (senderIsAdm) {
                            menu += `\n👮 *Administração (Apenas Admins):*\n`;
                            menu += `!ban @user - Bane (remove) o usuário do grupo.\n`;
                            menu += `!kick @user - O mesmo que banir.\n`;
                            menu += `!promover @user - Torna um usuário administrador.\n`;
                            menu += `!rebaixar @user - Remove o admin de um usuário.\n`;
                            menu += `!boasvindas <texto> - Configura mensagem (use #nome, #grupo) ou 'off'.\n`;
                            menu += `!apagar (responda) - Apaga a mensagem respondida.\n`;
                            menu += `!fechar - Fecha o grupo para que apenas admins falem.\n`;
                            menu += `!abrir - Abre o grupo para todos falarem.\n`;
                            menu += `!todos - Marca todos os membros do grupo.\n`;
                            menu += `!titulo <nome> - Altera o nome do grupo.\n`;
                            menu += `!descricao <texto> - Altera a descrição do grupo.\n`;
                            menu += `!link - Exibe o link de convite do grupo.\n`;
                            menu += `!antilink <on/off> - Ativa/Desativa remoção de links.\n`;
                            menu += `!reset - Limpa a memória da conversa com a IA.\n`;
                            menu += `!sair - O bot sai do grupo.\n`;
                        }
                        await sock.sendMessage(jid, { text: menu }, { quoted: msg });
                        return;
                    }

                    if (senderIsAdm) {
                        let targetUser = null;
                        const mentions = msg.message.extendedTextMessage?.contextInfo?.mentionedJid;
                        if (mentions && mentions.length > 0) targetUser = mentions[0];
                        else if (msg.message.extendedTextMessage?.contextInfo?.participant) targetUser = msg.message.extendedTextMessage.contextInfo.participant;
                        else if (args[0]) {
                            const potentialNum = args[0].replace(/[^0-9]/g, '');
                            if (potentialNum.length >= 10) targetUser = potentialNum + '@s.whatsapp.net';
                        }

                        switch (comando) {
                            case 'ban':
                            case 'banir':
                            case 'kick':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!targetUser) return sock.sendMessage(jid, { text: '❌ Marque alguém ou responda.' }, { quoted: msg });
                                await sock.groupParticipantsUpdate(jid, [targetUser], 'remove');
                                await sock.sendMessage(jid, { text: '✅ Usuário removido.' });
                                return;

                            case 'promover':
                            case 'admin':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!targetUser) return sock.sendMessage(jid, { text: '❌ Marque alguém ou responda.' }, { quoted: msg });
                                await sock.groupParticipantsUpdate(jid, [targetUser], 'promote');
                                await sock.sendMessage(jid, { text: '✅ Usuário promovido.' });
                                return;

                            case 'rebaixar':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!targetUser) return sock.sendMessage(jid, { text: '❌ Marque alguém ou responda.' }, { quoted: msg });
                                await sock.groupParticipantsUpdate(jid, [targetUser], 'demote');
                                await sock.sendMessage(jid, { text: '✅ ADM removido.' });
                                return;

                            case 'apagar':
                            case 'del':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!msg.message.extendedTextMessage?.contextInfo?.stanzaId) return sock.sendMessage(jid, { text: '❌ Responda a mensagem.' }, { quoted: msg });
                                const key = {
                                    remoteJid: jid,
                                    fromMe: false,
                                    id: msg.message.extendedTextMessage.contextInfo.stanzaId,
                                    participant: msg.message.extendedTextMessage.contextInfo.participant
                                };
                                await sock.sendMessage(jid, { delete: key });
                                return;

                            case 'fechar':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                await sock.groupSettingUpdate(jid, 'announcement');
                                await sock.sendMessage(jid, { text: '🔒 Grupo fechado.' });
                                return;

                            case 'abrir':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                await sock.groupSettingUpdate(jid, 'not_announcement');
                                await sock.sendMessage(jid, { text: '🔓 Grupo aberto.' });
                                return;
                            
                            case 'todos':
                            case 'everyone':
                                if (!botIsAdm) return; 
                                const groupMeta = await sock.groupMetadata(jid);
                                const mentionsAll = groupMeta.participants.map(p => p.id);
                                await sock.sendMessage(jid, { text: '📢 *Atenção todos!*', mentions: mentionsAll });
                                return;

                            case 'titulo':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!args.length) return sock.sendMessage(jid, { text: '❌ Digite o novo nome.' }, { quoted: msg });
                                await sock.groupUpdateSubject(jid, args.join(' '));
                                await sock.sendMessage(jid, { text: '✅ Nome alterado.' });
                                return;

                            case 'descricao':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                if (!args.length) return sock.sendMessage(jid, { text: '❌ Digite a descrição.' }, { quoted: msg });
                                await sock.groupUpdateDescription(jid, args.join(' '));
                                await sock.sendMessage(jid, { text: '✅ Descrição alterada.' });
                                return;

                            case 'link':
                                if (!botIsAdm) return sock.sendMessage(jid, { text: '❌ Preciso ser ADM.' }, { quoted: msg });
                                const code = await sock.groupInviteCode(jid);
                                await sock.sendMessage(jid, { text: `🔗 Link: https://chat.whatsapp.com/${code}` }, { quoted: msg });
                                return;

                            case 'reset':
                                historicoConversa[jid] = [];
                                await sock.sendMessage(jid, { text: '🧠 Memória da IA reiniciada.' }, { quoted: msg });
                                return;

                            case 'sair':
                                await sock.sendMessage(jid, { text: '👋 Adeus!' });
                                await sock.groupLeave(jid);
                                return;

                            case 'antilink':
                                if (!args[0]) return sock.sendMessage(jid, { text: 'Use: !antilink on ou !antilink off' });
                                const novoEstado = args[0].toLowerCase() === 'on';
                                authorizedGroups[jid].antiLink = novoEstado;
                                socket.emit('update-group-settings', { groupId: jid, settings: { antiLink: novoEstado } });
                                await sock.sendMessage(jid, { text: `🛡️ Anti-Link agora está: *${novoEstado ? 'LIGADO' : 'DESLIGADO'}*` });
                                return;

                            case 'boasvindas':
                                if (!args.length) return sock.sendMessage(jid, { text: '❌ Digite a mensagem ou "off". Ex: !boasvindas Olá #nome!' }, { quoted: msg });
                                const novaMsg = args.join(' ');
                                const valueToSave = novaMsg.toLowerCase() === 'off' ? 'off' : novaMsg;
                                authorizedGroups[jid].welcomeMessage = valueToSave;
                                socket.emit('update-group-settings', { groupId: jid, settings: { welcomeMessage: valueToSave } });
                                if (valueToSave === 'off') await sock.sendMessage(jid, { text: '🔕 Mensagem de boas-vindas desativada.' });
                                else await sock.sendMessage(jid, { text: '✅ Mensagem de boas-vindas configurada.' });
                                return;
                        }
                    }
                }
            }

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
                if (!isMentioned && !isQuoted && !isNameCalled && timeDiffMinutes < silenceTime) shouldRespond = false;
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
                const resposta = await processarComGemini(jid, isAudio ? audioBuffer : texto, isAudio, promptToUse);
                
                if (resposta && resposta.trim().length > 0) {
                    await sock.sendMessage(jid, { text: resposta }, { quoted: msg });
                    lastResponseTimes[jid] = Date.now();

                    if (notificationNumber) {
                        try {
                            const adminJid = notificationNumber.replace(/\D/g, '') + '@s.whatsapp.net';
                            const clientName = msg.pushName || sender.split('@')[0];
                            const msgNotif = `🔔 O cliente ${clientName} mandou uma mensagem e eu respondi.`;
                            await sock.sendMessage(adminJid, { text: msgNotif });
                        } catch (errNotif) { console.error(`[ERRO NOTIFICAÇÃO]`, errNotif); }
                    }
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

process.on('uncaughtException', (err) => { console.error('Exceção não tratada:', err); });
process.on('unhandledRejection', (reason, promise) => { console.error('Rejeição não tratada:', reason); });
