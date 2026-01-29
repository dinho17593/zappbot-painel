#!/bin/bash

# --- SCRIPT DE CONFIGURAÇÃO (CORRIGIDO E SEGURO) ---

TARGET_DIR="/var/www/bot-whatsapp"

# Cores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}--- CONFIGURANDO SERVIDOR ---${NC}"

cd "$TARGET_DIR" || exit 1

# --- 1. DADOS DO USUÁRIO ---
echo "---------------------------------------------------"
read -p "Nome do Sistema (ex: ZapBot): " APP_NAME
if [ -z "$APP_NAME" ]; then APP_NAME="ZappBot"; fi

read -p "Seu Domínio (ex: site.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Domínio é obrigatório!${NC}"
    exit 1
fi

read -p "Seu E-mail (para SSL): " EMAIL_SSL

# Cria slug (ex: Zap Bot -> zap-bot) para o package.json
APP_SLUG=$(echo "$APP_NAME" | iconv -t ascii//TRANSLIT | sed -r 's/[^a-zA-Z0-9]+/-/g' | sed -r 's/^-+\|-+$//g' | tr A-Z a-z)

# --- 2. PACOTES DO LINUX ---
echo -e "${YELLOW}Instalando dependências do sistema...${NC}"
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get update -qq
# Adiciona ffmpeg e build-essential
sudo apt-get install -y nodejs nginx build-essential git python3 ffmpeg certbot python3-certbot-nginx -qq

# --- 3. PACOTES DO NODE.JS ---
echo -e "${YELLOW}Instalando dependências do Node.js...${NC}"
rm -rf node_modules package-lock.json

if [ ! -f "package.json" ]; then npm init -y; fi

# Instala exatamente o que o projeto precisa
npm install \
    @google/generative-ai @whiskeysockets/baileys adm-zip archiver axios \
    bcrypt cookie-parser dotenv express express-session mercadopago multer \
    passport passport-google-oauth20 passport-local pino session-file-store \
    socket.io socket.io-client telegraf qrcode-terminal

# --- 4. PERSONALIZAÇÃO (VISUAL APENAS) ---
echo -e "${YELLOW}Aplicando nome da marca...${NC}"

# Apenas no Front-end e Manifest (Seguro)
grep -rl "ZappBot" index.html manifest.json | xargs sed -i "s/ZappBot/$APP_NAME/g" 2>/dev/null
grep -rl "zappbot.shop" index.html | xargs sed -i "s/zappbot.shop/$DOMAIN/g" 2>/dev/null

# Ajusta package.json
if [ -f "package.json" ]; then
    sed -i "s/\"name\": \"zappbot-shopp\"/\"name\": \"$APP_SLUG\"/g" package.json
    sed -i "s/\"name\": \"zappbot-painel\"/\"name\": \"$APP_SLUG\"/g" package.json
fi

# Padroniza arquivo principal
if [ -f "app.js" ]; then mv app.js server.js; fi

# --- 5. ESTRUTURA E PERMISSÕES ---
mkdir -p uploads sessions auth_sessions
for db in users.json bots.json groups.json settings.json; do
    if [ ! -f "$db" ]; then echo "{}" > "$db"; fi
done
chmod -R 777 uploads sessions auth_sessions *.json

# --- 6. ARQUIVO .ENV (CONFIGURA O BACKEND) ---
echo -e "${YELLOW}Criando configuração (.env)...${NC}"
# Aqui definimos o domínio para o server.js ler, sem precisar editar o código JS
cat > .env <<EOF
GOOGLE_CLIENT_ID="COLE_AQUI"
GOOGLE_CLIENT_SECRET="COLE_AQUI"
GOOGLE_CALLBACK_URL="https://${DOMAIN}/auth/google/callback"
SESSION_SECRET="secret-$(openssl rand -hex 16)"
API_KEYS_GEMINI="COLE_SUA_CHAVE_GEMINI"
EOF

# --- 7. INICIAR COM PM2 ---
echo -e "${YELLOW}Iniciando aplicação...${NC}"
npm install pm2 -g
pm2 delete painel >/dev/null 2>&1
pm2 start server.js --name "painel"
pm2 save
pm2 startup

# --- 8. CONFIGURAÇÃO NGINX ---
echo -e "${YELLOW}Configurando Proxy Nginx...${NC}"
NGINX_CONF="/etc/nginx/sites-available/bot-whatsapp"

cat > $NGINX_CONF <<EOF
server {
    server_name ${DOMAIN} www.${DOMAIN};

    root /var/www/bot-whatsapp;

    location ~ /.well-known/acme-challenge {
        allow all;
    }

    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        client_max_body_size 100M;
    }
}
EOF

ln -s -f $NGINX_CONF /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
rm -f /etc/nginx/sites-available/zappbot 
rm -f /etc/nginx/sites-enabled/zappbot

sudo nginx -t && sudo systemctl restart nginx

# --- 9. SSL E FIREWALL ---
if [ ! -z "$EMAIL_SSL" ]; then
    echo -e "${YELLOW}Configurando Firewall e SSL...${NC}"
    # Abre portas
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    sudo ufw allow 3000/tcp
    
    # Gera certificado
    sudo certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos -m $EMAIL_SSL --redirect
else
    echo -e "${RED}Sem e-mail, SSL pulado.${NC}"
fi

echo "---------------------------------------------------"
echo -e "${GREEN}✅ INSTALAÇÃO CONCLUÍDA!${NC}"
echo "---------------------------------------------------"
echo "Acesse: https://$DOMAIN"
echo "---------------------------------------------------"
