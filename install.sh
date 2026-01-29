#!/bin/bash

# --- SCRIPT 2: INSTALAÇÃO E CONFIGURAÇÃO COMPLETA (ATUALIZADO) ---

# Define a pasta correta
TARGET_DIR="/var/www/bot-whatsapp"

# Cores para logs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}--- 2. INICIANDO INSTALAÇÃO PERSONALIZADA ---${NC}"

# Força o diretório correto
cd "$TARGET_DIR" || exit 1

# --- 1. COLETA DE DADOS ---
echo "---------------------------------------------------"
echo "CONFIGURAÇÃO DA SUA MARCA"
echo "---------------------------------------------------"

# Pergunta 1: Nome do App (Visual)
read -p "Digite o NOME do seu sistema (ex: Bot Atendimento, ZapLoja): " APP_NAME
if [ -z "$APP_NAME" ]; then APP_NAME="ZappBot"; fi

# Pergunta 2: Domínio
read -p "Digite seu DOMÍNIO (ex: meubot.com.br): " DOMAIN
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Erro: Domínio necessário.${NC}"
    exit 1
fi

# Pergunta 3: E-mail para SSL
read -p "Digite seu E-MAIL (para o certificado SSL): " EMAIL_SSL

# --- Criação do "Slug" para o package.json ---
# Transforma "Bot Atendimento" em "bot-atendimento" (minúsculo, sem espaços)
APP_SLUG=$(echo "$APP_NAME" | iconv -t ascii//TRANSLIT | sed -r 's/[^a-zA-Z0-9]+/-/g' | sed -r 's/^-+\|-+$//g' | tr A-Z a-z)

echo -e "${YELLOW}Configurando sistema para: $APP_NAME ($DOMAIN)...${NC}"

# --- 2. INSTALAÇÃO DE PACOTES DO SISTEMA ---
echo -e "${YELLOW}Atualizando sistema e instalando dependências...${NC}"
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get update
# Adicionado ffmpeg, certbot e dependências de compilação
sudo apt-get install -y nodejs nginx build-essential git python3 ffmpeg certbot python3-certbot-nginx

# --- 3. INSTALAÇÃO DAS BIBLIOTECAS NODE.JS ---
echo -e "${YELLOW}Instalando bibliotecas do projeto...${NC}"

# Limpeza preventiva
rm -rf node_modules package-lock.json

# Garante que existe um package.json básico se o zip não trouxe
if [ ! -f "package.json" ]; then
    npm init -y
fi

# Instala TODAS as dependências necessárias
npm install express socket.io @whiskeysockets/baileys qrcode-terminal pino \
    @google/generative-ai dotenv telegraf axios archiver adm-zip multer \
    session-file-store express-session cookie-parser bcrypt passport \
    passport-google-oauth20 mercadopago socket.io-client

# --- 4. SUBSTITUIÇÃO DE MARCA E DOMÍNIO (FIND & REPLACE) ---
echo -e "${YELLOW}Personalizando arquivos com o nome '$APP_NAME'...${NC}"

# A. Substituição do DOMÍNIO (zappbot.shop -> dominio do usuario)
# Varre arquivos .js, .html e .json
grep -rl "zappbot.shop" . | xargs sed -i "s/zappbot.shop/$DOMAIN/g" 2>/dev/null

# B. Substituição do NOME VISUAL ("ZappBot" -> Nome escolhido)
# Afeta index.html (título, meta tags, cabeçalho) e logs do server
grep -rl "ZappBot" . | xargs sed -i "s/ZappBot/$APP_NAME/g" 2>/dev/null

# C. Substituição do SLUG no package.json ("zappbot-painel" -> nome-formatado)
# Isso evita avisos do NPM sobre nome de pacote inválido
if [ -f "package.json" ]; then
    # Tenta substituir variações comuns que possam vir no zip
    sed -i "s/\"name\": \"zappbot-painel\"/\"name\": \"$APP_SLUG\"/g" package.json
    sed -i "s/\"name\": \"zappbot-shopp\"/\"name\": \"$APP_SLUG\"/g" package.json
fi

# D. Ajuste no manifest.json (se existir) para o PWA
if [ -f "manifest.json" ]; then
    sed -i "s/ZappBot/$APP_NAME/g" manifest.json
    sed -i "s/zappbot-painel/$APP_SLUG/g" manifest.json
fi

# Renomeia app.js para server.js se necessário (padronização)
if [ -f "app.js" ]; then mv app.js server.js; fi

# --- 5. CONFIGURAÇÃO DE PASTAS E ARQUIVOS ---
echo -e "${YELLOW}Criando estrutura de diretórios...${NC}"
mkdir -p uploads sessions auth_sessions

# Cria bancos de dados vazios se não existirem
for db in users.json bots.json groups.json settings.json; do
    if [ ! -f "$db" ]; then echo "{}" > "$db"; fi
done

# Permissões completas para evitar erro de EACCES
chmod -R 777 uploads sessions auth_sessions *.json

# --- 6. CONFIGURAÇÃO DO .ENV ---
echo -e "${YELLOW}Configurando arquivo .env...${NC}"
if [ -f ".env" ]; then mv .env .env.bkp; fi

cat > .env <<EOF
GOOGLE_CLIENT_ID="COLE_SEU_CLIENT_ID_AQUI"
GOOGLE_CLIENT_SECRET="COLE_SEU_CLIENT_SECRET_AQUI"
GOOGLE_CALLBACK_URL="https://${DOMAIN}/auth/google/callback"
SESSION_SECRET="secret-key-$(openssl rand -hex 16)"
API_KEYS_GEMINI="SUA_CHAVE_GEMINI_AQUI"
EOF

# --- 7. CONFIGURAÇÃO PM2 ---
echo -e "${YELLOW}Configurando Processo Node.js...${NC}"
npm install pm2 -g
pm2 delete painel >/dev/null 2>&1
pm2 start server.js --name "painel"
pm2 save
pm2 startup

# --- 8. CONFIGURAÇÃO NGINX ---
echo -e "${YELLOW}Configurando Nginx para $DOMAIN...${NC}"
NGINX_CONF="/etc/nginx/sites-available/bot-whatsapp"

cat > $NGINX_CONF <<EOF
server {
    server_name ${DOMAIN} www.${DOMAIN};

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

# Link simbólico e restart
ln -s -f $NGINX_CONF /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
# Remove configuração antiga se tiver nome diferente
rm -f /etc/nginx/sites-available/zappbot 
rm -f /etc/nginx/sites-enabled/zappbot

sudo nginx -t && sudo systemctl restart nginx

# --- 9. SSL AUTOMÁTICO ---
if [ ! -z "$EMAIL_SSL" ]; then
    echo -e "${YELLOW}Gerando HTTPS (SSL)...${NC}"
    sudo certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos -m $EMAIL_SSL --redirect
else
    echo -e "${RED}Aviso: SSL não configurado (sem e-mail). O site rodará em HTTP.${NC}"
fi

echo "---------------------------------------------------"
echo -e "${GREEN}✅ INSTALAÇÃO CONCLUÍDA!${NC}"
echo "---------------------------------------------------"
echo "Sistema: $APP_NAME"
echo "Acesse: https://$DOMAIN"
echo "---------------------------------------------------"
echo "👉 Próximo passo: Edite o arquivo .env com suas chaves reais."
echo "Comando: nano $TARGET_DIR/.env"
echo "---------------------------------------------------"
