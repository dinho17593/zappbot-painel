#!/bin/bash

# --- SCRIPT DE CONFIGURAÇÃO (PASTE FULL .ENV) ---

TARGET_DIR="/var/www/bot-whatsapp"

# Cores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}--- CONFIGURANDO SERVIDOR ---${NC}"

cd "$TARGET_DIR" || exit 1

# ===================================================
# 1. COLETA DE DADOS INTERATIVA
# ===================================================
echo -e "${BLUE}---------------------------------------------------${NC}"
echo -e "${BLUE}       DADOS DO SISTEMA E PERSONALIZAÇÃO           ${NC}"
echo -e "${BLUE}---------------------------------------------------${NC}"

read -p "1. Nome do Sistema (ex: ZapBot): " APP_NAME
if [ -z "$APP_NAME" ]; then APP_NAME="ZappBot"; fi

read -p "2. Seu Domínio (SEM http/www, ex: painel.site.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Erro: Domínio é obrigatório!${NC}"
    exit 1
fi

read -p "3. Seu E-mail (para o certificado SSL): " EMAIL_SSL

echo ""
echo -e "${YELLOW}--- PERSONALIZAÇÃO VISUAL (LOGO) ---${NC}"
echo "Cole o LINK da sua logo (Dropbox/Imgur/Direto)."
echo "Deixe em branco para usar a padrão."
read -p "URL da Logo: " LOGO_URL

echo ""
echo -e "${YELLOW}--- ARQUIVO .ENV COMPLETO ---${NC}"
echo -e "${BLUE}Cole abaixo o conteúdo INTEIRO do seu arquivo .env:${NC}"
echo "(Inclua todas as chaves do Google, Gemini, etc)"
echo -e "${RED}>>> Quando terminar de colar, aperte ENTER, digite FIM e aperte ENTER novamente.${NC}"
echo "---------------------------------------------------"

# Lógica para ler multiplas linhas até encontrar a palavra FIM
rm -f .env # Garante que está vazio
touch .env

while IFS= read -r line; do
    if [[ "$line" == "FIM" ]]; then
        break
    fi
    echo "$line" >> .env
done

echo -e "${GREEN}Arquivo .env salvo com sucesso!${NC}"

# Cria slug para o package.json
APP_SLUG=$(echo "$APP_NAME" | iconv -t ascii//TRANSLIT | sed -r 's/[^a-zA-Z0-9]+/-/g' | sed -r 's/^-+\|-+$//g' | tr A-Z a-z)

# ===================================================
# 2. INSTALAÇÃO DO SISTEMA
# ===================================================
echo -e "${YELLOW}Instalando dependências do Linux...${NC}"
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get update -qq
# Instala ffmpeg para processar a imagem da logo e certbot
sudo apt-get install -y nodejs nginx build-essential git python3 ffmpeg certbot python3-certbot-nginx -qq

# ===================================================
# 3. INSTALAÇÃO DO NODE.JS
# ===================================================
echo -e "${YELLOW}Instalando módulos do Painel...${NC}"
rm -rf node_modules package-lock.json

if [ ! -f "package.json" ]; then npm init -y; fi

npm install \
    @google/generative-ai @whiskeysockets/baileys adm-zip archiver axios \
    bcrypt cookie-parser dotenv express express-session mercadopago multer \
    passport passport-google-oauth20 passport-local pino session-file-store \
    socket.io socket.io-client telegraf qrcode-terminal

# ===================================================
# 4. PROCESSAMENTO DE IMAGENS E MARCA
# ===================================================
echo -e "${YELLOW}Aplicando personalização visual...${NC}"

# A. Substituição de textos (Nome e Domínio)
grep -rl "ZappBot" index.html manifest.json | xargs sed -i "s/ZappBot/$APP_NAME/g" 2>/dev/null
grep -rl "zappbot.shop" index.html | xargs sed -i "s/zappbot.shop/$DOMAIN/g" 2>/dev/null

# B. Download e Conversão da Logo (Se fornecida)
if [ ! -z "$LOGO_URL" ]; then
    echo "Processando logo..."
    LOGO_URL=$(echo "$LOGO_URL" | sed 's/dl=0/dl=1/g') # Fix Dropbox
    
    wget -q "$LOGO_URL" -O logo_temp
    
    if [ -s logo_temp ]; then
        # Redimensiona usando FFmpeg
        ffmpeg -y -i logo_temp -vf scale=192:192 icon-192.png -loglevel error
        ffmpeg -y -i logo_temp -vf scale=512:512 icon-512.png -loglevel error
        cp icon-192.png favicon.ico
        rm logo_temp
        echo "✅ Logos atualizadas!"
    else
        echo -e "${RED}Falha ao baixar logo.${NC}"
    fi
fi

# C. Ajustes técnicos no package.json
if [ -f "package.json" ]; then
    sed -i "s/\"name\": \"zappbot-shopp\"/\"name\": \"$APP_SLUG\"/g" package.json
    sed -i "s/\"name\": \"zappbot-painel\"/\"name\": \"$APP_SLUG\"/g" package.json
fi

if [ -f "app.js" ]; then mv app.js server.js; fi

# ===================================================
# 5. ESTRUTURA E PERMISSÕES
# ===================================================
mkdir -p uploads sessions auth_sessions
for db in users.json bots.json groups.json settings.json; do
    if [ ! -f "$db" ]; then echo "{}" > "$db"; fi
done
chmod -R 777 uploads sessions auth_sessions *.json

# ===================================================
# 6. INICIALIZAÇÃO (PM2)
# ===================================================
echo -e "${YELLOW}Iniciando servidor...${NC}"
npm install pm2 -g
pm2 delete painel >/dev/null 2>&1
pm2 start server.js --name "painel"
pm2 save
pm2 startup

# ===================================================
# 7. NGINX E SSL
# ===================================================
echo -e "${YELLOW}Configurando Proxy Nginx...${NC}"
NGINX_CONF="/etc/nginx/sites-available/bot-whatsapp"

# Configuração SEM WWW para evitar erro de DNS em subdomínios
cat > $NGINX_CONF <<EOF
server {
    server_name ${DOMAIN};
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

if [ ! -z "$EMAIL_SSL" ]; then
    echo -e "${YELLOW}Gerando certificado SSL...${NC}"
    sudo ufw allow 80/tcp
    sudo ufw allow 443/tcp
    sudo ufw allow 3000/tcp
    
    # Gera SSL APENAS para o domínio principal (sem www)
    sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m $EMAIL_SSL --redirect
else
    echo -e "${RED}E-mail não informado. SSL ignorado.${NC}"
fi

echo "---------------------------------------------------"
echo -e "${GREEN}✅ INSTALAÇÃO CONCLUÍDA!${NC}"
echo "---------------------------------------------------"
echo "Acesse: https://$DOMAIN"
echo "---------------------------------------------------"
