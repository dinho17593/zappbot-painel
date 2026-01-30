#!/bin/bash

# --- SCRIPT DE CONFIGURAÇÃO (VERSÃO FINAL - NANO + CURL FIX) ---

TARGET_DIR="/var/www/bot-whatsapp"

# Cores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}--- CONFIGURANDO SERVIDOR ---${NC}"

# Garante que o nano e curl estejam instalados antes de tudo
sudo apt-get update -qq
sudo apt-get install -y nano curl -qq

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
echo "Cole o LINK da sua logo (Dropbox/Imgur/ImgBB/Direto)."
echo "Deixe em branco para usar a padrão."
read -p "URL da Logo: " LOGO_URL

echo ""
echo -e "${YELLOW}--- ARQUIVO .ENV (MÉTODO SEGURO) ---${NC}"
echo -e "${BLUE}O script abrirá o editor de texto NANO agora.${NC}"
echo "1. Quando abrir, COLE seu conteúdo."
echo "2. Pressione CTRL+O e ENTER para salvar."
echo "3. Pressione CTRL+X para sair."
echo -e "${GREEN}Pressione ENTER para abrir o editor...${NC}"
read -r wait_input

# Limpa arquivo anterior e abre o nano
rm -f .env
touch .env
nano .env

# Verifica se o usuário salvou algo
if [ ! -s .env ]; then
    echo -e "${RED}ERRO: O arquivo .env está vazio! Você não salvou ou não colou.${NC}"
    echo "Abortando instalação para evitar erros."
    exit 1
fi

echo -e "${GREEN}Arquivo .env salvo com sucesso!${NC}"

# Cria slug para o package.json
APP_SLUG=$(echo "$APP_NAME" | iconv -t ascii//TRANSLIT | sed -r 's/[^a-zA-Z0-9]+/-/g' | sed -r 's/^-+\|-+$//g' | tr A-Z a-z)

# ===================================================
# 2. INSTALAÇÃO DO SISTEMA
# ===================================================
echo -e "${YELLOW}Instalando dependências do Linux...${NC}"
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get update -qq
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

# A. Substituição de textos
grep -rl "ZappBot" index.html manifest.json | xargs sed -i "s/ZappBot/$APP_NAME/g" 2>/dev/null
grep -rl "zappbot.shop" index.html | xargs sed -i "s/zappbot.shop/$DOMAIN/g" 2>/dev/null

# B. Download e Conversão da Logo (CORRIGIDO COM HEADERS REAIS)
if [ ! -z "$LOGO_URL" ]; then
    echo "Baixando logo..."
    LOGO_URL=$(echo "$LOGO_URL" | sed 's/dl=0/dl=1/g') # Fix Dropbox
    
    # Remove arquivo anterior se existir
    rm -f logo_temp
    
    # CURL com headers completos para simular um navegador real e ignorar SSL (-k)
    curl -k -L \
         -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36" \
         -H "Accept: image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8" \
         "$LOGO_URL" -o logo_temp
    
    # Verifica se o arquivo baixado é realmente uma imagem
    FILE_TYPE=$(file --mime-type -b logo_temp)
    
    if [[ "$FILE_TYPE" == image/* ]]; then
        echo "Imagem detectada ($FILE_TYPE). Processando..."
        
        if ffmpeg -y -i logo_temp -vf scale=192:192 icon-192.png -loglevel error && \
           ffmpeg -y -i logo_temp -vf scale=512:512 icon-512.png -loglevel error; then
            
            cp icon-192.png favicon.ico
            rm logo_temp
            echo -e "${GREEN}✅ Logos atualizadas com sucesso!${NC}"
        else
            echo -e "${RED}❌ Erro no FFmpeg. O arquivo pode estar corrompido.${NC}"
            rm logo_temp
        fi
    else
        echo -e "${RED}❌ O link fornecido não retornou uma imagem válida.${NC}"
        echo "Tipo recebido: $FILE_TYPE"
        echo "Conteúdo (primeiras linhas):"
        head -n 3 logo_temp
        rm logo_temp
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
    
    sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m $EMAIL_SSL --redirect
else
    echo -e "${RED}E-mail não informado. SSL ignorado.${NC}"
fi

echo "---------------------------------------------------"
echo -e "${GREEN}✅ INSTALAÇÃO CONCLUÍDA!${NC}"
echo "---------------------------------------------------"
echo "Acesse: https://$DOMAIN"
echo "---------------------------------------------------"
