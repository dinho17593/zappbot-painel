#!/bin/bash

# --- SCRIPT 2: INSTALAÇÃO E CONFIGURAÇÃO ATUALIZADA ---

# Define a pasta correta
TARGET_DIR="/var/www/bot-whatsapp"

# Cores para logs
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}--- 2. INICIANDO INSTALAÇÃO DO PAINEL ZAPPBOT ---${NC}"

# Força o diretório correto
cd "$TARGET_DIR" || exit 1

# --- COLETA DE DADOS ---
read -p "Digite seu domínio (ex: meubot.com.br): " DOMAIN
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Erro: Domínio necessário.${NC}"
    exit 1
fi

read -p "Digite seu e-mail (para o certificado SSL): " EMAIL_SSL

# --- 1. INSTALAÇÃO DE PACOTES DO SISTEMA ---
echo -e "${YELLOW}Atualizando sistema e instalando dependências...${NC}"
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get update
# Adicionado ffmpeg (necessário para áudio) e certbot (SSL)
sudo apt-get install -y nodejs nginx build-essential git python3 ffmpeg certbot python3-certbot-nginx

# --- 2. INSTALAÇÃO DAS BIBLIOTECAS NODE.JS ---
echo -e "${YELLOW}Instalando bibliotecas do projeto...${NC}"

# Remove node_modules antigos para garantir instalação limpa
rm -rf node_modules package-lock.json

# Inicializa package.json se não existir (evita erro no npm install)
if [ ! -f "package.json" ]; then
    npm init -y
fi

# Instala TODAS as dependências listadas no seu código
npm install express socket.io @whiskeysockets/baileys qrcode-terminal pino \
    @google/generative-ai dotenv telegraf axios archiver adm-zip multer \
    session-file-store express-session cookie-parser bcrypt passport \
    passport-google-oauth20 mercadopago socket.io-client

# --- 3. CONFIGURAÇÃO DE ARQUIVOS E PASTAS ---
echo -e "${YELLOW}Criando estrutura de diretórios e arquivos...${NC}"

# Cria pastas necessárias para o script rodar sem erro
mkdir -p uploads sessions auth_sessions

# Cria arquivos JSON vazios se não existirem (Database)
if [ ! -f "users.json" ]; then echo "{}" > users.json; fi
if [ ! -f "bots.json" ]; then echo "{}" > bots.json; fi
if [ ! -f "groups.json" ]; then echo "{}" > groups.json; fi
if [ ! -f "settings.json" ]; then echo "{}" > settings.json; fi

# Permissões
chmod -R 777 uploads sessions auth_sessions *.json

# --- 4. SUBSTITUIÇÃO DE DOMÍNIO NO CÓDIGO ---
echo -e "${YELLOW}Atualizando URL do sistema nos arquivos...${NC}"

# Substitui zappbot.shop pelo domínio do cliente nos arquivos principais
# O comando sed -i edita o arquivo localmente
if [ -f "server.js" ]; then sed -i "s/zappbot.shop/$DOMAIN/g" server.js; fi
if [ -f "index.js" ]; then sed -i "s/zappbot.shop/$DOMAIN/g" index.js; fi
if [ -f "index.html" ]; then sed -i "s/zappbot.shop/$DOMAIN/g" index.html; fi

# Renomeia app.js se existir (legado)
if [ -f "app.js" ]; then mv app.js server.js; fi

# --- 5. CONFIGURAÇÃO DO .ENV ---
echo -e "${YELLOW}Configurando arquivo .env...${NC}"
if [ -f ".env" ]; then 
    echo "Arquivo .env já existe. Mantendo backup."
    cp .env .env.bkp 
fi

# Cria um .env novo com o domínio correto
cat > .env <<EOF
GOOGLE_CLIENT_ID="COLE_SEU_CLIENT_ID_AQUI"
GOOGLE_CLIENT_SECRET="COLE_SEU_CLIENT_SECRET_AQUI"
GOOGLE_CALLBACK_URL="https://${DOMAIN}/auth/google/callback"
SESSION_SECRET="secret-key-$(openssl rand -hex 16)"
API_KEYS_GEMINI="SUA_CHAVE_GEMINI_AQUI"
EOF

# --- 6. CONFIGURAÇÃO PM2 ---
echo -e "${YELLOW}Configurando Gerenciador de Processos (PM2)...${NC}"
npm install pm2 -g
pm2 startup

# Para processos antigos se existirem
pm2 delete painel >/dev/null 2>&1

# Inicia o servidor
pm2 start server.js --name "painel"
pm2 save

# --- 7. CONFIGURAÇÃO NGINX (PROXY REVERSO) ---
echo -e "${YELLOW}Configurando Nginx para $DOMAIN...${NC}"
NGINX_CONF="/etc/nginx/sites-available/zappbot"

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
        
        # Aumentar tamanho máximo de upload para arquivos de backup/mídia
        client_max_body_size 100M; 
    }
}
EOF

# Ativa site e reinicia Nginx
ln -s -f $NGINX_CONF /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
sudo nginx -t && sudo systemctl restart nginx

# --- 8. CONFIGURAÇÃO SSL (HTTPS) ---
if [ ! -z "$EMAIL_SSL" ]; then
    echo -e "${YELLOW}Gerando Certificado SSL (HTTPS)...${NC}"
    # Tenta obter o SSL automaticamente sem interação (--non-interactive)
    sudo certbot --nginx -d $DOMAIN -d www.$DOMAIN --non-interactive --agree-tos -m $EMAIL_SSL --redirect
else
    echo -e "${RED}E-mail não fornecido. Pulei a etapa do SSL.${NC}"
fi

echo "---------------------------------------------------"
echo -e "${GREEN}✅ INSTALAÇÃO CONCLUÍDA COM SUCESSO!${NC}"
echo "---------------------------------------------------"
echo "URL de Acesso: https://$DOMAIN"
echo "Local dos arquivos: $TARGET_DIR"
echo ""
echo "⚠️  IMPORTANTE:"
echo "1. Edite as chaves (Google/Gemini): nano $TARGET_DIR/.env"
echo "2. Para reiniciar o painel: pm2 restart painel"
echo "3. Para ver logs: pm2 logs painel"
echo "---------------------------------------------------"
