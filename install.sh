#!/bin/bash

# --- SCRIPT DE INSTALAÇÃO FINAL (CORRIGIDO) ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[AVISO] $1${NC}"; }
log_error() { echo -e "${RED}[ERRO] $1${NC}"; }

# --- 1. Perguntar APENAS o domínio ---
read -p "Digite seu domínio (ex: zappbot.shop): " DOMAIN
if [ -z "$DOMAIN" ]; then
    log_error "ERRO: O domínio não pode ser vazio."
    exit 1
fi
log_info "Iniciando instalação para o domínio: ${DOMAIN}"

# --- 2. Instalar Node.js e dependências ---
log_info "Configurando repositório do Node.js v18..."
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -

log_info "Instalando dependências de sistema..."
sudo apt-get install -y nodejs nginx build-essential libcairo2-dev libpango1.0-dev libjpeg-dev libgif-dev librsvg2-dev

# --- 3. Instalar dependências do projeto ---
INSTALL_DIR=$(pwd)
log_info "Instalando dependências do projeto (npm install)..."
sudo npm install

# --- 4. Instalar e configurar PM2 ---
log_info "Instalando PM2 Globalmente..."
sudo npm install pm2 -g
sudo pm2 startup systemd

# --- 5. Criar o arquivo .env de modelo ---
log_info "Gerando arquivo .env..."
sudo tee ${INSTALL_DIR}/.env > /dev/null <<EOF
# --- EDITE OS VALORES ABAIXO COM SUAS CHAVES ---

# Configurações do Google Login
GOOGLE_CLIENT_ID="COLE_SEU_GOOGLE_CLIENT_ID_AQUI"
GOOGLE_CLIENT_SECRET="COLE_SEU_GOOGLE_CLIENT_SECRET_AQUI"
GOOGLE_CALLBACK_URL="https://${DOMAIN}/auth/google/callback"

# Chaves da API Gemini (uma por linha)
API_KEYS_GEMINI="COLE_SUA_PRIMEIRA_API_KEY_GEMINI_AQUI
COLE_SUA_SEGUNDA_API_KEY_GEMINI_AQUI"
EOF

# --- 6. Configurar Nginx (HTTP) ---
log_info "Configurando Nginx..."
NGINX_CONF="/etc/nginx/sites-available/zappbot"
sudo tee $NGINX_CONF > /dev/null <<EOF
server {
    listen 80;
    server_name ${DOMAIN};
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
    }
}
EOF
sudo ln -s -f $NGINX_CONF /etc/nginx/sites-enabled/
if [ -f /etc/nginx/sites-enabled/default ]; then sudo rm /etc/nginx/sites-enabled/default; fi
sudo systemctl restart nginx

# --- 7. Configurar Firewall ---
log_info "Liberando Firewall..."
sudo ufw allow 'Nginx HTTP' > /dev/null
sudo ufw --force enable > /dev/null

# --- 8. Iniciar a aplicação ---
log_info "Iniciando aplicação no PM2..."
cd $INSTALL_DIR
sudo pm2 delete zappbot >/dev/null 2>&1
sudo pm2 start server.js --name zappbot
sudo pm2 save

# --- FINALIZAÇÃO ---
log_info "--------------------------------------------------------"
log_info "✅ Instalação concluída com sucesso!"
log_warn "⚠️  IMPORTANTE: Edite o arquivo .env com suas chaves!"
log_info "   Comando: sudo nano ${INSTALL_DIR}/.env"
log_info "   Depois salve (Ctrl+O) e saia (Ctrl+X)"
log_info "   E reinicie: sudo pm2 restart zappbot"
log_info "--------------------------------------------------------"
log_info "Acesse em: http://${DOMAIN}"
