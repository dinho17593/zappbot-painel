#!/bin/bash

# --- SCRIPT DE INSTALAÇÃO PRINCIPAL (VERSÃO DEFINITIVA E CORRIGIDA) ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[AVISO] $1${NC}"; }
log_error() { echo -e "${RED}[ERRO] $1${NC}"; }

log_info "Iniciando a instalação principal do ZappBot..."

# --- 1. Perguntar pelas informações necessárias ---
read -p "Digite seu domínio (ex: zappbot.shop): " DOMAIN
if [ -z "$DOMAIN" ]; then log_error "Domínio é obrigatório."; exit 1; fi

read -p "Digite seu email para o certificado SSL: " USER_EMAIL
if [ -z "$USER_EMAIL" ]; then log_error "Email é obrigatório."; exit 1; fi

read -p "Cole seu GOOGLE_CLIENT_ID: " GOOGLE_CLIENT_ID
if [ -z "$GOOGLE_CLIENT_ID" ]; then log_error "Google Client ID é obrigatório."; exit 1; fi

read -s -p "Cole seu GOOGLE_CLIENT_SECRET: " GOOGLE_CLIENT_SECRET
echo "" # Adiciona uma nova linha após a senha
if [ -z "$GOOGLE_CLIENT_SECRET" ]; then log_error "Google Client Secret é obrigatório."; exit 1; fi

log_info "Agora, cole suas chaves da API Gemini. Pressione ENTER após cada chave."
log_info "Quando terminar, pressione ENTER em uma linha vazia para continuar."

API_KEYS_GEMINI=""
while true; do
    read -p "Chave Gemini: " key
    if [ -z "$key" ]; then
        break
    fi
    API_KEYS_GEMINI+="${key}\n"
done

# --- 2. Instalar Nginx, Certbot e outras dependências ---
log_info "Instalando Nginx, Certbot e dependências..."
sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get install -y nginx certbot python3-certbot-nginx

# --- 3. Instalar dependências do Node.js ---
INSTALL_DIR=$(pwd)
log_info "Instalando dependências do projeto em ${INSTALL_DIR}..."
sudo npm install

# --- 4. Instalar e configurar o PM2 ---
log_info "Instalando PM2 para gerenciar a aplicação..."
sudo npm install pm2 -g
sudo pm2 startup systemd

# --- 5. Criar o arquivo de ambiente (.env) com as informações coletadas ---
log_info "Criando o arquivo de configuração .env..."
sudo tee ${INSTALL_DIR}/.env > /dev/null <<EOF
# Configurações do Google Login
GOOGLE_CLIENT_ID="${GOOGLE_CLIENT_ID}"
GOOGLE_CLIENT_SECRET="${GOOGLE_CLIENT_SECRET}"
GOOGLE_CALLBACK_URL="https://${DOMAIN}/auth/google/callback"

# Chaves da API Gemini
API_KEYS_GEMINI="${API_KEYS_GEMINI}"
EOF

log_info "Arquivo .env criado com sucesso com suas chaves."

# --- 6. Configurar o Nginx ---
log_info "Configurando o Nginx como proxy reverso para ${DOMAIN}..."
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
        proxy_cache_bypass \$http_upgrade;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
    }
}
EOF

sudo ln -s -f $NGINX_CONF /etc/nginx/sites-enabled/
if [ -f /etc/nginx/sites-enabled/default ]; then
    sudo rm /etc/nginx/sites-enabled/default
fi
sudo nginx -t
sudo systemctl restart nginx

# --- 7. Configurar SSL com Certbot ---
log_info "Solicitando certificado SSL para ${DOMAIN}..."
sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m "${USER_EMAIL}" --redirect

# --- 8. Iniciar a aplicação com PM2 ---
log_info "Iniciando a aplicação ZappBot com PM2..."
cd $INSTALL_DIR
# Reinicia o processo caso ele já exista de uma tentativa anterior
sudo pm2 delete zappbot >/dev/null 2>&1
sudo pm2 start server.js --name zappbot
sudo pm2 save

# --- FINALIZAÇÃO ---
log_info "--------------------------------------------------------"
log_info "✅ Instalação concluída com sucesso!"
log_info "Seu ZappBot deve estar rodando em: https://${DOMAIN}"
log_info "As chaves já foram configuradas no arquivo .env."
log_info "Para verificar se a aplicação está sem erros, use o comando:"
log_info "pm2 logs zappbot"
log_info "--------------------------------------------------------"
