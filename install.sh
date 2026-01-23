#!/bin/bash

# --- SCRIPT DE INSTALAÇÃO PRINCIPAL (VERSÃO CORRIGIDA) ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO] $1${NC}"; }
log_warn() { echo -e "${YELLOW}[AVISO] $1${NC}"; }
log_error() { echo -e "${RED}[ERRO] $1${NC}"; }

log_info "Iniciando a instalação principal do ZappBot..."

# --- 1. Perguntar o domínio ---
read -p "Digite seu domínio (ex: zappbot.seusite.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
    log_error "O domínio não pode ser vazio. Abortando."
    exit 1
fi

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

# --- 5. Criar o arquivo de ambiente (.env) ---
log_info "Criando o arquivo de configuração .env..."
sudo tee ${INSTALL_DIR}/.env > /dev/null <<EOF
# Configurações do Google Login (Opcional, mas recomendado)
GOOGLE_CLIENT_ID="COLE_SEU_GOOGLE_CLIENT_ID_AQUI"
GOOGLE_CLIENT_SECRET="COLE_SEU_GOOGLE_CLIENT_SECRET_AQUI"
GOOGLE_CALLBACK_URL="https://${DOMAIN}/auth/google/callback"

# Chaves da API Gemini (coloque uma por linha, sem aspas extras)
API_KEYS_GEMINI="COLE_SUA_PRIMEIRA_API_KEY_GEMINI_AQUI
COLE_SUA_SEGUNDA_API_KEY_GEMINI_AQUI"
EOF

log_warn "O arquivo .env foi criado. Edite-o com suas chaves de API: sudo nano ${INSTALL_DIR}/.env"

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
log_warn "O Certbot tentará configurar o Nginx automaticamente."
sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m seu-email@dominio.com --redirect

# --- 8. Iniciar a aplicação com PM2 ---
log_info "Iniciando a aplicação ZappBot com PM2..."
cd $INSTALL_DIR
sudo pm2 start server.js --name zappbot
sudo pm2 save

log_info "--------------------------------------------------------"
log_info "✅ Instalação concluída com sucesso!"
log_info "Seu ZappBot está rodando em: https://${DOMAIN}"
log_warn "Lembre-se de editar o arquivo .env com suas chaves:"
log_warn "sudo nano ${INSTALL_DIR}/.env"
log_info "Após editar, reinicie a aplicação com: sudo pm2 restart zappbot"
log_info "--------------------------------------------------------"# --- 5. Criar o arquivo de ambiente (.env) ---
log_info "Criando o arquivo de configuração .env..."
sudo tee ${INSTALL_DIR}/.env > /dev/null <<EOF
# Configurações do Google Login (Opcional, mas recomendado)
GOOGLE_CLIENT_ID="COLE_SEU_GOOGLE_CLIENT_ID_AQUI"
GOOGLE_CLIENT_SECRET="COLE_SEU_GOOGLE_CLIENT_SECRET_AQUI"
GOOGLE_CALLBACK_URL="https://${DOMAIN}/auth/google/callback"

# Chaves da API Gemini (coloque uma por linha, sem aspas extras)
API_KEYS_GEMINI="COLE_SUA_PRIMEIRA_API_KEY_GEMINI_AQUI
COLE_SUA_SEGUNDA_API_KEY_GEMINI_AQUI"
EOF

log_warn "O arquivo .env foi criado. Edite-o com suas chaves de API: sudo nano ${INSTALL_DIR}/.env"

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

sudo ln -s $NGINX_CONF /etc/nginx/sites-enabled/
if [ -f /etc/nginx/sites-enabled/default ]; then
    sudo rm /etc/nginx/sites-enabled/default
fi
sudo nginx -t
sudo systemctl restart nginx

# --- 7. Configurar SSL com Certbot ---
log_info "Solicitando certificado SSL para ${DOMAIN}..."
log_warn "O Certbot fará algumas perguntas. Forneça seu e-mail e aceite os termos."
sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m SEU_EMAIL@DOMINIO.COM --redirect

# --- 8. Iniciar a aplicação com PM2 ---
log_info "Iniciando a aplicação ZappBot com PM2..."
cd $INSTALL_DIR
sudo pm2 start server.js --name zappbot
sudo pm2 save

log_info "--------------------------------------------------------"
log_info "✅ Instalação concluída com sucesso!"
log_info "Seu ZappBot está rodando em: https://${DOMAIN}"
log_warn "Lembre-se de editar o arquivo .env com suas chaves:"
log_warn "sudo nano ${INSTALL_DIR}/.env"
log_info "Após editar, reinicie a aplicação com: sudo pm2 restart zappbot"
log_info "--------------------------------------------------------"
