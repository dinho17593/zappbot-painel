#!/bin/bash

# --- SCRIPT 2: INSTALAÇÃO E CONFIGURAÇÃO ---

# Define a pasta correta
TARGET_DIR="/var/www/bot-whatsapp"

# Força o diretório correto antes de começar
cd "$TARGET_DIR"

echo "--- 2. INICIANDO INSTALAÇÃO ---"

read -p "Digite seu domínio (ex: zappbot.shop): " DOMAIN
if [ -z "$DOMAIN" ]; then
    echo "Erro: Domínio necessário."
    exit 1
fi

# 1. Instalar Node.js 22 (Atualizado conforme seu curl)
echo "Instalando Node.js..."
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get install -y nodejs nginx build-essential git python3

# 2. Instalar dependências do projeto
echo "Instalando bibliotecas (npm install)..."
rm -rf node_modules
npm install

# 3. GARANTIR O NOME SERVER.JS
if [ -f "app.js" ]; then
    echo "Renomeando app.js para server.js..."
    mv app.js server.js
fi

# 4. Configurar PM2
echo "Configurando PM2..."
npm install pm2 -g
pm2 startup

# 5. Criar .env (Modelo)
echo "Criando arquivo .env..."
# Se já existir, salva backup
if [ -f ".env" ]; then mv .env .env.bkp; fi

cat > .env <<EOF
GOOGLE_CLIENT_ID="COLE_AQUI"
GOOGLE_CLIENT_SECRET="COLE_AQUI"
GOOGLE_CALLBACK_URL="https://${DOMAIN}/auth/google/callback"

API_KEYS_GEMINI="CHAVE_1
CHAVE_2
CHAVE_3"
EOF

# 6. Configurar Nginx
echo "Configurando Nginx para $DOMAIN..."
NGINX_CONF="/etc/nginx/sites-available/zappbot"
cat > $NGINX_CONF <<EOF
server {
    listen 80;
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
    }
}
EOF

ln -s -f $NGINX_CONF /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx

# 7. Iniciar o Painel
echo "Iniciando processo 'painel'..."
pm2 delete painel >/dev/null 2>&1
pm2 start server.js --name "painel"
pm2 save

echo "---------------------------------------------------"
echo "✅ CONCLUÍDO!"
echo "1. Edite as chaves: nano $TARGET_DIR/.env"
echo "2. Gere o SSL: certbot --nginx -d $DOMAIN"
echo "3. Se precisar reiniciar: pm2 restart painel"
echo "---------------------------------------------------"
# 5. Criar .env (Modelo)
echo "Criando arquivo .env..."
# Se já existir, salva backup
if [ -f ".env" ]; then mv .env .env.bkp; fi

cat > .env <<EOF
GOOGLE_CLIENT_ID="COLE_AQUI"
GOOGLE_CLIENT_SECRET="COLE_AQUI"
GOOGLE_CALLBACK_URL="https://${DOMAIN}/auth/google/callback"

API_KEYS_GEMINI="CHAVE_1
CHAVE_2
CHAVE_3"
EOF

# 6. Configurar Nginx
echo "Configurando Nginx para $DOMAIN..."
NGINX_CONF="/etc/nginx/sites-available/zappbot"
cat > $NGINX_CONF <<EOF
server {
    listen 80;
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
    }
}
EOF

ln -s -f $NGINX_CONF /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default
systemctl restart nginx

# 7. Iniciar o Painel
echo "Iniciando processo 'painel'..."
pm2 delete painel >/dev/null 2>&1
pm2 start server.js --name "painel"
pm2 save

echo "---------------------------------------------------"
echo "✅ CONCLUÍDO!"
echo "1. Edite as chaves: nano /root/bot-whatsapp/.env"
echo "2. Gere o SSL: certbot --nginx -d $DOMAIN"
echo "3. Reinicie: pm2 restart painel"
echo "---------------------------------------------------"
