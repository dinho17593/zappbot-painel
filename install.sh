#!/bin/bash

# --- SCRIPT DE CONFIGURAÇÃO E ATUALIZAÇÃO ---

TARGET_DIR="/var/www/bot-whatsapp"

# Cores
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${GREEN}--- CONFIGURANDO SERVIDOR ---${NC}"

# Garante que pacotes essenciais estejam instalados
sudo apt-get update -qq
sudo apt-get install -y nano curl -qq

cd "$TARGET_DIR" || exit 1

# ===================================================
# 1. COLETA DE DADOS INTERATIVA
# ===================================================
echo -e "${BLUE}---------------------------------------------------${NC}"
echo -e "${BLUE}           DADOS DO SERVIDOR E SSL               ${NC}"
echo -e "${BLUE}---------------------------------------------------${NC}"

read -p "1. Seu Domínio (ex: painel.site.com): " DOMAIN
if [ -z "$DOMAIN" ]; then
    echo -e "${RED}Erro: O domínio é um campo obrigatório!${NC}"
    exit 1
fi

read -p "2. Seu E-mail (usado para o certificado SSL): " EMAIL_SSL

# PERGUNTA CONDICIONAL PARA SSL E NGINX
read -p "3. Deseja configurar/reconfigurar o Nginx e o SSL (s/N)? " CONFIGURE_SSL

# Se o .env não existir (primeira instalação), solicita o preenchimento
if [ ! -f ".env" ]; then
    echo ""
    echo -e "${YELLOW}--- ARQUIVO .ENV (PRIMEIRA INSTALAÇÃO) ---${NC}"
    echo -e "${BLUE}O editor de texto NANO será aberto para você colar o conteúdo do .env.${NC}"
    echo "1. Cole o conteúdo no editor."
    echo "2. Pressione CTRL+O e depois ENTER para salvar."
    echo "3. Pressione CTRL+X para sair."
    echo -e "${GREEN}Pressione ENTER para continuar...${NC}"
    read -r
    
    nano .env

    if [ ! -s .env ]; then
        echo -e "${RED}ERRO: O arquivo .env está vazio. Instalação abortada.${NC}"
        exit 1
    fi
    echo -e "${GREEN}Arquivo .env salvo com sucesso!${NC}"
fi

# ===================================================
# 2. INSTALAÇÃO DE DEPENDÊNCIAS
# ===================================================
echo -e "${YELLOW}Instalando/Atualizando dependências do sistema...${NC}"
curl -fsSL https://deb.nodesource.com/setup_22.x | sudo -E bash -
sudo apt-get update -qq
sudo apt-get install -y nodejs nginx build-essential git python3 ffmpeg certbot python3-certbot-nginx -qq

# ===================================================
# 3. INSTALAÇÃO DO NODE.JS
# ===================================================
echo -e "${YELLOW}Instalando/Atualizando módulos do Node.js...${NC}"
rm -rf node_modules package-lock.json
npm install --silent

# ===================================================
# 4. ESTRUTURA E PERMISSÕES
# ===================================================
echo -e "${YELLOW}Verificando estrutura de arquivos e permissões...${NC}"
mkdir -p uploads sessions auth_sessions
for db in users.json bots.json groups.json settings.json; do
    if [ ! -f "$db" ]; then echo "{}" > "$db"; fi
done
chmod -R 777 uploads sessions auth_sessions *.json
if [ -f "app.js" ]; then mv app.js server.js; fi

# ===================================================
# 5. INICIALIZAÇÃO (PM2)
# ===================================================
echo -e "${YELLOW}Reiniciando o serviço da aplicação com PM2...${NC}"
npm install pm2 -g --silent
# Verifica se o processo já existe para decidir entre restart e start
if pm2 describe painel > /dev/null; then
    pm2 restart painel
else
    pm2 start server.js --name "painel"
fi
pm2 save
pm2 startup

# ===================================================
# 6. NGINX E SSL (CONDICIONAL)
# ===================================================
# A linha abaixo converte a resposta para minúscula para a verificação
if [[ "${CONFIGURE_SSL,,}" == "s" ]]; then
    echo -e "${YELLOW}Configurando Proxy Reverso com Nginx...${NC}"
    NGINX_CONF="/etc/nginx/sites-available/bot-whatsapp"

    cat > $NGINX_CONF <<EOF
server {
    server_name ${DOMAIN};
    root /var/www/bot-whatsapp;
    
    location ~ /.well-known/acme-challenge { allow all; }
    location / {
        proxy_pass http://localhost:3000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host \$host;
        proxy_cache_bypass \$http_upgrade;
    }
}
EOF

    ln -s -f $NGINX_CONF /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    sudo nginx -t && sudo systemctl restart nginx

    if [ ! -z "$EMAIL_SSL" ]; then
        echo -e "${YELLOW}Gerando certificado SSL com Certbot...${NC}"
        sudo ufw allow 'Nginx Full'
        sudo certbot --nginx -d $DOMAIN --non-interactive --agree-tos -m $EMAIL_SSL --redirect
    else
        echo -e "${RED}E-mail não informado. Geração de SSL ignorada.${NC}"
    fi
else
    echo -e "${YELLOW}Configuração de Nginx e SSL ignorada, conforme solicitado.${NC}"
fi

echo "---------------------------------------------------"
echo -e "${GREEN}✅ PROCESSO CONCLUÍDO!${NC}"
echo "---------------------------------------------------"
echo "Seu painel deve estar acessível em: https://$DOMAIN"
echo "(Lembre-se de verificar se seu DNS está apontando corretamente)."
echo "---------------------------------------------------"
