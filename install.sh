#!/bin/bash

# --- SCRIPT DE DOWNLOAD ---

# Configurações
PROJECT_ZIP_URL="https://github.com/dinho17593/zappbot-painel/archive/refs/heads/main.zip"
TARGET_DIR="/var/www/bot-whatsapp"
ZIP_FILE="project.zip"
TEMP_EXTRACT_FOLDER="zappbot-painel-main"
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${CYAN}--- PREPARANDO DOWNLOAD ---${NC}"

# Garante que o sudo está disponível e atualiza
sudo apt-get update -qq
sudo apt-get install -y wget unzip git -qq

# Limpeza da instalação anterior (Instalação Limpa)
if [ -d "$TARGET_DIR" ]; then
    echo "Limpando instalação anterior..."
    # Backup rápido
    mkdir -p /root/bkp_bot_antigo
    cp "$TARGET_DIR/.env" /root/bkp_bot_antigo/ 2>/dev/null
    cp "$TARGET_DIR"/*.json /root/bkp_bot_antigo/ 2>/dev/null
    rm -rf "$TARGET_DIR"
fi

mkdir -p "$TARGET_DIR"
cd /tmp 

echo "Baixando código fonte..."
wget -q "$PROJECT_ZIP_URL" -O $ZIP_FILE
unzip -o -q $ZIP_FILE

echo "Movendo arquivos..."
cp -r $TEMP_EXTRACT_FOLDER/* "$TARGET_DIR/"
cp $TEMP_EXTRACT_FOLDER/.env* "$TARGET_DIR/" 2>/dev/null 

# Copia o install.sh (que você criou/colou) para a pasta alvo
echo "Atualizando instalador..."
if [ -f "$OLDPWD/install.sh" ]; then
    cp "$OLDPWD/install.sh" "$TARGET_DIR/install.sh"
else
    echo "AVISO: install.sh não encontrado na pasta original. Usando versão do zip se existir."
fi

# Limpeza
rm $ZIP_FILE
rm -rf $TEMP_EXTRACT_FOLDER
chmod -R 777 "$TARGET_DIR"

echo -e "${CYAN}--- DOWNLOAD CONCLUÍDO ---${NC}"
cd "$TARGET_DIR"

# Executa o instalador
if [ -f "install.sh" ]; then
    chmod +x install.sh
    sed -i 's/\r$//' install.sh
    ./install.sh
else
    echo "ERRO CRÍTICO: install.sh não encontrado."
fi
