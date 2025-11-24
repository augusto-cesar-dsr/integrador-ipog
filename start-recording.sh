#!/bin/bash

echo "🎬 Iniciando gravação do Security Lab Dashboard..."
echo "📊 Dashboard em tempo real será exibido"
echo "🎥 Para parar a gravação: Ctrl+C"
echo ""

# Verificar se o sistema está rodando
if ! docker compose ps | grep -q "running"; then
    echo "⚠️  Sistema não está rodando. Iniciando..."
    docker compose up -d
    sleep 10
fi

# Criar diretório de logs se não existir
mkdir -p logs

# Iniciar gravação com script
echo "🚀 Iniciando dashboard..."
python3 dashboard-realtime.py | tee logs/dashboard-$(date +%Y%m%d-%H%M%S).log
