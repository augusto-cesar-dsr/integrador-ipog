#!/bin/bash

echo "=== Setup Completo do Laboratório de Segurança IPOG ==="

# 1. Verificar pré-requisitos
echo "1. Verificando pré-requisitos..."
if ! command -v docker &> /dev/null; then
    echo "❌ Docker não encontrado. Instale o Docker primeiro."
    exit 1
fi

if ! command -v docker-compose &> /dev/null; then
    echo "❌ Docker Compose não encontrado. Instale o Docker Compose primeiro."
    exit 1
fi

# 2. Configurar arquivos de backup
echo "2. Configurando arquivos de backup..."
if [ -d "backup/wazuh" ]; then
    cp -r backup/wazuh/* wazuh/
    echo "✅ Configurações do Wazuh restauradas"
fi

# 3. Gerar certificados SSL para Wazuh
echo "3. Gerando certificados SSL para Wazuh..."
cd wazuh/single-node
if [ ! -d "config/wazuh_indexer_ssl_certs" ]; then
    docker compose -f generate-indexer-certs.yml run --rm generator
    echo "✅ Certificados SSL gerados"
else
    echo "✅ Certificados SSL já existem"
fi
cd ../..

# 4. Parar serviços antigos se existirem
echo "4. Limpando serviços antigos..."
docker compose down 2>/dev/null || true
echo "✅ Serviços antigos removidos"

# 5. Iniciar todos os serviços
echo "5. Iniciando todos os serviços..."
docker compose up -d
echo "✅ Serviços iniciados"

# 6. Aguardar inicialização
echo "6. Aguardando inicialização dos serviços..."
sleep 30

# 7. Verificar status
echo "7. Verificando status dos serviços..."
docker compose ps

echo ""
echo "=== ACESSO AOS SERVIÇOS ==="
echo "🌐 Wazuh Dashboard: https://localhost (admin / SecretPassword)"
echo "🌐 CR-API Web: http://localhost:8888"
echo "🌐 OpenSearch: http://localhost:9201"
echo "🌐 MailHog: http://localhost:8025"
echo ""
echo "=== PRÓXIMOS PASSOS ==="
echo "1. Execute: ./scripts/test-crapi-attacks.sh"
echo "2. Monitore alertas: docker compose logs -f wazuh.manager"
echo "3. Acesse o Wazuh Dashboard para visualizar alertas"
