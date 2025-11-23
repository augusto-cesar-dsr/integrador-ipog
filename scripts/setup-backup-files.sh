#!/bin/bash

echo "=== CONFIGURANDO ARQUIVOS DE BACKUP ==="
echo ""

# Verificar se estamos no diretório correto
if [ ! -d "backup" ]; then
    echo "❌ Diretório backup não encontrado. Execute este script na raiz do projeto."
    exit 1
fi

echo "📁 Copiando arquivos do Wazuh..."
# Criar diretórios se não existirem
mkdir -p wazuh/single-node/config/wazuh_cluster/{rules,decoders}

# Copiar arquivos do Wazuh
cp backup/wazuh/docker-compose.yml wazuh/single-node/
cp backup/wazuh/wazuh_cluster/wazuh_manager.conf wazuh/single-node/config/wazuh_cluster/
cp backup/wazuh/wazuh_cluster/rules/crapi_rules.xml wazuh/single-node/config/wazuh_cluster/rules/
cp backup/wazuh/wazuh_cluster/decoders/crapi_decoder.xml wazuh/single-node/config/wazuh_cluster/decoders/

echo "✅ Arquivos do Wazuh copiados"

echo "📁 Copiando arquivos do CR-API..."
# Copiar arquivos do CR-API
cp backup/cr-api/docker-compose.yml cr-api/deploy/docker/

echo "✅ Arquivos do CR-API copiados"

echo ""
echo "🎉 Todos os arquivos de backup foram copiados com sucesso!"
echo ""
echo "Próximos passos:"
echo "1. Gerar certificados SSL: cd wazuh/single-node && docker compose -f generate-indexer-certs.yml run --rm generator"
echo "2. Iniciar serviços: docker compose up -d"
echo "3. Configurar OpenSearch: ./scripts/setup-opensearch.sh"
