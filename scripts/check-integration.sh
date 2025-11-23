#!/bin/bash

echo "=== Verificação de Integração ==="

# Cores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

check_service() {
    local service=$1
    local url=$2
    local expected_code=$3
    
    echo -n "Verificando $service... "
    
    if [ "$service" = "Wazuh Dashboard" ]; then
        response=$(curl -k -s -o /dev/null -w "%{http_code}" "$url")
    else
        response=$(curl -s -o /dev/null -w "%{http_code}" "$url")
    fi
    
    if [ "$response" = "$expected_code" ]; then
        echo -e "${GREEN}✅ OK${NC}"
        return 0
    else
        echo -e "${RED}❌ FALHOU (HTTP $response)${NC}"
        return 1
    fi
}

echo "1. Verificando serviços web..."
check_service "CR-API Web" "http://localhost:8888" "200"
check_service "OpenSearch" "http://localhost:9201" "200"
check_service "Wazuh Dashboard" "https://localhost" "302"
check_service "MailHog" "http://localhost:8025" "200"

echo ""
echo "2. Verificando containers..."
docker compose ps --format "table {{.Service}}\t{{.Status}}" | grep -E "(Up|healthy)" > /dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Containers rodando${NC}"
else
    echo -e "${RED}❌ Problemas nos containers${NC}"
fi

echo ""
echo "3. Verificando índices OpenSearch..."
indices=$(curl -s "localhost:9201/_cat/indices" | wc -l)
if [ "$indices" -gt 0 ]; then
    echo -e "${GREEN}✅ OpenSearch com $indices índices${NC}"
else
    echo -e "${RED}❌ OpenSearch sem índices${NC}"
fi

echo ""
echo "4. Testando conectividade Wazuh..."
echo "Test log" | nc -u -w 2 localhost 514 2>/dev/null
if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Wazuh UDP 514 acessível${NC}"
else
    echo -e "${RED}❌ Wazuh UDP 514 inacessível${NC}"
fi

echo ""
echo "=== Resumo da Integração ==="
echo "📊 Para monitorar logs: docker compose logs -f"
echo "🔍 Para ver alertas: docker compose logs -f wazuh.manager"
echo "🌐 Dashboard Wazuh: https://localhost (admin/SecretPassword)"
