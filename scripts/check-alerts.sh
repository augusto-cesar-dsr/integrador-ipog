#!/bin/bash

echo "=== Verificação de Alertas ==="

echo "1. Verificando alertas no Wazuh..."
docker compose exec wazuh.manager tail -20 /var/ossec/logs/alerts/alerts.json | jq -r '.rule.description' 2>/dev/null || echo "Sem alertas JSON recentes"

echo ""
echo "2. Verificando logs no OpenSearch..."
curl -s "localhost:9201/crapi-logs*/_search?size=5&sort=@timestamp:desc" | jq -r '.hits.hits[]._source | select(.attack_type) | "\(.attack_type): \(.severity)"' 2>/dev/null || echo "Sem logs de ataque no OpenSearch"

echo ""
echo "3. Verificando logs do Fluent Bit..."
docker compose logs --tail=10 fluent-bit | grep -i "attack\|alert" || echo "Sem alertas no Fluent Bit"

echo ""
echo "4. Verificando conectividade Wazuh..."
echo "Test alert" | nc -u -w 2 localhost 514 && echo "✅ UDP 514 OK" || echo "❌ UDP 514 falhou"

echo ""
echo "5. Status dos containers de monitoramento..."
docker compose ps | grep -E "(fluent-bit|logstash|wazuh|opensearch)"
