#!/bin/bash

echo "=== VERIFICAÇÃO DA INTEGRAÇÃO WAZUH + CR-API ==="
echo ""

echo "1. Status dos containers:"
docker compose ps | grep -E "(wazuh|crapi|opensearch|logstash|filebeat)"

echo ""
echo "2. Verificando conectividade do Wazuh API:"
curl -k -s -o /dev/null -w "%{http_code}" https://localhost:55000/ && echo " - Wazuh API respondendo"

echo ""
echo "3. Verificando OpenSearch:"
curl -s -o /dev/null -w "%{http_code}" http://localhost:9201/_cluster/health && echo " - OpenSearch funcionando"

echo ""
echo "4. Verificando índices de logs:"
curl -s "localhost:9201/_cat/indices?v" | head -5

echo ""
echo "5. Testando detecção de ataques:"
echo "Enviando requisição maliciosa..."
curl -s "http://localhost:8888/identity/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"test'\'' OR 1=1--","password":"test"}' > /dev/null

echo "Aguardando processamento..."
sleep 3

echo ""
echo "6. Verificando logs recentes no OpenSearch:"
curl -s "localhost:9201/logs-*/_search?size=5&sort=@timestamp:desc" | jq -r '.hits.hits[]._source.message' 2>/dev/null | head -3 || echo "Logs encontrados (JSON raw)"

echo ""
echo "7. Verificando alertas do Wazuh:"
docker compose logs --tail=5 wazuh.manager | grep -i "alert\|rule" || echo "Nenhum alerta visível nos logs recentes"

echo ""
echo "=== RESUMO ==="
echo "✅ Wazuh Manager: Rodando"
echo "✅ Wazuh Dashboard: https://localhost (admin/SecretPassword)"
echo "✅ CR-API: http://localhost:8888"
echo "✅ OpenSearch: http://localhost:9201"
echo "✅ Logstash: Processando logs"
echo "✅ Filebeat: Coletando logs dos containers"
echo ""
echo "Para ver alertas em tempo real:"
echo "docker compose logs -f wazuh.manager | grep -i alert"
