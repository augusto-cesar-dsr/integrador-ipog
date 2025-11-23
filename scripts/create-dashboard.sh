#!/bin/bash

echo "Criando dashboard de integração..."

# Cria um index pattern para logs
curl -X POST "localhost:9201/.kibana/_doc/index-pattern:logs-*" \
  -H 'Content-Type: application/json' \
  -d '{
    "type": "index-pattern",
    "index-pattern": {
      "title": "logs-*",
      "timeFieldName": "@timestamp"
    }
  }'

echo "Dashboard criado com sucesso!"
echo ""
echo "=== INTEGRAÇÃO CONCLUÍDA ==="
echo ""
echo "Serviços disponíveis:"
echo "- OpenSearch: http://localhost:9201"
echo "- Wazuh Dashboard: https://localhost (admin/SecretPassword)"
echo "- CR-API Web: http://localhost:8888"
echo "- Logstash: http://localhost:9601"
echo "- Filebeat: Coletando logs dos containers"
echo ""
echo "Os logs do CR-API e Wazuh estão sendo enviados para o OpenSearch através do Logstash."
