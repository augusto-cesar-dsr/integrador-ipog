#!/bin/bash

# Aguarda o OpenSearch estar disponível
echo "Aguardando OpenSearch..."
until curl -s http://localhost:9201/_cluster/health > /dev/null; do
  sleep 5
done

echo "OpenSearch disponível. Configurando índices..."

# Cria template para logs do CR-API
curl -X PUT "localhost:9201/_index_template/crapi-logs" \
  -H 'Content-Type: application/json' \
  -d '{
    "index_patterns": ["crapi-*"],
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
      },
      "mappings": {
        "properties": {
          "@timestamp": { "type": "date" },
          "level": { "type": "keyword" },
          "message": { "type": "text" },
          "service": { "type": "keyword" },
          "container_name": { "type": "keyword" }
        }
      }
    }
  }'

# Cria template para logs do Wazuh
curl -X PUT "localhost:9201/_index_template/wazuh-logs" \
  -H 'Content-Type: application/json' \
  -d '{
    "index_patterns": ["wazuh-*"],
    "template": {
      "settings": {
        "number_of_shards": 1,
        "number_of_replicas": 0
      },
      "mappings": {
        "properties": {
          "@timestamp": { "type": "date" },
          "agent": { "type": "keyword" },
          "rule": {
            "properties": {
              "id": { "type": "keyword" },
              "level": { "type": "integer" },
              "description": { "type": "text" }
            }
          }
        }
      }
    }
  }'

echo "Configuração do OpenSearch concluída!"
