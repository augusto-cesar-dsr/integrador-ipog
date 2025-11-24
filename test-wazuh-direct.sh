#!/bin/bash

echo "=== Testando Pipeline Wazuh Diretamente ==="

# Obter IP do Wazuh Manager
WAZUH_IP=$(docker inspect integrador-ipog-wazuh.manager-1 | grep IPAddress | tail -1 | cut -d'"' -f4)
echo "Wazuh Manager IP: $WAZUH_IP"

# Testar diferentes tipos de ataques via porta 1514 TCP
echo "1. Enviando SQL Injection..."
echo "1:Nov 24 00:05:00 crapi-web: SQL Injection detected: SELECT * FROM users WHERE id=1 OR 1=1" | nc $WAZUH_IP 1514

echo "2. Enviando XSS..."
echo "1:Nov 24 00:05:01 crapi-web: XSS detected: <script>alert('xss')</script>" | nc $WAZUH_IP 1514

echo "3. Enviando Path Traversal..."
echo "1:Nov 24 00:05:02 crapi-web: Path traversal detected: GET /etc/passwd" | nc $WAZUH_IP 1514

echo "4. Aguardando processamento..."
sleep 5

echo "5. Verificando alertas..."
docker compose exec wazuh.manager tail -10 /var/ossec/logs/alerts/alerts.json 2>/dev/null | tail -3
