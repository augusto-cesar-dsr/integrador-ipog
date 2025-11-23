#!/bin/bash

echo "Testando ataques no CR-API para verificar detecção do Wazuh..."

CRAPI_URL="http://localhost:8888"

echo "1. Testando SQL Injection..."
curl -s "$CRAPI_URL/identity/api/auth/login" \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@example.com'\'' OR 1=1--","password":"test"}' > /dev/null

echo "2. Testando XSS..."
curl -s "$CRAPI_URL/community/api/v2/community/posts" \
  -H "Content-Type: application/json" \
  -d '{"title":"<script>alert(\"XSS\")</script>","content":"test"}' > /dev/null

echo "3. Testando Path Traversal..."
curl -s "$CRAPI_URL/workshop/api/shop/products/../../../etc/passwd" > /dev/null

echo "4. Testando Command Injection..."
curl -s "$CRAPI_URL/workshop/api/mechanic/receive_report" \
  -H "Content-Type: application/json" \
  -d '{"report_link":"http://example.com; cat /etc/passwd"}' > /dev/null

echo "5. Testando acesso não autorizado..."
curl -s "$CRAPI_URL/identity/api/v2/user/dashboard" \
  -H "Authorization: Bearer invalid_token" > /dev/null

echo "6. Gerando erro 500..."
curl -s "$CRAPI_URL/workshop/api/shop/orders/999999999" > /dev/null

echo ""
echo "Ataques simulados enviados. Verificando alertas do Wazuh..."
sleep 5

echo ""
echo "Verificando logs do Wazuh:"
docker compose logs --tail=20 wazuh.manager | grep -i "alert\|rule\|crapi" || echo "Nenhum alerta encontrado ainda..."

echo ""
echo "Verificando índices no OpenSearch:"
curl -s "localhost:9201/_cat/indices?v" | grep logs

echo ""
echo "Teste concluído. Verifique o Wazuh Dashboard em https://localhost"
