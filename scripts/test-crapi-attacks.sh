#!/bin/bash

echo "=== Testando Ataques Avançados no CR-API ==="

BASE_URL="http://localhost:8888"

echo "1. Testando SQL Injection..."
curl -s "$BASE_URL/identity/api/auth/login" \
  -d '{"email":"admin@example.com OR 1=1 --","password":"test"}' \
  -H "Content-Type: application/json" > /dev/null

curl -s "$BASE_URL/identity/api/auth/login" \
  -d '{"email":"admin@example.com\"; DROP TABLE users; --","password":"test"}' \
  -H "Content-Type: application/json" > /dev/null

echo "2. Testando XSS..."
curl -s "$BASE_URL/identity/api/auth/login" \
  -d '{"email":"<script>alert(\"XSS\")</script>","password":"test"}' \
  -H "Content-Type: application/json" > /dev/null

curl -s "$BASE_URL/identity/api/auth/login" \
  -d '{"email":"javascript:alert(document.cookie)","password":"test"}' \
  -H "Content-Type: application/json" > /dev/null

echo "3. Testando Path Traversal..."
curl -s "$BASE_URL/../../../etc/passwd" > /dev/null
curl -s "$BASE_URL/identity/api/auth/../../etc/shadow" > /dev/null

echo "4. Testando Command Injection..."
curl -s "$BASE_URL/identity/api/auth/login" \
  -d '{"email":"test@example.com; cat /etc/passwd","password":"test"}' \
  -H "Content-Type: application/json" > /dev/null

echo "5. Testando Brute Force (10 tentativas)..."
for i in {1..10}; do
  curl -s "$BASE_URL/identity/api/auth/login" \
    -d '{"email":"admin@example.com","password":"wrongpass'$i'"}' \
    -H "Content-Type: application/json" > /dev/null
  sleep 1
done

echo "6. Aguardando processamento..."
sleep 15

echo ""
echo "✅ Ataques avançados simulados!"
echo "📊 Monitore os alertas:"
echo "   - Wazuh: docker compose logs -f wazuh.manager"
echo "   - Fluent Bit: docker compose logs -f fluent-bit"
echo "   - OpenSearch: curl localhost:9201/crapi-logs*/_search"
echo "🌐 Acesse o Wazuh Dashboard: https://localhost"
