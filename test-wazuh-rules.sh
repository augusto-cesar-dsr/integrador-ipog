#!/bin/bash

echo "=== Teste Sistemático das Regras Wazuh ==="

WAZUH_IP="172.20.0.8"
echo "Wazuh Manager IP: $WAZUH_IP"

# Função para enviar log via UDP
send_log() {
    local message="$1"
    local rule_id="$2"
    echo "Testando Rule $rule_id: $message"
    echo "$message" | nc -u $WAZUH_IP 514
    sleep 1
}

echo ""
echo "1. Testando SQL Injection (Rule 100001 - Level 12)"
send_log "SQL Injection detected: SELECT * FROM users WHERE id=1 OR 1=1" "100001"
send_log "SQL attack: union select password from users" "100001"
send_log "Database attack: drop table users" "100001"

echo ""
echo "2. Testando XSS (Rule 100002 - Level 10)"
send_log "XSS detected: <script>alert('xss')</script>" "100002"
send_log "JavaScript injection: javascript:alert(document.cookie)" "100002"

echo ""
echo "3. Testando Authentication Failure (Rule 100003 - Level 7)"
send_log "Authentication failed for user admin" "100003"
send_log "Invalid Credentials provided" "100003"

echo ""
echo "4. Testando Path Traversal (Rule 100005 - Level 10)"
send_log "Path traversal detected: /etc/passwd" "100005"
send_log "Directory traversal: ../../etc/shadow" "100005"

echo ""
echo "5. Testando Command Injection (Rule 100006 - Level 12)"
send_log "Command injection: ; cat /etc/passwd" "100006"
send_log "System command: \$(whoami)" "100006"

echo ""
echo "6. Aguardando processamento..."
sleep 10

echo ""
echo "7. Verificando alertas gerados:"
docker compose exec wazuh.manager tail -20 /var/ossec/logs/alerts/alerts.json | grep -E "(100001|100002|100003|100005|100006)" | jq -r '.rule.id + " (Level " + (.rule.level|tostring) + "): " + .rule.description' 2>/dev/null || echo "Verificando formato texto..."

echo ""
echo "8. Contagem de alertas por regra:"
docker compose exec wazuh.manager grep -E "(100001|100002|100003|100005|100006)" /var/ossec/logs/alerts/alerts.json 2>/dev/null | jq -r '.rule.id' | sort | uniq -c || echo "Sem alertas encontrados"
