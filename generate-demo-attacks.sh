#!/bin/bash

echo "🎯 Gerando ataques para demonstração..."

# Função para gerar ataques simulados
generate_attacks() {
    while true; do
        # SQL Injection
        echo "$(date) SQL Injection: SELECT * FROM users WHERE id=1 OR 1=1" | nc -u 172.20.0.8 514 2>/dev/null
        
        # XSS
        echo "$(date) XSS Attack: <script>alert('xss')</script>" | nc -u 172.20.0.8 514 2>/dev/null
        
        # Path Traversal  
        echo "$(date) Path Traversal: ../../etc/passwd" | nc -u 172.20.0.8 514 2>/dev/null
        
        # Command Injection
        echo "$(date) Command Injection: ; cat /etc/passwd" | nc -u 172.20.0.8 514 2>/dev/null
        
        # Auth Failure
        echo "$(date) Authentication failed for user admin" | nc -u 172.20.0.8 514 2>/dev/null
        
        sleep 5
    done
}

# Iniciar geração de ataques em background
generate_attacks &
ATTACK_PID=$!

echo "✅ Ataques sendo gerados (PID: $ATTACK_PID)"
echo "🛑 Para parar: kill $ATTACK_PID"
echo "$ATTACK_PID" > /tmp/attack_generator.pid
