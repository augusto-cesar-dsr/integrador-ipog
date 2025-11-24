#!/bin/bash

echo "🎯 Gerando ataques para demonstração..."

# Ataques via CR-API
curl -s "http://localhost:8888/identity/api/v2/user/dashboard/1' OR 1=1--" > /dev/null &
curl -s -X POST "http://localhost:8888/identity/api/auth/login" -d "email=<script>alert('xss')</script>&password=test" > /dev/null &
curl -s "http://localhost:8888/../../etc/passwd" > /dev/null &

# Ataques diretos via syslog UDP
echo "$(date) [CRAPI] SQL Injection detected: SELECT * FROM users WHERE id=1 OR 1=1" | nc -u localhost 514 2>/dev/null &
echo "$(date) [CRAPI] XSS Attack: <script>alert('xss')</script>" | nc -u localhost 514 2>/dev/null &
echo "$(date) [CRAPI] Path Traversal: ../../etc/passwd" | nc -u localhost 514 2>/dev/null &
echo "$(date) [CRAPI] Command Injection: ; cat /etc/passwd" | nc -u localhost 514 2>/dev/null &
echo "$(date) [CRAPI] Authentication failed for user admin" | nc -u localhost 514 2>/dev/null &

echo "✅ Ataques enviados!"
