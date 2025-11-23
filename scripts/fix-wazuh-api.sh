#!/bin/bash

echo "=== CORRIGINDO WAZUH API ==="

# 1. Parar Wazuh
echo "1. Parando Wazuh..."
docker compose stop wazuh.manager wazuh.dashboard

# 2. Remover decoders problemáticos
echo "2. Removendo decoders problemáticos..."
docker run --rm -v $(pwd)/wazuh/single-node/config/wazuh_cluster:/config alpine sh -c "rm -f /config/decoders/crapi_decoder.xml*"

# 3. Simplificar regras
echo "3. Simplificando regras..."
cat > wazuh/single-node/config/wazuh_cluster/rules/crapi_rules.xml << 'EOF'
<group name="crapi,web,application">
  <rule id="100001" level="5">
    <match>crapi</match>
    <description>CR-API: Basic log detected</description>
    <group>crapi</group>
  </rule>
</group>
EOF

# 4. Reiniciar
echo "4. Reiniciando Wazuh..."
docker compose start wazuh.manager
sleep 30
docker compose start wazuh.dashboard

echo "5. Testando API..."
sleep 15
curl -k -u wazuh-wui:MyS3cr37P450r.*- https://localhost:55000/ --max-time 5

echo ""
echo "✅ Correção aplicada. Acesse: https://localhost"
echo "   Usuário: admin"
echo "   Senha: SecretPassword"
