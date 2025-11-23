# Backup de Arquivos Modificados

Este diretório contém cópias de segurança dos arquivos modificados nos subprojetos Wazuh e CR-API.

## 📁 Estrutura

```
backup/
├── wazuh/
│   ├── docker-compose.yml           # Docker compose modificado do Wazuh
│   └── wazuh_cluster/
│       ├── wazuh_manager.conf       # Configuração do Wazuh Manager
│       ├── rules/
│       │   └── crapi_rules.xml      # Regras customizadas para CR-API
│       └── decoders/
│           └── crapi_decoder.xml    # Decoders customizados
└── cr-api/
    └── docker-compose.yml           # Docker compose modificado do CR-API
```

## 🔄 Como Usar

### Para Wazuh:
```bash
# Copiar configurações do Wazuh
cp backup/wazuh/docker-compose.yml wazuh/single-node/
cp -r backup/wazuh/wazuh_cluster wazuh/single-node/config/
```

### Para CR-API:
```bash
# Copiar configurações do CR-API
cp backup/cr-api/docker-compose.yml cr-api/deploy/docker/
```

## 📋 Arquivos Modificados

### Wazuh
- **docker-compose.yml**: Adicionados volumes para regras e decoders customizados
- **wazuh_manager.conf**: Configuração para monitorar logs do CR-API
- **crapi_rules.xml**: 10 regras de detecção específicas para CR-API
- **crapi_decoder.xml**: Decoders para parsing de logs JSON do CR-API

### CR-API
- **docker-compose.yml**: Configuração de rede compartilhada para integração

## ⚠️ Importante

Estes arquivos são essenciais para o funcionamento da integração. Certifique-se de copiá-los antes de executar o projeto.
