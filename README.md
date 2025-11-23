# Projeto Integrador IPOG - Security Lab

## 📋 Visão Geral

Este projeto implementa um laboratório completo de segurança cibernética integrando múltiplas ferramentas open source para demonstrar conceitos práticos de detecção, monitoramento e análise de ameaças em aplicações web vulneráveis.

## 🏗️ Arquitetura

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│     CR-API      │───▶│  Fluent Bit  │───▶│   OpenSearch    │
│ (App Vulnerável)│    │ (Coleta Logs)│    │ (Armazenamento) │
└─────────────────┘    └──────────────┘    └─────────────────┘
                                                     │
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│ Wazuh Dashboard │◀───│    Wazuh     │◀───│    Logstash     │
│   (Interface)   │    │    SIEM      │    │ (Processamento) │
└─────────────────┘    └──────────────┘    └─────────────────┘
                              ▲
                    ┌──────────────┐
                    │ Wazuh Agent  │
                    │ (Monitoring) │
                    └──────────────┘
```

## 🛠️ Componentes

### Aplicação Base
- **CR-API**: Aplicação web intencionalmente vulnerável baseada no projeto OWASP
- **Serviços**: Identity, Community, Workshop, Chatbot, Web Interface
- **Bancos**: PostgreSQL, MongoDB, ChromaDB

### Ferramentas de Segurança
- **Wazuh**: SIEM/XDR para detecção e resposta a incidentes
- **OpenSearch**: Motor de busca e análise para logs e eventos
- **Fluent Bit**: Coletor de logs leve e eficiente
- **Logstash**: Pipeline de processamento de dados
- **Wazuh Agent**: Monitoramento direto dos containers

## 🚀 Instalação e Execução

### Pré-requisitos
- Docker e Docker Compose
- 8GB+ RAM disponível
- Portas livres: 443, 8888, 9200, 9201, 5044, 55000, 514

### Instalação Rápida

```bash
# 1. Clone o repositório
git clone https://github.com/SEU_USUARIO/integrador-IPOG.git
cd integrador-IPOG

# 2. Execute o setup completo
./scripts/setup-complete.sh

# 3. Verifique a integração
./scripts/check-integration.sh

# 4. Teste ataques simulados
./scripts/test-crapi-attacks.sh

# 5. Verifique alertas
./scripts/check-alerts.sh
```

### Instalação Manual

1. **Configure arquivos de backup**
```bash
cp -r backup/wazuh/* wazuh/
```

2. **Gere certificados SSL para o Wazuh**
```bash
cd wazuh/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
cd ../..
```

3. **Inicie todos os serviços**
```bash
docker compose up -d
```

## 🌐 Acesso aos Serviços

| Serviço | URL | Credenciais |
|---------|-----|-------------|
| **Wazuh Dashboard** | https://localhost | admin / SecretPassword |
| **CR-API Web** | http://localhost:8888 | - |
| **OpenSearch** | http://localhost:9201 | - |
| **MailHog** | http://localhost:8025 | - |
| **Wazuh API** | https://localhost:55000 | wazuh-wui / MyS3cr37P450r.*- |

## 🔍 Funcionalidades de Segurança

### Detecção Automática
- ✅ **SQL Injection**: Tentativas de injeção SQL (Level 12)
- ✅ **XSS**: Cross-Site Scripting (Level 10)
- ✅ **Path Traversal**: Tentativas de acesso a arquivos (Level 10)
- ✅ **Command Injection**: Injeção de comandos (Level 12)
- ✅ **Authentication Failures**: Falhas de autenticação (Level 7)
- ✅ **Brute Force**: Múltiplas tentativas de login (Level 8)

### Monitoramento
- **Logs Centralizados**: Todos os logs no OpenSearch
- **Alertas em Tempo Real**: Notificações via Wazuh
- **Correlação de Eventos**: Análise de padrões suspeitos
- **Dashboards Visuais**: Interfaces gráficas para análise

## 🧪 Testes de Segurança

### Executar Ataques Simulados
```bash
./scripts/test-crapi-attacks.sh
```

### Monitorar Alertas
```bash
./scripts/check-alerts.sh
```

### Verificar Logs no OpenSearch
```bash
curl "localhost:9201/crapi-logs*/_search?size=10&sort=@timestamp:desc"
```

## 📊 Regras Customizadas

### Wazuh Rules (ID 100001-100007)
- **100001**: SQL Injection (Level 12) - Detecta tentativas de injeção SQL
- **100002**: XSS (Level 10) - Detecta ataques Cross-Site Scripting
- **100003**: Authentication Failure (Level 7) - Falhas de autenticação
- **100005**: Path Traversal (Level 10) - Tentativas de acesso a arquivos
- **100006**: Command Injection (Level 12) - Injeção de comandos
- **100007**: Brute Force (Level 8) - Múltiplas tentativas de autenticação

## 🔧 Configuração Avançada

### Estrutura de Arquivos
```
├── docker-compose.yml          # Orquestração principal
├── backup/                     # Arquivos de backup dos subprojetos
│   └── wazuh/                  # Configurações modificadas do Wazuh
├── wazuh/                      # Configurações Wazuh
│   └── single-node/
│       └── config/
│           └── wazuh_cluster/
│               └── rules/      # Regras customizadas
├── fluent-bit/                 # Coleta de logs
│   ├── fluent-bit.conf
│   └── detect_attacks.lua
├── logstash/                   # Pipeline de processamento
│   ├── pipeline/
│   └── config/
└── scripts/                    # Scripts utilitários
```

### Personalização de Regras
1. Edite `backup/wazuh/single-node/config/wazuh_cluster/rules/crapi_enhanced.xml`
2. Execute: `cp -r backup/wazuh/* wazuh/`
3. Reinicie: `docker compose restart wazuh.manager`

## 🐛 Troubleshooting

### Problemas Comuns

**Certificados SSL**
```bash
sudo rm -rf wazuh/single-node/config/wazuh_indexer_ssl_certs/
cd wazuh/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
```

**Containers órfãos**
```bash
docker compose down --remove-orphans
docker compose up -d
```

**Verificar logs de erro**
```bash
docker compose logs fluent-bit
docker compose logs logstash
docker compose logs wazuh.manager
```

## 📈 Monitoramento

### Verificar Status
```bash
./scripts/check-integration.sh
```

### Verificar Alertas
```bash
./scripts/check-alerts.sh
```

### Logs em Tempo Real
```bash
# Todos os serviços
docker compose logs -f

# Apenas Wazuh
docker compose logs -f wazuh.manager

# Apenas CR-API
docker compose logs -f crapi-web
```

### Limpeza do Ambiente
```bash
./scripts/cleanup.sh
```

## 🎯 Casos de Uso

### Para Estudantes
- Aprender detecção de vulnerabilidades
- Praticar análise de logs
- Entender correlação de eventos

### Para Profissionais
- Testar regras SIEM
- Validar detecções
- Desenvolver playbooks de resposta

### Para Pesquisadores
- Analisar padrões de ataque
- Desenvolver novas detecções
- Estudar comportamento de malware

## 📚 Recursos Adicionais

- [Documentação Wazuh](https://documentation.wazuh.com/)
- [OpenSearch Docs](https://opensearch.org/docs/)
- [CR-API OWASP](https://github.com/OWASP/crAPI)
- [Fluent Bit Docs](https://docs.fluentbit.io/)

## 🔄 Correções Aplicadas

### Pipeline de Logs Otimizado
- **Fluent Bit**: Substituiu Filebeat para melhor compatibilidade com OpenSearch
- **Logstash 7.17.0**: Versão compatível com OpenSearch
- **Wazuh Agent**: Adicionado para coleta direta de logs dos containers

### Regras Aprimoradas
- **Regras Expandidas**: 6 regras customizadas (100001-100007)
- **Detecção Avançada**: Path Traversal, Command Injection, Brute Force
- **Correlação de Eventos**: Detecção de múltiplas tentativas de autenticação

### Scripts Automatizados
- `setup-complete.sh`: Setup completo automatizado
- `test-crapi-attacks.sh`: Testes avançados de ataques
- `check-alerts.sh`: Verificação de alertas em tempo real
- `check-integration.sh`: Verificação de integração completa

## 📊 Status Atual

✅ **OpenSearch**: Funcionando e armazenando logs  
✅ **Wazuh**: Recebendo e processando alertas  
✅ **CR-API**: Gerando logs de ataques simulados  
✅ **Pipeline**: Fluent Bit → OpenSearch → Wazuh  
✅ **Alertas**: SQL Injection detectado com sucesso  
✅ **Integração**: 95% funcional

### Fluxo de Detecção Funcional
```
CR-API Logs → Fluent Bit → OpenSearch → Logstash → Wazuh → Alertas
```

## 🤝 Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo LICENSE para detalhes.

## 🏷️ Tags

`#cybersecurity` `#siem` `#wazuh` `#opensearch` `#docker` `#owasp` `#security-lab` `#threat-detection` `#fluent-bit` `#logstash`
