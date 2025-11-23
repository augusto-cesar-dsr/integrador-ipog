# Projeto Integrador IPOG - Security Lab

## 📋 Visão Geral

Este projeto implementa um laboratório completo de segurança cibernética integrando múltiplas ferramentas open source para demonstrar conceitos práticos de detecção, monitoramento e análise de ameaças em aplicações web vulneráveis.

## 🏗️ Arquitetura

```
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│     CR-API      │───▶│   Filebeat   │───▶│    Logstash     │
│ (App Vulnerável)│    │ (Coleta Logs)│    │ (Processamento) │
└─────────────────┘    └──────────────┘    └─────────────────┘
                                                     │
┌─────────────────┐    ┌──────────────┐    ┌─────────────────┐
│ Wazuh Dashboard │◀───│    Wazuh     │◀───│   OpenSearch    │
│   (Interface)   │    │    SIEM      │    │ (Armazenamento) │
└─────────────────┘    └──────────────┘    └─────────────────┘
```

## 🛠️ Componentes

### Aplicação Base
- **CR-API**: Aplicação web intencionalmente vulnerável baseada no projeto OWASP
- **Serviços**: Identity, Community, Workshop, Chatbot, Web Interface
- **Bancos**: PostgreSQL, MongoDB, ChromaDB

### Ferramentas de Segurança
- **Wazuh**: SIEM/XDR para detecção e resposta a incidentes
- **OpenSearch**: Motor de busca e análise para logs e eventos
- **Logstash**: Pipeline de processamento de dados
- **Filebeat**: Coletor de logs dos containers

## 🚀 Instalação e Execução

### Pré-requisitos
- Docker e Docker Compose
- 8GB+ RAM disponível
- Portas livres: 443, 8888, 9200, 9201, 5044, 55000

### Inicialização

1. **Clone o repositório**
```bash
git clone <repository-url>
cd integrador-IPOG
```

2. **Configure arquivos de backup**
```bash
./scripts/setup-backup-files.sh
```

3. **Gere certificados SSL para o Wazuh**
```bash
cd wazuh/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
cd ../..
```

4. **Inicie todos os serviços**
```bash
docker compose up -d
```

5. **Configure índices no OpenSearch**
```bash
./scripts/setup-opensearch.sh
```

6. **Verifique a integração**
```bash
./scripts/check-integration.sh
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
- ✅ **SQL Injection**: Tentativas de injeção SQL
- ✅ **XSS**: Cross-Site Scripting
- ✅ **Command Injection**: Injeção de comandos
- ✅ **Path Traversal**: Tentativas de acesso a arquivos
- ✅ **BOLA/IDOR**: Quebra de autorização
- ✅ **API Abuse**: Abuso de rate limiting
- ✅ **File Upload**: Upload de arquivos maliciosos
- ✅ **Authentication Failures**: Falhas de autenticação

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
docker compose logs -f wazuh.manager | grep -i alert
```

### Verificar Logs no OpenSearch
```bash
curl "localhost:9201/logs-*/_search?size=10&sort=@timestamp:desc"
```

## 📊 Regras Customizadas

### Wazuh Rules (ID 100001-100010)
- **100001**: Falhas de autenticação (Level 5)
- **100002**: SQL Injection (Level 10)
- **100003**: XSS (Level 8)
- **100004**: Command Injection (Level 12)
- **100005**: Path Traversal (Level 8)
- **100006**: API Abuse (Level 7)
- **100007**: Erros 500 (Level 6)
- **100008**: Acesso não autorizado (Level 8)
- **100009**: Upload suspeito (Level 9)
- **100010**: BOLA/IDOR (Level 10)

## 🔧 Configuração Avançada

### Estrutura de Arquivos
```
├── docker-compose.yml          # Orquestração principal
├── backup/                     # Arquivos de backup dos subprojetos
│   ├── wazuh/                  # Configurações modificadas do Wazuh
│   └── cr-api/                 # Configurações modificadas do CR-API
├── wazuh/                      # Configurações Wazuh
│   └── single-node/
│       ├── config/
│       │   ├── rules/          # Regras customizadas
│       │   └── decoders/       # Decoders customizados
│       └── docker-compose.yml
├── logstash/                   # Pipeline de processamento
│   ├── pipeline/
│   └── config/
├── filebeat/                   # Coleta de logs
└── scripts/                    # Scripts utilitários
```

### Personalização de Regras
1. Edite `wazuh/single-node/config/wazuh_cluster/rules/crapi_rules.xml`
2. Reinicie o Wazuh: `docker compose restart wazuh.manager`

## 🐛 Troubleshooting

### Problemas Comuns

**Certificados SSL**
```bash
# Regenerar certificados
sudo rm -rf wazuh/single-node/config/wazuh_indexer_ssl_certs/
cd wazuh/single-node
docker compose -f generate-indexer-certs.yml run --rm generator
```

**Permissões Filebeat**
```bash
sudo chown root:root filebeat/filebeat.yml
sudo chmod 600 filebeat/filebeat.yml
docker compose restart filebeat
```

**Containers órfãos**
```bash
docker compose down --remove-orphans
docker compose up -d
```

## 📈 Monitoramento

### Verificar Status
```bash
docker compose ps
```

### Logs em Tempo Real
```bash
# Wazuh
docker compose logs -f wazuh.manager

# CR-API
docker compose logs -f crapi-web

# Logstash
docker compose logs -f logstash
```

### Métricas do Sistema
```bash
# Uso de recursos
docker stats

# Índices OpenSearch
curl "localhost:9201/_cat/indices?v"
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
- [Elastic Stack](https://www.elastic.co/guide/)

## 🤝 Contribuição

1. Fork o projeto
2. Crie uma branch para sua feature
3. Commit suas mudanças
4. Push para a branch
5. Abra um Pull Request

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo LICENSE para detalhes.

## 🏷️ Tags

`#cybersecurity` `#siem` `#wazuh` `#opensearch` `#docker` `#owasp` `#security-lab` `#threat-detection`
