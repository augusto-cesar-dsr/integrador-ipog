# Changelog - Projeto Integrador IPOG

## [2.0.0] - 2025-11-23

### 🚀 Principais Mudanças

#### Integração Completa Wazuh + OpenSearch + CR-API
- Implementada arquitetura completa de monitoramento de segurança
- Pipeline de logs automatizado: CR-API → Filebeat → Logstash → OpenSearch + Wazuh
- Detecção em tempo real de ataques e vulnerabilidades

### ✨ Novas Funcionalidades

#### Sistema de Monitoramento
- **Filebeat**: Coleta automática de logs de todos os containers Docker
- **Logstash**: Processamento e filtragem de eventos de segurança
- **OpenSearch**: Armazenamento centralizado e indexação de logs
- **Wazuh SIEM**: Detecção e alertas de ameaças em tempo real

#### Regras de Detecção Customizadas
- **10 Regras Wazuh** para detecção específica do CR-API:
  - SQL Injection (ID: 100002, Level: 10)
  - XSS (ID: 100003, Level: 8)
  - Command Injection (ID: 100004, Level: 12)
  - Path Traversal (ID: 100005, Level: 8)
  - BOLA/IDOR (ID: 100010, Level: 10)
  - Falhas de autenticação (ID: 100001, Level: 5)
  - API Abuse (ID: 100006, Level: 7)
  - Erros 500 (ID: 100007, Level: 6)
  - Acesso não autorizado (ID: 100008, Level: 8)
  - Upload suspeito (ID: 100009, Level: 9)

#### Decoders Personalizados
- Parser JSON para logs do CR-API
- Extração automática de metadados (container, IP, status HTTP)
- Classificação de eventos por severidade

### 🔧 Configurações Técnicas

#### Docker Compose
- Rede compartilhada `integrador` para comunicação entre serviços
- Volumes persistentes para dados do Wazuh e OpenSearch
- Configuração de portas otimizada (evitando conflitos)

#### Certificados SSL
- Geração automática de certificados para Wazuh
- Configuração segura de comunicação entre componentes
- Scripts de regeneração de certificados

#### Pipeline de Logs
```
CR-API Containers → Filebeat → Logstash → OpenSearch
                                    ↓
                              Wazuh Manager
```

### 📁 Estrutura de Arquivos Adicionada

```
├── filebeat/
│   └── filebeat.yml              # Configuração coleta de logs
├── logstash/
│   ├── pipeline/
│   │   └── logstash.conf         # Pipeline de processamento
│   └── config/
│       └── logstash.yml          # Configurações do Logstash
├── wazuh/single-node/config/wazuh_cluster/
│   ├── rules/
│   │   └── crapi_rules.xml       # Regras customizadas
│   └── decoders/
│       └── crapi_decoder.xml     # Decoders customizados
└── scripts/
    ├── setup-opensearch.sh       # Configuração inicial OpenSearch
    ├── test-crapi-attacks.sh     # Testes de ataques simulados
    ├── check-integration.sh      # Verificação da integração
    └── create-dashboard.sh       # Criação de dashboards
```

### 🛠️ Scripts Utilitários

#### Novos Scripts
- `setup-opensearch.sh`: Configuração automática de índices e templates
- `test-crapi-attacks.sh`: Simulação de ataques para teste de detecção
- `check-integration.sh`: Verificação completa do status da integração
- `create-dashboard.sh`: Configuração de dashboards básicos

### 🔍 Monitoramento e Alertas

#### Detecção Automática
- Monitoramento em tempo real de todos os containers
- Correlação automática de eventos de segurança
- Alertas classificados por severidade (Level 5-12)
- Armazenamento de evidências no OpenSearch

#### Dashboards
- Interface web do Wazuh para análise de alertas
- Consultas diretas no OpenSearch
- Visualização de logs em tempo real

### 🚨 Correções de Bugs

#### Problemas Resolvidos
- **Certificados SSL**: Correção de geração e permissões
- **Conflitos de Porta**: Logstash movido para porta 9601
- **Permissões Filebeat**: Configuração correta de ownership
- **Containers Órfãos**: Limpeza automática na inicialização

### 📊 Melhorias de Performance

#### Otimizações
- Pipeline Logstash otimizado para processamento de logs
- Índices OpenSearch configurados com sharding adequado
- Configuração de recursos Docker para melhor performance
- Coleta seletiva de logs (apenas containers relevantes)

### 🔐 Segurança

#### Implementações de Segurança
- Comunicação SSL entre Wazuh e OpenSearch
- Isolamento de rede entre componentes
- Configuração de autenticação para APIs
- Logs de auditoria completos

### 📈 Métricas e Monitoramento

#### Novas Capacidades
- Monitoramento de recursos dos containers
- Métricas de performance do pipeline de logs
- Estatísticas de detecção de ataques
- Relatórios de saúde do sistema

### 🎯 Casos de Uso Expandidos

#### Para Educação
- Laboratório completo de segurança cibernética
- Demonstração prática de SIEM
- Análise de vulnerabilidades web
- Correlação de eventos de segurança

#### Para Profissionais
- Ambiente de teste para regras SIEM
- Validação de detecções de segurança
- Desenvolvimento de playbooks
- Treinamento em ferramentas open source

### 📋 Próximos Passos

#### Roadmap
- [ ] Integração com ferramentas de threat intelligence
- [ ] Dashboards avançados no OpenSearch
- [ ] Automação de resposta a incidentes
- [ ] Integração com APIs externas de segurança
- [ ] Análise comportamental avançada

---

## [1.0.0] - Estado Inicial

### Componentes Básicos
- CR-API como aplicação vulnerável
- Wazuh como SIEM básico
- OpenSearch como motor de busca
- Configuração Docker básica

### Limitações da Versão Anterior
- Sem integração automática entre componentes
- Coleta manual de logs
- Regras de detecção genéricas
- Configuração manual complexa
- Sem pipeline automatizado de análise
