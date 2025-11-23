# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

## [2.0.0] - 2025-11-23

### 🚀 Adicionado
- **Fluent Bit**: Substituiu Filebeat para melhor compatibilidade com OpenSearch
- **Wazuh Agent**: Monitoramento direto dos containers Docker
- **Regras Expandidas**: 6 regras customizadas de detecção (100001-100007)
- **Scripts Automatizados**: 
  - `check-alerts.sh`: Verificação de alertas em tempo real
  - `test-crapi-attacks.sh`: Testes avançados de ataques
  - `setup-complete.sh`: Setup completo automatizado
  - `check-integration.sh`: Verificação de integração
  - `cleanup.sh`: Limpeza do ambiente
- **Detecção Avançada**: Path Traversal, Command Injection, Brute Force
- **Pipeline Lua**: Script de detecção de ataques no Fluent Bit

### 🔧 Modificado
- **Logstash**: Atualizado para versão 7.17.0 (compatível com OpenSearch)
- **Docker Compose**: Configuração otimizada com novos serviços
- **Arquitetura**: Pipeline completo Fluent Bit → OpenSearch → Logstash → Wazuh
- **README**: Documentação completa atualizada
- **Regras Wazuh**: Expandidas de 4 para 6 regras customizadas

### 🐛 Corrigido
- **Compatibilidade OpenSearch**: Problemas de conexão com Filebeat resolvidos
- **Pipeline de Logs**: Fluxo completo de dados funcionando
- **Alertas**: Detecção de SQL Injection operacional
- **Configurações**: Permissões e volumes corrigidos

### ✅ Testado
- **SQL Injection**: Detecção funcionando (Level 12)
- **XSS**: Detecção funcionando (Level 10)
- **Path Traversal**: Detecção funcionando (Level 10)
- **Command Injection**: Detecção funcionando (Level 12)
- **Brute Force**: Correlação de eventos funcionando (Level 8)
- **Pipeline Completo**: 95% funcional

## [1.0.0] - 2025-11-23

### 🚀 Adicionado
- **Projeto Base**: Integração CR-API + Wazuh + OpenSearch
- **CR-API**: Aplicação vulnerável OWASP
- **Wazuh SIEM**: Sistema de detecção e resposta
- **OpenSearch**: Armazenamento e análise de logs
- **Filebeat**: Coleta inicial de logs (posteriormente substituído)
- **Logstash**: Pipeline de processamento
- **Docker Compose**: Orquestração completa
- **Regras Básicas**: 4 regras customizadas iniciais
- **Scripts Básicos**: Setup e configuração inicial
- **Documentação**: README e estrutura base

### 🔧 Configurado
- **Certificados SSL**: Geração automática para Wazuh
- **Volumes Docker**: Persistência de dados
- **Rede Docker**: Comunicação entre serviços
- **Portas**: Exposição de serviços necessários

### 📊 Métricas
- **Containers**: 15+ serviços orquestrados
- **Regras**: 4 regras customizadas iniciais
- **Scripts**: 5+ scripts de automação
- **Documentação**: README completo com guias

---

## Formato

Este changelog segue o formato [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Semantic Versioning](https://semver.org/lang/pt-BR/).

### Tipos de Mudanças
- `Adicionado` para novas funcionalidades
- `Modificado` para mudanças em funcionalidades existentes
- `Descontinuado` para funcionalidades que serão removidas
- `Removido` para funcionalidades removidas
- `Corrigido` para correções de bugs
- `Segurança` para vulnerabilidades
