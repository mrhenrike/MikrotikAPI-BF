# MikrotikAPI-BF v2.1 - Documentação Completa

## 📋 Índice

1. [Visão Geral](#visão-geral)
2. [Instalação](#instalação)
3. [Uso Básico](#uso-básico)
4. [Recursos Avançados](#recursos-avançados)
5. [Sistema de Sessão](#sistema-de-sessão)
6. [Serviços Suportados](#serviços-suportados)
7. [Exportação de Resultados](#exportação-de-resultados)
8. [Configuração](#configuração)
9. [Troubleshooting](#troubleshooting)
10. [Changelog](#changelog)

## 🎯 Visão Geral

**MikrotikAPI-BF v2.1** é uma ferramenta avançada de pentesting para dispositivos Mikrotik RouterOS. Desenvolvida especificamente para testes de segurança em equipamentos Mikrotik Cloud Hosted Router (CHR) e dispositivos RouterOS.

### ✨ Principais Características

- **🔐 Autenticação Dupla**: Testa API (8728) e REST-API (80/443)
- **🛡️ Validação Pós-Login**: FTP, SSH, Telnet
- **🔄 Sistema de Sessão**: Persistente como John The Ripper
- **⚡ Stealth Mode**: Delays Fibonacci e rotação de User-Agent
- **📊 Fingerprinting**: Identificação avançada de dispositivos
- **📈 Progress Tracking**: Barra de progresso com ETA
- **📋 Exportação**: JSON, CSV, XML, TXT
- **🎯 Smart Wordlists**: Geração inteligente de wordlists

## 🚀 Instalação

### Pré-requisitos

- Python 3.8 - 3.12 (recomendado 3.12.x)
- Sistema operacional: Windows, Linux, macOS

### Instalação Rápida

```bash
# Clone o repositório
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF

# Instale as dependências
pip install -r requirements.txt

# Execute o script de instalação (Linux/macOS)
chmod +x install-v2.1.sh
./install-v2.1.sh

# Ou execute diretamente
python mikrotikapi-bf-v2.1.py --help
```

### Dependências

```
requests>=2.25.0
colorama>=0.4.6
paramiko>=2.7.0
beautifulsoup4>=4.9.0
PySocks>=1.7.1
PyYAML>=6.0
pytest>=7.0.0
```

## 🎮 Uso Básico

### Comando Simples

```bash
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -U admin -P 123456
```

### Com Wordlists

```bash
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u wordlists/users.lst -p wordlists/passwords.lst
```

### Com Validação de Serviços

```bash
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --validate ftp,ssh,telnet
```

## 🔧 Recursos Avançados

### Stealth Mode

```bash
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --stealth
```

**Características:**
- Delays Fibonacci (1, 2, 3, 5, 8, 13, 21, 34, 55 segundos)
- Rotação de User-Agent
- Headers aleatórios
- Jitter aplicado

### Fingerprinting

```bash
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 --fingerprint
```

**Informações coletadas:**
- Versão do RouterOS
- Modelo do dispositivo
- Portas abertas
- Serviços detectados
- Vulnerabilidades conhecidas
- Score de risco (0-10)

### Progress Tracking

```bash
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --progress
```

**Mostra:**
- Barra de progresso visual
- ETA (tempo estimado)
- Velocidade de tentativas
- Contador de sucessos

## 🔄 Sistema de Sessão

### Comandos de Sessão

```bash
# Listar sessões
python mikrotikapi-bf-v2.1.py --list-sessions

# Ver informações de sessão
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 --session-info

# Continuar sessão existente
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 --resume

# Forçar nova sessão
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 --force
```

### Funcionalidades

- **Persistência**: Sessões salvas em `sessions/`
- **Resume**: Continua de onde parou
- **Prevenção de Duplicatas**: Não testa novamente se já completou
- **Tempo Estimado**: Calcula ETA baseado em tentativas anteriores

## 🛠️ Serviços Suportados

### Autenticação Principal

| Serviço | Porta | Protocolo | Descrição |
|---------|-------|------------|-----------|
| **API** | 8728 | Binário | RouterOS API nativo |
| **REST-API** | 80/443 | HTTP/HTTPS | REST API com Basic Auth |

### Validação Pós-Login

| Serviço | Porta | Protocolo | Status |
|---------|-------|-----------|--------|
| **FTP** | 21 | FTP | ✅ Funcional |
| **SSH** | 22 | SSH | ✅ Funcional |
| **Telnet** | 23 | Telnet | ✅ Funcional |

### Serviços Removidos

| Serviço | Motivo |
|---------|--------|
| **Winbox** | Protocolo proprietário não implementável |
| **Web Console** | WebFig retorna erro 406 para todos os requests |

## 📊 Exportação de Resultados

### Formatos Suportados

```bash
# Exportar em todos os formatos
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --export-all

# Exportar formatos específicos
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --export json,csv

# Especificar diretório de saída
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --export-all --export-dir reports/
```

### Estrutura dos Arquivos

```
results/
├── mikrotik_192_168_1_1_20251005_123456.json
├── mikrotik_192_168_1_1_20251005_123456.csv
├── mikrotik_192_168_1_1_20251005_123456.xml
└── mikrotik_192_168_1_1_20251005_123456.txt
```

## ⚙️ Configuração

### Parâmetros Principais

| Parâmetro | Descrição | Padrão |
|-----------|-----------|--------|
| `-t, --target` | IP do dispositivo Mikrotik | Obrigatório |
| `-u, --userlist` | Arquivo com usuários | - |
| `-p, --passlist` | Arquivo com senhas | - |
| `-d, --dictionary` | Arquivo combo (user:pass) | - |
| `--threads` | Número de threads (max 15) | 2 |
| `-s, --seconds` | Delay entre tentativas | 5 |
| `--validate` | Serviços para validar | - |

### Parâmetros Avançados

| Parâmetro | Descrição | Padrão |
|-----------|-----------|--------|
| `--api-port` | Porta da API | 8728 |
| `--http-port` | Porta HTTP | 80 |
| `--ssl` | Usar HTTPS | False |
| `--ssl-port` | Porta HTTPS | 443 |
| `--proxy` | URL do proxy | - |
| `--max-retries` | Tentativas de retry | 1 |

### Verbosidade

| Nível | Parâmetro | Descrição |
|-------|-----------|-----------|
| **Normal** | - | Apenas resultados |
| **Verbose** | `-v` | Mostra tentativas falhadas |
| **Debug** | `-vv` | Log completo com debug |

## 🔧 Troubleshooting

### Problemas Comuns

#### 1. Erro de Python Version

```
[WARN] You are using Python 3.13.5, which is newer than supported
```

**Solução**: Use Python 3.12.x ou aceite continuar com `y`

#### 2. Módulos Não Encontrados

```
ModuleNotFoundError: No module named '_api'
```

**Solução**: Verifique se todos os arquivos estão no diretório correto

#### 3. Timeout de Conexão

```
Connection timeout
```

**Solução**: Verifique conectividade de rede e firewall

#### 4. Erro de Permissão

```
Permission denied
```

**Solução**: Execute com privilégios adequados

### Logs de Debug

```bash
# Ativar debug completo
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst -vv

# Verificar sessões
python mikrotikapi-bf-v2.1.py --list-sessions

# Limpar sessões antigas
rm -rf sessions/*.json
```

## 📝 Changelog

### v2.1 (2025-10-05)

#### ✨ Novos Recursos
- Sistema de sessão persistente
- Stealth mode com delays Fibonacci
- Fingerprinting avançado
- Smart wordlists
- Progress tracking com ETA
- Exportação em múltiplos formatos
- Validação pós-login (FTP, SSH, Telnet)

#### 🔧 Melhorias
- Código modularizado
- Tratamento de erros aprimorado
- Performance otimizada
- Documentação completa

#### 🗑️ Removido
- Suporte a Winbox (protocolo proprietário)
- Suporte a Web Console (erro 406)

### v2.0 (2024-12-01)

#### ✨ Recursos
- Suporte a API e REST-API
- Sistema de retry
- Suporte a proxy
- Descoberta de rede
- Configuração YAML

### v1.0 (2024-01-01)

#### ✨ Recursos Iniciais
- Brute force básico
- Suporte a API RouterOS
- Exportação simples

## 📞 Suporte

- **GitHub**: https://github.com/mrhenrike/MikrotikAPI-BF
- **LinkedIn**: https://www.linkedin.com/in/mrhenrike
- **X (Twitter)**: @mrhenrike

## 📄 Licença

MIT License - veja arquivo LICENSE para detalhes.

## ⚠️ Aviso Legal

Esta ferramenta é destinada apenas para:
- Testes de segurança autorizados
- Auditorias de segurança
- Pesquisa em segurança

**Use apenas em sistemas que você possui ou tem autorização explícita para testar.**
