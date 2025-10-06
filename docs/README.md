# MikrotikAPI-BF v2.1 - Complete Documentation (en-us)

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

## 🎯 Overview

MikrotikAPI-BF v2.1 is an advanced pentesting toolkit for Mikrotik RouterOS and CHR. It focuses on credential testing against RouterOS API and REST-API and can validate access to FTP/SSH/Telnet after login. It includes sessions, stealth, fingerprinting, progress/ETA, and export.

### ✨ Highlights

- 🔐 API targets: RouterOS API (8728) and REST-API (80/443)
- 🛡️ Post-login validation: FTP, SSH, Telnet
- 🔄 Persistent sessions (JtR-like)
- ⚡ Stealth Mode: Fibonacci delays + UA rotation
- 📊 Fingerprinting and risk notes
- 📈 Progress/ETA and speed
- 📋 Export: JSON, CSV, XML, TXT

## 🚀 Installation

### Prerequisites

- Python 3.8–3.12 (3.12.x recommended)
- Windows, Linux, macOS

### Quick Setup

```bash
# Clone the repository
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF

# Install dependencies
pip install -r requirements.txt

# Optional installer (Linux/macOS)
chmod +x install-v2.1.sh
./install-v2.1.sh

# Or run directly
python mikrotikapi-bf-v2.1.py --help
```

### Dependencies

```
requests>=2.25.0
colorama>=0.4.6
paramiko>=2.7.0
beautifulsoup4>=4.9.0
PySocks>=1.7.1
PyYAML>=6.0
pytest>=7.0.0
```

## 🎮 Basic Usage

### Single credential

```bash
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -U admin -P 123456
```

### With wordlists

```bash
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u wordlists/users.lst -p wordlists/passwords.lst
```

### With post-login validation

```bash
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --validate ftp,ssh,telnet
```

## 🔧 Advanced Features

### Stealth Mode

```bash
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --stealth
```

Features:
- Fibonacci delays (1..55s)
- User-Agent rotation
- Randomized headers and jitter

### Fingerprinting

```bash
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 --fingerprint
```

Collected info:
- RouterOS version, model, open ports, detected services
- Known issues and risk score (0–10)

### Progress Tracking

```bash
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --progress
```

Shows: visual bar, ETA, speed, success counter

## 🔄 Session System

### Session commands

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

### Capabilities

- Persistence in `sessions/`, resume from last index
- Duplicate prevention for same target/services/wordlist
- ETA calculation

## 🛠️ Supported Services

### Primary Authentication

| Service | Port | Protocol | Notes |
|---------|------|----------|-------|
| API | 8728 | Proprietary | RouterOS API binary protocol |
| REST-API | 80/443 | HTTP/HTTPS | Basic Auth, `/rest/system/identity` |

### Post-login Validation

| Service | Port | Protocol | Status |
|---------|------|----------|--------|
| FTP | 21 | FTP | Supported |
| SSH | 22 | SSH | Supported |
| Telnet | 23 | Telnet | Supported |

### Not Supported (and why)

| Service | Reason |
|---------|--------|
| Winbox | Proprietary GUI protocol without stable/portable handshake libs; port-open checks cause false positives |
| Web Console (WebFig) | Many CHR builds return `406 Not Acceptable` or require dynamic flows that break automation reliably |

### Modern CHR defenses
- Session controls, per-source rate limiting and lockouts
- Extensive logging for auth failures and throttling
- Fronting proxies/WAFs for HTTP endpoints

Expect throttling and logs; prefer stealth and controlled maintenance windows.

## 🗺️ Attack Surface Mapping

Using the Mikrotik ecosystem map by the community project [`0ki/mikrotik-tools`](https://github.com/0ki/mikrotik-tools) — image `mikrotik_eco.png` ([direct link](https://github.com/0ki/mikrotik-tools/raw/master/mikrotik_eco.png)):

- Access vectors covered: `api`, `web` (REST), `ssh`, `telnet`, `ftp`
- Access targets: network services/daemons tied to the CPU, not storage subsystems

Why it’s possible: these are network-reachable auth endpoints intentionally exposed for management/automation.

How to mitigate:
- Disable unused services; restrict remaining ones to management networks
- Enforce strong creds/keys; firewall and address-lists
- Enable rate-limit/lockout features and monitor logs

## 📊 Export

### Formatos Suportados

```bash
# Exportar em todos os formatos
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --export-all

# Exportar formatos específicos
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --export json,csv

# Especificar diretório de saída
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --export-all --export-dir reports/
```

### Output structure

```
results/
├── mikrotik_192_168_1_1_20251005_123456.json
├── mikrotik_192_168_1_1_20251005_123456.csv
├── mikrotik_192_168_1_1_20251005_123456.xml
└── mikrotik_192_168_1_1_20251005_123456.txt
```

## ⚙️ Configuration

### Main parameters

| Parâmetro | Descrição | Padrão |
|-----------|-----------|--------|
| `-t, --target` | IP do dispositivo Mikrotik | Obrigatório |
| `-u, --userlist` | Arquivo com usuários | - |
| `-p, --passlist` | Arquivo com senhas | - |
| `-d, --dictionary` | Arquivo combo (user:pass) | - |
| `--threads` | Número de threads (max 15) | 2 |
| `-s, --seconds` | Delay entre tentativas | 5 |
| `--validate` | Serviços para validar | - |

### Advanced parameters

| Parâmetro | Descrição | Padrão |
|-----------|-----------|--------|
| `--api-port` | Porta da API | 8728 |
| `--http-port` | Porta HTTP | 80 |
| `--ssl` | Usar HTTPS | False |
| `--ssl-port` | Porta HTTPS | 443 |
| `--proxy` | URL do proxy | - |
| `--max-retries` | Tentativas de retry | 1 |

### Verbosity

| Nível | Parâmetro | Descrição |
|-------|-----------|-----------|
| **Normal** | - | Apenas resultados |
| **Verbose** | `-v` | Mostra tentativas falhadas |
| **Debug** | `-vv` | Log completo com debug |

## 🔧 Troubleshooting

### Common issues

#### 1. Erro de Python Version

```
[WARN] You are using Python 3.13.5, which is newer than supported
```

Solution: prefer Python 3.12.x or accept continuing in non-interactive mode

#### 2. Módulos Não Encontrados

```
ModuleNotFoundError: No module named '_api'
```

Solution: ensure files are in the correct directory

#### 3. Timeout de Conexão

```
Connection timeout
```

Solution: verify routing/firewall/service availability

#### 4. Erro de Permissão

```
Permission denied
```

Solution: run with adequate privileges

### Logs de Debug

```bash
# Enable full debug
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst -vv

# List sessions
python mikrotikapi-bf-v2.1.py --list-sessions

# Clean old sessions
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

## 📞 Support

- GitHub: https://github.com/mrhenrike/MikrotikAPI-BF
- LinkedIn: https://www.linkedin.com/in/mrhenrike
- X (Twitter): @mrhenrike

## 📄 License

MIT License — see LICENSE.

## ⚠️ Legal & Responsible Use

Use only on systems you own or have explicit written authorization to test. Testing will likely be logged; coordinate with stakeholders.
