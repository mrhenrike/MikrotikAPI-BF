# 🔐 MikrotikAPI-BF v2.1

[![Python Version](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.1-red.svg)](CHANGELOG.md)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](README.md)

**Ferramenta Avançada de Pentesting para Dispositivos Mikrotik RouterOS**

Uma ferramenta profissional de segurança desenvolvida especificamente para testes de penetração em equipamentos Mikrotik Cloud Hosted Router (CHR) e dispositivos RouterOS. Oferece capacidades completas de autenticação, validação pós-login e sistema de sessão persistente.

## ✨ Principais Características

### 🔐 **Autenticação Dupla**
- **API RouterOS** (porta 8728) - Protocolo binário proprietário
- **REST-API** (portas 80/443) - HTTP/HTTPS com Basic Auth
- Suporte completo a SSL/TLS

### 🛡️ **Validação Pós-Login**
- **FTP** (porta 21) - Autenticação e acesso
- **SSH** (porta 22) - Conexão segura
- **Telnet** (porta 23) - Acesso remoto
- Portas customizadas suportadas

### 🔄 **Sistema de Sessão Persistente**
- **Resume automático** - Continua de onde parou
- **Prevenção de duplicatas** - Não testa novamente se já completou
- **Tempo estimado** - Calcula ETA baseado em tentativas anteriores
- **Gerenciamento de sessões** - Lista, visualiza e gerencia sessões

### 🥷 **Stealth Mode**
- **Delays Fibonacci** (1, 2, 3, 5, 8, 13, 21, 34, 55 segundos)
- **Rotação de User-Agent** - Evita detecção
- **Headers aleatórios** - Simula navegadores reais
- **Jitter aplicado** - Variação temporal

### 🔍 **Fingerprinting Avançado**
- **Identificação de dispositivo** - Modelo, versão RouterOS
- **Portas abertas** - Scan automático de serviços
- **Vulnerabilidades** - Detecção de riscos conhecidos
- **Score de risco** (0-10) - Avaliação de segurança

### 📊 **Progress Tracking**
- **Barra de progresso visual** - Acompanhamento em tempo real
- **ETA (Estimated Time)** - Tempo estimado de conclusão
- **Velocidade de tentativas** - Tentativas por segundo
- **Contador de sucessos** - Credenciais encontradas

### 📋 **Exportação Completa**
- **JSON** - Estrutura completa de dados
- **CSV** - Planilhas para análise
- **XML** - Integração com ferramentas
- **TXT** - Relatórios legíveis

### 🎯 **Smart Wordlists**
- **Geração inteligente** - Baseada em informações do target
- **Wordlists brasileiras** - Específicas para o mercado BR
- **Combinações customizadas** - User:pass otimizadas
- **Estatísticas** - Análise de efetividade

## 🚀 Instalação Rápida

### Pré-requisitos
- Python 3.8 - 3.12 (recomendado 3.12.x)
- Sistema: Windows, Linux, macOS

### Instalação Automática
```bash
# Clone o repositório
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF

# Execute o script de instalação
./install-v2.1.sh  # Linux/macOS
# ou
.\install-v2.1.ps1  # Windows

# Teste a instalação
python mikrotikapi-bf-v2.1.py --help
```

### Instalação Manual
```bash
# Criar ambiente virtual
python -m venv venv
source venv/bin/activate  # Linux/macOS
# ou
.\venv\Scripts\Activate.ps1  # Windows

# Instalar dependências
pip install -r requirements.txt
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

### Pentest Completo
```bash
python mikrotikapi-bf-v2.1.py \
  -t 192.168.1.1 \
  -u wordlists/users.lst \
  -p wordlists/passwords.lst \
  --validate ftp,ssh,telnet \
  --stealth \
  --fingerprint \
  --progress \
  --export-all \
  --threads 5 \
  -vv
```

## 🔧 Recursos Avançados

### Sistema de Sessão
```bash
# Listar sessões
python mikrotikapi-bf-v2.1.py --list-sessions

# Continuar sessão existente
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 --resume

# Forçar nova sessão
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 --force

# Ver informações de sessão
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 --session-info
```

### Stealth Mode
```bash
# Ativar stealth mode
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --stealth
```

**Características:**
- Delays Fibonacci (1, 2, 3, 5, 8, 13, 21, 34, 55 segundos)
- Rotação de User-Agent
- Headers aleatórios
- Jitter aplicado

### Fingerprinting
```bash
# Fingerprinting do dispositivo
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 --fingerprint
```

**Informações coletadas:**
- Versão do RouterOS
- Modelo do dispositivo
- Portas abertas
- Serviços detectados
- Vulnerabilidades conhecidas
- Score de risco (0-10)

### Exportação
```bash
# Exportar em todos os formatos
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --export-all

# Exportar formatos específicos
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --export json,csv

# Especificar diretório de saída
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --export-all --export-dir reports/
```

## 📊 Exemplo de Saída

```
[INFO] Starting MikrotikAPI-BF v2.1
[INFO] Target: 192.168.1.1
[INFO] Loading wordlist: 25 combinations
[INFO] Starting brute force with 5 threads
[FINGERPRINT] Target: 192.168.1.1
[FINGERPRINT] RouterOS Version: 7.8
[FINGERPRINT] Model: RB750
[FINGERPRINT] Risk Score: 7.5/10
[SUCCESS] [API] admin:123456
[SUCCESS] [REST] admin:123456
[VALIDATION] FTP login successful for admin:123456
[VALIDATION] SSH login successful for admin:123456
[VALIDATION] TELNET login successful for admin:123456
[INFO] Found 1 valid credential(s)
[INFO] Exporting results to results/
[INFO] Session completed successfully
```

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

## 📋 Parâmetros Principais

### Básicos
| Parâmetro | Descrição | Padrão |
|-----------|-----------|--------|
| `-t, --target` | IP do dispositivo Mikrotik | Obrigatório |
| `-u, --userlist` | Arquivo com usuários | - |
| `-p, --passlist` | Arquivo com senhas | - |
| `-d, --dictionary` | Arquivo combo (user:pass) | - |
| `--threads` | Número de threads (max 15) | 2 |
| `-s, --seconds` | Delay entre tentativas | 5 |

### Avançados
| Parâmetro | Descrição | Padrão |
|-----------|-----------|--------|
| `--api-port` | Porta da API | 8728 |
| `--http-port` | Porta HTTP | 80 |
| `--ssl` | Usar HTTPS | False |
| `--ssl-port` | Porta HTTPS | 443 |
| `--proxy` | URL do proxy | - |
| `--max-retries` | Tentativas de retry | 1 |

### Sessão
| Parâmetro | Descrição |
|-----------|-----------|
| `--resume` | Continuar sessão existente |
| `--force` | Forçar nova sessão |
| `--list-sessions` | Listar sessões disponíveis |
| `--session-info` | Mostrar informações da sessão |

### Verbosidade
| Nível | Parâmetro | Descrição |
|-------|-----------|-----------|
| **Normal** | - | Apenas resultados |
| **Verbose** | `-v` | Mostra tentativas falhadas |
| **Debug** | `-vv` | Log completo com debug |

## 📁 Estrutura do Projeto

```
MikrotikAPI-BF/
├── mikrotikapi-bf-v2.1.py      # Script principal
├── _api.py                      # Comunicação RouterOS API
├── _log.py                      # Sistema de logging
├── _session.py                  # Gerenciamento de sessões
├── _export.py                   # Exportação de resultados
├── _progress.py                 # Progress tracking
├── _stealth.py                  # Stealth mode
├── _fingerprint.py              # Fingerprinting
├── _wordlists.py                # Smart wordlists
├── wordlists/                   # Wordlists brasileiras
├── results/                     # Resultados exportados
├── sessions/                    # Sessões persistentes
├── docs/                        # Documentação completa
│   ├── README.md
│   ├── API_REFERENCE.md
│   ├── INSTALLATION.md
│   ├── USAGE_EXAMPLES.md
│   └── index.html
├── requirements.txt             # Dependências Python
├── install-v2.1.sh             # Script de instalação Linux/macOS
├── install-v2.1.ps1             # Script de instalação Windows
└── README.md                    # Este arquivo
```

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

## 📚 Documentação Completa

- **[📖 Documentação Completa](docs/README.md)** - Guia detalhado
- **[🔧 Referência da API](docs/API_REFERENCE.md)** - Documentação técnica
- **[🚀 Guia de Instalação](docs/INSTALLATION.md)** - Instalação passo a passo
- **[📚 Exemplos de Uso](docs/USAGE_EXAMPLES.md)** - Exemplos práticos
- **[🌐 Documentação HTML](docs/index.html)** - Versão web interativa

## 🆕 Changelog v2.1

### ✨ Novos Recursos
- **Sistema de sessão persistente** - Resume automático como John The Ripper
- **Stealth mode** - Delays Fibonacci e rotação de User-Agent
- **Fingerprinting avançado** - Identificação completa de dispositivos
- **Smart wordlists** - Geração inteligente de combinações
- **Progress tracking** - Barra de progresso com ETA
- **Exportação múltipla** - JSON, CSV, XML, TXT
- **Validação pós-login** - FTP, SSH, Telnet

### 🔧 Melhorias
- **Código modularizado** - Arquitetura limpa e extensível
- **Tratamento de erros** - Robusto e informativo
- **Performance otimizada** - Threading e connection pooling
- **Documentação completa** - Guias detalhados e exemplos

### 🗑️ Removido
- **Suporte a Winbox** - Protocolo proprietário não implementável
- **Suporte a Web Console** - WebFig retorna erro 406 para todos os requests

## 📞 Suporte e Contato

- **GitHub**: [github.com/mrhenrike/MikrotikAPI-BF](https://github.com/mrhenrike/MikrotikAPI-BF)
- **LinkedIn**: [linkedin.com/in/mrhenrike](https://www.linkedin.com/in/mrhenrike)
- **X (Twitter)**: [@mrhenrike](https://x.com/mrhenrike)
- **Issues**: [GitHub Issues](https://github.com/mrhenrike/MikrotikAPI-BF/issues)

## 📄 Licença

Este projeto está licenciado sob a **MIT License** - veja o arquivo [LICENSE](LICENSE) para detalhes.

## ⚠️ Aviso Legal

Esta ferramenta é destinada apenas para:

- ✅ **Testes de segurança autorizados**
- ✅ **Auditorias de segurança**
- ✅ **Pesquisa em segurança**
- ✅ **Educação em segurança**

**❌ NÃO use em sistemas que você não possui ou não tem autorização explícita para testar.**

## 🎯 Roadmap Futuro

- [ ] **Integração com Nmap** - Scan automático de portas
- [ ] **Integração com Metasploit** - Exploits automáticos
- [ ] **Integração com Nuclei** - Detecção de vulnerabilidades
- [ ] **Burp Extension** - Integração com Burp Suite
- [ ] **GUI Interface** - Interface gráfica para usuários
- [ ] **Machine Learning** - Otimização inteligente de wordlists
- [ ] **Cloud Integration** - Suporte a AWS, Azure, GCP
- [ ] **Mobile App** - Aplicativo móvel para pentesters

---

**Desenvolvido com ❤️ por [Andre Henrique](https://www.linkedin.com/in/mrhenrike)**

*Ferramenta profissional para profissionais de segurança*