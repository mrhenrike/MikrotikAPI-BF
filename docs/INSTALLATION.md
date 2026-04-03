# MikrotikAPI-BF v3.6.0 - Installation Guide (en-us)

## 📋 Índice

1. [Pré-requisitos](#pré-requisitos)
2. [Instalação no Windows](#instalação-no-windows)
3. [Instalação no Linux/macOS](#instalação-no-linuxmacos)
4. [Instalação via Docker](#instalação-via-docker)
5. [Verificação da Instalação](#verificação-da-instalação)
6. [Troubleshooting](#troubleshooting)
7. [Atualização](#atualização)

## 🔧 Prerequisites

### Operating Systems
- Windows 10/11 (PowerShell 5.1+ or PowerShell 7+)
- Linux (Ubuntu 18.04+, Debian 10+, CentOS 7+, Fedora)
- macOS 10.15+

### Python
- Version: 3.8.x to 3.12.x (3.12.x recommended)
- Package manager: pip/venv

### System dependencies

#### Windows
```powershell
# Check Python
python --version

# Install using winget
winget install Python.Python.3.12
```

#### Linux (Ubuntu/Debian)
```bash
# Update
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip python3-venv -y

# Verify version
python3 --version
```

#### macOS
```bash
# Using Homebrew
brew install python@3.12

# Verify version
python3 --version
```

## 🪟 Windows Installation

### Method 1: Automated

```powershell
# 1. Clone the repository
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF

# 2. Run installer
.\install-v3.6.0.ps1

# 3. Activate venv
.\venv\Scripts\Activate.ps1

# 4. Test installation
python mikrotikapi-bf-v3.6.0.py --help
```

### Method 2: Manual

```powershell
# 1. Clone o repositório
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF

# 2. Create venv
python -m venv venv

# 3. Activate venv
.\venv\Scripts\Activate.ps1

# 4. Upgrade pip
python -m pip install --upgrade pip

# 5. Install requirements
pip install -r requirements.txt

# 6. Test installation
python mikrotikapi-bf-v3.6.0.py --help
```

### Method 3: Chocolatey

```powershell
# 1. Install Chocolatey
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 2. Install Python
choco install python --version=3.12.0

# 3. Clone and setup
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF
pip install -r requirements.txt
```

## 🐧 Linux/macOS Installation

### Method 1: Automated

```bash
# 1. Clone repository
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF

# 2. Make script executable
chmod +x install-v3.6.0.sh

# 3. Run installer
./install-v3.6.0.sh

# 4. Activate venv
source venv/bin/activate

# 5. Test installation
python mikrotikapi-bf-v3.6.0.py --help
```

### Method 2: Manual

#### Ubuntu/Debian
```bash
# 1. Update system
sudo apt update && sudo apt upgrade -y

# 2. Install deps
sudo apt install python3 python3-pip python3-venv git curl -y

# 3. Clone repository
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF

# 4. Create venv
python3 -m venv venv

# 5. Activate venv
source venv/bin/activate

# 6. Upgrade pip
pip install --upgrade pip

# 7. Install requirements
pip install -r requirements.txt

# 8. Test installation
python mikrotikapi-bf-v3.6.0.py --help
```

#### CentOS/RHEL/Fedora
```bash
# 1. Update
sudo yum update -y  # CentOS/RHEL
# ou
sudo dnf update -y  # Fedora

# 2. Install deps
sudo yum install python3 python3-pip git curl -y  # CentOS/RHEL
# ou
sudo dnf install python3 python3-pip git curl -y  # Fedora

# 3. Clone and setup
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Arch Linux
```bash
# 1. Update
sudo pacman -Syu

# 2. Install deps
sudo pacman -S python python-pip git curl

# 3. Clone and setup
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### macOS
```bash
# 1. Install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Install Python
brew install python@3.12

# 3. Clone and setup
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 🐳 Docker Installation

### Dockerfile
```dockerfile
FROM python:3.12-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy files
COPY . .

# Install Python deps
RUN pip install --no-cache-dir -r requirements.txt

# Make executable
RUN chmod +x mikrotikapi-bf-v3.6.0.py

# Default command
CMD ["python", "mikrotikapi-bf-v3.6.0.py", "--help"]
```

### Docker Compose
```yaml
version: '3.8'

services:
  mikrotikapi-bf:
    build: .
    volumes:
      - ./wordlists:/app/wordlists
      - ./results:/app/results
      - ./sessions:/app/sessions
    environment:
      - PYTHONUNBUFFERED=1
    command: ["python", "mikrotikapi-bf-v3.6.0.py", "-t", "192.168.1.1", "--help"]
```

### Docker commands
```bash
# 1. Build image
docker build -t mikrotikapi-bf:v3.6.0 .

# 2. Run container
docker run -it --rm mikrotikapi-bf:v3.6.0 python mikrotikapi-bf-v3.6.0.py --help

# 3. Run with volumes
docker run -it --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/results:/app/results \
  -v $(pwd)/sessions:/app/sessions \
  mikrotikapi-bf:v3.6.0 python mikrotikapi-bf-v3.6.0.py -t 192.168.1.1 -u wordlists/users.lst -p wordlists/passwords.lst

# 4. Using Docker Compose
docker-compose up
```

## ✅ Verify Installation

### Basic test
```bash
# Check Python version
python --version
# Deve retornar: Python 3.8.x até 3.12.x

# Check script runs
python mikrotikapi-bf-v3.6.0.py --help
# Deve mostrar a ajuda do programa
```

### Dependencies test
```bash
# Verify deps installed
python -c "
import requests, colorama, paramiko, bs4, socks, yaml, pytest
print('✅ Todas as dependências estão instaladas!')
"
```

### Functionality test
```bash
# Basic local test
python mikrotikapi-bf-v3.6.0.py -t 127.0.0.1 -U admin -P 123456 --fingerprint

# Deve mostrar informações de fingerprinting
```

### Module check
```bash
# Verify modules exist
ls -la _*.py
# Deve mostrar: _api.py, _log.py, _session.py, _export.py, _progress.py, _stealth.py, _fingerprint.py, _wordlists.py
```

## 🔧 Troubleshooting

### Issue: Python not found
```bash
# Windows
# Adicionar Python ao PATH ou reinstalar

# Linux/macOS
sudo apt install python3 python3-pip  # Ubuntu/Debian
brew install python@3.12              # macOS
```

### Issue: Missing modules
```bash
# Verificar se está no diretório correto
pwd
ls -la mikrotikapi-bf-v3.6.0.py

# Reinstalar dependências
pip install --force-reinstall -r requirements.txt
```

### Issue: Permission denied
```bash
# Linux/macOS
chmod +x mikrotikapi-bf-v3.6.0.py
chmod +x install-v3.6.0.sh

# Windows
# Executar PowerShell como Administrador
```

### Issue: SSL/TLS error
```bash
# Atualizar certificados
pip install --upgrade certifi

# Ou desabilitar verificação SSL (não recomendado para produção)
export PYTHONHTTPSVERIFY=0
```

### Issue: Network timeout
```bash
# Verificar conectividade
ping 8.8.8.8

# Testar com target local
python mikrotikapi-bf-v3.6.0.py -t 127.0.0.1 --fingerprint
```

### Issue: Encoding error
```bash
# Definir encoding UTF-8
export PYTHONIOENCODING=utf-8

# Windows
set PYTHONIOENCODING=utf-8
```

## 🔄 Update

### Update via Git
```bash
# 1. Backup
cp -r sessions/ sessions_backup/
cp -r results/ results_backup/

# 2. Pull latest
git pull origin master

# 3. Upgrade deps
pip install --upgrade -r requirements.txt

# 4. Verify
python mikrotikapi-bf-v3.6.0.py --help
```

### Manual update
```bash
# 1. Fazer backup
cp -r MikrotikAPI-BF/ MikrotikAPI-BF_backup/

# 2. Baixar nova versão
wget https://github.com/mrhenrike/MikrotikAPI-BF/archive/master.zip
unzip master.zip

# 3. Copiar arquivos atualizados
cp -r MikrotikAPI-BF-master/* MikrotikAPI-BF/

# 4. Atualizar dependências
cd MikrotikAPI-BF
pip install --upgrade -r requirements.txt
```

## 📋 Installation Checklist

### ✅ Pre-install
- [ ] Python 3.8-3.12 instalado
- [ ] Git instalado
- [ ] Conexão com internet
- [ ] Permissões adequadas

### ✅ Install
- [ ] Repositório clonado
- [ ] Ambiente virtual criado
- [ ] Dependências instaladas
- [ ] Scripts com permissão de execução

### ✅ Post-install
- [ ] Teste básico executado
- [ ] Dependências verificadas
- [ ] Módulos presentes
- [ ] Funcionalidade testada

### ✅ Configuration
- [ ] Diretórios criados (wordlists/, results/, sessions/)
- [ ] Wordlists baixadas
- [ ] Configuração personalizada (se necessário)

## 🆘 Support

Se encontrar problemas durante a instalação:

1. **Verificar logs**: Execute com `-vv` para debug completo
2. **Verificar dependências**: `pip list | grep -E "(requests|colorama|paramiko)"`
3. **Verificar Python**: `python --version`
4. **Verificar permissões**: `ls -la mikrotikapi-bf-v3.6.0.py`
5. **Reportar issue**: GitHub Issues com logs completos

### Info for support
```bash
# Coletar informações do sistema
python --version
pip list
uname -a  # Linux/macOS
systeminfo  # Windows
```

## 📚 Próximos Passos

Após a instalação bem-sucedida:

1. **Leia a documentação**: `docs/README.md`
2. **Configure wordlists**: Adicione suas wordlists em `wordlists/`
3. **Teste com target local**: Use `127.0.0.1` para testes
4. **Configure proxy** (se necessário): `--proxy socks5://127.0.0.1:1080`
5. **Explore recursos avançados**: Stealth mode, fingerprinting, sessões

