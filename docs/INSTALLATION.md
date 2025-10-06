# MikrotikAPI-BF v2.1 - Guia de Instalação

## 📋 Índice

1. [Pré-requisitos](#pré-requisitos)
2. [Instalação no Windows](#instalação-no-windows)
3. [Instalação no Linux/macOS](#instalação-no-linuxmacos)
4. [Instalação via Docker](#instalação-via-docker)
5. [Verificação da Instalação](#verificação-da-instalação)
6. [Troubleshooting](#troubleshooting)
7. [Atualização](#atualização)

## 🔧 Pré-requisitos

### Sistema Operacional
- **Windows**: 10/11 (PowerShell 5.1+ ou PowerShell Core 7+)
- **Linux**: Ubuntu 18.04+, CentOS 7+, Debian 10+
- **macOS**: 10.15+ (Catalina)

### Python
- **Versão**: 3.8.x até 3.12.x (recomendado 3.12.x)
- **Gerenciador**: pip, conda, ou pyenv

### Dependências do Sistema

#### Windows
```powershell
# Verificar se Python está instalado
python --version

# Se não estiver, baixar do python.org
# Ou usar winget
winget install Python.Python.3.12
```

#### Linux (Ubuntu/Debian)
```bash
# Atualizar sistema
sudo apt update && sudo apt upgrade -y

# Instalar Python e pip
sudo apt install python3 python3-pip python3-venv -y

# Verificar versão
python3 --version
```

#### macOS
```bash
# Usando Homebrew
brew install python@3.12

# Verificar versão
python3 --version
```

## 🪟 Instalação no Windows

### Método 1: Instalação Automática

```powershell
# 1. Clone o repositório
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF

# 2. Execute o script de instalação
.\install-v2.1.ps1

# 3. Ative o ambiente virtual
.\venv\Scripts\Activate.ps1

# 4. Teste a instalação
python mikrotikapi-bf-v2.1.py --help
```

### Método 2: Instalação Manual

```powershell
# 1. Clone o repositório
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF

# 2. Crie ambiente virtual
python -m venv venv

# 3. Ative o ambiente virtual
.\venv\Scripts\Activate.ps1

# 4. Atualize pip
python -m pip install --upgrade pip

# 5. Instale dependências
pip install -r requirements.txt

# 6. Teste a instalação
python mikrotikapi-bf-v2.1.py --help
```

### Método 3: Usando Chocolatey

```powershell
# 1. Instalar Chocolatey (se não tiver)
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

# 2. Instalar Python
choco install python --version=3.12.0

# 3. Clone e configure
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF
pip install -r requirements.txt
```

## 🐧 Instalação no Linux/macOS

### Método 1: Instalação Automática

```bash
# 1. Clone o repositório
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF

# 2. Torne o script executável
chmod +x install-v2.1.sh

# 3. Execute o script de instalação
./install-v2.1.sh

# 4. Ative o ambiente virtual
source venv/bin/activate

# 5. Teste a instalação
python mikrotikapi-bf-v2.1.py --help
```

### Método 2: Instalação Manual

#### Ubuntu/Debian
```bash
# 1. Atualizar sistema
sudo apt update && sudo apt upgrade -y

# 2. Instalar dependências
sudo apt install python3 python3-pip python3-venv git curl -y

# 3. Clone o repositório
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF

# 4. Criar ambiente virtual
python3 -m venv venv

# 5. Ativar ambiente virtual
source venv/bin/activate

# 6. Atualizar pip
pip install --upgrade pip

# 7. Instalar dependências
pip install -r requirements.txt

# 8. Testar instalação
python mikrotikapi-bf-v2.1.py --help
```

#### CentOS/RHEL/Fedora
```bash
# 1. Atualizar sistema
sudo yum update -y  # CentOS/RHEL
# ou
sudo dnf update -y  # Fedora

# 2. Instalar dependências
sudo yum install python3 python3-pip git curl -y  # CentOS/RHEL
# ou
sudo dnf install python3 python3-pip git curl -y  # Fedora

# 3. Clone e configure
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

#### Arch Linux
```bash
# 1. Atualizar sistema
sudo pacman -Syu

# 2. Instalar dependências
sudo pacman -S python python-pip git curl

# 3. Clone e configure
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### macOS
```bash
# 1. Instalar Homebrew (se não tiver)
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# 2. Instalar Python
brew install python@3.12

# 3. Clone e configure
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## 🐳 Instalação via Docker

### Dockerfile
```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Instalar dependências do sistema
RUN apt-get update && apt-get install -y \
    git \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copiar arquivos
COPY . .

# Instalar dependências Python
RUN pip install --no-cache-dir -r requirements.txt

# Tornar executável
RUN chmod +x mikrotikapi-bf-v2.1.py

# Comando padrão
CMD ["python", "mikrotikapi-bf-v2.1.py", "--help"]
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
    command: ["python", "mikrotikapi-bf-v2.1.py", "-t", "192.168.1.1", "--help"]
```

### Comandos Docker
```bash
# 1. Build da imagem
docker build -t mikrotikapi-bf:v2.1 .

# 2. Executar container
docker run -it --rm mikrotikapi-bf:v2.1 python mikrotikapi-bf-v2.1.py --help

# 3. Executar com volumes
docker run -it --rm \
  -v $(pwd)/wordlists:/app/wordlists \
  -v $(pwd)/results:/app/results \
  -v $(pwd)/sessions:/app/sessions \
  mikrotikapi-bf:v2.1 python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u wordlists/users.lst -p wordlists/passwords.lst

# 4. Usando Docker Compose
docker-compose up
```

## ✅ Verificação da Instalação

### Teste Básico
```bash
# Verificar versão do Python
python --version
# Deve retornar: Python 3.8.x até 3.12.x

# Verificar se o script executa
python mikrotikapi-bf-v2.1.py --help
# Deve mostrar a ajuda do programa
```

### Teste de Dependências
```bash
# Verificar se todas as dependências estão instaladas
python -c "
import requests, colorama, paramiko, bs4, socks, yaml, pytest
print('✅ Todas as dependências estão instaladas!')
"
```

### Teste de Funcionalidade
```bash
# Teste básico com target local
python mikrotikapi-bf-v2.1.py -t 127.0.0.1 -U admin -P 123456 --fingerprint

# Deve mostrar informações de fingerprinting
```

### Verificação de Módulos
```bash
# Verificar se todos os módulos estão presentes
ls -la _*.py
# Deve mostrar: _api.py, _log.py, _session.py, _export.py, _progress.py, _stealth.py, _fingerprint.py, _wordlists.py
```

## 🔧 Troubleshooting

### Problema: Python não encontrado
```bash
# Windows
# Adicionar Python ao PATH ou reinstalar

# Linux/macOS
sudo apt install python3 python3-pip  # Ubuntu/Debian
brew install python@3.12              # macOS
```

### Problema: Módulos não encontrados
```bash
# Verificar se está no diretório correto
pwd
ls -la mikrotikapi-bf-v2.1.py

# Reinstalar dependências
pip install --force-reinstall -r requirements.txt
```

### Problema: Permissões negadas
```bash
# Linux/macOS
chmod +x mikrotikapi-bf-v2.1.py
chmod +x install-v2.1.sh

# Windows
# Executar PowerShell como Administrador
```

### Problema: Erro de SSL/TLS
```bash
# Atualizar certificados
pip install --upgrade certifi

# Ou desabilitar verificação SSL (não recomendado para produção)
export PYTHONHTTPSVERIFY=0
```

### Problema: Timeout de rede
```bash
# Verificar conectividade
ping 8.8.8.8

# Testar com target local
python mikrotikapi-bf-v2.1.py -t 127.0.0.1 --fingerprint
```

### Problema: Erro de encoding
```bash
# Definir encoding UTF-8
export PYTHONIOENCODING=utf-8

# Windows
set PYTHONIOENCODING=utf-8
```

## 🔄 Atualização

### Atualização via Git
```bash
# 1. Fazer backup da configuração
cp -r sessions/ sessions_backup/
cp -r results/ results_backup/

# 2. Atualizar código
git pull origin master

# 3. Atualizar dependências
pip install --upgrade -r requirements.txt

# 4. Verificar se tudo funciona
python mikrotikapi-bf-v2.1.py --help
```

### Atualização Manual
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

## 📋 Checklist de Instalação

### ✅ Pré-instalação
- [ ] Python 3.8-3.12 instalado
- [ ] Git instalado
- [ ] Conexão com internet
- [ ] Permissões adequadas

### ✅ Instalação
- [ ] Repositório clonado
- [ ] Ambiente virtual criado
- [ ] Dependências instaladas
- [ ] Scripts com permissão de execução

### ✅ Pós-instalação
- [ ] Teste básico executado
- [ ] Dependências verificadas
- [ ] Módulos presentes
- [ ] Funcionalidade testada

### ✅ Configuração
- [ ] Diretórios criados (wordlists/, results/, sessions/)
- [ ] Wordlists baixadas
- [ ] Configuração personalizada (se necessário)

## 🆘 Suporte

Se encontrar problemas durante a instalação:

1. **Verificar logs**: Execute com `-vv` para debug completo
2. **Verificar dependências**: `pip list | grep -E "(requests|colorama|paramiko)"`
3. **Verificar Python**: `python --version`
4. **Verificar permissões**: `ls -la mikrotikapi-bf-v2.1.py`
5. **Reportar issue**: GitHub Issues com logs completos

### Informações para Suporte
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
