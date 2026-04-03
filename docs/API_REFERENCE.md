# MikrotikAPI-BF v3.6.0 - Referência da API

## 📋 Índice

1. [Módulos Principais](#módulos-principais)
2. [Classes e Funções](#classes-e-funções)
3. [Sistema de Sessão](#sistema-de-sessão)
4. [Validação de Serviços](#validação-de-serviços)
5. [Exportação](#exportação)
6. [Stealth Mode](#stealth-mode)
7. [Fingerprinting](#fingerprinting)

## 🏗️ Módulos Principais

### `mikrotikapi-bf.py`
Arquivo principal que orquestra todo o sistema.

**Funções principais:**
- `is_port_open()` - Verifica se porta está aberta
- `test_restapi_login()` - Testa autenticação REST-API
- `test_ftp_login()` - Testa autenticação FTP
- `test_ssh_login()` - Testa autenticação SSH
- `test_telnet_login()` - Testa autenticação Telnet

### `_api.py`
Módulo para comunicação com RouterOS API.

```python
from _api import Api

# Exemplo de uso
api = Api(host="192.168.1.1", port=8728)
success = api.login(username="admin", password="123456")
```

### `_log.py`
Sistema de logging colorido e verboso.

```python
from _log import Log

log = Log(verbose=True, verbose_all=False)
log.info("Mensagem informativa")
log.success("Operação bem-sucedida")
log.error("Erro ocorreu")
log.warning("Aviso importante")
log.debug("Informação de debug")
```

### `_session.py`
Sistema de sessão persistente.

```python
from _session import SessionManager

session_manager = SessionManager()
session_id = session_manager.create_session(target, services, wordlist, config)
session_data = session_manager.load_session(session_id)
session_manager.update_session(session_id, tested_count, successes, failures)
```

### `_export.py`
Sistema de exportação de resultados.

```python
from _export import ResultExporter

exporter = ResultExporter(credentials, target, output_dir="results")
json_file = exporter.export_json()
csv_file = exporter.export_csv()
xml_file = exporter.export_xml()
txt_file = exporter.export_txt()
```

### `_progress.py`
Sistema de progresso visual.

```python
from _progress import ProgressBar

progress = ProgressBar(total=1000, show_eta=True, show_speed=True)
progress.update(1, success=True)  # Atualiza com sucesso
progress.update(1, success=False) # Atualiza sem sucesso
progress.finish()  # Finaliza
```

### `_stealth.py`
Sistema de stealth mode.

```python
from _stealth import StealthManager

stealth = StealthManager(enabled=True)
delay = stealth.get_random_delay(base_delay=5.0)
headers = stealth.get_stealth_headers()
stealth.apply_stealth_delay(5.0)
```

### `_fingerprint.py`
Sistema de fingerprinting de dispositivos.

```python
from _fingerprint import MikrotikFingerprinter

fingerprinter = MikrotikFingerprinter()
info = fingerprinter.fingerprint_device("192.168.1.1")
report = fingerprinter.generate_fingerprint_report(info)
```

### `_wordlists.py`
Sistema de geração inteligente de wordlists.

```python
from _wordlists import SmartWordlistManager

wordlist_manager = SmartWordlistManager()
combinations = wordlist_manager.generate_smart_combinations(target_info)
custom_file = wordlist_manager.create_custom_wordlist(target_info)
```

## 🏛️ Classes e Funções

### Classe `EnhancedBruteforce`

Classe principal que gerencia o processo de brute force.

```python
bf = EnhancedBruteforce(
    target="192.168.1.1",
    usernames="admin",
    passwords="123456",
    combo_dict=None,
    delay=5,
    api_port=8728,
    rest_port=8729,
    http_port=80,
    use_ssl=False,
    ssl_port=443,
    max_workers=2,
    verbose=False,
    verbose_all=False,
    validate_services={'ftp': 21, 'ssh': 22, 'telnet': 23},
    services_ok={'api': True, 'http': True, 'ssl': False},
    show_progress=False,
    proxy_url=None,
    export_formats=['json', 'csv'],
    export_dir="results",
    max_retries=1,
    stealth_mode=True,
    fingerprint=True,
    session_manager=None,
    resume_session=False,
    force_new_session=False
)

bf.run()  # Executa o brute force
```

**Métodos principais:**
- `load_wordlist()` - Carrega wordlist
- `get_next_combo()` - Obtém próxima combinação
- `worker()` - Thread worker
- `run()` - Executa o processo

### Funções de Teste de Autenticação

#### `test_restapi_login(host, username, password, port, use_ssl=False)`
Testa autenticação via REST-API.

**Parâmetros:**
- `host` (str): IP do dispositivo
- `username` (str): Nome de usuário
- `password` (str): Senha
- `port` (int): Porta HTTP/HTTPS
- `use_ssl` (bool): Usar HTTPS

**Retorno:** `bool` - True se autenticação bem-sucedida

#### `test_ftp_login(host, username, password, port=21)`
Testa autenticação FTP.

**Parâmetros:**
- `host` (str): IP do dispositivo
- `username` (str): Nome de usuário
- `password` (str): Senha
- `port` (int): Porta FTP (padrão 21)

**Retorno:** `bool` - True se autenticação bem-sucedida

#### `test_ssh_login(host, username, password, port=22)`
Testa autenticação SSH.

**Parâmetros:**
- `host` (str): IP do dispositivo
- `username` (str): Nome de usuário
- `password` (str): Senha
- `port` (int): Porta SSH (padrão 22)

**Retorno:** `bool` - True se autenticação bem-sucedida

#### `test_telnet_login(host, username, password, port=23)`
Testa autenticação Telnet.

**Parâmetros:**
- `host` (str): IP do dispositivo
- `username` (str): Nome de usuário
- `password` (str): Senha
- `port` (int): Porta Telnet (padrão 23)

**Retorno:** `bool` - True se autenticação bem-sucedida

## 🔄 Sistema de Sessão

### Classe `SessionManager`

Gerencia sessões persistentes para continuidade de testes.

```python
session_manager = SessionManager(sessions_dir="sessions")
```

**Métodos principais:**

#### `create_session(target, services, wordlist, config)`
Cria nova sessão.

**Parâmetros:**
- `target` (str): IP do dispositivo
- `services` (list): Lista de serviços
- `wordlist` (list): Lista de combinações
- `config` (dict): Configuração

**Retorno:** `str` - ID da sessão

#### `load_session(session_id)`
Carrega sessão existente.

**Parâmetros:**
- `session_id` (str): ID da sessão

**Retorno:** `dict` - Dados da sessão

#### `update_session(session_id, tested_count, successes, failures, current_combo)`
Atualiza progresso da sessão.

**Parâmetros:**
- `session_id` (str): ID da sessão
- `tested_count` (int): Número de tentativas
- `successes` (list): Credenciais bem-sucedidas
- `failures` (list): Combinações falhadas
- `current_combo` (tuple): Combinação atual

#### `complete_session(session_id, successes, final_status)`
Marca sessão como completa.

**Parâmetros:**
- `session_id` (str): ID da sessão
- `successes` (list): Credenciais bem-sucedidas
- `final_status` (str): Status final

#### `find_existing_session(target, services, wordlist)`
Encontra sessão existente.

**Parâmetros:**
- `target` (str): IP do dispositivo
- `services` (list): Lista de serviços
- `wordlist` (list): Lista de combinações

**Retorno:** `dict` - Dados da sessão ou None

## 🛠️ Validação de Serviços

### Serviços Suportados

| Serviço | Porta Padrão | Função de Teste | Status |
|---------|--------------|-----------------|--------|
| **FTP** | 21 | `test_ftp_login()` | ✅ |
| **SSH** | 22 | `test_ssh_login()` | ✅ |
| **Telnet** | 23 | `test_telnet_login()` | ✅ |

### Exemplo de Uso

```python
validate_services = {
    'ftp': 21,      # Porta padrão
    'ssh': 2222,    # Porta customizada
    'telnet': 23    # Porta padrão
}

bf = EnhancedBruteforce(
    target="192.168.1.1",
    validate_services=validate_services,
    # ... outros parâmetros
)
```

## 📊 Exportação

### Classe `ResultExporter`

Gerencia exportação de resultados em múltiplos formatos.

```python
exporter = ResultExporter(
    credentials=[...],  # Lista de credenciais encontradas
    target="192.168.1.1",
    output_dir="results"
)
```

**Métodos de exportação:**

#### `export_json()`
Exporta resultados em formato JSON.

**Retorno:** `str` - Caminho do arquivo

#### `export_csv()`
Exporta resultados em formato CSV.

**Retorno:** `str` - Caminho do arquivo

#### `export_xml()`
Exporta resultados em formato XML.

**Retorno:** `str` - Caminho do arquivo

#### `export_txt()`
Exporta resultados em formato TXT.

**Retorno:** `str` - Caminho do arquivo

### Estrutura dos Dados Exportados

#### JSON
```json
{
    "scan_info": {
        "target": "192.168.1.1",
        "timestamp": "2025-10-05T12:34:56.789012",
        "total_found": 2
    },
    "credentials": [
        {
            "user": "admin",
            "pass": "123456",
            "services": ["api", "restapi", "ftp"],
            "target": "192.168.1.1"
        }
    ]
}
```

#### CSV
```csv
username,password,services
admin,123456,"api, restapi, ftp"
user,password,"api"
```

## 🥷 Stealth Mode

### Classe `StealthManager`

Implementa técnicas de stealth para evitar detecção.

```python
stealth = StealthManager(enabled=True)
```

**Métodos principais:**

#### `get_random_delay(base_delay=5.0)`
Gera delay aleatório baseado em sequência Fibonacci.

**Parâmetros:**
- `base_delay` (float): Delay base em segundos

**Retorno:** `float` - Delay calculado

#### `get_user_agent()`
Retorna User-Agent aleatório.

**Retorno:** `str` - User-Agent string

#### `get_stealth_headers()`
Gera headers HTTP aleatórios.

**Retorno:** `dict` - Headers HTTP

#### `apply_stealth_delay(base_delay=5.0)`
Aplica delay de stealth.

**Parâmetros:**
- `base_delay` (float): Delay base em segundos

### Sequência Fibonacci

Delays baseados na sequência: 1, 2, 3, 5, 8, 13, 21, 34, 55 segundos

## 🔍 Fingerprinting

### Classe `MikrotikFingerprinter`

Identifica e caracteriza dispositivos Mikrotik.

```python
fingerprinter = MikrotikFingerprinter(timeout=5)
```

**Métodos principais:**

#### `fingerprint_device(target)`
Realiza fingerprinting completo do dispositivo.

**Parâmetros:**
- `target` (str): IP do dispositivo

**Retorno:** `dict` - Informações do dispositivo

**Estrutura do retorno:**
```python
{
    'target': '192.168.1.1',
    'is_mikrotik': True,
    'routeros_version': '7.8',
    'model': 'RB750',
    'api_version': 'v1',
    'open_ports': [21, 22, 23, 80, 8728],
    'services': ['ftp', 'ssh', 'telnet', 'http', 'api'],
    'vulnerabilities': ['Exposed TELNET service'],
    'risk_score': 7.5,
    'fingerprint_time': '2025-10-05T12:34:56'
}
```

#### `generate_fingerprint_report(info)`
Gera relatório legível do fingerprinting.

**Parâmetros:**
- `info` (dict): Informações do dispositivo

**Retorno:** `str` - Relatório formatado

### Portas Verificadas

- **21** - FTP
- **22** - SSH
- **23** - Telnet
- **80** - HTTP
- **443** - HTTPS
- **8291** - Winbox
- **8728** - API
- **8729** - API-SSL

## 🎯 Smart Wordlists

### Classe `SmartWordlistManager`

Gera wordlists inteligentes baseadas em informações do target.

```python
wordlist_manager = SmartWordlistManager(wordlists_dir="wordlists")
```

**Métodos principais:**

#### `generate_smart_combinations(target_info)`
Gera combinações inteligentes baseadas no target.

**Parâmetros:**
- `target_info` (dict): Informações do target

**Retorno:** `list` - Lista de combinações (user, pass)

#### `create_custom_wordlist(target_info, output_file)`
Cria wordlist customizada.

**Parâmetros:**
- `target_info` (dict): Informações do target
- `output_file` (str): Nome do arquivo de saída

**Retorno:** `Path` - Caminho do arquivo criado

#### `get_wordlist_stats()`
Retorna estatísticas das wordlists.

**Retorno:** `dict` - Estatísticas

## 🔧 Exemplos de Uso

### Exemplo Básico

```python
from mikrotikapi_bf_v2_1 import EnhancedBruteforce

bf = EnhancedBruteforce(
    target="192.168.1.1",
    usernames="admin",
    passwords="123456"
)
bf.run()
```

### Exemplo Avançado

```python
from mikrotikapi_bf_v2_1 import EnhancedBruteforce
from _session import SessionManager
from _export import ResultExporter

# Configurar sessão
session_manager = SessionManager()

# Configurar brute force
bf = EnhancedBruteforce(
    target="192.168.1.1",
    usernames="wordlists/users.lst",
    passwords="wordlists/passwords.lst",
    validate_services={'ftp': 21, 'ssh': 22, 'telnet': 23},
    session_manager=session_manager,
    resume_session=True,
    stealth_mode=True,
    fingerprint=True,
    show_progress=True,
    export_formats=['json', 'csv', 'xml', 'txt']
)

# Executar
bf.run()

# Exportar resultados
if bf.successes:
    exporter = ResultExporter(bf.successes, bf.target)
    exporter.export_json()
    exporter.export_csv()
```

### Exemplo com Stealth Mode

```python
from _stealth import StealthManager

stealth = StealthManager(enabled=True)

# Aplicar delay de stealth
stealth.apply_stealth_delay(5.0)

# Obter headers de stealth
headers = stealth.get_stealth_headers()
```

### Exemplo de Fingerprinting

```python
from _fingerprint import MikrotikFingerprinter

fingerprinter = MikrotikFingerprinter()
info = fingerprinter.fingerprint_device("192.168.1.1")

if info['is_mikrotik']:
    print(f"RouterOS Version: {info['routeros_version']}")
    print(f"Model: {info['model']}")
    print(f"Risk Score: {info['risk_score']}/10")
```

## 📝 Notas de Desenvolvimento

### Arquitetura Modular

O sistema foi projetado com arquitetura modular para facilitar manutenção e extensão:

- **`mikrotikapi-bf.py`** - Orquestrador principal
- **`_api.py`** - Comunicação com RouterOS API
- **`_log.py`** - Sistema de logging
- **`_session.py`** - Gerenciamento de sessões
- **`_export.py`** - Exportação de resultados
- **`_progress.py`** - Progress tracking
- **`_stealth.py`** - Stealth mode
- **`_fingerprint.py`** - Fingerprinting
- **`_wordlists.py`** - Smart wordlists

### Tratamento de Erros

Todos os módulos implementam tratamento robusto de erros:

```python
try:
    result = api.login(user, password)
    return result
except Exception as e:
    log.warning(f"API error: {e}")
    return False
```

### Thread Safety

O sistema é thread-safe com uso de locks:

```python
with self.lock:
    self.successes.append(credential)
```

### Performance

Otimizações implementadas:

- Connection pooling
- Retry com exponential backoff
- Progress tracking assíncrono
- Exportação em background


