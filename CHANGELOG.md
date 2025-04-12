# 📜 CHANGELOG

Todas as alterações relevantes neste projeto serão documentadas neste arquivo.

> Formato baseado em [Keep a Changelog](https://keepachangelog.com/en/1.0.0/)  
> Este projeto segue o versionamento [SemVer](https://semver.org/spec/v2.0.0.html)

---

## [v1.15] - 2025-04-12
### 🔥 Adicionado
- ✅ Sumário final dos serviços testados com status `SUCCESS`, `ERROR` ou `NOT TESTED`.
- ✅ Tradução completa da CLI para inglês (`en-us`) com descrições claras e intuitivas.
- ✅ Inclusão de valores `default` explícitos na ajuda do CLI (`--seconds`, `--threads`, etc).
- ✅ Checagem de portas antes de executar qualquer teste, com bypass inteligente para serviços offline.
- ✅ Supressão de logs desnecessários quando serviços estão offline.
- ✅ Melhoria no alinhamento da tabela de credenciais expostas.
- ✅ Validação de serviços adicionais (FTP, SSH, TELNET) respeitando o status de portas abertas.
- ✅ Reconhecimento automático de porta REST-API (HTTP ou SSL).
- ✅ Ocultação de alertas SSL não verificados com `urllib3.disable_warnings`.

### 🛠 Alterado
- Refatoração da função `worker()` para respeitar status de portas no início do teste.
- Mensagens de log agora padronizadas com tags `[SKIP]`, `[FAIL]`, `[WARN]`, `[INFO]`, etc.
- Uso de `format_port()` para manter consistência na apresentação dos ports.
- Logging condicional melhorado para `-v` e `-vv` com granularidade de mensagens.

---

## [v1.14] - 2025-04-10
### 🔥 Adicionado
- ✅ Detecção automática de disponibilidade de portas API, REST, HTTP, SSL, etc.
- ✅ Estrutura para passar variáveis de status de portas entre funções (`services_ok`).
- ✅ Verificação de serviços antes de qualquer brute-force.
- ✅ Nova arquitetura de injeção de dependência para serviços validados.

---

## [v1.13] - 2025-04-09
### 🔥 Adicionado
- ✅ Novo parâmetro `--ssl-port` para REST-API com HTTPS.
- ✅ Lógica condicional para alterar entre `http` e `https` de acordo com a flag `--ssl`.
- ✅ Correção de teste REST-API via `requests` com bypass de verificação de certificado.
- ✅ Exibição de logs detalhados com `-vv` incluindo falhas por porta ou timeout.

### 🐞 Corrigido
- Erro de envio de argumento `ssl_port` para função que não o aceitava.
- Conexões incorretas por usar porta 443 mesmo sem flag `--ssl`.

---

## [v1.12] - 2025-04-08
### 🔥 Adicionado
- ✅ Identificação de erro 401 quando API está desabilitada para um usuário no Mikrotik.
- ✅ Inclusão de aviso: `Hint: REST-API requires 'api' policy enabled for the group`.

---

## [v1.11] - 2025-04-07
### 🔥 Adicionado
- ✅ Suporte à flag `--validate` para testes adicionais com FTP, SSH e TELNET após login na API.
- ✅ Suporte a portas customizadas via `ftp=2121`, `telnet=2323`, etc.

---

## [v1.10] - 2025-04-06
### 🔥 Adicionado
- ✅ Logging com níveis de verbosidade: `-v` (verbose) e `-vv` (verbose-all).
- ✅ Suporte a combos no formato `user:pass` por arquivo via `--dictionary`.
- ✅ Validação de login também para usuários com senha vazia ou apenas nome.

---

## [v1.9] - 2025-04-05
### 🐞 Corrigido
- Correção na deduplicação de combos `user:pass`.
- Fix no cálculo da tabela final para quando os campos eram muito curtos.

---

## [v1.8] - 2025-04-04
### 🔥 Adicionado
- ✅ Suporte básico à API REST usando login via `requests.get()`.
- ✅ Verificação de status code HTTP para identificar sucesso.

---

## [v1.7] - 2025-04-03
### 🔧 Ajustado
- Refatoração dos módulos `_api.py` e `_log.py` para modularização.
- Inclusão de logger com colorização simples via ANSI.

---

## [v1.6] - 2025-04-02
### 🐞 Corrigido
- Corrigido bug ao interpretar múltiplas senhas para um único usuário.
- Melhoria no parsing de arquivos `.txt` com codificação UTF-8.

---

## [v1.5] - 2025-04-01
### 🔥 Adicionado
- ✅ Suporte completo a múltiplas threads (máximo: 15).
- ✅ Inclusão da flag `--threads` com valor default = 2.

---

## [v1.4] - 2025-03-25
### 🔥 Adicionado
- ✅ Suporte à flag `--seconds` para intervalo entre tentativas.
- ✅ Valor default definido como 1 segundo.

---

## [v1.3] - 2025-02-12
### 🐞 Corrigido
- Correção de travamento quando apenas `-U` e `-P` eram usados sem lista.

---

## [v1.2] - 2024-05-29
### 🔧 Ajustado
- Refatoração completa da CLI para aceitar listas e combinações simples.
- Suporte a uso mínimo com apenas `-t`, `-U` e `-P`.

---

## [v1.1] - 2023-10-05
### 🔥 Adicionado
- ✅ Leitura de lista de usuários e senhas separadas via `--userlist` e `--passlist`.
- ✅ Suporte básico ao login API via módulo `_api.py`.


---

## [v1.0 e anteriores] - 2022-08-16
### 🚀 Versão inicial
- ✅ Brute force na API do Mikrotik via socket (porta 8728).
- ✅ Argumentos simples via linha de comando.

---

