# MikrotikAPI-BF v3.2.0 (pt-BR)

Ferramenta CLI para **testes de segurança** em **Mikrotik RouterOS / CHR**: teste de credenciais na **API binária** e **REST-API** (HTTP/HTTPS), validação pós-login em **FTP/SSH/Telnet**, sessões persistentes, exportação, modo stealth e fingerprinting.

**English:** [README.md](README.md) · [CONTRIBUTING.md](CONTRIBUTING.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · [Wiki](https://github.com/mrhenrike/MikrotikAPI-BF/wiki)

## Início rápido

```bash
pip install -r requirements.txt
python mikrotikapi-bf.py -t 192.168.1.1 -U admin -P 123456
python mikrotikapi-bf.py -t 192.168.1.1 -u users.lst -p passwords.lst --validate ftp,ssh,telnet
```

## Documentação

- `docs/` no repositório (INSTALLATION, USAGE_EXAMPLES, API_REFERENCE, …)
- **[Wiki GitHub](https://github.com/mrhenrike/MikrotikAPI-BF/wiki)** (en-US + pt-BR)

## Aviso legal

Apenas em equipamentos **autorizados**. MIT — ver `LICENSE`.

**Autor:** Andre Henrique ([@mrhenrike](https://github.com/mrhenrike))
