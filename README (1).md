# MikrotikAPI-BF

MikrotikAPI-BF is a Python-based brute-force attack tool for Mikrotik RouterOS devices using the RouterOS API interface (port 8728 for non-SSL, 8729 for SSL).

## Features
- Brute-force attack using a password wordlist
- SSL support (via `--ssl` flag)
- Auto delay between attempts
- Clear and structured terminal output
- Modular code for easy integration and customization

## Usage

```bash
python mikrotikapi-bf.py -t <target_ip> -d <wordlist.txt> [-u <user>] [-p <port>] [-s <seconds>] [--ssl]
```

### Example
```bash
python mikrotikapi-bf.py -t 192.168.88.1 -d ./passwords.txt --ssl
```

## Arguments

| Option       | Description                              | Default         |
|--------------|------------------------------------------|-----------------|
| `-t`         | Mikrotik IP address                      | *Required*      |
| `-d`         | Path to password wordlist                | *Required*      |
| `-u`         | Username to authenticate                 | `admin`         |
| `-p`         | API port                                 | `8728`          |
| `-s`         | Delay between attempts (in seconds)      | `1`             |
| `--ssl`      | Use SSL for RouterOS API (port 8729)     | *Disabled*      |

## Requirements

- Python 3.x
- No external dependencies required
- Local modules: `_api.py`, `_log.py`

## License

MIT License
