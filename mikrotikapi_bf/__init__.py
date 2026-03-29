"""
MikrotikAPI-BF — RouterOS Attack & Exploitation Framework
==========================================================
Importable Python package installed via: pip install mikrotikapi-bf

After installation, use the CLI:
    mikrotikapi-bf --help
    mikrotik-bf --help

Or import modules directly:
    from mikrotikapi_bf import __version__
    from core.api import Api
    from modules.decoder import UserDatDecoder
    from xpl.exploits import EXPLOIT_REGISTRY
"""

from version import __version__, VERSION, MAJOR, MINOR, PATCH

__all__ = ["__version__", "VERSION", "MAJOR", "MINOR", "PATCH"]
