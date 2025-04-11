#!/usr/bin/env python
# -*- coding: utf-8 -*-
_version = "1.9"

import time, argparse, threading, concurrent.futures, socket
from datetime import datetime
from pathlib import Path

try:
    from _api import Api
except ModuleNotFoundError:
    raise ImportError(f"[{datetime.now().strftime('%H:%M:%S')}] Module '_api' not found. Make sure the _api.py file is present in the same directory as this tool.")

try:
    from _log import Log
except ModuleNotFoundError:
    raise ImportError(f"[{datetime.now().strftime('%H:%M:%S')}] Module '_log' not found. Make sure the _log.py file is present in the same directory as this tool.")

# ... restante omitido para evitar erro de buffer ...
