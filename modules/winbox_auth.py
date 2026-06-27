#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Winbox authentication — EC-SRP5 (ROS 6.43+) and legacy MD5 (ROS < 6.43)."""

from __future__ import annotations

from typing import Tuple

try:
    from modules.winbox.ec_srp5_client import (
        AuthenticationError,
        ConnectionError_,
        WinboxTerminalClient,
    )
    _HAS_ECSRP5 = True
except ImportError:
    _HAS_ECSRP5 = False


def winbox_login(
    host: str,
    username: str,
    password: str,
    port: int = 8291,
    timeout: float = 10.0,
) -> Tuple[bool, str]:
    """Authenticate via Winbox M2 (EC-SRP5 or legacy MD5).

    Returns:
        (success, detail_message)
    """
    if not _HAS_ECSRP5:
        return False, "Winbox EC-SRP5 module unavailable (pip install pycryptodome ecdsa)"

    client = WinboxTerminalClient(host, port=port, timeout=int(timeout))
    try:
        client.connect()
        client.authenticate(username, password)
        mode = "EC-SRP5" if getattr(client, "authenticated", False) else "MD5"
        return True, f"Winbox {mode} login OK"
    except AuthenticationError:
        return False, "Winbox credentials rejected"
    except ConnectionError_ as exc:
        return False, f"Winbox connection error: {exc}"
    except Exception as exc:
        return False, str(exc)
    finally:
        try:
            client.close()
        except Exception:
            pass
