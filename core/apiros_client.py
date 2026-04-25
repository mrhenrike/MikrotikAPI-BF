#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Based on: Arturs Laizans (https://github.com/LaiArturs/RouterOS_API)

"""
ApiRosClient — Alternative RouterOS API client with full binary protocol.

Provides a complete implementation of the RouterOS API binary protocol
including word-length encoding, MD5 challenge/response login, and SSL
support with anonymous Diffie-Hellman.

Compared to :class:`core.api.Api`:
    - Full word-length encoding (supports words up to 4 GiB)
    - ``talk()`` method returns parsed dicts instead of raw sentences
    - ``is_alive()`` health-check
    - SSL with ``ADH:ALL`` cipher suite for RouterOS API-SSL

Usage::

    client = ApiRosClient("192.168.88.1", 8728, "admin", "")
    client.open_socket()
    client.login()
    reply = client.talk("/system/identity/print")
    client.close()
"""

import binascii
import hashlib
import logging
import socket
import ssl
from typing import Any, Dict, List, Optional, Tuple, Union

log = logging.getLogger(__name__)

_SSL_CONTEXT = ssl.create_default_context()
_SSL_CONTEXT.check_hostname = False
_SSL_CONTEXT.verify_mode = ssl.CERT_NONE
_SSL_CONTEXT.set_ciphers("ADH:ALL")


class LoginError(Exception):
    """Raised when RouterOS rejects the login attempt."""


class WordTooLong(Exception):
    """Raised when a word exceeds the 4 GiB API protocol limit."""


class CreateSocketError(Exception):
    """Raised when socket connection to the RouterOS device fails."""


class RouterOSTrapError(Exception):
    """Raised when RouterOS returns a !trap error for a command."""


class ApiRosClient:
    """Full-featured RouterOS API client with binary word-length protocol.

    Args:
        address: Target IP or hostname.
        port: API port (8728 plain, 8729 SSL).
        user: Login username.
        password: Login password.
        use_ssl: Wrap socket in SSL/TLS.
        context: SSL context (defaults to anonymous DH).
        timeout: Socket timeout in seconds.
    """

    PORT = 8728
    SSL_PORT = 8729

    def __init__(
        self,
        address: str,
        port: int = 8728,
        user: str = "admin",
        password: str = "",
        use_ssl: bool = False,
        context: Optional[ssl.SSLContext] = None,
        timeout: float = 8.0,
    ) -> None:
        self.address = address
        self.user = user
        self.password = password
        self.use_ssl = use_ssl
        self.context = context or _SSL_CONTEXT
        self.timeout = timeout

        if port:
            self.port = port
        elif use_ssl:
            self.port = self.SSL_PORT
        else:
            self.port = self.PORT

        self.sock: Optional[socket.socket] = None

    def open_socket(self) -> None:
        """Open TCP connection to the RouterOS device."""
        for res in socket.getaddrinfo(
            self.address, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM
        ):
            af, socktype, proto, canonname, sa = res

        self.sock = socket.socket(af, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)

        try:
            self.sock.connect(sa)
        except OSError as exc:
            raise CreateSocketError(
                f"API failed to connect: {self.address}:{self.port} — {exc}"
            ) from exc

        if self.use_ssl:
            self.sock = self.context.wrap_socket(self.sock)

    def login(self) -> List[List[str]]:
        """Authenticate against RouterOS API (auto-detects old/new login flow).

        Returns:
            Raw paragraph from the login response.

        Raises:
            LoginError: If authentication fails.
        """

        def _reply_has_error(reply: List[List[str]]) -> bool:
            return len(reply[0]) == 2 and reply[0][0] == "!trap"

        def _process_old_login(reply: List[List[str]]) -> List[List[str]]:
            md5 = hashlib.md5(("\x00" + self.password).encode("utf-8"))
            md5.update(binascii.unhexlify(reply[0][1][5:]))
            sentence = [
                "/login",
                "=name=" + self.user,
                "=response=00" + binascii.hexlify(md5.digest()).decode("utf-8"),
            ]
            return _check_reply(self.communicate(sentence))

        def _check_reply(reply: List[List[str]]) -> List[List[str]]:
            if len(reply[0]) == 1 and reply[0][0] == "!done":
                return reply
            elif _reply_has_error(reply):
                raise LoginError(str(reply))
            elif len(reply[0]) == 2 and reply[0][1][0:5] == "=ret=":
                return _process_old_login(reply)
            else:
                raise LoginError(f"Unexpected reply to login: {reply}")

        sentence = [
            "/login",
            "=name=" + self.user,
            "=password=" + self.password,
        ]
        reply = self.communicate(sentence)
        return _check_reply(reply)

    def communicate(self, sentence_to_send: List[str]) -> List[List[str]]:
        """Send a sentence and receive the full reply paragraph.

        Args:
            sentence_to_send: List of words forming one API sentence.

        Returns:
            List of received sentences (each a list of words).
        """

        def _send_length(w: str) -> None:
            length = len(w)
            if length < 0x80:
                num_bytes = 1
            elif length < 0x4000:
                length += 0x8000
                num_bytes = 2
            elif length < 0x200000:
                length += 0xC00000
                num_bytes = 3
            elif length < 0x10000000:
                length += 0xE0000000
                num_bytes = 4
            elif length < 0x100000000:
                num_bytes = 4
                self.sock.sendall(b"\xF0")
            else:
                raise WordTooLong(f"Word length {length} exceeds 4 GiB limit")
            self.sock.sendall(length.to_bytes(num_bytes, byteorder="big"))

        def _receive_length() -> int:
            r = self.sock.recv(1)
            if r < b"\x80":
                return int.from_bytes(r, byteorder="big")
            elif r < b"\xc0":
                r += self.sock.recv(1)
                return int.from_bytes(r, byteorder="big") - 0x8000
            elif r < b"\xe0":
                r += self.sock.recv(2)
                return int.from_bytes(r, byteorder="big") - 0xC00000
            elif r < b"\xf0":
                r += self.sock.recv(3)
                return int.from_bytes(r, byteorder="big") - 0xE0000000
            elif r == b"\xf0":
                r = self.sock.recv(4)
                return int.from_bytes(r, byteorder="big")
            return 0

        def _read_sentence() -> List[str]:
            rcv_sentence: List[str] = []
            rcv_length = _receive_length()
            while rcv_length != 0:
                received = b""
                while rcv_length > len(received):
                    rec = self.sock.recv(rcv_length - len(received))
                    if rec == b"":
                        raise RuntimeError("Socket connection broken")
                    received += rec
                rcv_sentence.append(received.decode("utf-8", "backslashreplace"))
                rcv_length = _receive_length()
            return rcv_sentence

        for word in sentence_to_send:
            _send_length(word)
            self.sock.sendall(word.encode("utf-8"))
        self.sock.sendall(b"\x00")

        paragraph: List[List[str]] = []
        received_sentence = [""]
        while received_sentence[0] != "!done":
            received_sentence = _read_sentence()
            paragraph.append(received_sentence)
        return paragraph

    def talk(
        self, message: Union[str, List[str], List[List[str]]]
    ) -> List[Dict[str, str]]:
        """Send command(s) and return parsed response dicts.

        Args:
            message: Single command string, list of words, or list of sentences.

        Returns:
            List of dicts parsed from the RouterOS response attributes.

        Raises:
            RouterOSTrapError: If RouterOS returns !trap.
        """
        if isinstance(message, str):
            return self._send_one(message.split())
        elif isinstance(message, list):
            if message and isinstance(message[0], list):
                results: List[Dict[str, str]] = []
                for sentence in message:
                    results.extend(self._send_one(sentence))
                return results
            return self._send_one(message)
        raise TypeError("talk() argument must be str or list")

    def _send_one(self, sentence: List[str]) -> List[Dict[str, str]]:
        """Send a single sentence and parse the reply."""
        reply = self.communicate(sentence)
        if reply and "!trap" in reply[0][0]:
            raise RouterOSTrapError(
                f"Command: {sentence}\nError: {reply}"
            )
        nice_reply: List[Dict[str, str]] = []
        for m in range(len(reply) - 1):
            entry: Dict[str, str] = {}
            for attr in reply[m][1:]:
                if "=" in attr[1:]:
                    k, v = attr[1:].split("=", 1)
                    entry[k] = v
            if entry:
                nice_reply.append(entry)
        return nice_reply

    def is_alive(self) -> bool:
        """Check if the connection is still active."""
        try:
            self.sock.settimeout(2)
        except OSError:
            return False
        try:
            self.talk("/system/identity/print")
        except (socket.timeout, IndexError, BrokenPipeError, RuntimeError):
            self.close()
            return False
        self.sock.settimeout(self.timeout)
        return True

    def create_connection(self) -> None:
        """Open socket and login in one call."""
        self.open_socket()
        self.login()

    def close(self) -> None:
        """Close the socket."""
        if self.sock:
            try:
                self.sock.close()
            except OSError:
                pass
            self.sock = None
