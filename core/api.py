#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
RouterOS API Client — MikrotikAPI-BF
=====================================
Low-level interaction with Mikrotik RouterOS API over TCP socket.

Supports both legacy plaintext login (RouterOS < 6.43) and the modern
challenge/response (MD5) login flow used in RouterOS 6.43+.

Protocol reference:
  https://wiki.mikrotik.com/wiki/Manual:API
"""

import hashlib
import socket
from typing import List, Optional


class Api:
    """Socket-based RouterOS API client with dual-mode login support."""

    def __init__(self, host: str, port: int = 8728, use_ssl: bool = False, timeout: int = 5) -> None:
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None

    # ------------------------------------------------------------------
    # Connection helpers
    # ------------------------------------------------------------------

    def connect(self) -> None:
        """Open a TCP connection to the RouterOS API."""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.host, self.port))

    def disconnect(self) -> None:
        """Close the socket if open."""
        if self.sock:
            try:
                self.sock.close()
            except Exception:
                pass
            self.sock = None

    # ------------------------------------------------------------------
    # Wire protocol: length-prefixed words
    # ------------------------------------------------------------------

    def send(self, words: List[str]) -> None:
        """Send an API sentence (list of words) followed by an empty word."""
        if not self.sock:
            self.connect()
        for word in words:
            encoded = word.encode("utf-8")
            self.sock.send(self._encode_length(len(encoded)))  # type: ignore[union-attr]
            self.sock.send(encoded)  # type: ignore[union-attr]
        self.sock.send(b"\x00")  # type: ignore[union-attr]  # end of sentence

    def read_sentence(self) -> List[str]:
        """Read one complete API sentence (multiple length-prefixed words)."""
        words: List[str] = []
        while True:
            length = self._read_length()
            if length == 0:
                break
            raw = self._recv_exact(length)
            words.append(raw.decode("utf-8", errors="replace"))
        return words

    def _recv_exact(self, n: int) -> bytes:
        """Receive exactly *n* bytes from the socket."""
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))  # type: ignore[union-attr]
            if not chunk:
                raise ConnectionError("Socket closed mid-read")
            buf += chunk
        return buf

    def _read_length(self) -> int:
        """Decode the RouterOS variable-length prefix."""
        first = self.sock.recv(1)  # type: ignore[union-attr]
        if not first:
            return 0
        b0 = first[0]
        if b0 < 0x80:
            return b0
        if b0 < 0xC0:
            b1 = self.sock.recv(1)[0]  # type: ignore[union-attr]
            return ((b0 & 0x3F) << 8) | b1
        if b0 < 0xE0:
            rest = self._recv_exact(2)
            return ((b0 & 0x1F) << 16) | (rest[0] << 8) | rest[1]
        if b0 < 0xF0:
            rest = self._recv_exact(3)
            return ((b0 & 0x0F) << 24) | (rest[0] << 16) | (rest[1] << 8) | rest[2]
        rest = self._recv_exact(4)
        return (rest[0] << 24) | (rest[1] << 16) | (rest[2] << 8) | rest[3]

    @staticmethod
    def _encode_length(length: int) -> bytes:
        """Encode an integer as a RouterOS variable-length prefix."""
        if length < 0x80:
            return bytes([length])
        if length < 0x4000:
            length |= 0x8000
            return bytes([(length >> 8) & 0xFF, length & 0xFF])
        if length < 0x200000:
            length |= 0xC00000
            return bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
        if length < 0x10000000:
            length |= 0xE0000000
            return bytes(
                [(length >> 24) & 0xFF, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF]
            )
        return bytes(
            [0xF0, (length >> 24) & 0xFF, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF]
        )

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def login(self, username: str, password: str) -> bool:
        """
        Authenticate against RouterOS API.

        Tries the modern challenge/response (MD5) flow first; falls back to
        legacy plaintext if the server responds with ``!done`` without
        ``=ret=``.

        Args:
            username: RouterOS username.
            password: RouterOS password.

        Returns:
            ``True`` on successful login, ``False`` otherwise.
        """
        try:
            self.connect()
            # Step 1 – send login with name only to get the challenge
            self.send(["/login", f"=name={username}"])
            response = self.read_sentence()

            # Modern challenge/response login (RouterOS 6.43+)
            challenge = self._extract_value(response, "=ret=")
            if challenge:
                digest = self._md5_challenge(password, challenge)
                self.send(["/login", f"=name={username}", f"=response=00{digest}"])
                response = self.read_sentence()
                return "!done" in response and "!trap" not in response

            # Legacy plaintext login (RouterOS < 6.43)
            if "!done" in response:
                self.send(["/login", f"=name={username}", f"=password={password}"])
                response = self.read_sentence()
                return "!done" in response and "!trap" not in response

            return False
        except Exception:
            return False
        finally:
            self.disconnect()

    @staticmethod
    def _extract_value(sentence: List[str], key: str) -> Optional[str]:
        """Return the value for *key* from an API sentence, or ``None``."""
        for word in sentence:
            if word.startswith(key):
                return word[len(key):]
        return None

    @staticmethod
    def _md5_challenge(password: str, challenge_hex: str) -> str:
        """
        Compute the MD5 challenge/response hash.

        Response = MD5(\\x00 + password + challenge_bytes)
        """
        challenge_bytes = bytes.fromhex(challenge_hex)
        md5 = hashlib.md5()
        md5.update(b"\x00")
        md5.update(password.encode("utf-8"))
        md5.update(challenge_bytes)
        return md5.hexdigest()

    # ------------------------------------------------------------------
    # Helpers for post-login queries
    # ------------------------------------------------------------------

    def send_command(self, command: List[str]) -> List[List[str]]:
        """
        Send a RouterOS command and collect all response sentences.

        Args:
            command: List of words forming the command.

        Returns:
            List of sentence lists (each sentence is a list of words).
        """
        self.send(command)
        sentences: List[List[str]] = []
        while True:
            sentence = self.read_sentence()
            sentences.append(sentence)
            if any(w in ("!done", "!trap", "!fatal") for w in sentence):
                break
        return sentences

    def get_system_info(self) -> dict:
        """
        Retrieve basic system resource information.

        Returns:
            Dictionary with system resource values or empty dict on failure.
        """
        try:
            sentences = self.send_command(["/system/resource/print"])
            info: dict = {}
            for sentence in sentences:
                for word in sentence:
                    if "=" in word and word.startswith("="):
                        key, _, value = word[1:].partition("=")
                        info[key] = value
            return info
        except Exception:
            return {}

    def get_routeros_version(self) -> Optional[str]:
        """Return the RouterOS version string or ``None`` on failure."""
        info = self.get_system_info()
        return info.get("version")
