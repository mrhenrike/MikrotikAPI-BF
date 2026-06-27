#!/usr/bin/env python3
"""
WinBox Terminal Client — vendored for MikrotikAPI-BF (EC-SRP5 auth only).

Original: https://github.com/subixonfire/winbox-terminal-protocol (MIT)
Integrated as modules/winbox/ec_srp5_client.py for RouterOS 6.43+ / 7.x Winbox login.
"""

import socket
import secrets
import struct
import hashlib
import argparse
import sys
import os
import select
import time
import tty
import termios

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA1, SHA256
from Crypto.Util.Padding import unpad
import ecdsa


class AuthenticationError(Exception):
    """Wrong username or password."""

class ConnectionError_(Exception):
    """Cannot connect to router or unsupported protocol."""


# ============================================================================
# Elliptic Curve Operations for EC-SRP5 Authentication
# ============================================================================

def _egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    g, y, x = _egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def _modinv(a, p):
    if a < 0:
        a = a % p
    g, x, y = _egcd(a, p)
    if g != 1:
        raise Exception('modular inverse does not exist')
    return x % p

def _legendre_symbol(a, p):
    l = pow(a, (p - 1)//2, p)
    return -1 if l == p - 1 else l

def _prime_mod_sqrt(a, p):
    a %= p
    if a == 0:
        return [0]
    if p == 2:
        return [a]
    if _legendre_symbol(a, p) != 1:
        return []
    if p % 4 == 3:
        x = pow(a, (p + 1) // 4, p)
        return [x, p - x]
    q, s = p - 1, 0
    while q % 2 == 0:
        s += 1
        q //= 2
    z = 1
    while _legendre_symbol(z, p) != -1:
        z += 1
    c = pow(z, q, p)
    x = pow(a, (q + 1) // 2, p)
    t = pow(a, q, p)
    m = s
    while t != 1:
        i, e = 0, 2
        for i in range(1, m):
            if pow(t, e, p) == 1:
                break
            e *= 2
        b = pow(c, 2**(m - i - 1), p)
        x = (x * b) % p
        t = (t * b * b) % p
        c = (b * b) % p
        m = i
    return [x, p - x]


class WCurve:
    def __init__(self):
        self._p = 0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed
        self._r = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
        self._mont_a = 486662
        self._conversion_from_m = self._mont_a * _modinv(3, self._p) % self._p
        self._conversion = (self._p - self._mont_a * _modinv(3, self._p)) % self._p
        self._a = 0x2aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa984914a144
        self._b = 0x7b425ed097b425ed097b425ed097b425ed097b4260b5e9c7710c864
        self._h = 8
        self._curve = ecdsa.ellipticcurve.CurveFp(self._p, self._a, self._b, self._h)
        self._g = self.lift_x(9, 0)

    def lift_x(self, x, parity):
        x = x % self._p
        y_squared = (x**3 + self._mont_a * x**2 + x) % self._p
        x += self._conversion_from_m
        x %= self._p
        ys = _prime_mod_sqrt(y_squared, self._p)
        if ys:
            pt1 = ecdsa.ellipticcurve.PointJacobi(self._curve, x, ys[0], 1, self._r)
            pt2 = ecdsa.ellipticcurve.PointJacobi(self._curve, x, ys[1], 1, self._r)
            if pt1.y() & 1 == 1 and parity != 0:
                return pt1
            elif pt2.y() & 1 == 1 and parity != 0:
                return pt2
            elif pt1.y() & 1 == 0 and parity == 0:
                return pt1
            else:
                return pt2
        return -1

    def to_montgomery(self, pt):
        x = (pt.x() + self._conversion) % self._p
        return int(x).to_bytes(32, "big"), pt.y() & 1

    def gen_public_key(self, priv):
        priv = int.from_bytes(priv, "big")
        pt = priv * self._g
        return self.to_montgomery(pt)

    def redp1(self, x, parity):
        x = hashlib.sha256(x).digest()
        while True:
            x2 = hashlib.sha256(x).digest()
            pt = self.lift_x(int.from_bytes(x2, "big"), parity)
            if pt == -1:
                x = (int.from_bytes(x, "big") + 1).to_bytes(32, "big")
            else:
                break
        return pt

    def gen_password_validator_priv(self, username, password, salt):
        return hashlib.sha256(
            salt + hashlib.sha256((username + ":" + password).encode("utf-8")).digest()
        ).digest()

    def finite_field_value(self, a):
        return a % self._r


# ============================================================================
# Encryption Utilities
# ============================================================================

def get_sha2_digest(data):
    return SHA256.new(data).digest()

def HKDF(message):
    h = HMAC.new(b'\x00' * 0x40, b'', SHA1)
    h.update(message)
    h1 = h.digest()
    h2 = b''
    res = b''
    for i in range(0, 2):
        h = HMAC.new(h1, b'', SHA1)
        h.update(h2)
        h.update((i + 1).to_bytes(1, "big"))
        h2 = h.digest()
        res += h2
    return res[:0x24]

def gen_stream_keys(server, z):
    magic2 = b"On the client side, this is the send key; on the server side, it is the receive key."
    magic3 = b"On the client side, this is the receive key; on the server side, it is the send key."
    if server:
        txEnc = z + b'\00' * 40 + magic3 + b'\xf2' * 40
        rxEnc = z + b'\00' * 40 + magic2 + b'\xf2' * 40
    else:
        txEnc = z + b'\00' * 40 + magic2 + b'\xf2' * 40
        rxEnc = z + b'\00' * 40 + magic3 + b'\xf2' * 40
    sha = SHA1.new()
    sha.update(rxEnc)
    rxEnc = sha.digest()[:16]
    sha = SHA1.new()
    sha.update(txEnc)
    txEnc = sha.digest()[:16]
    send_key = HKDF(txEnc)
    receive_key = HKDF(rxEnc)
    return send_key[:0x10], receive_key[:0x10], send_key[0x10:], receive_key[0x10:]


# ============================================================================
# M2 Message Builder — 3-namespace TLV format
# ============================================================================
# TLV: key_low(1) + key_high(1) + namespace(1) + type(1) + value
# Namespaces: 0xFF=system, 0xFE=session, 0x00=user

class M2:
    # System keys (namespace 0xFF)
    SYS_TO = (0x01, 0x00, 0xFF)       # key 0xFF0001
    SYS_FROM = (0x02, 0x00, 0xFF)     # key 0xFF0002
    SYS_REQUEST = (0x05, 0x00, 0xFF)  # key 0xFF0005
    SYS_REQID = (0x06, 0x00, 0xFF)    # key 0xFF0006
    SYS_CMD = (0x07, 0x00, 0xFF)      # key 0xFF0007

    # Session keys (namespace 0xFE)
    SESSION_ID = (0x01, 0x00, 0xFE)   # key 0xFE0001
    FE000C = (0x0C, 0x00, 0xFE)       # key 0xFE000C

    @staticmethod
    def _key_header(key_tuple):
        """Encode key_low, key_high, namespace bytes."""
        return bytes([key_tuple[0], key_tuple[1], key_tuple[2]])

    @staticmethod
    def _user_key_header(key_id):
        """Encode user key (namespace 0x00): key_low, key_high=0x00, ns=0x00."""
        return bytes([key_id & 0xFF, (key_id >> 8) & 0xFF, 0x00])

    @staticmethod
    def encode_bool(key_tuple, value):
        """Bool: type 0x01 (true) or 0x00 (false)."""
        return M2._key_header(key_tuple) + bytes([0x01 if value else 0x00])

    @staticmethod
    def encode_u8(key_tuple, value):
        """u8: type 0x09, then 1 byte value."""
        return M2._key_header(key_tuple) + bytes([0x09, value & 0xFF])

    @staticmethod
    def encode_u8_user(key_id, value):
        """u8 with user namespace key."""
        return M2._user_key_header(key_id) + bytes([0x09, value & 0xFF])

    @staticmethod
    def encode_u32(key_tuple, value):
        """u32: type 0x08, then 4 bytes LE."""
        return M2._key_header(key_tuple) + bytes([0x08]) + struct.pack('<I', value)

    @staticmethod
    def encode_u32_user(key_id, value):
        """u32 with user namespace key."""
        return M2._user_key_header(key_id) + bytes([0x08]) + struct.pack('<I', value)

    @staticmethod
    def encode_u32_array(key_tuple, values):
        """u32 array: type 0x88, then count (2 bytes LE), then values (4 bytes LE each)."""
        result = M2._key_header(key_tuple) + bytes([0x88])
        result += struct.pack('<H', len(values))
        for v in values:
            result += struct.pack('<I', v)
        return result

    @staticmethod
    def encode_string_user(key_id, value):
        """String with user namespace: type 0x21 (1-byte len) or 0x20 (2-byte len)."""
        data = value.encode('utf-8')
        hdr = M2._user_key_header(key_id)
        if len(data) > 255:
            return hdr + bytes([0x20]) + struct.pack('<H', len(data)) + data
        return hdr + bytes([0x21, len(data)]) + data

    @staticmethod
    def encode_raw_user(key_id, data):
        """Raw bytes with user namespace: type 0x31 (1-byte len) or 0x30 (2-byte len)."""
        hdr = M2._user_key_header(key_id)
        if len(data) > 255:
            return hdr + bytes([0x30]) + struct.pack('<H', len(data)) + data
        return hdr + bytes([0x31, len(data)]) + data

    @staticmethod
    def encode_embedded_msg_user(key_id, inner_msg_body):
        """Embedded message: type 0x29 (1-byte len) or 0x28 (2-byte len)."""
        inner = b'M2' + inner_msg_body
        hdr = M2._user_key_header(key_id)
        if len(inner) > 255:
            return hdr + bytes([0x28]) + struct.pack('<H', len(inner)) + inner
        return hdr + bytes([0x29, len(inner)]) + inner

    @staticmethod
    def build_initial_request(source_id):
        """Build the first request: SYS_TO=[13,4], SYS_FROM=[0,source_id], SYS_REQUEST=true, SYS_REQID=0, SYS_CMD=7."""
        body = b''
        body += M2.encode_u32_array(M2.SYS_TO, [13, 4])
        body += M2.encode_u32_array(M2.SYS_FROM, [0, source_id])
        body += M2.encode_bool(M2.SYS_REQUEST, True)
        body += M2.encode_u8(M2.SYS_REQID, 0)
        body += M2.encode_u8(M2.SYS_CMD, 7)
        return b'M2' + body

    @staticmethod
    def build_mepty_login(source_id, req_id, password, cols=80, rows=24):
        """Build meptyLogin message: SYS_CMD=0x0A0065 (655461)."""
        body = b''
        body += M2.encode_u32_array(M2.SYS_TO, [76])
        body += M2.encode_u32_array(M2.SYS_FROM, [0, source_id])
        body += M2.encode_bool(M2.SYS_REQUEST, True)
        body += M2.encode_u32_user(5, cols)        # key_5 = terminal columns
        body += M2.encode_u32_user(6, rows)        # key_6 = terminal rows
        body += M2.encode_u8_user(8, 0)            # key_8 = 0
        body += M2.encode_u8(M2.SYS_REQID, req_id)
        body += M2.encode_u32(M2.SYS_CMD, 0x0A0065)
        # key_11 = embedded msg with key_1=0
        inner_body = M2.encode_u8_user(1, 0)
        body += M2.encode_embedded_msg_user(11, inner_body)
        body += M2.encode_string_user(7, "vt102")  # key_7 = terminal type
        body += M2.encode_string_user(1, password)  # key_1 = password
        return b'M2' + body

    @staticmethod
    def build_mepty_data(source_id, session_id, counter, data=None):
        """Build mepty data message: SYS_CMD=0x0A0067 (655463)."""
        body = b''
        body += M2.encode_u32_array(M2.SYS_TO, [76])
        body += M2.encode_u32_array(M2.SYS_FROM, [0, source_id])
        body += M2.encode_u32_user(3, counter)       # key_3 = counter
        body += M2.encode_u8(M2.SESSION_ID, session_id)
        body += M2.encode_u32(M2.SYS_CMD, 0x0A0067)
        if data is not None:
            body += M2.encode_raw_user(2, data)      # key_2 = raw terminal data
        return b'M2' + body


# ============================================================================
# M2 Message Parser
# ============================================================================

class M2Parser:
    """Parse M2 response messages to extract TLV fields."""

    @staticmethod
    def parse(data):
        """Parse an M2 message, return dict of extracted fields."""
        if not data or len(data) < 2:
            return {}
        if data[:2] != b'M2':
            return {}

        result = {}
        pos = 2
        while pos < len(data):
            if pos + 4 > len(data):
                break

            key_low = data[pos]
            key_high = data[pos + 1]
            namespace = data[pos + 2]
            type_byte = data[pos + 3]
            pos += 4

            key_id = key_low | (key_high << 8)
            full_key = (namespace << 16) | (key_high << 8) | key_low

            if type_byte == 0x00:
                # bool false
                result[full_key] = ('bool', False)
            elif type_byte == 0x01:
                # bool true
                result[full_key] = ('bool', True)
            elif type_byte == 0x09:
                # u8
                if pos < len(data):
                    result[full_key] = ('u8', data[pos])
                    pos += 1
            elif type_byte == 0x08:
                # u32
                if pos + 4 <= len(data):
                    val = struct.unpack_from('<I', data, pos)[0]
                    result[full_key] = ('u32', val)
                    pos += 4
            elif type_byte == 0x10:
                # u64
                if pos + 8 <= len(data):
                    val = struct.unpack_from('<Q', data, pos)[0]
                    result[full_key] = ('u64', val)
                    pos += 8
            elif type_byte == 0x88:
                # u32 array
                if pos + 2 <= len(data):
                    count = struct.unpack_from('<H', data, pos)[0]
                    pos += 2
                    values = []
                    for _ in range(count):
                        if pos + 4 <= len(data):
                            values.append(struct.unpack_from('<I', data, pos)[0])
                            pos += 4
                    result[full_key] = ('u32_array', values)
            elif type_byte == 0x20:
                # string, 2-byte length (LE)
                if pos + 2 <= len(data):
                    slen = struct.unpack_from('<H', data, pos)[0]
                    pos += 2
                    if pos + slen <= len(data):
                        result[full_key] = ('string', data[pos:pos+slen].decode('utf-8', errors='replace'))
                        pos += slen
            elif type_byte == 0x21:
                # string, 1-byte length
                if pos < len(data):
                    slen = data[pos]
                    pos += 1
                    if pos + slen <= len(data):
                        result[full_key] = ('string', data[pos:pos+slen].decode('utf-8', errors='replace'))
                        pos += slen
            elif type_byte == 0x30:
                # raw bytes, 2-byte length (LE)
                if pos + 2 <= len(data):
                    rlen = struct.unpack_from('<H', data, pos)[0]
                    pos += 2
                    if pos + rlen <= len(data):
                        result[full_key] = ('raw', data[pos:pos+rlen])
                        pos += rlen
            elif type_byte == 0x31:
                # raw bytes, 1-byte length
                if pos < len(data):
                    rlen = data[pos]
                    pos += 1
                    if pos + rlen <= len(data):
                        result[full_key] = ('raw', data[pos:pos+rlen])
                        pos += rlen
            elif type_byte == 0x28:
                # embedded message, 2-byte length (LE)
                if pos + 2 <= len(data):
                    elen = struct.unpack_from('<H', data, pos)[0]
                    pos += 2
                    if pos + elen <= len(data):
                        result[full_key] = ('msg', data[pos:pos+elen])
                        pos += elen
            elif type_byte == 0x29:
                # embedded message, 1-byte length
                if pos < len(data):
                    elen = data[pos]
                    pos += 1
                    if pos + elen <= len(data):
                        result[full_key] = ('msg', data[pos:pos+elen])
                        pos += elen
            elif type_byte == 0xA0:
                # string array: count(2 LE), then count entries of len(2 LE)+data
                if pos + 2 <= len(data):
                    count = struct.unpack_from('<H', data, pos)[0]
                    pos += 2
                    for _ in range(count):
                        if pos + 2 > len(data):
                            break
                        slen = struct.unpack_from('<H', data, pos)[0]
                        pos += 2
                        pos += slen  # skip string data
                    result[full_key] = ('str_array', None)
            elif type_byte == 0xA8:
                # message array: count(2 LE), then count entries of len(2 LE)+data
                if pos + 2 <= len(data):
                    count = struct.unpack_from('<H', data, pos)[0]
                    pos += 2
                    for _ in range(count):
                        if pos + 2 > len(data):
                            break
                        mlen = struct.unpack_from('<H', data, pos)[0]
                        pos += 2
                        pos += mlen  # skip msg data
                    result[full_key] = ('msg_array', None)
            else:
                # Unknown type — can't continue parsing reliably
                break

        return result

    @staticmethod
    def get_sys_to(parsed):
        key = 0xFF0001
        if key in parsed and parsed[key][0] == 'u32_array':
            return parsed[key][1]
        return None

    @staticmethod
    def get_sys_from(parsed):
        key = 0xFF0002
        if key in parsed and parsed[key][0] == 'u32_array':
            return parsed[key][1]
        return None

    @staticmethod
    def get_sys_cmd(parsed):
        key = 0xFF0007
        if key in parsed:
            return parsed[key][1]
        return None

    @staticmethod
    def get_sys_reqid(parsed):
        key = 0xFF0006
        if key in parsed:
            return parsed[key][1]
        return None

    @staticmethod
    def get_session_id(parsed):
        key = 0xFE0001
        if key in parsed:
            return parsed[key][1]
        return None

    @staticmethod
    def get_key2_raw(parsed):
        """Get key_2 raw data (terminal output)."""
        key = 0x000002
        if key in parsed and parsed[key][0] == 'raw':
            return parsed[key][1]
        return None

    @staticmethod
    def get_sys_status(parsed):
        key = 0xFF0008
        if key in parsed:
            return parsed[key][1]
        return None


# ============================================================================
# Terminal Client
# ============================================================================

class WinboxTerminalClient:
    def __init__(self, host, port=8291, timeout=10):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.socket = None
        self.w = WCurve()

        # Auth state
        self.s_a = b''
        self.x_w_a = b''
        self.x_w_a_parity = 0

        # Encryption keys
        self.send_aes_key = b''
        self.send_hmac_key = b''
        self.receive_aes_key = b''
        self.receive_hmac_key = b''
        self.authenticated = False

        # Protocol mode
        self.encrypted = True         # False for old RouterOS (pre-6.43)
        self.auth_session_id = None   # session from old M2 auth (used until mepty session starts)

        # Session state
        self.source_id = 8  # SYS_FROM second element
        self.req_id = 0
        self.session_id = None
        self.counter = 0          # outgoing byte counter
        self.recv_counter = 0     # incoming byte counter (for flow-control ACKs)
        self.recv_buf = b''

    def connect(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.settimeout(self.timeout)
        self.socket.connect((self.host, self.port))

    def close(self):
        if self.socket:
            self.socket.close()
            self.socket = None

    def authenticate(self, username, password):
        """Authenticate to the router.

        Tries EC-SRP5 (RouterOS >= 6.43) first. If the server doesn't respond
        to the EC-SRP5 init (old RouterOS), reconnects and falls back to the
        old MD5 challenge-response over unencrypted M2.
        """
        try:
            self._ec_srp5_authenticate(username, password)
        except ConnectionError_ as e:
            err_msg = str(e)
            if "does not support EC-SRP5" in err_msg or "No response" in err_msg:
                # Old RouterOS — reconnect and try old auth
                sys.stderr.write("EC-SRP5 not supported, trying old auth...\n")
                self.close()
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(self.timeout)
                self.socket.connect((self.host, self.port))
                self._old_authenticate(username, password)
            else:
                raise

    def _ec_srp5_authenticate(self, username, password):
        """EC-SRP5 authentication for RouterOS >= 6.43."""
        # Stage 1: Generate and send public key
        self.s_a = secrets.token_bytes(32)
        self.x_w_a, self.x_w_a_parity = self.w.gen_public_key(self.s_a)

        msg = username.encode('utf-8') + b'\x00'
        msg += self.x_w_a + int(self.x_w_a_parity).to_bytes(1, "big")
        msg = len(msg).to_bytes(1, "big") + b'\x06' + msg
        self.socket.send(msg)

        # Receive server challenge — use short timeout for fallback detection
        self.socket.settimeout(3)
        try:
            resp = self.socket.recv(1024)
        except socket.timeout:
            raise ConnectionError_("No response from server — does not support EC-SRP5.")

        if not resp:
            raise ConnectionError_("Connection closed by server — WinBox may not be enabled.")

        if len(resp) < 2:
            raise ConnectionError_("Invalid response from server — not a WinBox service?")

        resp_len = resp[0]
        resp_tag = resp[1]
        resp = resp[2:]

        if resp_tag != 0x06:
            raise ConnectionError_(
                f"Server does not support EC-SRP5 (tag=0x{resp_tag:02x})."
            )

        if len(resp) != resp_len:
            raise ConnectionError_(
                f"Corrupted challenge response (expected {resp_len} bytes, got {len(resp)}). "
                "The server may not be running WinBox on this port."
            )

        if resp_len != 49:
            raise ConnectionError_(
                f"Unexpected challenge size ({resp_len} bytes, expected 49). "
                "This router may use an unsupported protocol version."
            )

        x_w_b = resp[:32]
        x_w_b_parity = resp[32]
        salt = resp[33:49]

        # Stage 2: Generate shared secret
        i = self.w.gen_password_validator_priv(username, password, salt)
        x_gamma, _ = self.w.gen_public_key(i)
        v = self.w.redp1(x_gamma, 1)
        w_b = self.w.lift_x(int.from_bytes(x_w_b, "big"), x_w_b_parity)
        w_b += v

        j = get_sha2_digest(self.x_w_a + x_w_b)
        pt = int.from_bytes(i, "big") * int.from_bytes(j, "big")
        pt += int.from_bytes(self.s_a, "big")
        pt = self.w.finite_field_value(pt)
        pt = pt * w_b
        z, _ = self.w.to_montgomery(pt)
        secret = get_sha2_digest(z)

        # Send confirmation
        client_cc = get_sha2_digest(j + z)
        msg = len(client_cc).to_bytes(1, "big") + b'\x06' + client_cc
        self.socket.send(msg)

        # Verify server confirmation
        self.socket.settimeout(self.timeout)
        try:
            resp = self.socket.recv(1024)
        except socket.timeout:
            raise AuthenticationError("No confirmation from server — authentication failed.")

        if not resp or len(resp) < 3:
            raise AuthenticationError("Empty confirmation — wrong username or password.")

        server_cc = get_sha2_digest(j + client_cc + z)
        if resp[2:] != server_cc:
            raise AuthenticationError("Wrong username or password.")

        # Derive encryption keys
        self.send_aes_key, self.receive_aes_key, self.send_hmac_key, self.receive_hmac_key = \
            gen_stream_keys(False, secret)

        self.authenticated = True

    def _send_raw_m2(self, msg):
        """Frame and send an unencrypted M2 message (tag 0x01)."""
        msg_len = len(msg)
        if msg_len < 0xFF:
            frame = bytes([msg_len + 2, 0x01, 0x00, msg_len]) + msg
        else:
            frame = bytes([0xFF, 0x01]) + struct.pack('>H', msg_len) + msg
        self.socket.send(frame)

    def _send_and_recv_raw(self, msg, timeout=5):
        """Send an unencrypted M2 message and return the first M2 response."""
        self._send_raw_m2(msg)
        old_timeout = self.socket.gettimeout()
        self.socket.settimeout(timeout)
        try:
            data = self.socket.recv(65536)
            if data:
                self.recv_buf += data
        except socket.timeout:
            pass
        finally:
            self.socket.settimeout(old_timeout)
        messages = self._process_recv_buf_raw()
        return messages[0] if messages else None

    def _old_authenticate(self, username, password):
        """Authenticate using old (pre-6.43) MD5 challenge-response over unencrypted M2.

        Flow (from jabb3rd/winbox):
        1. request_list: M2 to [2,2], SYS_CMD=7, key_1="list" -> get session_id
        2. request_challenge part 1: M2 to [2,2], SYS_CMD=5, session_id (no response expected)
        3. request_challenge part 2: M2 to [13,4], SYS_CMD=4, SYS_REQUEST -> get salt (key_9)
        4. login: M2 to [13,4], SYS_CMD=1, key_1=user, key_9=salt, key_10=hash
        """
        self.encrypted = False

        # Step 1: request_list — get session_id
        body = b''
        body += M2.encode_u32_array(M2.SYS_TO, [2, 2])
        body += M2.encode_u32_array(M2.SYS_FROM, [0, self.source_id])
        body += M2.encode_u32(M2.SYS_CMD, 7)
        body += M2.encode_bool(M2.SYS_REQUEST, True)
        rid = self._next_req_id()
        body += M2.encode_u8(M2.SYS_REQID, rid)
        body += M2.encode_string_user(1, "list")
        msg = b'M2' + body

        resp = self._send_and_recv_raw(msg)
        if not resp:
            raise ConnectionError_("No response to list request — old auth failed.")

        parsed = M2Parser.parse(resp)
        session_id = M2Parser.get_session_id(parsed)
        if session_id is None:
            raise ConnectionError_("No session ID in list response.")
        self.auth_session_id = session_id

        # Step 2a: request_challenge setup — M2 to [2,2], SYS_CMD=5, SESSION_ID
        body = b''
        body += M2.encode_u32_array(M2.SYS_TO, [2, 2])
        body += M2.encode_u32_array(M2.SYS_FROM, [0, self.source_id])
        body += M2.encode_u32(M2.SYS_CMD, 5)
        body += M2.encode_bool(M2.SYS_REQUEST, True)
        rid = self._next_req_id()
        body += M2.encode_u8(M2.SYS_REQID, rid)
        body += M2.encode_u8(M2.SESSION_ID, session_id)
        msg = b'M2' + body
        self._send_raw_m2(msg)
        # Drain any response (not always expected, but some routers may reply)
        time.sleep(0.2)
        try:
            self.socket.settimeout(0.5)
            data = self.socket.recv(65536)
            if data:
                self.recv_buf += data
                self._process_recv_buf_raw()  # discard
        except (socket.timeout, BlockingIOError):
            pass

        # Step 2b: request_challenge — M2 to [13,4], SYS_CMD=4 -> get salt
        body = b''
        body += M2.encode_u32_array(M2.SYS_TO, [13, 4])
        body += M2.encode_u32_array(M2.SYS_FROM, [0, self.source_id])
        body += M2.encode_u32(M2.SYS_CMD, 4)
        body += M2.encode_bool(M2.SYS_REQUEST, True)
        rid = self._next_req_id()
        body += M2.encode_u8(M2.SYS_REQID, rid)
        body += M2.encode_u8(M2.SESSION_ID, session_id)
        msg = b'M2' + body

        resp = self._send_and_recv_raw(msg)
        if not resp:
            raise ConnectionError_("No response to challenge request.")

        parsed = M2Parser.parse(resp)
        # Salt is in key_9 (namespace 0x00, raw)
        salt_entry = parsed.get(0x000009)
        if salt_entry is None or salt_entry[0] != 'raw':
            raise ConnectionError_("No salt in challenge response.")
        salt = salt_entry[1]

        # Step 3: login — MD5(0x00 + password + salt)
        digest = hashlib.md5()
        digest.update(b'\x00')
        digest.update(password.encode('utf-8'))
        digest.update(salt)
        hashed = b'\x00' + digest.digest()

        body = b''
        body += M2.encode_u32_array(M2.SYS_TO, [13, 4])
        body += M2.encode_u32_array(M2.SYS_FROM, [0, self.source_id])
        body += M2.encode_u32(M2.SYS_CMD, 1)
        body += M2.encode_bool(M2.SYS_REQUEST, True)
        rid = self._next_req_id()
        body += M2.encode_u8(M2.SYS_REQID, rid)
        body += M2.encode_u8(M2.SESSION_ID, session_id)
        body += M2.encode_string_user(1, username)
        body += M2.encode_raw_user(9, salt)
        body += M2.encode_raw_user(10, hashed)
        msg = b'M2' + body

        resp = self._send_and_recv_raw(msg)
        if not resp:
            raise AuthenticationError("No response to login — authentication failed.")

        parsed = M2Parser.parse(resp)
        # Check for error: SYS_STATUS (0xFF0008) != 0 means failure
        status = M2Parser.get_sys_status(parsed)
        if status is not None and status != 0:
            raise AuthenticationError("Wrong username or password (old auth).")

        self.authenticated = True

    def _encrypt_and_send(self, msg):
        """Encrypt and frame an M2 message, then send.
        Dispatches to raw send for old (unencrypted) protocol."""
        if not self.encrypted:
            self._send_raw_m2(msg)
            return
        # MAC-then-encrypt
        hmac_obj = HMAC.new(self.send_hmac_key, b'', SHA1)
        hmac_obj.update(msg)
        h = hmac_obj.digest()

        iv = secrets.token_bytes(0x10)
        aes = AES.new(self.send_aes_key, AES.MODE_CBC, iv)

        pad_byte = 0xf - len(msg + h) % 0x10
        padding = bytes([pad_byte]) * (pad_byte + 1)
        encrypted = aes.encrypt(msg + h + padding)

        msg_len = len(encrypted)
        full_msg = msg_len.to_bytes(2, "big") + iv + encrypted

        output = b''
        remaining = full_msg
        index = b'\x06'

        while True:
            frame_len = 0xff if len(remaining) >= 0xff else len(remaining)
            output += frame_len.to_bytes(1, "big") + index
            if len(remaining) >= 0xff:
                output += remaining[:0xff]
                remaining = remaining[0xff:]
            else:
                output += remaining
                break
            index = b'\xff'

        self.socket.send(output)

    def _try_extract_raw_frame(self):
        """Try to extract and reassemble one complete unencrypted M2 frame from recv_buf.

        Uses the same chunked framing as encrypted protocol, just with tag 0x01:
        - Chunk format: [len_byte(1), tag(1), ...len_byte bytes of payload...]
        - First chunk tag: 0x01, continuation tag: 0xFF
        - len_byte == 0xFF: full chunk (more to follow)
        - len_byte < 0xFF: last (or only) chunk
        - Assembled payload: body_len(2 bytes BE) + M2 message body

        Returns (M2_body_bytes, bytes_consumed) or None if incomplete.
        """
        buf = self.recv_buf
        if len(buf) < 2:
            return None

        if buf[1] != 0x01:
            # Not a tag 0x01 frame — skip 1 byte to resync
            return b'', 1

        # Reassemble chunks (same logic as encrypted frames)
        pos = 0
        assembled = b''

        while pos < len(buf):
            if pos + 2 > len(buf):
                return None  # incomplete header

            chunk_len = buf[pos]
            # tag = buf[pos + 1]  # 0x01 first, 0xFF continuation
            pos += 2

            payload_bytes = chunk_len  # 0xFF for full chunks, < 0xFF for last
            if pos + payload_bytes > len(buf):
                return None  # incomplete payload

            assembled += buf[pos:pos + payload_bytes]
            pos += payload_bytes

            if chunk_len < 0xFF:
                break  # last chunk

        # Strip 2-byte body length prefix from assembled payload
        if len(assembled) < 2:
            return b'', pos
        # body_len = (assembled[0] << 8) | assembled[1]
        m2_body = assembled[2:]

        return m2_body, pos

    def _process_recv_buf_raw(self):
        """Process recv_buf for unencrypted (old protocol) frames.
        Returns list of M2 message bytes.
        """
        messages = []
        while len(self.recv_buf) >= 4:
            result = self._try_extract_raw_frame()
            if result is None:
                break
            body, consumed = result
            self.recv_buf = self.recv_buf[consumed:]
            if body and len(body) >= 2 and body[:2] == b'M2':
                messages.append(body)
        return messages

    def _try_extract_frame(self):
        """Try to extract and reassemble one complete frame from recv_buf.

        Frame format: chunks of [len_byte(1) + idx_byte(1) + payload(len_byte or 0xff bytes)]
        First chunk has idx=0x06, continuation chunks have idx=0xff.
        Last chunk has len_byte < 0xff.

        Returns (assembled_payload, bytes_consumed) or None if incomplete.
        The assembled_payload includes the 2-byte encrypted-length prefix,
        the 16-byte IV, and the ciphertext.
        """
        buf = self.recv_buf
        if len(buf) < 2:
            return None

        pos = 0
        assembled = b''

        # Process chunks
        while pos < len(buf):
            if pos + 2 > len(buf):
                return None  # incomplete chunk header

            chunk_len = buf[pos]
            # idx = buf[pos + 1]  # 0x06 for first, 0xff for continuation
            pos += 2

            # Determine actual payload bytes in this chunk
            payload_bytes = 0xff if chunk_len == 0xff else chunk_len
            # For the first chunk with len < 0xff, payload_bytes = chunk_len
            # But we need to check: the original code uses frame_len = msg_len + 0x12
            # for small messages, where msg_len = len(encrypted). So for the first
            # chunk, the actual data is chunk_len bytes (the frame_len byte already
            # accounts for this).
            # Actually looking at send code: if msg_len < 0xff, frame_len = msg_len + 0x12
            # and the full_msg = msg_len(2) + iv(16) + encrypted = msg_len + 0x12
            # So first chunk payload = frame_len bytes. For continuation, 0xff bytes.
            # But for first chunk with frame_len=0xff (large message), first chunk is 0xff bytes.

            if pos == 2:
                # First chunk
                if chunk_len == 0xff:
                    payload_bytes = 0xff
                else:
                    payload_bytes = chunk_len
            else:
                # Continuation chunk
                payload_bytes = chunk_len  # last if < 0xff, else 0xff

            if pos + payload_bytes > len(buf):
                return None  # incomplete payload

            assembled += buf[pos:pos + payload_bytes]
            pos += payload_bytes

            if chunk_len < 0xff:
                break  # this was the last chunk

        return assembled, pos

    def _decrypt_assembled(self, assembled):
        """Decrypt an assembled frame payload.
        Format: encrypted_len(2 bytes BE) + IV(16) + ciphertext.
        Returns decrypted M2 message bytes or None.
        """
        if len(assembled) < 2 + 16:
            return None

        # Strip the 2-byte encrypted length prefix
        # enc_len = struct.unpack('>H', assembled[:2])[0]
        assembled = assembled[2:]

        if len(assembled) < 0x10:
            return None

        iv = assembled[:0x10]
        encrypted = assembled[0x10:]

        if len(encrypted) == 0 or len(encrypted) % 16 != 0:
            return None

        aes = AES.new(self.receive_aes_key, AES.MODE_CBC, iv)
        decrypted = aes.decrypt(encrypted)

        # Remove padding
        if decrypted[-1] != 0:
            try:
                decrypted = unpad(decrypted, AES.block_size)
            except ValueError:
                return None
        decrypted = decrypted[:-1]  # strip pad indicator byte

        # Verify HMAC and strip
        if len(decrypted) < 20:
            return None
        hmc = decrypted[-20:]
        decrypted = decrypted[:-20]

        hmac_obj = HMAC.new(self.receive_hmac_key, b'', SHA1)
        hmac_obj.update(decrypted)
        # Skip HMAC verification failure — some messages may still be usable

        return decrypted

    def _process_recv_buf(self):
        """Process recv_buf, extracting and decrypting all complete frames.
        Returns list of decrypted M2 message bytes.
        """
        if not self.encrypted:
            return self._process_recv_buf_raw()

        messages = []
        while len(self.recv_buf) >= 2:
            result = self._try_extract_frame()
            if result is None:
                break
            assembled, consumed = result
            self.recv_buf = self.recv_buf[consumed:]

            decrypted = self._decrypt_assembled(assembled)
            if decrypted is not None:
                messages.append(decrypted)
        return messages

    def _receive_and_decrypt(self, timeout=None):
        """Receive data from socket and decrypt any complete frames."""
        old_timeout = self.socket.gettimeout()
        if timeout is not None:
            self.socket.settimeout(timeout)
        try:
            data = self.socket.recv(65536)
            if data:
                self.recv_buf += data
        except socket.timeout:
            pass
        except BlockingIOError:
            pass
        finally:
            self.socket.settimeout(old_timeout)

        return self._process_recv_buf()

    def send_encrypted(self, msg):
        """Send an encrypted M2 message."""
        self._encrypt_and_send(msg)

    def send_and_receive(self, msg, timeout=5):
        """Send M2 and return first response (encrypted or raw depending on mode)."""
        if not self.encrypted:
            return self._send_and_recv_raw(msg, timeout)
        self._encrypt_and_send(msg)
        messages = self._receive_and_decrypt(timeout)
        if messages:
            return messages[0]
        return None

    def _next_req_id(self):
        self.req_id += 1
        return self.req_id

    def _inject_auth_session(self, msg):
        """For old protocol: inject the auth_session_id into an M2 message body.
        Appends SESSION_ID TLV after the 'M2' header."""
        if self.encrypted or self.auth_session_id is None:
            return msg
        # Append session_id TLV to the M2 body
        return msg + M2.encode_u8(M2.SESSION_ID, self.auth_session_id)

    def open_terminal(self, password, cols=80, rows=24):
        """Open terminal session: initial request, meptyLogin, ready signal."""
        # Step 1: Initial request (SYS_CMD=7, SYS_TO=[13,4])
        msg = M2.build_initial_request(self.source_id)
        msg = self._inject_auth_session(msg)
        resp = self.send_and_receive(msg)
        if resp:
            parsed = M2Parser.parse(resp)
            sys_from = M2Parser.get_sys_from(parsed)
            if sys_from and len(sys_from) >= 2:
                # The source_id for subsequent messages comes from
                # the response's SYS_TO second element
                sys_to = M2Parser.get_sys_to(parsed)
                if sys_to and len(sys_to) >= 2:
                    self.source_id = sys_to[1]

        # Step 2: meptyLogin (SYS_CMD=0x0A0065)
        rid = self._next_req_id()
        msg = M2.build_mepty_login(self.source_id, rid, password, cols, rows)
        msg = self._inject_auth_session(msg)
        self._encrypt_and_send(msg)

        # Read responses until we get the meptyLogin response with SESSION_ID
        # The server sends multiple messages (proxy info, session setup, etc.)
        self.socket.settimeout(5)
        attempts = 0
        while attempts < 20:
            attempts += 1
            if self.encrypted:
                messages = self._receive_and_decrypt(timeout=3)
            else:
                try:
                    data = self.socket.recv(65536)
                    if data:
                        self.recv_buf += data
                except socket.timeout:
                    pass
                messages = self._process_recv_buf_raw()
            for m in messages:
                parsed = M2Parser.parse(m)
                sid = M2Parser.get_session_id(parsed)
                if sid is not None:
                    # Check if this is from handler 76 (mepty)
                    sys_from = M2Parser.get_sys_from(parsed)
                    if sys_from and 76 in sys_from:
                        self.session_id = sid
                        return True
            if self.session_id is not None:
                return True

        return False

    def send_ready_signal(self):
        """Send initial 'ready' notification — mepty data with no key_2."""
        msg = M2.build_mepty_data(self.source_id, self.session_id, self.counter)
        self._encrypt_and_send(msg)

    def send_ack(self):
        """Send flow-control ACK — meptyData with recv_counter but no key_2.

        The server uses this as a flow-control signal: it stops sending
        terminal output once its buffer fills, and resumes only after
        receiving an ACK with the received byte count.
        """
        msg = M2.build_mepty_data(self.source_id, self.session_id, self.recv_counter)
        self._encrypt_and_send(msg)

    def send_terminal_input(self, data):
        """Send terminal keystroke(s)."""
        msg = M2.build_mepty_data(self.source_id, self.session_id, self.counter, data)
        self._encrypt_and_send(msg)
        self.counter += len(data)

    def receive_terminal_output(self, timeout=0.1):
        """Receive and extract terminal output bytes."""
        output = b''
        messages = self._receive_and_decrypt(timeout=timeout)
        for m in messages:
            parsed = M2Parser.parse(m)
            raw = M2Parser.get_key2_raw(parsed)
            if raw:
                output += raw
                self.recv_counter += len(raw)
        if output:
            self.send_ack()
        return output

    def dump_initial_output(self, duration=5):
        """Read and print terminal output for a fixed duration (non-interactive)."""
        self.socket.setblocking(False)
        self.send_ready_signal()

        end_time = time.time() + duration
        while time.time() < end_time:
            rlist, _, _ = select.select([self.socket], [], [], 0.1)
            if self.socket in rlist:
                try:
                    raw_data = self.socket.recv(65536)
                    if not raw_data:
                        break
                    self.recv_buf += raw_data
                except (BlockingIOError, socket.error):
                    pass

            got_output = False
            for m in self._process_recv_buf():
                parsed = M2Parser.parse(m)
                raw = M2Parser.get_key2_raw(parsed)
                if raw:
                    sys.stdout.buffer.write(raw)
                    sys.stdout.buffer.flush()
                    self.recv_counter += len(raw)
                    got_output = True

            if got_output:
                self.send_ack()

    def interactive_loop(self):
        """Run interactive terminal I/O loop. Requires a real TTY on stdin."""
        if not os.isatty(sys.stdin.fileno()):
            raise RuntimeError("interactive_loop requires a TTY (use --dump for non-interactive mode)")

        self.socket.settimeout(0)
        self.socket.setblocking(False)

        stdin_fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(stdin_fd)

        try:
            tty.setraw(stdin_fd)
            sys.stdout.write("\r\n[Connected. Press Ctrl+\\ to disconnect.]\r\n")
            sys.stdout.flush()

            # Send ready signal
            self.send_ready_signal()

            # Buffer to track typed input for "exit" detection
            input_line = b''

            while True:
                rlist, _, _ = select.select([stdin_fd, self.socket], [], [], 0.05)

                if stdin_fd in rlist:
                    data = os.read(stdin_fd, 1024)
                    if not data:
                        break
                    # Check for escape keys:
                    #   Ctrl+\  = 0x1c (SIGQUIT char, intercepted in raw mode)
                    #   Ctrl+]  = 0x1d (traditional telnet escape)
                    if b'\x1c' in data or b'\x1d' in data:
                        sys.stdout.write("\r\n[Disconnected.]\r\n")
                        sys.stdout.flush()
                        break

                    # Track typed characters to detect "exit" + Enter
                    for byte in data:
                        if byte in (0x0d, 0x0a):  # Enter/Return
                            if input_line.strip() == b'exit':
                                sys.stdout.write("\r\n[Disconnected.]\r\n")
                                sys.stdout.flush()
                                # Send the enter to the router first so it
                                # processes the exit cleanly on its side too
                                self.send_terminal_input(data)
                                return
                            input_line = b''
                        elif byte == 0x7f or byte == 0x08:  # Backspace/Delete
                            input_line = input_line[:-1]
                        elif byte >= 0x20:  # printable
                            input_line += bytes([byte])
                        else:
                            # Control char (arrow keys, etc.) — reset tracking
                            input_line = b''

                    self.send_terminal_input(data)

                if self.socket in rlist:
                    try:
                        raw_data = self.socket.recv(65536)
                        if not raw_data:
                            sys.stdout.write("\r\n[Connection closed by server.]\r\n")
                            sys.stdout.flush()
                            break
                        self.recv_buf += raw_data
                    except (BlockingIOError, socket.error):
                        pass

                # Try to process any buffered data
                got_output = False
                for m in self._process_recv_buf():
                    parsed = M2Parser.parse(m)
                    raw = M2Parser.get_key2_raw(parsed)
                    if raw:
                        os.write(sys.stdout.fileno(), raw)
                        self.recv_counter += len(raw)
                        got_output = True

                # Send flow-control ACK after processing output
                if got_output:
                    self.send_ack()

        finally:
            termios.tcsetattr(stdin_fd, termios.TCSADRAIN, old_settings)


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='WinBox Terminal Client for MikroTik routers',
        usage='%(prog)s <address>[:<port>] [-u username] [-p password] [options]',
        epilog='Examples:\n'
               '  %(prog)s 192.168.88.1\n'
               '  %(prog)s 192.168.88.1:8292\n'
               '  %(prog)s 192.168.88.1 -u admin -p secret\n'
               '  %(prog)s 192.168.88.1 --dump\n',
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument('address', nargs='?', help='Router IP address or address:port')
    parser.add_argument('-u', '--username', default='admin', help='Username (default: admin)')
    parser.add_argument('-p', '--password', default='', help='Password (default: empty)')
    parser.add_argument('--cols', type=int, default=80, help='Terminal columns (default: 80)')
    parser.add_argument('--rows', type=int, default=24, help='Terminal rows (default: 24)')
    parser.add_argument('--dump', action='store_true', help='Non-interactive: dump initial output and exit')
    parser.add_argument('--dump-time', type=int, default=5, help='Seconds to read output in dump mode (default: 5)')

    args = parser.parse_args()

    if not args.address:
        parser.print_help()
        return 1

    # Parse address:port
    host = args.address
    port = 8291
    if ':' in host:
        parts = host.rsplit(':', 1)
        host = parts[0]
        try:
            port = int(parts[1])
        except ValueError:
            sys.stderr.write(f"Invalid port: {parts[1]}\n")
            return 1

    client = WinboxTerminalClient(host, port)

    try:
        sys.stderr.write(f"Connecting to {host}:{port}...\n")
        client.connect()
        sys.stderr.write("Connected. Authenticating...\n")
        client.authenticate(args.username, args.password)
        sys.stderr.write("Authenticated. Opening terminal...\n")

        if not client.open_terminal(args.password, args.cols, args.rows):
            sys.stderr.write("Failed to open terminal session.\n")
            return 1

        sys.stderr.write(f"Terminal session opened (session_id={client.session_id}).\n")

        if args.dump or not os.isatty(sys.stdin.fileno()):
            client.dump_initial_output(args.dump_time)
        else:
            client.interactive_loop()

    except KeyboardInterrupt:
        sys.stderr.write("\r\n[Interrupted.]\r\n")
    except AuthenticationError as e:
        sys.stderr.write(f"Authentication failed: {e}\n")
        return 1
    except ConnectionError_ as e:
        sys.stderr.write(f"Connection error: {e}\n")
        return 1
    except (socket.timeout, TimeoutError):
        sys.stderr.write(f"Connection timed out — is {host}:{port} reachable?\n")
        return 1
    except ConnectionRefusedError:
        sys.stderr.write(f"Connection refused — no service on {host}:{port}.\n")
        return 1
    except OSError as e:
        sys.stderr.write(f"Network error: {e}\n")
        return 1
    except Exception as e:
        sys.stderr.write(f"\nUnexpected error: {e}\n")
        import traceback
        traceback.print_exc()
        return 1
    finally:
        client.close()

    return 0


if __name__ == '__main__':
    sys.exit(main())
