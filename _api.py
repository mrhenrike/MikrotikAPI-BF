import socket
import ssl
import binascii
import hashlib
import time
import sys
import signal
import threading
from _log import Log

class RouterOSTrapError(Exception):
    pass

class LoginError(Exception):
    pass

class WordTooLong(Exception):
    pass

_stop_flag = threading.Event()

def _handle_interrupt(signum, frame):
    Log(stdout=True).warning("[!] Interruption signal received. Stopping...")
    _stop_flag.set()

# Handle Ctrl+C and Ctrl+Z
signal.signal(signal.SIGINT, _handle_interrupt)
# signal.SIGTSTP is not available on Windows, so we skip it
if hasattr(signal, 'SIGTSTP'):
    signal.signal(signal.SIGTSTP, _handle_interrupt)

class Api:
    def __init__(self, target, port=8728, use_ssl=False, timeout=5):
        self.target = target
        self.port = port
        self.use_ssl = use_ssl
        self.timeout = timeout
        self.sock = None
        self.log = Log(stdout=False)
        self._connect()

    def _connect(self):
        family = socket.AF_INET if ':' not in self.target else socket.AF_INET6
        self.sock = socket.socket(family, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect((self.target, self.port))

        if self.use_ssl:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            self.sock = context.wrap_socket(self.sock, server_hostname=self.target)

    def login(self, username, password):
        if _stop_flag.is_set():
            raise KeyboardInterrupt("Bruteforce interrupted by user")

        self._write(['/login', f'=name={username}', f'=password={password}'])
        response = self._read_sentence()

        if len(response) == 1 and response[0] == '!done':
            self._disconnect()
            return True

        elif len(response) > 0 and len(response) > 1 and response[1].startswith('=ret='):
            # Challenge/response MD5 login fallback
            chal = binascii.unhexlify(response[1][5:])
            md = hashlib.md5()
            md.update(b'\x00' + password.encode('utf-8') + chal)
            digest = '00' + binascii.hexlify(md.digest()).decode('utf-8')

            self._write(['/login', f'=name={username}', f'=response={digest}'])
            second_response = self._read_sentence()
            self._disconnect()
            return '!done' in second_response

        self._disconnect()
        return False

    def _write(self, words):
        for word in words:
            self._send_word(word)
        self.sock.sendall(b'\x00')  # End of sentence

    def _send_word(self, word):
        word_bytes = word.encode('utf-8')
        length = len(word_bytes)

        if length < 0x80:
            self.sock.sendall(length.to_bytes(1, 'big'))
        elif length < 0x4000:
            length |= 0x8000
            self.sock.sendall(length.to_bytes(2, 'big'))
        elif length < 0x200000:
            length |= 0xC00000
            self.sock.sendall(length.to_bytes(3, 'big'))
        elif length < 0x10000000:
            length |= 0xE0000000
            self.sock.sendall(length.to_bytes(4, 'big'))
        else:
            self.sock.sendall(b'\xF0')
            self.sock.sendall(length.to_bytes(4, 'big'))

        self.sock.sendall(word_bytes)

    def _read_sentence(self):
        sentence = []
        while True:
            word = self._read_word()
            if word == '':
                break
            sentence.append(word)
        return sentence

    def _read_word(self):
        b = self.sock.recv(1)
        if not b:
            return ''

        b = b[0]
        if b < 0x80:
            length = b
        elif b < 0xC0:
            b2 = self.sock.recv(1)[0]
            length = ((b & ~0xC0) << 8) + b2
        elif b < 0xE0:
            b2 = self.sock.recv(1)[0]
            b3 = self.sock.recv(1)[0]
            length = ((b & ~0xE0) << 16) + (b2 << 8) + b3
        elif b < 0xF0:
            b2 = self.sock.recv(1)[0]
            b3 = self.sock.recv(1)[0]
            b4 = self.sock.recv(1)[0]
            length = ((b & ~0xF0) << 24) + (b2 << 16) + (b3 << 8) + b4
        else:
            b2 = self.sock.recv(1)[0]
            b3 = self.sock.recv(1)[0]
            b4 = self.sock.recv(1)[0]
            b5 = self.sock.recv(1)[0]
            length = (b2 << 24) + (b3 << 16) + (b4 << 8) + b5

        data = b''
        while len(data) < length:
            more = self.sock.recv(length - len(data))
            if not more:
                break
            data += more
        return data.decode('utf-8', errors='replace')

    def _disconnect(self):
        try:
            self.sock.close()
        except Exception:
            pass
