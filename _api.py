
import socket
import ssl


class Api:
    def __init__(self, host, port, use_ssl=False):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.sock = None

    def connect(self):
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        raw_sock.settimeout(5)
        if self.use_ssl:
            context = ssl._create_unverified_context()
            self.sock = context.wrap_socket(raw_sock, server_hostname=self.host)
        else:
            self.sock = raw_sock
        self.sock.connect((self.host, self.port))

    def close(self):
        if self.sock:
            self.sock.close()

    def send(self, words):
        for word in words:
            self.write_word(word[0])
        self.write_word('')

    def read(self):
        reply = []
        while True:
            word = self.read_word()
            if word == '':
                break
            reply.append(word)
        return reply

    def write_word(self, word):
        word_bytes = word.encode('utf-8')
        self.sock.send(self.encode_length(len(word_bytes)) + word_bytes)

    def read_word(self):
        length = self.decode_length()
        if length == 0:
            return ''
        data = b''
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return data.decode('utf-8')

    def encode_length(self, length):
        if length < 0x80:
            return bytes([length])
        elif length < 0x4000:
            length |= 0x8000
            return bytes([(length >> 8) & 0xFF, length & 0xFF])
        elif length < 0x200000:
            length |= 0xC00000
            return bytes([(length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
        elif length < 0x10000000:
            length |= 0xE0000000
            return bytes([(length >> 24) & 0xFF, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])
        else:
            return bytes([0xF0, (length >> 24) & 0xFF, (length >> 16) & 0xFF, (length >> 8) & 0xFF, length & 0xFF])

    def decode_length(self):
        b = self.sock.recv(1)[0]
        if (b & 0x80) == 0x00:
            return b
        elif (b & 0xC0) == 0x80:
            b2 = self.sock.recv(1)[0]
            return ((b & ~0xC0) << 8) + b2
        elif (b & 0xE0) == 0xC0:
            b2 = self.sock.recv(1)[0]
            b3 = self.sock.recv(1)[0]
            return ((b & ~0xE0) << 16) + (b2 << 8) + b3
        elif (b & 0xF0) == 0xE0:
            b2 = self.sock.recv(1)[0]
            b3 = self.sock.recv(1)[0]
            b4 = self.sock.recv(1)[0]
            return ((b & ~0xF0) << 24) + (b2 << 16) + (b3 << 8) + b4
        else:
            self.sock.recv(4)
            return 0

    def login(self, username, password):
        try:
            self.connect()
            self.send([('/login',), ('=name=' + username,), ('=password=' + password,)])
            response = self.read()
            self.close()
            if any("!done" in r for r in response):
                return True
            return False
        except Exception:
            self.close()
            return False
