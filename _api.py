#!/usr/bin/env python
# -*- coding: utf-8 -*-

# This module handles the low-level interaction with Mikrotik RouterOS API using socket.
# It includes connection, authentication, and response parsing.

import socket

class Api:
    def __init__(self, host, port=8728, use_ssl=False):
        # Initialize basic connection parameters
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.sock = None

    def connect(self):
        # Establishes a basic TCP socket connection (SSL not supported in RouterOS API on 8728)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(5)
        self.sock.connect((self.host, self.port))

    def disconnect(self):
        # Close socket connection if exists
        if self.sock:
            self.sock.close()
            self.sock = None

    def send(self, words):
        # Send encoded data to Mikrotik API socket
        if not self.sock:
            self.connect()
        for word in words:
            self.sock.send(self.encode_length(len(word)))
            self.sock.send(word.encode())
        self.sock.send(b'\x00')  # End of sentence

    def read_sentence(self):
        # Reads a complete API sentence (multiple words)
        words = []
        while True:
            length = self.read_length()
            if length == 0:
                break
            word = self.sock.recv(length).decode()
            words.append(word)
        return words

    def read_length(self):
        # Decodes the length prefix used in RouterOS API protocol
        c = self.sock.recv(1)
        if not c:
            return 0
        b = c[0]
        if b < 0x80:
            return b
        elif b < 0xC0:
            c += self.sock.recv(1)
            return ((b & 0x3F) << 8) + c[1]
        elif b < 0xE0:
            c += self.sock.recv(2)
            return ((b & 0x1F) << 16) + (c[1] << 8) + c[2]
        elif b < 0xF0:
            c += self.sock.recv(3)
            return ((b & 0x0F) << 24) + (c[1] << 16) + (c[2] << 8) + c[3]
        else:
            c += self.sock.recv(4)
            return (c[1] << 24) + (c[2] << 16) + (c[3] << 8) + c[4]

    def encode_length(self, length):
        # Encodes the length prefix to send to API
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

    def login(self, username, password):
        # Perform login using Mikrotik API protocol
        try:
            self.connect()
            self.send(['/login', '=name=' + username, '=password=' + password])
            response = self.read_sentence()
            self.disconnect()
            return '!done' in response
        except:
            self.disconnect()
            return False
