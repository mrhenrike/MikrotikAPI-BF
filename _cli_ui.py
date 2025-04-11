import time
import threading
import platform
import signal

try:
    import curses
    CURSES_AVAILABLE = True
except ImportError:
    CURSES_AVAILABLE = False

BANNER = r'''
        __  __ _ _              _   _ _        _    ____ ___      ____  _____
        |  \/  (_) | ___ __ ___ | |_(_) | __   / \  |  _ \_ _|    | __ )|  ___|
        | |\/| | | |/ / '__/ _ \| __| | |/ /  / _ \ | |_) | |_____|  _ \| |_
        | |  | | |   <| | | (_) | |_| |   <  / ___ \|  __/| |_____| |_) |  _|
        |_|  |_|_|_|\_\_|  \___/ \__|_|_|\_\/_/   \_\_|  |___|    |____/|_|

                     Mikrotik RouterOS API Bruteforce Tool 1.2
                     André Henrique (X / Linkedin: @mrhenrike)
            Please report tips, suggests and problems to X or LinkedIn
                    https://github.com/mrhenrike/MikrotikAPI-BF
'''

class CLIInterface:
    def __init__(self, enabled=True):
        self.screen = None
        self.running = True
        self.status = "Idle"
        self.attempt = 0
        self.total = 0
        self.last_password = ""
        self.username = ""
        self.success = None
        self.enabled = enabled and CURSES_AVAILABLE
        self._lock = threading.Lock()

    def start(self):
        if not self.enabled:
            print("[INFO] Interactive CLI monitor is not supported on this platform.")
            return
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def update(self, attempt=None, total=None, last_password=None, success=None, status=None, username=None):
        if not self.enabled:
            return
        with self._lock:
            if attempt is not None:
                self.attempt = attempt
            if total is not None:
                self.total = total
            if last_password is not None:
                self.last_password = last_password
            if success is not None:
                self.success = success
            if status is not None:
                self.status = status
            if username is not None:
                self.username = username

    def stop(self):
        self.running = False
        if not self.enabled or not self.screen:
            return
        time.sleep(0.2)
        try:
            curses.endwin()
        except curses.error:
            print("[WARNING] Could not end curses session cleanly.")

    def _run(self):
        if not self.enabled:
            return
        try:
            self.screen = curses.initscr()
            curses.noecho()
            curses.cbreak()
            self.screen.nodelay(True)

            signal.signal(signal.SIGINT, self._handle_interrupt)
            if hasattr(signal, "SIGTSTP"):
                signal.signal(signal.SIGTSTP, self._handle_interrupt)

            while self.running:
                self.screen.clear()
                offset = 0
                for i, line in enumerate(BANNER.strip('\n').splitlines()):
                    if i >= curses.LINES - 1:
                        break
                    try:
                        self.screen.addstr(i + offset, 1, line[:curses.COLS - 2])
                    except curses.error:
                        pass

                try:
                    self.screen.border(0)
                except curses.error:
                    pass

                y = len(BANNER.strip('\n').splitlines()) + 2
                if curses.LINES > y + 6:
                    try:
                        self.screen.addstr(y, 2, "Mikrotik API Brute Force - Live Monitor")
                        self.screen.addstr(y + 1, 4, f"User: {self.username}")
                        self.screen.addstr(y + 2, 4, f"Status: {self.status}")
                        self.screen.addstr(y + 3, 4, f"Attempt: {self.attempt}/{self.total}")
                        self.screen.addstr(y + 4, 4, f"Current Password: {self.last_password}")
                        if self.success:
                            self.screen.addstr(y + 6, 4, f"[SUCCESS] {self.success}", curses.A_BOLD)
                    except curses.error:
                        pass

                self.screen.refresh()
                time.sleep(0.2)

        except Exception as e:
            print(f"[ERROR] CLI UI failed to initialize: {e}")
            self.enabled = False

    def _handle_interrupt(self, signum, frame):
        self.running = False
        self.stop()
        raise KeyboardInterrupt

def print_banner():
    print(BANNER)
