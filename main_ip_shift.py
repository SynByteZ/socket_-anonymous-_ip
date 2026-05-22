import time
import uuid
import logging
import subprocess
import sys
from http.cookiejar import DefaultCookiePolicy

# ─────────────────────────────────────────────────────────────
# AUTO-INSTALL DEPENDENCIES
# ─────────────────────────────────────────────────────────────
REQUIRED_PACKAGES = ["requests", "PySocks", "stem"]

for package in REQUIRED_PACKAGES:
    try:
        __import__(package.replace("-", "_"))
    except ImportError:
        print(f"[+] Installing {package}...")
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", package],
            stdout=subprocess.DEVNULL
        )

import requests
from stem import Signal
from stem.control import Controller
from stem.connection import MissingPassword, PasswordAuthFailed

# ─────────────────────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────────────────────
TOR_PROXY_PORT   = 9050
TOR_CONTROL_PORT = 9051
ROTATE_INTERVAL  = 30       # seconds between rotations
REQUEST_TIMEOUT  = (10, 30) # (connect_timeout, read_timeout)
MAX_RETRIES      = 3        # retries on failed requests
RETRY_WAIT       = 2        # seconds between retries
CHECK_URL        = "https://ipinfo.io/json"

# ─────────────────────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("tor_rotator.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
log = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────
# COOKIE BLOCKER
# Blocks ALL cookies at policy level before any
# request is made — not after (response.clear is useless)
# ─────────────────────────────────────────────────────────────
class BlockCookies(DefaultCookiePolicy):
    def set_ok(self, cookie, request):    return False
    def return_ok(self, cookie, request): return False

# ─────────────────────────────────────────────────────────────
# STATIC TOR BROWSER HEADERS
#
# IMPORTANT: Do NOT rotate User-Agent.
# Tor anonymity works by making all users look identical.
# Rotating UA breaks that uniformity and makes you MORE
# fingerprintable, not less.
#
# These headers exactly match real Tor Browser output.
# ─────────────────────────────────────────────────────────────
TOR_HEADERS = {
    "User-Agent"     : "Mozilla/5.0 (Windows NT 10.0; rv:115.0) Gecko/20100101 Firefox/115.0",
    "Accept"         : "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT"            : "1",
    # Sec-Fetch headers — real Tor Browser sends these
    # omitting them makes requests fingerprint stand out
    "Sec-Fetch-Dest" : "document",
    "Sec-Fetch-Mode" : "navigate",
    "Sec-Fetch-Site" : "none",
    "Sec-Fetch-User" : "?1",
    # NOTE: "Connection" header intentionally omitted
    # requests manages connections internally —
    # setting it manually has no effect and adds noise
}

# ─────────────────────────────────────────────────────────────
# HARDENED TOR SESSION
# ─────────────────────────────────────────────────────────────
def get_tor_session():
    """
    Creates a fully hardened anonymous session:

    - Cookies blocked at policy level (not just cleared)
    - Fixed Tor Browser headers (blend in, not stand out)
    - Stream isolation via unique UUID credentials
      Each session gets its own Tor circuit — requests
      cannot be correlated even within same rotation
    - socks5h = DNS resolved by Tor remotely
      (prevents DNS leaks — local DNS never queried)
    - SSL verification enabled
    - No JS engine (requests is not a browser)
    """
    session = requests.Session()

    # Block all cookies at policy level
    session.cookies.set_policy(BlockCookies())

    # Fixed Tor Browser headers
    session.headers.update(TOR_HEADERS)

    # Stream isolation — unique identity per session
    # Tor treats different SOCKS credentials as
    # separate circuits, preventing cross-request linkage
    identity = str(uuid.uuid4())
    session.proxies = {
        "http" : f"socks5h://{identity}:x@127.0.0.1:{TOR_PROXY_PORT}",
        "https": f"socks5h://{identity}:x@127.0.0.1:{TOR_PROXY_PORT}",
    }

    session.verify = True
    return session

# ─────────────────────────────────────────────────────────────
# TOR CONTROLLER CONTEXT MANAGER
# Centralizes all controller logic — avoids duplicating
# connection + auth code across check_tor / rotate_ip
# ─────────────────────────────────────────────────────────────
def get_controller():
    """
    Returns an authenticated Tor controller or None.
    Caller must use as context manager:
        with get_controller() as c: ...
    """
    try:
        controller = Controller.from_port(port=TOR_CONTROL_PORT)
        controller.authenticate()
        return controller
    except ConnectionRefusedError:
        log.error("Tor control port refused. Is Tor running?")
    except MissingPassword:
        log.error("Tor requires a control password. Check torrc.")
    except PasswordAuthFailed:
        log.error("Wrong Tor control password.")
    except Exception as e:
        log.error(f"Controller error: {e}")
    return None

# ─────────────────────────────────────────────────────────────
# CHECK TOR IS RUNNING
# ─────────────────────────────────────────────────────────────
def check_tor():
    controller = get_controller()
    if controller:
        controller.close()
        return True
    return False

# ─────────────────────────────────────────────────────────────
# ROTATE TOR CIRCUIT
# ─────────────────────────────────────────────────────────────
def rotate_ip():
    """
    Requests a new Tor circuit and waits the exact
    time Tor requires before the new circuit is ready.
    Uses c.get_newnym_wait() — dynamic, not hardcoded.
    """
    controller = get_controller()
    if not controller:
        return False

    try:
        with controller:
            controller.signal(Signal.NEWNYM)

            # get_newnym_wait() returns the exact seconds
            # Tor needs before a new circuit is usable.
            # Hardcoding (e.g. sleep(2)) risks using the
            # old circuit — this is the correct approach.
            wait = controller.get_newnym_wait()
            log.info(f"New circuit requested. Waiting {wait}s...")
            time.sleep(wait)
            return True

    except Exception as e:
        log.error(f"Rotation failed: {e}")
        return False

# ─────────────────────────────────────────────────────────────
# GET CURRENT IP INFO
# ─────────────────────────────────────────────────────────────
def get_ip_info():
    """
    Fetches current visible IP with retry logic.
    Returns dict or None on total failure.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            session  = get_tor_session()
            response = session.get(CHECK_URL, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            data = response.json()
            return {
                "ip"     : data.get("ip",      "Unknown"),
                "city"   : data.get("city",    "Unknown"),
                "country": data.get("country", "Unknown"),
                "org"    : data.get("org",     "Unknown"),
            }
        except requests.exceptions.Timeout:
            log.warning(f"IP fetch timeout ({attempt}/{MAX_RETRIES})")
        except requests.exceptions.ConnectionError:
            log.warning(f"IP fetch connection error ({attempt}/{MAX_RETRIES})")
        except requests.exceptions.HTTPError as e:
            log.warning(f"IP fetch HTTP error {e} ({attempt}/{MAX_RETRIES})")
        except Exception as e:
            log.warning(f"IP fetch failed ({attempt}/{MAX_RETRIES}): {e}")

        time.sleep(RETRY_WAIT)

    log.error("All IP fetch attempts failed.")
    return None

# ─────────────────────────────────────────────────────────────
# FETCH ANY WEBSITE ANONYMOUSLY
# ─────────────────────────────────────────────────────────────
def fetch_website(url):
    """
    Fetches any URL through Tor anonymously.
    Fresh session per call = full stream isolation.
    No shared state, cookies, or identity between calls.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            session  = get_tor_session()
            response = session.get(url, timeout=REQUEST_TIMEOUT)
            response.raise_for_status()
            return response.text

        except requests.exceptions.Timeout:
            log.warning(f"[{url}] Timeout ({attempt}/{MAX_RETRIES})")

        except requests.exceptions.SSLError:
            log.error(f"[{url}] SSL error — skipping.")
            return None

        except requests.exceptions.TooManyRedirects:
            log.error(f"[{url}] Too many redirects — skipping.")
            return None

        except requests.exceptions.ConnectionError:
            log.warning(f"[{url}] Connection error ({attempt}/{MAX_RETRIES})")

        except Exception as e:
            log.warning(f"[{url}] Failed ({attempt}/{MAX_RETRIES}): {e}")

        time.sleep(RETRY_WAIT)

    log.error(f"[{url}] All {MAX_RETRIES} attempts failed.")
    return None

# ─────────────────────────────────────────────────────────────
# MAIN LOOP
# ─────────────────────────────────────────────────────────────
def main():
    print("=" * 60)
    print("         TOR ANONYMOUS ROTATOR — FINAL")
    print("=" * 60)
    print(f"  Cookies          : BLOCKED (policy level)")
    print(f"  DNS Leaks        : PROTECTED (socks5h)")
    print(f"  JS Execution     : NONE (not a browser)")
    print(f"  Stream Isolation : ENABLED (UUID per session)")
    print(f"  User-Agent       : FIXED (Tor Browser standard)")
    print(f"  Rotate Every     : {ROTATE_INTERVAL}s")
    print("=" * 60)
    print()
    print("  torrc must contain:")
    print("    ControlPort 9051")
    print("    CookieAuthentication 1")
    print()
    print("  Note: CookieAuthentication 1 requires Tor's")
    print("  cookie file to be readable by current user.")
    print("  Linux fix: sudo usermod -aG debian-tor $USER")
    print("=" * 60)

    if not check_tor():
        print("\n[!] Tor is not running or not reachable.")
        print("    Start tor.exe then run this script again.\n")
        sys.exit(1)

    log.info("Tor detected. Starting rotation loop.")

    last_ip  = None
    rotation = 0

    while True:
        rotation += 1
        log.info(f"--- Rotation #{rotation} ---")

        if not rotate_ip():
            log.warning("Rotation failed. Retrying in 5s...")
            time.sleep(5)
            continue

        info = get_ip_info()

        if not info:
            log.error("Could not get IP info. Retrying in 5s...")
            time.sleep(5)
            continue

        changed = "YES " if info["ip"] != last_ip else "NO "
        last_ip = info["ip"]

        print("\n" + "─" * 60)
        print(f"  Rotation   : #{rotation}")
        print(f"  IP Address : {info['ip']}")
        print(f"  Location   : {info['city']}, {info['country']}")
        print(f"  Provider   : {info['org']}")
        print(f"  IP Changed : {changed}")
        print("─" * 60)

        # ── Fetch any website anonymously ─────────────────────
        # Uncomment to use:
        # html = fetch_website("https://example.com")
        # if html:
        #     print(html[:500])

        time.sleep(ROTATE_INTERVAL)

# ─────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Stopped by user.")
        log.info("Program terminated.")
