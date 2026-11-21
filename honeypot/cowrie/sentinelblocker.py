"""SentinelAI Cowrie blocker plugin: refuses connections from IPs on the SentinelAI deny-list.
Install: copy to cowrie/src/cowrie/output/sentinelblocker.py and enable [output_sentinelblocker]. The name has no
underscore on purpose: Cowrie loads module cowrie.output.<section.split("_")[1]>, so "sentinel_blocker" would
load "sentinel" (which does not exist) and the plugin would silently never run.

A background thread pulls the full deny-list every SYNC_INTERVAL seconds; connection handling only reads
the in-memory copy, so the Twisted reactor never blocks on the network and a connection flood cannot
start threads or requests. A newly blocked IP is therefore refused within SYNC_INTERVAL (+ request time).
If the backend is unreachable the last list is kept.

The sync thread is started from reactor.callWhenRunning, not from start(): Cowrie builds its output plugins
before twistd daemonizes, and a thread started then does not survive the fork. Under `cowrie start` the
deny-list stayed empty and nothing was ever blocked (only the foreground mode worked).
"""
import ipaddress
import os
import re
import time
import requests
import threading
from cowrie.core import output
from cowrie.ssh.factory import CowrieSSHFactory
try:
    from cowrie.telnet.factory import HoneyPotTelnetFactory
except ImportError:
    HoneyPotTelnetFactory = None
try:
    from cowrie.core.config import CowrieConfig
except ImportError:
    CowrieConfig = None

SYNC_INTERVAL = 2.0


def honeypot_own_addresses(env=None, config=None):
    """Addresses that belong to the honeypot host itself and are never refused, even when on the deny-list.

    A connection from one of them comes from this host: the deception rotator's banner check after a persona switch
    (it connects to Cowrie's listen address, so its source is that address) or an operator testing locally. Refusing
    them makes every persona switch fail its verification and roll back, which happened when the WSL address of the
    lab Cowrie was blocked after local test sessions. A TCP peer cannot spoof these from outside: the handshake
    would have to complete from this host.
      * loopback (127.0.0.0/8, ::1) - always
      * the interface(s) in [ssh]/[telnet] listen_endpoints (wildcards ignored)
      * SENTINEL_BLOCKER_EXEMPT_IPS: extra comma-separated addresses (e.g. a second local interface)
    """
    env = os.environ if env is None else env
    own = set()
    if config is not None:
        for section in ("ssh", "telnet"):
            try:
                endpoints = config.get(section, "listen_endpoints", fallback="") or ""
            except Exception:
                endpoints = ""
            for addr in re.findall(r"interface=([^\s:]+)", endpoints):
                own.add(addr)
    own.update(a.strip() for a in str(env.get("SENTINEL_BLOCKER_EXEMPT_IPS", "")).split(",") if a.strip())
    valid = set()
    for addr in own:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if not ip.is_unspecified:  # 0.0.0.0 / :: is a wildcard binding, not an address of this host
            valid.add(str(ip))
    return frozenset(valid)


def is_loopback(ip):
    try:
        return ipaddress.ip_address(ip).is_loopback
    except ValueError:
        return False


class Output(output.Output):
    def start(self):
        self.blocked_ips = frozenset()
        self.last_sync = None
        self.own_addresses = honeypot_own_addresses(config=CowrieConfig)
        self._exempt_reported = set()
        if self.own_addresses:
            print(f"[SentinelAI] Never refused (this host's own addresses): {', '.join(sorted(self.own_addresses))} and loopback.")
        # Same default as the parser (log_parser.py SENTINEL_API); set SENTINEL_API_URL when the backend is remote.
        self.api_url = os.getenv("SENTINEL_API_URL", "http://localhost:5000/api")
        self.api_key = os.getenv("HONEYPOT_API_KEY", "")
        self.running = True
        if not self.api_key:
            print("[SentinelAI] HONEYPOT_API_KEY is not set: the blocker cannot read the deny-list and blocks nothing.")

        # Start the sync thread once the reactor runs, i.e. in the process that is left after daemonizing.
        self.sync_thread = None
        from twisted.internet import reactor
        reactor.callWhenRunning(self._start_sync_thread)

        self.patch_ssh()
        if HoneyPotTelnetFactory:
            self.patch_telnet()
        print("[SentinelAI] Non-blocking blocker plugin loaded and connection factories patched successfully.")

    def stop(self):
        self.running = False

    def write(self, entry):
        pass

    def sync_once(self):
        """Replace the deny-list with the backend's; on any failure keep the previous one."""
        if not self.api_key:
            return False
        try:
            res = requests.get(
                f"{self.api_url}/honeypot/ingest/check-block",
                headers={"X-API-Key": self.api_key},
                timeout=2.5
            )
            if res.status_code == 200:
                data = res.json().get("data", {})
                if isinstance(data.get("blockedIPs"), list):
                    self.blocked_ips = frozenset(str(ip) for ip in data["blockedIPs"])
                    self.last_sync = time.time()
                    return True
        except Exception:
            pass
        return False

    def _start_sync_thread(self):
        self.sync_thread = threading.Thread(target=self._background_sync_loop, daemon=True)
        self.sync_thread.start()

    def _background_sync_loop(self):
        """Continuously syncs the full blocklist in the background so buildProtocol never blocks."""
        while self.running:
            self.sync_once()
            time.sleep(SYNC_INTERVAL)

    def patch_ssh(self):
        original_buildProtocol = CowrieSSHFactory.buildProtocol
        def patched_buildProtocol(factory_self, addr):
            ip = addr.host
            if self.is_ip_blocked(ip):
                print(f"[SentinelAI] Connection from blocked IP {ip} rejected (SSH).")
                return None
            return original_buildProtocol(factory_self, addr)
        CowrieSSHFactory.buildProtocol = patched_buildProtocol

    def patch_telnet(self):
        original_buildProtocol = HoneyPotTelnetFactory.buildProtocol
        def patched_buildProtocol(factory_self, addr):
            ip = addr.host
            if self.is_ip_blocked(ip):
                print(f"[SentinelAI] Connection from blocked IP {ip} rejected (Telnet).")
                return None
            return original_buildProtocol(factory_self, addr)
        HoneyPotTelnetFactory.buildProtocol = patched_buildProtocol

    def is_ip_blocked(self, ip):
        # In-memory lookup only: no I/O and no thread per connection (a flood of new IPs used to start a
        # thread and an HTTP request each).
        if ip not in self.blocked_ips:
            return False
        if ip in self.own_addresses or is_loopback(ip):
            # This host's own address is on the deny-list: say so once, but never refuse it (see honeypot_own_addresses).
            if ip not in self._exempt_reported:
                self._exempt_reported.add(ip)
                print(f"[SentinelAI] {ip} is on the deny-list but is this host's own address; not refused.")
            return False
        return True
