"""SentinelAI Cowrie blocker plugin: refuses connections from IPs on the SentinelAI deny-list.
Install: copy to cowrie/src/cowrie/output/sentinelblocker.py and enable [output_sentinelblocker]. The name has no
underscore on purpose: Cowrie loads module cowrie.output.<section.split("_")[1]>, so "sentinel_blocker" would
load "sentinel" (which does not exist) and the plugin would silently never run.

A background thread pulls the full deny-list every SYNC_INTERVAL seconds; connection handling only reads
the in-memory copy, so the Twisted reactor never blocks on the network and a connection flood cannot
start threads or requests. A newly blocked IP is therefore refused within SYNC_INTERVAL (+ request time).
If the backend is unreachable the last list is kept.
"""
import os
import time
import requests
import threading
from cowrie.core import output
from cowrie.ssh.factory import CowrieSSHFactory
try:
    from cowrie.telnet.factory import HoneyPotTelnetFactory
except ImportError:
    HoneyPotTelnetFactory = None

SYNC_INTERVAL = 2.0


class Output(output.Output):
    def start(self):
        self.blocked_ips = frozenset()
        self.last_sync = None
        # Same default as the parser (log_parser.py SENTINEL_API); set SENTINEL_API_URL when the backend is remote.
        self.api_url = os.getenv("SENTINEL_API_URL", "http://localhost:5000/api")
        self.api_key = os.getenv("HONEYPOT_API_KEY", "")
        self.running = True
        if not self.api_key:
            print("[SentinelAI] HONEYPOT_API_KEY is not set: the blocker cannot read the deny-list and blocks nothing.")

        # Start background sync thread to poll blocklist continuously
        self.sync_thread = threading.Thread(target=self._background_sync_loop, daemon=True)
        self.sync_thread.start()

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
        return ip in self.blocked_ips
