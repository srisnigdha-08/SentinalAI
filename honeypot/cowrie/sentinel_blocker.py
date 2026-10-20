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

class Output(output.Output):
    def start(self):
        self.blocked_ips = set()
        self.cache = {}  # ip -> (is_blocked, timestamp)
        self.cache_ttl = 2.0  # 2 seconds TTL for local overrides
        # Same default as the parser (log_parser.py SENTINEL_API); set SENTINEL_API_URL when the backend is remote.
        self.api_url = os.getenv("SENTINEL_API_URL", "http://localhost:5000/api")
        self.api_key = os.getenv("HONEYPOT_API_KEY", "")
        self.running = True
        
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

    def _background_sync_loop(self):
        """Continuously syncs the full blocklist in the background so buildProtocol never blocks."""
        while self.running:
            try:
                if self.api_key:
                    res = requests.get(
                        f"{self.api_url}/honeypot/ingest/check-block",
                        headers={"X-API-Key": self.api_key},
                        timeout=2.5
                    )
                    if res.status_code == 200:
                        data = res.json().get("data", {})
                        if "blockedIPs" in data:
                            self.blocked_ips = set(data["blockedIPs"])
            except Exception as e:
                pass
            time.sleep(2.0)

    def _async_query_ip(self, ip):
        """Background thread query for un-cached single IP lookup."""
        try:
            if not self.api_key:
                return
            res = requests.get(
                f"{self.api_url}/honeypot/ingest/check-block?ip={ip}",
                headers={"X-API-Key": self.api_key},
                timeout=2.0
            )
            if res.status_code == 200:
                is_blocked = res.json().get("data", {}).get("blocked", False)
                self.cache[ip] = (is_blocked, time.time())
                if is_blocked:
                    self.blocked_ips.add(ip)
                else:
                    self.blocked_ips.discard(ip)
        except Exception:
            pass

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
        # 1. Immediate in-memory set check (0ms latency, zero blocking I/O)
        if ip in self.blocked_ips:
            return True

        # 2. Check local short-term cache
        now = time.time()
        if ip in self.cache:
            is_blocked, ts = self.cache[ip]
            if now - ts < self.cache_ttl:
                return is_blocked

        # 3. If cache miss, dispatch an asynchronous non-blocking fetch in background
        # and do not block Twisted reactor during protocol handshake
        threading.Thread(target=self._async_query_ip, args=(ip,), daemon=True).start()
        
        return False
