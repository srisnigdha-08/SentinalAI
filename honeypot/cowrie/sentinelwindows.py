"""SentinelAI Cowrie plugin: the simulated Windows shell for the experimental windows_srv persona (Rank 7).

NOT DEPLOYED and OFF by default. It exists so an owner can enable the simulation deliberately; nothing in the
project installs or enables it. Install: copy to cowrie/src/cowrie/output/sentinelwindows.py, make the
honeypot/windows_persona package importable (persona_path), and add

    [output_sentinelwindows]
    enabled = true
    allow_experimental = true
    persona_path = /path/to/sentinelai/honeypot

Even then the hook only acts when the persona header written by switch_profile.py says windows_srv, and
switch_profile.py still refuses to write that persona (production serving disabled). The plugin swaps the shell
only; it logs nothing itself (Cowrie's own JSON log records the events the shell dispatches).
"""
import re
import sys

from cowrie.core import output
from cowrie.core.config import CowrieConfig

_HEADER = re.compile(r"switch_profile\.py \((\w+)\)")


def _served_persona():
    try:
        path = CowrieConfig.get("output_sentinelwindows", "cowrie_cfg", fallback="etc/cowrie.cfg")
        with open(path, encoding="utf-8") as f:  # read-only: the persona header on line 1
            m = _HEADER.search(f.readline())
        return m.group(1) if m else None
    except OSError:
        return None


class Output(output.Output):
    def start(self):
        enabled = CowrieConfig.getboolean("output_sentinelwindows", "enabled", fallback=False)
        allow = CowrieConfig.getboolean("output_sentinelwindows", "allow_experimental", fallback=False)
        path = CowrieConfig.get("output_sentinelwindows", "persona_path", fallback="")
        if path and path not in sys.path:
            sys.path.insert(0, path)
        from cowrie.shell import honeypot
        from windows_persona.cowrie_hook import install

        result = install(honeypot, enabled=enabled, persona=_served_persona(), allow_experimental=allow)
        print(f"[SentinelAI] simulated Windows shell: {result}")

    def stop(self):
        pass

    def write(self, event):
        pass
