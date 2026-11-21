"""Cowrie adapter: the simulated Windows shell in the slot Cowrie's Linux shell normally occupies (Rank 7).

Cowrie 3.1.3 builds each session's shell as `cmdstack = [honeypot.HoneyPotShell(protocol)]` (interactive) or
`HoneyPotShell(protocol, interactive=False)` (`ssh host <command>`). WindowsCowrieShell implements the same
interface Cowrie's protocol calls on that object (lineReceived, showPrompt, resume, eofReceived, handle_CTRL_C,
handle_TAB, interactive, cwd, environ, exported, last_exit_code; checked against the installed Cowrie source by
ai-engine/tests/test_windows_persona.py). Cowrie keeps doing SSH, authentication, logging and session handling.

Every line is answered by windows_persona.shell.WindowsShell: nothing is executed on the host.

Telemetry, exactly (Rank 8):
  - INGESTED by SentinelAI: the standard cowrie.command.input (one per line) and cowrie.command.failed (one per
    unknown program) events. honeypot/parsers/log_parser.py forwards them to the backend, which stores the command
    and computes intent and ATT&CK itself (persona-gated).
  - COWRIE-SIDE ONLY (written to Cowrie's JSON log, NOT ingested: the parser has no handler for them):
    sentinel.windows.command (name, category, intent, ATT&CK ids, simulated=true) and sentinel.windows.limit (a
    hard limit was hit on that line). Ingesting them would duplicate the command records the standard events create.
"""
from __future__ import annotations

from .shell import WindowsShell


class WindowsCowrieShell:
    def __init__(self, protocol, interactive: bool = True, reads_stdin: bool = False, shell: WindowsShell | None = None):
        self.protocol = protocol
        self.interactive = interactive
        self.reads_stdin = reads_stdin
        self.sim = shell or WindowsShell()
        self.last_exit_code = 0
        self.environ = dict(self.sim.env)
        self.exported = set(self.environ)

    @property
    def cwd(self) -> str:
        return self.sim.cwd

    # ── Cowrie protocol interface ───────────────────────────────────────────────────────────────────────────────
    def lineReceived(self, line) -> None:
        if isinstance(line, bytes):
            line = line.decode("utf-8", errors="replace")
        line = line.rstrip("\r\n")  # the logged command is what was typed, without the line terminator
        self._dispatch("cowrie.command.input", "CMD: %(input)s", input=line)
        res = self.sim.execute(line)
        self.last_exit_code = res.exit_code
        for e in res.events:
            if not e["recognised"]:
                self._dispatch("cowrie.command.failed", "Command not found: %(input)s", input=e["command"])
            self._dispatch("sentinel.windows.command", "Simulated Windows command: %(name)s", name=e["name"],
                           category=e["category"], intent=e["intent"], attack=[a["id"] for a in e["attack"]],
                           recognised=e["recognised"], simulated=True, persona="windows_srv")
        if res.limits:
            self._dispatch("sentinel.windows.limit", "Simulated Windows shell limit: %(limits)s", limits=list(res.limits),
                           simulated=True, persona="windows_srv")
        term = self.protocol.terminal
        if res.clear:
            term.eraseDisplay()
            term.cursorHome()
        if res.output:
            term.write((res.output.replace("\r\n", "\n").replace("\n", "\r\n") + "\r\n").encode("utf-8", errors="replace"))
        if res.exit_session or not self.interactive:
            self.protocol.end_process(self.last_exit_code)
            return
        self.showPrompt()

    def showPrompt(self) -> None:
        if not self.interactive:
            return
        prompt = self.sim.prompt().encode("utf-8")
        self.protocol.terminal.write(prompt)
        self.protocol.ps = (prompt, b"More? ")

    def resume(self) -> None:
        self.showPrompt()

    def eofReceived(self) -> None:
        self.protocol.end_process(self.last_exit_code)

    def handle_CTRL_C(self) -> None:
        self.protocol.lineBuffer = []
        self.protocol.lineBufferIndex = 0
        self.protocol.terminal.write(b"^C\r\n")
        self.showPrompt()

    def handle_TAB(self) -> None:
        """No completion: an unanswered TAB is what cmd.exe over a basic SSH terminal looks like."""

    def _dispatch(self, eventid, fmt, **kw):
        events = getattr(self.protocol, "events", None)
        if events is not None:
            events.dispatch(eventid, fmt, **kw)
