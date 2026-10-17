"""
SentinelAI Modular Threat Detection - Host EDR Telemetry Adapter Contract
Phase 10 Detector Recovery: E3 Host Process Lineage & EDR Telemetry Adapter

Provides typed schema, process lineage reconstruction, living-off-the-land (LOLBin)
reconnaissance heuristics, bounded LRU memory, and fail-safe degradation for host telemetry.
"""

from __future__ import annotations
import math
import os
import re
import time
import logging
from collections import OrderedDict
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import threading
from pydantic import BaseModel, Field

from modular.base import BaseDetector
from modular.contracts import (
    DetectorResult,
    DetectorStatus,
    PolicyDecision,
    SeverityLevel,
    MitigationAction,
    EvidenceRecord,
    SimulatedMitigation,
    create_degraded_result,
    validate_finite_score
)

log = logging.getLogger("sentinel.modular.host_telemetry_adapter")


class HostEventType(str, Enum):
    PROCESS_CREATION = "PROCESS_CREATION"
    LOGON = "LOGON"
    NETWORK_CONNECT = "NETWORK_CONNECT"
    FILE_EVENT = "FILE_EVENT"


class HostTelemetryEvent(BaseModel):
    """Normalized host security event contract."""
    event_type: HostEventType
    timestamp: float = Field(..., description="Epoch seconds timestamp of host event")
    host_id: str = Field(..., min_length=1, description="Target host identifier (hostname or IP)")
    process_name: Optional[str] = Field(default=None, description="Executable process name")
    process_path: Optional[str] = Field(default=None, description="Full filesystem path of process")
    command_line: Optional[str] = Field(default=None, description="Full command line string executed")
    parent_process_name: Optional[str] = Field(default=None, description="Parent process name")
    parent_command_line: Optional[str] = Field(default=None, description="Parent command line")
    user_identity: Optional[str] = Field(default=None, description="User context under which process executed")
    event_id: Optional[int] = Field(default=None, description="Windows Event ID (4688, 4624, etc.) or Sysmon ID")
    logon_type: Optional[int] = Field(default=None, description="Windows Logon Type (3=Network, 10=RemoteInteractive)")
    dest_ip: Optional[str] = Field(default=None, description="Remote network destination IP")
    dest_port: Optional[int] = Field(default=None, description="Remote network destination port")
    raw_data: Optional[Dict[str, Any]] = Field(default=None, description="Original raw event dictionary")


# High-risk web server and service parent processes
WEB_AND_SERVICE_PARENTS: Set[str] = {
    "w3wp.exe", "httpd.exe", "nginx.exe", "apache2", "apache2.exe",
    "tomcat.exe", "sqlservr.exe", "mysqld.exe", "java.exe", "php-cgi.exe"
}

# High-risk interactive shell children
SHELL_CHILDREN: Set[str] = {
    "cmd.exe", "powershell.exe", "powershell", "cmd", "pwsh.exe",
    "sh", "bash", "zsh", "whoami.exe", "net.exe", "net1.exe"
}

# Office application parents prone to malicious macro execution
OFFICE_PARENTS: Set[str] = {
    "winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe", "acrord32.exe"
}

# Script engines and payload droppers
SCRIPT_CHILDREN: Set[str] = {
    "cmd.exe", "powershell.exe", "cscript.exe", "wscript.exe",
    "mshta.exe", "certutil.exe", "bitsadmin.exe", "rundll32.exe", "regsvr32.exe"
}

# LOLBin and C2 reconnaissance command indicators (regex patterns)
PATTERNS_CRITICAL_LOLBINS: List[Tuple[str, re.Pattern]] = [
    ("DEFENSE_EVASION_VSSADMIN", re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows", re.IGNORECASE)),
    ("DEFENSE_EVASION_WMIC_SHADOW", re.compile(r"wmic\s+shadowcopy\s+delete", re.IGNORECASE)),
    ("CREDENTIAL_DUMPING_MIMIKATZ", re.compile(r"(?:mimikatz|sekurlsa|lsadump|procdump(?:\.exe)?\s+-ma\s+lsass)", re.IGNORECASE)),
    ("MALICIOUS_CERTUTIL_DOWNLOAD", re.compile(r"certutil(?:\.exe)?\s+(?:-urlcache|-f)\s+(?:http|ftp)", re.IGNORECASE)),
    ("ENCODED_POWERSHELL_PAYLOAD", re.compile(r"powershell(?:\.exe)?(?:\s+.*)?\s+(?:-enc|-encodedcommand|-e)\s+[A-Za-z0-9+/=]{16,}", re.IGNORECASE)),
    ("REVERSE_SHELL_PIPE", re.compile(r"(?:/bin/sh|/bin/bash)\s+-i\s+>&|nc(?:\.exe)?\s+.*\s+-e\s+(?:/bin/sh|cmd\.exe)", re.IGNORECASE)),
]

PATTERNS_RECONNAISSANCE: List[Tuple[str, re.Pattern]] = [
    ("DOMAIN_RECON_NLTEST", re.compile(r"nltest(?:\.exe)?\s+/(?:dclist|domain_trusts)", re.IGNORECASE)),
    ("USER_RECON_NET_USER", re.compile(r"net(?:\.exe)?\s+user(?:\s+/domain|\s+Administrator)?", re.IGNORECASE)),
    ("GROUP_RECON_NET_GROUP", re.compile(r"net(?:\.exe)?\s+(?:group|localgroup)\s+\"?administrators\"?", re.IGNORECASE)),
    ("PRIVILEGE_RECON_WHOAMI", re.compile(r"whoami(?:\.exe)?\s+/(?:all|priv|groups)", re.IGNORECASE)),
    ("NETWORK_RECON_IPCONFIG", re.compile(r"ipconfig(?:\.exe)?\s+/all", re.IGNORECASE)),
    ("SYSTEM_RECON_SYSTEMINFO", re.compile(r"systeminfo(?:\.exe)?", re.IGNORECASE)),
]


def _extract_basename(path_or_name: Optional[str]) -> str:
    if not path_or_name:
        return ""
    clean = str(path_or_name).strip().replace("/", "\\")
    return os.path.basename(clean).lower()


def parse_host_telemetry(raw: Dict[str, Any]) -> Optional[HostTelemetryEvent]:
    """
    Parses heterogeneous host telemetry formats into standard HostTelemetryEvent.
    Supports:
    1. Direct structured JSON/dict
    2. Windows Security Event 4688 (Process Creation) and 4624 (Logon)
    3. Sysmon Event 1 (Process Create) and 3 (Network Connect)
    4. Linux auditd / execve dictionaries
    
    Returns None if payload cannot be validated or contains non-finite numbers.
    """
    if not isinstance(raw, dict):
        return None

    norm = {str(k).strip().lower().replace(" ", "_").replace("-", "_"): v for k, v in raw.items()}

    ts_raw = norm.get("timestamp") or norm.get("ts") or norm.get("utctime") or time.time()
    try:
        ts = float(ts_raw)
        if not math.isfinite(ts) or ts <= 0:
            return None
    except (ValueError, TypeError):
        return None

    host_id = str(norm.get("host_id") or norm.get("hostname") or norm.get("computer_name") or norm.get("host") or "localhost").strip()
    if not host_id:
        host_id = "localhost"

    # Event ID identification
    eid = None
    if norm.get("event_id") is not None or norm.get("eventid") is not None:
        try:
            eid = int(norm.get("event_id") or norm.get("eventid"))
        except (ValueError, TypeError):
            pass

    # Sysmon Event 1 or Windows Event 4688: Process creation
    is_process_creation = False
    proc_name = norm.get("process_name") or norm.get("image") or norm.get("newprocessname") or norm.get("exe") or norm.get("comm")
    cmd_line = norm.get("command_line") or norm.get("commandline") or norm.get("cmdline") or norm.get("cmd")
    parent_proc = norm.get("parent_process_name") or norm.get("parentimage") or norm.get("parentprocessname")
    parent_cmd = norm.get("parent_command_line") or norm.get("parentcommandline")
    user = norm.get("user_identity") or norm.get("user") or norm.get("targetusername") or norm.get("subjectusername")

    if eid in (1, 4688) or norm.get("event_type") == "PROCESS_CREATION" or proc_name is not None or cmd_line is not None:
        is_process_creation = True

    if is_process_creation:
        return HostTelemetryEvent(
            event_type=HostEventType.PROCESS_CREATION,
            timestamp=ts,
            host_id=host_id,
            process_name=_extract_basename(str(proc_name)) if proc_name else None,
            process_path=str(proc_name) if proc_name else None,
            command_line=str(cmd_line) if cmd_line else None,
            parent_process_name=_extract_basename(str(parent_proc)) if parent_proc else None,
            parent_command_line=str(parent_cmd) if parent_cmd else None,
            user_identity=str(user) if user else None,
            event_id=eid,
            raw_data=raw
        )

    # Windows Event 4624 / Logon
    if eid in (4624, 4625) or norm.get("event_type") == "LOGON" or norm.get("logon_type") is not None:
        l_type = None
        if norm.get("logon_type") is not None:
            try:
                l_type = int(norm["logon_type"])
            except (ValueError, TypeError):
                pass
        return HostTelemetryEvent(
            event_type=HostEventType.LOGON,
            timestamp=ts,
            host_id=host_id,
            user_identity=str(user) if user else None,
            event_id=eid,
            logon_type=l_type,
            dest_ip=str(norm.get("ipaddress") or norm.get("src_ip")) if norm.get("ipaddress") or norm.get("src_ip") else None,
            raw_data=raw
        )

    return None


class HostHistory:
    """Sliding-window tracking of recent host events for lateral movement correlation with deduplication."""
    def __init__(self, host_id: str):
        self.host_id = host_id
        self.recent_logons: List[Tuple[float, int, Optional[str]]] = []  # (ts, logon_type, user)
        self.recent_commands: List[Tuple[float, str]] = []  # (ts, cmdline)
        self.last_seen_ts: float = 0.0
        self.recent_signatures: Set[str] = set()

    def record_logon(self, ts: float, logon_type: Optional[int], user: Optional[str], sig: Optional[str] = None) -> bool:
        if sig and sig in self.recent_signatures:
            return False
        if sig:
            if len(self.recent_signatures) > 500:
                self.recent_signatures.clear()
            self.recent_signatures.add(sig)
        self.last_seen_ts = max(self.last_seen_ts, ts)
        self.recent_logons.append((ts, logon_type or 0, user))
        self.recent_logons.sort(key=lambda x: x[0])
        return True

    def record_command(self, ts: float, cmdline: str, sig: Optional[str] = None) -> bool:
        if sig and sig in self.recent_signatures:
            return False
        if sig:
            if len(self.recent_signatures) > 500:
                self.recent_signatures.clear()
            self.recent_signatures.add(sig)
        self.last_seen_ts = max(self.last_seen_ts, ts)
        self.recent_commands.append((ts, cmdline))
        self.recent_commands.sort(key=lambda x: x[0])
        return True

    def prune(self, current_ts: float, horizon_seconds: float = 300.0) -> None:
        effective_ts = max(current_ts, self.last_seen_ts)
        cutoff = effective_ts - horizon_seconds
        self.recent_logons = [x for x in self.recent_logons if x[0] >= cutoff]
        self.recent_commands = [x for x in self.recent_commands if x[0] >= cutoff]
        self.recent_logons.sort(key=lambda x: x[0])
        self.recent_commands.sort(key=lambda x: x[0])


class HostTelemetryDetector(BaseDetector):
    """
    E3 Host EDR Telemetry Adapter & Advanced Threat Detector.
    
    Ingests and normalizes host security telemetry.
    Detects:
    1. Web shell / RCE execution (web servers spawning shells).
    2. Malicious document macros (Office spawning script interpreters).
    3. Living-off-the-land (LOLBin) attack execution (certutil, mimikatz, encoded powershell).
    4. Post-compromise reconnaissance commands (whoami /all, net user /domain).
    5. Lateral movement (network logon immediately followed by interactive command execution).
    
    Enforces bounded LRU state table, thread safety, and fail-safe degradation on missing fields.
    """

    def __init__(
        self,
        detector_id: str = "host_telemetry_adapter",
        version: str = "1.0.0",
        max_tracked_hosts: int = 2000,
        lateral_movement_window_seconds: float = 60.0
    ):
        super().__init__(detector_id=detector_id, version=version)
        self.max_tracked_hosts = int(max_tracked_hosts)
        self.lateral_movement_window_seconds = float(lateral_movement_window_seconds)

        self._lock = threading.RLock()
        self._host_table: OrderedDict[str, HostHistory] = OrderedDict()

    def health_check(self) -> DetectorStatus:
        with self._lock:
            if len(self._host_table) > self.max_tracked_hosts:
                return DetectorStatus.DEGRADED
            return DetectorStatus.HEALTHY

    def reset_state(self) -> None:
        with self._lock:
            self._host_table.clear()

    def _get_or_create_host(self, host_id: str) -> HostHistory:
        with self._lock:
            if host_id in self._host_table:
                hist = self._host_table.pop(host_id)
                self._host_table[host_id] = hist
                return hist

            if len(self._host_table) >= self.max_tracked_hosts:
                self._host_table.popitem(last=False)

            hist = HostHistory(host_id)
            self._host_table[host_id] = hist
            return hist

    def _inspect(self, telemetry: Dict[str, Any], correlation_id: str) -> DetectorResult:
        host_event = parse_host_telemetry(telemetry)
        if host_event is None:
            # Telemetry lacks required host structures or contains invalid/non-finite fields
            return create_degraded_result(
                detector_id=self.detector_id,
                status=DetectorStatus.INCOMPLETE,
                reason="Input telemetry lacks valid structured host EDR event fields",
                correlation_id=correlation_id
            )

        proc = host_event.process_name or ""
        parent = host_event.parent_process_name or ""
        cmd = host_event.command_line or ""
        event_sig = f"{host_event.timestamp}:{host_event.host_id}:{host_event.event_type.value}:{proc}:{cmd}:{host_event.logon_type}"

        with self._lock:
            host_hist = self._get_or_create_host(host_event.host_id)
            host_hist.prune(host_event.timestamp)

            if host_event.event_type == HostEventType.LOGON:
                host_hist.record_logon(host_event.timestamp, host_event.logon_type, host_event.user_identity, sig=event_sig)
                return DetectorResult(
                    detector_id=self.detector_id,
                    version=self.version,
                    correlation_id=correlation_id,
                    status=DetectorStatus.HEALTHY,
                    decision=PolicyDecision.ALLOW,
                    confidence=0.01,
                    severity=SeverityLevel.INFORMATIONAL,
                    evidence=EvidenceRecord(
                        trigger_rule="BENIGN_HOST_LOGON_RECORDED",
                        summary=f"Host logon recorded for user {host_event.user_identity} (Type: {host_event.logon_type})",
                        extracted_features={"host_id": host_event.host_id, "logon_type": host_event.logon_type}
                    ),
                    mitigation_recommendation=SimulatedMitigation(action=MitigationAction.NONE, simulated=True)
                )

            # Record process execution
            if host_event.command_line:
                host_hist.record_command(host_event.timestamp, host_event.command_line, sig=event_sig)

        proc = host_event.process_name or ""
        parent = host_event.parent_process_name or ""
        cmd = host_event.command_line or ""

        extracted = {
            "host_id": host_event.host_id,
            "process_name": proc,
            "parent_process_name": parent,
            "command_line": cmd,
            "user_identity": host_event.user_identity
        }

        # 1. Web Server / Service Spawning Command Shell (Web Shell / Remote Code Execution)
        if parent.lower() in WEB_AND_SERVICE_PARENTS and proc.lower() in SHELL_CHILDREN:
            return DetectorResult(
                detector_id=self.detector_id,
                version=self.version,
                correlation_id=correlation_id,
                status=DetectorStatus.HEALTHY,
                decision=PolicyDecision.SIMULATED_BLOCK,
                confidence=0.98,
                severity=SeverityLevel.CRITICAL,
                evidence=EvidenceRecord(
                    trigger_rule="EXPLOIT_WEBSHELL_PROCESS_SPAWNED",
                    summary=f"Web server or daemon '{parent}' spawned interactive shell '{proc}' on host {host_event.host_id}",
                    extracted_features=extracted
                ),
                mitigation_recommendation=SimulatedMitigation(
                    action=MitigationAction.SIMULATED_BLOCK,
                    simulated=True,
                    watermark="[SIMULATED BLOCK - WEBSHELL EXECUTION]"
                )
            )

        # 2. Office Document Spawning Script Host or Shell (Phishing Payload)
        if parent.lower() in OFFICE_PARENTS and proc.lower() in SCRIPT_CHILDREN:
            return DetectorResult(
                detector_id=self.detector_id,
                version=self.version,
                correlation_id=correlation_id,
                status=DetectorStatus.HEALTHY,
                decision=PolicyDecision.SIMULATED_BLOCK,
                confidence=0.96,
                severity=SeverityLevel.CRITICAL,
                evidence=EvidenceRecord(
                    trigger_rule="SUSPICIOUS_OFFICE_CHILD_PROCESS",
                    summary=f"Office application '{parent}' spawned script host/shell '{proc}' on host {host_event.host_id}",
                    extracted_features=extracted
                ),
                mitigation_recommendation=SimulatedMitigation(
                    action=MitigationAction.SIMULATED_BLOCK,
                    simulated=True,
                    watermark="[SIMULATED BLOCK - OFFICE MACRO EXPLOIT]"
                )
            )

        # 3. Critical LOLBin / Defense Evasion / Credential Dumping Commands
        for rule_id, pattern in PATTERNS_CRITICAL_LOLBINS:
            if pattern.search(cmd):
                return DetectorResult(
                    detector_id=self.detector_id,
                    version=self.version,
                    correlation_id=correlation_id,
                    status=DetectorStatus.HEALTHY,
                    decision=PolicyDecision.SIMULATED_BLOCK,
                    confidence=0.95,
                    severity=SeverityLevel.CRITICAL,
                    evidence=EvidenceRecord(
                        trigger_rule=f"LOLBIN_CRITICAL_{rule_id}",
                        summary=f"High-risk adversary command pattern matched '{rule_id}' in: {cmd[:120]}",
                        extracted_features=extracted
                    ),
                    mitigation_recommendation=SimulatedMitigation(
                        action=MitigationAction.SIMULATED_BLOCK,
                        simulated=True,
                        watermark="[SIMULATED BLOCK - LOLBIN EXECUTION]"
                    )
                )

        # 4. Lateral Movement Correlation: Network Logon (Type 3 or 10) followed by Shell/Command
        with self._lock:
            recent_net_logons = [
                lg for lg in host_hist.recent_logons
                if lg[1] in (3, 9, 10) and (host_event.timestamp - lg[0]) <= self.lateral_movement_window_seconds
            ]
        if recent_net_logons and proc.lower() in SHELL_CHILDREN:
            lg_ts, lg_type, lg_user = recent_net_logons[-1]
            return DetectorResult(
                detector_id=self.detector_id,
                version=self.version,
                correlation_id=correlation_id,
                status=DetectorStatus.HEALTHY,
                decision=PolicyDecision.SIMULATED_BLOCK,
                confidence=0.92,
                severity=SeverityLevel.CRITICAL,
                evidence=EvidenceRecord(
                    trigger_rule="LATERAL_MOVEMENT_REMOTE_EXECUTION",
                    summary=(
                        f"Process '{proc}' spawned on {host_event.host_id} within "
                        f"{host_event.timestamp - lg_ts:.1f}s of remote network logon (Type {lg_type}, user {lg_user})"
                    ),
                    extracted_features=extracted
                ),
                mitigation_recommendation=SimulatedMitigation(
                    action=MitigationAction.SIMULATED_BLOCK,
                    simulated=True,
                    watermark="[SIMULATED BLOCK - LATERAL MOVEMENT]"
                )
            )

        # 5. Reconnaissance Command Indicators
        for rule_id, pattern in PATTERNS_RECONNAISSANCE:
            if pattern.search(cmd):
                return DetectorResult(
                    detector_id=self.detector_id,
                    version=self.version,
                    correlation_id=correlation_id,
                    status=DetectorStatus.HEALTHY,
                    decision=PolicyDecision.DETECTED,
                    confidence=0.82,
                    severity=SeverityLevel.HIGH,
                    evidence=EvidenceRecord(
                        trigger_rule=f"HOST_RECONNAISSANCE_{rule_id}",
                        summary=f"Reconnaissance command detected on host {host_event.host_id}: {cmd[:120]}",
                        extracted_features=extracted
                    ),
                    mitigation_recommendation=SimulatedMitigation(
                        action=MitigationAction.SIMULATED_RATE_LIMIT,
                        simulated=True,
                        watermark="[SIMULATED RATE LIMIT - HOST RECONNAISSANCE]"
                    )
                )

        # 6. Benign process execution -> ALLOW
        return DetectorResult(
            detector_id=self.detector_id,
            version=self.version,
            correlation_id=correlation_id,
            status=DetectorStatus.HEALTHY,
            decision=PolicyDecision.ALLOW,
            confidence=0.02,
            severity=SeverityLevel.INFORMATIONAL,
            evidence=EvidenceRecord(
                trigger_rule="BENIGN_HOST_PROCESS",
                summary=f"Process '{proc}' executed within normal host baseline",
                extracted_features=extracted
            ),
            mitigation_recommendation=SimulatedMitigation(action=MitigationAction.NONE, simulated=True)
        )
