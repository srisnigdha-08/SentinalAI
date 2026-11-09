"""
Label taxonomies for development experiments (audit/ML_DEV_PROTOCOL.md §5). Experiment-only: the deployed model,
API, stored records and UI keep the current 11-class contract (utils.features.LABEL_MAP) until an approved migration.

Every raw label of CICIDS2017 and CSE-CIC-IDS2018 is listed once in RAW_LABELS with its family, whether the flow
features can plausibly separate it from its neighbours (flow_observable), and its current project class (T0).
Labels are normalised (lower case, non-alphanumerics collapsed) because the CSVs spell them inconsistently.
"""
import re

import numpy as np


def norm(label) -> str:
    return re.sub(r"[^a-z0-9]+", " ", str(label).encode("ascii", "ignore").decode().lower()).strip()


# raw label -> (corpus, family, T0 project class, flow_observable, note)
RAW_LABELS = {
    "benign": ("both", "Benign", "BENIGN", True, ""),
    # CICIDS2017
    "ssh patator": ("2017", "Brute Force", "SSH Brute Force", True, ""),
    "ftp patator": ("2017", "Brute Force", "Credential Stuffing", True, "T0 merges FTP with HTTP brute force"),
    "web attack brute force": ("2017", "Brute Force", "Credential Stuffing", True, "HTTP form brute force; T0 merges it with FTP"),
    "web attack xss": ("2017", "Web Attack", "XSS Attempt", False, "payload distinction; flows look like HTTP brute force (5-NN 57.5 %)"),
    "web attack sql injection": ("2017", "Web Attack", "SQL Injection", False, "21 flows; payload distinction"),
    "dos hulk": ("2017", "DoS/DDoS", "DDoS", True, ""),
    "dos goldeneye": ("2017", "DoS/DDoS", "DDoS", True, ""),
    "dos slowloris": ("2017", "DoS/DDoS", "DDoS", True, ""),
    "dos slowhttptest": ("2017", "DoS/DDoS", "DDoS", True, ""),
    "ddos": ("2017", "DoS/DDoS", "DDoS", True, "LOIC"),
    "portscan": ("2017", "Reconnaissance", "Port Scan", True, "158,930 raw -> 354 unique vectors"),
    "bot": ("both", "Botnet", "Malware Beacon", True, ""),
    "infiltration": ("2017", "Infiltration", "Lateral Movement", True, "36 flows"),
    "heartbleed": ("2017", "Exploit", "RCE Attempt", False, "11 flows; information disclosure, not RCE; a TLS rule fits better"),
    # CSE-CIC-IDS2018 (development days only; see protected_data.py)
    "ftp bruteforce": ("2018", "Brute Force", "Credential Stuffing", True, ""),
    "ssh bruteforce": ("2018", "Brute Force", "SSH Brute Force", True, ""),
    "dos attacks goldeneye": ("2018", "DoS/DDoS", "DDoS", True, ""),
    "dos attacks slowloris": ("2018", "DoS/DDoS", "DDoS", True, ""),
    "dos attacks slowhttptest": ("2018", "DoS/DDoS", "DDoS", True, "protected day 16-02"),
    "dos attacks hulk": ("2018", "DoS/DDoS", "DDoS", True, "protected day 16-02"),
    "ddos attacks loic http": ("2018", "DoS/DDoS", "DDoS", True, "protected day 20-02"),
    "ddos attack loic udp": ("2018", "DoS/DDoS", "DDoS", True, "UDP flood: no 2017 counterpart"),
    "ddos attack hoic": ("2018", "DoS/DDoS", "DDoS", True, ""),
    "brute force web": ("2018", "Brute Force", "Credential Stuffing", True, ""),
    "brute force xss": ("2018", "Web Attack", "XSS Attempt", False, ""),
    "sql injection": ("2018", "Web Attack", "SQL Injection", False, ""),
    "infilteration": ("2018", "Infiltration", "Lateral Movement", True, "labels assigned by time/IP window"),
}

# Project classes with no data in either corpus
NO_DATA = ("Data Exfiltration",)

TAXONOMIES = {
    # T0: the deployed 11-class contract (Data Exfiltration has no samples)
    "T0": lambda raw: RAW_LABELS[raw][2],
    # T1: T0 with "Credential Stuffing" split into the two behaviours it merges
    "T1": lambda raw: {"ftp patator": "FTP Brute Force", "ftp bruteforce": "FTP Brute Force",
                       "web attack brute force": "Web Brute Force", "brute force web": "Web Brute Force"}.get(raw, RAW_LABELS[raw][2]),
    # T2: behaviour families (XSS/SQLi merged into Web Attack; DoS and DDoS together; Heartbleed as Exploit)
    "T2": lambda raw: RAW_LABELS[raw][1],
    # TB: binary decision only
    "TB": lambda raw: "Benign" if RAW_LABELS[raw][1] == "Benign" else "Attack",
}


def map_labels(raw_labels, taxonomy: str):
    """Raw CSV labels -> class names under `taxonomy`. Unknown labels raise (never silently become BENIGN)."""
    fn = TAXONOMIES[taxonomy]
    out = []
    for lab in raw_labels:
        key = norm(lab)
        if key not in RAW_LABELS:
            raise KeyError(f"unmapped raw label: {lab!r}")
        out.append(fn(key))
    return np.asarray(out, dtype=object)


def describe(taxonomy: str) -> dict:
    """{class: [raw labels]} — the explicit mapping table for documentation."""
    table = {}
    for raw in RAW_LABELS:
        table.setdefault(TAXONOMIES[taxonomy](raw), []).append(raw)
    return table
