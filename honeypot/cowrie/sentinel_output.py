"""SentinelAI Cowrie Output Plugin
Install: copy to cowrie/src/cowrie/output/sentinel.py
"""
import time, datetime, requests, logging
from cowrie.core import output
from cowrie.core.config import CowrieConfig

log = logging.getLogger("sentinel.cowrie.output")

class Output(output.Output):
    def start(self):
        self.sessions = {}
        self.url = CowrieConfig.get("output_sentinel", "url", fallback="http://localhost:5000/api/honeypot/ingest")
        self.api_key = CowrieConfig.get("output_sentinel", "api_key", fallback="")
        if not self.api_key:
            raise ValueError("Sentinel output requires an internal API key")
    def stop(self): pass
    def _post(self, etype, data):
        try:
            response = requests.post(self.url, json={"eventType":etype,"timestamp":datetime.datetime.now(datetime.timezone.utc).isoformat(),**data},
                headers={"Content-Type":"application/json","X-API-Key":self.api_key}, timeout=5)
            response.raise_for_status()
            return True
        except Exception as exc:
            log.warning("Sentinel output delivery failed (%s)", type(exc).__name__)
            return False
    def sessionOpened(self, session, src_ip, src_port, dst_ip, dst_port, **kw):
        self.sessions[session]={"sourceIP":src_ip,"startTime":time.time(),"commands":[],"credentials":[]}
        self._post("SESSION_OPENED",{"sessionId":session,"sourceIP":src_ip,"sourcePort":src_port,"honeypotNode":"SSH-COWRIE-01","protocol":"SSH"})
    def sessionClosed(self, session, **kw):
        m=self.sessions.get(session)
        if not m: return
        dur=int(time.time()-m["startTime"])
        if self._post("SESSION_CLOSED",{"sessionId":session,"sourceIP":m["sourceIP"],"durationSeconds":dur,"commandCount":len(m["commands"]),"credentials":m["credentials"]}):
            self.sessions.pop(session, None)
    def loginFailed(self, session, username, password, **kw):
        if session in self.sessions:
            self.sessions[session]["credentials"].append({"username":username,"password":password,"success":False})
    def loginSucceeded(self, session, username, password, **kw):
        if session in self.sessions:
            self.sessions[session]["credentials"].append({"username":username,"password":password,"success":True})
    def command_input(self, session, command, **kw):
        src=self.sessions.get(session,{}).get("sourceIP","?")
        if session in self.sessions: self.sessions[session]["commands"].append(command)
        self._post("COMMAND_INPUT",{"sessionId":session,"sourceIP":src,"command":command})
    def file_download(self, session, duplicate, url, outfile, **kw):
        src=self.sessions.get(session,{}).get("sourceIP","?")
        self._post("FILE_DOWNLOAD",{"sessionId":session,"sourceIP":src,"url":url,"filename":outfile,"isDuplicate":duplicate})
    def write(self, entry):
        """Cowrie delivers normalized event dictionaries through this method."""
        event = entry.get("eventid")
        sid = entry.get("session")
        if not isinstance(sid, str) or not sid: return
        if event == "cowrie.session.connect":
            self.sessionOpened(sid, entry.get("src_ip"), entry.get("src_port"), entry.get("dst_ip"), entry.get("dst_port"))
        elif sid in self.sessions:
            if event == "cowrie.login.failed":
                self.loginFailed(sid, entry.get("username", ""), entry.get("password", ""))
            elif event == "cowrie.login.success":
                self.loginSucceeded(sid, entry.get("username", ""), entry.get("password", ""))
            elif event == "cowrie.command.input":
                self.command_input(sid, entry.get("input", ""))
            elif event == "cowrie.session.file_download":
                self.file_download(sid, entry.get("duplicate", False), entry.get("url", ""), entry.get("outfile", ""))
            elif event == "cowrie.session.closed":
                self.sessionClosed(sid)
