/**
 * ============================================================================
 * MOCK / SIMULATION DATA FIXTURES (INTENTIONALLY PRESERVED)
 * ============================================================================
 * This file contains synthetic datasets, dummy incident records, and mock
 * chart series created during early prototyping and testing.
 *
 * In SentinelAI default REAL DATA MODE, all dashboard views, feeds, KPIs,
 * charts, and logs query actual database records and real-time WebSocket
 * events from the live detection pipeline.
 *
 * These fixtures are intentionally PRESERVED for:
 * 1. Unit testing and offline test harnesses
 * 2. Visual design benchmarking
 * 3. Controlled sandbox demonstrations
 *
 * To use in future tests:
 * import { MOCK_THREATS, MOCK_SESSIONS, ... } from './mockData.js'
 * ============================================================================
 */

// ── THREATS ──
export const MOCK_THREATS = [
  { id:1, sev:'CRITICAL', ip:'185.220.101.47', type:'SSH Brute Force',       target:'AUTH-SRV-01',  time:'14:32:17', score:0.97, status:'BLOCKED'    },
  { id:2, sev:'CRITICAL', ip:'45.95.147.22',   type:'RCE Attempt',           target:'WEB-SRV-03',   time:'14:28:04', score:0.94, status:'BLOCKED'    },
  { id:3, sev:'HIGH',     ip:'194.165.16.78',  type:'SQL Injection',         target:'DB-PROD-01',   time:'14:21:45', score:0.87, status:'MONITORING' },
  { id:4, sev:'HIGH',     ip:'212.102.39.212', type:'Port Scan',             target:'GATEWAY-01',   time:'14:18:33', score:0.82, status:'MONITORING' },
  { id:5, sev:'HIGH',     ip:'77.247.110.50',  type:'DDoS',                  target:'LB-PROD-01',   time:'14:12:09', score:0.79, status:'MONITORING' },
  { id:6, sev:'MEDIUM',   ip:'103.75.190.51',  type:'XSS Attempt',           target:'WEB-APP-02',   time:'14:05:22', score:0.64, status:'LOGGED'     },
  { id:7, sev:'MEDIUM',   ip:'91.92.252.10',   type:'Credential Stuffing',   target:'AUTH-SRV-01',  time:'13:58:47', score:0.61, status:'LOGGED'     },
  { id:8, sev:'LOW',      ip:'5.188.210.3',    type:'Malware Beacon',        target:'ENDPOINT-14',  time:'13:44:11', score:0.43, status:'LOGGED'     },
]

// ── HONEYPOT SESSIONS ──
export const MOCK_SESSIONS = [
  { id:'sess-4f9a', ip:'45.95.147.22',   country:'RU', duration:'8m 14s', cmds:['wget','cat /etc/passwd','uname -a','id'],      hp:'SSH-COWRIE-01', ts:'14:28' },
  { id:'sess-2b1c', ip:'185.220.101.47', country:'DE', duration:'2m 44s', cmds:['ls -la','whoami','ps aux'],                    hp:'SSH-COWRIE-01', ts:'14:15' },
  { id:'sess-7e3d', ip:'194.165.16.78',  country:'NL', duration:'6m 02s', cmds:['netstat','curl','chmod +x','wget http://...'], hp:'HTTP-LURE-02',  ts:'13:58' },
  { id:'sess-1a8f', ip:'77.247.110.50',  country:'US', duration:'1m 18s', cmds:['id','uname -a'],                               hp:'SSH-COWRIE-01', ts:'13:44' },
  { id:'sess-9d2e', ip:'91.92.252.10',   country:'CN', duration:'11m 30s',cmds:['cat /etc/shadow','adduser hax','crontab -e'],  hp:'SSH-COWRIE-01', ts:'13:30' },
]

// ── HONEYPOT NODES ──
export const MOCK_HONEYPOTS = [
  { id:1, name:'SSH-COWRIE-01',  status:'active', sessions:23, port:2222 },
  { id:2, name:'HTTP-LURE-02',   status:'active', sessions:11, port:8080 },
  { id:3, name:'FTP-TRAP-03',    status:'idle',   sessions:3,  port:21   },
  { id:4, name:'SMTP-DECOY-04',  status:'active', sessions:7,  port:25   },
]

// ── AI PREDICTIONS ──
export const MOCK_AI_PREDS = [
  { icon:'🔴', threat:'Ransomware Deployment',  meta:'Pattern: WannaCry variant — 94% match',   score:94, color:'#ff2d55' },
  { icon:'🟠', threat:'Lateral Movement',        meta:'SMB traversal from 185.220.101.47',        score:78, color:'#ff6400' },
  { icon:'🟡', threat:'Data Exfiltration',       meta:'Anomalous outbound traffic: 2.4GB',         score:61, color:'#ffaa00' },
]

// ── USERS ──
export const MOCK_USERS = [
  { id:1, initials:'AS', name:'Arjun Sharma',   email:'admin@sentinel.io',  role:'Admin',   status:'Online',  last:'Just now' },
  { id:2, initials:'PK', name:'Priya Krishnan', email:'priya@sentinel.io',  role:'Analyst', status:'Online',  last:'5m ago'   },
  { id:3, initials:'RN', name:'Rahul Nair',     email:'rahul@sentinel.io',  role:'Analyst', status:'Offline', last:'2h ago'   },
  { id:4, initials:'SM', name:'Sara Mehta',     email:'sara@sentinel.io',   role:'Viewer',  status:'Online',  last:'12m ago'  },
  { id:5, initials:'VR', name:'Vikram Reddy',   email:'vikram@sentinel.io', role:'Analyst', status:'Offline', last:'1d ago'   },
]

// ── AUTONOMOUS ACTIONS ──
export const MOCK_ACTIONS = [
  { icon:'🚫', title:'IP Blocked',         detail:'185.220.101.47 — SSH brute force',        time:'2m ago',  status:'EXECUTED',  type:'danger' },
  { icon:'🔒', title:'Session Terminated', detail:'Honeypot session 4f9a — 45.95.147.22',    time:'8m ago',  status:'EXECUTED',  type:'danger' },
  { icon:'⚠',  title:'Alert Escalated',    detail:'Critical threshold — Tier 1 notified',    time:'15m ago', status:'ESCALATED', type:'warn'   },
  { icon:'🛡',  title:'Endpoint Isolated',  detail:'ENDPOINT-14 quarantined — malware beacon',time:'22m ago', status:'ISOLATED',  type:'warn'   },
]

// ── CHART DATA ──
export const CHART_HOURS = Array.from({length:24},(_,i)=>`${String(i).padStart(2,'0')}:00`)
export const CHART_THREATS_24H = [2,1,3,8,14,22,18,12,9,16,24,31,28,22,19,35,47,38,29,22,18,14,10,7]
export const CHART_DAYS = ['Mon','Tue','Wed','Thu','Fri','Sat','Sun']
export const CHART_VECTORS = {
  'Brute Force': [12,18,14,22,19,8,15],
  'SQL Injection':[6,9,11,7,13,4,8],
  'Port Scan':   [20,15,25,18,22,12,19],
  'DDoS':        [4,7,3,12,8,2,5],
  'Malware':     [3,5,4,6,7,2,4],
}
export const CHART_ML_CATEGORIES = ['Brute Force','SQL Injection','DDoS','Port Scan','Malware','XSS','Ransomware']
export const CHART_ML_PRECISION =  [0.98,0.95,0.97,0.99,0.93,0.91,0.96]
export const CHART_ML_RECALL =     [0.96,0.92,0.95,0.97,0.89,0.88,0.93]
export const CHART_CATEGORY_COUNTS=[2341,1872,1204,3102,891,734,679]
export const CHART_CMD_FREQ = {
  labels:['wget','cat /etc/passwd','uname -a','ls -la','id','whoami','ps aux','netstat','curl','chmod'],
  data:  [45,38,31,28,24,22,18,16,14,11],
}
