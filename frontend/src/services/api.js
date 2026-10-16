import axios from 'axios'
import { authSession } from './authSession.js'
import { installAuthInterceptors } from './authInterceptors.js'
const api = axios.create({ baseURL: import.meta.env.VITE_API_BASE_URL || '/api', timeout: 10000, withCredentials: true })
installAuthInterceptors(api, authSession)
export const authAPI = {
  login: async data => ({ data: await authSession.login(data) }),
  register: async data => ({ data: await authSession.register(data) }),
  me: () => api.get('/auth/me'),
  updatePassword: async data => {
    // Password mutations share the cookie/CSRF lock with refresh/logout.
    const result = await authSession.updatePassword(data)
    return { data: result }
  },
}

export const threatAPI = {
  list:        (params)   => api.get('/threats', { params }),
  get:         (id)       => api.get(`/threats/${id}`),
  create:      (data)     => api.post('/threats', data),
  update:      (id, data) => api.put(`/threats/${id}`, data),
  delete:      (id)       => api.delete(`/threats/${id}`),
  blockIP:     (id)       => api.post(`/threats/${id}/block`),
  analytics:   ()         => api.get('/threats/analytics/summary'),
  vectorTrend: (days = 7) => api.get('/threats/vector-trend', { params: { days } }),
  recent:      (limit=10) => api.get('/threats/recent', { params: { limit } }),
  getSettings:     ()       => api.get('/threats/settings'),
  updateSettings:  (data)   => api.post('/threats/settings', data),
  getBlockedIPs:   ()       => api.get('/threats/blocked-ips'),
  blockIPManual:   (data)   => api.post('/threats/block-ip', data),
  unblockIPManual: (data)   => api.post('/threats/unblock-ip', data),
}

export const containmentAPI = {
  getStatus: () => api.get('/containment/status'),
  listActions: (params) => api.get('/containment/actions', { params }),
  getAction: (id) => api.get(`/containment/actions/${id}`),
  requestAction: (data) => api.post('/containment/actions', data),
  rollbackAction: (id, data) => api.post(`/containment/actions/${id}/rollback`, data),
}

export const honeypotAPI = {
  sessions:     (params)  => api.get('/honeypot/sessions', { params }),
  getSession:   (id)      => api.get(`/honeypot/sessions/${id}`),
  createSession:(data)    => api.post('/honeypot/sessions', data),
  addCommands:  (id, cmds)=> api.post(`/honeypot/sessions/${id}/commands`, { commands: cmds }),
  closeSession: (id)      => api.put(`/honeypot/sessions/${id}/close`),
  analytics:    ()        => api.get('/honeypot/analytics'),
  nodes:        ()        => api.get('/honeypot/nodes'),
}

export const alertAPI = {
  list:        (params) => api.get('/alerts', { params }),
  unreadCount: ()       => api.get('/alerts/unread-count'),
  markRead:    (id)     => api.put(`/alerts/${id}/read`),
  markAllRead: ()       => api.put('/alerts/mark-all-read'),
}

export const userAPI = {
  create: async data => ({ data: await authSession.provision(data) }),
  list:   (params)    => api.get('/users', { params }),
  get:    (id)        => api.get(`/users/${id}`),
  update: (id, data)  => api.put(`/users/${id}`, data),
  delete: (id)        => api.delete(`/users/${id}`),
  stats:  ()          => api.get('/users/stats'),
}

export const CANONICAL_CLASSES = [
  'BENIGN',
  'SSH Brute Force',
  'SQL Injection',
  'Port Scan',
  'DDoS',
  'RCE Attempt',
  'XSS Attempt',
  'Malware Beacon',
  'Credential Stuffing',
  'Lateral Movement',
  'Data Exfiltration',
]

export const aiAPI = {
  health:     ()       => api.get('/ai/engine/health'),
  modelInfo:  ()       => api.get('/ai/engine/model-info'),
  engineStats:()       => api.get('/ai/engine/stats'),
  predictions:(params) => api.get('/ai/predictions', { params }),
  stats:      ()       => api.get('/ai/stats'),
  verify:     (id,cls) => api.put(`/ai/predictions/${id}/verify`, { actualClass: cls }),
}

export const campaignAPI = {
  list: () => api.get('/campaigns'),
  get: (id) => api.get(`/campaigns/${id}`),
}

export const systemAPI = {
  health: () => api.get('/system/health'),
}

export const trainingSampleAPI = {
  list:     (params) => api.get('/training-samples', { params }),
  get:      (id)     => api.get(`/training-samples/${id}`),
  ingest:   (id)     => api.post(`/training-samples/ingest/${id}`),
  validate: (id)     => api.post(`/training-samples/${id}/validate`),
  reject:   (id, reason) => api.post(`/training-samples/${id}/reject`, { reason }),
}

export default api
