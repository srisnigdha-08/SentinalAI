'use strict'

const PERMISSIONS = {
  // Threats
  THREATS_READ: 'threats:read',
  THREATS_WRITE: 'threats:write',
  THREATS_BLOCK: 'threats:block',
  THREATS_DELETE: 'threats:delete',
  THREATS_TRIAGE: 'threats:triage',

  // Containment
  CONTAINMENT_READ: 'containment:read',
  CONTAINMENT_MANAGE: 'containment:manage',

  // Honeypot
  HONEYPOT_READ: 'honeypot:read',
  HONEYPOT_READ_RAW: 'honeypot:read_raw',
  HONEYPOT_WRITE: 'honeypot:write',

  // Campaigns
  CAMPAIGNS_READ: 'campaigns:read',
  CAMPAIGNS_READ_RAW: 'campaigns:read_raw',

  // Alerts
  ALERTS_READ: 'alerts:read',
  ALERTS_WRITE: 'alerts:write',
  ALERTS_DELETE: 'alerts:delete',

  // AI Engine
  AI_READ: 'ai:read',
  AI_ANALYZE: 'ai:analyze',
  AI_VERIFY: 'ai:verify',
  AI_TRAIN: 'ai:train',

  // Users & Access Control
  USERS_MANAGE: 'users:manage',
  USERS_READ: 'users:read',

  // Settings
  SETTINGS_READ: 'settings:read',
  SETTINGS_WRITE: 'settings:write',

  // Audit Logs
  AUDIT_READ: 'audit:read',

  // System
  SYSTEM_TELEMETRY_FULL: 'system:telemetry_full',
}

const ROLE_PERMISSIONS = {
  admin: Object.values(PERMISSIONS),
  analyst: [
    PERMISSIONS.THREATS_READ,
    PERMISSIONS.THREATS_WRITE,
    PERMISSIONS.THREATS_BLOCK,
    PERMISSIONS.THREATS_TRIAGE,
    PERMISSIONS.CONTAINMENT_READ,
    PERMISSIONS.CONTAINMENT_MANAGE,
    PERMISSIONS.HONEYPOT_READ,
    PERMISSIONS.HONEYPOT_READ_RAW,
    PERMISSIONS.HONEYPOT_WRITE,
    PERMISSIONS.CAMPAIGNS_READ,
    PERMISSIONS.CAMPAIGNS_READ_RAW,
    PERMISSIONS.ALERTS_READ,
    PERMISSIONS.AI_READ,
    PERMISSIONS.AI_ANALYZE,
    PERMISSIONS.AI_VERIFY,
    PERMISSIONS.AI_TRAIN,
    PERMISSIONS.SETTINGS_READ,
    PERMISSIONS.SYSTEM_TELEMETRY_FULL,
  ],
  viewer: [
    PERMISSIONS.THREATS_READ,
    PERMISSIONS.CONTAINMENT_READ,
    PERMISSIONS.HONEYPOT_READ,
    PERMISSIONS.CAMPAIGNS_READ,
    PERMISSIONS.ALERTS_READ,
    PERMISSIONS.AI_READ,
  ],
}

function hasPermission(role, permission) {
  if (!role || typeof role !== 'string') return false
  const perms = ROLE_PERMISSIONS[role.toLowerCase()]
  if (!perms) return false
  return perms.includes(permission)
}

function getPermissions(role) {
  if (!role || typeof role !== 'string') return []
  return ROLE_PERMISSIONS[role.toLowerCase()] || []
}

module.exports = {
  PERMISSIONS,
  ROLE_PERMISSIONS,
  hasPermission,
  getPermissions,
}
