import { useMemo } from 'react'
import { useAuth } from './useAuth'

const DEFAULT_ROLE_PERMISSIONS = {
  admin: [
    'threats:read', 'threats:write', 'threats:block', 'threats:delete', 'threats:triage',
    'containment:manage', 'containment:read',
    'honeypot:read', 'honeypot:read_raw', 'honeypot:write',
    'campaigns:read', 'campaigns:read_raw',
    'alerts:read', 'alerts:write', 'alerts:delete',
    'ai:read', 'ai:analyze', 'ai:verify', 'ai:train',
    'users:manage', 'users:read',
    'settings:read', 'settings:write',
    'audit:read',
    'system:telemetry_full',
  ],
  analyst: [
    'threats:read', 'threats:write', 'threats:block', 'threats:triage',
    'containment:manage', 'containment:read',
    'honeypot:read', 'honeypot:read_raw', 'honeypot:write',
    'campaigns:read', 'campaigns:read_raw',
    'alerts:read',
    'ai:read', 'ai:analyze', 'ai:verify', 'ai:train',
    'settings:read',
    'system:telemetry_full',
  ],
  viewer: [
    'threats:read',
    'containment:read',
    'honeypot:read',
    'campaigns:read',
    'alerts:read',
    'ai:read',
  ],
}

export function usePermission() {
  const { user } = useAuth()

  const permissions = useMemo(() => {
    if (!user) return []
    if (Array.isArray(user.permissions) && user.permissions.length > 0) {
      return user.permissions
    }
    const role = (user.role || 'viewer').toLowerCase()
    return DEFAULT_ROLE_PERMISSIONS[role] || []
  }, [user])

  const hasPermission = (permission) => {
    if (!permission) return false
    return permissions.includes(permission)
  }

  const hasAnyPermission = (perms = []) => {
    if (!Array.isArray(perms) || perms.length === 0) return false
    return perms.some((p) => permissions.includes(p))
  }

  const hasAllPermissions = (perms = []) => {
    if (!Array.isArray(perms) || perms.length === 0) return true
    return perms.every((p) => permissions.includes(p))
  }

  return {
    permissions,
    hasPermission,
    hasAnyPermission,
    hasAllPermissions,
    role: user?.role || 'viewer',
  }
}
