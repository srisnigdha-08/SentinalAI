import { createContext, useState, useEffect } from 'react'
import { authSession } from '../services/authSession.js'
export const AuthContext = createContext(null)
export function AuthProvider({ children }) {
  const [state, setState] = useState(authSession.getState())
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  useEffect(() => {
    const unsubscribe = authSession.subscribe(setState)
    if (!authSession.hasSessionHint?.()) {
      setLoading(false)
      return unsubscribe
    }
    authSession.refresh().catch(error => {
      if (![401, 403].includes(error.status)) setError('Session service unavailable. Sign in again when it is reachable.')
    }).finally(() => setLoading(false))
    return unsubscribe
  }, [])
  return <AuthContext.Provider value={{ ...state, loading, error,
    login: credentials => authSession.login(credentials), logout: () => authSession.logout(),
    logoutAll: () => authSession.logout(true),
    updatePassword: data => authSession.updatePassword(data) }}>
    {!loading && children}
  </AuthContext.Provider>
}
