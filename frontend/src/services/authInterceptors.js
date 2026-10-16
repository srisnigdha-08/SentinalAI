// Keep the single-retry contract shared by the runtime client and regression tests.
export function installAuthInterceptors(api, session) {
  api.interceptors.request.use(config => {
    const token = session.getState().token
    if (token) config.headers.Authorization = `Bearer ${token}`
    return config
  })
  api.interceptors.response.use(res => res, async error => {
    const config = error.config
    if (error.response?.status === 401 && config && !config._authRetried && !config.url.includes('/auth/') && !config.skipAuthRedirect) {
      config._authRetried = true
      try {
        const token = await session.refresh()
        if (!token) throw new Error('Sign in required')
        config.headers.Authorization = `Bearer ${token}`
        return api(config)
      } catch (refreshError) {
        if ([401, 403].includes(refreshError.status) || !session.getState().token) session.clear()
        return Promise.reject(refreshError)
      }
    }
    if (error.response?.status === 401 && config?._authRetried) session.clear()
    return Promise.reject(error)
  })
}
