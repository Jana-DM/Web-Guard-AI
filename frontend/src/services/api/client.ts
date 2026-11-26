const API_BASE = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000/api/v1'

export function getStoredToken(): string | null {
  return localStorage.getItem('wg_access_token')
}

export function setStoredTokens(access: string, refresh: string): void {
  localStorage.setItem('wg_access_token', access)
  localStorage.setItem('wg_refresh_token', refresh)
}

export function clearStoredTokens(): void {
  localStorage.removeItem('wg_access_token')
  localStorage.removeItem('wg_refresh_token')
}

export async function apiRequest<T>(path: string, options: RequestInit = {}): Promise<T> {
  const token = getStoredToken()
  const headers = new Headers(options.headers || {})

  if (token) {
    headers.set('Authorization', `Bearer ${token}`)
  }
  if (!(options.body instanceof FormData) && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json')
  }

  const response = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers,
  })

  if (!response.ok) {
    let message = `Request failed (${response.status})`
    try {
      const errBody = await response.json()
      if (errBody?.detail) {
        message = typeof errBody.detail === 'string' ? errBody.detail : JSON.stringify(errBody.detail)
      }
    } catch {
      // ignore json parse error
    }
    throw new Error(message)
  }

  const contentType = response.headers.get('content-type') || ''
  if (contentType.includes('application/json')) {
    return (await response.json()) as T
  }
  return (await response.text()) as unknown as T
}

export { API_BASE }
