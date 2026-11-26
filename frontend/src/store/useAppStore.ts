import { useState } from 'react'

export interface AppNotification {
  id: string
  type: 'info' | 'success' | 'error'
  message: string
}

export function useNotificationQueue() {
  const [notifications, setNotifications] = useState<AppNotification[]>([])

  const notify = (type: AppNotification['type'], message: string) => {
    const id = `${Date.now()}-${Math.random().toString(36).slice(2, 7)}`
    setNotifications((prev) => [...prev, { id, type, message }])
    window.setTimeout(() => {
      setNotifications((prev) => prev.filter((n) => n.id !== id))
    }, 5000)
  }

  const dismiss = (id: string) => {
    setNotifications((prev) => prev.filter((n) => n.id !== id))
  }

  return { notifications, notify, dismiss }
}
