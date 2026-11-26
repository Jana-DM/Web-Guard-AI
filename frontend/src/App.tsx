import React from 'react'
import { AuthProvider } from './contexts/AuthContext'
import { AppRoutes } from './routes/AppRoutes'

export const App: React.FC = () => (
  <AuthProvider>
    <AppRoutes />
  </AuthProvider>
)

export default App
