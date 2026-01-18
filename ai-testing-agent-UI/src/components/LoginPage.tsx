import { useState } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Lock } from 'lucide-react'
import { useTenantStatus } from '../contexts/TenantStatusContext'

export function LoginPage() {
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const navigate = useNavigate()
  const location = useLocation()
  const { resetTenantContext, refreshTenantStatus, refreshBootstrapStatus } = useTenantStatus()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setIsLoading(true)

    try {
      const apiBase = import.meta.env.VITE_API_BASE || import.meta.env.VITE_TEST_PLAN_API_BASE_URL || 'http://localhost:5050'
      
      let response: Response
      try {
        response = await fetch(`${apiBase}/auth/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ email, password }),
        })
      } catch (fetchError) {
        // Network error (backend not running, CORS, etc.)
        if (fetchError instanceof TypeError && fetchError.message.includes('Failed to fetch')) {
          setError(`Cannot connect to backend at ${apiBase}. Please ensure the backend server is running.`)
        } else {
          setError(fetchError instanceof Error ? fetchError.message : 'Network error: Failed to connect to server')
        }
        return
      }

      if (!response.ok) {
        // Parse error response
        let errorMessage = 'Login failed'
        try {
          const errorData = await response.json()
          errorMessage = errorData.detail || errorData.message || errorData.error || errorMessage
        } catch {
          // If JSON parsing fails, use status text
          errorMessage = response.statusText || `Server returned ${response.status}`
        }
        setError(errorMessage)
        return
      }

      // Parse success response
      let data: any
      try {
        data = await response.json()
      } catch (parseError) {
        setError('Invalid response from server')
        return
      }

      const { access_token, user } = data

      if (!access_token || !user) {
        setError('Invalid response: missing access_token or user data')
        return
      }

      // Store token and user in localStorage
      localStorage.setItem('access_token', access_token)
      localStorage.setItem('user', JSON.stringify(user))

      // CRITICAL: Reset tenant context to clear any stale data from previous session
      resetTenantContext()

      // Notify other components (e.g., Sidebar) that auth state has changed
      window.dispatchEvent(new CustomEvent('auth-state-changed'))

      // Fetch fresh tenant data BEFORE navigating
      try {
        await refreshTenantStatus()
        await refreshBootstrapStatus()
      } catch (refreshError) {
        // Log but don't block navigation - user can still proceed
        console.error('Failed to refresh tenant status after login:', refreshError)
      }

      // Navigate to the page the user was trying to access, or default to home
      const from = (location.state as any)?.from?.pathname || (new URLSearchParams(location.search).get('from')) || '/'
      navigate(from, { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred')
      localStorage.removeItem('access_token')
      localStorage.removeItem('user')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex flex-col items-center justify-center p-4">
      <div className="mb-8">
        <img 
          src="/scopetrace-horizontal.png" 
          alt="ScopeTrace AI" 
          className="h-24 w-auto"
        />
      </div>
      <Card className="w-full max-w-md border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
        <CardHeader>
          <div className="flex items-center gap-3">
            <Lock className="h-6 w-6 text-foreground/80" />
            <CardTitle>Login</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="email" className="text-sm font-medium text-foreground">
                Email <span className="text-destructive">*</span>
              </label>
              <input
                id="email"
                type="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                required
                disabled={isLoading}
                className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50"
                placeholder="Enter your email"
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="password" className="text-sm font-medium text-foreground">
                Password <span className="text-destructive">*</span>
              </label>
              <input
                id="password"
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                required
                disabled={isLoading}
                className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50"
                placeholder="Enter your password"
              />
            </div>
            {error && (
              <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                <p className="text-sm text-destructive">{error}</p>
              </div>
            )}
            <Button
              type="submit"
              disabled={isLoading || !email || !password}
              className="w-full"
            >
              {isLoading ? 'Logging in...' : 'Login'}
            </Button>
            <div className="text-center text-sm text-foreground/70">
              <span>Don't have an account? </span>
              <Link to="/register" className="text-primary hover:underline">
                Register New Account
              </Link>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
