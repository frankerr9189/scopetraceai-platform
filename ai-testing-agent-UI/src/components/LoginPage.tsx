import { useState } from 'react'
import { useNavigate, useLocation, Link } from 'react-router-dom'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Lock } from 'lucide-react'
import { useTenantStatus } from '../contexts/TenantStatusContext'
import { TEST_PLAN_API_BASE_URL } from '../config'

interface TenantOption {
  tenant_id: string
  tenant_name: string
  tenant_slug: string
}

export function LoginPage() {
  // Password is stored ONLY in component state (useState) - never in localStorage, sessionStorage, cookies, or global stores
  // Password is cleared from memory immediately after tenant selection for security
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [showTenantSelection, setShowTenantSelection] = useState(false)
  const [tenants, setTenants] = useState<TenantOption[]>([])
  const navigate = useNavigate()
  const location = useLocation()
  const { resetTenantContext, refreshTenantStatus, refreshBootstrapStatus } = useTenantStatus()

  const handleLoginSuccess = (data: any) => {
    const { access_token, user } = data

    if (!access_token || !user) {
      setError('Invalid response: missing access_token or user data')
      return
    }

    // Clear password from memory immediately after successful authentication for security
    setPassword('')

    // Store token and user in localStorage
    localStorage.setItem('access_token', access_token)
    localStorage.setItem('user', JSON.stringify(user))

    // CRITICAL: Reset tenant context to clear any stale data from previous session
    resetTenantContext()

    // Notify other components (e.g., Sidebar) that auth state has changed
    window.dispatchEvent(new CustomEvent('auth-state-changed'))

    // Fetch fresh tenant data BEFORE navigating
    refreshTenantStatus().then(() => {
      refreshBootstrapStatus().catch(() => {})
    }).catch(() => {})

    // Check if subscription plan is selected
    const subscriptionStatus = user.subscription_status || data.subscription_status
    
    if (subscriptionStatus === 'unselected') {
      navigate('/onboarding/plan', { replace: true })
      return
    }
    
    // Navigate to the page the user was trying to access, or default to home
    const from = (location.state as any)?.from?.pathname || (new URLSearchParams(location.search).get('from')) || '/'
    navigate(from, { replace: true })
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setIsLoading(true)

    if (!email.trim() || !password) {
      setError('Email and password are required')
      setIsLoading(false)
      return
    }

    try {
      let response: Response
      try {
        response = await fetch(`${TEST_PLAN_API_BASE_URL}/auth/login`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
          },
          body: JSON.stringify({ 
            email, 
            password 
          }),
        })
      } catch (fetchError) {
        // Network error (backend not running, CORS, etc.)
        if (fetchError instanceof TypeError && fetchError.message.includes('Failed to fetch')) {
          setError(`Cannot connect to backend at ${TEST_PLAN_API_BASE_URL}. Please ensure the backend server is running.`)
        } else {
          setError(fetchError instanceof Error ? fetchError.message : 'Network error: Failed to connect to server')
        }
        return
      }

      if (!response.ok) {
        // Handle 409 - Multiple tenants found
        if (response.status === 409) {
          try {
            const errorData = await response.json()
            if (errorData.code === 'TENANT_SELECTION_REQUIRED' && errorData.tenants) {
              setTenants(errorData.tenants)
              setShowTenantSelection(true)
              return
            }
          } catch {
            // Fall through to generic error
          }
        }

        // Parse error response
        let errorMessage = 'Login failed'
        try {
          const errorData = await response.json()
          
          // Handle specific inactive user/tenant errors
          if (response.status === 403) {
            if (errorData.code === 'USER_INACTIVE') {
              errorMessage = errorData.detail || 'Your account is inactive. Contact hello@scopetraceai.com'
              setError(errorMessage)
              return
            }
            if (errorData.code === 'TENANT_INACTIVE') {
              errorMessage = errorData.detail || 'Workspace is inactive. Contact hello@scopetraceai.com'
              setError(errorMessage)
              return
            }
          }
          
          // Generic error handling
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

      handleLoginSuccess(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred')
      localStorage.removeItem('access_token')
      localStorage.removeItem('user')
    } finally {
      setIsLoading(false)
    }
  }

  const handleTenantSelect = async (tenantId: string) => {
    setError(null)
    setIsLoading(true)

    try {
      const response = await fetch(`${TEST_PLAN_API_BASE_URL}/auth/login/tenant`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          tenant_id: tenantId,
          email,
          password
        }),
      })

      if (!response.ok) {
        // Clear password from memory immediately after failed tenant selection for security
        // User must re-enter password before retrying
        setPassword('')
        
        let errorMessage = 'Login failed'
        try {
          const errorData = await response.json()
          
          if (response.status === 403) {
            if (errorData.code === 'USER_INACTIVE') {
              errorMessage = errorData.detail || 'Your account is inactive. Contact hello@scopetraceai.com'
            } else if (errorData.code === 'TENANT_INACTIVE') {
              errorMessage = errorData.detail || 'Workspace is inactive. Contact hello@scopetraceai.com'
            } else {
              errorMessage = errorData.detail || errorData.message || errorMessage
            }
          } else {
            errorMessage = errorData.detail || errorData.message || errorMessage
          }
        } catch {
          errorMessage = response.statusText || `Server returned ${response.status}`
        }
        setError(errorMessage)
        // Reset to email/password form since password was cleared
        setShowTenantSelection(false)
        setTenants([])
        return
      }

      const data = await response.json()
      // Clear password from memory immediately after successful tenant selection for security
      setPassword('')
      handleLoginSuccess(data)
    } catch (err) {
      // Clear password from memory on error for security
      setPassword('')
      setError(err instanceof Error ? err.message : 'An unexpected error occurred')
      // Reset to email/password form since password was cleared
      setShowTenantSelection(false)
      setTenants([])
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
          {showTenantSelection ? (
            <div className="space-y-4">
              <div>
                <h3 className="text-lg font-semibold mb-2">Select your workspace</h3>
                <p className="text-sm text-muted-foreground mb-4">
                  Multiple workspaces found for this email. Please select which one to use.
                </p>
              </div>
              <div className="space-y-2">
                {tenants.map((tenant) => (
                  <button
                    key={tenant.tenant_id}
                    type="button"
                    onClick={() => handleTenantSelect(tenant.tenant_id)}
                    disabled={isLoading}
                    className="w-full p-4 text-left border border-input rounded-md hover:bg-secondary/50 focus:outline-none focus:ring-2 focus:ring-ring disabled:opacity-50 transition-colors"
                  >
                    <div className="font-medium text-foreground">{tenant.tenant_name}</div>
                    <div className="text-sm text-muted-foreground">{tenant.tenant_slug}</div>
                  </button>
                ))}
              </div>
              <Button
                type="button"
                variant="ghost"
                onClick={() => {
                  // Clear password from memory when navigating back to email/password form for security
                  setPassword('')
                  setShowTenantSelection(false)
                  setTenants([])
                  setError(null)
                }}
                disabled={isLoading}
                className="w-full"
              >
                Back
              </Button>
              {error && (
                <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                  <p className="text-sm text-destructive">{error}</p>
                </div>
              )}
            </div>
          ) : (
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
              <Link to="/forgot-password" className="text-primary hover:underline">
                Forgot password?
              </Link>
            </div>
            <div className="text-center text-sm text-foreground/70">
              <span>Don't have a workspace? </span>
              <Link to="/onboarding/tenant" className="text-primary hover:underline">
                Create Workspace
              </Link>
            </div>
          </form>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
