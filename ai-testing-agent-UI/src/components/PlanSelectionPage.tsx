import { useState, useEffect } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Sparkles, Zap, Loader2 } from 'lucide-react'
import { useTenantStatus } from '../contexts/TenantStatusContext'
import { TEST_PLAN_API_BASE_URL } from '../config'

interface BillingStatusResponse {
  ok: boolean
  tenant_id?: string
  plan_tier?: string
  status?: string
  current_period_start?: string | null
  current_period_end?: string | null
  cancel_at_period_end?: boolean
  error?: string
}

export function PlanSelectionPage() {
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const { bootstrapStatus, refreshTenantStatus } = useTenantStatus()
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [isPolling, setIsPolling] = useState(false)

  const handlePlanSelect = async (plan: 'trial') => {
    setIsLoading(true)
    setError(null)

    try {
      // Get tenant_id from user data
      const userStr = localStorage.getItem('user')
      if (!userStr) {
        setError('User not found. Please log in again.')
        navigate('/login', { replace: true })
        return
      }

      const user = JSON.parse(userStr)
      const tenantId = user.tenant_id

      if (!tenantId) {
        setError('Tenant not found. Please restart onboarding.')
        navigate('/onboarding/tenant', { replace: true })
        return
      }

      // Call subscription update endpoint (only for trial/free)
      const response = await fetch(
        `${TEST_PLAN_API_BASE_URL}/api/v1/tenants/${tenantId}/subscription`,
        {
          method: 'PATCH',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          },
          body: JSON.stringify({ plan }),
        }
      )

      if (!response.ok) {
        let errorMessage = 'Failed to set subscription plan'
        try {
          const errorData = await response.json()
          errorMessage = errorData.detail || errorData.message || errorMessage
        } catch {
          errorMessage = response.statusText || `Server returned ${response.status}`
        }
        setError(errorMessage)
        return
      }

      // Refresh tenant status
      try {
        await refreshTenantStatus()
      } catch (refreshError) {
        console.error('Failed to refresh tenant status:', refreshError)
      }

      // Navigate based on Jira configuration status
      if (bootstrapStatus && (!bootstrapStatus.jira.configured || !bootstrapStatus.jira.is_active)) {
        navigate('/onboarding/jira', { replace: true })
      } else {
        navigate('/onboarding/first-run', { replace: true })
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred')
    } finally {
      setIsLoading(false)
    }
  }

  // Handle return from Stripe checkout
  useEffect(() => {
    const canceled = searchParams.get('canceled')
    const success = searchParams.get('success')

    if (canceled === '1') {
      setError('Checkout canceled')
      // Clean up URL
      navigate('/onboarding/plan', { replace: true })
      return
    }

    if (success === '1') {
      // Poll billing status until active
      setIsPolling(true)
      pollBillingStatus()
    }
  }, [searchParams, navigate])

  const pollBillingStatus = async (attempt = 0, maxAttempts = 15) => {
    try {
      const token = localStorage.getItem('access_token')
      if (!token) {
        setError('Authentication required. Please log in again.')
        navigate('/login', { replace: true })
        return
      }

      const response = await fetch(
        `${TEST_PLAN_API_BASE_URL}/api/v1/billing/status`,
        {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        }
      )

      if (!response.ok) {
        if (attempt < maxAttempts) {
          // Retry after 1 second
          setTimeout(() => pollBillingStatus(attempt + 1, maxAttempts), 1000)
          return
        } else {
          setError('Payment pending. Please refresh in a moment.')
          setIsPolling(false)
          return
        }
      }

      const data: BillingStatusResponse = await response.json()

      if (data.ok && data.status === 'active') {
        // Payment successful, proceed to next step
        setIsPolling(false)
        // Refresh tenant status
        try {
          await refreshTenantStatus()
        } catch (refreshError) {
          console.error('Failed to refresh tenant status:', refreshError)
        }
        // Navigate based on Jira configuration
        if (bootstrapStatus && (!bootstrapStatus.jira.configured || !bootstrapStatus.jira.is_active)) {
          navigate('/onboarding/jira', { replace: true })
        } else {
          navigate('/onboarding/first-run', { replace: true })
        }
      } else if (attempt < maxAttempts) {
        // Status not active yet, retry
        setTimeout(() => pollBillingStatus(attempt + 1, maxAttempts), 1000)
      } else {
        setError('Payment pending. Please refresh in a moment.')
        setIsPolling(false)
      }
    } catch (err) {
      console.error('Error polling billing status:', err)
      if (attempt < maxAttempts) {
        setTimeout(() => pollBillingStatus(attempt + 1, maxAttempts), 1000)
      } else {
        setError('Payment pending. Please refresh in a moment.')
        setIsPolling(false)
      }
    }
  }

  const handleTrialContinue = () => {
    handlePlanSelect('trial')
  }

  const handleIndividualContinue = async () => {
    setIsLoading(true)
    setError(null)

    try {
      const token = localStorage.getItem('access_token')
      if (!token) {
        setError('Authentication required. Please log in again.')
        navigate('/login', { replace: true })
        return
      }

      // Call checkout-session endpoint
      const response = await fetch(
        `${TEST_PLAN_API_BASE_URL}/api/v1/billing/checkout-session`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify({ plan_tier: 'user' }),
        }
      )

      if (!response.ok) {
        let errorMessage = 'Failed to create checkout session'
        try {
          const errorData = await response.json()
          errorMessage = errorData.error || errorData.detail || errorData.message || errorMessage
        } catch {
          errorMessage = response.statusText || `Server returned ${response.status}`
        }
        setError(errorMessage)
        return
      }

      const data = await response.json()
      if (data.ok && data.url) {
        // Redirect to Stripe checkout
        window.location.href = data.url
      } else {
        setError('Failed to get checkout URL')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred')
    } finally {
      setIsLoading(false)
    }
  }

  const handleTeamContinue = async () => {
    setIsLoading(true)
    setError(null)

    try {
      const token = localStorage.getItem('access_token')
      if (!token) {
        setError('Authentication required. Please log in again.')
        navigate('/login', { replace: true })
        return
      }

      // Call checkout-session endpoint
      const response = await fetch(
        `${TEST_PLAN_API_BASE_URL}/api/v1/billing/checkout-session`,
        {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${token}`,
          },
          body: JSON.stringify({ plan_tier: 'team' }),
        }
      )

      if (!response.ok) {
        let errorMessage = 'Failed to create checkout session'
        try {
          const errorData = await response.json()
          errorMessage = errorData.error || errorData.detail || errorData.message || errorMessage
        } catch {
          errorMessage = response.statusText || `Server returned ${response.status}`
        }
        setError(errorMessage)
        return
      }

      const data = await response.json()
      if (data.ok && data.url) {
        // Redirect to Stripe checkout
        window.location.href = data.url
      } else {
        setError('Failed to get checkout URL')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-2xl border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
        <CardHeader>
          <CardTitle className="text-2xl">Choose your plan</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {/* Trial Option */}
            <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
              <CardContent className="p-6 space-y-4">
                <div className="flex items-center gap-3">
                  <Sparkles className="h-6 w-6 text-foreground/80" />
                  <div>
                    <h3 className="text-lg font-semibold">Trial</h3>
                    <span className="text-xs text-primary">Recommended</span>
                  </div>
                </div>
                <p className="text-sm text-foreground/70">
                  3 runs each: Requirements, Test Plan, Jira Writeback
                </p>
                <Button
                  onClick={handleTrialContinue}
                  disabled={isLoading || isPolling}
                  className="w-full"
                >
                  {isLoading ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      Setting up...
                    </>
                  ) : (
                    'Start Trial'
                  )}
                </Button>
              </CardContent>
            </Card>

            {/* Individual Option */}
            <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
              <CardContent className="p-6 space-y-4">
                <div className="flex items-center gap-3">
                  <Zap className="h-6 w-6 text-foreground/80" />
                  <h3 className="text-lg font-semibold">Individual</h3>
                </div>
                <p className="text-sm text-foreground/70">
                  Personal plan with full access
                </p>
                <Button
                  onClick={handleIndividualContinue}
                  disabled={isLoading || isPolling}
                  variant="outline"
                  className="w-full"
                >
                  {isLoading || isPolling ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      {isPolling ? 'Processing payment...' : 'Setting up...'}
                    </>
                  ) : (
                    'Select Individual'
                  )}
                </Button>
              </CardContent>
            </Card>

            {/* Team Option */}
            <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
              <CardContent className="p-6 space-y-4">
                <div className="flex items-center gap-3">
                  <Zap className="h-6 w-6 text-foreground/80" />
                  <h3 className="text-lg font-semibold">Team</h3>
                </div>
                <p className="text-sm text-foreground/70">
                  Team collaboration features
                </p>
                <Button
                  onClick={handleTeamContinue}
                  disabled={isLoading || isPolling}
                  variant="outline"
                  className="w-full"
                >
                  {isLoading || isPolling ? (
                    <>
                      <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                      {isPolling ? 'Processing payment...' : 'Setting up...'}
                    </>
                  ) : (
                    'Select Team'
                  )}
                </Button>
              </CardContent>
            </Card>
          </div>
          {error && (
            <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-md mt-4">
              <p className="text-sm text-destructive">{error}</p>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
