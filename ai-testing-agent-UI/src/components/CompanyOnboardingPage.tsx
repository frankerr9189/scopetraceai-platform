import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Building2, Check, X, Loader2 } from 'lucide-react'
import { useTenantStatus } from '../contexts/TenantStatusContext'
import { TEST_PLAN_API_BASE_URL } from '../config'

interface SlugCheckResponse {
  available: boolean
  slug: string
  suggestions: string[]
}

export function CompanyOnboardingPage() {
  const [companyName, setCompanyName] = useState('')
  const [selectedSlug, setSelectedSlug] = useState<string | null>(null)
  const [slugCheck, setSlugCheck] = useState<SlugCheckResponse | null>(null)
  const [isCheckingSlug, setIsCheckingSlug] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const navigate = useNavigate()
  const { resetTenantContext, refreshTenantStatus, refreshBootstrapStatus } = useTenantStatus()

  // Debounced slug availability check
  useEffect(() => {
    if (!companyName.trim()) {
      setSlugCheck(null)
      setSelectedSlug(null)
      return
    }

    const timeoutId = setTimeout(() => {
      checkSlugAvailability(companyName)
    }, 400) // 400ms debounce

    return () => clearTimeout(timeoutId)
  }, [companyName])

  const checkSlugAvailability = async (name: string) => {
    if (!name.trim()) {
      setSlugCheck(null)
      return
    }

    setIsCheckingSlug(true)
    try {
      const response = await fetch(
        `${TEST_PLAN_API_BASE_URL}/api/v1/tenants/check-slug?name=${encodeURIComponent(name)}`,
        {
          method: 'GET',
          // No auth required for public slug check
        }
      )

      if (response.ok) {
        const data: SlugCheckResponse = await response.json()
        setSlugCheck(data)
        // Auto-select base slug if available
        if (data.available) {
          setSelectedSlug(data.slug)
        } else {
          // Pre-select first suggestion if base is taken
          setSelectedSlug(data.suggestions[0] || null)
        }
      } else {
        setSlugCheck(null)
      }
    } catch (err) {
      // Silently fail - don't block user input
      setSlugCheck(null)
    } finally {
      setIsCheckingSlug(false)
    }
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    if (!companyName.trim()) {
      setError('Company name is required')
      return
    }

    if (!slugCheck || !slugCheck.available && !selectedSlug) {
      setError('Please wait for availability check to complete')
      return
    }

    setIsLoading(true)

    try {
      const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/onboarding/company`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
        },
        body: JSON.stringify({
          company_name: companyName,
        }),
      })

      if (!response.ok) {
        let errorMessage = 'Failed to create company'
        try {
          const errorData = await response.json()
          
          // Handle slug conflict with suggestions
          if (response.status === 409 && errorData.suggestions) {
            setSlugCheck({
              available: false,
              slug: errorData.slug,
              suggestions: errorData.suggestions
            })
            setSelectedSlug(errorData.suggestions[0] || null)
            errorMessage = 'Company name is already taken. Please select a suggestion or try a different name.'
          } else {
            errorMessage = errorData.detail || errorData.message || errorData.error || errorMessage
          }
        } catch {
          errorMessage = response.statusText || `Server returned ${response.status}`
        }
        setError(errorMessage)
        return
      }

      const data = await response.json()

      // Update access token if provided (new JWT with tenant_id)
      if (data.access_token) {
        localStorage.setItem('access_token', data.access_token)
      }

      // Update user in localStorage
      const userStr = localStorage.getItem('user')
      if (userStr) {
        try {
          const user = JSON.parse(userStr)
          user.tenant_id = data.tenant_id
          user.tenant_name = data.tenant_name
          localStorage.setItem('user', JSON.stringify(user))
        } catch {
          // Ignore parse errors
        }
      }

      // Reset tenant context and refresh
      resetTenantContext()
      window.dispatchEvent(new CustomEvent('auth-state-changed'))

      try {
        await refreshTenantStatus()
        await refreshBootstrapStatus()
      } catch (refreshError) {
        console.error('Failed to refresh tenant status:', refreshError)
      }

      // Navigate to next onboarding step (Jira or plan selection)
      navigate('/onboarding/jira', { replace: true })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An unexpected error occurred')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
        <CardHeader>
          <div className="flex items-center gap-3">
            <Building2 className="h-6 w-6 text-foreground/80" />
            <CardTitle>Create Your Company</CardTitle>
          </div>
          <p className="text-sm text-muted-foreground mt-2">
            Set up your workspace to get started
          </p>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="companyName" className="text-sm font-medium text-foreground">
                Company Name <span className="text-destructive">*</span>
              </label>
              <input
                id="companyName"
                type="text"
                value={companyName}
                onChange={(e) => setCompanyName(e.target.value)}
                required
                disabled={isLoading}
                className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50"
                placeholder="Enter your company name"
              />
              
              {/* Availability indicator */}
              {companyName.trim() && (
                <div className="flex items-center gap-2 text-sm">
                  {isCheckingSlug ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                      <span className="text-muted-foreground">Checking availability...</span>
                    </>
                  ) : slugCheck ? (
                    <>
                      {slugCheck.available ? (
                        <>
                          <Check className="h-4 w-4 text-green-500" />
                          <span className="text-green-600 dark:text-green-400">Available</span>
                          <span className="text-xs text-muted-foreground ml-2">
                            ({slugCheck.slug})
                          </span>
                        </>
                      ) : (
                        <>
                          <X className="h-4 w-4 text-destructive" />
                          <span className="text-destructive">Name already taken</span>
                        </>
                      )}
                    </>
                  ) : null}
                </div>
              )}

              {/* Suggestions */}
              {slugCheck && !slugCheck.available && slugCheck.suggestions.length > 0 && (
                <div className="space-y-2">
                  <p className="text-xs text-muted-foreground">Suggested alternatives:</p>
                  <div className="flex flex-wrap gap-2">
                    {slugCheck.suggestions.map((suggestion) => (
                      <button
                        key={suggestion}
                        type="button"
                        onClick={() => {
                          setSelectedSlug(suggestion)
                          // Update company name to match suggestion (user can edit)
                          const baseName = companyName.trim()
                          setCompanyName(baseName)
                        }}
                        className={`px-3 py-1 text-xs rounded-md border transition-colors ${
                          selectedSlug === suggestion
                            ? 'bg-primary text-primary-foreground border-primary'
                            : 'bg-background border-input hover:bg-secondary'
                        }`}
                      >
                        {suggestion}
                      </button>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {error && (
              <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                <p className="text-sm text-destructive">{error}</p>
              </div>
            )}

            <Button
              type="submit"
              disabled={isLoading || !companyName.trim() || (slugCheck && !slugCheck.available && !selectedSlug) || isCheckingSlug}
              className="w-full"
            >
              {isLoading ? 'Creating Company...' : 'Create Company'}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
