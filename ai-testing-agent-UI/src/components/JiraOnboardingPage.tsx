import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Settings } from 'lucide-react'
import { refreshTenantStatus } from '../services/api'
import { useTenantStatus } from '../contexts/TenantStatusContext'
import { TEST_PLAN_API_BASE_URL } from '../config'

export function JiraOnboardingPage() {
  const [jiraBaseUrl, setJiraBaseUrl] = useState('')
  const [jiraEmail, setJiraEmail] = useState('')
  const [jiraApiToken, setJiraApiToken] = useState('')
  const [error, setError] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const navigate = useNavigate()
  const { refreshBootstrapStatus } = useTenantStatus()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    // Client-side validation
    if (!jiraBaseUrl || !jiraEmail || !jiraApiToken) {
      setError('Please fill in all required fields')
      return
    }

    setIsLoading(true)

    try {
      let response: Response
      try {
        response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/integrations/jira`, {
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${localStorage.getItem('access_token')}`,
          },
          body: JSON.stringify({
            jira_base_url: jiraBaseUrl,
            jira_user_email: jiraEmail,
            jira_api_token: jiraApiToken,
          }),
        })
      } catch (fetchError) {
        // Network error
        if (fetchError instanceof TypeError && fetchError.message.includes('Failed to fetch')) {
          setError(`Cannot connect to backend at ${TEST_PLAN_API_BASE_URL}. Please ensure the backend server is running.`)
        } else {
          setError(fetchError instanceof Error ? fetchError.message : 'Network error: Failed to connect to server')
        }
        return
      }

      if (!response.ok) {
        // Parse error response
        let errorMessage = 'Failed to save Jira connection'
        try {
          const errorData = await response.json()
          errorMessage = errorData.detail || errorData.message || errorData.error || errorMessage
          
          // Ensure we never show "[object Object]"
          if (typeof errorMessage !== 'string') {
            errorMessage = JSON.stringify(errorMessage)
          }
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

      if (!data.ok) {
        setError('Failed to save Jira connection')
        return
      }

      // Refresh tenant status and bootstrap status
      refreshTenantStatus()
      await refreshBootstrapStatus()

      // Navigate to first-run page
      navigate('/onboarding/first-run', { replace: true })
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
            <Settings className="h-6 w-6 text-foreground/80" />
            <CardTitle>Connect Jira</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <label htmlFor="jiraBaseUrl" className="text-sm font-medium text-foreground">
                Jira Base URL <span className="text-destructive">*</span>
              </label>
              <input
                id="jiraBaseUrl"
                type="url"
                value={jiraBaseUrl}
                onChange={(e) => setJiraBaseUrl(e.target.value)}
                required
                disabled={isLoading}
                className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50"
                placeholder="https://yourdomain.atlassian.net"
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="jiraEmail" className="text-sm font-medium text-foreground">
                Jira Email <span className="text-destructive">*</span>
              </label>
              <input
                id="jiraEmail"
                type="email"
                value={jiraEmail}
                onChange={(e) => setJiraEmail(e.target.value)}
                required
                disabled={isLoading}
                className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50"
                placeholder="user@company.com"
              />
            </div>
            <div className="space-y-2">
              <label htmlFor="jiraApiToken" className="text-sm font-medium text-foreground">
                Jira API Token <span className="text-destructive">*</span>
              </label>
              <input
                id="jiraApiToken"
                type="password"
                value={jiraApiToken}
                onChange={(e) => setJiraApiToken(e.target.value)}
                required
                disabled={isLoading}
                className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50"
                placeholder="Enter your Jira API token"
              />
            </div>
            <p className="text-xs text-foreground/60">
              We use this to read projects and create tickets.
            </p>
            {error && (
              <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                <p className="text-sm text-destructive">{error}</p>
              </div>
            )}
            <Button
              type="submit"
              disabled={isLoading || !jiraBaseUrl || !jiraEmail || !jiraApiToken}
              className="w-full"
            >
              {isLoading ? 'Saving...' : 'Save Jira Connection'}
            </Button>
            <div className="text-center text-sm text-foreground/70">
              <Link to="/onboarding/first-run" className="text-primary hover:underline">
                Skip for now — I'll connect Jira later
              </Link>
            </div>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
