import { Link } from 'react-router-dom'
import { AlertCircle } from 'lucide-react'
import { useTenantStatus } from '../contexts/TenantStatusContext'

export function JiraNotConfiguredBanner() {
  const { bootstrapStatus } = useTenantStatus()

  // Show banner if Jira is not fully configured (any of the three required fields are missing/empty)
  // The backend now checks that jira_base_url, jira_user_email, and credentials_ciphertext are all non-NULL and non-empty
  // Show banner if: bootstrapStatus exists, jira object exists, and configured is explicitly false
  // Note: configured will be false if integration doesn't exist OR if any of the 3 fields are NULL/empty
  const shouldShow = bootstrapStatus?.jira && bootstrapStatus.jira.configured === false

  // Debug logging (remove in production if needed)
  if (import.meta.env.NODE_ENV === 'development') {
    console.log('[JiraNotConfiguredBanner] bootstrapStatus:', bootstrapStatus)
    console.log('[JiraNotConfiguredBanner] jira configured:', bootstrapStatus?.jira?.configured)
    console.log('[JiraNotConfiguredBanner] shouldShow:', shouldShow)
  }

  if (!shouldShow) {
    return null
  }

  return (
    <div className="mb-4 p-3 bg-destructive/10 border border-destructive/20 rounded-md">
      <div className="flex items-start gap-3">
        <AlertCircle className="h-5 w-5 text-destructive flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          <p className="text-sm text-destructive font-medium">
            Jira not connected. Test Plan, Jira Writeback, and Jira Scope Ingest require Jira credentials.
          </p>
        </div>
        <Link
          to="/onboarding/jira"
          className="text-sm text-destructive hover:text-destructive/80 underline font-medium whitespace-nowrap"
        >
          Connect Jira
        </Link>
      </div>
    </div>
  )
}
