import { useNavigate } from 'react-router-dom'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Rocket } from 'lucide-react'
import { useTenantStatus } from '../contexts/TenantStatusContext'
import { JiraNotConfiguredBanner } from './JiraNotConfiguredBanner'

export function FirstRunOnboardingPage() {
  const navigate = useNavigate()
  const { tenantStatus, isLoading } = useTenantStatus()

  // Determine if test plan generation is disabled
  const isTestPlanDisabled = tenantStatus
    ? (tenantStatus.subscription_status === 'Paywalled' ||
       (tenantStatus.subscription_status === 'Trial' && tenantStatus.trial_testplan_runs_remaining <= 0))
    : false

  // Determine if requirements generation is disabled
  const isRequirementsDisabled = tenantStatus
    ? (tenantStatus.subscription_status === 'Paywalled' ||
       (tenantStatus.subscription_status === 'Trial' && tenantStatus.trial_requirements_runs_remaining <= 0))
    : false

  const subscriptionStatus = tenantStatus?.subscription_status || 'Trial'
  const requirementsRemaining = tenantStatus?.trial_requirements_runs_remaining ?? 3
  const testplanRemaining = tenantStatus?.trial_testplan_runs_remaining ?? 3
  const writebackRemaining = tenantStatus?.trial_writeback_runs_remaining ?? 3

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
        <CardHeader>
          <div className="flex items-center gap-3">
            <Rocket className="h-6 w-6 text-foreground/80" />
            <CardTitle>Get Started</CardTitle>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <JiraNotConfiguredBanner />
          {/* Plan Badge and Trial Status */}
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <span className="text-sm font-medium text-foreground">Plan:</span>
              <span className={`px-2 py-1 rounded text-xs font-medium ${
                subscriptionStatus === 'Active' 
                  ? 'bg-green-500/20 text-green-400' 
                  : subscriptionStatus === 'Paywalled'
                  ? 'bg-destructive/20 text-destructive'
                  : 'bg-blue-500/20 text-blue-400'
              }`}>
                {subscriptionStatus}
              </span>
            </div>
            {subscriptionStatus === 'Trial' && (
              <div className="text-sm text-foreground/70">
                <p>Trial remaining:</p>
                <ul className="list-disc list-inside ml-2 space-y-1">
                  <li>Requirements: {requirementsRemaining}/3</li>
                  <li>Test Plans: {testplanRemaining}/3</li>
                  <li>Writebacks: {writebackRemaining}/3</li>
                </ul>
              </div>
            )}
            {subscriptionStatus === 'Paywalled' && (
              <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                <p className="text-sm text-destructive">
                  Trial complete. Activate subscription to continue.
                </p>
              </div>
            )}
          </div>

          {/* Action Buttons */}
          <div className="space-y-3">
            <Button
              onClick={() => navigate('/requirements')}
              disabled={isRequirementsDisabled || isLoading}
              className="w-full"
            >
              Generate Requirements
            </Button>
            <Button
              onClick={() => navigate('/')}
              disabled={isTestPlanDisabled || isLoading}
              className="w-full"
            >
              Generate Test Plan
            </Button>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
