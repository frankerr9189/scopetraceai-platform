import { useNavigate } from 'react-router-dom'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Sparkles, Zap } from 'lucide-react'
import { useTenantStatus } from '../contexts/TenantStatusContext'

export function PlanSelectionPage() {
  const navigate = useNavigate()
  const { bootstrapStatus } = useTenantStatus()

  const handleTrialContinue = () => {
    // Route based on Jira configuration status
    if (bootstrapStatus && (!bootstrapStatus.jira.configured || !bootstrapStatus.jira.is_active)) {
      navigate('/onboarding/jira', { replace: true })
    } else {
      navigate('/onboarding/first-run', { replace: true })
    }
  }

  const handleFullAccess = () => {
    navigate('/onboarding/activate', { replace: true })
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-2xl border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
        <CardHeader>
          <CardTitle className="text-2xl">Choose your plan</CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Free Trial Option */}
            <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
              <CardContent className="p-6 space-y-4">
                <div className="flex items-center gap-3">
                  <Sparkles className="h-6 w-6 text-foreground/80" />
                  <div>
                    <h3 className="text-lg font-semibold">Start Free Trial</h3>
                    <span className="text-xs text-primary">Recommended</span>
                  </div>
                </div>
                <p className="text-sm text-foreground/70">
                  3 runs each: Requirements, Test Plan, Jira Writeback
                </p>
                <Button
                  onClick={handleTrialContinue}
                  className="w-full"
                >
                  Continue with Trial
                </Button>
              </CardContent>
            </Card>

            {/* Full Access Option */}
            <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
              <CardContent className="p-6 space-y-4">
                <div className="flex items-center gap-3">
                  <Zap className="h-6 w-6 text-foreground/80" />
                  <h3 className="text-lg font-semibold">Full Access</h3>
                </div>
                <p className="text-sm text-foreground/70">
                  Requires activation
                </p>
                <Button
                  onClick={handleFullAccess}
                  variant="outline"
                  className="w-full"
                >
                  Activate Full Access
                </Button>
              </CardContent>
            </Card>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
