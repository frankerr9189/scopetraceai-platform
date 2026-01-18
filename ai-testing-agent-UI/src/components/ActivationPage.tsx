import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Key } from 'lucide-react'

export function ActivationPage() {
  const [activationCode, setActivationCode] = useState('')
  const [message, setMessage] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const navigate = useNavigate()

  const handleApplyCode = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setMessage(null)

    // MVP placeholder: Show friendly message
    setTimeout(() => {
      setMessage('Activation codes are not enabled yet. Please start the free trial or contact support.')
      setIsLoading(false)
    }, 500)
  }

  const handleStartTrial = () => {
    navigate('/onboarding/plan', { replace: true })
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4">
      <Card className="w-full max-w-md border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
        <CardHeader>
          <div className="flex items-center gap-3">
            <Key className="h-6 w-6 text-foreground/80" />
            <CardTitle>Activate Full Access</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-4">
            <p className="text-sm text-foreground/70">
              Full access requires activation. If you already purchased, enter your activation code. Otherwise you can start a free trial now.
            </p>
            
            <form onSubmit={handleApplyCode} className="space-y-4">
              <div className="space-y-2">
                <label htmlFor="activationCode" className="text-sm font-medium text-foreground">
                  Activation Code
                </label>
                <input
                  id="activationCode"
                  type="text"
                  value={activationCode}
                  onChange={(e) => setActivationCode(e.target.value)}
                  disabled={isLoading}
                  className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50"
                  placeholder="Enter activation code (optional)"
                />
              </div>
              
              {message && (
                <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                  <p className="text-sm text-destructive">{message}</p>
                </div>
              )}
              
              <Button
                type="submit"
                disabled={isLoading}
                className="w-full"
              >
                {isLoading ? 'Processing...' : 'Apply Code'}
              </Button>
            </form>
            
            <div className="text-center text-sm text-foreground/70">
              <Link to="/onboarding/plan" className="text-primary hover:underline">
                Start Free Trial instead
              </Link>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
