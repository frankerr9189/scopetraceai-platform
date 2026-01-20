import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Mail } from 'lucide-react'
import { forgotPassword } from '../services/api'
import { showToast } from './Toast'

export function ForgotPasswordPage() {
  const [email, setEmail] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [isSubmitted, setIsSubmitted] = useState(false)
  const navigate = useNavigate()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)

    try {
      await forgotPassword({ email })
      setIsSubmitted(true)
      showToast('If an account exists for that email, you\'ll receive a reset link.', 'info')
    } catch (err) {
      showToast(err instanceof Error ? err.message : 'Failed to request password reset', 'error')
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
            <Mail className="h-6 w-6 text-foreground/80" />
            <CardTitle>Forgot Password</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {isSubmitted ? (
            <div className="space-y-4">
              <div className="p-4 bg-blue-500/10 border border-blue-500/20 rounded-md">
                <p className="text-sm text-foreground">
                  If an account exists for that email, you'll receive a reset link.
                </p>
              </div>
              <Button
                type="button"
                variant="outline"
                onClick={() => navigate('/login')}
                className="w-full"
              >
                Back to Login
              </Button>
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
                <p className="text-xs text-muted-foreground">
                  Enter your email address and we'll send you a link to reset your password.
                </p>
              </div>
              <Button
                type="submit"
                disabled={isLoading || !email}
                className="w-full"
              >
                {isLoading ? 'Sending...' : 'Send Reset Link'}
              </Button>
              <div className="text-center text-sm text-foreground/70">
                <Link to="/login" className="text-primary hover:underline">
                  Back to Login
                </Link>
              </div>
            </form>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
