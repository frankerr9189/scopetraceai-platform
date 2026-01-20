import { useState, useEffect } from 'react'
import { useNavigate, useSearchParams, Link } from 'react-router-dom'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Lock } from 'lucide-react'
import { resetPassword } from '../services/api'
import { showToast } from './Toast'

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams()
  const token = searchParams.get('token')
  const navigate = useNavigate()
  
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    if (!token) {
      setError('Reset token is missing. Please use the link from your email.')
    }
  }, [token])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)

    if (!token) {
      setError('Reset token is missing. Please use the link from your email.')
      return
    }

    if (newPassword !== confirmPassword) {
      setError('Passwords do not match')
      return
    }

    if (newPassword.length < 12) {
      setError('Password must be at least 12 characters long')
      return
    }

    setIsLoading(true)

    try {
      await resetPassword({
        token,
        new_password: newPassword,
      })
      showToast('Password reset successfully. Please log in with your new password.', 'info')
      navigate('/login')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to reset password'
      setError(message)
      showToast(message, 'error')
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
            <CardTitle>Reset Password</CardTitle>
          </div>
        </CardHeader>
        <CardContent>
          {!token ? (
            <div className="space-y-4">
              <div className="p-4 bg-destructive/10 border border-destructive/20 rounded-md">
                <p className="text-sm text-destructive">
                  Reset token is missing. Please use the link from your email.
                </p>
              </div>
              <Button
                type="button"
                variant="outline"
                onClick={() => navigate('/forgot-password')}
                className="w-full"
              >
                Request New Reset Link
              </Button>
              <div className="text-center text-sm text-foreground/70">
                <Link to="/login" className="text-primary hover:underline">
                  Back to Login
                </Link>
              </div>
            </div>
          ) : (
            <form onSubmit={handleSubmit} className="space-y-4">
              {error && (
                <div className="p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                  <p className="text-sm text-destructive">{error}</p>
                </div>
              )}
              <div className="space-y-2">
                <label htmlFor="newPassword" className="text-sm font-medium text-foreground">
                  New Password <span className="text-destructive">*</span>
                </label>
                <input
                  id="newPassword"
                  type="password"
                  value={newPassword}
                  onChange={(e) => setNewPassword(e.target.value)}
                  required
                  minLength={12}
                  disabled={isLoading}
                  className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50"
                  placeholder="Enter new password"
                />
                <p className="text-xs text-muted-foreground">Must be at least 12 characters</p>
              </div>
              <div className="space-y-2">
                <label htmlFor="confirmPassword" className="text-sm font-medium text-foreground">
                  Confirm New Password <span className="text-destructive">*</span>
                </label>
                <input
                  id="confirmPassword"
                  type="password"
                  value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  required
                  minLength={12}
                  disabled={isLoading}
                  className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background disabled:opacity-50"
                  placeholder="Confirm new password"
                />
              </div>
              <Button
                type="submit"
                disabled={isLoading || !newPassword || !confirmPassword}
                className="w-full"
              >
                {isLoading ? 'Resetting Password...' : 'Reset Password'}
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
