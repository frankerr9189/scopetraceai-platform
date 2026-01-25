import { useState, useEffect } from 'react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { User, Lock, Loader2, Users, CreditCard, ExternalLink } from 'lucide-react'
import { useNavigate } from 'react-router-dom'
import { 
  getUserProfile, 
  updateUserProfile, 
  changePassword, 
  UserProfile,
  listTenantUsers,
  inviteTenantUser,
  getBillingStatus,
  createPortalSession,
  deactivateTenantUser,
  reactivateTenantUser,
  type TenantUser,
  type InviteUserRequest,
  type BillingStatus
} from '../services/api'
import { showToast } from './Toast'

// Helper function to safely format dates
function formatDate(dateString: string | null | undefined): string {
  if (!dateString) return '—'
  const date = new Date(dateString)
  if (isNaN(date.getTime())) return '—'
  return date.toLocaleDateString()
}

export function ProfilePage() {
  const navigate = useNavigate()
  const [profile, setProfile] = useState<UserProfile | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isSaving, setIsSaving] = useState(false)
  const [isChangingPassword, setIsChangingPassword] = useState(false)
  const [error, setError] = useState<string | null>(null)
  
  // Profile form fields
  const [firstName, setFirstName] = useState('')
  const [lastName, setLastName] = useState('')
  const [address1, setAddress1] = useState('')
  const [address2, setAddress2] = useState('')
  const [city, setCity] = useState('')
  const [state, setState] = useState('')
  const [zip, setZip] = useState('')
  const [phone, setPhone] = useState('')
  
  // Password change fields
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  
  // Team Management state (admin only)
  const [userRole, setUserRole] = useState<string | null>(null)
  const [currentUserId, setCurrentUserId] = useState<string | null>(null)
  const [tenantUsers, setTenantUsers] = useState<TenantUser[]>([])
  const [tenantUsersLoading, setTenantUsersLoading] = useState(false)
  const [tenantUsersError, setTenantUsersError] = useState<string | null>(null)
  const [seatCap, setSeatCap] = useState<number | null>(null)
  const [isInviting, setIsInviting] = useState(false)
  const [inviteForm, setInviteForm] = useState<InviteUserRequest>({
    email: '',
    role: 'user',
    first_name: '',
    last_name: ''
  })
  const [activatingUserId, setActivatingUserId] = useState<string | null>(null)
  
  // Billing/Subscription state
  const [billingStatus, setBillingStatus] = useState<BillingStatus | null>(null)
  const [billingLoading, setBillingLoading] = useState(false)
  const [isOpeningPortal, setIsOpeningPortal] = useState(false)
  
  useEffect(() => {
    loadProfile()
    loadBillingStatus()
  }, [])
  
  // Set browser tab title for Profile page
  useEffect(() => {
    document.title = 'Profile · ScopeTraceAI'
    // Cleanup: restore default title when component unmounts
    return () => {
      document.title = 'ScopeTraceAI'
    }
  }, [])
  
  // Load user role and team management data if admin/owner
  useEffect(() => {
    const userStr = localStorage.getItem('user')
    if (userStr) {
      try {
        const user = JSON.parse(userStr)
        setUserRole(user.role)
        setCurrentUserId(user.id || null)
        if (user.role === 'admin' || user.role === 'owner') {
          loadTenantUsers()
          loadSeatCap()
        }
      } catch {
        // Ignore parse errors
      }
    }
  }, [])
  
  const loadTenantUsers = async () => {
    setTenantUsersLoading(true)
    setTenantUsersError(null)
    try {
      const users = await listTenantUsers()
      setTenantUsers(users)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load tenant users'
      setTenantUsersError(errorMessage)
      if (errorMessage.includes('Unauthorized') || errorMessage.includes('FORBIDDEN')) {
        showToast('Access denied', 'error')
      }
    } finally {
      setTenantUsersLoading(false)
    }
  }
  
  const loadSeatCap = async () => {
    try {
      const billing = await getBillingStatus()
      const planTier = billing.plan_tier || 'free'
      // Map plan tier to seat cap
      const seatCapMap: Record<string, number> = {
        'free': 1,
        'trial': 1,
        'individual': 1,
        'team': 3,
        'pro': 5,
        'enterprise': 100
      }
      setSeatCap(seatCapMap[planTier] || 1)
    } catch (err) {
      // Silently fail - don't break page if billing status unavailable
      console.warn('Failed to load seat cap:', err)
    }
  }

  const loadBillingStatus = async () => {
    setBillingLoading(true)
    try {
      const billing = await getBillingStatus()
      setBillingStatus(billing)
    } catch (err) {
      // Silently fail - don't break page if billing status unavailable
      console.warn('Failed to load billing status:', err)
    } finally {
      setBillingLoading(false)
    }
  }

  const isEligibleForPortal = (): boolean => {
    if (!billingStatus) return false
    
    // Check if tenant has a paid plan tier (not trial/unselected)
    const paidTiers = ['individual', 'team', 'pro', 'enterprise']
    const hasPaidPlan = Boolean(billingStatus.plan_tier && paidTiers.includes(billingStatus.plan_tier))
    
    // Check if status indicates they have a Stripe subscription
    // Exclude incomplete/unselected (no Stripe customer yet)
    // Include active, trialing, past_due, canceled (all have Stripe customer)
    const hasStripeSubscription = Boolean(billingStatus.status && 
      billingStatus.status !== 'incomplete' && 
      billingStatus.status !== 'unselected')
    
    // Eligible if: paid plan tier AND has Stripe subscription status
    // Period dates are a good indicator but not required (edge case: just activated)
    return hasPaidPlan && hasStripeSubscription
  }

  const handleOpenPortal = async () => {
    // Check eligibility: if trial/unselected/incomplete, navigate to plan selection instead
    if (!isEligibleForPortal()) {
      // Navigate to plan selection page for upgrade
      navigate('/onboarding/plan')
      return
    }

    // Eligible for portal: call portal session endpoint
    setIsOpeningPortal(true)
    try {
      const result = await createPortalSession()
      if (result.ok && result.url) {
        // Redirect to Stripe Customer Portal
        window.location.href = result.url
      } else {
        const errorMsg = result.error || 'Failed to open billing portal'
        showToast(errorMsg, 'error')
      }
    } catch (err: any) {
      // Handle 409 errors (no stripe_customer_id) gracefully
      if (err.status === 409) {
        const errorMsg = err.error || 'No active subscription. Please upgrade to a paid plan first.'
        showToast(errorMsg, 'error')
        // Optionally navigate to plan selection on 409
        navigate('/onboarding/plan')
      } else {
        const errorMsg = err.error || err.message || 'Failed to open billing portal'
        showToast(errorMsg, 'error')
      }
    } finally {
      setIsOpeningPortal(false)
    }
  }
  
  const handleInviteUser = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsInviting(true)
    setTenantUsersError(null)
    
    try {
      const result = await inviteTenantUser(inviteForm)
      if (result.ok) {
        showToast('Invite sent', 'info')
        // Reset form
        setInviteForm({
          email: '',
          role: 'user',
          first_name: '',
          last_name: ''
        })
        // Reload users
        await loadTenantUsers()
      }
    } catch (err: any) {
      // Handle structured errors
      if (err.error === 'SEAT_CAP_EXCEEDED') {
        const message = `Seat limit reached (${err.current_seats || 0}/${err.seat_cap || 0}). Upgrade plan to add more users.`
        setTenantUsersError(message)
        showToast(message, 'error')
      } else if (err.error === 'BILLING_INACTIVE') {
        const message = 'Billing inactive. Please complete billing to add users.'
        setTenantUsersError(message)
        showToast(message, 'error')
      } else if (err.error === 'USER_ALREADY_EXISTS') {
        const message = 'User already exists.'
        setTenantUsersError(message)
        showToast(message, 'error')
      } else if (err.error === 'EMAIL_IN_USE') {
        const message = 'Email is already used in another tenant.'
        setTenantUsersError(message)
        showToast(message, 'error')
      } else {
        const message = err.message || err.error || 'Unable to invite user.'
        setTenantUsersError(message)
        showToast(message, 'error')
      }
    } finally {
      setIsInviting(false)
    }
  }
  
  const handleDeactivateUser = async (userId: string) => {
    setActivatingUserId(userId)
    setTenantUsersError(null)
    
    try {
      await deactivateTenantUser(userId)
      showToast('User deactivated', 'info')
      await loadTenantUsers()
    } catch (err: any) {
      // Handle structured errors
      if (err.error === 'SELF_DEACTIVATE_FORBIDDEN') {
        const message = "You can't deactivate your own account."
        setTenantUsersError(message)
        showToast(message, 'error')
      } else if (err.error === 'LAST_ADMIN_FORBIDDEN') {
        const message = "You can't deactivate the last admin on the account."
        setTenantUsersError(message)
        showToast(message, 'error')
      } else {
        const message = err.message || err.error || 'Failed to deactivate user'
        setTenantUsersError(message)
        showToast(message, 'error')
      }
    } finally {
      setActivatingUserId(null)
    }
  }
  
  const handleReactivateUser = async (userId: string) => {
    setActivatingUserId(userId)
    setTenantUsersError(null)
    
    try {
      await reactivateTenantUser(userId)
      showToast('User reactivated', 'info')
      await loadTenantUsers()
    } catch (err: any) {
      // Handle structured errors
      if (err.error === 'SEAT_CAP_EXCEEDED') {
        const message = `Seat limit reached (${err.current_seats || 0}/${err.seat_cap || 0}). Upgrade plan to add more users.`
        setTenantUsersError(message)
        showToast(message, 'error')
      } else if (err.error === 'BILLING_INACTIVE') {
        const message = 'Billing inactive. Please complete billing to add users.'
        setTenantUsersError(message)
        showToast(message, 'error')
      } else {
        const message = err.message || err.error || 'Failed to reactivate user'
        setTenantUsersError(message)
        showToast(message, 'error')
      }
    } finally {
      setActivatingUserId(null)
    }
  }
  
  const loadProfile = async () => {
    try {
      setIsLoading(true)
      const data = await getUserProfile()
      setProfile(data)
      setFirstName(data.first_name || '')
      setLastName(data.last_name || '')
      setAddress1(data.address_1 || '')
      setAddress2(data.address_2 || '')
      setCity(data.city || '')
      setState(data.state || '')
      setZip(data.zip || '')
      setPhone(data.phone || '')
      setError(null)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load profile')
      showToast('Failed to load profile', 'error')
    } finally {
      setIsLoading(false)
    }
  }
  
  const handleSaveProfile = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    setIsSaving(true)
    
    try {
      const updated = await updateUserProfile({
        first_name: firstName || null,
        last_name: lastName || null,
        address_1: address1 || null,
        address_2: address2 || null,
        city: city || null,
        state: state || null,
        zip: zip || null,
        phone: phone || null,
      })
      setProfile(updated)
      showToast('Profile updated successfully', 'info')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to update profile'
      setError(message)
      showToast(message, 'error')
    } finally {
      setIsSaving(false)
    }
  }
  
  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault()
    setError(null)
    
    if (newPassword !== confirmPassword) {
      setError('New passwords do not match')
      return
    }
    
    if (newPassword.length < 12) {
      setError('Password must be at least 12 characters long')
      return
    }
    
    setIsChangingPassword(true)
    
    try {
      await changePassword({
        current_password: currentPassword,
        new_password: newPassword,
      })
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      showToast('Password changed successfully', 'info')
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to change password'
      setError(message)
      showToast(message, 'error')
    } finally {
      setIsChangingPassword(false)
    }
  }
  
  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="text-lg text-foreground/70 mb-2">Loading profile...</div>
        </div>
      </div>
    )
  }
  
  if (!profile) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="text-lg text-foreground/70 mb-2">Failed to load profile</div>
          <Button onClick={loadProfile} className="mt-4">Retry</Button>
        </div>
      </div>
    )
  }
  
  return (
    <div className="max-w-4xl mx-auto py-8 px-4">
      <div className="mb-8">
        <h1 className="text-3xl font-bold mb-2">Account Profile</h1>
        <p className="text-muted-foreground">Manage your account, security, and subscription</p>
      </div>
      
      {error && (
        <div className="mb-6 p-3 bg-destructive/10 border border-destructive/20 rounded-md">
          <p className="text-sm text-destructive">{error}</p>
        </div>
      )}
      
      <div className="space-y-6">
        {/* Profile Information */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-3">
              <User className="h-6 w-6 text-foreground/80" />
              <CardTitle>Profile Information</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSaveProfile} className="space-y-4">
              {/* Read-only fields */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="text-sm font-medium text-foreground/70">Email</label>
                  <input
                    type="email"
                    value={profile.email}
                    disabled
                    className="w-full px-4 py-2 bg-muted border border-input rounded-md text-foreground/50 cursor-not-allowed"
                  />
                  <p className="text-xs text-muted-foreground mt-1">Email cannot be changed</p>
                </div>
                <div>
                  <label className="text-sm font-medium text-foreground/70">Role</label>
                  <input
                    type="text"
                    value={profile.role}
                    disabled
                    className="w-full px-4 py-2 bg-muted border border-input rounded-md text-foreground/50 cursor-not-allowed"
                  />
                </div>
                <div>
                  <label className="text-sm font-medium text-foreground/70">Client Name</label>
                  <input
                    type="text"
                    value={profile.tenant_name || '—'}
                    disabled
                    className="w-full px-4 py-2 bg-muted border border-input rounded-md text-foreground/50 cursor-not-allowed"
                  />
                </div>
              </div>
              
              {/* Editable fields */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label htmlFor="firstName" className="text-sm font-medium text-foreground">
                    First Name
                  </label>
                  <input
                    id="firstName"
                    type="text"
                    value={firstName}
                    onChange={(e) => setFirstName(e.target.value)}
                    className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                  />
                </div>
                <div>
                  <label htmlFor="lastName" className="text-sm font-medium text-foreground">
                    Last Name
                  </label>
                  <input
                    id="lastName"
                    type="text"
                    value={lastName}
                    onChange={(e) => setLastName(e.target.value)}
                    className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                  />
                </div>
              </div>
              
              <div>
                <label htmlFor="address1" className="text-sm font-medium text-foreground">
                  Address Line 1
                </label>
                <input
                  id="address1"
                  type="text"
                  value={address1}
                  onChange={(e) => setAddress1(e.target.value)}
                  className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              
              <div>
                <label htmlFor="address2" className="text-sm font-medium text-foreground">
                  Address Line 2
                </label>
                <input
                  id="address2"
                  type="text"
                  value={address2}
                  onChange={(e) => setAddress2(e.target.value)}
                  className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <label htmlFor="city" className="text-sm font-medium text-foreground">
                    City
                  </label>
                  <input
                    id="city"
                    type="text"
                    value={city}
                    onChange={(e) => setCity(e.target.value)}
                    className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                  />
                </div>
                <div>
                  <label htmlFor="state" className="text-sm font-medium text-foreground">
                    State
                  </label>
                  <input
                    id="state"
                    type="text"
                    value={state}
                    onChange={(e) => setState(e.target.value)}
                    className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                  />
                </div>
                <div>
                  <label htmlFor="zip" className="text-sm font-medium text-foreground">
                    ZIP Code
                  </label>
                  <input
                    id="zip"
                    type="text"
                    value={zip}
                    onChange={(e) => setZip(e.target.value)}
                    className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                  />
                </div>
              </div>
              
              <div>
                <label htmlFor="phone" className="text-sm font-medium text-foreground">
                  Phone
                </label>
                <input
                  id="phone"
                  type="tel"
                  value={phone}
                  onChange={(e) => setPhone(e.target.value)}
                  className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              
              <Button type="submit" disabled={isSaving} className="w-full">
                {isSaving ? 'Saving...' : 'Save Profile'}
              </Button>
            </form>
          </CardContent>
        </Card>
        
        {/* Change Password */}
        <Card>
          <CardHeader>
            <div className="flex items-center gap-3">
              <Lock className="h-6 w-6 text-foreground/80" />
              <CardTitle>Change Password</CardTitle>
            </div>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleChangePassword} className="space-y-4">
              <div>
                <label htmlFor="currentPassword" className="text-sm font-medium text-foreground">
                  Current Password <span className="text-destructive">*</span>
                </label>
                <input
                  id="currentPassword"
                  type="password"
                  value={currentPassword}
                  onChange={(e) => setCurrentPassword(e.target.value)}
                  required
                  className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              
              <div>
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
                  className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                />
                <p className="text-xs text-muted-foreground mt-1">Must be at least 12 characters</p>
              </div>
              
              <div>
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
                  className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              
              <Button type="submit" disabled={isChangingPassword} className="w-full">
                {isChangingPassword ? 'Changing Password...' : 'Change Password'}
              </Button>
            </form>
          </CardContent>
        </Card>
        
        {/* Billing & Subscription Section (admin/owner only) */}
        {(userRole === 'admin' || userRole === 'owner') && (
          <Card>
            <CardHeader>
              <div className="flex items-center gap-3">
                <CreditCard className="h-6 w-6 text-foreground/80" />
                <CardTitle>Billing & Subscription</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              {billingLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin text-foreground/50" />
                </div>
              ) : billingStatus ? (
                <div className="space-y-4">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div>
                      <label className="text-sm font-medium text-foreground/70">Plan Tier</label>
                      <div className="mt-1">
                        <Badge variant="outline" className="text-base px-3 py-1">
                          {billingStatus.plan_tier ? 
                            billingStatus.plan_tier.charAt(0).toUpperCase() + billingStatus.plan_tier.slice(1) 
                            : '—'}
                        </Badge>
                      </div>
                    </div>
                    <div>
                      <label className="text-sm font-medium text-foreground/70">Status</label>
                      <div className="mt-1">
                        <Badge 
                          variant={
                            billingStatus.status === 'active' || billingStatus.status === 'trialing' 
                              ? 'default' 
                              : billingStatus.status === 'canceled' || billingStatus.status === 'past_due'
                              ? 'destructive'
                              : 'secondary'
                          }
                          className="text-base px-3 py-1"
                        >
                          {billingStatus.status ? 
                            billingStatus.status.charAt(0).toUpperCase() + billingStatus.status.slice(1) 
                            : '—'}
                        </Badge>
                      </div>
                    </div>
                  </div>
                  
                  {(billingStatus.current_period_start || billingStatus.current_period_end) && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-2 border-t border-border/50">
                      {billingStatus.current_period_start && (
                        <div>
                          <label className="text-sm font-medium text-foreground/70">Period Start</label>
                          <p className="text-sm text-foreground mt-1">
                            {formatDate(billingStatus.current_period_start)}
                          </p>
                        </div>
                      )}
                      {billingStatus.current_period_end && (
                        <div>
                          <label className="text-sm font-medium text-foreground/70">Period End</label>
                          <p className="text-sm text-foreground mt-1">
                            {formatDate(billingStatus.current_period_end)}
                          </p>
                        </div>
                      )}
                    </div>
                  )}

                  <div className="pt-4 border-t border-border/50">
                    <Button
                      onClick={handleOpenPortal}
                      disabled={isOpeningPortal}
                      variant="outline"
                      className="w-full"
                    >
                      {isOpeningPortal ? (
                        <>
                          <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                          {isEligibleForPortal() ? 'Opening...' : 'Redirecting...'}
                        </>
                      ) : (
                        <>
                          {isEligibleForPortal() 
                            ? (billingStatus.status === 'canceled' ? 'Reactivate Subscription' : 'Manage Billing')
                            : 'Upgrade Plan'}
                          <ExternalLink className="h-4 w-4 ml-2" />
                        </>
                      )}
                    </Button>
                    <p className="text-xs text-muted-foreground mt-2 text-center">
                      {isEligibleForPortal()
                        ? 'Update payment method, view invoices, or cancel subscription'
                        : 'Upgrade to a paid plan to access billing management'}
                    </p>
                  </div>
                </div>
              ) : (
                <div className="text-sm text-muted-foreground">
                  Unable to load billing information
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Team Management Section (admin only) */}
        {userRole === 'admin' && (
          <Card>
            <CardHeader>
              <div className="flex items-center gap-3">
                <Users className="h-6 w-6 text-foreground/80" />
                <CardTitle>Team Management</CardTitle>
              </div>
            </CardHeader>
            <CardContent>
              {tenantUsersError && (
                <div className="mb-4 p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                  <p className="text-sm text-destructive">{tenantUsersError}</p>
                </div>
              )}
              
              {/* Seat usage indicator */}
              {seatCap !== null && (
                <div className="mb-4 text-sm text-muted-foreground">
                  Seats: {tenantUsers.filter(u => u.is_active).length} / {seatCap}
                </div>
              )}
              
              {/* Invite form */}
              <form onSubmit={handleInviteUser} className="mb-6 space-y-4 border-b border-border pb-6">
                <h3 className="text-sm font-semibold text-foreground">Invite User</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-xs font-medium text-foreground">Email <span className="text-destructive">*</span></label>
                    <input
                      type="email"
                      value={inviteForm.email}
                      onChange={(e) => setInviteForm({ ...inviteForm, email: e.target.value })}
                      required
                      disabled={isInviting}
                      className="w-full px-3 py-2 bg-background border border-input rounded-md text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                      placeholder="user@example.com"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs font-medium text-foreground">Role <span className="text-destructive">*</span></label>
                    <select
                      value={inviteForm.role}
                      onChange={(e) => setInviteForm({ ...inviteForm, role: e.target.value as 'user' | 'admin' })}
                      required
                      disabled={isInviting}
                      className="w-full px-3 py-2 bg-background border border-input rounded-md text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                    >
                      <option value="user">User</option>
                      <option value="admin">Admin</option>
                    </select>
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs font-medium text-foreground">First Name</label>
                    <input
                      type="text"
                      value={inviteForm.first_name}
                      onChange={(e) => setInviteForm({ ...inviteForm, first_name: e.target.value })}
                      disabled={isInviting}
                      className="w-full px-3 py-2 bg-background border border-input rounded-md text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                      placeholder="Optional"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-xs font-medium text-foreground">Last Name</label>
                    <input
                      type="text"
                      value={inviteForm.last_name}
                      onChange={(e) => setInviteForm({ ...inviteForm, last_name: e.target.value })}
                      disabled={isInviting}
                      className="w-full px-3 py-2 bg-background border border-input rounded-md text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                      placeholder="Optional"
                    />
                  </div>
                </div>
                <div className="flex justify-end">
                  <Button
                    type="submit"
                    disabled={isInviting || !inviteForm.email}
                  >
                    {isInviting ? (
                      <>
                        <Loader2 className="h-3 w-3 animate-spin mr-1" />
                        Inviting...
                      </>
                    ) : (
                      'Invite User'
                    )}
                  </Button>
                </div>
              </form>
              
              {/* Users list */}
              {tenantUsersLoading ? (
                <div className="flex items-center justify-center py-8">
                  <Loader2 className="h-6 w-6 animate-spin text-foreground/50" />
                </div>
              ) : (
                <div className="space-y-2">
                  {tenantUsers.length === 0 ? (
                    <p className="text-sm text-muted-foreground">No users found</p>
                  ) : (
                    <div className="overflow-x-auto">
                      <table className="w-full">
                        <thead>
                          <tr className="border-b border-border">
                            <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Email</th>
                            <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Name</th>
                            <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Role</th>
                            <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Status</th>
                            <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Created</th>
                            <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {tenantUsers.map((user) => (
                            <tr key={user.id} className="border-b border-border/50 hover:bg-secondary/20">
                              <td className="px-4 py-3 text-sm">{user.email}</td>
                              <td className="px-4 py-3 text-sm">
                                {user.first_name || user.last_name 
                                  ? `${user.first_name || ''} ${user.last_name || ''}`.trim()
                                  : '—'}
                              </td>
                              <td className="px-4 py-3 text-sm">
                                <Badge variant="outline">{user.role}</Badge>
                              </td>
                              <td className="px-4 py-3 text-sm">
                                {user.is_active ? (
                                  <Badge variant="default">Active</Badge>
                                ) : user.has_pending_invite ? (
                                  <Badge variant="outline" className="bg-yellow-500/20 text-yellow-400 border-yellow-500/50">
                                    Pending Activation
                                  </Badge>
                                ) : (
                                  <Badge variant="secondary">Inactive</Badge>
                                )}
                              </td>
                              <td className="px-4 py-3 text-sm text-muted-foreground">
                                {formatDate(user.created_at)}
                              </td>
                              <td className="px-4 py-3 text-sm">
                                {user.is_active ? (
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    onClick={() => handleDeactivateUser(user.id)}
                                    disabled={activatingUserId === user.id || user.id === currentUserId}
                                  >
                                    {activatingUserId === user.id ? (
                                      <>
                                        <Loader2 className="h-3 w-3 animate-spin mr-1" />
                                        Deactivating...
                                      </>
                                    ) : (
                                      'Deactivate'
                                    )}
                                  </Button>
                                ) : (
                                  <Button
                                    size="sm"
                                    variant="default"
                                    onClick={() => handleReactivateUser(user.id)}
                                    disabled={activatingUserId === user.id}
                                  >
                                    {activatingUserId === user.id ? (
                                      <>
                                        <Loader2 className="h-3 w-3 animate-spin mr-1" />
                                        Reactivating...
                                      </>
                                    ) : (
                                      'Reactivate'
                                    )}
                                  </Button>
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
