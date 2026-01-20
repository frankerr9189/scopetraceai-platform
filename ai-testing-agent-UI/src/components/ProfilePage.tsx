import { useState, useEffect } from 'react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { User, Lock } from 'lucide-react'
import { getUserProfile, updateUserProfile, changePassword, UserProfile } from '../services/api'
import { showToast } from './Toast'

export function ProfilePage() {
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
  
  useEffect(() => {
    loadProfile()
  }, [])
  
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
      <h1 className="text-3xl font-bold mb-8">Profile Settings</h1>
      
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
                  <label className="text-sm font-medium text-foreground/70">Tenant ID</label>
                  <input
                    type="text"
                    value={profile.tenant_id}
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
      </div>
    </div>
  )
}
