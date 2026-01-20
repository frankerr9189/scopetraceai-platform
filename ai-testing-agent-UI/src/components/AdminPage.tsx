import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Loader2, ChevronDown, ChevronUp, ChevronRight } from 'lucide-react'
import { 
  listTenants, 
  resetTenantTrial, 
  setTenantTrial, 
  type TenantSummary, 
  refreshTenantStatus,
  adminListTenants,
  adminSetTenantStatus,
  adminListTenantUsers,
  adminDeactivateTenantUser,
  adminReactivateTenantUser,
  type AdminUser
} from '../services/api'
import { useTenantStatus } from '../contexts/TenantStatusContext'
import { showToast } from './Toast'

export function AdminPage() {
  const navigate = useNavigate()
  const { tenantStatus, refreshTenantStatus: refreshTenantStatusFromContext, refreshBootstrapStatus } = useTenantStatus()
  const [tenants, setTenants] = useState<TenantSummary[]>([])
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [editingTenant, setEditingTenant] = useState<string | null>(null)
  const [editForm, setEditForm] = useState<{
    req: number
    test: number
    writeback: number
    status: 'unselected' | 'trial' | 'individual' | 'team' | 'paywalled' | 'canceled'
  } | null>(null)
  const [isResetting, setIsResetting] = useState<string | null>(null)
  const [isSaving, setIsSaving] = useState<string | null>(null)
  const [expandedTenantId, setExpandedTenantId] = useState<string | null>(null)
  
  // Tenant-specific data (loaded when tenant is expanded)
  const [tenantUsers, setTenantUsers] = useState<Record<string, AdminUser[]>>({})
  const [tenantDataLoading, setTenantDataLoading] = useState<Record<string, boolean>>({})
  
  // Current user info
  const [currentUser, setCurrentUser] = useState<any>(null)
  const [authReady, setAuthReady] = useState(false)

  // Check if user has admin role and get current user/tenant info
  // This must complete BEFORE any admin API calls
  useEffect(() => {
    const accessToken = localStorage.getItem('access_token')
    const userStr = localStorage.getItem('user')
    
    if (!accessToken || !userStr) {
      // No auth - redirect to home
      navigate('/', { replace: true })
      return
    }
    
    try {
      const user = JSON.parse(userStr)
      const role = user.role
      
      // Check owner access (only owner can manage all tenants)
      if (role !== 'owner') {
        showToast('Owner access required', 'error')
        navigate('/', { replace: true })
        return
      }
      
      // Set user info
      setCurrentUser(user)
      
      // Mark auth as ready - this gates all admin API calls
      setAuthReady(true)
    } catch (err) {
      console.error('Error parsing user data:', err)
      navigate('/', { replace: true })
      return
    }
  }, [navigate])

  // Load tenants only after auth is ready
  useEffect(() => {
    if (!authReady) return
    loadTenants()
  }, [authReady])

  const loadTenants = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const data = await adminListTenants()
      setTenants(data)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load tenants'
      setError(errorMessage)
      if (errorMessage.includes('Owner access required') || errorMessage.includes('FORBIDDEN')) {
        showToast('Owner access required', 'error')
        navigate('/', { replace: true })
      }
    } finally {
      setIsLoading(false)
    }
  }
  
  const loadTenantData = async (tenantId: string) => {
    if (tenantDataLoading[tenantId]) return
    
    setTenantDataLoading(prev => ({ ...prev, [tenantId]: true }))
    try {
      const users = await adminListTenantUsers(tenantId)
      setTenantUsers(prev => ({ ...prev, [tenantId]: users }))
    } catch (err) {
      console.error('Failed to load tenant data:', err)
      const errorMessage = err instanceof Error ? err.message : 'Failed to load tenant data'
      if (errorMessage.includes('Unauthorized') || errorMessage.includes('Forbidden')) {
        showToast('Access denied', 'error')
      }
    } finally {
      setTenantDataLoading(prev => ({ ...prev, [tenantId]: false }))
    }
  }

  const handleResetTrial = async (tenantId: string) => {
    setIsResetting(tenantId)
    try {
      const updated = await resetTenantTrial(tenantId)
      
      // Update tenant in list
      setTenants(prev => prev.map(t => t.id === tenantId ? updated : t))
      
      // If this is the current tenant, refresh status
      if (tenantStatus && tenantStatus.tenant_id === tenantId) {
        refreshTenantStatus()
        await refreshTenantStatusFromContext()
        await refreshBootstrapStatus()
      }
      
      showToast('Trial reset to 3/3/3', 'info')
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to reset trial'
      showToast(errorMessage, 'error')
    } finally {
      setIsResetting(null)
    }
  }

  const handleEditClick = (tenant: TenantSummary) => {
    // Expand tenant if not already expanded
    if (expandedTenantId !== tenant.id) {
      setExpandedTenantId(tenant.id)
      // Load tenant data when expanding
      loadTenantData(tenant.id)
    }
    
    // Toggle edit form
    if (editingTenant === tenant.id) {
      setEditingTenant(null)
      setEditForm(null)
    } else {
      setEditingTenant(tenant.id)
      setEditForm({
        req: tenant.req_remaining,
        test: tenant.test_remaining,
        writeback: tenant.wb_remaining,
        status: tenant.subscription_status
      })
    }
  }
  
  const handleToggleTenantExpanded = (tenantId: string) => {
    if (expandedTenantId === tenantId) {
      setExpandedTenantId(null)
    } else {
      setExpandedTenantId(tenantId)
      // Load tenant data when expanding
      loadTenantData(tenantId)
    }
  }
  
  const handleAccountStatusToggle = async (tenant: TenantSummary) => {
    const isSuspended = tenant.subscription_status === 'suspended' || !tenant.is_active
    const newStatus = isSuspended ? 'active' : 'suspended'
    
    try {
      await adminSetTenantStatus(tenant.id, newStatus)
      showToast(`Tenant ${newStatus === 'active' ? 'activated' : 'suspended'}`, 'info')
      // Reload tenants to get updated status
      await loadTenants()
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to update tenant status'
      showToast(errorMessage, 'error')
    }
  }

  const handleSaveEdit = async (tenantId: string) => {
    if (!editForm) return
    
    setIsSaving(tenantId)
    try {
      const updated = await setTenantTrial(tenantId, editForm)
      
      // Update tenant in list
      setTenants(prev => prev.map(t => t.id === tenantId ? updated : t))
      
      // If this is the current tenant, refresh status
      if (tenantStatus && tenantStatus.tenant_id === tenantId) {
        refreshTenantStatus()
        await refreshTenantStatusFromContext()
        await refreshBootstrapStatus()
      }
      
      setEditingTenant(null)
      setEditForm(null)
      showToast('Trial settings updated', 'info')
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to update trial'
      showToast(errorMessage, 'error')
    } finally {
      setIsSaving(null)
    }
  }

  const handleDeactivateTenantUser = async (tenantId: string, userId: string) => {
    if (!authReady || !currentUser) {
      showToast('Authentication not ready', 'error')
      return
    }
    
    if (!userId) {
      showToast('Invalid user ID', 'error')
      return
    }
    
    try {
      await adminDeactivateTenantUser(tenantId, userId)
      showToast('User deactivated', 'info')
      // Reload tenant users
      const users = await adminListTenantUsers(tenantId)
      setTenantUsers(prev => ({ ...prev, [tenantId]: users }))
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to deactivate user'
      showToast(errorMessage, 'error')
    }
  }

  const handleReactivateTenantUser = async (tenantId: string, userId: string) => {
    if (!authReady || !currentUser) {
      showToast('Authentication not ready', 'error')
      return
    }
    
    if (!userId) {
      showToast('Invalid user ID', 'error')
      return
    }
    
    try {
      await adminReactivateTenantUser(tenantId, userId)
      showToast('User reactivated', 'info')
      // Reload tenant users
      const users = await adminListTenantUsers(tenantId)
      setTenantUsers(prev => ({ ...prev, [tenantId]: users }))
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to reactivate user'
      showToast(errorMessage, 'error')
    }
  }

  const getStatusBadge = (status: string) => {
    const colors = {
      'trial': 'bg-blue-500/20 text-blue-400',
      'individual': 'bg-green-500/20 text-green-400',
      'team': 'bg-green-500/20 text-green-400',
      'paywalled': 'bg-destructive/20 text-destructive',
      'canceled': 'bg-destructive/20 text-destructive',
      'unselected': 'bg-muted/20 text-muted-foreground'
    }
    return (
      <Badge variant="default" className={colors[status as keyof typeof colors] || ''}>
        {status}
      </Badge>
    )
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <Loader2 className="h-8 w-8 animate-spin text-foreground/50" />
      </div>
    )
  }

  if (error) {
    return (
      <div className="space-y-4">
        <Card className="border-destructive/50">
          <CardContent className="p-6">
            <p className="text-destructive">{error}</p>
          </CardContent>
        </Card>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold text-foreground">Admin</h1>
          <p className="text-muted-foreground mt-1">Manage tenant trials and subscriptions</p>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Tenants</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Tenant Name</th>
                  <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Slug</th>
                  <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Status</th>
                  <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Req</th>
                  <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Test</th>
                  <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Writeback</th>
                  <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Actions</th>
                </tr>
              </thead>
              <tbody>
                {tenants.map((tenant) => {
                  const isExpanded = expandedTenantId === tenant.id
                  const isSuspended = tenant.subscription_status === 'suspended' || !tenant.is_active
                  return (
                    <>
                      <tr 
                        key={tenant.id} 
                        className="border-b border-border/50 hover:bg-secondary/20"
                      >
                        <td className="px-4 py-3 text-sm">
                          <div className="flex items-center gap-2">
                            <button
                              onClick={() => handleToggleTenantExpanded(tenant.id)}
                              className="flex items-center gap-2 hover:text-foreground"
                            >
                              {isExpanded ? (
                                <ChevronDown className="h-4 w-4 text-muted-foreground" />
                              ) : (
                                <ChevronRight className="h-4 w-4 text-muted-foreground" />
                              )}
                              {tenant.name}
                            </button>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-sm font-mono text-muted-foreground">{tenant.slug}</td>
                        <td className="px-4 py-3 text-sm">
                          {getStatusBadge(tenant.subscription_status)}
                        </td>
                        <td className="px-4 py-3 text-sm">{tenant.req_remaining}</td>
                        <td className="px-4 py-3 text-sm">{tenant.test_remaining}</td>
                        <td className="px-4 py-3 text-sm">{tenant.wb_remaining}</td>
                        <td className="px-4 py-3 text-sm">
                          <div className="flex items-center gap-2">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => handleResetTrial(tenant.id)}
                              disabled={isResetting === tenant.id}
                            >
                              {isResetting === tenant.id ? (
                                <>
                                  <Loader2 className="h-3 w-3 animate-spin mr-1" />
                                  Resetting...
                                </>
                              ) : (
                                'Reset Trial'
                              )}
                            </Button>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => handleEditClick(tenant)}
                            >
                              {editingTenant === tenant.id ? (
                                <>
                                  <ChevronUp className="h-4 w-4 mr-1" />
                                  Hide
                                </>
                              ) : (
                                <>
                                  <ChevronDown className="h-4 w-4 mr-1" />
                                  Edit
                                </>
                              )}
                            </Button>
                          </div>
                        </td>
                      </tr>
                      {isExpanded && (
                        <tr>
                          <td colSpan={7} className="px-4 py-4 bg-secondary/10">
                            <div className="space-y-6">
                              {/* Account Status Toggle */}
                              <div className="space-y-2 border-b border-border pb-4">
                                <h3 className="text-sm font-semibold text-foreground">Account Status</h3>
                                <div className="flex items-center justify-between">
                                  <div>
                                    <p className="text-sm text-muted-foreground">Current Status</p>
                                    <p className="text-sm font-medium">{isSuspended ? 'Suspended' : 'Active'}</p>
                                  </div>
                                  <div className="flex items-center gap-2">
                                    <label className="text-sm text-foreground">Account Status:</label>
                                    <button
                                      onClick={() => handleAccountStatusToggle(tenant)}
                                      className={`px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                                        isSuspended
                                          ? 'bg-destructive/20 text-destructive hover:bg-destructive/30'
                                          : 'bg-green-500/20 text-green-400 hover:bg-green-500/30'
                                      }`}
                                    >
                                      {isSuspended ? 'Suspended' : 'Active'}
                                    </button>
                                  </div>
                                </div>
                              </div>

                              {/* Trial/Billing Edit Section */}
                              {editingTenant === tenant.id && editForm && (
                                <div className="space-y-4 border-b border-border pb-4">
                                  <h3 className="text-sm font-semibold text-foreground">Edit Trial Settings</h3>
                                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                                    <div className="space-y-2">
                                      <label className="text-xs font-medium text-foreground">Status</label>
                                      <select
                                        value={editForm.status}
                                        onChange={(e) => setEditForm({ ...editForm, status: e.target.value as 'unselected' | 'trial' | 'individual' | 'team' | 'paywalled' | 'canceled' })}
                                        className="w-full px-3 py-2 bg-background border border-input rounded-md text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                                      >
                                        <option value="unselected">Unselected</option>
                                        <option value="trial">Trial</option>
                                        <option value="individual">Individual</option>
                                        <option value="team">Team</option>
                                        <option value="paywalled">Paywalled</option>
                                        <option value="canceled">Canceled</option>
                                      </select>
                                    </div>
                                    <div className="space-y-2">
                                      <label className="text-xs font-medium text-foreground">Req Remaining</label>
                                      <input
                                        type="number"
                                        min="0"
                                        value={editForm.req}
                                        onChange={(e) => setEditForm({ ...editForm, req: parseInt(e.target.value) || 0 })}
                                        className="w-full px-3 py-2 bg-background border border-input rounded-md text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                                      />
                                    </div>
                                    <div className="space-y-2">
                                      <label className="text-xs font-medium text-foreground">Test Remaining</label>
                                      <input
                                        type="number"
                                        min="0"
                                        value={editForm.test}
                                        onChange={(e) => setEditForm({ ...editForm, test: parseInt(e.target.value) || 0 })}
                                        className="w-full px-3 py-2 bg-background border border-input rounded-md text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                                      />
                                    </div>
                                    <div className="space-y-2">
                                      <label className="text-xs font-medium text-foreground">Writeback Remaining</label>
                                      <input
                                        type="number"
                                        min="0"
                                        value={editForm.writeback}
                                        onChange={(e) => setEditForm({ ...editForm, writeback: parseInt(e.target.value) || 0 })}
                                        className="w-full px-3 py-2 bg-background border border-input rounded-md text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                                      />
                                    </div>
                                  </div>
                                  <div className="flex justify-end">
                                    <Button
                                      size="sm"
                                      onClick={() => handleSaveEdit(tenant.id)}
                                      disabled={isSaving === tenant.id}
                                    >
                                      {isSaving === tenant.id ? (
                                        <>
                                          <Loader2 className="h-3 w-3 animate-spin mr-1" />
                                          Saving...
                                        </>
                                      ) : (
                                        'Save'
                                      )}
                                    </Button>
                                  </div>
                                </div>
                              )}

                              {/* Users List */}
                              {tenantDataLoading[tenant.id] ? (
                                <div className="flex items-center justify-center py-8">
                                  <Loader2 className="h-6 w-6 animate-spin text-foreground/50" />
                                </div>
                              ) : (
                                <Card>
                                  <CardHeader>
                                    <CardTitle className="text-base">Users</CardTitle>
                                  </CardHeader>
                                  <CardContent>
                                    <div className="space-y-2">
                                      {tenantUsers[tenant.id]?.length === 0 ? (
                                        <p className="text-sm text-muted-foreground">No users found</p>
                                      ) : (
                                        tenantUsers[tenant.id]?.map((user) => (
                                          <div key={user.id} className="flex items-center justify-between p-2 border border-border rounded-md">
                                            <div>
                                              <p className="text-sm font-medium">{user.email}</p>
                                              <p className="text-xs text-muted-foreground">
                                                {user.first_name} {user.last_name} • {user.role} • {user.is_active ? 'Active' : 'Inactive'}
                                              </p>
                                            </div>
                                            <div>
                                              {user.is_active ? (
                                                <Button
                                                  size="sm"
                                                  variant="outline"
                                                  onClick={() => handleDeactivateTenantUser(tenant.id, user.id)}
                                                  disabled={user.id === currentUser?.id}
                                                >
                                                  Deactivate
                                                </Button>
                                              ) : (
                                                <Button
                                                  size="sm"
                                                  variant="default"
                                                  onClick={() => handleReactivateTenantUser(tenant.id, user.id)}
                                                >
                                                  Reactivate
                                                </Button>
                                              )}
                                            </div>
                                          </div>
                                        ))
                                      )}
                                    </div>
                                  </CardContent>
                                </Card>
                              )}
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  )
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
