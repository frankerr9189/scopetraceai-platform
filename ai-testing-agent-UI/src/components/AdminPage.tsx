import { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Loader2, ChevronDown, ChevronUp } from 'lucide-react'
import { listTenants, resetTenantTrial, setTenantTrial, type TenantSummary, refreshTenantStatus } from '../services/api'
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
    status: 'Trial' | 'Active' | 'Paywalled'
  } | null>(null)
  const [isResetting, setIsResetting] = useState<string | null>(null)
  const [isSaving, setIsSaving] = useState<string | null>(null)

  // Check if user has admin role
  useEffect(() => {
    const userStr = localStorage.getItem('user')
    if (userStr) {
      try {
        const user = JSON.parse(userStr)
        const role = user.role
        if (role !== 'owner' && role !== 'superAdmin') {
          // Not authorized - redirect to home
          showToast('Admin access required', 'error')
          navigate('/', { replace: true })
          return
        }
      } catch {
        navigate('/', { replace: true })
        return
      }
    } else {
      navigate('/', { replace: true })
      return
    }
  }, [navigate])

  useEffect(() => {
    loadTenants()
  }, [])

  const loadTenants = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const data = await listTenants()
      setTenants(data)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load tenants'
      setError(errorMessage)
      if (errorMessage.includes('Admin access required') || errorMessage.includes('FORBIDDEN')) {
        showToast('Admin access required', 'error')
        navigate('/', { replace: true })
      }
    } finally {
      setIsLoading(false)
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

  const getStatusBadge = (status: string) => {
    const colors = {
      'Trial': 'bg-blue-500/20 text-blue-400',
      'Active': 'bg-green-500/20 text-green-400',
      'Paywalled': 'bg-destructive/20 text-destructive'
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
                {tenants.map((tenant) => (
                  <>
                    <tr key={tenant.id} className="border-b border-border/50 hover:bg-secondary/20">
                      <td className="px-4 py-3 text-sm">{tenant.name}</td>
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
                    {editingTenant === tenant.id && editForm && (
                      <tr>
                        <td colSpan={7} className="px-4 py-4 bg-secondary/10">
                          <div className="space-y-4">
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                              <div className="space-y-2">
                                <label className="text-xs font-medium text-foreground">Status</label>
                                <select
                                  value={editForm.status}
                                  onChange={(e) => setEditForm({ ...editForm, status: e.target.value as 'Trial' | 'Active' | 'Paywalled' })}
                                  className="w-full px-3 py-2 bg-background border border-input rounded-md text-foreground text-sm focus:outline-none focus:ring-2 focus:ring-ring"
                                >
                                  <option value="Trial">Trial</option>
                                  <option value="Active">Active</option>
                                  <option value="Paywalled">Paywalled</option>
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
                        </td>
                      </tr>
                    )}
                  </>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
