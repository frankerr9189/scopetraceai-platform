import { createContext, useContext, useState, useEffect, useCallback, ReactNode, useRef } from 'react'
import { getTenantStatus, getBootstrapStatus, type TenantStatus, type BootstrapStatus } from '../services/api'

interface TenantStatusContextType {
  tenantStatus: TenantStatus | null
  bootstrapStatus: BootstrapStatus | null
  isLoading: boolean
  isTenantContextReady: boolean // true when tenant data has been fetched for current token (or no token)
  error: Error | null
  refreshTenantStatus: () => Promise<void>
  refreshBootstrapStatus: () => Promise<void>
  resetTenantContext: () => void
}

const TenantStatusContext = createContext<TenantStatusContextType | undefined>(undefined)

export function TenantStatusProvider({ children }: { children: ReactNode }) {
  const [tenantStatus, setTenantStatus] = useState<TenantStatus | null>(null)
  const [bootstrapStatus, setBootstrapStatus] = useState<BootstrapStatus | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [isTenantContextReady, setIsTenantContextReady] = useState(false)
  const [error, setError] = useState<Error | null>(null)
  
  // Track current tenant_id to detect tenant changes
  const currentTenantIdRef = useRef<string | null>(null)

  const resetTenantContext = useCallback(() => {
    setTenantStatus(null)
    setBootstrapStatus(null)
    setIsTenantContextReady(false)
    currentTenantIdRef.current = null
    setError(null)
  }, [])

  const refreshTenantStatus = useCallback(async () => {
    const accessToken = localStorage.getItem('access_token')
    if (!accessToken) {
      setTenantStatus(null)
      setBootstrapStatus(null)
      setIsLoading(false)
      setIsTenantContextReady(true) // Ready when logged out
      return
    }

    try {
      setIsLoading(true)
      setError(null)
      const data = await getTenantStatus()
      setTenantStatus(data)
      
      // Mark as ready after successful fetch
      setIsTenantContextReady(true)
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to fetch tenant status'))
      // Don't clear tenantStatus on error - keep last known state
      // But still mark as ready so UI can render (with error state)
      setIsTenantContextReady(true)
    } finally {
      setIsLoading(false)
    }
  }, [])

  const refreshBootstrapStatus = useCallback(async () => {
    const accessToken = localStorage.getItem('access_token')
    if (!accessToken) {
      setBootstrapStatus(null)
      return
    }

    try {
      setError(null)
      const data = await getBootstrapStatus()
      
      // Safety check: detect tenant_id changes
      const newTenantId = data.tenant_id
      if (currentTenantIdRef.current !== null && currentTenantIdRef.current !== newTenantId) {
        // Tenant changed! Reset and refetch
        if (import.meta.env.NODE_ENV === 'development') {
          console.warn('[TenantStatusContext] Tenant ID changed, resetting context', {
            old: currentTenantIdRef.current,
            new: newTenantId
          })
        }
        resetTenantContext()
        // Refetch both statuses
        const tenantData = await getTenantStatus()
        setTenantStatus(tenantData)
        const bootstrapData = await getBootstrapStatus()
        setBootstrapStatus(bootstrapData)
        currentTenantIdRef.current = bootstrapData.tenant_id
        setIsTenantContextReady(true)
      } else {
        setBootstrapStatus(data)
        currentTenantIdRef.current = newTenantId
      }
    } catch (err) {
      setError(err instanceof Error ? err : new Error('Failed to fetch bootstrap status'))
      // Don't clear bootstrapStatus on error - keep last known state
    }
  }, [resetTenantContext])

  // Initial load - only if we have a token
  useEffect(() => {
    const accessToken = localStorage.getItem('access_token')
    if (accessToken) {
      refreshTenantStatus()
      refreshBootstrapStatus()
    } else {
      // No token = ready (logged out state)
      setIsTenantContextReady(true)
      setIsLoading(false)
    }
  }, [refreshTenantStatus, refreshBootstrapStatus])

  // Listen for refresh events (from existing refreshTenantStatus() function)
  useEffect(() => {
    const handleRefresh = () => {
      refreshTenantStatus()
      refreshBootstrapStatus()
    }
    window.addEventListener('refresh-tenant-status', handleRefresh)
    return () => window.removeEventListener('refresh-tenant-status', handleRefresh)
  }, [refreshTenantStatus, refreshBootstrapStatus])

  return (
    <TenantStatusContext.Provider value={{ 
      tenantStatus, 
      bootstrapStatus, 
      isLoading, 
      isTenantContextReady,
      error, 
      refreshTenantStatus, 
      refreshBootstrapStatus,
      resetTenantContext
    }}>
      {children}
    </TenantStatusContext.Provider>
  )
}

export function useTenantStatus() {
  const context = useContext(TenantStatusContext)
  if (context === undefined) {
    throw new Error('useTenantStatus must be used within a TenantStatusProvider')
  }
  return context
}
