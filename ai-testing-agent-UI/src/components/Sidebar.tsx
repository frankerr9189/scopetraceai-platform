import { useState, useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { useLocation, useNavigate } from 'react-router-dom'
import { 
  FileText, 
  ListChecks, 
  FileCheck, 
  ClipboardList, 
  TestTube, 
  Layers,
  Menu,
  X,
  Download,
  FileDown,
  Sparkles,
  History,
  LogOut,
  Settings
} from 'lucide-react'
import { Button } from './ui/button'
import { useTenantStatus } from '../contexts/TenantStatusContext'

interface SidebarProps {
  activeTab: string
  onTabChange: (tab: string) => void
  onDownloadRTM?: () => void
  onDownloadTestPlan?: () => void
  hasData?: boolean
}

const topLevelNavItems = [
  {
    path: '/requirements',
    label: 'AI Sr Business Analyst Scope',
    icon: Sparkles
  },
  {
    path: '/',
    label: 'Generate Test Plan',
    icon: TestTube
  },
  {
    path: '/run-history',
    label: 'Run History',
    icon: History
  }
]

const navigationItems = [
  {
    id: 'tickets',
    label: 'Tickets',
    icon: FileText,
    group: 'Input'
  },
  {
    id: 'ticket-breakdown',
    label: 'Ticket Breakdown',
    icon: ClipboardList,
    group: 'Analysis'
  },
  {
    id: 'requirements',
    label: 'Requirements',
    icon: ListChecks,
    group: 'Analysis'
  },
  {
    id: 'rtm',
    label: 'RTM',
    icon: FileCheck,
    group: 'Results'
  },
  {
    id: 'tests-by-requirement',
    label: 'Tests (By Requirement)',
    icon: Layers,
    group: 'Results'
  },
  {
    id: 'tests-by-type',
    label: 'Tests (By Type)',
    icon: TestTube,
    group: 'Results'
  }
]

export function Sidebar({ 
  activeTab, 
  onTabChange, 
  onDownloadRTM, 
  onDownloadTestPlan,
  hasData = false 
}: SidebarProps) {
  const { tenantStatus, resetTenantContext, isLoading: isTenantLoading, isTenantContextReady } = useTenantStatus()
  const [isCollapsed, setIsCollapsed] = useState(false)
  const [hoveredGroup, setHoveredGroup] = useState<string | null>(null)
  const [isMobile, setIsMobile] = useState(false)
  const [userDisplayName, setUserDisplayName] = useState<string>('Anonymous')
  const [tenantName, setTenantName] = useState<string | null>(null)
  const [canSeeAdmin, setCanSeeAdmin] = useState(false)
  const location = useLocation()
  const navigate = useNavigate()
  const currentPath = location.pathname
  const isTestPlanPage = currentPath === '/'

  useEffect(() => {
    const checkMobile = () => {
      setIsMobile(window.innerWidth < 1024)
      if (window.innerWidth >= 1024) {
        setIsCollapsed(false) // Auto-expand on desktop
      } else {
        setIsCollapsed(true) // Auto-collapse on mobile
      }
    }
    
    checkMobile()
    window.addEventListener('resize', checkMobile)
    return () => window.removeEventListener('resize', checkMobile)
  }, [])

  // Load user info from localStorage
  useEffect(() => {
    const loadUserInfo = () => {
      const userStr = localStorage.getItem('user')
      if (userStr) {
        try {
          const user = JSON.parse(userStr)
          // Determine display name: first_name + last_name, or email, or Anonymous
          let displayName = 'Anonymous'
          if (user.first_name || user.last_name) {
            const parts = [user.first_name, user.last_name].filter(Boolean)
            displayName = parts.join(' ') || user.email || 'Anonymous'
          } else if (user.email) {
            displayName = user.email
          }
          setUserDisplayName(displayName)
          setTenantName(user.tenant_name || null)
          
          // Check if user can see admin link - only set to true if role is confirmed
          const role = user.role
          setCanSeeAdmin(role === 'owner' || role === 'superAdmin')
        } catch {
          setUserDisplayName('Anonymous')
          setTenantName(null)
          setCanSeeAdmin(false)
        }
      } else {
        setUserDisplayName('Anonymous')
        setTenantName(null)
        setCanSeeAdmin(false)
      }
    }
    
    // Load user info on mount
    loadUserInfo()
    
    // Listen for storage changes (in case user data changes in another tab)
    const handleStorageChange = () => {
      loadUserInfo()
    }
    
    // Listen for auth state changes in the same tab (login/register)
    const handleAuthStateChange = () => {
      loadUserInfo()
    }
    
    window.addEventListener('storage', handleStorageChange)
    window.addEventListener('auth-state-changed', handleAuthStateChange)
    
    return () => {
      window.removeEventListener('storage', handleStorageChange)
      window.removeEventListener('auth-state-changed', handleAuthStateChange)
    }
  }, [])


  const handleLogout = () => {
    // Explicitly reset admin visibility before clearing localStorage
    setCanSeeAdmin(false)
    
    // CRITICAL: Reset tenant context to clear any tenant-scoped state BEFORE clearing token
    resetTenantContext()
    
    // Clear localStorage
    localStorage.removeItem('access_token')
    localStorage.removeItem('user')
    localStorage.removeItem('authToken')
    localStorage.removeItem('actorName')
    // Clear any stored lastRoute if present
    localStorage.removeItem('lastRoute')
    
    // Redirect to login
    navigate('/login')
  }

  const groupedItems = navigationItems.reduce((acc, item) => {
    if (!acc[item.group]) {
      acc[item.group] = []
    }
    acc[item.group].push(item)
    return acc
  }, {} as Record<string, typeof navigationItems>)

  const groups = ['Input', 'Analysis', 'Results']

  return (
    <>
      {/* Mobile overlay */}
      <AnimatePresence>
        {!isCollapsed && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={() => setIsCollapsed(true)}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-40 lg:hidden"
          />
        )}
      </AnimatePresence>

      {/* Sidebar */}
      <motion.aside
        initial={false}
        animate={{
          width: isCollapsed && !isMobile ? '4rem' : '16rem',
          x: isMobile && isCollapsed ? '-100%' : 0
        }}
        transition={{ duration: 0.3, ease: [0.22, 1, 0.36, 1] }}
        className={`
          fixed left-0 top-0 h-screen z-50
          bg-gradient-to-br from-blue-950/50 via-blue-900/40 to-blue-800/30
          backdrop-blur-2xl border-r-2
          flex flex-col
          ${isCollapsed && !isMobile ? 'lg:w-16' : 'lg:w-64'}
          before:absolute before:inset-0 before:bg-gradient-to-br 
          before:from-blue-500/15 before:via-blue-400/10 before:to-blue-500/15
          before:pointer-events-none
          after:absolute after:inset-0 after:bg-gradient-to-r 
          after:from-transparent after:via-blue-400/10 after:to-transparent
          after:pointer-events-none
        `}
        style={{
          borderImage: 'linear-gradient(to bottom, rgba(59,130,246,0.4), rgba(96,165,250,0.3), rgba(59,130,246,0.4)) 1',
          boxShadow: '0 0 50px rgba(59,130,246,0.25), 4px 0 30px rgba(59,130,246,0.2), -4px 0 30px rgba(96,165,250,0.15), inset 0 0 80px rgba(59,130,246,0.06)'
        }}
      >
        {/* Header */}
        <div className="p-4 border-b border-gradient-to-r from-blue-500/40 via-blue-400/40 to-blue-500/40 relative overflow-hidden">
          {/* Animated background gradient */}
          <div className="absolute inset-0 bg-gradient-to-r from-blue-500/10 via-blue-400/8 to-blue-500/10 animate-pulse" />
          <div className="relative z-10 flex items-center justify-between">
            {!isCollapsed && (
              <motion.div
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                className="space-y-1"
              >
                <h2 className="text-sm font-bold bg-gradient-to-r from-blue-300 via-blue-400 to-blue-300 bg-clip-text text-transparent drop-shadow-[0_0_8px_rgba(59,130,246,0.5)]">
                  Navigation
                </h2>
                <p className="text-xs text-blue-300/80 font-mono tracking-wider">
                  ScopeTrace AI
                </p>
              </motion.div>
            )}
            <Button
              variant="ghost"
              onClick={() => setIsCollapsed(!isCollapsed)}
              className="ml-auto h-10 w-10 p-0 hover:bg-blue-500/20 hover:shadow-[0_0_15px_rgba(59,130,246,0.35)] transition-all rounded-lg border border-blue-400/30 hover:border-blue-400/70"
            >
              {isCollapsed ? (
                <Menu className="h-5 w-5 text-blue-300" />
              ) : (
                <X className="h-5 w-5 text-blue-300" />
              )}
            </Button>
          </div>
          {/* User info and logout */}
          {!isCollapsed && (
            <motion.div
              initial={{ opacity: 0, y: -5 }}
              animate={{ opacity: 1, y: 0 }}
              className="relative z-10 mt-3 pt-3 border-t border-blue-500/20 space-y-2"
            >
              <div className="space-y-1">
                <p className="text-xs text-blue-300/70 font-medium">
                  Signed in as <span className="text-blue-200/90">{userDisplayName}</span>
                </p>
                <p className="text-xs text-blue-300/50 font-normal">
                  Client: <span className="text-blue-200/70">
                    {!isTenantContextReady || isTenantLoading 
                      ? 'Loading…' 
                      : (tenantStatus?.tenant_name ?? tenantName ?? '—')}
                  </span>
                </p>
                {!isTenantContextReady || isTenantLoading ? (
                  <p className="text-xs text-blue-300/50 font-normal">
                    Plan: <span className="text-blue-200/70">Loading…</span>
                  </p>
                ) : tenantStatus && (
                  <>
                    <p className="text-xs text-blue-300/50 font-normal">
                      Plan: <span className="text-blue-200/70">{tenantStatus.subscription_status}</span>
                    </p>
                    {tenantStatus.subscription_status === 'trial' && (
                      <div className="text-xs text-blue-300/50 font-normal space-y-0.5">
                        <div>Requirements: {tenantStatus.trial_requirements_runs_remaining}</div>
                        <div>Test Plan: {tenantStatus.trial_testplan_runs_remaining}</div>
                        <div>Jira Writeback: {tenantStatus.trial_writeback_runs_remaining}</div>
                      </div>
                    )}
                  </>
                )}
              </div>
              <Button
                variant="ghost"
                size="sm"
                onClick={handleLogout}
                className="w-full justify-start gap-2 h-8 text-xs text-blue-300/70 hover:text-blue-200 hover:bg-blue-500/20 hover:shadow-[0_0_10px_rgba(59,130,246,0.25)] transition-all rounded-lg border border-transparent hover:border-blue-400/30"
              >
                <LogOut className="h-3.5 w-3.5" />
                Log out
              </Button>
              {/* Admin link - only show for owner/superAdmin */}
              {canSeeAdmin && (
                <Button
                  variant="ghost"
                  size="sm"
                  onClick={() => navigate('/admin')}
                  className="w-full justify-start gap-2 h-8 text-xs text-blue-300/70 hover:text-blue-200 hover:bg-blue-500/20 hover:shadow-[0_0_10px_rgba(59,130,246,0.25)] transition-all rounded-lg border border-transparent hover:border-blue-400/30"
                >
                  <Settings className="h-3.5 w-3.5" />
                  Admin
                </Button>
              )}
            </motion.div>
          )}
        </div>

        {/* Navigation */}
        <nav className="flex-1 overflow-y-auto p-4 space-y-6">
          {/* Top-level navigation */}
          <div className="space-y-2">
            {!isCollapsed && (
              <motion.h3
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="text-xs font-bold text-blue-300/90 uppercase tracking-wider px-2 mb-2 flex items-center gap-2"
              >
                <span className="w-1 h-1 rounded-full bg-gradient-to-r from-blue-400 to-blue-300 shadow-[0_0_6px_rgba(59,130,246,0.5)]" />
                Main
              </motion.h3>
            )}
            <div className="space-y-1">
              {topLevelNavItems.map((item) => {
                const Icon = item.icon
                const isActive = currentPath === item.path || (item.path === '/run-history' && currentPath.startsWith('/run-history'))
                
                return (
                  <motion.button
                    key={item.path}
                    onClick={() => {
                      navigate(item.path)
                      if (window.innerWidth < 1024) {
                        setIsCollapsed(true)
                      }
                    }}
                    onHoverStart={() => setHoveredGroup(item.path)}
                    onHoverEnd={() => setHoveredGroup(null)}
                    className={`
                      w-full flex items-center gap-3 px-3 py-2.5 rounded-lg
                      transition-all duration-300
                      relative overflow-hidden group
                      ${isActive 
                        ? 'bg-gradient-to-r from-blue-500/40 via-blue-400/30 to-blue-500/40 text-white shadow-[0_0_25px_rgba(59,130,246,0.35),inset_0_0_15px_rgba(59,130,246,0.1)] border border-blue-400/50' 
                        : 'text-blue-200/70 hover:text-white hover:bg-gradient-to-r hover:from-blue-500/25 hover:via-blue-400/15 hover:to-blue-500/25 hover:shadow-[0_0_15px_rgba(59,130,246,0.25)] hover:border hover:border-blue-400/30'
                      }
                    `}
                  >
                    {/* Active indicator */}
                    {isActive && (
                      <motion.div
                        layoutId="activeIndicator"
                        className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-blue-400 via-blue-300 to-blue-400 rounded-r-full shadow-[0_0_8px_rgba(59,130,246,0.6),0_0_15px_rgba(96,165,250,0.4)]"
                        transition={{ type: "spring", stiffness: 500, damping: 30 }}
                      />
                    )}

                    {/* Icon */}
                    <Icon className={`h-5 w-5 flex-shrink-0 transition-all duration-300 ${isActive ? 'text-white drop-shadow-[0_0_5px_rgba(59,130,246,0.5)]' : 'text-blue-300/70 group-hover:text-blue-200 group-hover:drop-shadow-[0_0_4px_rgba(59,130,246,0.3)]'}`} />
                    
                    {/* Label */}
                    {!isCollapsed && (
                      <motion.span
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        className="text-sm font-medium"
                      >
                        {item.label}
                      </motion.span>
                    )}

                    {/* Hover glow effect */}
                    {hoveredGroup === item.path && !isActive && (
                      <motion.div
                        initial={{ opacity: 0 }}
                        animate={{ opacity: 1 }}
                        exit={{ opacity: 0 }}
                        className="absolute inset-0 bg-gradient-to-r from-blue-500/15 via-blue-400/10 to-blue-500/15 pointer-events-none rounded-lg"
                      />
                    )}
                  </motion.button>
                )
              })}
            </div>
          </div>

          {/* Test Plan tabs - only show on test plan page */}
          {isTestPlanPage && groups.map((group) => (
            <div key={group} className="space-y-2">
              {!isCollapsed && (
                <motion.h3
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  className="text-xs font-bold text-blue-300/90 uppercase tracking-wider px-2 mb-2 flex items-center gap-2"
                >
                  <span className="w-1 h-1 rounded-full bg-gradient-to-r from-blue-400 to-blue-300 shadow-[0_0_6px_rgba(59,130,246,0.5)]" />
                  {group}
                </motion.h3>
              )}
              <div className="space-y-1">
                {groupedItems[group]?.map((item) => {
                  const Icon = item.icon
                  const isActive = activeTab === item.id
                  
                  return (
                    <motion.button
                      key={item.id}
                      onClick={() => {
                        onTabChange(item.id)
                        if (window.innerWidth < 1024) {
                          setIsCollapsed(true)
                        }
                      }}
                      onHoverStart={() => setHoveredGroup(item.id)}
                      onHoverEnd={() => setHoveredGroup(null)}
                      className={`
                        w-full flex items-center gap-3 px-3 py-2.5 rounded-lg
                        transition-all duration-300
                        relative overflow-hidden group
                        ${isActive 
                          ? 'bg-gradient-to-r from-blue-500/40 via-blue-400/30 to-blue-500/40 text-white shadow-[0_0_25px_rgba(59,130,246,0.35),inset_0_0_15px_rgba(59,130,246,0.1)] border border-blue-400/50' 
                          : 'text-blue-200/70 hover:text-white hover:bg-gradient-to-r hover:from-blue-500/25 hover:via-blue-400/15 hover:to-blue-500/25 hover:shadow-[0_0_15px_rgba(59,130,246,0.25)] hover:border hover:border-blue-400/30'
                        }
                      `}
                    >
                      {/* Active indicator */}
                      {isActive && (
                        <motion.div
                          layoutId="activeIndicator"
                          className="absolute left-0 top-0 bottom-0 w-1 bg-gradient-to-b from-blue-400 via-blue-300 to-blue-400 rounded-r-full shadow-[0_0_8px_rgba(59,130,246,0.6),0_0_15px_rgba(96,165,250,0.4)]"
                          transition={{ type: "spring", stiffness: 500, damping: 30 }}
                        />
                      )}

                      {/* Icon */}
                      <Icon className={`h-5 w-5 flex-shrink-0 transition-all duration-300 ${isActive ? 'text-white drop-shadow-[0_0_5px_rgba(59,130,246,0.5)]' : 'text-blue-300/70 group-hover:text-blue-200 group-hover:drop-shadow-[0_0_4px_rgba(59,130,246,0.3)]'}`} />
                      
                      {/* Label */}
                      {!isCollapsed && (
                        <motion.span
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          className="text-sm font-medium"
                        >
                          {item.label}
                        </motion.span>
                      )}

                      {/* Hover glow effect */}
                      {hoveredGroup === item.id && !isActive && (
                        <motion.div
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          exit={{ opacity: 0 }}
                          className="absolute inset-0 bg-gradient-to-r from-blue-500/15 via-blue-400/10 to-blue-500/15 pointer-events-none rounded-lg"
                        />
                      )}
                    </motion.button>
                  )
                })}
              </div>
            </div>
          ))}
        </nav>

        {/* Quick Actions */}
        {hasData && !isCollapsed && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="p-4 border-t border-gradient-to-r from-blue-500/40 via-blue-400/40 to-blue-500/40 space-y-2 relative overflow-hidden"
          >
            {/* Animated background */}
            <div className="absolute inset-0 bg-gradient-to-r from-blue-500/10 via-blue-400/8 to-blue-500/10" />
            <div className="relative z-10">
              <h3 className="text-xs font-bold text-blue-300/90 uppercase tracking-wider px-2 mb-2 flex items-center gap-2">
                <span className="w-1 h-1 rounded-full bg-gradient-to-r from-blue-400 to-blue-300 shadow-[0_0_10px_rgba(59,130,246,0.8)]" />
                Export
              </h3>
              <Button
                variant="outline"
                size="sm"
                onClick={onDownloadRTM}
                className="w-full justify-start gap-2 bg-gradient-to-r from-blue-500/25 to-blue-400/15 hover:from-blue-500/35 hover:to-blue-400/25 border-blue-400/40 hover:border-blue-400/60 text-blue-200 hover:text-white transition-all hover:shadow-[0_0_25px_rgba(59,130,246,0.5)]"
              >
                <Download className="h-4 w-4" />
                Download RTM
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={onDownloadTestPlan}
                className="w-full justify-start gap-2 bg-gradient-to-r from-blue-500/25 to-blue-400/15 hover:from-blue-500/35 hover:to-blue-400/25 border-blue-400/40 hover:border-blue-400/60 text-blue-200 hover:text-white transition-all hover:shadow-[0_0_25px_rgba(59,130,246,0.5)]"
              >
                <FileDown className="h-4 w-4" />
                Download Test Plan
              </Button>
            </div>
          </motion.div>
        )}

        {/* Collapsed quick actions */}
        {hasData && isCollapsed && (
          <div className="p-2 border-t border-blue-500/40 space-y-2">
            <Button
              variant="ghost"
              onClick={onDownloadRTM}
              className="w-full h-10 w-10 p-0 hover:bg-blue-500/25 hover:shadow-[0_0_12px_rgba(59,130,246,0.3)] border border-transparent hover:border-blue-400/40 transition-all"
              title="Download RTM"
            >
              <Download className="h-4 w-4 text-blue-300" />
            </Button>
            <Button
              variant="ghost"
              onClick={onDownloadTestPlan}
              className="w-full h-10 w-10 p-0 hover:bg-blue-500/25 hover:shadow-[0_0_12px_rgba(59,130,246,0.3)] border border-transparent hover:border-blue-400/40 transition-all"
              title="Download Test Plan"
            >
              <FileDown className="h-4 w-4 text-blue-300" />
            </Button>
          </div>
        )}
      </motion.aside>

      
      {/* Mobile menu button - show when sidebar is collapsed on mobile */}
      {isCollapsed && (
        <motion.button
          initial={{ opacity: 0, scale: 0.8 }}
          animate={{ opacity: 1, scale: 1 }}
          onClick={() => setIsCollapsed(false)}
          className="fixed top-4 left-4 z-50 lg:hidden p-3 rounded-lg bg-gradient-to-br from-blue-500/40 via-blue-400/30 to-blue-500/40 backdrop-blur-xl border-2 border-blue-400/50 hover:border-blue-400/70 hover:bg-gradient-to-br hover:from-blue-500/50 hover:via-blue-400/40 hover:to-blue-500/50 transition-all shadow-[0_0_25px_rgba(59,130,246,0.3)] hover:shadow-[0_0_35px_rgba(59,130,246,0.4)]"
        >
          <Menu className="h-6 w-6 text-blue-200 drop-shadow-[0_0_5px_rgba(59,130,246,0.5)]" />
        </motion.button>
      )}
    </>
  )
}
