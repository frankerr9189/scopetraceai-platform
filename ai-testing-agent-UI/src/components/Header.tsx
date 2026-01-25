import { motion } from 'framer-motion'
import { useLocation } from 'react-router-dom'

export function Header() {
  const location = useLocation()
  const isRequirementsPage = location.pathname === '/requirements'
  const isRunHistoryPage = location.pathname.startsWith('/run-history')
  const isAdminPage = location.pathname.startsWith('/admin')
  const isProfilePage = location.pathname === '/profile'
  
  return (
    <motion.header
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ 
        duration: 0.4,
        ease: [0.22, 1, 0.36, 1]
      }}
      className="w-full bg-black/60 backdrop-blur-xl border-b border-white/10 pb-12 pt-16 mb-12 shadow-[0_1px_0_0_rgba(255,255,255,0.05)]"
    >
      <div className="container mx-auto px-4 sm:px-6 lg:px-8 max-w-7xl">
        <div className="space-y-4">
          {isAdminPage ? (
            <h1 className="text-5xl font-bold tracking-tight bg-gradient-to-r from-foreground via-foreground/90 to-foreground/70 bg-clip-text text-transparent drop-shadow-[0_0_20px_rgba(255,255,255,0.3)]">
              Account Administration
            </h1>
          ) : (
            <>
              <h1 className="text-5xl font-bold tracking-tight bg-gradient-to-r from-foreground via-foreground/90 to-foreground/70 bg-clip-text text-transparent drop-shadow-[0_0_20px_rgba(255,255,255,0.3)]">
                {isRequirementsPage 
                  ? 'AI Sr Business Analyst Scope' 
                  : isRunHistoryPage 
                  ? 'Run History' 
                  : isProfilePage
                  ? 'Profile'
                  : 'Test Plan Creation Agent'}
              </h1>
              <p className="text-lg text-muted-foreground font-light">
                {isRequirementsPage 
                  ? 'Generate Normalized, consistent requirements from text, Jira, or documents.'
                  : isRunHistoryPage
                  ? 'View past test plan generation runs and their artifacts'
                  : isProfilePage
                  ? 'Manage your account, security, and subscription'
                  : 'Autonomous test intelligence & traceability - Powered by AI'
                }
              </p>
              <p className="text-xs text-muted-foreground/60 font-mono tracking-wider uppercase flex items-center gap-2">
                <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                ISO-READY • RISK-AWARE • DETERMINISTIC
              </p>
            </>
          )}
        </div>
      </div>
    </motion.header>
  )
}

