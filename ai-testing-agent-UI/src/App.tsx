import { useState, useEffect } from 'react'
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom'
import { Header } from './components/Header'
import { Background } from './components/Background'
import { Sidebar } from './components/Sidebar'
import { TestPlanPage } from './components/TestPlanPage'
import { RequirementsPage } from './components/RequirementsPage'
import { RunHistoryPage } from './components/RunHistoryPage'
import { LoginPage } from './components/LoginPage'
import { RegisterPage } from './components/RegisterPage'
import { JiraOnboardingPage } from './components/JiraOnboardingPage'
import { FirstRunOnboardingPage } from './components/FirstRunOnboardingPage'
import { PlanSelectionPage } from './components/PlanSelectionPage'
import { ActivationPage } from './components/ActivationPage'
import { AdminPage } from './components/AdminPage'
import { ToastContainer } from './components/Toast'
import { TenantStatusProvider, useTenantStatus } from './contexts/TenantStatusContext'
import { downloadRTM, downloadTestPlan, TestPlanResponse } from './services/api'

/**
 * Protected route component that checks for auth token.
 * Redirects to login if not authenticated.
 */
function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const location = useLocation()
  const accessToken = localStorage.getItem('access_token')
  
  if (!accessToken) {
    // Redirect to login, preserving the attempted route
    return <Navigate to="/login" state={{ from: location }} replace />
  }
  
  return <>{children}</>
}

function AppContent() {
  const [testPlanData, setTestPlanData] = useState<TestPlanResponse | null>(null)
  const [activeTab, setActiveTab] = useState('tickets')
  const [sidebarPadding, setSidebarPadding] = useState(256)
  const location = useLocation()
  const { isTenantContextReady } = useTenantStatus()
  
  // Check if user is authenticated
  const accessToken = localStorage.getItem('access_token')
  const isAuthenticated = !!accessToken
  
  // Gate: Don't render tenant-scoped UI until tenant context is ready
  // If logged in, wait for tenant data to load. If logged out, ready immediately.
  const shouldRenderTenantUI = !isAuthenticated || (isAuthenticated && isTenantContextReady)
  
  useEffect(() => {
    const updatePadding = () => {
      setSidebarPadding(window.innerWidth >= 1024 ? 256 : 0)
    }
    updatePadding()
    window.addEventListener('resize', updatePadding)
    return () => window.removeEventListener('resize', updatePadding)
  }, [])
  
  // Hide sidebar and header on login, register, and onboarding pages
  const isLoginPage = location.pathname === '/login'
  const isRegisterPage = location.pathname === '/register'
  const isOnboardingPage = location.pathname.startsWith('/onboarding')
  const isAuthPage = isLoginPage || isRegisterPage || isOnboardingPage

  const handleDownloadRTM = async () => {
    try {
      const blob = await downloadRTM()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'rtm.csv'
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (err) {
      // Handle error silently or show notification
    }
  }

  const handleDownloadTestPlan = async () => {
    try {
      const blob = await downloadTestPlan()
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = 'test-plan.json'
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (err) {
      // Handle error silently or show notification
    }
  }

  return (
    <div className="min-h-screen relative">
      <Background />
      {!isAuthPage && shouldRenderTenantUI && (
        <>
          <Sidebar
            activeTab={activeTab}
            onTabChange={setActiveTab}
            onDownloadRTM={handleDownloadRTM}
            onDownloadTestPlan={handleDownloadTestPlan}
            hasData={!!testPlanData}
          />
          <div 
            className="relative z-10" 
            style={{ 
              marginLeft: `${sidebarPadding + 8}px`,
              paddingTop: '0',
              marginTop: '0'
            }}
          >
            <Header />
          </div>
        </>
      )}
      {/* Show loading state while tenant context is being prepared */}
      {!isAuthPage && !shouldRenderTenantUI && (
        <div className="min-h-screen flex items-center justify-center">
          <div className="text-center">
            <div className="text-lg text-foreground/70 mb-2">Loading…</div>
            <div className="text-sm text-muted-foreground">Preparing your workspace</div>
          </div>
        </div>
      )}
      <div 
        className="relative z-10" 
        style={{ 
          marginLeft: isAuthPage ? '0' : `${sidebarPadding + 8}px`,
          paddingTop: '0',
          marginTop: '0'
        }}
      >
        <div className="container mx-auto px-4 sm:px-6 lg:px-8 pb-8 max-w-7xl">
          <Routes>
            <Route path="/login" element={<LoginPage />} />
            <Route path="/register" element={<RegisterPage />} />
            <Route 
              path="/onboarding/jira" 
              element={
                <ProtectedRoute>
                  <JiraOnboardingPage />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/onboarding/first-run" 
              element={
                <ProtectedRoute>
                  <FirstRunOnboardingPage />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/onboarding/plan" 
              element={
                <ProtectedRoute>
                  <PlanSelectionPage />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/onboarding/activate" 
              element={
                <ProtectedRoute>
                  <ActivationPage />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/" 
              element={
                <ProtectedRoute>
                  <TestPlanPage 
                    testPlanData={testPlanData}
                    setTestPlanData={setTestPlanData}
                    activeTab={activeTab}
                    setActiveTab={setActiveTab}
                  />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/requirements" 
              element={
                <ProtectedRoute>
                  <RequirementsPage />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/run-history" 
              element={
                <ProtectedRoute>
                  <RunHistoryPage />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/run-history/:runId" 
              element={
                <ProtectedRoute>
                  <RunHistoryPage />
                </ProtectedRoute>
              } 
            />
            <Route 
              path="/admin" 
              element={
                <ProtectedRoute>
                  <AdminPage />
                </ProtectedRoute>
              } 
            />
          </Routes>
        </div>
      </div>
    </div>
  )
}

function App() {
  return (
    <TenantStatusProvider>
      <BrowserRouter>
        <AppContent />
        <ToastContainer />
      </BrowserRouter>
    </TenantStatusProvider>
  )
}

export default App
