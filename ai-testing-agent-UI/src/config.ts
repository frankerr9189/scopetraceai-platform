// API base URL for requirements analysis (ai-sr-business-req-analyst)
// Service runs on port 8000 in development
// Primary: VITE_API_BASE (shared base URL for all services)
// Fallback: VITE_API_BASE_URL (backward compatibility)
const getRequirementsAPIBase = (): string => {
  // In production, require env var
  if (import.meta.env.MODE === 'production') {
    const base = import.meta.env.VITE_API_BASE || import.meta.env.VITE_API_BASE_URL
    if (!base) {
      throw new Error('VITE_API_BASE must be set in production')
    }
    return base
  }
  // In development, allow localhost fallback
  return import.meta.env.VITE_API_BASE || import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'
}

export const API_BASE_URL = getRequirementsAPIBase()

// API base URL for test plan generation (ai-testing-agent)
// Service runs on port 5050 in development
// Primary: VITE_API_BASE (shared base URL for all services)
// Fallback: VITE_TEST_PLAN_API_BASE_URL (if separate service deployment needed)
const getTestPlanAPIBase = (): string => {
  // In production, require env var
  if (import.meta.env.MODE === 'production') {
    const base = import.meta.env.VITE_API_BASE || import.meta.env.VITE_TEST_PLAN_API_BASE_URL
    if (!base) {
      throw new Error('VITE_API_BASE must be set in production')
    }
    return base
  }
  // In development, allow localhost fallback
  return import.meta.env.VITE_API_BASE || import.meta.env.VITE_TEST_PLAN_API_BASE_URL || 'http://localhost:5050'
}

export const TEST_PLAN_API_BASE_URL = getTestPlanAPIBase()
