// API base URL for requirements analysis (ai-sr-business-req-analyst)
// Use VITE_API_BASE_URL for backward compatibility, but prefer VITE_API_BASE
const getRequirementsAPIBase = (): string => {
  // In production, require env var
  if (import.meta.env.MODE === 'production') {
    const base = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_BASE
    if (!base) {
      throw new Error('VITE_API_BASE_URL or VITE_API_BASE must be set in production')
    }
    return base
  }
  // In development, allow localhost fallback
  return import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_BASE || 'http://localhost:8000'
}

export const API_BASE_URL = getRequirementsAPIBase()

// API base URL for test plan generation (ai-testing-agent)
// Primary: VITE_API_BASE (set in Vercel Production)
// Fallback: VITE_TEST_PLAN_API_BASE_URL (backward compatibility)
// Development: localhost:5050
const getTestPlanAPIBase = (): string => {
  // In production, require env var
  if (import.meta.env.MODE === 'production') {
    const base = import.meta.env.VITE_API_BASE || import.meta.env.VITE_TEST_PLAN_API_BASE_URL
    if (!base) {
      throw new Error('VITE_API_BASE or VITE_TEST_PLAN_API_BASE_URL must be set in production')
    }
    return base
  }
  // In development, allow localhost fallback
  return import.meta.env.VITE_API_BASE || import.meta.env.VITE_TEST_PLAN_API_BASE_URL || 'http://localhost:5050'
}

export const TEST_PLAN_API_BASE_URL = getTestPlanAPIBase()
