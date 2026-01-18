// API base URL for requirements analysis (ai-sr-business-req-analyst)
export const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000'

// API base URL for test plan generation (ai-testing-agent)
// eslint-disable-next-line @typescript-eslint/no-explicit-any
export const TEST_PLAN_API_BASE_URL = (import.meta as any).env?.VITE_TEST_PLAN_API_BASE_URL || 'http://localhost:5050'
