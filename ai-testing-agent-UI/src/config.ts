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
  // Always check for env vars first (they should be set in production)
  const envBase = import.meta.env.VITE_API_BASE || import.meta.env.VITE_TEST_PLAN_API_BASE_URL
  
  if (envBase) {
    // Log in both dev and prod so we can debug production issues
    console.log('[Config] Using API Base URL from env:', envBase)
    return envBase
  }
  
  // Check for production mode or production-like environment
  const isProduction = import.meta.env.MODE === 'production' || 
                       import.meta.env.PROD === true ||
                       (typeof window !== 'undefined' && 
                        window.location.hostname !== 'localhost' && 
                        window.location.hostname !== '127.0.0.1' &&
                        !window.location.hostname.startsWith('192.168.') &&
                        !window.location.hostname.startsWith('10.') &&
                        !window.location.hostname.startsWith('172.'))
  
  // If no env var is set and we're in production, try to infer from current hostname
  if (isProduction && typeof window !== 'undefined') {
    const protocol = window.location.protocol
    const hostname = window.location.hostname
    
    // Try common production patterns:
    // 1. If on vercel.app or scopetraceai domain, try common backend URLs
    if (hostname.includes('vercel.app') || hostname.includes('scopetraceai')) {
      // Try api.scopetraceai.com first (common API subdomain pattern)
      // If that doesn't work, the actual URL might be on Render (e.g., ai-testing-agent.onrender.com)
      // TODO: Set VITE_API_BASE to the actual backend URL in production
      const possibleUrls = [
        'https://api.scopetraceai.com',
        'https://ai-testing-agent.onrender.com', // Based on other service patterns
      ]
      const inferredBase = possibleUrls[0] // Try api.scopetraceai.com first
      console.warn(`VITE_API_BASE or VITE_TEST_PLAN_API_BASE_URL not set. Trying inferred URL: ${inferredBase}`)
      console.warn('If this fails, please set VITE_API_BASE environment variable at build time.')
      console.warn(`Other possible URLs: ${possibleUrls.slice(1).join(', ')}`)
      return inferredBase
    }
    
    // 2. Try api subdomain pattern
    if (hostname.includes('.')) {
      const parts = hostname.split('.')
      // If hostname is like "app.example.com", try "api.example.com"
      if (parts.length >= 2) {
        const domain = parts.slice(-2).join('.') // Get last two parts (example.com)
        const inferredBase = `${protocol}//api.${domain}`
        console.warn(`VITE_API_BASE or VITE_TEST_PLAN_API_BASE_URL not set. Trying inferred URL: ${inferredBase}`)
        console.warn('Please set VITE_API_BASE environment variable at build time for proper configuration.')
        return inferredBase
      }
    }
    
    // 3. Last resort: same hostname (won't work for Vercel but might work for other hosts)
    const inferredBase = `${protocol}//${hostname}`
    console.warn(`VITE_API_BASE or VITE_TEST_PLAN_API_BASE_URL not set. Using inferred URL: ${inferredBase}`)
    console.warn('Please set VITE_API_BASE environment variable at build time for proper configuration.')
    return inferredBase
  }
  
  // In development, allow localhost fallback
  return 'http://localhost:5050'
}

export const TEST_PLAN_API_BASE_URL = getTestPlanAPIBase()

// Log the API base URL for debugging (both dev and prod)
console.log('[Config] Final TEST_PLAN_API_BASE_URL:', TEST_PLAN_API_BASE_URL)
console.log('[Config] VITE_API_BASE env var:', import.meta.env.VITE_API_BASE || 'not set')
console.log('[Config] VITE_TEST_PLAN_API_BASE_URL env var:', import.meta.env.VITE_TEST_PLAN_API_BASE_URL || 'not set')
console.log('[Config] MODE:', import.meta.env.MODE)
