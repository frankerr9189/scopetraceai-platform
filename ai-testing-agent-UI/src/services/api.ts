import { API_BASE_URL, TEST_PLAN_API_BASE_URL } from '../config'

// ---------------------------------------------------------------------------
// Tenant status (Account Status in sidebar)
// ---------------------------------------------------------------------------

export interface TenantStatus {
  tenant_id: string
  tenant_name: string
  subscription_status: 'unselected' | 'trial' | 'individual' | 'team' | 'paywalled' | 'canceled'
  trial_requirements_runs_remaining: number
  trial_testplan_runs_remaining: number
  trial_writeback_runs_remaining: number
}

export interface BootstrapStatus {
  tenant_id: string
  subscription_status: 'unselected' | 'trial' | 'individual' | 'team' | 'paywalled' | 'canceled'
  trial: {
    requirements: number
    testplan: number
    writeback: number
  }
  jira: {
    configured: boolean
    is_active: boolean
    jira_base_url: string | null
    jira_user_email: string | null
  }
}

export async function getTenantStatus(): Promise<TenantStatus> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/tenant/status`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to fetch tenant status: ${response.statusText}`)
  }

  return response.json()
}

export async function getBootstrapStatus(): Promise<BootstrapStatus> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/tenant/bootstrap-status`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to fetch bootstrap status: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Notify the sidebar (and any listeners) to refresh tenant status.
 * Call after successful: requirements generation, test plan generation, jira writeback execute.
 */
export function refreshTenantStatus(): void {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('refresh-tenant-status'))
  }
}

/**
 * Get auth headers for API requests.
 * Returns Authorization header from localStorage access_token.
 */
function getAuthHeaders(): HeadersInit {
  const headers = new Headers()
  headers.set('Content-Type', 'application/json')
  
  const accessToken = localStorage.getItem('access_token')
  
  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`)
  }
  
  // Get user info for X-Actor header (backward compatibility)
  const userStr = localStorage.getItem('user')
  if (userStr) {
    try {
      const user = JSON.parse(userStr)
      // Use first_name + last_name, or email, or 'anonymous' as fallback
      let actorName = 'anonymous'
      if (user.first_name || user.last_name) {
        const parts = [user.first_name, user.last_name].filter(Boolean)
        actorName = parts.join(' ') || user.email || 'anonymous'
      } else if (user.email) {
        actorName = user.email
      }
      headers.set('X-Actor', actorName)
    } catch {
      headers.set('X-Actor', 'anonymous')
    }
  } else {
    headers.set('X-Actor', 'anonymous')
  }
  
  return headers
}

/**
 * Handle 401 Unauthorized responses by clearing auth and redirecting to login.
 */
function handleUnauthorized() {
  localStorage.removeItem('access_token')
  localStorage.removeItem('user')
  // Redirect to login, preserving the attempted route
  const currentPath = window.location.pathname
  if (currentPath !== '/login') {
    window.location.href = `/login?from=${encodeURIComponent(currentPath)}`
  }
}

/**
 * Handle API errors, including PAYWALLED responses.
 * Returns the error data if PAYWALLED, null otherwise.
 * Note: This function consumes the response body, so callers should clone the response first.
 */
async function handleApiError(response: Response): Promise<{ error: string; message: string; code?: string } | null> {
  // Check if this is a Jira meta endpoint - skip global toasts for Jira configuration errors
  // RequirementsPage handles displaying these errors locally with a banner
  const isJiraMetaRequest = response.url && response.url.includes('/api/v1/jira/meta')
  
  // Handle 400 errors from Jira meta endpoints (Jira not configured)
  if (response.status === 400 && isJiraMetaRequest) {
    try {
      const errorData = await response.json().catch(() => ({}))
      // Don't show global toast - RequirementsPage will handle this with a banner
      return errorData
    } catch {
      // If JSON parsing fails, continue with normal error handling
    }
  }
  
  if (response.status === 403) {
    try {
      const errorData = await response.json().catch(() => ({}))
      
      // Check if this is a login request - skip global toasts for login errors
      // LoginPage.tsx handles displaying these errors
      const isLoginRequest = response.url && response.url.includes('/auth/login')
      
      // Handle PAYWALLED errors
      if (errorData.error === 'PAYWALLED') {
        // Show toast notification
        const { showToast } = await import('../components/Toast')
        const message = errorData.message || 'Trial limit reached. Activate subscription to continue.'
        showToast(message, 'error')
        
        // Refresh tenant status to update sidebar
        refreshTenantStatus()
        
        return errorData // Return error data for caller
      }
      
      // Handle USER_INACTIVE errors
      if (errorData.code === 'USER_INACTIVE') {
        // Skip toast for login requests - LoginPage handles the error display
        if (!isLoginRequest) {
          const { showToast } = await import('../components/Toast')
          const message = errorData.detail || 'Your account is inactive. Contact hello@scopetraceai.com'
          showToast(message, 'error')
        }
        return errorData
      }
      
      // Handle TENANT_INACTIVE errors
      if (errorData.code === 'TENANT_INACTIVE') {
        // Skip toast for login requests - LoginPage handles the error display
        if (!isLoginRequest) {
          const { showToast } = await import('../components/Toast')
          const message = errorData.detail || 'Workspace is inactive. Contact hello@scopetraceai.com'
          showToast(message, 'error')
        }
        return errorData
      }
      
      // Handle JIRA_NOT_CONFIGURED errors - don't show global toast for Jira meta requests
      // RequirementsPage handles this locally with a banner
      if (errorData.code === 'JIRA_NOT_CONFIGURED' && isJiraMetaRequest) {
        // Don't show global toast - RequirementsPage will handle this
        return errorData
      }
    } catch {
      // If JSON parsing fails, continue with normal error handling
    }
  }
  return null // Error was not handled
}

export interface TicketInput {
  ticket_id: string
}

export interface AuditMetadata {
  run_id: string
  generated_at: string
  agent_version: string
  model: {
    name: string
    temperature: number
    response_format: string
  }
  environment: string
  source: {
    type: string
    ticket_count: number
    scope_type: string
    scope_id: string
  }
  algorithms: {
    test_generation: string
    coverage_analysis: string
    quality_scoring: string
    confidence_calculation: string
  }
  agent_metadata?: {
    agent: string
    agent_version: string
    logic_version: string
    determinism: string
    change_policy: string
  }
}

export interface TestPlanResponse {
  schema_version: string
  metadata: {
    source: string
    source_id: string
    generated_at: string
  }
  requirements: Requirement[]
  business_intent: string
  assumptions: string[]
  gaps_detected: Gap[]
  test_plan: {
    api_tests: TestCase[]
    ui_tests: TestCase[]
    data_validation_tests: TestCase[]
    edge_cases: TestCase[]
    negative_tests: TestCase[]
  }
  rtm: RTMEntry[]
  summary: string
  scope_summary?: {
    scope_type: string
    scope_id: string
    tickets_analyzed: number
    tickets_requested: number
    tickets_failed: number
    requirements_total: number
    requirements_covered: number
    requirements_uncovered: number
    ticket_details?: Array<{
      ticket_id: string
      summary: string
      description: string
      requirements_count: number
      has_explicit_requirements: boolean
      has_acceptance_criteria: boolean
      explanation?: string
      status: string
    }>
    failed_tickets?: Array<{
      ticket_id: string
      reason: string
      status: string
      summary?: string
      description?: string
    }>
  }
  audit_metadata?: AuditMetadata
  test_plan_by_requirement?: Array<{
    requirement_id: string
    requirement_text: string
    requirement_source: 'jira' | 'inferred'
    quality?: Requirement['quality']
    coverage_confidence?: Requirement['coverage_confidence']
    coverage_expectations?: Requirement['coverage_expectations']
    tests: {
      happy_path: TestCase[]
      negative: TestCase[]
      boundary: TestCase[]
      authorization: TestCase[]
      other: TestCase[]
    }
  }>
  ticket_traceability?: Array<{
    ticket_id: string
    items: Array<{
      item_id: string
      text: string
      classification: 'primary_requirement' | 'acceptance_criterion' | 'boundary_condition' | 'negative_condition' | 'technical_constraint' | 'informational_only' | 'unclear_needs_clarification' | 'system_behavior'
      source_section: string
      mapped_requirement_id?: string
      validated_by_tests?: string[]
      testable?: boolean
      note?: string
    }>
  }>
}

export interface Requirement {
  id: string
  source: 'jira' | 'inferred'
  description: string
  quality?: {
    clarity_score: number
    testability_score: number
    issues: string[]
  }
  coverage_expectations?: {
    happy_path: string
    negative: string
    boundary: string
    authorization: string
    data_validation: string
    stateful: string
  }
  coverage_confidence?: {
    score: number
    level: 'low' | 'medium' | 'high'
    reasons: string[]
  }
}

export interface TestCase {
  id: string
  title: string
  source_requirement_id?: string
  intent_type?: 'happy_path' | 'negative' | 'authorization' | 'boundary'
  requirements_covered: string[]
  steps: string[]
  steps_explanation?: string
  steps_origin?: 'requirement-derived' | 'none'
  expected_result: string
  priority: 'low' | 'medium' | 'high'
  confidence: 'explicit' | 'inferred'
  dimension?: string
}

export interface Gap {
  type: string
  severity: 'low' | 'medium' | 'high'
  description: string
  suggested_question: string
}

export interface RTMEntry {
  requirement_id: string
  requirement_description: string
  covered_by_tests: string[]
  coverage_status: 'COVERED' | 'NOT COVERED' | 'N/A'
  trace_type?: 'testable' | 'informational'
  testability?: 'testable' | 'not_testable'
  source_section?: string
  rationale?: string
}

export async function generateTestPlan(tickets: TicketInput[], createdBy?: string): Promise<TestPlanResponse> {
  const baseHeaders = getAuthHeaders()
  // Convert to Headers instance for safe modification
  const headers = baseHeaders instanceof Headers ? baseHeaders : new Headers(baseHeaders)
  
  // Override X-Actor if createdBy is explicitly provided
  if (createdBy) {
    headers.set('X-Actor', createdBy)
  }
  
  const body: any = { tickets }
  // Also include created_by in body as fallback
  if (createdBy) {
    body.created_by = createdBy
  }
  
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/generate-test-plan`, {
    method: 'POST',
    headers,
    body: JSON.stringify(body),
  })
  
  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    // Check for PAYWALLED error first (clone since handleApiError consumes the body)
    const paywallError = await handleApiError(response.clone())
    if (paywallError) {
      // Re-throw with PAYWALLED error for caller to handle
      // Use error data already parsed by handleApiError
      const paywallErr = new Error(paywallError.message || 'Trial limit reached. Activate subscription to continue.')
      ;(paywallErr as any).isPaywalled = true
      throw paywallErr
    }
    
    // Not PAYWALLED - parse error from original response
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP error! status: ${response.status}`)
  }

  return response.json()
}

/**
 * Fetch test plan artifact for a specific run
 */
export async function fetchTestPlanArtifact(runId: string): Promise<any> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/test-plan/${runId}.json`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('Artifact not available')
    }
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to fetch test plan artifact: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Fetch RTM artifact for a specific run
 */
export async function fetchRTMArtifact(runId: string): Promise<any> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/rtm/${runId}.json`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('Artifact not available')
    }
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to fetch RTM artifact: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Fetch analysis artifact for a specific run
 */
export async function fetchAnalysisArtifact(runId: string): Promise<any> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/analysis/${runId}.json`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('Artifact not available')
    }
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to fetch analysis artifact: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Fetch audit metadata artifact for a specific run
 */
export async function fetchAuditArtifact(runId: string): Promise<any> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/audit/${runId}.json`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    if (response.status === 404) {
      throw new Error('Artifact not available')
    }
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to fetch audit artifact: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Fetch list of all runs
 */
export interface Run {
  run_id: string
  created_at: string
  source_type: string
  ticket_count: number | null
  status: string
  logic_version: string | null
  model_name: string | null
  created_by: string
  environment: string
  review_status?: 'generated' | 'reviewed' | 'approved'
  reviewed_by?: string | null
  reviewed_at?: string | null
  approved_by?: string | null
  approved_at?: string | null
  jira_issue_key?: string | null
  jira_issue_url?: string | null
  jira_created_by?: string | null
  jira_created_at?: string | null
  agent?: string
  run_kind?: string
}

export async function fetchRuns(): Promise<Run[]> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/runs`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to fetch runs: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Mark a run as reviewed.
 */
export async function markRunReviewed(runId: string): Promise<Run> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/runs/${runId}/review`, {
    method: 'POST',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to mark run as reviewed: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Approve a run.
 */
export async function approveRun(runId: string): Promise<Run> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/runs/${runId}/approve`, {
    method: 'POST',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to approve run: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Create a Jira ticket from an approved run.
 */
export async function createJiraTicket(runId: string): Promise<{
  jira_issue_key: string
  jira_issue_url: string
  message: string
  created_by: string
  created_at: string
}> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/runs/${runId}/jira`, {
    method: 'POST',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to create Jira ticket: ${response.statusText}`)
  }

  return response.json()
}

export async function downloadRTM(): Promise<Blob> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/export/rtm`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    // Check for PAYWALLED error first (clone since handleApiError consumes the body)
    const paywallError = await handleApiError(response.clone())
    if (paywallError) {
      // Re-throw with PAYWALLED error for caller to handle
      // Use error data already parsed by handleApiError
      const paywallErr = new Error(paywallError.message || 'Trial limit reached. Activate subscription to continue.')
      ;(paywallErr as any).isPaywalled = true
      throw paywallErr
    }
    
    // Not PAYWALLED - parse error from original response
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP error! status: ${response.status}`)
  }

  return response.blob()
}

export async function downloadTestPlan(): Promise<Blob> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/export/test-plan`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    // Check for PAYWALLED error first (clone since handleApiError consumes the body)
    const paywallError = await handleApiError(response.clone())
    if (paywallError) {
      // Re-throw with PAYWALLED error for caller to handle
      // Use error data already parsed by handleApiError
      const paywallErr = new Error(paywallError.message || 'Trial limit reached. Activate subscription to continue.')
      ;(paywallErr as any).isPaywalled = true
      throw paywallErr
    }
    
    // Not PAYWALLED - parse error from original response
    const error = await response.json().catch(() => ({ error: 'Unknown error' }))
    throw new Error(error.error || `HTTP error! status: ${response.status}`)
  }

  return response.blob()
}

export async function downloadExecutionReport(runId: string): Promise<Blob> {
  const baseHeaders = getAuthHeaders()
  // Convert to Headers instance for safe modification
  const headers = baseHeaders instanceof Headers ? baseHeaders : new Headers(baseHeaders)
  headers.set('Content-Type', 'text/csv')
  
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/test-plan/${runId}/execution-report.csv`, {
    method: 'GET',
    headers: headers,
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    if (response.status === 404) {
      const error = await response.json().catch(() => ({ detail: 'Run not found' }))
      throw new Error(error.detail || `Run not found: ${runId}`)
    }
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to download execution report: ${response.statusText}`)
  }

  return response.blob()
}

export interface AnalyzeRequirementsRequest {
  input_text: string
  source?: string
  context?: string
  attachments?: File[]
}

export interface AnalyzeRequirementsResponse {
  meta: Record<string, any>
  summary: Record<string, any>
  package: Record<string, any>
  readable_summary: Record<string, any>
}

export interface RequirementOverrideRequest {
  summary?: string
  description?: string
  scope_boundaries?: {
    in_scope?: string[]
    out_of_scope?: string[]
  }
  open_questions?: string[]
  business_requirement_overrides?: Record<string, { statement: string; edited_by?: string }>
  edited_by?: string
}

export interface OverrideResponse {
  requirement: Record<string, any>
  quality_scores: Record<string, number>
  quality_notes?: string[]
}

export async function applyRequirementOverride(
  requirementId: string,
  overrideRequest: RequirementOverrideRequest,
  packageData: Record<string, any>
): Promise<OverrideResponse> {
  // Call Flask gateway instead of BA agent directly
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/requirements/${requirementId}/overrides`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({
      override_request: overrideRequest,
      package: packageData,
    }),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    let errorMessage = `HTTP error! status: ${response.status}`
    try {
      const error = await response.json()
      errorMessage = error.detail || error.message || error.error || JSON.stringify(error) || errorMessage
    } catch (e) {
      try {
        const text = await response.text()
        errorMessage = text || errorMessage
      } catch (textError) {
        // Keep default error message
      }
    }
    throw new Error(errorMessage)
  }

  return response.json()
}

export interface ScopeStatusTransitionRequest {
  changed_by?: string
}

export interface ScopeStatusTransitionResponse {
  package: Record<string, any>
  previous_status: 'draft' | 'reviewed' | 'locked'
  new_status: 'draft' | 'reviewed' | 'locked'
}

export async function markPackageReviewed(
  packageId: string,
  packageData: Record<string, any>,
  transitionRequest: ScopeStatusTransitionRequest
): Promise<ScopeStatusTransitionResponse> {
  // Call Flask gateway instead of BA agent directly
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/packages/${packageId}/review`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({
      request: {
        package: packageData
      },
      transition_request: transitionRequest,
    }),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    let errorMessage = `HTTP error! status: ${response.status}`
    try {
      const error = await response.json()
      errorMessage = error.detail || error.message || error.error || JSON.stringify(error) || errorMessage
    } catch (e) {
      try {
        const text = await response.text()
        errorMessage = text || errorMessage
      } catch (textError) {
        // Keep default error message
      }
    }
    throw new Error(errorMessage)
  }

  return response.json()
}

export async function lockPackageScope(
  packageId: string,
  packageData: Record<string, any>,
  transitionRequest: ScopeStatusTransitionRequest
): Promise<ScopeStatusTransitionResponse> {
  // Call Flask gateway instead of BA agent directly
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/packages/${packageId}/lock`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({
      request: {
        package: packageData
      },
      transition_request: transitionRequest,
    }),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    let errorMessage = `HTTP error! status: ${response.status}`
    try {
      const error = await response.json()
      errorMessage = error.detail || error.message || error.error || JSON.stringify(error) || errorMessage
    } catch (e) {
      try {
        const text = await response.text()
        errorMessage = text || errorMessage
      } catch (textError) {
        // Keep default error message
      }
    }
    throw new Error(errorMessage)
  }

  return response.json()
}

export async function analyzeRequirements(
  request: AnalyzeRequirementsRequest
): Promise<AnalyzeRequirementsResponse> {
  // PHASE 1 ATTACHMENT SUPPORT: Use FormData if attachments exist, otherwise JSON
  // NOTE: Now calling Flask gateway instead of BA agent directly
  if (request.attachments && request.attachments.length > 0) {
    const formData = new FormData()
    formData.append('input_text', request.input_text)
    if (request.source) {
      formData.append('source', request.source)
    }
    if (request.context) {
      formData.append('context', request.context)
    }
    
    // Add attachments
    request.attachments.forEach((file) => {
      formData.append('attachments', file)
    })
    
    // Get auth headers but don't set Content-Type for FormData (browser will set it with boundary)
    const accessToken = localStorage.getItem('access_token')
    const headers = new Headers()
    
    if (accessToken) {
      headers.set('Authorization', `Bearer ${accessToken}`)
    }
    
    // Get user info for X-Actor header (backward compatibility)
    const userStr = localStorage.getItem('user')
    if (userStr) {
      try {
        const user = JSON.parse(userStr)
        // Use first_name + last_name, or email, or 'anonymous' as fallback
        let actorName = 'anonymous'
        if (user.first_name || user.last_name) {
          const parts = [user.first_name, user.last_name].filter(Boolean)
          actorName = parts.join(' ') || user.email || 'anonymous'
        } else if (user.email) {
          actorName = user.email
        }
        headers.set('X-Actor', actorName)
      } catch {
        headers.set('X-Actor', 'anonymous')
      }
    } else {
      headers.set('X-Actor', 'anonymous')
    }
    
    // Call Flask gateway instead of BA agent directly
    const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/analyze`, {
      method: 'POST',
      headers: headers,
      body: formData,
    })

    if (response.status === 401) {
      handleUnauthorized()
      // Don't throw error - redirect is happening, error would be caught and displayed
      // Return a user-friendly error that won't be displayed (since redirect happens)
      throw new Error('Session expired. Redirecting to login...')
    }

    if (!response.ok) {
      // Check for PAYWALLED error first (clone since handleApiError consumes the body)
      const paywallError = await handleApiError(response.clone())
      if (paywallError) {
        // Re-throw with PAYWALLED error for caller to handle
        // Use error data already parsed by handleApiError
        const paywallErr = new Error(paywallError.message || 'Trial limit reached. Activate subscription to continue.')
        ;(paywallErr as any).isPaywalled = true
        throw paywallErr
      }
      
      // Not PAYWALLED - parse error from original response
      let errorMessage = `HTTP error! status: ${response.status}`
      try {
        const error = await response.json()
        errorMessage = error.detail || error.message || error.error || JSON.stringify(error) || errorMessage
      } catch (e) {
        // If JSON parsing fails, try to get text
        try {
          const text = await response.text()
          errorMessage = text || errorMessage
        } catch (textError) {
          // Keep default error message
        }
      }
      throw new Error(errorMessage)
    }

    try {
      const data = await response.json()
      return data
    } catch (jsonError) {
      // If JSON parsing fails, try to get the response text for debugging
      const text = await response.text()
      console.error('Failed to parse JSON response:', text)
      throw new Error(`Failed to parse response: ${jsonError instanceof Error ? jsonError.message : 'Unknown error'}`)
    }
  } else {
    // No attachments - use JSON
    // Call Flask gateway instead of BA agent directly
    const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/analyze`, {
      method: 'POST',
      headers: getAuthHeaders(),
      body: JSON.stringify({
        input_text: request.input_text,
        source: request.source,
        context: request.context,
      }),
    })

    if (response.status === 401) {
      handleUnauthorized()
      // Don't throw error - redirect is happening, error would be caught and displayed
      // Return a user-friendly error that won't be displayed (since redirect happens)
      throw new Error('Session expired. Redirecting to login...')
    }

    if (!response.ok) {
      // Check for PAYWALLED error first (clone since handleApiError consumes the body)
      const paywallError = await handleApiError(response.clone())
      if (paywallError) {
        // Re-throw with PAYWALLED error for caller to handle
        // Use error data already parsed by handleApiError
        const paywallErr = new Error(paywallError.message || 'Trial limit reached. Activate subscription to continue.')
        ;(paywallErr as any).isPaywalled = true
        throw paywallErr
      }
      
      // Not PAYWALLED - parse error from original response
      let errorMessage = `HTTP error! status: ${response.status}`
      try {
        const error = await response.json()
        errorMessage = error.detail || error.message || error.error || JSON.stringify(error) || errorMessage
      } catch (e) {
        // If JSON parsing fails, try to get text
        try {
          const text = await response.text()
          errorMessage = text || errorMessage
        } catch (textError) {
          // Keep default error message
        }
      }
      throw new Error(errorMessage)
    }

    try {
      const data = await response.json()
      return data
    } catch (jsonError) {
      // If JSON parsing fails, try to get the response text for debugging
      const text = await response.text()
      console.error('Failed to parse JSON response:', text)
      throw new Error(`Failed to parse response: ${jsonError instanceof Error ? jsonError.message : 'Unknown error'}`)
    }
  }
}

// ============================================================================
// Jira Writeback API (Phase 4A: Rewrite)
// ============================================================================

export interface RewriteDryRunRequest {
  package: Record<string, any>
}

export interface RewriteDryRunResponse {
  jira_issue: string
  current_snapshot: Record<string, string>
  proposed_changes: Record<string, string>
  comment_preview: string
  checksum: string
}

export interface RewriteExecuteRequest {
  package: Record<string, any>
  checksum: string
  approved_by: string
  approved_at: string
}

export interface RewriteExecuteResponse {
  jira_issue_key: string
  result: 'success' | 'skipped'
  fields_modified: string[]
  comment_id?: string
  checksum: string
}

export async function rewriteDryRun(
  request: RewriteDryRunRequest
): Promise<RewriteDryRunResponse> {
  // Call Flask gateway instead of jira-writeback-agent directly
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/jira/rewrite/dry-run`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    let errorMessage = `HTTP error! status: ${response.status}`
    try {
      const error = await response.json()
      errorMessage = error.detail || error.message || error.error || JSON.stringify(error) || errorMessage
    } catch (e) {
      try {
        const text = await response.text()
        errorMessage = text || errorMessage
      } catch (textError) {
        // Keep default error message
      }
    }
    throw new Error(errorMessage)
  }

  return response.json()
}

export async function rewriteExecute(
  request: RewriteExecuteRequest
): Promise<RewriteExecuteResponse> {
  // Call Flask gateway instead of jira-writeback-agent directly
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/jira/rewrite/execute`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    let errorMessage = `HTTP error! status: ${response.status}`
    try {
      const error = await response.json()
      errorMessage = error.detail || error.message || error.error || JSON.stringify(error) || errorMessage
    } catch (e) {
      try {
        const text = await response.text()
        errorMessage = text || errorMessage
      } catch (textError) {
        // Keep default error message
      }
    }
    throw new Error(errorMessage)
  }

  return response.json()
}

// ============================================================================
// Jira Writeback API (Phase 4B: Create)
// ============================================================================

export interface JiraProject {
  key: string
  name: string
}

export interface JiraIssueType {
  id: string
  name: string
  subtask?: boolean
}

export interface CreateDryRunRequest {
  package: Record<string, any>
  project_key: string
  issue_type?: string
  summary?: string
  approved_by?: string
  approved_at?: string
}

export interface CreateDryRunResponse {
  proposed_issue: {
    project_key: string
    issue_type: string
    summary: string
  }
  proposed_changes: {
    description: string
    acceptance_criteria: string
  }
  comment_preview: string
  checksum: string
}

export interface CreateExecuteRequest {
  package: Record<string, any>
  project_key: string
  issue_type?: string
  summary?: string
  checksum: string
  approved_by: string
  approved_at: string
}

export interface CreateExecuteResponse {
  created_issue_key: string
  result: 'success' | 'skipped'
  fields_set: string[]
  comment_id?: string
  checksum: string
}

// Get Jira Writeback API base URL
// Service runs on port 8001 in development
// Primary: VITE_API_BASE (shared base URL for all services)
// Fallback: VITE_JIRA_WB_API_BASE_URL (if separate service deployment needed)
const getJiraWritebackAPIBase = (): string => {
  // In production, require env var
  if (import.meta.env.MODE === 'production') {
    // Use VITE_API_BASE first (shared base), then fallback to VITE_JIRA_WB_API_BASE_URL
    const base = import.meta.env.VITE_API_BASE || import.meta.env.VITE_JIRA_WB_API_BASE_URL
    if (!base) {
      throw new Error('VITE_API_BASE must be set in production')
    }
    return base
  }
  // In development, allow localhost fallback
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  return import.meta.env.VITE_API_BASE || (import.meta as any).env?.VITE_JIRA_WB_API_BASE_URL || 'http://localhost:8001'
}

const JIRA_WB_API_BASE_URL = getJiraWritebackAPIBase()

export async function getJiraProjects(): Promise<JiraProject[]> {
  // Call Flask gateway instead of jira-writeback-agent directly
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/jira/meta/projects`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    let errorMessage = `HTTP error! status: ${response.status}`
    try {
      const error = await response.json()
      errorMessage = error.detail || error.message || error.error || JSON.stringify(error) || errorMessage
    } catch (e) {
      try {
        const text = await response.text()
        errorMessage = text || errorMessage
      } catch (textError) {
        // Keep default error message
      }
    }
    throw new Error(errorMessage)
  }

  return response.json()
}

export async function getJiraIssueTypes(projectKey: string): Promise<JiraIssueType[]> {
  // Call Flask gateway instead of jira-writeback-agent directly
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/jira/meta/issue-types?project_key=${encodeURIComponent(projectKey)}`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    let errorMessage = `HTTP error! status: ${response.status}`
    try {
      const error = await response.json()
      errorMessage = error.detail || error.message || error.error || JSON.stringify(error) || errorMessage
    } catch (e) {
      try {
        const text = await response.text()
        errorMessage = text || errorMessage
      } catch (textError) {
        // Keep default error message
      }
    }
    throw new Error(errorMessage)
  }

  return response.json()
}

export async function createJiraTicketDryRun(
  request: CreateDryRunRequest
): Promise<CreateDryRunResponse> {
  // Call Flask gateway instead of jira-writeback-agent directly
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/jira/create/dry-run`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    let errorMessage = `HTTP error! status: ${response.status}`
    try {
      const error = await response.json()
      errorMessage = error.detail || error.message || error.error || JSON.stringify(error) || errorMessage
    } catch (e) {
      try {
        const text = await response.text()
        errorMessage = text || errorMessage
      } catch (textError) {
        // Keep default error message
      }
    }
    throw new Error(errorMessage)
  }

  return response.json()
}

// ============================================================================
// Admin API
// ============================================================================

export interface TenantSummary {
  id: string
  name: string
  slug: string
  subscription_status: 'unselected' | 'trial' | 'individual' | 'team' | 'paywalled' | 'canceled'
  req_remaining: number
  test_remaining: number
  wb_remaining: number
  is_active: boolean
  created_at: string | null
}

export async function listTenants(): Promise<TenantSummary[]> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/tenants`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (response.status === 403) {
    const error = await response.json().catch(() => ({ error: 'FORBIDDEN', message: 'Admin access required' }))
    throw new Error(error.message || 'Admin access required')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || error.message || `Failed to list tenants: ${response.statusText}`)
  }

  return response.json()
}

export interface ResetTrialRequest {
  req?: number
  test?: number
  writeback?: number
  status?: 'unselected' | 'trial' | 'individual' | 'team' | 'paywalled' | 'canceled'
}

export async function resetTenantTrial(tenantId: string, request?: ResetTrialRequest): Promise<TenantSummary> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/tenants/${tenantId}/trial/reset`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request || {}),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (response.status === 403) {
    const error = await response.json().catch(() => ({ error: 'FORBIDDEN', message: 'Admin access required' }))
    throw new Error(error.message || 'Admin access required')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || error.message || error.error || `Failed to reset trial: ${response.statusText}`)
  }

  return response.json()
}

export interface SetTrialRequest {
  req: number
  test: number
  writeback: number
  status: 'unselected' | 'trial' | 'individual' | 'team' | 'paywalled' | 'canceled'
}

export async function setTenantTrial(tenantId: string, request: SetTrialRequest): Promise<TenantSummary> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/tenants/${tenantId}/trial/set`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (response.status === 403) {
    const error = await response.json().catch(() => ({ error: 'FORBIDDEN', message: 'Admin access required' }))
    throw new Error(error.message || 'Admin access required')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || error.message || error.error || `Failed to set trial: ${response.statusText}`)
  }

  return response.json()
}

export async function createJiraTicketExecute(
  request: CreateExecuteRequest
): Promise<CreateExecuteResponse> {
  // Call Flask gateway instead of jira-writeback-agent directly
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/jira/create/execute`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    let errorMessage = `HTTP error! status: ${response.status}`
    try {
      const error = await response.json()
      errorMessage = error.detail || error.message || error.error || JSON.stringify(error) || errorMessage
    } catch (e) {
      try {
        const text = await response.text()
        errorMessage = text || errorMessage
      } catch (textError) {
        // Keep default error message
      }
    }
    throw new Error(errorMessage)
  }

  return response.json()
}
