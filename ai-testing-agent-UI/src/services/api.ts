import { TEST_PLAN_API_BASE_URL } from '../config'

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

export interface BillingStatus {
  ok: boolean
  tenant_id?: string
  plan_tier?: string
  status?: string
  current_period_start?: string | null
  current_period_end?: string | null
  cancel_at_period_end?: boolean
  error?: string
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
 * Get billing status (includes plan_tier)
 */
export async function getBillingStatus(): Promise<BillingStatus> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/billing/status`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ ok: false, error: 'Unknown error' }))
    throw error
  }

  return response.json()
}

/**
 * Create Stripe Customer Portal session for billing management
 */
export interface PortalSessionResponse {
  ok: boolean
  url?: string
  error?: string
}

export async function createPortalSession(): Promise<PortalSessionResponse> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/billing/portal-session`, {
    method: 'POST',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    // Surface backend error string for 409 and other errors
    const errorData = await response.json().catch(() => ({ ok: false, error: 'Unknown error' }))
    const errorMessage = errorData.error || errorData.detail || errorData.message || 'Unknown error'
    throw { ...errorData, error: errorMessage, status: response.status }
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
  rtm_artifact?: {
    requirements_rtm?: Array<{
      coverage?: {
        status?: string
      }
    }>
  }
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

export interface PaginationParams {
  page?: number
  limit?: number
}

export interface PaginationMeta {
  total: number
  page: number
  limit: number
  total_pages: number
  has_prev: boolean
  has_next: boolean
}

export interface PaginatedRunsResponse {
  items: Run[]
  pagination: PaginationMeta
}

export async function fetchRuns(params?: PaginationParams): Promise<PaginatedRunsResponse> {
  const page = params?.page ?? 1
  const limit = params?.limit ?? 10
  
  const url = new URL(`${TEST_PLAN_API_BASE_URL}/api/v1/runs`)
  url.searchParams.set('page', page.toString())
  url.searchParams.set('limit', limit.toString())
  
  const response = await fetch(url.toString(), {
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
  subscription_status: 'unselected' | 'trial' | 'individual' | 'team' | 'paywalled' | 'canceled' | 'suspended' | 'active'
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

  const data = await response.json()
  // Handle new format with "items" array
  if (data.items && Array.isArray(data.items)) {
    // Map new format to old format for compatibility
    return data.items.map((item: any) => ({
      id: item.id,
      name: item.name,
      slug: item.slug,
      subscription_status: item.subscription_status,
      req_remaining: item.trial_requirements_runs_remaining,
      test_remaining: item.trial_testplan_runs_remaining,
      wb_remaining: item.trial_writeback_runs_remaining,
      is_active: item.is_active,
      created_at: item.created_at
    }))
  }
  // Fallback to old format (array directly)
  return data
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
  status: 'unselected' | 'trial' | 'individual' | 'team' | 'paywalled' | 'canceled' | 'suspended' | 'active'
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

// ============================================================================
// User Profile API (Phase 2.1)
// ============================================================================

export interface UserProfile {
  id: string
  email: string
  role: string
  is_active: boolean
  first_name: string | null
  last_name: string | null
  address_1: string | null
  address_2: string | null
  city: string | null
  state: string | null
  zip: string | null
  phone: string | null
  tenant_id: string
  tenant_name: string | null
}

export interface UpdateUserProfileRequest {
  first_name?: string | null
  last_name?: string | null
  address_1?: string | null
  address_2?: string | null
  city?: string | null
  state?: string | null
  zip?: string | null
  phone?: string | null
}

export interface ChangePasswordRequest {
  current_password: string
  new_password: string
}

export interface ForgotPasswordRequest {
  email: string
}

export interface ResetPasswordRequest {
  token: string
  new_password: string
}

/**
 * Get current user profile
 */
export async function getUserProfile(): Promise<UserProfile> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/users/me`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to fetch user profile: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Update current user profile
 */
export async function updateUserProfile(request: UpdateUserProfileRequest): Promise<UserProfile> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/users/me`, {
    method: 'PATCH',
    headers: getAuthHeaders(),
    body: JSON.stringify(request),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to update user profile: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Change user password
 */
export async function changePassword(request: ChangePasswordRequest): Promise<void> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/users/me/change-password`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to change password: ${response.statusText}`)
  }
}

/**
 * Request password reset (forgot password)
 */
export async function forgotPassword(request: ForgotPasswordRequest): Promise<void> {
  try {
    const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/auth/forgot-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    })

    // Always returns 200, even if email doesn't exist (security)
    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
      throw new Error(error.detail || `Failed to request password reset: ${response.statusText}`)
    }
  } catch (error) {
    // Handle network errors (DNS resolution, connection refused, etc.)
    if (error instanceof TypeError && (
      error.message.includes('Failed to fetch') ||
      error.message.includes('NetworkError') ||
      error.message.includes('Network request failed') ||
      error.message.includes('could not be found')
    )) {
      throw new Error(
        `Unable to connect to the server. Please check that the backend is running at ${TEST_PLAN_API_BASE_URL}`
      )
    }
    // Re-throw other errors
    throw error
  }
}

/**
 * Reset password using token
 */
export async function resetPassword(request: ResetPasswordRequest): Promise<void> {
  try {
    const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/auth/reset-password`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    })

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
      throw new Error(error.detail || `Failed to reset password: ${response.statusText}`)
    }
  } catch (error) {
    // Handle network errors (DNS resolution, connection refused, etc.)
    if (error instanceof TypeError && (
      error.message.includes('Failed to fetch') ||
      error.message.includes('NetworkError') ||
      error.message.includes('Network request failed') ||
      error.message.includes('could not be found')
    )) {
      throw new Error(
        `Unable to connect to the server. Please check that the backend is running at ${TEST_PLAN_API_BASE_URL}`
      )
    }
    // Re-throw other errors
    throw error
  }
}

// ---------------------------------------------------------------------------
// Tenant User Management (Phase B: Tenant-scoped user invites)
// ---------------------------------------------------------------------------

export interface TenantUser {
  id: string
  email: string
  role: string
  is_active: boolean
  first_name: string | null
  last_name: string | null
  created_at: string | null
  last_login_at: string | null
  has_pending_invite?: boolean
}

export interface InviteUserRequest {
  email: string
  role: 'user' | 'admin'
  first_name?: string
  last_name?: string
}

export interface InviteUserResponse {
  ok: boolean
  user_id?: string
  email?: string
  error?: string
  current_seats?: number
  seat_cap?: number
}

export interface AcceptInviteRequest {
  token: string
  new_password: string
}

/**
 * List users for the authenticated tenant
 */
export async function listTenantUsers(): Promise<TenantUser[]> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/tenant/users`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || error.error || `Failed to list tenant users: ${response.statusText}`)
  }

  return response.json()
}

/**
 * Invite a user to the authenticated tenant
 */
export async function inviteTenantUser(request: InviteUserRequest): Promise<InviteUserResponse> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/tenant/users/invite`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify(request),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ ok: false, error: 'Unknown error' }))
    // Return error object with structured error info
    throw error
  }

  return response.json()
}

/**
 * Accept invite and set password
 */
export async function acceptInvite(request: AcceptInviteRequest): Promise<void> {
  try {
    const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/auth/accept-invite`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(request),
    })

    if (!response.ok) {
      const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
      throw new Error(error.detail || `Failed to accept invite: ${response.statusText}`)
    }
  } catch (error) {
    // Handle network errors
    if (error instanceof TypeError && (
      error.message.includes('Failed to fetch') ||
      error.message.includes('NetworkError') ||
      error.message.includes('Network request failed') ||
      error.message.includes('could not be found')
    )) {
      throw new Error(
        `Unable to connect to the server. Please check that the backend is running at ${TEST_PLAN_API_BASE_URL}`
      )
    }
    // Re-throw other errors
    throw error
  }
}

/**
 * Deactivate a user in the authenticated tenant
 */
export async function deactivateTenantUser(userId: string): Promise<void> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/tenant/users/${userId}/deactivate`, {
    method: 'POST',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ ok: false, error: 'Unknown error' }))
    // Return error object with structured error info
    throw error
  }

  const result = await response.json()
  if (!result.ok) {
    throw result
  }
}

/**
 * Reactivate a user in the authenticated tenant
 */
export async function reactivateTenantUser(userId: string): Promise<void> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/tenant/users/${userId}/reactivate`, {
    method: 'POST',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ ok: false, error: 'Unknown error' }))
    // Return error object with structured error info
    throw error
  }

  const result = await response.json()
  if (!result.ok) {
    throw result
  }
}

// ---------------------------------------------------------------------------
// Admin Ops Safety (owner + kerr-ai-studio only)
// ---------------------------------------------------------------------------

export interface AdminUser {
  id: string
  email: string
  role: string
  is_active: boolean
  first_name: string | null
  last_name: string | null
  created_at: string | null
  last_login_at: string | null
}

export interface UsageSummary {
  days: number
  totals: {
    events: number
    success: number
    failed: number
    jira_ticket_count: number
    input_char_count: number
  }
  by_agent: Array<{
    agent: string
    events: number
    success: number
    failed: number
    jira_ticket_count: number
    input_char_count: number
  }>
}

export interface AdminRun {
  run_id: string
  created_at: string | null
  agent: string
  status: string
  review_status: string
  jira_issue_key: string | null
  summary: string | null
}

export interface AdminAuditLogEntry {
  id: string
  user_id: string
  action: string
  target_type: string | null
  target_id: string | null
  metadata: any
  created_at: string | null
}

export async function adminListUsers(): Promise<AdminUser[]> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/users`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to list users: ${response.statusText}`)
  }

  return response.json()
}

export async function adminDeactivateUser(userId: string): Promise<void> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/users/${userId}/deactivate`, {
    method: 'POST',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to deactivate user: ${response.statusText}`)
  }
}

export async function adminReactivateUser(userId: string): Promise<void> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/users/${userId}/reactivate`, {
    method: 'POST',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to reactivate user: ${response.statusText}`)
  }
}

export async function adminSuspendTenant(): Promise<void> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/tenant/suspend`, {
    method: 'POST',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to suspend tenant: ${response.statusText}`)
  }
}

export async function adminReactivateTenant(): Promise<void> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/tenant/reactivate`, {
    method: 'POST',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to reactivate tenant: ${response.statusText}`)
  }
}

export async function adminUsageSummary(days: number = 30): Promise<UsageSummary> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/usage/summary?days=${days}`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to get usage summary: ${response.statusText}`)
  }

  return response.json()
}

export async function adminRecentRuns(limit: number = 25): Promise<AdminRun[]> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/runs/recent?limit=${limit}`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to get recent runs: ${response.statusText}`)
  }

  return response.json()
}

export async function adminAudit(limit: number = 50): Promise<AdminAuditLogEntry[]> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/audit?limit=${limit}`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to get audit log: ${response.statusText}`)
  }

  return response.json()
}

// ============================================================================
// Tenant-Addressable Admin API (Owner can manage ALL tenants)
// ============================================================================

export async function adminListTenants(): Promise<TenantSummary[]> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/tenants`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (response.status === 403) {
    const error = await response.json().catch(() => ({ error: 'FORBIDDEN', message: 'Owner access required' }))
    throw new Error(error.message || 'Owner access required')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || error.message || `Failed to list tenants: ${response.statusText}`)
  }

  const data = await response.json()
  // Map new format to old format for compatibility
  if (data.items && Array.isArray(data.items)) {
    return data.items.map((item: any) => ({
      id: item.id,
      name: item.name,
      slug: item.slug,
      subscription_status: item.subscription_status,
      req_remaining: item.trial_requirements_runs_remaining,
      test_remaining: item.trial_testplan_runs_remaining,
      wb_remaining: item.trial_writeback_runs_remaining,
      is_active: item.is_active,
      created_at: item.created_at
    }))
  }
  return data.items || []
}

export async function adminSetTenantStatus(tenantId: string, status: 'active' | 'suspended'): Promise<void> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/tenants/${tenantId}/status`, {
    method: 'POST',
    headers: getAuthHeaders(),
    body: JSON.stringify({ status }),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (response.status === 403) {
    const error = await response.json().catch(() => ({ error: 'FORBIDDEN', message: 'Owner access required' }))
    throw new Error(error.message || 'Owner access required')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to set tenant status: ${response.statusText}`)
  }
}

export async function adminListTenantUsers(tenantId: string): Promise<AdminUser[]> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/tenants/${tenantId}/users`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (response.status === 403) {
    const error = await response.json().catch(() => ({ error: 'FORBIDDEN', message: 'Owner access required' }))
    throw new Error(error.message || 'Owner access required')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to list tenant users: ${response.statusText}`)
  }

  return response.json()
}

export async function adminDeactivateTenantUser(tenantId: string, userId: string): Promise<void> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/tenants/${tenantId}/users/${userId}/deactivate`, {
    method: 'POST',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (response.status === 403) {
    const error = await response.json().catch(() => ({ error: 'FORBIDDEN', message: 'Owner access required' }))
    throw new Error(error.message || 'Owner access required')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to deactivate user: ${response.statusText}`)
  }
}

export async function adminReactivateTenantUser(tenantId: string, userId: string): Promise<void> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/tenants/${tenantId}/users/${userId}/reactivate`, {
    method: 'POST',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (response.status === 403) {
    const error = await response.json().catch(() => ({ error: 'FORBIDDEN', message: 'Owner access required' }))
    throw new Error(error.message || 'Owner access required')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to reactivate user: ${response.statusText}`)
  }
}

export async function adminTenantUsageSummary(tenantId: string, days: number = 30): Promise<UsageSummary> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/tenants/${tenantId}/usage/summary?days=${days}`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (response.status === 403) {
    const error = await response.json().catch(() => ({ error: 'FORBIDDEN', message: 'Owner access required' }))
    throw new Error(error.message || 'Owner access required')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to get usage summary: ${response.statusText}`)
  }

  return response.json()
}

export async function adminTenantRecentRuns(tenantId: string, limit: number = 25): Promise<AdminRun[]> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/tenants/${tenantId}/runs/recent?limit=${limit}`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (response.status === 403) {
    const error = await response.json().catch(() => ({ error: 'FORBIDDEN', message: 'Owner access required' }))
    throw new Error(error.message || 'Owner access required')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to get recent runs: ${response.statusText}`)
  }

  return response.json()
}

export async function adminTenantAudit(tenantId: string, limit: number = 50): Promise<AdminAuditLogEntry[]> {
  const response = await fetch(`${TEST_PLAN_API_BASE_URL}/api/v1/admin/tenants/${tenantId}/audit?limit=${limit}`, {
    method: 'GET',
    headers: getAuthHeaders(),
  })

  if (response.status === 401) {
    handleUnauthorized()
    throw new Error('Unauthorized')
  }

  if (response.status === 403) {
    const error = await response.json().catch(() => ({ error: 'FORBIDDEN', message: 'Owner access required' }))
    throw new Error(error.message || 'Owner access required')
  }

  if (!response.ok) {
    const error = await response.json().catch(() => ({ detail: 'Unknown error' }))
    throw new Error(error.detail || `Failed to get audit log: ${response.statusText}`)
  }

  return response.json()
}
