import { useState } from 'react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { Loader2, Plus, X, Upload, Edit2, Save, XCircle, Check, Lock, AlertCircle } from 'lucide-react'
import { analyzeRequirements, AnalyzeRequirementsResponse, applyRequirementOverride, RequirementOverrideRequest, markPackageReviewed, lockPackageScope, getJiraProjects, createJiraTicketDryRun, createJiraTicketExecute, JiraProject, CreateDryRunResponse, rewriteDryRun, rewriteExecute, RewriteDryRunResponse, RewriteExecuteRequest, refreshTenantStatus } from '../services/api'
import { useTenantStatus } from '../contexts/TenantStatusContext'
import { motion, AnimatePresence } from 'framer-motion'
import { JiraNotConfiguredBanner } from './JiraNotConfiguredBanner'

type InputSource = 'free-text' | 'jira-tickets' | 'document-upload'

interface Requirement {
  id: string
  parent_id?: string | null
  ticket_type: 'story' | 'sub-task'
  summary: string
  description: string
  business_requirements?: Array<{
    id: string
    statement: string
    inferred?: boolean
    manual_override?: {
      statement?: string
      audit?: {
        edited_by?: string
        edited_at?: string
        fields_changed?: string[]
      }
    }
  }>
  scope_boundaries?: {
    in_scope: string[]
    out_of_scope: string[]
  }
  open_questions?: string[]
  manual_override?: {
    summary?: string
    description?: string
    scope_boundaries?: {
      in_scope: string[]
      out_of_scope: string[]
    }
    open_questions?: string[]
    scope_misalignment_advisory?: boolean
    audit?: {
      edited_by?: string
      edited_at?: string
      fields_changed?: string[]
    }
  }
}

interface ReadableSummaryViewProps {
  requirements: Requirement[]
  readableSummary: Record<string, any>
  packageData: Record<string, any>
  onRequirementUpdate?: (requirementId: string, updatedRequirement: Requirement) => void
}

function ReadableSummaryView({ requirements, readableSummary, packageData, onRequirementUpdate }: ReadableSummaryViewProps) {
  const isScopeLocked = packageData?.scope_status === 'locked'
  // Organize requirements by parent/child structure
  const parentRequirements = requirements.filter(req => !req.parent_id)
  const childRequirements = requirements.filter(req => req.parent_id)
  
  // Create a map of parent_id to children
  const childrenByParent = new Map<string, Requirement[]>()
  childRequirements.forEach(child => {
    if (child.parent_id) {
      if (!childrenByParent.has(child.parent_id)) {
        childrenByParent.set(child.parent_id, [])
      }
      childrenByParent.get(child.parent_id)!.push(child)
    }
  })
  
  // Sort children by ID
  childrenByParent.forEach((children) => {
    children.sort((a, b) => a.id.localeCompare(b.id))
  })
  
  // Sort parents by ID
  const sortedParents = [...parentRequirements].sort((a, b) => a.id.localeCompare(b.id))
  
  // Editing state
  const [editingRequirementId, setEditingRequirementId] = useState<string | null>(null)
  const [editState, setEditState] = useState<{
    summary?: string
    description?: string
    scope_boundaries?: { in_scope: string[]; out_of_scope: string[] }
    open_questions?: string[]
    business_requirements?: Record<string, string>
  }>({})
  const [isSaving, setIsSaving] = useState(false)
  
  // Get display value (with manual override if present)
  const getDisplayValue = (req: Requirement, field: 'summary' | 'description' | 'scope_boundaries' | 'open_questions' | 'business_requirements'): string | string[] | { in_scope: string[]; out_of_scope: string[] } | null => {
    if (req.manual_override) {
      if (field === 'summary' && req.manual_override.summary) return req.manual_override.summary
      if (field === 'description' && req.manual_override.description) return req.manual_override.description
      if (field === 'scope_boundaries' && req.manual_override.scope_boundaries) {
        return {
          in_scope: req.manual_override.scope_boundaries.in_scope || [],
          out_of_scope: req.manual_override.scope_boundaries.out_of_scope || []
        }
      }
      if (field === 'open_questions' && req.manual_override.open_questions) return req.manual_override.open_questions
    }
    // Fall back to original
    if (field === 'summary') return req.summary
    if (field === 'description') return req.description
    if (field === 'scope_boundaries') {
      const scope = req.scope_boundaries
      if (!scope) return { in_scope: [], out_of_scope: [] }
      // Normalize to object format
      if (typeof scope === 'string') {
        return { in_scope: [scope], out_of_scope: [] }
      }
      if (Array.isArray(scope)) {
        return { in_scope: scope, out_of_scope: [] }
      }
      return scope
    }
    if (field === 'open_questions') return req.open_questions || []
    return null
  }
  
  const getBRDisplayValue = (br: NonNullable<Requirement['business_requirements']>[0]) => {
    if (br.manual_override && br.manual_override.statement) {
      return br.manual_override.statement
    }
    return br.statement
  }
  
  const isManuallyEdited = (req: Requirement) => {
    return req.manual_override !== null && req.manual_override !== undefined
  }
  
  const isBRManuallyEdited = (br: NonNullable<Requirement['business_requirements']>[0]) => {
    return br.manual_override !== null && br.manual_override !== undefined && br.manual_override.statement !== null
  }
  
  const handleStartEdit = (req: Requirement) => {
    setEditingRequirementId(req.id)
    setEditState({
      summary: getDisplayValue(req, 'summary') as string,
      description: getDisplayValue(req, 'description') as string,
      scope_boundaries: getDisplayValue(req, 'scope_boundaries') as { in_scope: string[]; out_of_scope: string[] },
      open_questions: getDisplayValue(req, 'open_questions') as string[],
      business_requirements: req.business_requirements?.reduce((acc, br) => {
        acc[br.id] = getBRDisplayValue(br)
        return acc
      }, {} as Record<string, string>) || {}
    })
  }
  
  const handleCancelEdit = () => {
    setEditingRequirementId(null)
    setEditState({})
  }
  
  const handleSaveEdit = async (req: Requirement) => {
    setIsSaving(true)
    try {
      // Get original values (before any overrides)
      const originalSummary = req.summary
      const originalDescription = req.description
      const originalScope = req.scope_boundaries || { in_scope: [], out_of_scope: [] }
      const originalOpenQuestions = req.open_questions || []
      
      // Build override request - only include fields that actually changed
      const overrideRequest: RequirementOverrideRequest = {
        summary: editState.summary !== originalSummary ? editState.summary : undefined,
        description: editState.description !== originalDescription ? editState.description : undefined,
        scope_boundaries: (editState.scope_boundaries && (
          JSON.stringify(editState.scope_boundaries.in_scope) !== JSON.stringify(originalScope.in_scope) ||
          JSON.stringify(editState.scope_boundaries.out_of_scope) !== JSON.stringify(originalScope.out_of_scope)
        )) ? {
          in_scope: editState.scope_boundaries.in_scope || [],
          out_of_scope: editState.scope_boundaries.out_of_scope || []
        } : undefined,
        open_questions: JSON.stringify(editState.open_questions || []) !== JSON.stringify(originalOpenQuestions) 
          ? editState.open_questions 
          : undefined,
        business_requirement_overrides: req.business_requirements?.reduce((acc, br) => {
          const editedValue = editState.business_requirements?.[br.id]
          const originalValue = br.statement
          if (editedValue && editedValue !== originalValue) {
            acc[br.id] = { statement: editedValue }
          }
          return acc
        }, {} as Record<string, { statement: string }>) || undefined,
        edited_by: 'user' // TODO: Get from auth context
      }
      
      // Remove undefined fields
      Object.keys(overrideRequest).forEach(key => {
        if (overrideRequest[key as keyof RequirementOverrideRequest] === undefined) {
          delete overrideRequest[key as keyof RequirementOverrideRequest]
        }
      })
      
      // Don't send request if nothing changed
      if (Object.keys(overrideRequest).length === 0 || (Object.keys(overrideRequest).length === 1 && overrideRequest.edited_by)) {
        handleCancelEdit()
        return
      }
      
      const response = await applyRequirementOverride(req.id, overrideRequest, packageData)
      
      // Update local state
      if (onRequirementUpdate) {
        onRequirementUpdate(req.id, response.requirement as Requirement)
      }
      
      setEditingRequirementId(null)
      setEditState({})
    } catch (err) {
      console.error('Failed to save override:', err)
      alert(`Failed to save changes: ${err instanceof Error ? err.message : 'Unknown error'}`)
    } finally {
      setIsSaving(false)
    }
  }
  
  const renderRequirement = (req: Requirement, isChild: boolean = false) => {
    const ticketTypeVariant = req.ticket_type === 'story' ? 'default' : 'secondary'
    const ticketTypeLabel = req.ticket_type === 'story' ? 'Story' : 'Sub-task'
    const isEditing = editingRequirementId === req.id
    const hasManualEdits = isManuallyEdited(req)
    const displaySummary = isEditing ? editState.summary : (getDisplayValue(req, 'summary') as string | null)
    const displayDescription = isEditing ? editState.description : (getDisplayValue(req, 'description') as string | null)
    const scopeValue = isEditing ? editState.scope_boundaries : getDisplayValue(req, 'scope_boundaries')
    // Normalize scope to object format
    const displayScope: { in_scope: string[]; out_of_scope: string[] } = (() => {
      if (!scopeValue) return { in_scope: [], out_of_scope: [] }
      if (typeof scopeValue === 'string') return { in_scope: [scopeValue], out_of_scope: [] }
      if (Array.isArray(scopeValue)) return { in_scope: scopeValue, out_of_scope: [] }
      return scopeValue
    })()
    const openQuestionsValue = isEditing ? editState.open_questions : getDisplayValue(req, 'open_questions')
    const displayOpenQuestions: string[] = (() => {
      if (!openQuestionsValue) return []
      if (Array.isArray(openQuestionsValue)) return openQuestionsValue
      if (typeof openQuestionsValue === 'string') return [openQuestionsValue]
      return []
    })()
    
    return (
      <Card 
        key={req.id}
        className={`border-border/50 bg-gradient-to-br from-background via-background to-secondary/5 ${isChild ? 'ml-8 mt-3' : ''} ${hasManualEdits ? 'ring-2 ring-blue-500/20' : ''}`}
      >
        <CardHeader className="pb-3">
          <div className="flex items-start justify-between gap-4">
            <div className="flex-1 space-y-2">
              {/* Ticket Header */}
              <div className="flex items-center gap-2 flex-wrap">
                <CardTitle className="text-base font-semibold font-mono">{req.id}</CardTitle>
                <Badge variant={ticketTypeVariant} className="text-xs">
                  {ticketTypeLabel}
                </Badge>
                {hasManualEdits && (
                  <Badge variant="outline" className="text-xs bg-blue-500/10 text-blue-600 dark:text-blue-400">
                    Manually Edited
                  </Badge>
                )}
                {req.manual_override?.scope_misalignment_advisory && (
                  <Badge variant="outline" className="text-xs bg-amber-500/10 text-amber-600 dark:text-amber-400 border-amber-500/30">
                    Scope Review Recommended
                  </Badge>
                )}
                {!isEditing && !isScopeLocked && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleStartEdit(req)}
                    className="h-6 px-2 text-xs"
                    disabled={isScopeLocked}
                  >
                    <Edit2 className="h-3 w-3 mr-1" />
                    Edit
                  </Button>
                )}
                {isScopeLocked && (
                  <Badge variant="outline" className="text-xs bg-red-500/10 text-red-600 dark:text-red-400">
                    <Lock className="h-3 w-3 mr-1" />
                    Locked
                  </Badge>
                )}
              </div>
              
              {/* Summary */}
              {isEditing ? (
                <textarea
                  value={displaySummary || ''}
                  onChange={(e) => setEditState({ ...editState, summary: e.target.value })}
                  className="w-full px-3 py-2 bg-background border border-input rounded-md text-base font-semibold text-foreground focus:outline-none focus:ring-2 focus:ring-ring"
                  rows={2}
                />
              ) : (
                <p className="text-base font-semibold text-foreground">{displaySummary}</p>
              )}
              
              {/* Description */}
              {isEditing ? (
                <textarea
                  value={displayDescription || ''}
                  onChange={(e) => setEditState({ ...editState, description: e.target.value })}
                  className="w-full px-3 py-2 bg-background border border-input rounded-md text-sm text-foreground/90 focus:outline-none focus:ring-2 focus:ring-ring"
                  rows={4}
                />
              ) : (
                displayDescription && (
                  <p className="text-sm text-foreground/90">{displayDescription}</p>
                )
              )}
            </div>
          </div>
        </CardHeader>
        
        <CardContent className="pt-0 space-y-4">
          {/* Business Requirements */}
          {req.business_requirements && req.business_requirements.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold text-foreground/90 mb-2">Business Requirements</h4>
              {isEditing ? (
                <div className="space-y-2">
                  {req.business_requirements.map((br) => (
                    <div key={br.id} className="flex items-start gap-2">
                      <span className="text-xs text-muted-foreground mt-2">{br.id}:</span>
                      <textarea
                        value={editState.business_requirements?.[br.id] || getBRDisplayValue(br)}
                        onChange={(e) => setEditState({
                          ...editState,
                          business_requirements: {
                            ...editState.business_requirements,
                            [br.id]: e.target.value
                          }
                        })}
                        className="flex-1 px-3 py-2 bg-background border border-input rounded-md text-sm text-foreground/80 focus:outline-none focus:ring-2 focus:ring-ring"
                        rows={2}
                      />
                      {isBRManuallyEdited(br) && (
                        <Badge variant="outline" className="text-xs bg-blue-500/10 text-blue-600 dark:text-blue-400 mt-2">
                          Edited
                        </Badge>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <ul className="list-disc list-inside space-y-1 text-sm text-foreground/80">
                  {req.business_requirements.map((br) => (
                    <li key={br.id} className="flex items-start gap-2">
                      <span>{getBRDisplayValue(br)}</span>
                      {br.inferred && (
                        <span className="text-xs text-muted-foreground ml-2">(inferred)</span>
                      )}
                      {isBRManuallyEdited(br) && (
                        <Badge variant="outline" className="text-xs bg-blue-500/10 text-blue-600 dark:text-blue-400 ml-2">
                          Edited
                        </Badge>
                      )}
                    </li>
                  ))}
                </ul>
              )}
            </div>
          )}
          
          {/* Scope Boundaries */}
          {displayScope && (
            <div className="space-y-3">
              {/* SCOPE OWNERSHIP GUARDRAIL: Advisory message */}
              {req.manual_override?.scope_misalignment_advisory && !isEditing && (
                <div className="bg-amber-500/10 border border-amber-500/30 rounded-md p-3 text-sm">
                  <div className="flex items-start gap-2">
                    <span className="text-amber-600 dark:text-amber-400 font-semibold">⚠️</span>
                    <div>
                      <p className="font-semibold text-amber-700 dark:text-amber-300 mb-1">Scope Review Recommended</p>
                      <p className="text-amber-600 dark:text-amber-400">
                        Manual edits to the requirement text may have altered scope meaning. 
                        Please review scope boundaries to ensure they align with the updated requirement.
                      </p>
                    </div>
                  </div>
                </div>
              )}
              {isEditing ? (
                <>
                  <div>
                    <h4 className="text-sm font-semibold text-foreground/90 mb-2">In Scope</h4>
                    <textarea
                      value={(displayScope.in_scope || []).join('\n')}
                      onChange={(e) => setEditState({
                        ...editState,
                        scope_boundaries: {
                          ...displayScope,
                          in_scope: e.target.value.split('\n').filter(line => line.trim())
                        }
                      })}
                      className="w-full px-3 py-2 bg-background border border-input rounded-md text-sm text-foreground/80 focus:outline-none focus:ring-2 focus:ring-ring"
                      rows={4}
                      placeholder="One item per line"
                    />
                  </div>
                  <div>
                    <h4 className="text-sm font-semibold text-foreground/90 mb-2">Out of Scope</h4>
                    <textarea
                      value={(displayScope.out_of_scope || []).join('\n')}
                      onChange={(e) => setEditState({
                        ...editState,
                        scope_boundaries: {
                          ...displayScope,
                          out_of_scope: e.target.value.split('\n').filter(line => line.trim())
                        }
                      })}
                      className="w-full px-3 py-2 bg-background border border-input rounded-md text-sm text-foreground/80 focus:outline-none focus:ring-2 focus:ring-ring"
                      rows={4}
                      placeholder="One item per line"
                    />
                  </div>
                </>
              ) : (
                <>
                  {displayScope.in_scope && displayScope.in_scope.length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold text-foreground/90 mb-2">In Scope</h4>
                      <ul className="list-disc list-inside space-y-1 text-sm text-foreground/80">
                        {displayScope.in_scope.map((item, idx) => (
                          <li key={idx}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  
                  {displayScope.out_of_scope && displayScope.out_of_scope.length > 0 && (
                    <div>
                      <h4 className="text-sm font-semibold text-foreground/90 mb-2">Out of Scope</h4>
                      <ul className="list-disc list-inside space-y-1 text-sm text-foreground/80">
                        {displayScope.out_of_scope.map((item, idx) => (
                          <li key={idx}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                </>
              )}
            </div>
          )}
          
          {/* Open Questions */}
          {displayOpenQuestions && displayOpenQuestions.length > 0 && (
            <div>
              <h4 className="text-sm font-semibold text-foreground/90 mb-2">Open Questions</h4>
              {isEditing ? (
                <textarea
                  value={displayOpenQuestions.join('\n')}
                  onChange={(e) => setEditState({
                    ...editState,
                    open_questions: e.target.value.split('\n').filter(line => line.trim())
                  })}
                  className="w-full px-3 py-2 bg-background border border-input rounded-md text-sm text-foreground/80 focus:outline-none focus:ring-2 focus:ring-ring"
                  rows={4}
                  placeholder="One question per line"
                />
              ) : (
                <ul className="list-disc list-inside space-y-1 text-sm text-foreground/80">
                  {displayOpenQuestions.map((item, idx) => (
                    <li key={idx}>{item}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
          
          {/* Save/Cancel Controls */}
          {isEditing && (
            <div className="flex items-center gap-2 pt-2 border-t border-border/30">
              <Button
                size="sm"
                onClick={() => handleSaveEdit(req)}
                disabled={isSaving}
                className="flex items-center gap-1"
              >
                {isSaving ? (
                  <Loader2 className="h-3 w-3 animate-spin" />
                ) : (
                  <Save className="h-3 w-3" />
                )}
                Save
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={handleCancelEdit}
                disabled={isSaving}
                className="flex items-center gap-1"
              >
                <XCircle className="h-3 w-3" />
                Cancel
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    )
  }
  
  return (
    <div className="space-y-4">
      {sortedParents.map((parent) => {
        const children = childrenByParent.get(parent.id) || []
        return (
          <div key={parent.id} className="space-y-3">
            {renderRequirement(parent, false)}
            {children.map(child => renderRequirement(child, true))}
          </div>
        )
      })}
      
      {/* Metadata - collapsed/subtle */}
      {(readableSummary.requires_human_review || readableSummary.confidence || readableSummary.key_gaps) && (
        <div className="mt-6 pt-4 border-t border-border/30">
          <details className="text-sm text-muted-foreground">
            <summary className="cursor-pointer hover:text-foreground/80">Metadata</summary>
            <div className="mt-2 space-y-1 pl-4">
              {readableSummary.requires_human_review && (
                <p>Requires human review: Yes</p>
              )}
              {readableSummary.confidence && (
                <p>Confidence: {readableSummary.confidence}</p>
              )}
              {readableSummary.key_gaps && Array.isArray(readableSummary.key_gaps) && readableSummary.key_gaps.length > 0 && (
                <div>
                  <p className="font-semibold mb-1">Key Gaps:</p>
                  <ul className="list-disc list-inside space-y-1">
                    {readableSummary.key_gaps.map((gap: string, idx: number) => (
                      <li key={idx}>{gap}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          </details>
        </div>
      )}
    </div>
  )
}

interface AttachmentFile {
  file: File
  id: string
}

// Helper function to get scope status badge
function getScopeStatusBadge(scopeStatus: string) {
  const variants: Record<string, { label: string; variant: 'default' | 'secondary' | 'success' | 'warning' | 'destructive'; icon: any }> = {
    draft: {
      label: 'Draft',
      variant: 'secondary',
      icon: Edit2
    },
    reviewed: {
      label: 'Reviewed',
      variant: 'warning',
      icon: AlertCircle
    },
    locked: {
      label: 'Locked',
      variant: 'success',
      icon: Lock
    }
  }
  
  const config = variants[scopeStatus] || {
    label: scopeStatus,
    variant: 'secondary' as const,
    icon: AlertCircle
  }
  
  const Icon = config.icon
  
  return (
    <Badge variant={config.variant} className="flex items-center gap-1">
      <Icon className="h-3 w-3" />
      {config.label}
    </Badge>
  )
}

export function RequirementsPage() {
  const { tenantStatus, bootstrapStatus } = useTenantStatus()
  const [inputSource, setInputSource] = useState<InputSource>('free-text')
  const [freeText, setFreeText] = useState('')
  const [jiraTickets, setJiraTickets] = useState<string[]>([''])
  const [attachments, setAttachments] = useState<AttachmentFile[]>([])
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<AnalyzeRequirementsResponse | null>(null)
  const [showLockModal, setShowLockModal] = useState(false)
  const [isTransitioning, setIsTransitioning] = useState(false)
  
  // Jira Target state (Phase 4B: Create)
  const [jiraProjects, setJiraProjects] = useState<JiraProject[]>([])
  const [selectedProjectKey, setSelectedProjectKey] = useState<string>('')
  const [isLoadingProjects, setIsLoadingProjects] = useState(false)
  const [createDryRunResult, setCreateDryRunResult] = useState<CreateDryRunResponse | null>(null)
  const [isCreatingDryRun, setIsCreatingDryRun] = useState(false)
  const [isExecuting, setIsExecuting] = useState(false)
  
  // Phase 4A: Rewrite state
  const [rewriteDryRunResult, setRewriteDryRunResult] = useState<RewriteDryRunResponse | null>(null)
  const [isRewritingDryRun, setIsRewritingDryRun] = useState(false)
  const [isRewritingExecute, setIsRewritingExecute] = useState(false)
  
  // Check if requirements generation is disabled
  const isRequirementsDisabled = tenantStatus 
    ? (tenantStatus.subscription_status === 'paywalled' || 
       (tenantStatus.subscription_status === 'trial' && tenantStatus.trial_requirements_runs_remaining <= 0))
    : false
  
  // Check if Jira writeback is disabled
  const isWritebackDisabled: boolean = tenantStatus
    ? (tenantStatus.subscription_status === 'paywalled' ||
       (tenantStatus.subscription_status === 'trial' && tenantStatus.trial_writeback_runs_remaining <= 0))
    : false
  
  // Also disable if Jira is not configured
  const isJiraNotConfigured: boolean = !!(bootstrapStatus && (!bootstrapStatus.jira.configured || !bootstrapStatus.jira.is_active))
  
  // Helper: Check if package is Jira-origin
  const isJiraOriginPackage = (): boolean => {
    if (!results?.package) return false
    const metadata = results.package.metadata || {}
    return metadata.source === 'jira' || 
           metadata.origin?.type === 'jira' || 
           metadata.jira_context !== undefined
  }

  // Phase 4A: Handle Rewrite Dry-Run
  const handleRewriteDryRun = async () => {
    if (!results?.package) return
    
    setIsRewritingDryRun(true)
    setError(null)
    
    try {
      const dryRunResponse = await rewriteDryRun({
        package: results.package
      })
      setRewriteDryRunResult(dryRunResponse)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to run rewrite dry-run')
    } finally {
      setIsRewritingDryRun(false)
    }
  }

  // Phase 4A: Handle Rewrite Execute
  const handleRewriteExecute = async () => {
    if (!results?.package || !rewriteDryRunResult) return
    
    setIsRewritingExecute(true)
    setError(null)
    
    try {
      const executeRequest: RewriteExecuteRequest = {
        package: results.package,
        checksum: rewriteDryRunResult.checksum,
        approved_by: 'user', // TODO: Get actual user ID
        approved_at: new Date().toISOString()
      }
      
      await rewriteExecute(executeRequest)
      setError(null)
      refreshTenantStatus()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to execute rewrite')
    } finally {
      setIsRewritingExecute(false)
    }
  }
  
  // Infer issue type from package data (defaults to "Story")
  const getInferredIssueType = (): string => {
    if (!results?.package) return 'Story'
    
    const requirements = results.package.requirements || []
    if (requirements.length > 0) {
      // Check first requirement for ticket_type
      const firstReq = requirements[0]
      if (firstReq?.ticket_type) {
        return firstReq.ticket_type
      }
    }
    
    // Default to Story
    return 'Story'
  }

  // Load Jira projects lazily - only when user actually needs them (e.g., clicking "Push to Jira")
  // Do NOT fetch on page load or when switching to free-text mode
  const loadJiraProjects = async (): Promise<boolean> => {
    // Check if Jira is configured before attempting to fetch
    if (isJiraNotConfigured) {
      // Jira is not configured - don't attempt fetch, return false
      return false
    }
    
    if (isLoadingProjects || jiraProjects.length > 0) return true
    
    setIsLoadingProjects(true)
    try {
      const projects = await getJiraProjects()
      setJiraProjects(projects)
      
      // Default to "ATA" project if available, otherwise first project
      const ataProject = projects.find(p => p.key === 'ATA')
      if (ataProject) {
        setSelectedProjectKey(ataProject.key)
      } else if (projects.length > 0) {
        setSelectedProjectKey(projects[0].key)
      }
      return true
    } catch (err) {
      // Handle Jira errors gracefully - don't set main error state for JIRA_NOT_CONFIGURED
      // This allows free-text mode to work without Jira
      const errorMessage = err instanceof Error ? err.message : 'Failed to load Jira projects'
      
      // Check if this is a JIRA_NOT_CONFIGURED error - handle silently
      // The banner will show that Jira is not configured
      if (errorMessage.includes('JIRA_NOT_CONFIGURED') || errorMessage.includes('not configured')) {
        // Only log the error, don't block the page
        console.warn('Jira is not configured - projects cannot be loaded')
        return false
      }
      
      // For other errors, log but don't block
      console.warn('Jira projects could not be loaded:', errorMessage)
      
      // Don't set main error state - this is non-blocking for free-text mode
      return false
    } finally {
      setIsLoadingProjects(false)
    }
  }
  
  // Handle project selection change
  const handleProjectChange = (projectKey: string) => {
    setSelectedProjectKey(projectKey)
  }
  
  // Handle input source change - clear Jira Target when switching to Jira Tickets
  const handleInputSourceChange = (newSource: InputSource) => {
    setInputSource(newSource)
    if (newSource === 'jira-tickets') {
      // Clear Jira Target state when switching to Jira Tickets
      setSelectedProjectKey('')
      setCreateDryRunResult(null)
    }
    // Do NOT load Jira projects when switching to free-text/document-upload
    // Projects will be loaded lazily when user clicks "Push to Jira" or "Create Dry Run"
  }
  
  // Handle Create Dry-Run
  const handleCreateDryRun = async () => {
    if (!results?.package) return
    
    // Lazy-load Jira projects if not already loaded
    if (jiraProjects.length === 0) {
      const loaded = await loadJiraProjects()
      if (!loaded) {
        // Jira is not configured - show error but don't block
        setError('Jira is not configured. Please configure Jira integration to push tickets.')
        return
      }
    }
    
    if (!selectedProjectKey) {
      setError('Please select a Jira project')
      return
    }
    
    setIsCreatingDryRun(true)
    setError(null)
    
    try {
      const dryRunResponse = await createJiraTicketDryRun({
        package: results.package,
        project_key: selectedProjectKey,
      })
      setCreateDryRunResult(dryRunResponse)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to create dry-run')
    } finally {
      setIsCreatingDryRun(false)
    }
  }
  
  // Handle Execute
  const handleExecute = async () => {
    if (!results?.package || !selectedProjectKey || !createDryRunResult) return
    
    setIsExecuting(true)
    setError(null)
    
    try {
      const executeResponse = await createJiraTicketExecute({
        package: results.package,
        project_key: selectedProjectKey,
        checksum: createDryRunResult.checksum,
        approved_by: 'user', // TODO: Get actual user ID
        approved_at: new Date().toISOString(),
      })
      
      setError(null)
      alert(`Jira ticket created successfully: ${executeResponse.created_issue_key}`)
      setCreateDryRunResult(null)
      refreshTenantStatus()
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to execute Jira ticket creation')
    } finally {
      setIsExecuting(false)
    }
  }

  // Do NOT auto-load Jira projects on page load or input source change
  // Projects will be loaded lazily when user actually needs them (e.g., clicking "Push to Jira")

  const handleJiraAddTicket = () => {
    setJiraTickets([...jiraTickets, ''])
  }

  const handleJiraRemoveTicket = (index: number) => {
    if (jiraTickets.length > 1) {
      setJiraTickets(jiraTickets.filter((_, i) => i !== index))
    }
  }

  const handleJiraTicketChange = (index: number, value: string) => {
    const newTickets = [...jiraTickets]
    newTickets[index] = value
    setJiraTickets(newTickets)
  }

  const handleAttachmentAdd = (event: React.ChangeEvent<HTMLInputElement>) => {
    const files = event.target.files
    if (!files) return

    const newAttachments: AttachmentFile[] = []
    for (let i = 0; i < files.length; i++) {
      const file = files[i]
      // Validate file type
      const allowedTypes = ['application/pdf', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document', 'text/plain', 'application/json']
      const allowedExtensions = ['.pdf', '.docx', '.txt', '.json']
      const fileExtension = file.name.toLowerCase().substring(file.name.lastIndexOf('.'))
      
      if (!allowedTypes.includes(file.type) && !allowedExtensions.includes(fileExtension)) {
        setError(`File type not supported: ${file.name}. Supported formats: PDF, DOCX, TXT, JSON`)
        continue
      }
      
      newAttachments.push({
        file,
        id: `${Date.now()}-${i}`
      })
    }
    
    setAttachments([...attachments, ...newAttachments])
    // Reset input
    event.target.value = ''
  }

  const handleAttachmentRemove = (id: string) => {
    setAttachments(attachments.filter(a => a.id !== id))
  }

  const hasInput = () => {
    if (inputSource === 'free-text') {
      return freeText.trim().length > 0
    } else if (inputSource === 'jira-tickets') {
      return jiraTickets.some(t => t.trim().length > 0)
    } else {
      return false
    }
  }

  const handleMarkReviewed = async () => {
    if (!results?.package) return
    
    setIsTransitioning(true)
    setError(null)
    
    try {
      const response = await markPackageReviewed(
        results.package.package_id,
        results.package,
        { changed_by: 'user' } // TODO: Get actual user ID
      )
      
      // Update results with new package state (refresh scope_status)
      setResults({
        ...results,
        package: response.package
      })
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to mark package as reviewed')
    } finally {
      setIsTransitioning(false)
    }
  }

  const handleLockScope = async () => {
    if (!results?.package) return
    
    setIsTransitioning(true)
    setError(null)
    
    try {
      const response = await lockPackageScope(
        results.package.package_id,
        results.package,
        { changed_by: 'user' } // TODO: Get actual user ID
      )
      
      // Update results with new package state (refresh scope_status)
      setResults({
        ...results,
        package: response.package
      })
      
      // Clear rewrite dry-run result when scope is locked (fresh state)
      setRewriteDryRunResult(null)
      
      // Close modal
      setShowLockModal(false)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to lock package scope')
    } finally {
      setIsTransitioning(false)
    }
  }

  const handleGenerate = async () => {
    setIsLoading(true)
    setError(null)
    setResults(null)
    setCreateDryRunResult(null) // Clear previous dry-run result

    try {
      let inputText = ''
      let source = ''

      // Prepare input based on selected mode
      if (inputSource === 'free-text') {
        inputText = freeText.trim()
        source = 'free-text'
      } else if (inputSource === 'jira-tickets') {
        const validTickets = jiraTickets.filter(t => t.trim().length > 0)
        if (validTickets.length === 0) {
          throw new Error('Please enter at least one Jira ticket ID')
        }
        inputText = validTickets.join(', ')
        source = 'jira'
      } else if (inputSource === 'document-upload') {
        throw new Error('Document upload is not yet implemented')
      }

      if (!inputText) {
        throw new Error('Please provide input text')
      }

      // PHASE 1 ATTACHMENT SUPPORT: Validate that free-form text is not empty if attachments exist
      if (attachments.length > 0 && !inputText.trim()) {
        throw new Error('Describe scope in text. Attachments are supporting materials only.')
      }

      // Call the API with attachments
      console.log('Calling analyzeRequirements with:', {
        input_text: inputText,
        source: source || undefined,
        attachmentCount: attachments.length
      })
      
      const response = await analyzeRequirements({
        input_text: inputText,
        source: source || undefined,
        attachments: attachments.map(a => a.file)
      })

      console.log('Received response:', response)
      setResults(response)
      refreshTenantStatus()
    } catch (err) {
      // Don't show error if it's a redirect message (session expired)
      if (err instanceof Error && err.message.includes('Redirecting to login')) {
        // Redirect is happening, don't show error
        return
      }
      
      // Show exact error message from backend (detail field)
      let errorMessage = 'Failed to generate requirements'
      if (err instanceof Error) {
        errorMessage = err.message
      } else if (typeof err === 'string') {
        errorMessage = err
      } else if (err && typeof err === 'object') {
        // Try to extract error message from error object (prefer detail field)
        errorMessage = (err as any).detail || (err as any).message || (err as any).error || JSON.stringify(err)
      }
      setError(errorMessage)
      console.error('Error generating requirements:', err)
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="space-y-8">
      <JiraNotConfiguredBanner />
      <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
        <CardHeader>
          <CardTitle className="text-2xl font-bold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent">
            AI Sr Business Analyst Scope
          </CardTitle>
          <p className="text-sm text-muted-foreground mt-2">
            Generate Normalized, consistent requirements from text, Jira, or documents.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-2">
            <label className="text-sm font-medium text-foreground">
              Input Source
            </label>
            <select
              value={inputSource}
              onChange={(e) => handleInputSourceChange(e.target.value as InputSource)}
              disabled={isLoading}
              className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background"
            >
              <option value="free-text">Free Text</option>
              <option value="jira-tickets">Jira Tickets</option>
              <option value="document-upload">Document Upload</option>
            </select>
          </div>

          {/* Jira Target section (Phase 4B: Create) - Only show for free-form/document */}
          {(inputSource === 'free-text' || inputSource === 'document-upload') && (
            <div className="space-y-4 border-t border-border/50 pt-4">
              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground">
                  Jira Target
                </label>
                <p className="text-xs text-muted-foreground">
                  Select the Jira project and issue type for ticket creation.
                </p>
              </div>
              
              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground">
                  Jira Project
                </label>
                <select
                  value={selectedProjectKey}
                  onChange={(e) => handleProjectChange(e.target.value)}
                  onFocus={async () => {
                    // Lazy-load Jira projects when user focuses on the dropdown
                    if (jiraProjects.length === 0 && !isLoadingProjects) {
                      await loadJiraProjects()
                    }
                  }}
                  disabled={isLoading || isLoadingProjects || isJiraNotConfigured}
                  className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background"
                >
                  <option value="">Select a project...</option>
                  {isLoadingProjects && (
                    <option value="" disabled>Loading projects...</option>
                  )}
                  {jiraProjects.map((project) => (
                    <option key={project.key} value={project.key}>
                      {project.name} ({project.key})
                    </option>
                  ))}
                </select>
              </div>
              
              <div className="space-y-2">
                <p className="text-sm text-muted-foreground">
                  Issue Type: <span className="font-medium text-foreground">{getInferredIssueType()}</span> (auto-selected by BA agent)
                </p>
              </div>
              
              {!selectedProjectKey && (
                <p className="text-xs text-muted-foreground">
                  Please select a project to enable Jira ticket creation.
                </p>
              )}
            </div>
          )}

          {inputSource === 'free-text' && (
            <>
              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground">
                  Requirements Text
                </label>
                <textarea
                  value={freeText}
                  onChange={(e) => setFreeText(e.target.value)}
                  placeholder="Paste or type requirements, user stories, or paragraphs here..."
                  disabled={isLoading}
                  rows={8}
                  className="w-full px-4 py-2 bg-background border border-input rounded-md text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background resize-y"
                />
              </div>
              
              {/* PHASE 1 ATTACHMENT SUPPORT: File upload section */}
              <div className="space-y-2">
                <label className="text-sm font-medium text-foreground">
                  Supporting Materials (Optional)
                </label>
                <p className="text-xs text-muted-foreground">
                  Attachments provide supporting context (e.g., API specs, diagrams).
                  Scope and requirements must still be described in text.
                </p>
                <div className="flex items-center gap-2">
                  <input
                    type="file"
                    id="attachment-upload"
                    multiple
                    accept=".pdf,.docx,.txt,.json"
                    onChange={handleAttachmentAdd}
                    disabled={isLoading}
                    className="hidden"
                  />
                  <label
                    htmlFor="attachment-upload"
                    className="px-4 py-2 bg-secondary text-secondary-foreground rounded-md hover:bg-secondary/80 cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed text-sm font-medium"
                  >
                    <Upload className="inline-block w-4 h-4 mr-2" />
                    Add Files
                  </label>
                </div>
                
                {/* Display uploaded attachments */}
                {attachments.length > 0 && (
                  <div className="mt-2 space-y-1">
                    {attachments.map((attachment) => (
                      <div
                        key={attachment.id}
                        className="flex items-center justify-between px-3 py-2 bg-secondary/50 rounded-md text-sm"
                      >
                        <span className="text-foreground">
                          {attachment.file.name} ({attachment.file.type || 'unknown type'})
                        </span>
                        <button
                          type="button"
                          onClick={() => handleAttachmentRemove(attachment.id)}
                          disabled={isLoading}
                          className="text-muted-foreground hover:text-foreground disabled:opacity-50"
                        >
                          <X className="w-4 h-4" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}

          {inputSource === 'jira-tickets' && (
            <div className="space-y-3">
              <label className="text-sm font-medium text-foreground">
                Jira Ticket IDs
              </label>
              <div className="space-y-3">
                {jiraTickets.map((ticket, index) => (
                  <div key={index} className="flex gap-2 items-center">
                    <input
                      type="text"
                      value={ticket}
                      onChange={(e) => handleJiraTicketChange(index, e.target.value)}
                      placeholder="Enter JIRA ticket ID (e.g., ATA-36)"
                      disabled={isLoading}
                      className="flex-1 px-4 py-2 bg-background border border-input rounded-md text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background"
                    />
                    {jiraTickets.length > 1 && (
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => handleJiraRemoveTicket(index)}
                        disabled={isLoading}
                        className="text-muted-foreground hover:text-foreground"
                      >
                        <X className="h-4 w-4" />
                      </Button>
                    )}
                  </div>
                ))}
              </div>
              <Button
                variant="outline"
                onClick={handleJiraAddTicket}
                disabled={isLoading}
                className="flex items-center gap-2"
              >
                <Plus className="h-4 w-4" />
                Add Ticket
              </Button>
            </div>
          )}

          {inputSource === 'document-upload' && (
            <div className="space-y-2">
              <label className="text-sm font-medium text-foreground">
                Upload requirements document
              </label>
              <div className="border-2 border-dashed border-input rounded-md p-8 text-center">
                <Upload className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                <p className="text-sm text-muted-foreground mb-1">
                  Drop your document here or click to browse
                </p>
                <p className="text-xs text-muted-foreground">
                  Supported formats: PDF, DOCX
                </p>
              </div>
            </div>
          )}

          <div className="pt-2">
            <Button
              onClick={handleGenerate}
              disabled={isLoading || !hasInput() || isRequirementsDisabled}
              className="w-full flex items-center justify-center gap-2 bg-gradient-to-r from-primary to-primary/80 hover:from-primary/90 hover:to-primary/70 shadow-[0_4px_14px_0_rgba(255,255,255,0.15)] hover:shadow-[0_6px_20px_0_rgba(59,130,246,0.3)] transition-all"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Generating...
                </>
              ) : (
                'Generate Requirements'
              )}
            </Button>
          </div>
        </CardContent>
      </Card>

      {error && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -10 }}
          className="p-4 bg-destructive/20 border border-destructive/50 rounded-lg"
        >
          <div className="font-semibold text-destructive mb-1">Request failed</div>
          <div className="text-sm text-destructive/90">{error}</div>
        </motion.div>
      )}

      <AnimatePresence>
        {results && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
          >
            <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
              <CardContent className="p-6">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h2 className="text-2xl font-bold">Generated Requirements</h2>
                    <div className="flex items-center gap-3">
                      {results.package?.scope_status && (
                        <>
                          {getScopeStatusBadge(results.package.scope_status)}
                          {results.package.scope_status === 'reviewed' && (
                            <Button
                              onClick={() => setShowLockModal(true)}
                              disabled={isTransitioning}
                              className="flex items-center gap-2"
                              variant="outline"
                            >
                              {isTransitioning ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <Lock className="h-4 w-4" />
                              )}
                              Lock Scope
                            </Button>
                          )}
                          {results.package.scope_status === 'draft' && (
                            <Button
                              onClick={handleMarkReviewed}
                              disabled={isTransitioning}
                              className="flex items-center gap-2"
                              variant="outline"
                            >
                              {isTransitioning ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <Check className="h-4 w-4" />
                              )}
                              Mark Reviewed
                            </Button>
                          )}
                        </>
                      )}
                    </div>
                  </div>
                  
                  {/* Scope Lifecycle Metadata */}
                  {results.package?.scope_status_transitions && results.package.scope_status_transitions.length > 0 && (
                    <div className="mt-4 pt-4 border-t border-border/50 space-y-2">
                      <h3 className="text-sm font-semibold">Scope Lifecycle</h3>
                      {results.package.scope_status_transitions
                        .filter((t: any) => t.new_status === 'reviewed' || t.new_status === 'locked')
                        .map((transition: any, idx: number) => (
                          <div key={idx} className="text-sm text-muted-foreground">
                            {transition.new_status === 'reviewed' && (
                              <>
                                <span className="font-medium">Reviewed:</span> {transition.changed_by || 'Unknown'} on {transition.changed_at ? new Date(transition.changed_at).toLocaleString() : 'N/A'}
                              </>
                            )}
                            {transition.new_status === 'locked' && (
                              <>
                                <span className="font-medium">Approved:</span> {transition.changed_by || 'Unknown'} on {transition.changed_at ? new Date(transition.changed_at).toLocaleString() : 'N/A'}
                              </>
                            )}
                          </div>
                        ))}
                    </div>
                  )}
                  
                  {/* Phase 4A: Rewrite Jira Ticket buttons (only for Jira-origin packages) */}
                  {results.package?.scope_status === 'locked' && 
                   inputSource === 'jira-tickets' && 
                   isJiraOriginPackage() && (
                    <div className="space-y-3 border-t border-border/50 pt-4">
                      <h3 className="text-lg font-semibold">Rewrite Jira Ticket</h3>
                      <div className="flex gap-2">
                        <Button
                          onClick={handleRewriteDryRun}
                          disabled={isRewritingDryRun || isRewritingExecute || isJiraNotConfigured}
                          variant="outline"
                          className="flex items-center gap-2"
                        >
                          {isRewritingDryRun ? (
                            <>
                              <Loader2 className="h-4 w-4 animate-spin" />
                              Running Dry-Run...
                            </>
                          ) : (
                            'Rewrite Dry-Run'
                          )}
                        </Button>
                        <Button
                          onClick={handleRewriteExecute}
                          disabled={isRewritingExecute || isRewritingDryRun || !rewriteDryRunResult || isWritebackDisabled || isJiraNotConfigured}
                          className="flex items-center gap-2"
                        >
                          {isRewritingExecute ? (
                            <>
                              <Loader2 className="h-4 w-4 animate-spin" />
                              Executing...
                            </>
                          ) : (
                            'Execute'
                          )}
                        </Button>
                      </div>
                      
                      {!rewriteDryRunResult && (
                        <p className="text-xs text-muted-foreground">
                          Run Dry-Run to enable Execute.
                        </p>
                      )}
                      
                      {rewriteDryRunResult && (
                        <div className="mt-4 p-4 bg-secondary/50 rounded-md space-y-2">
                          <p className="text-sm font-medium">Dry-Run Preview:</p>
                          <p className="text-xs text-muted-foreground">
                            <strong>Issue:</strong> {rewriteDryRunResult.jira_issue}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            <strong>Checksum:</strong> {rewriteDryRunResult.checksum}
                          </p>
                        </div>
                      )}
                    </div>
                  )}
                  
                  {/* Phase 4B: Create Jira Ticket buttons (only for free-form/document packages) */}
                  {results.package?.scope_status === 'locked' && 
                   (inputSource === 'free-text' || inputSource === 'document-upload') && 
                   results.package?.metadata?.origin?.type !== 'jira' && (
                    <div className="space-y-3 border-t border-border/50 pt-4">
                      <h3 className="text-lg font-semibold">Create Jira Ticket</h3>
                      <div className="flex gap-2">
                        <Button
                          onClick={handleCreateDryRun}
                          disabled={isCreatingDryRun || isExecuting || !selectedProjectKey}
                          variant="outline"
                          className="flex items-center gap-2"
                        >
                          {isCreatingDryRun ? (
                            <>
                              <Loader2 className="h-4 w-4 animate-spin" />
                              Running Dry-Run...
                            </>
                          ) : (
                            'Create Dry-Run'
                          )}
                        </Button>
                        <Button
                          onClick={handleExecute}
                          disabled={isExecuting || isCreatingDryRun || !createDryRunResult || !selectedProjectKey || isWritebackDisabled || isJiraNotConfigured}
                          className="flex items-center gap-2"
                        >
                          {isExecuting ? (
                            <>
                              <Loader2 className="h-4 w-4 animate-spin" />
                              Creating...
                            </>
                          ) : (
                            'Execute'
                          )}
                        </Button>
                      </div>
                      
                      {createDryRunResult && (
                        <div className="mt-4 p-4 bg-secondary/50 rounded-md space-y-2">
                          <p className="text-sm font-medium">Dry-Run Preview:</p>
                          <p className="text-xs text-muted-foreground">
                            <strong>Project:</strong> {createDryRunResult.proposed_issue.project_key} | 
                            <strong> Type:</strong> {createDryRunResult.proposed_issue.issue_type} | 
                            <strong> Summary:</strong> {createDryRunResult.proposed_issue.summary}
                          </p>
                          <p className="text-xs text-muted-foreground">
                            <strong>Checksum:</strong> {createDryRunResult.checksum}
                          </p>
                        </div>
                      )}
                    </div>
                  )}
                  
                  <div className="space-y-4">
                    <div>
                      <h3 className="text-lg font-semibold mb-2">Summary</h3>
                      <pre className="bg-black/40 border border-white/10 rounded-md p-4 overflow-auto text-sm font-mono text-foreground/80">
                        {JSON.stringify({
                          ...results.summary,
                          status: (() => {
                            // Derive status from package.scope_status (authoritative)
                            const scopeStatus = results.package?.scope_status
                            if (scopeStatus === 'draft') return 'DRAFT'
                            if (scopeStatus === 'reviewed') return 'IN_REVIEW'
                            if (scopeStatus === 'locked') return 'LOCKED'
                            // Fallback to existing summary status for older packages
                            return results.summary?.status || 'UNKNOWN'
                          })()
                        }, null, 2)}
                      </pre>
                    </div>
                    {results.package?.requirements && (
                      <div>
                        <h3 className="text-lg font-semibold mb-3">Tickets by Sub Type</h3>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div className="bg-black/40 border border-white/10 rounded-md p-4">
                            <div className="text-sm text-muted-foreground mb-1">Parent Requirements (Stories)</div>
                            <div className="text-2xl font-bold text-foreground">
                              {results.package.requirements.filter((req: any) => !req.parent_id || req.parent_id === null).length}
                            </div>
                          </div>
                          <div className="bg-black/40 border border-white/10 rounded-md p-4">
                            <div className="text-sm text-muted-foreground mb-1">Child Requirements (Sub-tasks)</div>
                            <div className="text-2xl font-bold text-foreground">
                              {results.package.requirements.filter((req: any) => req.parent_id !== null && req.parent_id !== undefined).length}
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                    {results.package?.requirements && (() => {
                      const requirementsWithScores = results.package.requirements.filter((req: any) => req.quality_scores)
                      if (requirementsWithScores.length === 0) return null
                      
                      const avgClarity = requirementsWithScores.reduce((sum: number, req: any) => sum + req.quality_scores.clarity, 0) / requirementsWithScores.length
                      const avgScope = requirementsWithScores.reduce((sum: number, req: any) => sum + req.quality_scores.scope_containment, 0) / requirementsWithScores.length
                      
                      const getScoreColor = (score: number) => {
                        if (score >= 0.75) return 'text-green-400'
                        if (score >= 0.5) return 'text-yellow-400'
                        return 'text-red-400'
                      }
                      const getScoreBg = (score: number) => {
                        if (score >= 0.75) return 'bg-green-500/20 border-green-500/30'
                        if (score >= 0.5) return 'bg-yellow-500/20 border-yellow-500/30'
                        return 'bg-red-500/20 border-red-500/30'
                      }
                      
                      return (
                        <div>
                          <h3 className="text-lg font-semibold mb-3">Quality Scores</h3>
                          <div className="mb-4">
                            <div className="text-sm text-muted-foreground mb-2">Average Scores Across All Requirements</div>
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                              <div className={`${getScoreBg(avgClarity)} border rounded-md p-3`}>
                                <div className="text-xs text-muted-foreground mb-1">Avg Clarity</div>
                                <div className={`text-xl font-bold ${getScoreColor(avgClarity)}`}>
                                  {(avgClarity * 100).toFixed(0)}%
                                </div>
                              </div>
                              <div className={`${getScoreBg(avgScope)} border rounded-md p-3`}>
                                <div className="text-xs text-muted-foreground mb-1">Avg Scope Containment</div>
                                <div className={`text-xl font-bold ${getScoreColor(avgScope)}`}>
                                  {(avgScope * 100).toFixed(0)}%
                                </div>
                              </div>
                            </div>
                          </div>
                          <div className="space-y-4">
                            {requirementsWithScores.map((req: any) => {
                              const { clarity, scope_containment } = req.quality_scores
                              return (
                                <div key={req.id} className="bg-black/40 border border-white/10 rounded-md p-4">
                                  <div className="flex items-center justify-between mb-2">
                                    <div>
                                      <div className="font-semibold text-foreground">{req.id}: {req.title}</div>
                                      {req.parent_id && (
                                        <div className="text-xs text-muted-foreground mt-1">Child of {req.parent_id}</div>
                                      )}
                                    </div>
                                  </div>
                                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3 mt-3">
                                    <div className={`${getScoreBg(clarity)} border rounded-md p-3`}>
                                      <div className="text-xs text-muted-foreground mb-1">Clarity</div>
                                      <div className={`text-xl font-bold ${getScoreColor(clarity)}`}>
                                        {(clarity * 100).toFixed(0)}%
                                      </div>
                                    </div>
                                    <div className={`${getScoreBg(scope_containment)} border rounded-md p-3`}>
                                      <div className="text-xs text-muted-foreground mb-1">Scope Containment</div>
                                      <div className={`text-xl font-bold ${getScoreColor(scope_containment)}`}>
                                        {(scope_containment * 100).toFixed(0)}%
                                      </div>
                                    </div>
                                  </div>
                                  {req.quality_notes && req.quality_notes.length > 0 && (
                                    <div className="mt-3 pt-3 border-t border-white/10">
                                      <div className="text-xs text-muted-foreground mb-1">Quality Notes:</div>
                                      <ul className="list-disc list-inside text-sm text-foreground/80 space-y-1">
                                        {req.quality_notes.map((note: string, idx: number) => (
                                          <li key={idx}>{note}</li>
                                        ))}
                                      </ul>
                                    </div>
                                  )}
                                </div>
                              )
                            })}
                          </div>
                        </div>
                      )
                    })()}
                    <div>
                      <h3 className="text-lg font-semibold mb-2">Requirements Package</h3>
                      <pre className="bg-black/40 border border-white/10 rounded-md p-4 overflow-auto max-h-96 text-sm font-mono text-foreground/80">
                        {JSON.stringify(results.package, null, 2)}
                      </pre>
                    </div>
                    {results.readable_summary && results.package?.requirements && (
                      <div>
                        <h3 className="text-lg font-semibold mb-4">Readable Summary</h3>
                        <ReadableSummaryView 
                          requirements={results.package.requirements}
                          readableSummary={results.readable_summary}
                          packageData={results.package}
                          onRequirementUpdate={(requirementId, updatedRequirement) => {
                            // Update the requirement in results.package.requirements
                            if (results) {
                              const updatedPackage = {
                                ...results.package,
                                requirements: results.package.requirements.map((req: any) =>
                                  req.id === requirementId ? updatedRequirement : req
                                )
                              }
                              setResults({
                                ...results,
                                package: updatedPackage
                              })
                            }
                          }}
                        />
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>

      {!results && !error && (
        <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
          <CardContent className="p-6">
            <div className="space-y-4">
              <h2 className="text-2xl font-bold">Generated Requirements</h2>
              <p className="text-muted-foreground">
                Generated requirements will appear here.
              </p>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Lock Scope Confirmation Modal */}
      {showLockModal && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <Card className="max-w-md w-full mx-4">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertCircle className="h-5 w-5 text-amber-500" />
                Lock Scope?
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <p className="text-sm text-foreground/90">
                Locking scope prevents further edits and enables downstream actions like Jira write-back.
              </p>
              <div className="bg-amber-500/10 border border-amber-500/30 rounded-md p-3">
                <p className="text-sm font-semibold text-amber-700 dark:text-amber-300 mb-2">
                  Once locked, the following will be disabled:
                </p>
                <ul className="text-xs text-amber-600 dark:text-amber-400 space-y-1 list-disc list-inside">
                  <li>Manual edits to requirements or business requirements</li>
                  <li>AI regeneration</li>
                  <li>Automatic requirement decomposition</li>
                  <li>Attachment re-processing</li>
                </ul>
              </div>
              <div className="flex items-center gap-2 justify-end">
                <Button
                  variant="outline"
                  onClick={() => setShowLockModal(false)}
                  disabled={isTransitioning}
                >
                  Cancel
                </Button>
                <Button
                  onClick={handleLockScope}
                  disabled={isTransitioning}
                  className="flex items-center gap-2"
                >
                  {isTransitioning ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Lock className="h-4 w-4" />
                  )}
                  Lock Scope
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}
