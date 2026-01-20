import { useState, useEffect } from 'react'
import { useParams, useNavigate, useSearchParams } from 'react-router-dom'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Button } from './ui/button'
import { Badge } from './ui/badge'
import { Tabs, TabsList, TabsTrigger, TabsContent } from './ui/tabs'
import { FileDown, ArrowLeft, Loader2, AlertCircle, ExternalLink } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { 
  fetchRuns, 
  Run, 
  fetchTestPlanArtifact, 
  fetchRTMArtifact, 
  fetchAnalysisArtifact, 
  fetchAuditArtifact,
  markRunReviewed,
  approveRun,
  createJiraTicket,
  refreshTenantStatus,
  PaginationMeta
} from '../services/api'
import { Pagination } from './Pagination'

export function RunHistoryPage() {
  const { runId } = useParams<{ runId?: string }>()
  const navigate = useNavigate()
  const [searchParams, setSearchParams] = useSearchParams()
  const [runs, setRuns] = useState<Run[]>([])
  const [pagination, setPagination] = useState<PaginationMeta | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [page, setPage] = useState(() => {
    const pageParam = searchParams.get('page')
    return pageParam ? Math.max(1, parseInt(pageParam, 10)) : 1
  })
  const limit = 10
  const [selectedRun, setSelectedRun] = useState<Run | null>(null)
  const [artifacts, setArtifacts] = useState<{
    testPlan: any | null
    rtm: any | null
    analysis: any | null
    audit: any | null
  }>({
    testPlan: null,
    rtm: null,
    analysis: null,
    audit: null
  })
  const [artifactsLoading, setArtifactsLoading] = useState(false)
  const [artifactsError, setArtifactsError] = useState<string | null>(null)
  const [activeArtifactTab, setActiveArtifactTab] = useState('analysis')
  const [isTransitioning, setIsTransitioning] = useState(false)
  const [transitionError, setTransitionError] = useState<string | null>(null)

  // Sync URL to state on mount
  useEffect(() => {
    const currentPage = searchParams.get('page')
    const pageNum = currentPage ? Math.max(1, parseInt(currentPage, 10)) : 1
    if (pageNum !== page) {
      setPage(pageNum)
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []) // Only run on mount

  // Load runs when page changes
  useEffect(() => {
    loadRuns()
  }, [page])

  useEffect(() => {
    if (runId) {
      if (runs.length > 0) {
        const run = runs.find(r => r.run_id === runId)
        if (run) {
          setSelectedRun(run)
          loadArtifacts(run.run_id)
        } else {
          // Run not found in list, try to load artifacts anyway
          loadArtifacts(runId)
        }
      } else {
        // Runs not loaded yet, but we have runId - load artifacts
        loadArtifacts(runId)
      }
    } else {
      setSelectedRun(null)
      setArtifacts({
        testPlan: null,
        rtm: null,
        analysis: null,
        audit: null
      })
    }
  }, [runId, runs])

  const loadRuns = async () => {
    setIsLoading(true)
    setError(null)
    try {
      const response = await fetchRuns({ page, limit })
      
      // Auto-clamp: if page > total_pages and total_pages > 0, redirect to last valid page
      if (response.pagination.total_pages > 0 && 
          response.items.length === 0 && 
          page > response.pagination.total_pages) {
        const clampedPage = response.pagination.total_pages
        setPage(clampedPage)
        setSearchParams({ page: clampedPage.toString() }, { replace: true })
        // Re-fetch with clamped page (will happen via useEffect dependency on page)
        setIsLoading(false)
        return
      }
      
      setRuns(response.items)
      setPagination(response.pagination)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to load runs')
    } finally {
      setIsLoading(false)
    }
  }

  const handlePageChange = (newPage: number) => {
    setPage(newPage)
    setSearchParams({ page: newPage.toString() }, { replace: true })
  }

  const loadArtifacts = async (runId: string) => {
    setArtifactsLoading(true)
    setArtifactsError(null)
    try {
      const [testPlanResult, rtmResult, analysisResult, auditResult] = await Promise.allSettled([
        fetchTestPlanArtifact(runId),
        fetchRTMArtifact(runId),
        fetchAnalysisArtifact(runId),
        fetchAuditArtifact(runId)
      ])

      setArtifacts({
        testPlan: testPlanResult.status === 'fulfilled' ? testPlanResult.value : null,
        rtm: rtmResult.status === 'fulfilled' ? rtmResult.value : null,
        analysis: analysisResult.status === 'fulfilled' ? analysisResult.value : null,
        audit: auditResult.status === 'fulfilled' ? auditResult.value : null
      })

      // Check if any artifacts failed
      const failures = [
        testPlanResult.status === 'rejected' && testPlanResult.reason,
        rtmResult.status === 'rejected' && rtmResult.reason,
        analysisResult.status === 'rejected' && analysisResult.reason,
        auditResult.status === 'rejected' && auditResult.reason
      ].filter(Boolean)

      if (failures.length > 0 && failures.length === 4) {
        setArtifactsError('Artifacts not available')
      }
    } catch (err) {
      setArtifactsError(err instanceof Error ? err.message : 'Failed to load artifacts')
    } finally {
      setArtifactsLoading(false)
    }
  }

  const handleRunClick = (run: Run) => {
    navigate(`/run-history/${run.run_id}`)
  }

  const handleDownloadArtifact = (artifactType: string, artifactData: any) => {
    if (!artifactData || !runId) return
    
    const blob = new Blob([JSON.stringify(artifactData, null, 2)], { type: 'application/json' })
    const url = window.URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${artifactType}-${runId}.json`
    document.body.appendChild(a)
    a.click()
    window.URL.revokeObjectURL(url)
    document.body.removeChild(a)
  }

  const getStatusBadge = (status: string) => {
    const variants: Record<string, 'default' | 'secondary' | 'success' | 'warning' | 'destructive'> = {
      generated: 'success',
      success: 'success',
      error: 'destructive'
    }
    return (
      <Badge variant={variants[status] || 'secondary'} className="text-xs">
        {status.toUpperCase()}
      </Badge>
    )
  }

  const getReviewStatusBadge = (reviewStatus?: string) => {
    if (!reviewStatus) reviewStatus = 'generated'
    const variants: Record<string, 'default' | 'secondary' | 'success' | 'warning' | 'destructive'> = {
      generated: 'secondary',
      reviewed: 'warning',
      approved: 'success'
    }
    return (
      <Badge variant={variants[reviewStatus] || 'secondary'} className="text-xs">
        {reviewStatus.toUpperCase()}
      </Badge>
    )
  }

  const getAgentDisplayName = (agent?: string): string => {
    if (!agent) {
      return 'Testing Agent'
    }
    switch (agent) {
      case 'ba-agent':
        return 'Business Requirements Agent'
      case 'testing-agent':
        return 'Testing Agent'
      default:
        // Title-case the raw value as fallback
        return agent
          .split('-')
          .map(word => word.charAt(0).toUpperCase() + word.slice(1))
          .join(' ')
    }
  }

  const handleMarkReviewed = async () => {
    if (!selectedRun) return
    if (!window.confirm('Mark this run as reviewed? This action cannot be undone.')) return

    setIsTransitioning(true)
    setTransitionError(null)
    try {
      const updatedRun = await markRunReviewed(selectedRun.run_id)
      // Update the run in the list
      setRuns(runs.map(r => r.run_id === updatedRun.run_id ? updatedRun : r))
      setSelectedRun(updatedRun)
      // Reload runs to get fresh data
      await loadRuns()
    } catch (err) {
      setTransitionError(err instanceof Error ? err.message : 'Failed to mark run as reviewed')
    } finally {
      setIsTransitioning(false)
    }
  }

  const handleApprove = async () => {
    if (!selectedRun) return
    if (!window.confirm('Approve this run? Once approved, the run becomes immutable and cannot be changed.')) return

    setIsTransitioning(true)
    setTransitionError(null)
    try {
      const updatedRun = await approveRun(selectedRun.run_id)
      // Update the run in the list
      setRuns(runs.map(r => r.run_id === updatedRun.run_id ? updatedRun : r))
      setSelectedRun(updatedRun)
      // Reload runs to get fresh data
      await loadRuns()
    } catch (err) {
      setTransitionError(err instanceof Error ? err.message : 'Failed to approve run')
    } finally {
      setIsTransitioning(false)
    }
  }

  const handleCreateJiraTicket = async () => {
    if (!selectedRun) return
    if (!window.confirm('Create a Jira ticket from this approved run? This action cannot be undone.')) return

    setIsTransitioning(true)
    setTransitionError(null)
    try {
      await createJiraTicket(selectedRun.run_id)
      await loadRuns()
      const updatedResponse = await fetchRuns({ page, limit })
      const updatedRun = updatedResponse.items.find(r => r.run_id === selectedRun.run_id)
      if (updatedRun) {
        setSelectedRun(updatedRun)
      }
      refreshTenantStatus()
    } catch (err) {
      setTransitionError(err instanceof Error ? err.message : 'Failed to create Jira ticket')
    } finally {
      setIsTransitioning(false)
    }
  }

  if (runId) {
    // Run detail view
    const displayRun: Run | null = selectedRun || (runId ? { 
      run_id: runId, 
      created_at: '', 
      created_by: 'unknown', 
      status: 'unknown', 
      source_type: 'unknown', 
      ticket_count: null, 
      environment: null,
      logic_version: null,
      model_name: null
    } as unknown as Run : null)
    
    if (!displayRun) {
      return (
        <div className="space-y-6">
          <Card>
            <CardContent className="p-6 text-center">
              <p className="text-muted-foreground">Run not found</p>
            </CardContent>
          </Card>
        </div>
      )
    }
    
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <Button
            variant="outline"
            onClick={() => navigate('/run-history')}
            className="flex items-center gap-2"
          >
            <ArrowLeft className="h-4 w-4" />
            Back to List
          </Button>
          <div>
            <h1 className="text-2xl font-bold">Run Details</h1>
            <p className="text-sm text-muted-foreground">Run ID: {displayRun.run_id}</p>
          </div>
        </div>

        <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
          <CardHeader>
            <CardTitle>Run Metadata</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-4 text-sm">
              {displayRun.created_at && (
                <div>
                  <span className="text-muted-foreground">Created At:</span>
                  <p className="font-medium">{new Date(displayRun.created_at).toLocaleString()}</p>
                </div>
              )}
              <div>
                <span className="text-muted-foreground">Created By:</span>
                <p className="font-medium">{displayRun.created_by}</p>
              </div>
              <div>
                <span className="text-muted-foreground">Status:</span>
                <div className="mt-1">{getStatusBadge(displayRun.status)}</div>
              </div>
              <div>
                <span className="text-muted-foreground">Review Status:</span>
                <div className="mt-1">{getReviewStatusBadge(displayRun.review_status || 'generated')}</div>
              </div>
              <div>
                <span className="text-muted-foreground">Source Type:</span>
                <p className="font-medium">{displayRun.source_type}</p>
              </div>
              <div>
                <span className="text-muted-foreground">Agent:</span>
                <p className="font-medium">{getAgentDisplayName(displayRun.agent || undefined)}</p>
              </div>
              {displayRun.ticket_count !== null && (
                <div>
                  <span className="text-muted-foreground">Ticket Count:</span>
                  <p className="font-medium">{displayRun.ticket_count}</p>
                </div>
              )}
              {displayRun.environment && (
                <div>
                  <span className="text-muted-foreground">Environment:</span>
                  <p className="font-medium">{displayRun.environment}</p>
                </div>
              )}
              {displayRun.reviewed_by && (
                <div>
                  <span className="text-muted-foreground">Reviewed By:</span>
                  <p className="font-medium">{displayRun.reviewed_by}</p>
                </div>
              )}
              {displayRun.reviewed_at && (
                <div>
                  <span className="text-muted-foreground">Reviewed At:</span>
                  <p className="font-medium">{new Date(displayRun.reviewed_at).toLocaleString()}</p>
                </div>
              )}
              {displayRun.approved_by && (
                <div>
                  <span className="text-muted-foreground">Approved By:</span>
                  <p className="font-medium">{displayRun.approved_by}</p>
                </div>
              )}
              {displayRun.approved_at && (
                <div>
                  <span className="text-muted-foreground">Approved At:</span>
                  <p className="font-medium">{new Date(displayRun.approved_at).toLocaleString()}</p>
                </div>
              )}
            </div>
            
            {/* Review/Approval Actions */}
            {(displayRun.review_status === 'generated' || !displayRun.review_status) && (
              <div className="mt-4 pt-4 border-t border-border/50">
                <Button
                  onClick={handleMarkReviewed}
                  disabled={isTransitioning}
                  className="flex items-center gap-2"
                >
                  {isTransitioning ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Processing...
                    </>
                  ) : (
                    'Mark as Reviewed'
                  )}
                </Button>
              </div>
            )}
            {displayRun.review_status === 'reviewed' && (
              <div className="mt-4 pt-4 border-t border-border/50">
                <Button
                  onClick={handleApprove}
                  disabled={isTransitioning}
                  className="flex items-center gap-2"
                >
                  {isTransitioning ? (
                    <>
                      <Loader2 className="h-4 w-4 animate-spin" />
                      Processing...
                    </>
                  ) : (
                    'Approve Run'
                  )}
                </Button>
              </div>
            )}
            {displayRun.review_status === 'approved' && (
              <div className="mt-4 pt-4 border-t border-border/50">
                <p className="text-sm text-muted-foreground mb-4">
                  This run is approved and immutable. No further changes are allowed.
                </p>
                
                {/* Jira Write-Back (Phase 3) */}
                <div className="space-y-2">
                  <h3 className="text-sm font-semibold">Jira Integration</h3>
                  {displayRun.jira_issue_key ? (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <span className="text-sm text-muted-foreground">Jira Issue:</span>
                        <a
                          href={displayRun.jira_issue_url || '#'}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sm font-mono text-primary hover:underline flex items-center gap-1"
                        >
                          {displayRun.jira_issue_key}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                      </div>
                      {displayRun.created_by && (
                        <p className="text-xs text-muted-foreground">
                          Created by {displayRun.created_by} on{' '}
                          {(displayRun as any).jira_created_at || displayRun.created_at
                            ? new Date((displayRun as any).jira_created_at || displayRun.created_at).toLocaleString()
                            : 'N/A'}
                        </p>
                      )}
                    </div>
                  ) : (
                    <Button
                      onClick={handleCreateJiraTicket}
                      disabled={isTransitioning}
                      className="flex items-center gap-2"
                    >
                      {isTransitioning ? (
                        <>
                          <Loader2 className="h-4 w-4 animate-spin" />
                          Creating...
                        </>
                      ) : (
                        'Create Jira Ticket'
                      )}
                    </Button>
                  )}
                </div>
              </div>
            )}
            {transitionError && (
              <div className="mt-4 p-3 bg-destructive/10 border border-destructive/20 rounded-md">
                <p className="text-sm text-destructive">{transitionError}</p>
              </div>
            )}
          </CardContent>
        </Card>

        {artifactsLoading ? (
          <Card>
            <CardContent className="p-6 flex items-center justify-center">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </CardContent>
          </Card>
        ) : artifactsError ? (
          <Card>
            <CardContent className="p-6">
              <div className="flex items-center gap-2 text-destructive">
                <AlertCircle className="h-5 w-5" />
                <p>{artifactsError}</p>
              </div>
            </CardContent>
          </Card>
        ) : (
          <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle>Artifacts</CardTitle>
                <div className="flex gap-2">
                  {artifacts.analysis && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleDownloadArtifact('analysis', artifacts.analysis)}
                      className="flex items-center gap-2"
                    >
                      <FileDown className="h-4 w-4" />
                      Analysis JSON
                    </Button>
                  )}
                  {artifacts.testPlan && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleDownloadArtifact('test-plan', artifacts.testPlan)}
                      className="flex items-center gap-2"
                    >
                      <FileDown className="h-4 w-4" />
                      Test Plan JSON
                    </Button>
                  )}
                  {artifacts.rtm && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleDownloadArtifact('rtm', artifacts.rtm)}
                      className="flex items-center gap-2"
                    >
                      <FileDown className="h-4 w-4" />
                      RTM JSON
                    </Button>
                  )}
                  {artifacts.audit && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleDownloadArtifact('audit', artifacts.audit)}
                      className="flex items-center gap-2"
                    >
                      <FileDown className="h-4 w-4" />
                      Audit JSON
                    </Button>
                  )}
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <Tabs value={activeArtifactTab} onValueChange={setActiveArtifactTab}>
                <TabsList className="mb-4">
                  <TabsTrigger value="analysis">Analysis</TabsTrigger>
                  <TabsTrigger value="test-plan">Test Plan</TabsTrigger>
                  <TabsTrigger value="rtm">RTM</TabsTrigger>
                  <TabsTrigger value="audit">Audit</TabsTrigger>
                </TabsList>
                <TabsContent value="analysis">
                  {artifacts.analysis ? (
                    <pre className="bg-secondary/50 p-4 rounded-md overflow-auto text-xs">
                      {JSON.stringify(artifacts.analysis, null, 2)}
                    </pre>
                  ) : (
                    <p className="text-muted-foreground">Artifact not available</p>
                  )}
                </TabsContent>
                <TabsContent value="test-plan">
                  {artifacts.testPlan ? (
                    <pre className="bg-secondary/50 p-4 rounded-md overflow-auto text-xs">
                      {JSON.stringify(artifacts.testPlan, null, 2)}
                    </pre>
                  ) : (
                    <p className="text-muted-foreground">Artifact not available</p>
                  )}
                </TabsContent>
                <TabsContent value="rtm">
                  {artifacts.rtm ? (
                    <pre className="bg-secondary/50 p-4 rounded-md overflow-auto text-xs">
                      {JSON.stringify(artifacts.rtm, null, 2)}
                    </pre>
                  ) : (
                    <p className="text-muted-foreground">Artifact not available</p>
                  )}
                </TabsContent>
                <TabsContent value="audit">
                  {artifacts.audit ? (
                    <pre className="bg-secondary/50 p-4 rounded-md overflow-auto text-xs">
                      {JSON.stringify(artifacts.audit, null, 2)}
                    </pre>
                  ) : (
                    <p className="text-muted-foreground">Artifact not available</p>
                  )}
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        )}
      </div>
    )
  }

  // Run list view
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold mb-2">Run History</h1>
        <p className="text-sm text-muted-foreground">
          View past test plan generation runs and their artifacts
        </p>
      </div>

      {isLoading ? (
        <Card>
          <CardContent className="p-6 flex items-center justify-center">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </CardContent>
        </Card>
      ) : error ? (
        <Card>
          <CardContent className="p-6">
            <div className="flex items-center gap-2 text-destructive">
              <AlertCircle className="h-5 w-5" />
              <p>{error}</p>
            </div>
          </CardContent>
        </Card>
      ) : runs.length === 0 ? (
        <Card>
          <CardContent className="p-6 text-center">
            <p className="text-muted-foreground">No runs available yet</p>
          </CardContent>
        </Card>
      ) : (
        <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
          <CardHeader>
            <CardTitle>Runs</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              <AnimatePresence>
                {runs.map((run) => (
                  <motion.div
                    key={run.run_id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -10 }}
                    className="border border-border/50 rounded-lg p-4 hover:bg-secondary/50 cursor-pointer transition-colors"
                    onClick={() => handleRunClick(run)}
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex-1">
                        <div className="flex items-center gap-3 mb-2">
                          <p className="font-mono text-sm font-medium">{run.run_id}</p>
                          {getStatusBadge(run.status)}
                        </div>
                        <div className="grid grid-cols-3 gap-4 text-sm text-muted-foreground">
                          <div>
                            <span className="font-medium">Created:</span>{' '}
                            {new Date(run.created_at).toLocaleString()}
                          </div>
                          <div>
                            <span className="font-medium">By:</span> {run.created_by}
                          </div>
                          <div>
                            <span className="font-medium">Source:</span> {run.source_type}
                          </div>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                ))}
              </AnimatePresence>
            </div>
            {pagination && (
              <Pagination
                page={pagination.page}
                totalPages={pagination.total_pages}
                onPageChange={handlePageChange}
                total={pagination.total}
                limit={pagination.limit}
              />
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
