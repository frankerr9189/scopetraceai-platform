import { useState } from 'react'
import { TicketInputPanel } from './TicketInputPanel'
import { TestPlanView } from './TestPlanView'
import { RTMTable } from './RTMTable'
import { RequirementsView } from './RequirementsView'
import { TicketsView } from './TicketsView'
import { TicketBreakdownView } from './TicketBreakdownView'
import { RequirementCentricTestView } from './RequirementCentricTestView'
import { AuditMetadataView } from './AuditMetadataView'
import { Tabs, TabsList, TabsTrigger } from './ui/tabs'
import { Button } from './ui/button'
import { Card, CardContent } from './ui/card'
import { Download, FileDown } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'
import { generateTestPlan, downloadRTM, downloadExecutionReport, TestPlanResponse, fetchTestPlanArtifact, fetchRTMArtifact, fetchAnalysisArtifact, fetchAuditArtifact, refreshTenantStatus } from '../services/api'
import { useTenantStatus } from '../contexts/TenantStatusContext'
import { JiraNotConfiguredBanner } from './JiraNotConfiguredBanner'

interface TestPlanPageProps {
  testPlanData: TestPlanResponse | null
  setTestPlanData: (data: TestPlanResponse | null) => void
  activeTab: string
  setActiveTab: (tab: string) => void
}

export function TestPlanPage({ testPlanData, setTestPlanData, activeTab, setActiveTab }: TestPlanPageProps) {
  const { tenantStatus } = useTenantStatus()
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [executionReportError, setExecutionReportError] = useState<string | null>(null)
  
  // Check if test plan generation is disabled
  const isTestPlanDisabled = tenantStatus
    ? (tenantStatus.subscription_status === 'paywalled' ||
       (tenantStatus.subscription_status === 'trial' && tenantStatus.trial_testplan_runs_remaining <= 0))
    : false

  const handleGenerate = async (tickets: { ticket_id: string }[]) => {
    setIsLoading(true)
    setError(null)
    setTestPlanData(null)
    
    try {
      const data = await generateTestPlan(tickets)
      setTestPlanData(data)
      setActiveTab('tickets')
      refreshTenantStatus()
    } catch (err) {
      // Show exact error message from backend (detail field)
      const errorMessage = err instanceof Error ? err.message : 'Failed to generate test plan'
      setError(errorMessage)
    } finally {
      setIsLoading(false)
    }
  }

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
      setError(err instanceof Error ? err.message : 'Failed to download RTM')
    }
  }


  const handleDownloadArtifact = async (runId: string, artifactType: string, filename: string) => {
    try {
      let artifactData: any
      switch (artifactType) {
        case 'test_plan':
          artifactData = await fetchTestPlanArtifact(runId)
          break
        case 'rtm':
          artifactData = await fetchRTMArtifact(runId)
          break
        case 'analysis':
          artifactData = await fetchAnalysisArtifact(runId)
          break
        case 'audit':
          artifactData = await fetchAuditArtifact(runId)
          break
        default:
          throw new Error(`Unknown artifact type: ${artifactType}`)
      }
      
      const blob = new Blob([JSON.stringify(artifactData, null, 2)], { type: 'application/json' })
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to download artifact'
      setError(errorMessage)
    }
  }

  const handleDownloadExecutionReport = async () => {
    if (!testPlanData?.audit_metadata?.run_id) {
      return
    }

    setExecutionReportError(null)
    try {
      const runId = testPlanData.audit_metadata.run_id
      const blob = await downloadExecutionReport(runId)
      const url = window.URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `execution-report-${runId}.csv`
      document.body.appendChild(a)
      a.click()
      window.URL.revokeObjectURL(url)
      document.body.removeChild(a)
    } catch (err) {
      setExecutionReportError(err instanceof Error ? err.message : 'Failed to download execution report')
    }
  }

  return (
    <div className="space-y-8">
      <JiraNotConfiguredBanner />
      <TicketInputPanel onGenerate={handleGenerate} isLoading={isLoading} isDisabled={isTestPlanDisabled} />
      
      {error && (
        <motion.div
          initial={{ opacity: 0, y: -10 }}
          animate={{ opacity: 1, y: 0 }}
          className="p-4 bg-destructive/20 border border-destructive/50 rounded-lg"
        >
          <div className="font-semibold text-destructive mb-1">Request failed</div>
          <div className="text-sm text-destructive/90">{error}</div>
        </motion.div>
      )}

      <AnimatePresence>
        {testPlanData && (
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0, y: -20 }}
            transition={{ duration: 0.3 }}
            className="space-y-6"
          >
            <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
              <CardContent className="p-6">
                <div className="flex items-center justify-between mb-6">
                  <div className="space-y-2">
                    <div className="flex items-center gap-3">
                      <h2 className="text-2xl font-bold mb-2">Ticket Analysis</h2>
                      {testPlanData.audit_metadata && (
                        <div className="text-xs text-muted-foreground">
                          <span>Created by: {testPlanData.audit_metadata.run_id ? 'anonymous' : 'anonymous'}</span>
                          {testPlanData.audit_metadata.generated_at && (
                            <span className="ml-2">• {new Date(testPlanData.audit_metadata.generated_at).toLocaleString()}</span>
                          )}
                        </div>
                      )}
                    </div>
                    {testPlanData.scope_summary && (
                      <div className="space-y-1">
                        <p className="text-sm text-muted-foreground">
                          {testPlanData.scope_summary.requirements_covered} of {testPlanData.scope_summary.requirements_total} requirements covered
                        </p>
                        <p className="text-sm text-muted-foreground">
                          {testPlanData.scope_summary.tickets_analyzed} ticket{testPlanData.scope_summary.tickets_analyzed !== 1 ? 's' : ''} analyzed
                        </p>
                        {(() => {
                          const testPlan = testPlanData.test_plan || {}
                          const allTests = [
                            ...(testPlan.api_tests || []),
                            ...(testPlan.ui_tests || []),
                            ...(testPlan.negative_tests || []),
                            ...(testPlan.edge_cases || []),
                            ...(testPlan.data_validation_tests || [])
                          ]
                          const totalSteps = allTests.reduce((sum, test) => {
                            const steps = test.steps || []
                            return sum + steps.length
                          }, 0)
                          
                          return (
                            <p className="text-sm text-muted-foreground">
                              {totalSteps} total test step{totalSteps !== 1 ? 's' : ''}
                            </p>
                          )
                        })()}
                        {(() => {
                          const requirements = testPlanData.requirements || []
                          const confidenceScores = requirements
                            .map(req => req.coverage_confidence?.score)
                            .filter((score): score is number => typeof score === 'number')
                          
                          if (confidenceScores.length === 0) return null
                          
                          const avgScore = confidenceScores.reduce((sum, score) => sum + score, 0) / confidenceScores.length
                          const level = avgScore >= 0.8 ? 'high' : avgScore >= 0.5 ? 'medium' : 'low'
                          const levelColor = level === 'high' ? 'text-green-400' : level === 'medium' ? 'text-yellow-400' : 'text-red-400'
                          
                          return (
                            <p className="text-sm">
                              <span className="text-muted-foreground">Overall Confidence: </span>
                              <span className={`font-semibold ${levelColor}`}>
                                {level.toUpperCase()} ({avgScore.toFixed(2)})
                              </span>
                            </p>
                          )
                        })()}
                      </div>
                    )}
                  </div>
                  <div className="flex flex-col gap-2">
                    <div className="flex gap-2">
                      <Button
                        variant="outline"
                        onClick={handleDownloadRTM}
                        className="flex items-center gap-2"
                      >
                        <Download className="h-4 w-4" />
                        Download RTM CSV
                      </Button>
                      {testPlanData.audit_metadata?.run_id && (
                        <Button
                          variant="outline"
                          onClick={handleDownloadExecutionReport}
                          className="flex items-center gap-2"
                        >
                          <FileDown className="h-4 w-4" />
                          Download Execution Report CSV (for manual testing)
                        </Button>
                      )}
                    </div>
                    {testPlanData.audit_metadata?.run_id && (
                      <>
                        <p className="text-xs text-muted-foreground">
                          CSV includes Result/Tester Notes columns for manual execution.
                        </p>
                        <div className="flex gap-2 mt-2">
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleDownloadArtifact(testPlanData.audit_metadata!.run_id, 'test_plan', `test-plan-${testPlanData.audit_metadata!.run_id}.json`)}
                            className="flex items-center gap-2 text-xs"
                          >
                            <FileDown className="h-3 w-3" />
                            Test Plan JSON
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleDownloadArtifact(testPlanData.audit_metadata!.run_id, 'rtm', `rtm-${testPlanData.audit_metadata!.run_id}.json`)}
                            className="flex items-center gap-2 text-xs"
                          >
                            <FileDown className="h-3 w-3" />
                            RTM JSON
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() => handleDownloadArtifact(testPlanData.audit_metadata!.run_id, 'analysis', `analysis-${testPlanData.audit_metadata!.run_id}.json`)}
                            className="flex items-center gap-2 text-xs"
                          >
                            <FileDown className="h-3 w-3" />
                            Analysis JSON
                          </Button>
                        </div>
                      </>
                    )}
                    {executionReportError && (
                      <div className="mt-1">
                        <div className="font-semibold text-destructive text-sm mb-1">Request failed</div>
                        <p className="text-sm text-destructive/90">{executionReportError}</p>
                      </div>
                    )}
                  </div>
                </div>

                <Tabs value={activeTab} onValueChange={setActiveTab} className="hidden">
                  <TabsList className="mb-4">
                    <TabsTrigger value="tickets">Tickets</TabsTrigger>
                    <TabsTrigger value="rtm">RTM</TabsTrigger>
                    <TabsTrigger value="requirements">Requirements</TabsTrigger>
                    <TabsTrigger value="ticket-breakdown">Ticket Breakdown</TabsTrigger>
                    <TabsTrigger value="tests-by-requirement">Tests (By Requirement)</TabsTrigger>
                    <TabsTrigger value="tests-by-type">Tests (By Type)</TabsTrigger>
                  </TabsList>
                </Tabs>

                <div className="space-y-6">
                  <AnimatePresence mode="wait">
                    {activeTab === 'tickets' && (
                      <motion.div
                        key="tickets"
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -20 }}
                        transition={{ duration: 0.2 }}
                        className="space-y-6"
                      >
                        <TicketsView
                          ticketDetails={testPlanData.scope_summary?.ticket_details || []}
                          failedTickets={testPlanData.scope_summary?.failed_tickets || []}
                        />
                        {testPlanData.audit_metadata && (
                          <AuditMetadataView metadata={testPlanData.audit_metadata} />
                        )}
                      </motion.div>
                    )}

                    {activeTab === 'rtm' && (
                      <motion.div
                        key="rtm"
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -20 }}
                        transition={{ duration: 0.2 }}
                        className="space-y-6"
                      >
                        <RTMTable rtm={testPlanData.rtm} />
                        {testPlanData.audit_metadata && (
                          <AuditMetadataView metadata={testPlanData.audit_metadata} />
                        )}
                      </motion.div>
                    )}

                    {activeTab === 'requirements' && (
                      <motion.div
                        key="requirements"
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -20 }}
                        transition={{ duration: 0.2 }}
                        className="space-y-6"
                      >
                        <RequirementsView 
                          requirements={testPlanData.requirements} 
                          testPlan={testPlanData.test_plan}
                        />
                        {testPlanData.audit_metadata && (
                          <AuditMetadataView metadata={testPlanData.audit_metadata} />
                        )}
                      </motion.div>
                    )}

                    {activeTab === 'ticket-breakdown' && (
                      <motion.div
                        key="ticket-breakdown"
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -20 }}
                        transition={{ duration: 0.2 }}
                        className="space-y-6"
                      >
                        <TicketBreakdownView
                          ticketTraceability={testPlanData.ticket_traceability}
                        />
                        {testPlanData.audit_metadata && (
                          <AuditMetadataView metadata={testPlanData.audit_metadata} />
                        )}
                      </motion.div>
                    )}

                    {activeTab === 'tests-by-requirement' && (
                      <motion.div
                        key="tests-by-requirement"
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -20 }}
                        transition={{ duration: 0.2 }}
                        className="space-y-6"
                      >
                        <RequirementCentricTestView
                          testPlanByRequirement={testPlanData.test_plan_by_requirement}
                        />
                        {testPlanData.audit_metadata && (
                          <AuditMetadataView metadata={testPlanData.audit_metadata} />
                        )}
                      </motion.div>
                    )}

                    {activeTab === 'tests-by-type' && (
                      <motion.div
                        key="tests-by-type"
                        initial={{ opacity: 0, x: 20 }}
                        animate={{ opacity: 1, x: 0 }}
                        exit={{ opacity: 0, x: -20 }}
                        transition={{ duration: 0.2 }}
                        className="space-y-6"
                      >
                        <TestPlanView testPlan={testPlanData.test_plan} />
                        {testPlanData.audit_metadata && (
                          <AuditMetadataView metadata={testPlanData.audit_metadata} />
                        )}
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              </CardContent>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  )
}

