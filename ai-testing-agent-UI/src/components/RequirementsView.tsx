import { Requirement, TestCase } from '../services/api'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { motion } from 'framer-motion'
import { useState } from 'react'
import { ChevronDown, ChevronRight, Code, AlertTriangle } from 'lucide-react'
import { AnimatePresence } from 'framer-motion'

interface RequirementsViewProps {
  requirements: Requirement[]
  testPlan?: {
    api_tests: TestCase[]
    ui_tests: TestCase[]
    data_validation_tests: TestCase[]
    edge_cases: TestCase[]
    negative_tests: TestCase[]
  }
}

function RequirementCard({ requirement, testPlan }: { requirement: Requirement; testPlan?: RequirementsViewProps['testPlan'] }) {
  const [isExpanded, setIsExpanded] = useState(false)
  const [showRawJson, setShowRawJson] = useState(false)
  const [showCoverageConfidence, setShowCoverageConfidence] = useState(false)
  const [showQuality, setShowQuality] = useState(false)
  const [showCoverageExpectations, setShowCoverageExpectations] = useState(false)
  const [showExecutableTests, setShowExecutableTests] = useState(false)

  const sourceVariant = requirement.source === 'jira' ? 'success' : 'warning'
  const confidenceVariant = requirement.coverage_confidence?.level === 'high' 
    ? 'success' 
    : requirement.coverage_confidence?.level === 'medium' 
    ? 'warning' 
    : 'destructive'

  // Get all fields from the requirement object
  const getAllFields = () => {
    const fields: Array<{ key: string; value: any }> = []
    for (const key in requirement) {
      if (requirement.hasOwnProperty(key)) {
        fields.push({ key, value: (requirement as any)[key] })
      }
    }
    return fields
  }

  const formatValue = (value: any): string => {
    if (value === null || value === undefined) return '—'
    if (Array.isArray(value)) {
      return value.length === 0 ? '[]' : value.join(', ')
    }
    if (typeof value === 'object') {
      return JSON.stringify(value, null, 2)
    }
    return String(value)
  }

  return (
    <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/5 hover:border-border transition-colors">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <CardTitle className="text-base font-semibold font-mono">{requirement.id}</CardTitle>
              <Badge variant={sourceVariant} className="text-xs">
                {requirement.source}
              </Badge>
              {requirement.coverage_confidence && (
                <Badge variant={confidenceVariant} className="text-xs">
                  {requirement.coverage_confidence.level} ({requirement.coverage_confidence.score.toFixed(2)})
                </Badge>
              )}
              {requirement.quality && typeof requirement.quality.clarity_score === 'number' && typeof requirement.quality.testability_score === 'number' && (
                <Badge variant="secondary" className="text-xs">
                  Clarity: {requirement.quality.clarity_score.toFixed(2)} | Testability: {requirement.quality.testability_score.toFixed(2)}
                </Badge>
              )}
            </div>
            <p className="text-sm text-foreground/90">{requirement.description}</p>
            {/* Metadata - Source */}
            <p className="text-xs text-muted-foreground/60 font-mono">
              Source: {requirement.source}
            </p>
          </div>
          <button
            onClick={() => setIsExpanded(!isExpanded)}
            className="text-muted-foreground hover:text-foreground transition-colors"
          >
            {isExpanded ? (
              <ChevronDown className="h-5 w-5" />
            ) : (
              <ChevronRight className="h-5 w-5" />
            )}
          </button>
        </div>
      </CardHeader>
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
          >
            <CardContent className="pt-0 space-y-3">

              {/* A. Coverage Confidence (ISO Risk Signal) */}
              {requirement.coverage_confidence ? (
                <div className="border border-border/30 rounded-lg bg-background/50 backdrop-blur-sm">
                  <button
                    onClick={() => setShowCoverageConfidence(!showCoverageConfidence)}
                    className="w-full flex items-center justify-between p-3 text-left hover:bg-secondary/10 transition-colors"
                  >
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-semibold text-foreground/90">Coverage Confidence (ISO Risk Signal)</span>
                      <Badge variant={confidenceVariant} className="text-xs">
                        {requirement.coverage_confidence.level}
                      </Badge>
                    </div>
                    {showCoverageConfidence ? (
                      <ChevronDown className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    )}
                  </button>
                  <AnimatePresence>
                    {showCoverageConfidence && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                      >
                        <div className="px-3 pb-3 space-y-3 border-t border-border/30">
                          {/* Progress Bar */}
                          <div className="space-y-1">
                            <div className="flex justify-between text-xs">
                              <span className="text-muted-foreground">Score</span>
                              <span className="text-foreground/80 font-mono">
                                {(requirement.coverage_confidence.score * 100).toFixed(1)}%
                              </span>
                            </div>
                            <div className="h-2 bg-secondary/30 rounded-full overflow-hidden">
                              <div
                                className="h-full transition-all duration-300"
                                style={{
                                  width: `${requirement.coverage_confidence.score * 100}%`,
                                  backgroundColor:
                                    requirement.coverage_confidence.level === 'high'
                                      ? 'rgb(34, 197, 94)'
                                      : requirement.coverage_confidence.level === 'medium'
                                      ? 'rgb(234, 179, 8)'
                                      : 'rgb(239, 68, 68)',
                                }}
                              />
                            </div>
                          </div>
                          {/* Reasons */}
                          {requirement.coverage_confidence.reasons && requirement.coverage_confidence.reasons.length > 0 && (
                            <div className="space-y-1">
                              <span className="text-xs font-medium text-foreground/80">Risk Factors:</span>
                              <ul className="list-disc list-inside space-y-1 text-xs text-foreground/70">
                                {requirement.coverage_confidence.reasons.map((reason, idx) => (
                                  <li key={idx}>{reason}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              ) : (
                <div className="border border-border/30 rounded-lg bg-background/50 backdrop-blur-sm p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold text-foreground/90">Coverage Confidence (ISO Risk Signal)</span>
                    <span className="text-xs text-muted-foreground">Not available</span>
                  </div>
                </div>
              )}

              {/* B. Requirement Quality */}
              {requirement.quality ? (
                <div className="border border-border/30 rounded-lg bg-background/50 backdrop-blur-sm">
                  <button
                    onClick={() => setShowQuality(!showQuality)}
                    className="w-full flex items-center justify-between p-3 text-left hover:bg-secondary/10 transition-colors"
                  >
                    <span className="text-sm font-semibold text-foreground/90">Requirement Quality</span>
                    {showQuality ? (
                      <ChevronDown className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    )}
                  </button>
                  <AnimatePresence>
                    {showQuality && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                      >
                        <div className="px-3 pb-3 space-y-3 border-t border-border/30">
                          {/* Clarity Score */}
                          {'clarity_score' in requirement.quality && requirement.quality.clarity_score != null && (
                            <div className="space-y-1">
                              <div className="flex justify-between text-xs">
                                <span className="text-muted-foreground">Clarity Score</span>
                                <span className="text-foreground/80 font-mono">
                                  {typeof requirement.quality.clarity_score === 'number'
                                    ? requirement.quality.clarity_score.toFixed(2)
                                    : String(requirement.quality.clarity_score)}
                                </span>
                              </div>
                              {typeof requirement.quality.clarity_score === 'number' && (
                                <div className="h-1.5 bg-secondary/30 rounded-full overflow-hidden">
                                  <div
                                    className="h-full transition-all duration-300"
                                    style={{
                                      width: `${requirement.quality.clarity_score * 100}%`,
                                      backgroundColor:
                                        requirement.quality.clarity_score >= 0.8
                                          ? 'rgb(34, 197, 94)'
                                          : requirement.quality.clarity_score >= 0.5
                                          ? 'rgb(234, 179, 8)'
                                          : 'rgb(239, 68, 68)',
                                    }}
                                  />
                                </div>
                              )}
                            </div>
                          )}
                          {/* Testability Score */}
                          {'testability_score' in requirement.quality && requirement.quality.testability_score != null && (
                            <div className="space-y-1">
                              <div className="flex justify-between text-xs">
                                <span className="text-muted-foreground">Testability Score</span>
                                <span className="text-foreground/80 font-mono">
                                  {typeof requirement.quality.testability_score === 'number'
                                    ? requirement.quality.testability_score.toFixed(2)
                                    : String(requirement.quality.testability_score)}
                                </span>
                              </div>
                              {typeof requirement.quality.testability_score === 'number' && (
                                <div className="h-1.5 bg-secondary/30 rounded-full overflow-hidden">
                                  <div
                                    className="h-full transition-all duration-300"
                                    style={{
                                      width: `${requirement.quality.testability_score * 100}%`,
                                      backgroundColor:
                                        requirement.quality.testability_score >= 0.8
                                          ? 'rgb(34, 197, 94)'
                                          : requirement.quality.testability_score >= 0.5
                                          ? 'rgb(234, 179, 8)'
                                          : 'rgb(239, 68, 68)',
                                    }}
                                  />
                                </div>
                              )}
                            </div>
                          )}
                          {/* Issues */}
                          {requirement.quality.issues && Array.isArray(requirement.quality.issues) && requirement.quality.issues.length > 0 && (
                            <div className="space-y-1 pt-1">
                              <div className="flex items-center gap-1 text-xs font-medium text-foreground/80">
                                <AlertTriangle className="h-3 w-3 text-yellow-400" />
                                <span>Quality Issues</span>
                              </div>
                              <ul className="list-disc list-inside space-y-0.5 text-xs text-foreground/70">
                                {requirement.quality.issues.map((issue, idx) => (
                                  <li key={idx}>{issue}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              ) : (
                <div className="border border-border/30 rounded-lg bg-background/50 backdrop-blur-sm p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold text-foreground/90">Requirement Quality</span>
                    <span className="text-xs text-muted-foreground">Not available</span>
                  </div>
                </div>
              )}

              {/* Executable Tests & Steps */}
              {testPlan && (() => {
                // Find all tests where source_requirement_id matches this requirement
                const allTests: TestCase[] = [
                  ...(testPlan.api_tests || []),
                  ...(testPlan.ui_tests || []),
                  ...(testPlan.data_validation_tests || []),
                  ...(testPlan.edge_cases || []),
                  ...(testPlan.negative_tests || [])
                ]
                const requirementTests = allTests.filter(
                  test => test.source_requirement_id === requirement.id
                )
                
                if (requirementTests.length === 0) {
                  return null
                }
                
                return (
                  <div className="border border-border/30 rounded-lg bg-background/50 backdrop-blur-sm">
                    <button
                      onClick={() => setShowExecutableTests(!showExecutableTests)}
                      className="w-full flex items-center justify-between p-3 text-left hover:bg-secondary/10 transition-colors"
                    >
                      <span className="text-sm font-semibold text-foreground/90">Executable Tests & Steps</span>
                      {showExecutableTests ? (
                        <ChevronDown className="h-4 w-4 text-muted-foreground" />
                      ) : (
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      )}
                    </button>
                    <AnimatePresence>
                      {showExecutableTests && (
                        <motion.div
                          initial={{ height: 0, opacity: 0 }}
                          animate={{ height: 'auto', opacity: 1 }}
                          exit={{ height: 0, opacity: 0 }}
                          transition={{ duration: 0.2 }}
                          className="overflow-hidden"
                        >
                          <div className="px-3 pb-3 space-y-4 border-t border-border/30 pt-3">
                            {requirementTests.map((test) => (
                              <div key={test.id} className="space-y-2 border-b border-border/20 pb-3 last:border-b-0 last:pb-0">
                                <div className="space-y-1">
                                  <div className="flex items-center gap-2 flex-wrap">
                                    <span className="font-mono text-xs text-foreground/80">{test.id}</span>
                                    {test.intent_type && (
                                      <Badge variant="secondary" className="text-xs">
                                        {test.intent_type.replace('_', ' ')}
                                      </Badge>
                                    )}
                                  </div>
                                  <p className="text-sm text-foreground/90">{test.title}</p>
                                </div>
                                {test.steps && test.steps.length > 0 ? (
                                  <div className="space-y-1">
                                    <span className="text-xs font-medium text-foreground/80">Steps:</span>
                                    <ol className="list-decimal list-inside space-y-1 text-xs text-foreground/70 ml-2">
                                      {test.steps.map((step, idx) => (
                                        <li key={idx}>{step}</li>
                                      ))}
                                    </ol>
                                  </div>
                                ) : (
                                  <p className="text-xs text-muted-foreground italic">
                                    Steps not generated for this test (inferred coverage)
                                  </p>
                                )}
                              </div>
                            ))}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </div>
                )
              })()}

              {/* C. Coverage Expectations */}
              {requirement.coverage_expectations ? (
                <div className="border border-border/30 rounded-lg bg-background/50 backdrop-blur-sm">
                  <button
                    onClick={() => setShowCoverageExpectations(!showCoverageExpectations)}
                    className="w-full flex items-center justify-between p-3 text-left hover:bg-secondary/10 transition-colors"
                  >
                    <span className="text-sm font-semibold text-foreground/90">Coverage Expectations</span>
                    {showCoverageExpectations ? (
                      <ChevronDown className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    )}
                  </button>
                  <AnimatePresence>
                    {showCoverageExpectations && (
                      <motion.div
                        initial={{ height: 0, opacity: 0 }}
                        animate={{ height: 'auto', opacity: 1 }}
                        exit={{ height: 0, opacity: 0 }}
                        transition={{ duration: 0.2 }}
                        className="overflow-hidden"
                      >
                        <div className="px-3 pb-3 border-t border-border/30">
                          <div className="grid grid-cols-2 gap-2 pt-3">
                            {Object.entries(requirement.coverage_expectations).map(([key, value]) => {
                              const getStatusColor = (status: string) => {
                                if (status === 'covered') return 'text-green-400'
                                if (status === 'expected') return 'text-yellow-400'
                                return 'text-muted-foreground'
                              }
                              const getStatusBg = (status: string) => {
                                if (status === 'covered') return 'bg-green-500/20 border-green-500/30'
                                if (status === 'expected') return 'bg-yellow-500/20 border-yellow-500/30'
                                return 'bg-secondary/20 border-border/30'
                              }
                              return (
                                <div
                                  key={key}
                                  className={`p-2 rounded border text-xs ${getStatusBg(String(value))} ${getStatusColor(String(value))}`}
                                >
                                  <div className="font-medium capitalize mb-0.5">
                                    {key.replace(/_/g, ' ')}
                                  </div>
                                  <div className="text-xs opacity-80">{String(value)}</div>
                                </div>
                              )
                            })}
                          </div>
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              ) : (
                <div className="border border-border/30 rounded-lg bg-background/50 backdrop-blur-sm p-3">
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold text-foreground/90">Coverage Expectations</span>
                    <span className="text-xs text-muted-foreground">Not available</span>
                  </div>
                </div>
              )}

              {/* Any additional fields not covered above */}
              {getAllFields().filter(({ key }) => {
                const knownFields = ['id', 'source', 'description', 'quality', 'coverage_expectations', 'coverage_confidence']
                return !knownFields.includes(key)
              }).map(({ key, value }) => (
                <div key={key} className="space-y-2">
                  <div className="flex gap-4 text-sm">
                    <span className="font-mono text-xs text-muted-foreground min-w-[140px] capitalize">
                      {key.replace(/_/g, ' ')}:
                    </span>
                    <div className="flex-1">
                      {Array.isArray(value) ? (
                        <div className="space-y-1">
                          {value.length === 0 ? (
                            <span className="text-sm text-muted-foreground">[]</span>
                          ) : (
                            value.map((item, idx) => (
                              <div key={idx} className="text-sm text-foreground/80">
                                {typeof item === 'object' && item !== null ? (
                                  <pre className="text-xs font-mono whitespace-pre-wrap">
                                    {JSON.stringify(item, null, 2)}
                                  </pre>
                                ) : (
                                  String(item)
                                )}
                              </div>
                            ))
                          )}
                        </div>
                      ) : typeof value === 'object' && value !== null ? (
                        <pre className="text-xs text-foreground/80 font-mono whitespace-pre-wrap break-words">
                          {JSON.stringify(value, null, 2)}
                        </pre>
                      ) : (
                        <span className="text-sm text-foreground/80">{formatValue(value)}</span>
                      )}
                    </div>
                  </div>
                </div>
              ))}

              {/* Raw JSON Toggle */}
              <div className="pt-4 border-t border-border/50">
                <button
                  onClick={() => setShowRawJson(!showRawJson)}
                  className="flex items-center gap-2 text-sm text-muted-foreground hover:text-foreground transition-colors"
                >
                  <Code className="h-4 w-4" />
                  <span>{showRawJson ? 'Hide' : 'View'} Raw JSON</span>
                </button>
                <AnimatePresence>
                  {showRawJson && (
                    <motion.div
                      initial={{ height: 0, opacity: 0 }}
                      animate={{ height: 'auto', opacity: 1 }}
                      exit={{ height: 0, opacity: 0 }}
                      transition={{ duration: 0.2 }}
                      className="mt-3"
                    >
                      <div className="bg-black/40 border border-white/10 rounded-md p-4 overflow-auto max-h-96">
                        <pre className="text-xs font-mono text-foreground/70 whitespace-pre-wrap break-words">
                          {JSON.stringify(requirement, null, 2)}
                        </pre>
                      </div>
                    </motion.div>
                  )}
                </AnimatePresence>
              </div>
            </CardContent>
          </motion.div>
        )}
      </AnimatePresence>
    </Card>
  )
}

export function RequirementsView({ requirements, testPlan }: RequirementsViewProps) {
  if (requirements.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        No requirements available
      </div>
    )
  }

  return (
    <div className="space-y-3">
      {requirements.map((requirement, index) => (
        <motion.div
          key={requirement.id}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: index * 0.05 }}
        >
          <RequirementCard requirement={requirement} testPlan={testPlan} />
        </motion.div>
      ))}
    </div>
  )
}

