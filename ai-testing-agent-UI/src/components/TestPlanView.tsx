import { useState } from 'react'
import { TestCase } from '../services/api'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { ChevronDown, ChevronRight, Code } from 'lucide-react'
import { motion, AnimatePresence } from 'framer-motion'

interface TestPlanViewProps {
  testPlan: {
    api_tests: TestCase[]
    ui_tests: TestCase[]
    data_validation_tests: TestCase[]
    edge_cases: TestCase[]
    negative_tests: TestCase[]
  }
}

interface TestCardProps {
  test: TestCase
}

function TestCard({ test }: TestCardProps) {
  const [isExpanded, setIsExpanded] = useState(false)
  const [showRawJson, setShowRawJson] = useState(false)

  const getDimensionBadge = (dimension?: string) => {
    if (!dimension) return null
    
    const dimensionMap: Record<string, { label: string; variant: 'default' | 'secondary' | 'success' | 'warning' | 'destructive' }> = {
      happy_path: { label: 'Happy Path', variant: 'success' },
      data_validation: { label: 'Data Validation', variant: 'default' },
      authorization: { label: 'Authorization', variant: 'warning' },
      boundary: { label: 'Boundary', variant: 'secondary' },
      negative: { label: 'Negative', variant: 'destructive' },
    }
    
    const dim = dimensionMap[dimension]
    if (!dim) return null
    
    return (
      <Badge variant={dim.variant} className="text-xs">
        {dim.label}
      </Badge>
    )
  }

  const confidenceVariant = test.confidence === 'explicit' ? 'success' : 'warning'
  
  const priorityVariant = test.priority === 'high' ? 'destructive' : test.priority === 'medium' ? 'warning' : 'secondary'

  // Get all fields from the test object, including any that might not be in the TypeScript interface
  const getAllFields = () => {
    const fields: Array<{ key: string; value: any }> = []
    for (const key in test) {
      if (test.hasOwnProperty(key)) {
        fields.push({ key, value: (test as any)[key] })
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
    <Card id={`test-${test.id}`} className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/5 hover:border-border transition-colors">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 space-y-2">
            <div className="flex items-center gap-2 flex-wrap">
              <CardTitle className="text-base font-semibold">{test.id}</CardTitle>
              {getDimensionBadge(test.dimension)}
              <Badge variant={confidenceVariant} className="text-xs">
                {test.confidence}
              </Badge>
              {test.priority && (
                <Badge variant={priorityVariant} className="text-xs">
                  {test.priority}
                </Badge>
              )}
            </div>
            <p className="text-sm text-foreground/90">{test.title}</p>
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
            <CardContent className="pt-0 space-y-4">
              <h4 className="text-sm font-semibold text-foreground/90 border-b border-border/50 pb-2">
                Complete Details
              </h4>

              {/* Test ID */}
              <div className="flex gap-4 py-1 text-sm">
                <span className="font-mono text-xs text-muted-foreground min-w-[140px]">Test ID:</span>
                <span className="text-foreground/80 font-mono">{test.id}</span>
              </div>

              {/* Title */}
              <div className="flex gap-4 py-1 text-sm">
                <span className="font-mono text-xs text-muted-foreground min-w-[140px]">Title:</span>
                <span className="text-foreground/80">{test.title}</span>
              </div>

              {/* Intent Type */}
              {test.intent_type && (
                <div className="flex gap-4 py-1 text-sm">
                  <span className="font-mono text-xs text-muted-foreground min-w-[140px]">Intent Type:</span>
                  <Badge variant={test.intent_type === 'happy_path' ? 'success' : test.intent_type === 'negative' ? 'destructive' : 'warning'} className="text-xs">
                    {test.intent_type.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase())}
                  </Badge>
                </div>
              )}

              {/* Source Requirement ID */}
              {test.source_requirement_id && (
                <div className="flex gap-4 py-1 text-sm">
                  <span className="font-mono text-xs text-muted-foreground min-w-[140px]">Source Requirement:</span>
                  <Badge variant="secondary" className="text-xs font-mono">
                    {test.source_requirement_id}
                  </Badge>
                </div>
              )}

              {/* Dimension */}
              {test.dimension && (
                <div className="flex gap-4 py-1 text-sm">
                  <span className="font-mono text-xs text-muted-foreground min-w-[140px]">Dimension:</span>
                  <span className="text-foreground/80">{test.dimension}</span>
                </div>
              )}

              {/* Confidence */}
              <div className="flex gap-4 py-1 text-sm">
                <span className="font-mono text-xs text-muted-foreground min-w-[140px]">Confidence:</span>
                <span className="text-foreground/80">{test.confidence}</span>
              </div>

              {/* Priority */}
              {test.priority && (
                <div className="flex gap-4 py-1 text-sm">
                  <span className="font-mono text-xs text-muted-foreground min-w-[140px]">Priority:</span>
                  <span className="text-foreground/80">{test.priority}</span>
                </div>
              )}

              {/* Expected Result */}
              {test.expected_result && (
                <div className="flex gap-4 py-1 text-sm">
                  <span className="font-mono text-xs text-muted-foreground min-w-[140px]">Expected Result:</span>
                  <span className="text-foreground/80 flex-1">{test.expected_result}</span>
                </div>
              )}

              {/* Requirements Covered */}
              {test.requirements_covered && test.requirements_covered.length > 0 && (
                <div className="space-y-2">
                  <div className="flex gap-4 text-sm">
                    <span className="font-mono text-xs text-muted-foreground min-w-[140px]">Requirements Covered:</span>
                    <div className="flex flex-wrap gap-2 flex-1">
                      {test.requirements_covered.map((reqId) => (
                        <Badge key={reqId} variant="secondary" className="text-xs font-mono">
                          {reqId}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Steps */}
              {test.steps && test.steps.length > 0 ? (
                <div className="space-y-2">
                  <div className="flex gap-4 text-sm">
                    <span className="font-mono text-xs text-muted-foreground min-w-[140px]">Steps:</span>
                    <ol className="list-decimal list-inside space-y-1 text-sm text-foreground/80 flex-1">
                      {test.steps.map((step, idx) => (
                        <li key={idx} className="pl-2">{step}</li>
                      ))}
                    </ol>
                  </div>
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="flex gap-4 text-sm">
                    <span className="font-mono text-xs text-muted-foreground min-w-[140px]">Steps:</span>
                    <div className="flex-1">
                      <span className="text-sm text-muted-foreground italic">No steps available</span>
                    </div>
                  </div>
                </div>
              )}

              {/* Steps Explanation (shown when steps are empty) */}
              {test.steps_explanation && (
                <div className="space-y-2">
                  <div className="flex gap-4 text-sm">
                    <span className="font-mono text-xs text-muted-foreground min-w-[140px]">Steps Explanation:</span>
                    <div className="flex-1 p-3 bg-warning/10 border border-warning/30 rounded-md">
                      <p className="text-sm text-foreground/80">{test.steps_explanation}</p>
                    </div>
                  </div>
                </div>
              )}

              {/* Steps Origin */}
              {test.steps_origin && (
                <div className="flex gap-4 py-1 text-sm">
                  <span className="font-mono text-xs text-muted-foreground min-w-[140px]">Steps Origin:</span>
                  <Badge variant={test.steps_origin === 'requirement-derived' ? 'success' : 'warning'} className="text-xs">
                    {test.steps_origin === 'requirement-derived' ? 'Requirement-Derived' : 'None'}
                  </Badge>
                </div>
              )}

              {/* Any additional fields not covered above */}
              {getAllFields().filter(({ key }) => {
                const knownFields = ['id', 'title', 'intent_type', 'source_requirement_id', 'dimension', 'confidence', 'priority', 'expected_result', 'requirements_covered', 'steps', 'steps_explanation', 'steps_origin']
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
                      <div className="bg-black/40 border border-white/10 rounded-md p-4 overflow-auto">
                        <pre className="text-xs font-mono text-foreground/70 whitespace-pre-wrap break-words">
                          {JSON.stringify(test, null, 2)}
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

export function TestPlanView({ testPlan }: TestPlanViewProps) {
  // Group tests by category
  const testsByCategory: Record<string, TestCase[]> = {
    'Happy Path': [
      ...testPlan.api_tests.filter(t => !t.dimension || t.dimension === 'happy_path'),
      ...testPlan.ui_tests.filter(t => !t.dimension || t.dimension === 'happy_path'),
    ],
    'Data Validation': testPlan.data_validation_tests,
    'Authorization': [
      ...testPlan.negative_tests.filter(t => t.dimension === 'authorization'),
    ],
    'Edge Cases': testPlan.edge_cases.filter(t => t.dimension !== 'authorization'),
    'Negative Tests': testPlan.negative_tests.filter(t => t.dimension !== 'authorization'),
  }

  // Count total tests
  const totalTests = 
    testPlan.api_tests.length +
    testPlan.ui_tests.length +
    testPlan.data_validation_tests.length +
    testPlan.edge_cases.length +
    testPlan.negative_tests.length

  return (
    <div className="space-y-6">
      {Object.entries(testsByCategory).map(([category, tests]) => {
        if (tests.length === 0) return null
        
        return (
          <div key={category} className="space-y-3">
            <h3 className="text-lg font-semibold text-foreground/90 border-b border-border pb-2">
              {category} <span className="text-sm text-muted-foreground font-normal">({tests.length})</span>
            </h3>
            <div className="space-y-3">
              {tests.map((test) => (
                <TestCard key={test.id} test={test} />
              ))}
            </div>
          </div>
        )
      })}
      
      {totalTests === 0 && (
        <div className="text-center py-8 text-muted-foreground">
          No test cases available
        </div>
      )}
    </div>
  )
}

