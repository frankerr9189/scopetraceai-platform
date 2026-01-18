import { useState } from 'react'
import { TestCase } from '../services/api'
import { ChevronDown, ChevronRight, TestTube, CheckCircle2, XCircle, Shield, Gauge } from 'lucide-react'

interface RequirementTestGroup {
  requirement_id: string
  requirement_text: string
  requirement_source: 'jira' | 'inferred'
  quality?: {
    clarity_score: number
    testability_score: number
    issues: string[]
  }
  coverage_confidence?: {
    score: number
    level: 'low' | 'medium' | 'high'
    reasons: string[]
  }
  coverage_expectations?: {
    happy_path: string
    negative: string
    boundary: string
    authorization: string
    data_validation: string
    stateful: string
  }
  tests: {
    happy_path: TestCase[]
    negative: TestCase[]
    boundary: TestCase[]
    authorization: TestCase[]
    other: TestCase[]
  }
}

interface RequirementCentricTestViewProps {
  testPlanByRequirement?: RequirementTestGroup[]
}

function TestCard({ test }: { test: TestCase }) {
  const [isExpanded, setIsExpanded] = useState(false)

  const getIntentBadge = (intentType?: string) => {
    if (!intentType) return null
    
    const variants: Record<string, { label: string; className: string; icon: any }> = {
      happy_path: { 
        label: 'Happy Path', 
        className: 'bg-green-500/20 text-green-700 dark:text-green-400',
        icon: CheckCircle2
      },
      negative: { 
        label: 'Negative', 
        className: 'bg-red-500/20 text-red-700 dark:text-red-400',
        icon: XCircle
      },
      boundary: { 
        label: 'Boundary', 
        className: 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-400',
        icon: Gauge
      },
      authorization: { 
        label: 'Authorization', 
        className: 'bg-purple-500/20 text-purple-700 dark:text-purple-400',
        icon: Shield
      }
    }
    
    const config = variants[intentType] || { 
      label: intentType.replace('_', ' ').replace(/\b\w/g, l => l.toUpperCase()), 
      className: 'bg-secondary text-secondary-foreground',
      icon: TestTube
    }
    
    const Icon = config.icon
    
    return (
      <span className={`px-2 py-1 text-xs rounded flex items-center gap-1 ${config.className}`}>
        <Icon className="h-3 w-3" />
        {config.label}
      </span>
    )
  }

  const getConfidenceBadge = (confidence?: string) => {
    if (!confidence) return null
    
    const variants: Record<string, string> = {
      explicit: 'bg-blue-500/20 text-blue-700 dark:text-blue-400',
      inferred: 'bg-orange-500/20 text-orange-700 dark:text-orange-400'
    }
    
    return (
      <span className={`px-2 py-1 text-xs rounded ${variants[confidence] || 'bg-secondary text-secondary-foreground'}`}>
        {confidence}
      </span>
    )
  }

  return (
    <div id={`test-${test.id}`} className="border border-border rounded-lg p-4 bg-card">
      <div className="flex items-start justify-between gap-4">
        <div className="flex-1 space-y-2">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-mono text-xs text-muted-foreground">{test.id}</span>
            {getIntentBadge(test.intent_type)}
            {getConfidenceBadge(test.confidence)}
            {test.steps_origin === 'none' && (
              <span className="px-2 py-1 text-xs rounded bg-warning/20 text-warning">
                No Steps
              </span>
            )}
          </div>
          <h4 className="font-medium text-foreground">{test.title}</h4>
          {test.expected_result && (
            <p className="text-sm text-muted-foreground">
              <span className="font-medium">Expected:</span> {test.expected_result}
            </p>
          )}
        </div>
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="p-1 hover:bg-secondary rounded transition-colors"
        >
          {isExpanded ? (
            <ChevronDown className="h-4 w-4" />
          ) : (
            <ChevronRight className="h-4 w-4" />
          )}
        </button>
      </div>
      
      {isExpanded && (
        <div className="mt-4 space-y-3 pt-4 border-t border-border">
          {test.steps && test.steps.length > 0 ? (
            <div>
              <h5 className="text-sm font-medium mb-2">Test Steps:</h5>
              <ol className="list-decimal list-inside space-y-1 text-sm">
                {test.steps.map((step, idx) => (
                  <li key={idx} className="text-foreground/80">{step}</li>
                ))}
              </ol>
            </div>
          ) : test.steps_explanation ? (
            <div className="p-3 bg-warning/10 border border-warning/30 rounded-md">
              <p className="text-xs text-foreground/80">{test.steps_explanation}</p>
            </div>
          ) : null}
          
          {test.priority && (
            <div className="text-xs text-muted-foreground">
              Priority: <span className="capitalize">{test.priority}</span>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

function IntentGroup({ 
  title, 
  tests, 
  icon: Icon 
}: { 
  title: string
  tests: TestCase[]
  icon: any
}) {
  if (tests.length === 0) return null
  
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-2 text-sm font-medium text-foreground/90">
        <Icon className="h-4 w-4" />
        {title} ({tests.length})
      </div>
      <div className="space-y-3 pl-6">
        {tests.map((test) => (
          <TestCard key={test.id} test={test} />
        ))}
      </div>
    </div>
  )
}

export function RequirementCentricTestView({ testPlanByRequirement = [] }: RequirementCentricTestViewProps) {
  const [expandedRequirements, setExpandedRequirements] = useState<Set<string>>(
    new Set(testPlanByRequirement.length > 0 ? [testPlanByRequirement[0].requirement_id] : [])
  )

  const toggleRequirement = (reqId: string) => {
    const newExpanded = new Set(expandedRequirements)
    if (newExpanded.has(reqId)) {
      newExpanded.delete(reqId)
    } else {
      newExpanded.add(reqId)
    }
    setExpandedRequirements(newExpanded)
  }

  const getQualityColor = (score: number) => {
    if (score >= 0.8) return 'text-green-600 dark:text-green-400'
    if (score >= 0.5) return 'text-yellow-600 dark:text-yellow-400'
    return 'text-red-600 dark:text-red-400'
  }

  const getConfidenceColor = (level?: string) => {
    switch (level) {
      case 'high': return 'bg-green-500/20 text-green-700 dark:text-green-400'
      case 'medium': return 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-400'
      case 'low': return 'bg-red-500/20 text-red-700 dark:text-red-400'
      default: return 'bg-secondary text-secondary-foreground'
    }
  }

  if (testPlanByRequirement.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        No requirement-centric test plan available
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {testPlanByRequirement.map((reqGroup) => {
        const isExpanded = expandedRequirements.has(reqGroup.requirement_id)
        const totalTests = 
          reqGroup.tests.happy_path.length +
          reqGroup.tests.negative.length +
          reqGroup.tests.boundary.length +
          reqGroup.tests.authorization.length +
          reqGroup.tests.other.length

        return (
          <div key={reqGroup.requirement_id} className="border border-border rounded-lg bg-card">
            <button
              onClick={() => toggleRequirement(reqGroup.requirement_id)}
              className="w-full p-4 flex items-start justify-between gap-4 hover:bg-secondary/50 transition-colors text-left"
            >
              <div className="flex-1 space-y-2">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-mono text-sm text-foreground/80">
                    {reqGroup.requirement_id}
                  </span>
                  <span className={`px-2 py-1 text-xs rounded ${
                    reqGroup.requirement_source === 'jira' 
                      ? 'bg-blue-500/20 text-blue-700 dark:text-blue-400' 
                      : 'bg-orange-500/20 text-orange-700 dark:text-orange-400'
                  }`}>
                    {reqGroup.requirement_source}
                  </span>
                  {reqGroup.coverage_confidence && (
                    <span className={`px-2 py-1 text-xs rounded ${getConfidenceColor(reqGroup.coverage_confidence.level)}`}>
                      {reqGroup.coverage_confidence.level} confidence
                    </span>
                  )}
                  <span className="px-2 py-1 text-xs rounded bg-secondary text-secondary-foreground">
                    {totalTests} test{totalTests !== 1 ? 's' : ''}
                  </span>
                </div>
                <p className="text-sm font-medium text-foreground">{reqGroup.requirement_text}</p>
                
                {reqGroup.quality && (
                  <div className="flex items-center gap-4 text-xs">
                    <div>
                      <span className="text-muted-foreground">Clarity: </span>
                      <span className={getQualityColor(reqGroup.quality.clarity_score)}>
                        {(reqGroup.quality.clarity_score * 100).toFixed(0)}%
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Testability: </span>
                      <span className={getQualityColor(reqGroup.quality.testability_score)}>
                        {(reqGroup.quality.testability_score * 100).toFixed(0)}%
                      </span>
                    </div>
                  </div>
                )}
              </div>
              {isExpanded ? (
                <ChevronDown className="h-5 w-5 text-muted-foreground flex-shrink-0" />
              ) : (
                <ChevronRight className="h-5 w-5 text-muted-foreground flex-shrink-0" />
              )}
            </button>

            {isExpanded && (
              <div className="px-4 pb-4 space-y-4 border-t border-border">
                <IntentGroup 
                  title="Happy Path Tests" 
                  tests={reqGroup.tests.happy_path} 
                  icon={CheckCircle2}
                />
                <IntentGroup 
                  title="Negative Tests" 
                  tests={reqGroup.tests.negative} 
                  icon={XCircle}
                />
                <IntentGroup 
                  title="Boundary Tests" 
                  tests={reqGroup.tests.boundary} 
                  icon={Gauge}
                />
                <IntentGroup 
                  title="Authorization Tests" 
                  tests={reqGroup.tests.authorization} 
                  icon={Shield}
                />
                {reqGroup.tests.other.length > 0 && (
                  <IntentGroup 
                    title="Other Tests" 
                    tests={reqGroup.tests.other} 
                    icon={TestTube}
                  />
                )}
                
                {totalTests === 0 && (
                  <div className="text-center py-4 text-muted-foreground text-sm">
                    No tests generated for this requirement
                  </div>
                )}
              </div>
            )}
          </div>
        )
      })}
    </div>
  )
}

