import { FileText, Link2, TestTube, AlertCircle, Info, CheckCircle2 } from 'lucide-react'

interface TicketItem {
  item_id: string
  text: string
  classification: 'primary_requirement' | 'acceptance_criterion' | 'boundary_condition' | 'negative_condition' | 'technical_constraint' | 'informational_only' | 'unclear_needs_clarification' | 'system_behavior'
  source_section: string
  mapped_requirement_id?: string
  validated_by_tests?: string[]
  testable?: boolean
  note?: string
}

interface TicketTraceability {
  ticket_id: string
  items: TicketItem[]
}

interface TicketBreakdownViewProps {
  ticketTraceability?: TicketTraceability[]
}

export function TicketBreakdownView({ ticketTraceability = [] }: TicketBreakdownViewProps) {
  if (!ticketTraceability || ticketTraceability.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        No ticket breakdown information available
      </div>
    )
  }

  const getClassificationBadge = (classification: TicketItem['classification']) => {
    const variants: Record<string, { label: string; className: string }> = {
      primary_requirement: { label: 'Primary Requirement', className: 'bg-primary text-primary-foreground' },
      acceptance_criterion: { label: 'Acceptance Criterion', className: 'bg-green-500/20 text-green-700 dark:text-green-400' },
      boundary_condition: { label: 'Boundary Condition', className: 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-400' },
      negative_condition: { label: 'Negative Condition', className: 'bg-red-500/20 text-red-700 dark:text-red-400' },
      technical_constraint: { label: 'Technical Constraint', className: 'bg-secondary text-secondary-foreground' },
      informational_only: { label: 'Informational Only', className: 'bg-secondary text-secondary-foreground' },
      system_behavior: { label: 'System Behavior', className: 'bg-blue-500/20 text-blue-700 dark:text-blue-400' },
      unclear_needs_clarification: { label: 'Needs Clarification', className: 'bg-yellow-500/20 text-yellow-700 dark:text-yellow-400' }
    }
    
    const config = variants[classification] || { label: classification, className: 'bg-secondary text-secondary-foreground' }
    return (
      <span className={`px-2 py-1 text-xs rounded ${config.className}`}>
        {config.label}
      </span>
    )
  }

  const getClassificationIcon = (classification: TicketItem['classification']) => {
    switch (classification) {
      case 'primary_requirement':
        return <FileText className="h-4 w-4" />
      case 'acceptance_criterion':
        return <CheckCircle2 className="h-4 w-4" />
      case 'boundary_condition':
      case 'negative_condition':
        return <TestTube className="h-4 w-4" />
      case 'technical_constraint':
        return <Info className="h-4 w-4" />
      case 'informational_only':
        return <Info className="h-4 w-4" />
      case 'system_behavior':
        return <TestTube className="h-4 w-4" />
      case 'unclear_needs_clarification':
        return <AlertCircle className="h-4 w-4" />
      default:
        return <FileText className="h-4 w-4" />
    }
  }

  return (
    <div className="space-y-6">
      {ticketTraceability.map((traceability, ticketIndex) => (
        <div key={traceability.ticket_id} className="space-y-4">
          <div className="flex items-center gap-2">
            <h3 className="text-lg font-semibold text-foreground/90">
              {traceability.ticket_id}
            </h3>
            <span className="px-2 py-1 text-xs rounded border border-border">
              {traceability.items.length} item{traceability.items.length !== 1 ? 's' : ''}
            </span>
          </div>

          <div className="space-y-3">
            {traceability.items.map((item, itemIndex) => (
              <div
                key={item.item_id}
                className="border border-border/50 rounded-lg p-4 bg-card"
              >
                <div className="space-y-3">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1 space-y-2">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-mono text-xs text-muted-foreground">
                          {item.item_id}
                        </span>
                        {getClassificationBadge(item.classification)}
                        {item.testable === false && (
                          <span className="px-2 py-1 text-xs rounded bg-secondary text-secondary-foreground">
                            Not Testable
                          </span>
                        )}
                      </div>
                      <p className="text-sm text-foreground/90">{item.text}</p>
                    </div>
                    <div className="flex items-center gap-1 text-muted-foreground">
                      {getClassificationIcon(item.classification)}
                    </div>
                  </div>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-xs text-muted-foreground">Source Section:</span>
                        <p className="text-xs text-foreground/80 mt-1 capitalize">
                          {item.source_section.replace('_', ' ')}
                        </p>
                      </div>
                      {item.mapped_requirement_id && (
                        <div>
                          <span className="text-xs text-muted-foreground">Mapped Requirement:</span>
                          <div className="mt-1">
                            <span className="px-2 py-1 text-xs rounded bg-secondary text-secondary-foreground font-mono">
                              {item.mapped_requirement_id}
                            </span>
                          </div>
                        </div>
                      )}
                    </div>

                    {item.validated_by_tests && item.validated_by_tests.length > 0 && (
                      <div>
                        <span className="text-xs text-muted-foreground mb-2 block">Covered by tests:</span>
                        <div className="flex flex-wrap gap-2">
                          {item.validated_by_tests.map((testId, idx) => (
                            <button
                              key={testId}
                              onClick={() => {
                                const element = document.getElementById(`test-${testId}`)
                                if (element) {
                                  element.scrollIntoView({ behavior: 'smooth', block: 'center' })
                                  element.focus()
                                }
                              }}
                              className="px-2 py-1 text-xs rounded border border-border font-mono flex items-center gap-1 hover:bg-secondary/50 transition-colors cursor-pointer"
                            >
                              <Link2 className="h-3 w-3" />
                              {testId}
                            </button>
                          ))}
                        </div>
                      </div>
                    )}

                    {item.note && (
                      <div className="p-3 bg-warning/10 border border-warning/30 rounded-md">
                        <div className="flex items-start gap-2">
                          <Info className="h-4 w-4 text-warning mt-0.5 flex-shrink-0" />
                          <p className="text-xs text-foreground/80">{item.note}</p>
                        </div>
                      </div>
                    )}

                    {item.testable === false && !item.note && (
                      <div className="p-3 bg-secondary/20 border border-border rounded-md">
                        <p className="text-xs text-muted-foreground">
                          This item is not directly testable but is tracked for audit compliance.
                        </p>
                      </div>
                    )}
                </div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

