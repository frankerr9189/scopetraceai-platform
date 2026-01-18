import { RTMEntry } from '../services/api'
import { Badge } from './ui/badge'
import { motion } from 'framer-motion'

interface RTMTableProps {
  rtm: RTMEntry[]
}

export function RTMTable({ rtm }: RTMTableProps) {
  if (rtm.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        No RTM data available
      </div>
    )
  }

  return (
    <div className="rounded-lg border border-border/50 overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="border-b border-border bg-secondary/20">
              <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Requirement ID</th>
              <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Description</th>
              <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Type</th>
              <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Coverage Status</th>
              <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Covered By Tests</th>
              <th className="px-4 py-3 text-left text-sm font-semibold text-foreground">Rationale</th>
            </tr>
          </thead>
          <tbody>
            {rtm.map((entry, index) => {
              const isInformational = entry.trace_type === 'informational' || entry.testability === 'not_testable'
              
              return (
                <motion.tr
                  key={entry.requirement_id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="border-b border-border/50 hover:bg-secondary/10 transition-colors"
                >
                  <td className="px-4 py-3 text-sm font-mono text-foreground/90">
                    {entry.requirement_id}
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground max-w-md">
                    {entry.requirement_description}
                  </td>
                  <td className="px-4 py-3">
                    <Badge
                      variant={isInformational ? 'secondary' : 'default'}
                      className="text-xs"
                    >
                      {isInformational ? 'Informational (Not Testable)' : 'Testable'}
                    </Badge>
                  </td>
                  <td className="px-4 py-3">
                    {isInformational ? (
                      <span className="text-xs text-muted-foreground">N/A</span>
                    ) : (
                      <Badge
                        variant={entry.coverage_status === 'COVERED' ? 'success' : 'destructive'}
                        className="text-xs"
                      >
                        {entry.coverage_status}
                      </Badge>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    {entry.covered_by_tests && entry.covered_by_tests.length > 0 ? (
                      <div className="flex flex-wrap gap-1">
                        {entry.covered_by_tests.map((testId) => (
                          <Badge key={testId} variant="secondary" className="text-xs font-mono">
                            {testId}
                          </Badge>
                        ))}
                      </div>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-sm text-muted-foreground max-w-xs">
                    {entry.rationale ? (
                      <span className="text-xs">{entry.rationale}</span>
                    ) : (
                      <span className="text-xs text-muted-foreground">—</span>
                    )}
                  </td>
                </motion.tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

