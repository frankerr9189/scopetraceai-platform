import { AuditMetadata } from '../services/api'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { motion } from 'framer-motion'
import { useState } from 'react'
import { ChevronDown, ChevronRight, Info } from 'lucide-react'
import { AnimatePresence } from 'framer-motion'

interface AuditMetadataViewProps {
  metadata: AuditMetadata
}

export function AuditMetadataView({ metadata }: AuditMetadataViewProps) {
  const [isExpanded, setIsExpanded] = useState(false)

  const getEnvironmentBadge = (env: string) => {
    const envMap: Record<string, { label: string; variant: 'default' | 'secondary' | 'success' | 'warning' | 'destructive' }> = {
      production: { label: 'Production', variant: 'destructive' },
      staging: { label: 'Staging', variant: 'warning' },
      development: { label: 'Development', variant: 'secondary' },
      dev: { label: 'Development', variant: 'secondary' },
    }
    const envInfo = envMap[env.toLowerCase()] || { label: env, variant: 'secondary' as const }
    return <Badge variant={envInfo.variant} className="text-xs">{envInfo.label}</Badge>
  }

  return (
    <Card className="border-border/30 bg-background/50 backdrop-blur-sm">
      <CardHeader className="pb-3">
        <button
          onClick={() => setIsExpanded(!isExpanded)}
          className="w-full flex items-center justify-between text-left hover:opacity-80 transition-opacity"
        >
          <div className="flex items-center gap-2">
            <Info className="h-4 w-4 text-muted-foreground" />
            <CardTitle className="text-sm font-semibold text-foreground/90">
              Audit Metadata (ISO 27001/SOC 2)
            </CardTitle>
            {getEnvironmentBadge(metadata.environment)}
          </div>
          {isExpanded ? (
            <ChevronDown className="h-4 w-4 text-muted-foreground" />
          ) : (
            <ChevronRight className="h-4 w-4 text-muted-foreground" />
          )}
        </button>
      </CardHeader>
      <AnimatePresence>
        {isExpanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden"
          >
            <CardContent className="pt-0 space-y-3">
              {/* Compact Run Metadata Section */}
              <div className="pb-2 border-b border-border/30">
                <span className="text-xs font-semibold text-muted-foreground mb-2 block">Run Metadata</span>
                <div className="space-y-1 text-xs text-muted-foreground">
                  <div className="flex items-start gap-2">
                    <span className="font-mono text-muted-foreground/70 min-w-[100px]">Run ID:</span>
                    <span className="font-mono text-foreground/70 break-all">{metadata.run_id}</span>
                  </div>
                  <div className="flex items-start gap-2">
                    <span className="font-mono text-muted-foreground/70 min-w-[100px]">Generated At:</span>
                    <span className="font-mono text-foreground/70">{metadata.generated_at}</span>
                  </div>
                  {metadata.agent_metadata ? (
                    <>
                      <div className="flex items-start gap-2">
                        <span className="font-mono text-muted-foreground/70 min-w-[100px]">Agent Version:</span>
                        <span className="font-mono text-foreground/70">{metadata.agent_metadata.agent_version}</span>
                      </div>
                      <div className="flex items-start gap-2">
                        <span className="font-mono text-muted-foreground/70 min-w-[100px]">Logic Version:</span>
                        <span className="font-mono text-foreground/70">{metadata.agent_metadata.logic_version}</span>
                      </div>
                      <div className="flex items-start gap-2">
                        <span className="font-mono text-muted-foreground/70 min-w-[100px]">Determinism:</span>
                        <span className="text-foreground/70">{metadata.agent_metadata.determinism}</span>
                      </div>
                    </>
                  ) : (
                    <div className="flex items-start gap-2">
                      <span className="font-mono text-muted-foreground/70 min-w-[100px]">Agent Version:</span>
                      <span className="font-mono text-foreground/70">{metadata.agent_version}</span>
                    </div>
                  )}
                </div>
              </div>
              
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <span className="text-xs text-muted-foreground font-mono">Model:</span>
                  <p className="text-xs text-foreground/80 mt-1">
                    {metadata.model.name} (temp: {metadata.model.temperature})
                  </p>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground font-mono">Source Type:</span>
                  <p className="text-xs text-foreground/80 mt-1 capitalize">{metadata.source.type}</p>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground font-mono">Tickets Analyzed:</span>
                  <p className="text-xs text-foreground/80 mt-1">{metadata.source.ticket_count}</p>
                </div>
              </div>
              
              <div className="pt-2 border-t border-border/30">
                <span className="text-xs font-semibold text-foreground/90 mb-2 block">Algorithms Used:</span>
                <div className="space-y-1.5 text-xs">
                  <div>
                    <span className="text-muted-foreground">Test Generation: </span>
                    <span className="text-foreground/80">{metadata.algorithms.test_generation}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Coverage Analysis: </span>
                    <span className="text-foreground/80">{metadata.algorithms.coverage_analysis}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Quality Scoring: </span>
                    <span className="text-foreground/80">{metadata.algorithms.quality_scoring}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Confidence Calculation: </span>
                    <span className="text-foreground/80">{metadata.algorithms.confidence_calculation}</span>
                  </div>
                </div>
              </div>
            </CardContent>
          </motion.div>
        )}
      </AnimatePresence>
    </Card>
  )
}

