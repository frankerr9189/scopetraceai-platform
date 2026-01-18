import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Badge } from './ui/badge'
import { AlertTriangle, CheckCircle2, XCircle, Info } from 'lucide-react'
import { motion } from 'framer-motion'

interface TicketDetail {
  ticket_id: string
  summary: string
  description: string
  requirements_count: number
  has_explicit_requirements: boolean
  has_acceptance_criteria: boolean
  explanation?: string
  status: string
}

interface FailedTicket {
  ticket_id: string
  reason: string
  status: string
  summary?: string
  description?: string
}

interface TicketsViewProps {
  ticketDetails?: TicketDetail[]
  failedTickets?: FailedTicket[]
}

export function TicketsView({ ticketDetails = [], failedTickets = [] }: TicketsViewProps) {
  // Safely handle undefined/null values
  const safeTicketDetails = Array.isArray(ticketDetails) ? ticketDetails : []
  const safeFailedTickets = Array.isArray(failedTickets) ? failedTickets : []
  
  if (safeTicketDetails.length === 0 && safeFailedTickets.length === 0) {
    return (
      <div className="text-center py-8 text-muted-foreground">
        No ticket information available
      </div>
    )
  }

  const getStatusBadge = (ticket: TicketDetail | FailedTicket) => {
    if (!ticket) return null
    if (ticket.status === 'failed') {
      return (
        <Badge variant="destructive" className="flex items-center gap-1">
          <XCircle className="h-3 w-3" />
          Failed
        </Badge>
      )
    }
    if ('requirements_count' in ticket && ticket.requirements_count === 0) {
      return (
        <Badge variant="warning" className="flex items-center gap-1">
          <AlertTriangle className="h-3 w-3" />
          No Requirements
        </Badge>
      )
    }
    return (
      <Badge variant="success" className="flex items-center gap-1">
        <CheckCircle2 className="h-3 w-3" />
        Processed
      </Badge>
    )
  }

  const getRequirementsBadge = (ticket: TicketDetail) => {
    if (!ticket) return null
    if (ticket.requirements_count === 0) {
      return <Badge variant="secondary">0 requirements</Badge>
    }
    if (ticket.has_explicit_requirements) {
      return (
        <Badge variant="default">
          {ticket.requirements_count} requirement{ticket.requirements_count !== 1 ? 's' : ''} (explicit)
        </Badge>
      )
    }
    return (
      <Badge variant="outline">
        {ticket.requirements_count} requirement{ticket.requirements_count !== 1 ? 's' : ''} (inferred)
      </Badge>
    )
  }

  return (
    <div className="space-y-4">
      {/* Processed Tickets */}
      {safeTicketDetails.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-foreground/90 border-b border-border pb-2">
            Analyzed Tickets <span className="text-sm text-muted-foreground font-normal">({safeTicketDetails.length})</span>
          </h3>
          {safeTicketDetails.map((ticket, index) => {
            if (!ticket || !ticket.ticket_id) return null
            return (
            <motion.div
              key={ticket.ticket_id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: index * 0.05 }}
            >
              <Card className="border-border/50">
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <CardTitle className="text-base font-semibold mb-1">
                        {ticket.ticket_id}
                      </CardTitle>
                      {ticket.summary && (
                        <p className="text-sm text-foreground/80 mb-2">{ticket.summary}</p>
                      )}
                    </div>
                    <div className="flex flex-col items-end gap-2">
                      {getStatusBadge(ticket)}
                      {getRequirementsBadge(ticket)}
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="pt-0 space-y-3">
                  {ticket.description && (
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Description:</p>
                      <p className="text-sm text-foreground/70">{ticket.description}</p>
                    </div>
                  )}
                  
                  <div className="flex flex-wrap gap-2 text-xs">
                    {ticket.has_acceptance_criteria ? (
                      <Badge variant="outline" className="text-xs">
                        Has Acceptance Criteria
                      </Badge>
                    ) : (
                      <Badge variant="outline" className="text-xs">
                        No Acceptance Criteria
                      </Badge>
                    )}
                  </div>

                  {ticket.explanation && (
                    <div className="p-3 bg-warning/10 border border-warning/30 rounded-md">
                      <div className="flex items-start gap-2">
                        <Info className="h-4 w-4 text-warning mt-0.5 flex-shrink-0" />
                        <div>
                          <p className="text-xs font-medium text-warning mb-1">Analysis Note</p>
                          <p className="text-xs text-foreground/80">{ticket.explanation}</p>
                        </div>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </motion.div>
            )
          })}
        </div>
      )}

      {/* Failed Tickets */}
      {safeFailedTickets.length > 0 && (
        <div className="space-y-3">
          <h3 className="text-lg font-semibold text-foreground/90 border-b border-border pb-2">
            Failed Tickets <span className="text-sm text-muted-foreground font-normal">({safeFailedTickets.length})</span>
          </h3>
          {safeFailedTickets.map((ticket, index) => {
            if (!ticket || !ticket.ticket_id) return null
            return (
            <motion.div
              key={ticket.ticket_id}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: (safeTicketDetails.length + index) * 0.05 }}
            >
              <Card className="border-destructive/50 bg-destructive/5">
                <CardHeader className="pb-3">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <CardTitle className="text-base font-semibold mb-1 text-destructive">
                        {ticket.ticket_id}
                      </CardTitle>
                      {ticket.summary && (
                        <p className="text-sm text-foreground/80 mb-2">{ticket.summary}</p>
                      )}
                    </div>
                    {getStatusBadge(ticket)}
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="p-3 bg-destructive/10 border border-destructive/30 rounded-md">
                    <p className="text-xs font-medium text-destructive mb-1">Error Reason</p>
                    <p className="text-xs text-foreground/80">{ticket.reason}</p>
                  </div>
                </CardContent>
              </Card>
            </motion.div>
            )
          })}
        </div>
      )}
    </div>
  )
}

