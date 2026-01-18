import { useState } from 'react'
import { Button } from './ui/button'
import { Card, CardContent, CardHeader, CardTitle } from './ui/card'
import { Loader2, Plus, X } from 'lucide-react'
import { motion } from 'framer-motion'

interface TicketInputPanelProps {
  onGenerate: (tickets: { ticket_id: string }[]) => void
  isLoading: boolean
  isDisabled?: boolean
}

export function TicketInputPanel({ onGenerate, isLoading, isDisabled = false }: TicketInputPanelProps) {
  const [tickets, setTickets] = useState<string[]>([''])

  const handleAddTicket = () => {
    setTickets([...tickets, ''])
  }

  const handleRemoveTicket = (index: number) => {
    if (tickets.length > 1) {
      setTickets(tickets.filter((_, i) => i !== index))
    }
  }

  const handleTicketChange = (index: number, value: string) => {
    const newTickets = [...tickets]
    newTickets[index] = value
    setTickets(newTickets)
  }

  const handleGenerate = () => {
    const validTickets = tickets
      .map(t => t.trim())
      .filter(t => t.length > 0)
      .map(t => ({ ticket_id: t }))
    
    if (validTickets.length > 0) {
      onGenerate(validTickets)
    }
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
    >
      <Card className="border-border/50 bg-gradient-to-br from-background via-background to-secondary/10">
        <CardHeader>
          <CardTitle className="text-2xl font-bold bg-gradient-to-r from-foreground to-foreground/70 bg-clip-text text-transparent">
            Generate Test Plan
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            {tickets.map((ticket, index) => (
              <div key={index} className="flex gap-2 items-center">
                <input
                  type="text"
                  value={ticket}
                  onChange={(e) => handleTicketChange(index, e.target.value)}
                  placeholder="Enter JIRA ticket ID (e.g., ATA-36)"
                  className="flex-1 px-4 py-2 bg-background border border-input rounded-md text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 focus:ring-offset-background"
                  disabled={isLoading}
                />
                {tickets.length > 1 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => handleRemoveTicket(index)}
                    disabled={isLoading}
                    className="text-muted-foreground hover:text-foreground"
                  >
                    <X className="h-4 w-4" />
                  </Button>
                )}
              </div>
            ))}
          </div>
          
          <div className="flex gap-2">
            <Button
              variant="outline"
              onClick={handleAddTicket}
              disabled={isLoading}
              className="flex items-center gap-2"
            >
              <Plus className="h-4 w-4" />
              Add Ticket
            </Button>
            
            <Button
              onClick={handleGenerate}
              disabled={isLoading || tickets.every(t => !t.trim()) || isDisabled}
              className="flex-1 flex items-center justify-center gap-2 bg-gradient-to-r from-primary to-primary/80 hover:from-primary/90 hover:to-primary/70 shadow-[0_4px_14px_0_rgba(255,255,255,0.15)] hover:shadow-[0_6px_20px_0_rgba(59,130,246,0.3)] transition-all"
            >
              {isLoading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Generating...
                </>
              ) : (
                'Generate Test Plan'
              )}
            </Button>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  )
}

