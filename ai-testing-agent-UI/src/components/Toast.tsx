/**
 * Toast notification system for the application.
 * 
 * This is the canonical toast/snackbar system for the frontend.
 * No other toast libraries are used - this is the single source of truth.
 * 
 * Features:
 * - PAYWALLED error notifications
 * - Auto-dismiss after 5 seconds
 * - 5-second deduplication window for PAYWALLED messages
 * - Uses existing UI patterns (framer-motion, lucide-react, tailwind)
 */
import { motion, AnimatePresence } from 'framer-motion'
import { AlertCircle, X } from 'lucide-react'
import { useEffect, useState } from 'react'

interface Toast {
  id: string
  message: string
  type: 'error' | 'warning' | 'info'
}

let toastListeners: Array<(toast: Toast) => void> = []
let lastPaywalledToastTime = 0
const PAYWALLED_DEDUPE_MS = 5000

export function showToast(message: string, type: 'error' | 'warning' | 'info' = 'error') {
  const now = Date.now()
  
  // Dedupe PAYWALLED toasts for 5 seconds
  if (message.includes('Trial limit') || message.includes('PAYWALLED')) {
    if (now - lastPaywalledToastTime < PAYWALLED_DEDUPE_MS) {
      return // Skip duplicate
    }
    lastPaywalledToastTime = now
  }
  
  const toast: Toast = {
    id: `${Date.now()}-${Math.random()}`,
    message,
    type,
  }
  
  toastListeners.forEach(listener => listener(toast))
}

export function ToastContainer() {
  const [toasts, setToasts] = useState<Toast[]>([])

  useEffect(() => {
    const listener = (toast: Toast) => {
      setToasts(prev => [...prev, toast])
      
      // Auto-remove after 5 seconds
      setTimeout(() => {
        setToasts(prev => prev.filter(t => t.id !== toast.id))
      }, 5000)
    }
    
    toastListeners.push(listener)
    return () => {
      toastListeners = toastListeners.filter(l => l !== listener)
    }
  }, [])

  return (
    <div className="fixed top-4 right-4 z-50 space-y-2 pointer-events-none">
      <AnimatePresence>
        {toasts.map(toast => (
          <motion.div
            key={toast.id}
            initial={{ opacity: 0, x: 100, scale: 0.9 }}
            animate={{ opacity: 1, x: 0, scale: 1 }}
            exit={{ opacity: 0, x: 100, scale: 0.9 }}
            className="pointer-events-auto"
          >
            <div
              className={`
                flex items-center gap-3 px-4 py-3 rounded-lg shadow-lg
                border-2 min-w-[300px] max-w-[500px]
                ${
                  toast.type === 'error'
                    ? 'bg-destructive/95 border-destructive text-destructive-foreground'
                    : toast.type === 'warning'
                    ? 'bg-amber-500/95 border-amber-400 text-amber-50'
                    : 'bg-blue-500/95 border-blue-400 text-blue-50'
                }
              `}
            >
              <AlertCircle className="h-5 w-5 flex-shrink-0" />
              <p className="text-sm font-medium flex-1">{toast.message}</p>
              <button
                onClick={() => setToasts(prev => prev.filter(t => t.id !== toast.id))}
                className="flex-shrink-0 hover:opacity-70 transition-opacity"
              >
                <X className="h-4 w-4" />
              </button>
            </div>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  )
}
