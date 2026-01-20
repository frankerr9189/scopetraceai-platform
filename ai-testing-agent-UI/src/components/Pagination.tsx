import { ChevronLeft, ChevronRight } from 'lucide-react'
import { Button } from './ui/button'

interface PaginationProps {
  page: number
  totalPages: number
  onPageChange: (page: number) => void
  total: number
  limit: number
}

export function Pagination({ page, totalPages, onPageChange, total, limit }: PaginationProps) {
  // If no items, don't show pagination controls (only show "Showing 0–0 of 0" if desired)
  if (total === 0) {
    return (
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4 mt-6">
        <div className="text-sm text-muted-foreground">
          Showing 0–0 of 0
        </div>
      </div>
    )
  }

  const getPageNumbers = (): (number | 'ellipsis')[] => {
    if (totalPages <= 7) {
      // Show all pages if 7 or fewer
      return Array.from({ length: totalPages }, (_, i) => i + 1)
    }

    const pages: (number | 'ellipsis')[] = []
    
    // Always show first page
    pages.push(1)
    
    if (page <= 4) {
      // Near the start: show 1, 2, 3, 4, 5, ..., last
      for (let i = 2; i <= 5; i++) {
        pages.push(i)
      }
      pages.push('ellipsis')
      pages.push(totalPages)
    } else if (page >= totalPages - 3) {
      // Near the end: show 1, ..., last-4, last-3, last-2, last-1, last
      pages.push('ellipsis')
      for (let i = totalPages - 4; i <= totalPages; i++) {
        pages.push(i)
      }
    } else {
      // Middle: show 1, ..., current-1, current, current+1, ..., last
      pages.push('ellipsis')
      pages.push(page - 1)
      pages.push(page)
      pages.push(page + 1)
      pages.push('ellipsis')
      pages.push(totalPages)
    }
    
    return pages
  }

  const pageNumbers = getPageNumbers()
  const start = total === 0 ? 0 : (page - 1) * limit + 1
  const end = Math.min(page * limit, total)

  return (
    <div className="flex flex-col sm:flex-row items-center justify-between gap-4 mt-6">
      <div className="text-sm text-muted-foreground">
        Showing {start}–{end} of {total}
      </div>
      
      <div className="flex items-center gap-1">
        <Button
          variant="outline"
          size="sm"
          onClick={() => onPageChange(page - 1)}
          disabled={page === 1}
          className="h-8 w-8 p-0"
        >
          <ChevronLeft className="h-4 w-4" />
        </Button>
        
        {pageNumbers.map((pageNum, idx) => {
          if (pageNum === 'ellipsis') {
            return (
              <span key={`ellipsis-${idx}`} className="px-2 text-muted-foreground">
                ...
              </span>
            )
          }
          
          return (
            <Button
              key={pageNum}
              variant={pageNum === page ? "default" : "outline"}
              size="sm"
              onClick={() => onPageChange(pageNum)}
              className={`h-8 w-8 p-0 ${pageNum === page ? 'font-semibold' : ''}`}
            >
              {pageNum}
            </Button>
          )
        })}
        
        <Button
          variant="outline"
          size="sm"
          onClick={() => onPageChange(page + 1)}
          disabled={page === totalPages || totalPages === 0}
          className="h-8 w-8 p-0"
        >
          <ChevronRight className="h-4 w-4" />
        </Button>
      </div>
    </div>
  )
}
