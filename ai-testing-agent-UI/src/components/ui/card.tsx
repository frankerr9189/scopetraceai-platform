import * as React from "react"
import { cn } from "@/lib/utils"

const Card = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
      className={cn(
        "rounded-lg border bg-card text-card-foreground backdrop-blur-xl bg-gradient-to-br from-background/80 via-background/60 to-background/40 transition-all duration-300 hover:translate-y-[-2px]",
        "border-white/10 hover:border-white/20",
        "shadow-[0_8px_32px_0_rgba(0,0,0,0.37),inset_0_0_0_1px_rgba(255,255,255,0.05)]",
        "hover:shadow-[0_12px_40px_0_rgba(59,130,246,0.15),0_0_0_1px_rgba(59,130,246,0.2),inset_0_0_0_1px_rgba(255,255,255,0.1)]",
        "relative before:absolute before:inset-0 before:rounded-lg before:bg-gradient-to-br before:from-blue-500/0 before:via-purple-500/0 before:to-cyan-500/0 before:opacity-0 hover:before:opacity-10 before:transition-opacity before:duration-300 before:-z-10",
        className
      )}
    {...props}
  />
))
Card.displayName = "Card"

const CardHeader = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex flex-col space-y-1.5 p-6", className)}
    {...props}
  />
))
CardHeader.displayName = "CardHeader"

const CardTitle = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLHeadingElement>
>(({ className, ...props }, ref) => (
  <h3
    ref={ref}
    className={cn(
      "text-2xl font-semibold leading-none tracking-tight",
      className
    )}
    {...props}
  />
))
CardTitle.displayName = "CardTitle"

const CardDescription = React.forwardRef<
  HTMLParagraphElement,
  React.HTMLAttributes<HTMLParagraphElement>
>(({ className, ...props }, ref) => (
  <p
    ref={ref}
    className={cn("text-sm text-muted-foreground", className)}
    {...props}
  />
))
CardDescription.displayName = "CardDescription"

const CardContent = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div ref={ref} className={cn("p-6 pt-0", className)} {...props} />
))
CardContent.displayName = "CardContent"

const CardFooter = React.forwardRef<
  HTMLDivElement,
  React.HTMLAttributes<HTMLDivElement>
>(({ className, ...props }, ref) => (
  <div
    ref={ref}
    className={cn("flex items-center p-6 pt-0", className)}
    {...props}
  />
))
CardFooter.displayName = "CardFooter"

export { Card, CardHeader, CardFooter, CardTitle, CardDescription, CardContent }

