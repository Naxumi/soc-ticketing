export function humanizeEnum(value: string): string {
  const cleaned = String(value ?? "")
    .trim()
    .replace(/[-_]+/g, " ")
    .toLowerCase()
  if (!cleaned) return ""
  return cleaned.replace(/\b\w/g, (m) => m.toUpperCase())
}

export type BadgeVariant = "default" | "secondary" | "destructive" | "outline" | "ghost" | "link"

export function severityBadgeProps(severity: string | null | undefined): {
  variant: BadgeVariant
  className?: string
} {
  switch (severity) {
    case "critical":
      return {
        variant: "destructive",
        className: "border border-red-400/30 bg-red-500/15 text-red-600 dark:text-red-400",
      }
    case "high":
      return {
        variant: "destructive",
      }
    case "medium":
      return {
        variant: "secondary",
        className:
          "border border-brand-yellow-500/30 bg-brand-yellow-500/15 text-brand-yellow-700 dark:text-brand-yellow-300",
      }
    case "low":
      return {
        variant: "secondary",
        className:
          "border border-brand-blue-400/30 bg-brand-blue-400/15 text-brand-blue-600 dark:text-brand-blue-300",
      }
    default:
      return { variant: "outline" }
  }
}
