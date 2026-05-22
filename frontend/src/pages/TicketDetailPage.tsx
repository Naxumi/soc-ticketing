import * as React from "react"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { Link, useParams } from "react-router-dom"
import { toast } from "sonner"

import { socApi, type TicketStatus } from "@/api/soc"
import { ApiError } from "@/lib/api"
import { useAuth } from "@/auth/AuthContext"
import { humanizeEnum, severityBadgeProps } from "@/lib/format"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Label } from "@/components/ui/label"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Textarea } from "@/components/ui/textarea"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

function allowedNextStatuses(current: TicketStatus): TicketStatus[] {
  switch (current) {
    case "AGGREGATING":
      return []
    case "OPEN":
      return ["IN_PROGRESS"]
    case "IN_PROGRESS":
      return ["ESCALATED", "FALSE_POSITIVE"]
    case "ESCALATED":
      return ["INVESTIGATING"]
    case "INVESTIGATING":
      return ["FALSE_POSITIVE", "RESOLVED"]
    default:
      return []
  }
}

function formatJsonPayload(payload: unknown): string {
  if (payload == null) return ""

  if (typeof payload === "string") {
    const trimmed = payload.trim()
    if (!trimmed) return payload
    try {
      const parsed = JSON.parse(trimmed)
      return JSON.stringify(parsed, (_key, value) => (typeof value === "bigint" ? value.toString() : value), 2)
    } catch {
      return payload
    }
  }

  try {
    return JSON.stringify(payload, (_key, value) => (typeof value === "bigint" ? value.toString() : value), 2)
  } catch {
    return String(payload)
  }
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
}

const JSON_TOKEN_CLASSES = {
  key: "json-key",
  string: "json-string",
  number: "json-number",
  boolean: "json-boolean",
  null: "json-null",
}

const DEFAULT_MODEL = "llama-3.3-70b-versatile"

// Basic JSON token highlighter to improve readability without external deps.
function highlightJson(value: string): string {
  if (!value) return ""
  const escaped = escapeHtml(value)
  return escaped.replace(
    /("(\\u[a-zA-Z0-9]{4}|\\[^u]|[^\\"])*"(?:\s*:)?|\b(true|false|null)\b|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?)/g,
    (match) => {
      let className = JSON_TOKEN_CLASSES.number
      if (match.startsWith('"')) {
        className = match.endsWith(":") ? JSON_TOKEN_CLASSES.key : JSON_TOKEN_CLASSES.string
      } else if (match === "true" || match === "false") {
        className = JSON_TOKEN_CLASSES.boolean
      } else if (match === "null") {
        className = JSON_TOKEN_CLASSES.null
      }
      return `<span class="${className}">${match}</span>`
    }
  )
}

type RawLogBlockProps = {
  title: string
  timestamp?: string
  payload: unknown
  copyLabel?: string
}

function RawLogBlock({ title, timestamp, payload, copyLabel = "Copy" }: RawLogBlockProps) {
  const formatted = React.useMemo(() => formatJsonPayload(payload), [payload])
  const highlighted = React.useMemo(() => highlightJson(formatted), [formatted])

  const handleCopy = React.useCallback(async () => {
    if (!formatted) return
    try {
      await navigator.clipboard.writeText(formatted)
      toast.success("Copied to clipboard")
    } catch (err) {
      toast.error(err instanceof Error ? err.message : "Failed to copy")
    }
  }, [formatted])

  return (
    <div className="min-w-0 w-full max-w-full rounded-md border p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <div className="text-xs font-medium text-muted-foreground">{title}</div>
        <div className="flex items-center gap-2">
          {timestamp ? <div className="text-xs text-muted-foreground">{timestamp}</div> : null}
          <Button size="xs" variant="outline" onClick={handleCopy} disabled={!formatted}>
            {copyLabel}
          </Button>
        </div>
      </div>
      <div className="json-scroll max-h-80 w-full max-w-full overflow-auto rounded-md bg-muted">
        <pre
          className="min-w-max whitespace-pre text-xs font-semibold font-mono"
          dangerouslySetInnerHTML={{ __html: highlighted || escapeHtml(formatted) }}
        />
      </div>
    </div>
  )
}

export function TicketDetailPage() {
  const { id } = useParams<{ id: string }>()
  const { me } = useAuth()
  const qc = useQueryClient()

  const ticketQuery = useQuery({
    queryKey: ["ticket", id],
    queryFn: () => socApi.ticketDetail(id!),
    enabled: Boolean(id),
  })

  const detail = ticketQuery.data
  const currentStatus = detail?.ticket.status
  const nextStatuses = currentStatus ? allowedNextStatuses(currentStatus) : []

  const [nextStatus, setNextStatus] = React.useState<TicketStatus | "">("")
  const [note, setNote] = React.useState("")
  const [assigneeId, setAssigneeId] = React.useState<string>(me?.id ?? "")
  const [formError, setFormError] = React.useState<string | null>(null)
  const [analysisLanguage, setAnalysisLanguage] = React.useState<"id" | "en">("id")
  const [analysisModel, setAnalysisModel] = React.useState(DEFAULT_MODEL)

  const modelsQuery = useQuery({
    queryKey: ["ai-models"],
    queryFn: () => socApi.listAiModels(),
  })

  const modelOptions = React.useMemo(() => {
    const options = modelsQuery.data?.models ?? []
    return Array.from(new Set([DEFAULT_MODEL, ...options]))
  }, [modelsQuery.data])

  React.useEffect(() => {
    if (!nextStatus && nextStatuses.length > 0) {
      setNextStatus(nextStatuses[0])
    }
  }, [nextStatus, nextStatuses])

  const usersQuery = useQuery({
    queryKey: ["users"],
    queryFn: () => socApi.listUsers(),
    enabled: me?.role === "SOC_MANAGER",
  })

  const assignableUsers = React.useMemo(() => {
    if (!usersQuery.data) return []
    let users = [...usersQuery.data]
    
    // Filter based on allowed roles for specific statuses
    users = users.filter((u) => {
      if (nextStatus === "IN_PROGRESS") {
        return u.role === "L1_ANALYST" || u.role === "SOC_MANAGER"
      }
      if (nextStatus === "INVESTIGATING") {
        return u.role === "L2_ANALYST" || u.role === "SOC_MANAGER"
      }
      return true
    })

    if (me) {
      const meIdx = users.findIndex((u) => u.id === me.id)
      if (meIdx > -1) {
        const [meUser] = users.splice(meIdx, 1)
        users.unshift(meUser)
      }
    }
    return users
  }, [usersQuery.data, me, nextStatus])

  React.useEffect(() => {
    if (me?.role === "SOC_MANAGER" && assignableUsers.length > 0) {
      if (!assigneeId || !assignableUsers.find(u => u.id === assigneeId)) {
        setAssigneeId(assignableUsers[0].id)
      }
    }
  }, [me?.role, assignableUsers, assigneeId])

  const updateMutation = useMutation({
    mutationFn: async () => {
      if (!id) return
      if (!nextStatus) throw new Error("Missing status")
      if (!note.trim()) throw new Error("Note is required")
      await socApi.updateTicketStatus(id, {
        status: nextStatus,
        note: note.trim(),
        assignee_id: me?.role === "SOC_MANAGER" ? assigneeId : (me?.id ?? null),
      })
    },
    onSuccess: async () => {
      setNote("")
      setFormError(null)
      await qc.invalidateQueries({ queryKey: ["ticket", id] })
      await qc.invalidateQueries({ queryKey: ["tickets"] })
    },
    onError: (err) => {
      if (err instanceof ApiError) {
        setFormError(err.message)
        return
      }
      if (err instanceof Error) {
        setFormError(err.message)
        return
      }
      setFormError("Failed to update")
    },
  })

  const analyzeMutation = useMutation({
    mutationFn: async () => {
      if (!id) return
      await socApi.analyzeTicket(id, {
        model_name: analysisModel || undefined,
        response_language: analysisLanguage,
      })
    },
    onSuccess: async () => {
      toast.success("Analisis AI berhasil dipicu.")
      await qc.invalidateQueries({ queryKey: ["ticket", id] })
      await qc.invalidateQueries({ queryKey: ["tickets"] })
    },
    onError: (err) => {
      if (err instanceof ApiError) {
        toast.error(err.message)
        return
      }
      if (err instanceof Error) {
        toast.error(err.message)
        return
      }
      toast.error("Failed to trigger analysis")
    },
  })

  if (ticketQuery.isLoading) {
    return <div className="text-sm text-muted-foreground">Loading...</div>
  }

  if (ticketQuery.isError || !detail) {
    return <div className="text-sm text-destructive">Failed to load ticket.</div>
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between gap-2">
        <div className="space-y-1">
          <div className="text-xs text-muted-foreground">
            <Link className="underline-offset-4 hover:underline" to="/tickets">
              Tickets
            </Link>
            <span className="mx-2">/</span>
            <span>{detail.ticket.ticket_number || detail.ticket.id}</span>
          </div>
          <div className="text-lg font-semibold">Ticket {detail.ticket.ticket_number || detail.ticket.id}</div>
          <div className="text-xs text-muted-foreground">Rule {detail.ticket.attack_rule_id}</div>
        </div>
        <div className="flex items-center gap-2">
          <Badge variant="outline">{humanizeEnum(detail.ticket.status)}</Badge>
          <Badge {...severityBadgeProps(detail.ticket.severity)}>
            {detail.ticket.severity ? humanizeEnum(detail.ticket.severity) : "--"}
          </Badge>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[minmax(0,1fr)_280px]">
        <div className="min-w-0 space-y-4">
          <Card className="ring-brand-blue-600/20">
            <CardHeader className="border-b bg-brand-blue-800/5 dark:bg-brand-blue-600/10">
              <CardTitle className="text-brand-blue-800 dark:text-brand-yellow-500">Analysis</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="rounded-md border bg-muted/30 p-3">
                <div className="text-xs font-medium text-muted-foreground">Trigger AI analysis</div>
                <div className="mt-3 grid gap-3 sm:grid-cols-2">
                  <div className="space-y-2">
                    <Label>Response language</Label>
                    <Select value={analysisLanguage} onValueChange={(v) => setAnalysisLanguage(v as "id" | "en")}>
                      <SelectTrigger className="w-full">
                        <SelectValue placeholder="Select language" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="id">Indonesia (id)</SelectItem>
                        <SelectItem value="en">English (en)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label>Model</Label>
                    <Select value={analysisModel} onValueChange={setAnalysisModel}>
                      <SelectTrigger className="w-full">
                        <SelectValue placeholder="Select model" />
                      </SelectTrigger>
                      <SelectContent>
                        {modelOptions.map((model) => (
                          <SelectItem key={model} value={model}>
                            {model}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <div className="text-xs text-muted-foreground">
                      {modelsQuery.isLoading
                        ? "Loading models..."
                        : modelsQuery.isError
                          ? "Failed to load models. Using default."
                          : `${modelOptions.length} models available.`}
                    </div>
                  </div>
                </div>

                <div className="mt-3 flex flex-wrap items-center gap-2">
                  <Button
                    disabled={analyzeMutation.isPending}
                    onClick={() => analyzeMutation.mutate()}
                  >
                    {analyzeMutation.isPending ? "Triggering..." : "Trigger AI analysis"}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={modelsQuery.isFetching}
                    onClick={() => modelsQuery.refetch()}
                  >
                    {modelsQuery.isFetching ? "Refreshing..." : "Refresh models"}
                  </Button>
                </div>
              </div>

              {detail.analysis?.summary ? (
                <div className="grid gap-2 sm:grid-cols-[96px_minmax(0,1fr)] sm:items-start">
                  <div className="text-xs font-medium text-muted-foreground">Summary</div>
                  <div className="text-sm whitespace-pre-wrap break-words">{detail.analysis.summary}</div>
                </div>
              ) : (
                <div className="text-sm text-muted-foreground">No analysis available.</div>
              )}

              {detail.analysis?.detailed_analysis ? (
                <div className="grid gap-2 sm:grid-cols-[96px_minmax(0,1fr)] sm:items-start">
                  <div className="text-xs font-medium text-muted-foreground">Details</div>
                  <div className="whitespace-pre-wrap break-words text-sm">{detail.analysis.detailed_analysis}</div>
                </div>
              ) : null}

              <div className="grid gap-2 sm:grid-cols-[96px_minmax(0,1fr)] sm:items-start">
                <div className="text-xs font-medium text-muted-foreground">Attack vector</div>
                <div className="text-sm break-words">{detail.analysis?.attack_vector ?? "--"}</div>
              </div>

              <div className="grid gap-2 sm:grid-cols-[96px_minmax(0,1fr)] sm:items-start">
                <div className="text-xs font-medium text-muted-foreground">Potential impact</div>
                <div className="text-sm break-words">{detail.analysis?.potential_impact ?? "--"}</div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Indicators (IOCs)</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="rounded-md border">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead>Type</TableHead>
                      <TableHead>Value</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {detail.iocs.length === 0 ? (
                      <TableRow>
                        <TableCell colSpan={2} className="text-sm text-muted-foreground">
                          No indicators.
                        </TableCell>
                      </TableRow>
                    ) : null}
                    {detail.iocs.map((ioc, idx) => (
                      <TableRow key={`${ioc.ioc_type}-${idx}`}>
                        <TableCell className="text-sm">{ioc.ioc_type}</TableCell>
                        <TableCell className="font-mono text-xs">{ioc.ioc_value}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </CardContent>
          </Card>

          <Card className="min-w-0">
            <CardHeader>
              <CardTitle>Raw logs</CardTitle>
            </CardHeader>
            <CardContent className="min-w-0 space-y-3 overflow-x-hidden">
              {detail.raw_logs.length === 0 ? (
                <div className="text-sm text-muted-foreground">No raw logs stored.</div>
              ) : null}
              {detail.raw_logs.map((log, idx) => (
                <RawLogBlock
                  key={`${log.wazuh_event_id ?? "event"}-${idx}`}
                  title={`#${idx + 1} - ${log.attack_rule_id}`}
                  timestamp={new Date(log.event_timestamp).toLocaleString()}
                  payload={log.raw_payload}
                />
              ))}

              {detail.ticket.payload_sample ? (
                <RawLogBlock title="Payload sample" payload={detail.ticket.payload_sample} copyLabel="Copy payload" />
              ) : null}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Audit logs</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {detail.audit_logs.length === 0 ? (
                <div className="text-sm text-muted-foreground">No audit logs.</div>
              ) : null}
              {detail.audit_logs.map((l, idx) => {
                let actionText = l.action
                if (actionText.startsWith("STATUS_UPDATED_TO_")) {
                  const newStatus = actionText.replace("STATUS_UPDATED_TO_", "").replace(/_/g, " ")
                  actionText = `Status changed to ${newStatus}`
                } else if (actionText.startsWith("DELEGATED_TO|")) {
                  const parts = actionText.split("|")
                  if (parts.length === 3) {
                    const [_, targetName, targetRole] = parts
                    actionText = `Delegated to ${targetName} (${targetRole.replace(/_/g, " ")})`
                  } else {
                    actionText = `Delegated ticket`
                  }
                } else if (actionText.startsWith("DELEGATED_TO_")) {
                  const target = actionText.replace("DELEGATED_TO_", "")
                  actionText = `Delegated to ${target}`
                } else if (actionText === "STATUS_UPDATED") {
                  actionText = "Status updated"
                }

                return (
                  <div key={idx} className="rounded-md border p-3">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="text-xs font-medium">{actionText}</div>
                        {l.user_full_name && (
                          <div className="mt-0.5 text-xs text-muted-foreground">
                            by {l.user_full_name} {l.user_role ? `(${l.user_role.replace(/_/g, " ")})` : ""}
                          </div>
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground whitespace-nowrap">{new Date(l.created_at).toLocaleString()}</div>
                    </div>
                    {l.note ? <div className="mt-2 whitespace-pre-wrap text-sm">{l.note}</div> : null}
                  </div>
                )
              })}
            </CardContent>
          </Card>
        </div>

        <div className="min-w-0 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle>Ticket Info</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2 text-sm">
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">Source IP</span>
                <span className="font-medium">{detail.ticket.source_ip || "—"}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">Category</span>
                <span className="font-medium">{detail.ticket.threat_category || "—"}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">Type</span>
                <span className="font-medium">{detail.ticket.threat_type || "—"}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">First seen</span>
                <span>{new Date(detail.ticket.first_seen).toLocaleString()}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">Last seen</span>
                <span>{new Date(detail.ticket.last_seen).toLocaleString()}</span>
              </div>
              <div className="flex items-center justify-between gap-2">
                <span className="text-muted-foreground">Raw logs</span>
                <span className="font-medium">{detail.ticket.raw_log_count}</span>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Update status</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {nextStatuses.length === 0 ? (
                <div className="text-sm text-muted-foreground">
                  No further transitions allowed from {humanizeEnum(detail.ticket.status)}.
                </div>
              ) : (
                <>
                  <div className="space-y-2">
                    <Label>Next status</Label>
                    <Select value={nextStatus} onValueChange={(v) => setNextStatus(v as TicketStatus)}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select status" />
                      </SelectTrigger>
                      <SelectContent>
                        {nextStatuses.map((s) => (
                          <SelectItem key={s} value={s}>
                            {humanizeEnum(s)}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label>Note</Label>
                    <Textarea value={note} onChange={(e) => setNote(e.target.value)} placeholder="What did you do / observe?" />
                    <div className="text-xs text-muted-foreground">Required by the backend.</div>
                  </div>

                  {me?.role === "SOC_MANAGER" ? (
                    <div className="space-y-2">
                      <Label>Assignee</Label>
                      <Select value={assigneeId} onValueChange={setAssigneeId}>
                        <SelectTrigger>
                          <SelectValue placeholder="Select user" />
                        </SelectTrigger>
                        <SelectContent>
                          {assignableUsers.map((u) => (
                            <SelectItem key={u.id} value={u.id}>
                              {u.full_name} ({u.role.replace(/_/g, " ")}) {u.id === me?.id ? "(Me)" : ""}
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                  ) : null}

                  {formError ? <div className="text-sm text-destructive">{formError}</div> : null}

                  <Button
                    className="w-full"
                    disabled={updateMutation.isPending}
                    onClick={() => {
                      setFormError(null)
                      updateMutation.mutate()
                    }}
                  >
                    {updateMutation.isPending ? "Updating..." : "Update status"}
                  </Button>
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Recommendations</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {detail.recommendations.length === 0 ? (
                <div className="text-sm text-muted-foreground">No recommendations.</div>
              ) : null}
              {detail.recommendations
                .slice()
                .sort((a, b) => a.priority - b.priority)
                .map((r) => (
                  <div key={r.priority} className="rounded-md border p-3">
                    <div className="text-xs text-muted-foreground">Priority {r.priority}</div>
                    <div className="text-sm font-medium">{r.action}</div>
                    {r.reason ? <div className="mt-1 text-sm text-muted-foreground">{r.reason}</div> : null}
                  </div>
                ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}