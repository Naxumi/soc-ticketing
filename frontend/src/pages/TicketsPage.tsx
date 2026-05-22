import * as React from "react"
import { useNavigate } from "react-router-dom"
import { useQuery, useQueryClient } from "@tanstack/react-query"

import { socApi, type TicketSeverity, type TicketStatus, type TicketTab } from "@/api/soc"
import { useAuth } from "@/auth/AuthContext"
import { humanizeEnum, severityBadgeProps } from "@/lib/format"
import { useTicketsStream } from "@/hooks/useTicketsStream"
import { Badge } from "@/components/ui/badge"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import { Button } from "@/components/ui/button"

const ALL_STATUS_OPTIONS: TicketStatus[] = [
  "AGGREGATING",
  "OPEN",
  "IN_PROGRESS",
  "ESCALATED",
  "INVESTIGATING",
  "FALSE_POSITIVE",
  "RESOLVED",
]
const L1_ACTIVE_STATUSES: TicketStatus[] = ["OPEN", "IN_PROGRESS"]
const L1_HISTORY_STATUSES: TicketStatus[] = [
  "IN_PROGRESS",
  "ESCALATED",
  "INVESTIGATING",
  "FALSE_POSITIVE",
  "RESOLVED",
]
const L2_ACTIVE_STATUSES: TicketStatus[] = ["ESCALATED", "INVESTIGATING"]
const L2_HISTORY_STATUSES: TicketStatus[] = ["INVESTIGATING", "FALSE_POSITIVE", "RESOLVED"]

export function TicketsPage() {
  const { me } = useAuth()
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [page, setPage] = React.useState(1)
  const [limit, setLimit] = React.useState(10)
  const [tab, setTab] = React.useState<TicketTab>("active")
  const [status, setStatus] = React.useState<TicketStatus | "all">("all")
  const [severity, setSeverity] = React.useState<TicketSeverity | "all">("all")
  const [assignee, setAssignee] = React.useState<"all" | "me">("all")
  const [now, setNow] = React.useState(() => Date.now())
  const showTabs = me?.role === "L1_ANALYST" || me?.role === "L2_ANALYST"
  const showAssigneeFilter = me?.role === "SOC_MANAGER"

  const statusOptions = React.useMemo(() => {
    if (me?.role === "L1_ANALYST") {
      return tab === "active" ? L1_ACTIVE_STATUSES : L1_HISTORY_STATUSES
    }
    if (me?.role === "L2_ANALYST") {
      return tab === "active" ? L2_ACTIVE_STATUSES : L2_HISTORY_STATUSES
    }
    return ALL_STATUS_OPTIONS
  }, [me?.role, tab])

  React.useEffect(() => {
    const id = window.setInterval(() => setNow(Date.now()), 1000)
    return () => window.clearInterval(id)
  }, [])

  React.useEffect(() => {
    if (status !== "all" && !statusOptions.includes(status)) {
      setStatus("all")
    }
  }, [status, statusOptions])

  const formatCountdown = React.useCallback(
    (expiresAt: string) => {
      const end = new Date(expiresAt).getTime()
      const diff = Math.max(0, Math.floor((end - now) / 1000))
      const hours = Math.floor(diff / 3600)
      const minutes = Math.floor((diff % 3600) / 60)
      const seconds = diff % 60

      if (hours > 0) {
        return `${hours}h ${String(minutes).padStart(2, "0")}m`
      }
      return `${minutes}m ${String(seconds).padStart(2, "0")}s`
    },
    [now]
  )

  const query = useQuery({
    queryKey: [
      "tickets",
      {
        page,
        limit,
        status,
        severity,
        assignee,
        tab: showTabs ? tab : undefined,
        role: me?.role,
        user_id: showTabs ? me?.id : undefined,
      },
    ],
    queryFn: () =>
      socApi.listTickets({
        page,
        limit,
        status: status === "all" ? undefined : status,
        severity: severity === "all" ? undefined : severity,
        assignee_id: showAssigneeFilter && assignee === "me" ? me?.id : undefined,
        tab: showTabs ? tab : undefined,
      }),
    enabled: Boolean(me),
    placeholderData: (prev) => prev,
  })

  useTicketsStream({ enabled: Boolean(me) })

  React.useEffect(() => {
    if (!me) return
    const id = window.setInterval(() => {
      void qc.invalidateQueries({ queryKey: ["tickets"] })
    }, 120_000)
    return () => window.clearInterval(id)
  }, [me, qc])

  const data = query.data

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between gap-3">
        <CardTitle>Tickets</CardTitle>
        <div className="flex flex-wrap items-center gap-2">
          <Select value={String(status)} onValueChange={(v) => setStatus(v as TicketStatus | "all")}>
            <SelectTrigger className="w-45">
              <SelectValue placeholder="Status" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All statuses</SelectItem>
              {statusOptions.map((opt) => (
                <SelectItem key={opt} value={opt}>
                  {humanizeEnum(opt)}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>

          <Select value={String(severity)} onValueChange={(v) => setSeverity(v as TicketSeverity | "all")}>
            <SelectTrigger className="w-45">
              <SelectValue placeholder="Severity" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All severities</SelectItem>
              <SelectItem value="low">Low</SelectItem>
              <SelectItem value="medium">Medium</SelectItem>
              <SelectItem value="high">High</SelectItem>
              <SelectItem value="critical">Critical</SelectItem>
            </SelectContent>
          </Select>

          {showAssigneeFilter ? (
            <Select value={assignee} onValueChange={(v) => setAssignee(v as "all" | "me")}>
              <SelectTrigger className="w-45">
                <SelectValue placeholder="Assignee" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All</SelectItem>
                <SelectItem value="me">Assigned to me</SelectItem>
              </SelectContent>
            </Select>
          ) : null}
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        {query.isError ? (
          <div className="text-sm text-destructive">Failed to load tickets.</div>
        ) : null}

        {showTabs ? (
          <Tabs value={tab} onValueChange={(v) => setTab(v as TicketTab)}>
            <TabsList variant="line">
              <TabsTrigger value="active">Active</TabsTrigger>
              <TabsTrigger value="history">History</TabsTrigger>
            </TabsList>
          </Tabs>
        ) : null}

        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Ticket No.</TableHead>
                <TableHead>Source IP</TableHead>
                <TableHead>Rule ID</TableHead>
                <TableHead>Category</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Assignee</TableHead>
                <TableHead>First seen</TableHead>
                <TableHead>Last seen</TableHead>
                <TableHead className="text-right">Raw logs</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {query.isLoading ? (
                <TableRow>
                  <TableCell colSpan={11} className="text-sm text-muted-foreground">
                    Loading…
                  </TableCell>
                </TableRow>
              ) : null}

              {data && data.data.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={11} className="text-sm text-muted-foreground">
                    No tickets found.
                  </TableCell>
                </TableRow>
              ) : null}

              {data?.data.map((t) => {
                const isAggregating = t.status === "AGGREGATING" || Boolean(t.is_aggregating)
                const expiresAt = t.window_expires_at ?? undefined
                const countdown = isAggregating && expiresAt ? formatCountdown(expiresAt) : null

                return (
                <TableRow
                  key={t.id}
                  className={isAggregating ? "bg-muted/60 text-muted-foreground" : "cursor-pointer"}
                  onClick={() => {
                    if (!isAggregating) {
                      navigate(`/tickets/${t.id}`)
                    }
                  }}
                >
                  <TableCell className="font-mono text-xs whitespace-nowrap">
                    {t.ticket_number || "—"}
                  </TableCell>
                  <TableCell>
                    {isAggregating ? (
                      <span className="text-sm font-medium" title="Grouping in progress">
                        {t.source_ip || "—"}
                      </span>
                    ) : (
                      <span className="text-sm font-medium">
                        {t.source_ip || "—"}
                      </span>
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-xs">{t.attack_rule_id}</TableCell>
                  <TableCell className="text-sm">{t.threat_category ?? "—"}</TableCell>
                  <TableCell className="text-sm">{t.threat_type ?? "—"}</TableCell>
                  <TableCell>
                    <Badge {...severityBadgeProps(t.severity)}>
                      {t.severity ? humanizeEnum(t.severity) : "—"}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    <Badge
                      variant={isAggregating ? "secondary" : "outline"}
                      className={isAggregating ? "border border-muted-foreground/30 bg-muted text-muted-foreground" : undefined}
                    >
                      {humanizeEnum(t.status)}
                    </Badge>
                  </TableCell>
                  <TableCell className="text-sm truncate max-w-[120px]">
                    {t.assignee_name || <span className="text-muted-foreground">—</span>}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">{new Date(t.first_seen).toLocaleString()}</TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {countdown ? (
                      <span title={`Window closes at ${new Date(expiresAt!).toLocaleString()}`}>ETA {countdown}</span>
                    ) : (
                      new Date(t.last_seen).toLocaleString()
                    )}
                  </TableCell>
                  <TableCell className="text-right text-sm font-medium">
                    {isAggregating ? (
                      <div className="flex flex-col items-end">
                        <span>
                          {t.raw_log_count}
                          <span className="text-xs text-muted-foreground">+</span>
                        </span>
                        <span className="text-[11px] text-muted-foreground">growing</span>
                      </div>
                    ) : (
                      t.raw_log_count
                    )}
                  </TableCell>
                </TableRow>
              )})}
            </TableBody>
          </Table>
        </div>

        {data ? (
          <div className="flex items-center justify-between gap-2">
            <div className="text-xs text-muted-foreground">
              Page {data.metadata.page} of {data.metadata.total_pages} • {data.metadata.total_data} items
            </div>
            <div className="flex items-center gap-2">
              <Select value={String(limit)} onValueChange={(v) => { setLimit(Number(v)); setPage(1) }}>
                  <SelectTrigger className="w-30">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="10">10 / page</SelectItem>
                  <SelectItem value="20">20 / page</SelectItem>
                  <SelectItem value="50">50 / page</SelectItem>
                </SelectContent>
              </Select>

              <Button variant="outline" size="sm" disabled={page <= 1} onClick={() => setPage((p) => Math.max(1, p - 1))}>
                Prev
              </Button>
              <Button
                variant="outline"
                size="sm"
                disabled={data.metadata.total_pages === 0 || page >= data.metadata.total_pages}
                onClick={() => setPage((p) => p + 1)}
              >
                Next
              </Button>
            </div>
          </div>
        ) : null}
      </CardContent>
    </Card>
  )
}
