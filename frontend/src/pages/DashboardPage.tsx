import * as React from "react"
import { useQuery } from "@tanstack/react-query"
import { toast } from "sonner"

import { socApi, type DashboardResponse, type TicketStatus } from "@/api/soc"
import { useAuth } from "@/auth/AuthContext"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Button } from "@/components/ui/button"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"
import { humanizeEnum } from "@/lib/format"

function numberOrZero(value: number | undefined | null) {
  return typeof value === "number" ? value : 0
}

function Stat({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-md border p-3">
      <div className="text-xs text-muted-foreground">{label}</div>
      <div className="text-2xl font-semibold tabular-nums">{value}</div>
    </div>
  )
}

function getStatusCount(map: Partial<Record<TicketStatus, number>> | undefined | null, status: TicketStatus) {
  if (!map) return 0
  const raw = map[status]
  return typeof raw === "number" ? raw : 0
}

export function DashboardPage() {
  const { me } = useAuth()
  const [range, setRange] = React.useState<string>("24h")
  const [exporting, setExporting] = React.useState<null | "csv" | "pdf">(null)

  const dashboardQuery = useQuery({
    queryKey: ["dashboard", { range }],
    queryFn: () => socApi.dashboard({ range, recent_limit: 10 }),
  })

  const data: DashboardResponse | undefined = dashboardQuery.data

  const statusOrder = React.useMemo(() => {
    if (me?.role === "L2_ANALYST") {
      return ["ESCALATED", "INVESTIGATING", "FALSE_POSITIVE", "RESOLVED"] as TicketStatus[]
    }
    return ["OPEN", "IN_PROGRESS", "ESCALATED", "INVESTIGATING", "FALSE_POSITIVE", "RESOLVED"] as TicketStatus[]
  }, [me?.role])

  const backlogLabel = React.useMemo(() => {
    if (me?.role === "L1_ANALYST") return "Active backlog (OPEN + IN_PROGRESS)"
    if (me?.role === "L2_ANALYST") return "Active backlog (ESCALATED + INVESTIGATING)"
    return "Active backlog (OPEN + IN_PROGRESS + ESCALATED + INVESTIGATING)"
  }, [me?.role])

  const backlogValue = React.useMemo(() => {
    if (!data) return 0
    if (me?.role === "L2_ANALYST") {
      return (
        getStatusCount(data.tickets.backlog_by_status, "ESCALATED") +
        getStatusCount(data.tickets.backlog_by_status, "INVESTIGATING")
      )
    }
    if (me?.role === "SOC_MANAGER") {
      return (
        getStatusCount(data.tickets.backlog_by_status, "OPEN") +
        getStatusCount(data.tickets.backlog_by_status, "IN_PROGRESS") +
        getStatusCount(data.tickets.backlog_by_status, "ESCALATED") +
        getStatusCount(data.tickets.backlog_by_status, "INVESTIGATING")
      )
    }
    return (
      getStatusCount(data.tickets.backlog_by_status, "OPEN") +
      getStatusCount(data.tickets.backlog_by_status, "IN_PROGRESS")
    )
  }, [data, me?.role])

  const myActiveLabel = React.useMemo(() => {
    if (me?.role === "L1_ANALYST") return "My active (IN_PROGRESS)"
    if (me?.role === "L2_ANALYST") return "My active (INVESTIGATING)"
    return "My active (IN_PROGRESS + INVESTIGATING)"
  }, [me?.role])

  const myActiveValue = React.useMemo(() => {
    if (!data) return 0
    if (me?.role === "L1_ANALYST") return getStatusCount(data.tickets.my_by_status, "IN_PROGRESS")
    if (me?.role === "L2_ANALYST") return getStatusCount(data.tickets.my_by_status, "INVESTIGATING")
    return (
      getStatusCount(data.tickets.my_by_status, "IN_PROGRESS") +
      getStatusCount(data.tickets.my_by_status, "INVESTIGATING")
    )
  }, [data, me?.role])

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-3">
          <div>
            <div className="flex flex-wrap items-center gap-2">
              <CardTitle>Dashboard</CardTitle>
              {me?.role === "L1_ANALYST" || me?.role === "L2_ANALYST" ? (
                <Badge
                  variant="outline"
                  title="Metrics and lists are scoped to your allowed ticket visibility"
                >
                  Scope: my work
                </Badge>
              ) : null}
            </div>
            {data ? (
              <div className="text-xs text-muted-foreground">
                Window: {new Date(data.window.from).toLocaleString()} → {new Date(data.window.to).toLocaleString()}
              </div>
            ) : null}
          </div>

          <div className="flex items-center gap-2">
            {me?.role === "SOC_MANAGER" ? (
              <>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={exporting !== null}
                  onClick={async () => {
						try {
							setExporting("csv")
							const blob = await socApi.exportTicketsCSV({ range })
							const url = URL.createObjectURL(blob)
							const a = document.createElement("a")
							a.href = url
							a.download = `tickets_${range}.csv`
							a.click()
							URL.revokeObjectURL(url)
						} catch (e) {
							toast.error(e instanceof Error ? e.message : "Failed to export CSV")
						} finally {
							setExporting(null)
						}
                  }}
                >
                  Export CSV
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={exporting !== null}
                  onClick={async () => {
						try {
							setExporting("pdf")
							const blob = await socApi.exportTicketsPDF({ range })
							const url = URL.createObjectURL(blob)
							const a = document.createElement("a")
							a.href = url
							a.download = `tickets_${range}.pdf`
							a.click()
							URL.revokeObjectURL(url)
						} catch (e) {
							toast.error(e instanceof Error ? e.message : "Failed to export PDF")
						} finally {
							setExporting(null)
						}
                  }}
                >
                  Export PDF
                </Button>
              </>
            ) : null}

            <div className="w-[160px]">
              <Select value={range} onValueChange={setRange}>
                <SelectTrigger>
                  <SelectValue placeholder="Range" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="24h">Last 24 hours</SelectItem>
                  <SelectItem value="7d">Last 7 days</SelectItem>
                  <SelectItem value="30d">Last 30 days</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardHeader>

        <CardContent className="space-y-4">
          {dashboardQuery.isLoading ? (
            <div className="text-sm text-muted-foreground">Loading…</div>
          ) : null}
          {dashboardQuery.isError ? (
            <div className="text-sm text-destructive">Failed to load dashboard.</div>
          ) : null}

          {data ? (
            <>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                <Stat label="Unread notifications" value={numberOrZero(data.unread_notifications)} />
                <Stat label="Created in window" value={numberOrZero(data.tickets.created_in_window)} />
                <Stat label={backlogLabel} value={backlogValue} />
                <Stat label={myActiveLabel} value={myActiveValue} />
              </div>

              {data.focus?.l1 ? (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">L1 Focus</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid gap-3 sm:grid-cols-3">
                      <Stat label="Unassigned OPEN" value={numberOrZero(data.focus.l1.unassigned_open)} />
                      <Stat label="OPEN High/Critical" value={numberOrZero(data.focus.l1.open_high_critical)} />
                      <Stat label="My IN_PROGRESS" value={numberOrZero(data.focus.l1.my_in_progress)} />
                    </div>
                  </CardContent>
                </Card>
              ) : null}

              {data.focus?.l2 ? (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">L2 Focus</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                      <Stat label="Escalated" value={numberOrZero(data.focus.l2.escalated)} />
                      <Stat label="Investigating" value={numberOrZero(data.focus.l2.investigating)} />
                      <Stat
                        label="Unassigned (Escalated/Investigating, scope)"
                        value={numberOrZero(data.focus.l2.unassigned_escalated_or_investigating)}
                      />
                      <Stat label="My Investigating" value={numberOrZero(data.focus.l2.my_investigating)} />
                    </div>
                  </CardContent>
                </Card>
              ) : null}

              <div className="grid gap-4 lg:grid-cols-2">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Backlog by status</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Status</TableHead>
                          <TableHead className="text-right">Count</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {statusOrder.map((st) => (
                          <TableRow key={`backlog-${st}`}>
                            <TableCell>{humanizeEnum(st)}</TableCell>
                            <TableCell className="text-right tabular-nums">
                              {getStatusCount(data.tickets.backlog_by_status, st)}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>

                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">My tickets by status</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Status</TableHead>
                          <TableHead className="text-right">Count</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {statusOrder.map((st) => (
                          <TableRow key={`my-${st}`}>
                            <TableCell>{humanizeEnum(st)}</TableCell>
                            <TableCell className="text-right tabular-nums">
                              {getStatusCount(data.tickets.my_by_status, st)}
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              </div>

              <Card>
                <CardHeader>
                  <CardTitle className="text-base">Recent tickets (in window)</CardTitle>
                </CardHeader>
                <CardContent>
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>Source IP</TableHead>
                        <TableHead>Rule ID</TableHead>
                        <TableHead>Category</TableHead>
                        <TableHead>Type</TableHead>
                        <TableHead>Status</TableHead>
                        <TableHead>Severity</TableHead>
                        <TableHead className="text-right">First seen</TableHead>
                        <TableHead className="text-right">Last seen</TableHead>
                        <TableHead className="text-right">Raw logs</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {data.tickets.recent_in_window.length ? (
                        data.tickets.recent_in_window.map((t) => (
                          <TableRow key={t.id}>
                            <TableCell className="font-mono text-xs">{t.source_ip}</TableCell>
                            <TableCell className="font-mono text-xs">{t.attack_rule_id}</TableCell>
                            <TableCell>{t.threat_category ?? "—"}</TableCell>
                            <TableCell>{t.threat_type ?? "—"}</TableCell>
                            <TableCell>{humanizeEnum(t.status)}</TableCell>
                            <TableCell>{t.severity ? humanizeEnum(t.severity) : "—"}</TableCell>
                            <TableCell className="text-right text-xs text-muted-foreground">
                              {new Date(t.first_seen).toLocaleString()}
                            </TableCell>
                            <TableCell className="text-right text-xs text-muted-foreground">{new Date(t.last_seen).toLocaleString()}</TableCell>
                            <TableCell className="text-right font-medium">{t.raw_log_count}</TableCell>
                          </TableRow>
                        ))
                      ) : (
                        <TableRow>
                          <TableCell colSpan={9} className="text-sm text-muted-foreground">
                            No tickets in this window.
                          </TableCell>
                        </TableRow>
                      )}
                    </TableBody>
                  </Table>
                </CardContent>
              </Card>

              {data.team ? (
                <Card>
                  <CardHeader>
                    <CardTitle className="text-base">Team workload</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                      <Stat label="Unassigned active" value={numberOrZero(data.team.unassigned_active)} />
                    </div>

                    <Table>
                      <TableHeader>
                        <TableRow>
                          <TableHead>Assignee</TableHead>
                          <TableHead>Role</TableHead>
                          <TableHead className="text-right">OPEN</TableHead>
                          <TableHead className="text-right">IN_PROGRESS</TableHead>
                          <TableHead className="text-right">ESCALATED</TableHead>
                          <TableHead className="text-right">INVESTIGATING</TableHead>
                          <TableHead className="text-right">Total active</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {data.team.assignees.length ? (
                          data.team.assignees.map((a) => (
                            <TableRow key={a.user_id}>
                              <TableCell>
                                <div className="font-medium">{a.full_name}</div>
                                <div className="text-xs text-muted-foreground">@{a.username}</div>
                              </TableCell>
                              <TableCell>{humanizeEnum(a.role)}</TableCell>
                              <TableCell className="text-right tabular-nums">
                                {getStatusCount(a.active_by_status, "OPEN")}
                              </TableCell>
                              <TableCell className="text-right tabular-nums">
                                {getStatusCount(a.active_by_status, "IN_PROGRESS")}
                              </TableCell>
                              <TableCell className="text-right tabular-nums">
                                {getStatusCount(a.active_by_status, "ESCALATED")}
                              </TableCell>
                              <TableCell className="text-right tabular-nums">
                                {getStatusCount(a.active_by_status, "INVESTIGATING")}
                              </TableCell>
                              <TableCell className="text-right tabular-nums">{a.total_active}</TableCell>
                            </TableRow>
                          ))
                        ) : (
                          <TableRow>
                            <TableCell colSpan={7} className="text-sm text-muted-foreground">
                              No assignee workload in this window.
                            </TableCell>
                          </TableRow>
                        )}
                      </TableBody>
                    </Table>
                  </CardContent>
                </Card>
              ) : null}
            </>
          ) : null}
        </CardContent>
      </Card>
    </div>
  )
}
