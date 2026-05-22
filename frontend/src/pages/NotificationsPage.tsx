import * as React from "react"
import { Link } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"

import { socApi } from "@/api/soc"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select"
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table"

export function NotificationsPage() {
  const qc = useQueryClient()
  const [page, setPage] = React.useState(1)
  const [limit, setLimit] = React.useState(10)
  const [filter, setFilter] = React.useState<"all" | "unread">("unread")

  const query = useQuery({
    queryKey: ["notifications", { page, limit, filter }],
    queryFn: () =>
      socApi.listNotifications({
        page,
        limit,
        is_read: filter === "unread" ? false : undefined,
      }),
  })

  const markRead = useMutation({
    mutationFn: (id: string) => socApi.markNotificationRead(id),
    onSuccess: async () => {
      await qc.invalidateQueries({ queryKey: ["notifications"] })
      await qc.invalidateQueries({ queryKey: ["notificationsUnread"] })
    },
  })

  const data = query.data

  return (
    <Card className="ring-brand-blue-600/20">
      <CardHeader className="flex flex-row items-center justify-between gap-3 border-b bg-brand-blue-800/5 dark:bg-brand-blue-600/10">
        <div className="flex items-center gap-2">
          <CardTitle className="text-brand-blue-800 dark:text-brand-yellow-500">Notifications</CardTitle>
          {typeof data?.metadata.total_data === "number" ? (
            <Badge variant="secondary" className="border border-brand-blue-600/20 bg-brand-blue-600/10 text-brand-blue-800 dark:text-brand-blue-200">
              {data.metadata.total_data}
            </Badge>
          ) : null}
        </div>
        <div className="flex items-center gap-2">
          <Select value={filter} onValueChange={(v) => { setFilter(v as "all" | "unread"); setPage(1) }}>
            <SelectTrigger className="w-40">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="unread">Unread</SelectItem>
              <SelectItem value="all">All</SelectItem>
            </SelectContent>
          </Select>

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
        </div>
      </CardHeader>

      <CardContent className="space-y-3">
        {query.isError ? <div className="text-sm text-destructive">Failed to load notifications.</div> : null}

        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Status</TableHead>
                <TableHead>Message</TableHead>
                <TableHead>Time</TableHead>
                <TableHead className="text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {query.isLoading ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-sm text-muted-foreground">Loading…</TableCell>
                </TableRow>
              ) : null}

              {data && data.data.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={4} className="text-sm text-muted-foreground">No notifications.</TableCell>
                </TableRow>
              ) : null}

              {data?.data.map((n) => (
                <TableRow key={n.id} className={!n.is_read ? "bg-brand-blue-800/5 dark:bg-brand-blue-600/10" : undefined}>
                  <TableCell>
                    {n.is_read ? (
                      <Badge variant="outline">Read</Badge>
                    ) : (
                      <Badge className="border border-brand-yellow-500/30 bg-brand-yellow-500/10 text-brand-yellow-700 dark:text-brand-yellow-300">Unread</Badge>
                    )}
                  </TableCell>
                  <TableCell>
                    {n.ticket_id ? (
                      <Link className="text-sm underline-offset-4 hover:underline" to={`/tickets/${n.ticket_id}`}>
                        {n.message}
                      </Link>
                    ) : (
                      <span className="text-sm text-muted-foreground">{n.message}</span>
                    )}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">{new Date(n.created_at).toLocaleString()}</TableCell>
                  <TableCell className="text-right">
                    {!n.is_read ? (
                      <Button
                        variant="outline"
                        size="sm"
                        disabled={markRead.isPending}
                        onClick={() => markRead.mutate(n.id)}
                      >
                        Mark read
                      </Button>
                    ) : null}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>

        {data ? (
          <div className="flex items-center justify-between">
            <div className="text-xs text-muted-foreground">
              Page {data.metadata.page} of {data.metadata.total_pages} • {data.metadata.total_data} items
            </div>
            <div className="flex items-center gap-2">
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
