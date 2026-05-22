import * as React from "react"
import { Link, Navigate, useNavigate, useParams } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"

import { type AdminUpdateAnalystRequest, type AnalystRole, socApi } from "@/api/soc"
import { useAuth } from "@/auth/AuthContext"
import { ApiError } from "@/lib/api"
import { humanizeEnum } from "@/lib/format"
import { Badge } from "@/components/ui/badge"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
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

function isAnalystRole(role: string): role is AnalystRole {
  return role === "L1_ANALYST" || role === "L2_ANALYST"
}

export function UserDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const { me } = useAuth()

  const detailQuery = useQuery({
    queryKey: ["user", id],
    queryFn: () => socApi.getUserDetail(id!),
    enabled: Boolean(id) && me?.role === "SOC_MANAGER",
  })

  const detail = detailQuery.data

  const canManageAnalyst = React.useMemo(() => {
    if (!detail) return false
    return isAnalystRole(detail.user.role)
  }, [detail])

  const [fullName, setFullName] = React.useState("")
  const [username, setUsername] = React.useState("")
  const [role, setRole] = React.useState<AnalystRole>("L1_ANALYST")
  const [password, setPassword] = React.useState("")
  const [formError, setFormError] = React.useState<string | null>(null)

  React.useEffect(() => {
    if (!detail) return
    setFullName(detail.user.full_name)
    setUsername(detail.user.username)
    if (isAnalystRole(detail.user.role)) {
      setRole(detail.user.role)
    }
    setPassword("")
    setFormError(null)
  }, [detail])

  const updateMutation = useMutation({
    mutationFn: async () => {
      if (!id || !detail) return

      const payload: AdminUpdateAnalystRequest = {}
      const nextFullName = fullName.trim()
      const nextUsername = username.trim()
      const nextPassword = password.trim()

      if (nextFullName && nextFullName !== detail.user.full_name) {
        payload.full_name = nextFullName
      }
      if (nextUsername && nextUsername !== detail.user.username) {
        payload.username = nextUsername
      }
      if (isAnalystRole(detail.user.role) && role !== detail.user.role) {
        payload.role = role
      }
      if (nextPassword) {
        payload.password = nextPassword
      }

      if (Object.keys(payload).length === 0) {
        throw new Error("Tidak ada perubahan untuk disimpan")
      }

      await socApi.adminUpdateAnalyst(id, payload)
    },
    onSuccess: async () => {
      setPassword("")
      setFormError(null)
      toast.success("User berhasil diupdate")
      await qc.invalidateQueries({ queryKey: ["user", id] })
      await qc.invalidateQueries({ queryKey: ["users"] })
    },
    onError: (err) => {
      if (err instanceof ApiError) {
        setFormError(err.message)
        return
      }
      setFormError(err instanceof Error ? err.message : "Failed to update user")
    },
  })

  const revokeMutation = useMutation({
    mutationFn: async (sessionId?: string) => {
      if (!id) return
      await socApi.revokeUserSessions(id, sessionId ? { session_id: sessionId } : undefined)
    },
    onSuccess: async () => {
      toast.success("Session berhasil direvoke")
      await qc.invalidateQueries({ queryKey: ["user", id] })
      await qc.invalidateQueries({ queryKey: ["users"] })
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : "Failed to revoke sessions")
    },
  })

  const deleteMutation = useMutation({
    mutationFn: async () => {
      if (!id) return
      await socApi.deleteAnalyst(id)
    },
    onSuccess: async () => {
      toast.success("User berhasil dihapus")
      await qc.invalidateQueries({ queryKey: ["users"] })
      navigate("/users", { replace: true })
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : "Failed to delete user")
    },
  })

  if (me?.role !== "SOC_MANAGER") {
    return <Navigate to="/dashboard" replace />
  }

  if (detailQuery.isLoading) {
    return <div className="text-sm text-muted-foreground">Loading…</div>
  }

  if (detailQuery.isError || !detail) {
    return <div className="text-sm text-destructive">Failed to load user detail.</div>
  }

  const sessions = [...detail.sessions].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
  const logs = [...detail.ticket_logs].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
  const isSelf = detail.user.id === me?.id

  return (
    <div className="space-y-4">
      <div className="space-y-1">
        <div className="text-xs text-muted-foreground">
          <Link className="underline-offset-4 hover:underline" to="/users">
            Users
          </Link>
          <span className="mx-2">/</span>
          <span>{detail.user.username}</span>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="text-lg font-semibold">{detail.user.full_name}</div>
          <Badge variant="outline">{humanizeEnum(detail.user.role)}</Badge>
          <div className="text-xs text-muted-foreground">Created {new Date(detail.user.created_at).toLocaleString()}</div>
        </div>
      </div>

      <div className="grid gap-4 lg:grid-cols-[360px_1fr]">
        <Card className="h-fit">
          <CardHeader>
            <CardTitle>Manager Actions</CardTitle>
          </CardHeader>
          <CardContent className="space-y-2">
            <Button
              variant="outline"
              className="w-full"
              disabled={revokeMutation.isPending}
              onClick={() => revokeMutation.mutate(undefined)}
            >
              {revokeMutation.isPending ? "Revoking…" : "Revoke all sessions"}
            </Button>

            <Button
              variant="destructive"
              className="w-full"
              disabled={deleteMutation.isPending || !canManageAnalyst || isSelf}
              onClick={() => {
                const ok = window.confirm(`Delete user @${detail.user.username}?`)
                if (!ok) return
                deleteMutation.mutate()
              }}
            >
              {deleteMutation.isPending ? "Deleting…" : "Delete analyst"}
            </Button>

            {!canManageAnalyst ? (
              <div className="text-xs text-muted-foreground">
                Endpoint delete/update hanya berlaku untuk role analyst (L1/L2).
              </div>
            ) : null}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Update Analyst</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="detail-full-name">Full name</Label>
                <Input
                  id="detail-full-name"
                  value={fullName}
                  disabled={!canManageAnalyst}
                  onChange={(e) => setFullName(e.target.value)}
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="detail-username">Username</Label>
                <Input
                  id="detail-username"
                  value={username}
                  disabled={!canManageAnalyst}
                  onChange={(e) => setUsername(e.target.value)}
                />
              </div>
            </div>

            <div className="grid gap-3 md:grid-cols-2">
              <div className="space-y-2">
                <Label>Role</Label>
                <Select value={role} onValueChange={(v) => setRole(v as AnalystRole)} disabled={!canManageAnalyst}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="L1_ANALYST">L1 Analyst</SelectItem>
                    <SelectItem value="L2_ANALYST">L2 Analyst</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="detail-password">New password (optional)</Label>
                <Input
                  id="detail-password"
                  type="password"
                  disabled={!canManageAnalyst}
                  value={password}
                  placeholder="Isi jika ingin reset password"
                  onChange={(e) => setPassword(e.target.value)}
                />
              </div>
            </div>

            {formError ? <div className="text-sm text-destructive">{formError}</div> : null}

            <Button
              disabled={updateMutation.isPending || !canManageAnalyst}
              onClick={() => {
                setFormError(null)
                updateMutation.mutate()
              }}
            >
              {updateMutation.isPending ? "Saving…" : "Save changes"}
            </Button>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>User Sessions</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Status</TableHead>
                  <TableHead>User agent</TableHead>
                  <TableHead>IP address</TableHead>
                  <TableHead>Expires</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-sm text-muted-foreground">
                      No active session history.
                    </TableCell>
                  </TableRow>
                ) : null}
                {sessions.map((s) => (
                  <TableRow key={s.id}>
                    <TableCell>
                      {s.is_revoked ? (
                        <Badge variant="outline">Revoked</Badge>
                      ) : (
                        <Badge variant="secondary" className="border border-brand-blue-600/20 bg-brand-blue-600/10 text-brand-blue-800 dark:text-brand-blue-200">
                          Active
                        </Badge>
                      )}
                    </TableCell>
                    <TableCell className="max-w-90 truncate text-sm text-muted-foreground">{s.user_agent ?? "-"}</TableCell>
                    <TableCell className="font-mono text-xs">{s.ip_address ?? "-"}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{new Date(s.expires_at).toLocaleString()}</TableCell>
                    <TableCell className="text-sm text-muted-foreground">{new Date(s.created_at).toLocaleString()}</TableCell>
                    <TableCell className="text-right">
                      {!s.is_revoked ? (
                        <Button
                          variant="outline"
                          size="sm"
                          disabled={revokeMutation.isPending}
                          onClick={() => revokeMutation.mutate(s.id)}
                        >
                          Revoke
                        </Button>
                      ) : null}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Ticket Activity Logs</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Ticket</TableHead>
                  <TableHead>Source</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Action</TableHead>
                  <TableHead>Note</TableHead>
                  <TableHead className="text-right">Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {logs.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-sm text-muted-foreground">
                      No ticket logs for this user.
                    </TableCell>
                  </TableRow>
                ) : null}

                {logs.map((l) => (
                  <TableRow key={l.id}>
                    <TableCell>
                      <Link className="font-mono text-xs underline-offset-4 hover:underline" to={`/tickets/${l.ticket_id}`}>
                        {l.ticket_number}
                      </Link>
                    </TableCell>
                    <TableCell className="text-sm">
                      {l.source_ip}
                      <div className="text-xs text-muted-foreground">
                        {l.threat_category ?? "-"} / {l.threat_type ?? "-"}
                      </div>
                    </TableCell>
                    <TableCell>{l.severity ? humanizeEnum(l.severity) : "-"}</TableCell>
                    <TableCell>
                      <Badge variant="outline">{humanizeEnum(l.action)}</Badge>
                    </TableCell>
                    <TableCell className="max-w-100 truncate text-sm text-muted-foreground">{l.note ?? "-"}</TableCell>
                    <TableCell className="text-right text-sm text-muted-foreground">
                      {new Date(l.created_at).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
