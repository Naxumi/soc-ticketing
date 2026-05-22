import * as React from "react"
import { Link, Navigate } from "react-router-dom"
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query"
import { toast } from "sonner"

import { type AnalystRole, socApi, type UserListItem } from "@/api/soc"
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

function sortByCreatedDesc(items: UserListItem[]) {
  return [...items].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime())
}

export function UsersPage() {
  const { me } = useAuth()
  const qc = useQueryClient()

  const [isCreateOpen, setIsCreateOpen] = React.useState(false)
  const [fullName, setFullName] = React.useState("")
  const [username, setUsername] = React.useState("")
  const [password, setPassword] = React.useState("")
  const [role, setRole] = React.useState<AnalystRole>("L1_ANALYST")

  const resetCreateForm = React.useCallback(() => {
    setFullName("")
    setUsername("")
    setPassword("")
    setRole("L1_ANALYST")
  }, [])

  const closeCreatePopup = React.useCallback(() => {
    setIsCreateOpen(false)
    resetCreateForm()
  }, [resetCreateForm])

  const usersQuery = useQuery({
    queryKey: ["users"],
    queryFn: () => socApi.listUsers(),
    enabled: me?.role === "SOC_MANAGER",
  })

  const registerMutation = useMutation({
    mutationFn: () =>
      socApi.registerAnalyst({
        full_name: fullName.trim(),
        username: username.trim(),
        password: password.trim(),
        role,
      }),
    onSuccess: async () => {
      closeCreatePopup()
      toast.success("User berhasil dibuat")
      await qc.invalidateQueries({ queryKey: ["users"] })
    },
    onError: (err) => {
      if (err instanceof ApiError) {
        toast.error(err.message)
        return
      }
      toast.error(err instanceof Error ? err.message : "Failed to create user")
    },
  })

  const revokeMutation = useMutation({
    mutationFn: (userID: string) => socApi.revokeUserSessions(userID),
    onSuccess: async () => {
      toast.success("Session user berhasil direvoke")
      await qc.invalidateQueries({ queryKey: ["users"] })
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : "Failed to revoke sessions")
    },
  })

  const deleteMutation = useMutation({
    mutationFn: (userID: string) => socApi.deleteAnalyst(userID),
    onSuccess: async () => {
      toast.success("User berhasil dihapus")
      await qc.invalidateQueries({ queryKey: ["users"] })
    },
    onError: (err) => {
      toast.error(err instanceof Error ? err.message : "Failed to delete user")
    },
  })

  if (me?.role !== "SOC_MANAGER") {
    return <Navigate to="/dashboard" replace />
  }

  const users = usersQuery.data ? sortByCreatedDesc(usersQuery.data) : []

  const submitCreateUser = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()

    if (!fullName.trim()) {
      toast.error("Full name wajib diisi")
      return
    }
    if (!username.trim()) {
      toast.error("Username wajib diisi")
      return
    }
    if (password.trim().length < 8) {
      toast.error("Password minimal 8 karakter")
      return
    }

    registerMutation.mutate()
  }

  return (
    <>
      <Card>
        <CardHeader className="flex flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <CardTitle>User Management</CardTitle>
            {typeof users.length === "number" ? (
              <Badge variant="secondary" className="border border-brand-blue-600/20 bg-brand-blue-600/10 text-brand-blue-800 dark:text-brand-blue-200">
                {users.length} users
              </Badge>
            ) : null}
          </div>

          <Button size="sm" onClick={() => setIsCreateOpen(true)}>
            Tambah User
          </Button>
        </CardHeader>

        <CardContent className="space-y-3">
          {usersQuery.isError ? <div className="text-sm text-destructive">Failed to load users.</div> : null}

          <div className="rounded-md border">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Full name</TableHead>
                  <TableHead>Username</TableHead>
                  <TableHead>Role</TableHead>
                  <TableHead>Created</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {usersQuery.isLoading ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-sm text-muted-foreground">
                      Loading…
                    </TableCell>
                  </TableRow>
                ) : null}

                {!usersQuery.isLoading && users.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={5} className="text-sm text-muted-foreground">
                      No users found.
                    </TableCell>
                  </TableRow>
                ) : null}

                {users.map((u) => {
                  const isSelf = u.id === me?.id
                  const isManager = u.role === "SOC_MANAGER"
                  return (
                    <TableRow key={u.id}>
                      <TableCell>
                        <div className="font-medium">{u.full_name}</div>
                      </TableCell>
                      <TableCell className="text-sm text-muted-foreground">@{u.username}</TableCell>
                      <TableCell>
                        <Badge variant="outline">{humanizeEnum(u.role)}</Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {new Date(u.created_at).toLocaleString()}
                      </TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-2">
                          <Button asChild variant="outline" size="sm">
                            <Link to={`/users/${u.id}`}>Detail</Link>
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            disabled={revokeMutation.isPending}
                            onClick={() => revokeMutation.mutate(u.id)}
                          >
                            Revoke all sessions
                          </Button>
                          <Button
                            variant="destructive"
                            size="sm"
                            disabled={deleteMutation.isPending || isSelf || isManager}
                            onClick={() => {
                              const ok = window.confirm(`Delete user @${u.username}?`)
                              if (!ok) return
                              deleteMutation.mutate(u.id)
                            }}
                          >
                            Delete
                          </Button>
                        </div>
                      </TableCell>
                    </TableRow>
                  )
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {isCreateOpen ? (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-background/60 px-4 backdrop-blur-[1px]">
          <Card className="w-full max-w-md">
            <CardHeader className="flex flex-row items-center justify-between gap-3">
              <CardTitle>Create Analyst</CardTitle>
              <Button variant="outline" size="sm" onClick={closeCreatePopup}>
                Cancel
              </Button>
            </CardHeader>
            <CardContent>
              <form className="space-y-3" onSubmit={submitCreateUser}>
                <div className="space-y-2">
                  <Label htmlFor="full-name">Full name</Label>
                  <Input
                    id="full-name"
                    value={fullName}
                    onChange={(e) => setFullName(e.target.value)}
                    placeholder="Full name"
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="username">Username</Label>
                  <Input
                    id="username"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    placeholder="username"
                    autoComplete="off"
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    type="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Minimum 8 characters"
                  />
                </div>

                <div className="space-y-2">
                  <Label>Role</Label>
                  <Select value={role} onValueChange={(v) => setRole(v as AnalystRole)}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="L1_ANALYST">L1 Analyst</SelectItem>
                      <SelectItem value="L2_ANALYST">L2 Analyst</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="flex items-center justify-end gap-2 pt-1">
                  <Button type="button" variant="outline" onClick={closeCreatePopup}>
                    Cancel
                  </Button>
                  <Button type="submit" disabled={registerMutation.isPending}>
                    {registerMutation.isPending ? "Creating…" : "Create user"}
                  </Button>
                </div>

                <div className="text-xs text-muted-foreground">
                  Hanya role L1/L2 yang dapat dibuat dari endpoint manager.
                </div>
              </form>
            </CardContent>
          </Card>
        </div>
      ) : null}
    </>
  )
}
