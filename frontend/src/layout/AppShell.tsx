import { type ReactNode, useState } from "react"
import {
  BellIcon,
  LogOutIcon,
  KeyIcon,
  MenuIcon,
  MoonIcon,
  ShieldIcon,
  SunIcon,
  TicketIcon,
  UsersIcon,
  XIcon,
} from "lucide-react"
import { NavLink, Outlet, useNavigate } from "react-router-dom"
import { toast } from "sonner"
import { useQuery, useQueryClient } from "@tanstack/react-query"

import { socApi, type NotificationListItem } from "@/api/soc"
import { useAuth } from "@/auth/AuthContext"
import { useNotificationsStream } from "@/hooks/useNotificationsStream"
import { Button } from "@/components/ui/button"
import { Badge } from "@/components/ui/badge"
import { Separator } from "@/components/ui/separator"
import { getTheme, setTheme, toggleTheme, type ThemeMode } from "@/lib/theme"
import { ChangePasswordModal } from "@/components/ChangePasswordModal"

/* ─────────────────────── Nav Item ─────────────────────── */

function NavItem({
  to,
  icon,
  label,
  onClick,
}: {
  to: string
  icon: ReactNode
  label: string
  onClick?: () => void
}) {
  return (
    <NavLink
      to={to}
      onClick={onClick}
      className={({ isActive }) =>
        [
          "flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-all duration-200",
          isActive
            ? "border-l-[3px] border-brand-yellow-500 bg-brand-blue-50 text-brand-blue-800 dark:bg-brand-blue-600 dark:text-white"
            : "border-l-[3px] border-transparent text-brand-blue-500 hover:bg-brand-blue-50 hover:text-brand-blue-800 dark:text-brand-blue-200 dark:hover:bg-brand-blue-600/60 dark:hover:text-white",
        ].join(" ")
      }
    >
      {({ isActive }) => (
        <>
          <span
            className={
              isActive
                ? "text-brand-yellow-600 dark:text-brand-yellow-500"
                : "text-brand-blue-400 dark:text-brand-blue-300"
            }
          >
            {icon}
          </span>
          <span>{label}</span>
        </>
      )}
    </NavLink>
  )
}

/* ─────────────────────── Brand Logo ─────────────────────── */

function BrandLogo({ className }: { className?: string }) {
  return (
    <div className={`flex items-center gap-2.5 ${className ?? ""}`}>
      <div className="flex size-8 items-center justify-center rounded-lg bg-brand-yellow-500">
        <ShieldIcon className="size-4.5 text-brand-blue-900" />
      </div>
      <div className="flex flex-col leading-tight">
        <span className="text-xs font-bold tracking-wider text-brand-blue-800 dark:text-white">
          SOC <span className="text-brand-yellow-600 dark:text-brand-yellow-500">Ticketing</span>
        </span>
        <span className="text-[10px] font-medium tracking-wide text-brand-blue-400 dark:text-brand-blue-300">
          VOKASI UB
        </span>
      </div>
    </div>
  )
}

/* ─────────────────────── Sidebar Overlay (Mobile) ──────── */

function SidebarOverlay({
  open,
  onClose,
}: {
  open: boolean
  onClose: () => void
}) {
  if (!open) return null
  return (
    <div
      className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm lg:hidden"
      onClick={onClose}
      aria-hidden
    />
  )
}

/* ─────────────────────── App Shell ─────────────────────── */

export function AppShell() {
  const { me, logout } = useAuth()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [theme, setThemeState] = useState<ThemeMode>(() => getTheme())
  const [sidebarOpen, setSidebarOpen] = useState(false)
  const [passwordModalOpen, setPasswordModalOpen] = useState(false)

  const unread = useQuery({
    queryKey: ["notificationsUnread"],
    queryFn: async () => {
      const res = await socApi.listNotifications({ page: 1, limit: 1, is_read: false })
      return res.metadata.total_data
    },
    enabled: Boolean(me),
    refetchInterval: 60_000,
  })

  useNotificationsStream({
    enabled: Boolean(me),
    onNotification: (n: NotificationListItem) => {
      const hasTicket = Boolean(n.ticket_id)
      toast.custom(
        (t) => (
          <div className="w-95 rounded-xl border bg-popover p-3 text-popover-foreground">
            <div className="flex items-start justify-between gap-3">
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="mt-0.5 inline-flex size-2 shrink-0 rounded-full bg-brand-yellow-500" />
                  <div className="text-sm font-semibold">New notification</div>
                  <div className="ml-auto text-xs text-muted-foreground">
                    {new Date(n.created_at).toLocaleTimeString()}
                  </div>
                </div>

                <div className="mt-1 whitespace-pre-wrap text-sm text-foreground/90">{n.message}</div>

                <div className="mt-2 flex items-center gap-2 text-xs text-muted-foreground">
                  <span className="font-mono">{hasTicket ? "Ticket" : "Grouping"}</span>
                  <span className="break-all font-mono">{hasTicket ? n.ticket_id : "Aggregating window"}</span>
                </div>
              </div>

              <div className="flex shrink-0 flex-col items-end gap-2">
                <Button
                  size="xs"
                  variant="secondary"
                  onClick={() => {
                    toast.dismiss(t)
                    if (n.ticket_id) {
                      navigate(`/tickets/${n.ticket_id}`)
                    }
                  }}
                  disabled={!hasTicket}
                >
                  View
                </Button>
                <button
                  type="button"
                  className="text-xs text-muted-foreground underline-offset-4 hover:underline"
                  onClick={() => toast.dismiss(t)}
                >
                  Dismiss
                </button>
              </div>
            </div>
          </div>
        ),
        { duration: 8000 }
      )
      void qc.invalidateQueries({ queryKey: ["notifications"] })
      void qc.invalidateQueries({ queryKey: ["notificationsUnread"] })
    },
  })

  const closeSidebar = () => setSidebarOpen(false)

  /* ── Sidebar content (shared between desktop & mobile) ── */
  const sidebarContent = (
    <>
      <div className="flex h-14 items-center px-4">
        <BrandLogo />
      </div>
      <Separator className="bg-border dark:bg-brand-blue-600/50" />
      <nav className="flex-1 space-y-1 p-3">
        <NavItem
          to="/dashboard"
          icon={<ShieldIcon className="size-4" />}
          label="Dashboard"
          onClick={closeSidebar}
        />
        <NavItem
          to="/tickets"
          icon={<TicketIcon className="size-4" />}
          label="Tickets"
          onClick={closeSidebar}
        />
        <NavItem
          to="/notifications"
          icon={<BellIcon className="size-4" />}
          label="Notifications"
          onClick={closeSidebar}
        />
        {me?.role === "SOC_MANAGER" ? (
          <NavItem
            to="/users"
            icon={<UsersIcon className="size-4" />}
            label="Users"
            onClick={closeSidebar}
          />
        ) : null}
      </nav>

      {/* User info at bottom of sidebar */}
      <div className="border-t border-border p-3 dark:border-brand-blue-600/50">
        <div className="flex items-center gap-2 rounded-lg bg-brand-blue-50 px-3 py-2 dark:bg-brand-blue-600/40">
          <div className="flex size-7 items-center justify-center rounded-full bg-brand-yellow-500 text-xs font-bold text-brand-blue-900">
            {(me?.full_name ?? me?.username ?? "?").charAt(0).toUpperCase()}
          </div>
          <div className="min-w-0 flex-1">
            <div className="truncate text-xs font-medium text-brand-blue-800 dark:text-white">
              {me?.full_name ?? me?.username}
            </div>
            <div className="text-[10px] text-brand-blue-400 dark:text-brand-blue-300">
              {me?.role?.replace(/_/g, " ")}
            </div>
          </div>
        </div>
      </div>
    </>
  )

  return (
    <div className="min-h-svh bg-background text-foreground">
      {/* ── Mobile sidebar overlay ── */}
      <SidebarOverlay open={sidebarOpen} onClose={closeSidebar} />
      <ChangePasswordModal open={passwordModalOpen} onClose={() => setPasswordModalOpen(false)} />

      <div className="grid min-h-svh lg:grid-cols-[260px_1fr]">
        {/* ── Desktop sidebar ── */}
        <aside className="hidden lg:flex lg:flex-col border-r border-border bg-white text-brand-blue-800 dark:border-brand-blue-600/30 dark:bg-brand-blue-800 dark:text-white">
          {sidebarContent}
        </aside>

        {/* ── Mobile sidebar drawer ── */}
        <aside
          className={[
            "fixed inset-y-0 left-0 z-50 flex w-[280px] flex-col bg-white text-brand-blue-800 shadow-2xl transition-transform duration-300 ease-in-out dark:bg-brand-blue-800 dark:text-white lg:hidden",
            sidebarOpen ? "translate-x-0" : "-translate-x-full",
          ].join(" ")}
        >
          <div className="absolute right-2 top-3 z-10">
            <Button
              variant="ghost"
              size="icon-sm"
              onClick={closeSidebar}
              className="text-brand-blue-400 hover:bg-brand-blue-50 hover:text-brand-blue-800 dark:text-brand-blue-300 dark:hover:bg-brand-blue-600 dark:hover:text-white"
              aria-label="Close sidebar"
            >
              <XIcon className="size-4" />
            </Button>
          </div>
          {sidebarContent}
        </aside>

        {/* ── Main column ── */}
        <div className="flex min-w-0 flex-col">
          {/* ── Top navbar ── */}
          <header
            id="top-navbar"
            className="flex h-14 items-center justify-between gap-3 border-b border-border bg-white px-4 text-brand-blue-800 dark:border-brand-blue-600/30 dark:bg-brand-blue-800 dark:text-white"
          >
            <div className="flex items-center gap-3">
              {/* Mobile hamburger */}
              <Button
                variant="ghost"
                size="icon-sm"
                className="text-brand-blue-400 hover:bg-brand-blue-50 hover:text-brand-blue-800 dark:text-brand-blue-200 dark:hover:bg-brand-blue-600 dark:hover:text-white lg:hidden"
                onClick={() => setSidebarOpen(true)}
                aria-label="Open menu"
              >
                <MenuIcon className="size-5" />
              </Button>

              {/* Logo in navbar (visible on mobile) */}
              <div className="lg:hidden">
                <BrandLogo />
              </div>

              {/* Desktop title */}
              <div className="hidden items-center gap-2 lg:flex">
                <ShieldIcon className="size-4.5 text-brand-yellow-600 dark:text-brand-yellow-500" />
                <span className="text-sm font-bold tracking-wider">
                  SOC{" "}
                  <span className="text-brand-yellow-600 dark:text-brand-yellow-500">
                    Ticketing System
                  </span>
                </span>
              </div>
            </div>

            {/* Right actions */}
            <div className="flex items-center gap-2">
              {/* User pill – hidden on small screens, shown in sidebar instead */}
              <div className="hidden items-center gap-2 rounded-full border border-border bg-brand-blue-50 px-3 py-1 text-xs dark:border-brand-blue-600 dark:bg-brand-blue-600/40 md:flex">
                <span className="max-w-45 truncate text-brand-blue-800 dark:text-white">
                  {me?.full_name ?? me?.username}
                </span>
                <span className="text-brand-blue-300 dark:text-brand-blue-400">•</span>
                <span className="text-brand-blue-500 dark:text-brand-blue-200">
                  {me?.role?.replace(/_/g, " ")}
                </span>
              </div>

              {/* Theme toggle */}
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  const next = toggleTheme(theme)
                  setTheme(next)
                  setThemeState(next)
                }}
                aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} mode`}
                className="text-brand-blue-500 hover:bg-brand-blue-50 hover:text-brand-blue-800 dark:text-brand-blue-200 dark:hover:bg-brand-blue-600 dark:hover:text-white"
              >
                {theme === "dark" ? <SunIcon className="size-4" /> : <MoonIcon className="size-4" />}
                <span className="ml-1 hidden sm:inline">{theme === "dark" ? "Light" : "Dark"}</span>
              </Button>

              {/* Notifications */}
              <Button
                variant="ghost"
                size="sm"
                onClick={() => navigate("/notifications")}
                aria-label="Notifications"
                className="text-brand-blue-500 hover:bg-brand-blue-50 hover:text-brand-blue-800 dark:text-brand-blue-200 dark:hover:bg-brand-blue-600 dark:hover:text-white"
              >
                <BellIcon className="size-4" />
                <span className="ml-1 hidden sm:inline">Inbox</span>
                {typeof unread.data === "number" && unread.data > 0 ? (
                  <Badge
                    variant="secondary"
                    className="ml-1.5 border-brand-yellow-600 bg-brand-yellow-500 text-brand-blue-900 font-semibold"
                  >
                    {unread.data}
                  </Badge>
                ) : null}
              </Button>

              {/* Password */}
              <Button
                variant="ghost"
                size="sm"
                onClick={() => setPasswordModalOpen(true)}
                className="text-brand-blue-500 hover:bg-brand-blue-50 hover:text-brand-blue-800 dark:text-brand-blue-200 dark:hover:bg-brand-blue-600 dark:hover:text-white"
              >
                <KeyIcon className="size-4" />
                <span className="ml-1 hidden sm:inline">Password</span>
              </Button>

              {/* Logout */}
              <Button
                variant="ghost"
                size="sm"
                onClick={async () => {
                  await logout()
                  qc.clear()
                  navigate("/login", { replace: true })
                }}
                className="text-brand-blue-500 hover:bg-brand-blue-50 hover:text-brand-blue-800 dark:text-brand-blue-200 dark:hover:bg-brand-blue-600 dark:hover:text-white"
              >
                <LogOutIcon className="size-4" />
                <span className="ml-1 hidden sm:inline">Logout</span>
              </Button>
            </div>
          </header>

          {/* ── Main content area ── */}
          <main className="min-w-0 flex-1 p-3 sm:p-4 lg:p-6">
            <Outlet />
          </main>
        </div>
      </div>
    </div>
  )
}
