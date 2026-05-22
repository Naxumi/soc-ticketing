import * as React from "react"
import { Navigate, useLocation } from "react-router-dom"

import { useAuth } from "@/auth/AuthContext"

export function RequireAuth({ children }: { children: React.ReactNode }) {
  const { me, isBootstrapping } = useAuth()
  const location = useLocation()

  if (isBootstrapping) {
    return <div className="flex min-h-svh items-center justify-center text-sm text-muted-foreground">Loading…</div>
  }

  if (!me) {
    return <Navigate to="/login" replace state={{ from: location.pathname }} />
  }

  return <>{children}</>
}
